//! `rustfun-sandbox-init` — the single-threaded sandbox launcher.
//!
//! This binary is started by the Linux sandbox layer as a *fresh, single-threaded* process so
//! it can create a PID namespace (`unshare(CLONE_NEWPID)` is refused for multi-threaded
//! callers), then it runs the function's interpreter as PID 1 of that namespace.
//!
//! It is an implementation detail: users never invoke it, and no manifest references it.
//!
//! ```text
//! rustfun (multi-threaded tokio runtime)
//!   └── rustfun-sandbox-init <base64 spec>   ← creates namespaces, applies limits
//!         └── <interpreter> <args…>         ← PID 1 in the new PID namespace
//! ```
//!
//! The **user** namespace is deliberately *not* created here: it is created by the parent
//! through `pre_exec`, where the platform can write `/proc/<pid>/uid_map` on its behalf. The
//! launcher inherits that namespace and therefore already holds the capabilities needed to
//! unshare the rest.

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;

use rustfun_sandbox::launcher::{is_launcher_invocation, spec_from_args, LauncherSpec};

fn main() -> std::process::ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if !is_launcher_invocation(&args) {
        eprintln!(
            "rustfun-sandbox-init is an internal component; it is started by the rustfun runtime"
        );
        return std::process::ExitCode::from(70);
    }

    let spec = match spec_from_args(&args) {
        Some(Ok(spec)) => spec,
        Some(Err(error)) => {
            eprintln!("[RUSTFUN_SANDBOX_ERROR] {error}");
            return std::process::ExitCode::from(78);
        }
        None => {
            eprintln!("[RUSTFUN_SANDBOX_ERROR] the sandbox launcher requires an encoded spec");
            return std::process::ExitCode::from(78);
        }
    };

    run(spec)
}

/// Create the namespaces, apply limits, and run the payload as PID 1.
#[allow(unsafe_code)]
fn run(spec: LauncherSpec) -> std::process::ExitCode {
    if let Err(error) = apply_namespace(&spec) {
        eprintln!("[RUSTFUN_SANDBOX_ERROR] {error}");
        return std::process::ExitCode::from(72);
    }

    // `CLONE_NEWPID` applies to *children*: the payload must be started by this process to
    // become PID 1 of the new namespace.
    let mut command = std::process::Command::new(&spec.program);
    command.args(&spec.args);
    command.env_clear();
    for (key, value) in std::env::vars() {
        command.env(key, value);
    }
    if let Some(cgroup) = &spec.cgroup_path {
        // The payload joins its cgroup before `exec`, so it is accounted for from its very
        // first instruction.
        let cgroup = cgroup.clone();
        // SAFETY: `pre_exec` runs in the forked child before `exec`; the hook only performs a
        // single `write(2)` to a path derived from the platform's own cgroup directory.
        unsafe {
            command.pre_exec(move || {
                std::fs::write(
                    format!("{cgroup}/cgroup.procs"),
                    std::process::id().to_string(),
                )
                .map_err(|error| {
                    std::io::Error::other(format!("cannot join the cgroup {cgroup}: {error}"))
                })
            });
        }
    }
    command.stdin(std::process::Stdio::inherit());
    command.stdout(std::process::Stdio::inherit());
    command.stderr(std::process::Stdio::inherit());

    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!(
                "[RUSTFUN_SANDBOX_ERROR] cannot execute '{}': {error}",
                spec.program
            );
            return std::process::ExitCode::from(72);
        }
    };

    let mut child = child;
    match child.wait() {
        Ok(status) => match status.code() {
            Some(0) => std::process::ExitCode::SUCCESS,
            Some(code) => std::process::ExitCode::from(u8::try_from(code & 0xff).unwrap_or(1)),
            None => {
                // Terminated by a signal: report it the way a shell would, so the caller can
                // tell a timeout kill (SIGKILL/SIGTERM) from an ordinary failure.
                if let Some(signal) = status.signal() {
                    std::process::ExitCode::from(128 + u8::try_from(signal).unwrap_or(0))
                } else {
                    std::process::ExitCode::from(1)
                }
            }
        },
        Err(error) => {
            eprintln!("[RUSTFUN_SANDBOX_ERROR] cannot wait for the payload: {error}");
            std::process::ExitCode::from(71)
        }
    }
}

/// Create the namespaces requested by the spec.
///
/// # Safety-relevant implementation note
///
/// This is the only place besides [`rustfun_sandbox::linux`] that calls `unshare`, and it is
/// deliberately in a separate, single-threaded binary so the kernel accepts `CLONE_NEWPID`.
#[allow(unsafe_code)]
fn apply_namespace(spec: &LauncherSpec) -> Result<(), String> {
    const CLONE_NEWNS: libc::c_int = 0x0002_0000;
    const CLONE_NEWUTS: libc::c_int = 0x0400_0000;
    const CLONE_NEWIPC: libc::c_int = 0x0800_0000;
    const CLONE_NEWPID: libc::c_int = 0x2000_0000;
    const CLONE_NEWNET: libc::c_int = 0x4000_0000;

    const CLONE_NEWUSER: libc::c_int = 0x1000_0000;

    // Prefer the user namespace the parent already created (it installed the id maps on our
    // behalf). When the launcher is started without that setup — for example by a test harness
    // — create it here; the kernel permits a process to map its own ids inside a namespace it
    // just created.
    // SAFETY: `unshare` takes an integer mask and has no memory effects.
    if unsafe { libc::unshare(CLONE_NEWUSER) } == 0 {
        let _ = std::fs::write("/proc/self/setgroups", "deny");
        let _ = std::fs::write("/proc/self/uid_map", format!("0 {}\n", current_uid()));
        let _ = std::fs::write("/proc/self/gid_map", format!("0 {}\n", current_gid()));
    }

    let mut flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS;
    if spec.pid_namespace {
        flags |= CLONE_NEWPID;
    }
    if spec.network_namespace {
        flags |= CLONE_NEWNET;
    }

    // SAFETY: `unshare` takes an integer mask and has no memory effects; the caller is
    // single-threaded, which is the precondition for `CLONE_NEWPID`.
    let rc = unsafe { libc::unshare(flags) };
    if rc != 0 {
        return Err(format!(
            "unshare({flags:#x}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    apply_resource_limits(spec)?;

    // Order matters: `no_new_privs` first (it authorises `PR_SET_SECCOMP` without
    // CAP_SYS_ADMIN), then the seccomp filter, and only then drop the capabilities the
    // namespace setup needed. The payload must never see them.
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1)` takes no pointers.
    if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "cannot set no_new_privs: {}",
            std::io::Error::last_os_error()
        ));
    }

    rustfun_sandbox::linux::apply_post_namespace_controls(spec.seccomp, spec.drop_capabilities)?;
    Ok(())
}

#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: `getuid` has no memory effects.
    unsafe { libc::getuid() }
}

#[allow(unsafe_code)]
fn current_gid() -> u32 {
    // SAFETY: `getgid` has no memory effects.
    unsafe { libc::getgid() }
}

/// Apply the payload's resource limits.
///
/// Limits are inherited across `fork`/`exec`, so applying them here covers the payload too.
/// This launcher is deliberately tiny (it never allocates a large buffer), which keeps
/// `RLIMIT_AS` from affecting the namespace setup itself.
fn apply_resource_limits(spec: &LauncherSpec) -> Result<(), String> {
    use nix::sys::resource::{setrlimit, Resource, RLIM_INFINITY};

    let memory = if spec.memory_bytes == 0 {
        RLIM_INFINITY
    } else {
        spec.memory_bytes
    };
    // `memory` is intentionally unused as an rlimit; see the comment above.
    let _ = memory;
    let files = u64::from(spec.max_open_files);
    let processes = u64::from(spec.max_processes);

    // `setrlimit` failures are not fatal: a container may forbid tightening some limits, and
    // refusing to start because of that would be worse than running with the host's default.
    // Memory is enforced with cgroup v2, not with RLIMIT_AS/RLIMIT_DATA: since Linux 4.7 both
    // count `mmap`, and V8 reserves huge anonymous ranges at startup.
    let _ = &memory;
    let _ = setrlimit(Resource::RLIMIT_NOFILE, files, files);
    let _ = setrlimit(Resource::RLIMIT_NPROC, processes, processes);
    let _ = setrlimit(Resource::RLIMIT_CORE, 0, 0);
    Ok(())
}

/// Ensure stdout is unbuffered so a crash never loses diagnostics.
#[allow(dead_code)]
fn flush_streams() {
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
}
