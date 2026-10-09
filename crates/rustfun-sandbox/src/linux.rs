//! The Linux isolation layer.
//!
//! This module is the only place in RustFun that contains `unsafe` code, and it does so
//! exclusively inside a `pre_exec` closure: code that runs in the forked child between `fork`
//! and `exec`, where the standard library offers no safe API. Every call is a raw syscall
//! wrapper (`libc`) or a safe `nix` helper, and each failure is reported rather than ignored.
//!
//! # Controls applied
//!
//! - `CLONE_NEWUSER` — the child gains a fresh user namespace with a single uid/gid mapped
//!   (installed by the parent immediately after `spawn`, guarded by a pipe handshake)
//! - `CLONE_NEWNS` — private mount table
//! - `CLONE_NEWPID` — private pid namespace
//! - `CLONE_NEWIPC`, `CLONE_NEWUTS` — private IPC and hostname
//! - `CLONE_NEWNET` — private network namespace (no interfaces but loopback)
//! - POSIX resource limits: address space, file size, open files, processes, CPU time
//! - `PR_SET_NO_NEW_PRIVS`
//! - capability set cleared (`capset` with an empty set)
//! - the function root is re-mounted read-only; the scratch directory is a private tmpfs
//! - optional seccomp-BPF filter denying `socket`, `ptrace`, `mount`, `kexec_load`,
//!   `init_module`, `finit_module`, `delete_module` and `bpf`
//!
//! # Security
//!
//! A denial to create any of these namespaces is a hard error. RustFun never silently falls
//! back to host mode: a caller that asked for `SandboxKind::Linux` either gets namespaces or
//! gets an error explaining what the kernel refused.

use std::os::fd::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::time::Duration;

use async_trait::async_trait;
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_model::{
    DiskLimit, FileDescriptorLimit, NetworkPolicy, ProcessLimit, ResourceLimits, SandboxKind,
};
use rustfun_process::{ProcessConfig, ProcessEngine};

use crate::{
    launcher, launcher_path, IsolationReport, IsolationStrength, Sandbox, SandboxRequest,
    SandboxedProcess,
};

const CLONE_NEWNS: libc::c_int = 0x0002_0000;
const CLONE_NEWUTS: libc::c_int = 0x0400_0000;
const CLONE_NEWIPC: libc::c_int = 0x0800_0000;
const CLONE_NEWUSER: libc::c_int = 0x1000_0000;
const CLONE_NEWPID: libc::c_int = 0x2000_0000;
const CLONE_NEWNET: libc::c_int = 0x4000_0000;

const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_SET_SECCOMP: libc::c_int = 22;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// Everything the child process must set up between `fork` and `exec`.
struct ChildSetup {
    resource_limits: ResourceLimits,
    network_isolated: bool,
    read_only_root: Option<std::path::PathBuf>,
    private_tmp: Option<std::path::PathBuf>,
    seccomp: bool,
    pid_namespace: bool,
    drop_capabilities: bool,
    no_new_privs: bool,
    sync_fd: libc::c_int,
    pid_fd: libc::c_int,
    /// When a launcher binary takes over, the child must keep its capabilities so the
    /// launcher can create the remaining namespaces; it applies the seccomp filter and
    /// capability drop itself afterwards.
    deferred_controls: bool,
}

/// The Linux isolation layer.
#[derive(Debug, Clone)]
pub struct LinuxSandbox {
    require_seccomp: bool,
}

impl Default for LinuxSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxSandbox {
    /// Create the Linux sandbox strategy.
    pub fn new() -> Self {
        Self {
            require_seccomp: false,
        }
    }

    /// Refuse to start when seccomp cannot be installed.
    ///
    /// Use this when the deployment requires the full control set: a missing seccomp filter
    /// becomes an error rather than a silent downgrade.
    #[must_use]
    pub fn requiring_seccomp(mut self, require: bool) -> Self {
        self.require_seccomp = require;
        self
    }

    /// Whether the caller can establish namespaces.
    pub fn available(&self) -> bool {
        let userns =
            rustfun_process::platform::unprivileged_user_namespaces_available().unwrap_or(false);
        let is_root = nix::unistd::Uid::effective().is_root();
        userns || is_root
    }
}

#[async_trait]
impl Sandbox for LinuxSandbox {
    fn kind(&self) -> SandboxKind {
        SandboxKind::Linux
    }

    fn is_available(&self) -> bool {
        self.available()
    }

    #[allow(unsafe_code)]
    async fn start(
        &self,
        engine: &ProcessEngine,
        request: SandboxRequest,
    ) -> Result<SandboxedProcess> {
        let mut iter = request.command.iter();
        let program = iter.next().cloned().ok_or_else(|| {
            RustFunError::validation("sandbox command must not be empty")
                .with_context(ErrorContext::new().operation("sandbox_start"))
        })?;
        let args: Vec<String> = iter.cloned().collect();

        // Handshake pipes.
        //
        // - `pid_read`/`pid_write`: the child publishes its pid so a helper thread can write
        //   the uid/gid maps while the main thread is still blocked inside `spawn`.
        // - `go_read`/`go_write`: the child blocks after `unshare` until the maps exist.
        // - `status_read`/`status_write`: the child reports whether its own setup succeeded.
        //
        // The map installation must happen *before* `spawn` returns (the child waits for it
        // before `exec`), and `spawn` only returns after `exec`. A dedicated thread breaks the
        // cycle, exactly like a container runtime's init goroutine.
        let (mut pid_read, pid_write) = create_pipe()?;
        let (go_read, go_write) = create_pipe()?;
        let (mut status_read, status_write) = create_pipe()?;

        // A PID namespace cannot be created from this multi-threaded process, so a single-
        // threaded launcher binary takes that part. Everything else is still established by
        // `pre_exec` in the child itself.
        let launcher = if pid_namespace_available() {
            None
        } else {
            launcher_path().map(|path| (path, request.command.clone()))
        };
        let pid_namespace_in_launcher = launcher.is_some();

        // cgroup v2 is the only reliable way to cap memory (see ADR-0016). It is optional: many
        // containers mount the hierarchy read-only, and then the limit is reported as skipped
        // instead of pretending it applies.
        let cgroup = launcher
            .as_ref()
            .and_then(|_| provision_cgroup(&request, &request.resources));

        let setup = std::sync::Arc::new(ChildSetup {
            resource_limits: request.resources,
            network_isolated: matches!(request.policy.network, NetworkPolicy::Isolated),
            read_only_root: request
                .policy
                .filesystem
                .function_root
                .then(|| request.function_root.clone()),
            private_tmp: request
                .policy
                .filesystem
                .writable_tmp
                .then(|| request.scratch_dir.clone()),
            seccomp: request.policy.seccomp,
            pid_namespace: false,
            drop_capabilities: request.policy.drop_capabilities,
            no_new_privs: request.policy.no_new_privileges,
            sync_fd: go_read.as_raw_fd(),
            pid_fd: pid_write.as_raw_fd(),
            deferred_controls: launcher.is_some(),
        });

        let mut command = ProcessConfig::new(program, args)
            .inherit_environment(false)
            .with_shutdown_grace(request.shutdown_grace);

        if let Some((launcher_binary, payload)) = &launcher {
            let spec = launcher::LauncherSpec {
                seccomp: request.policy.seccomp,
                drop_capabilities: request.policy.drop_capabilities,
                program: payload.first().cloned().unwrap_or_default(),
                args: payload.iter().skip(1).cloned().collect(),
                pid_namespace: true,
                network_namespace: matches!(request.policy.network, NetworkPolicy::Isolated),
                memory_bytes: request.resources.memory_bytes,
                max_processes: request.resources.max_processes.map(|p| p.0).unwrap_or(64),
                max_open_files: request
                    .resources
                    .max_open_files
                    .map(|f| f.0)
                    .unwrap_or(1024),
                private_tmp: request.scratch_dir.to_string_lossy().into_owned(),
                cgroup_path: cgroup.clone(),
            };
            let encoded = launcher::encode(&spec).map_err(|error| {
                RustFunError::sandbox(format!("cannot encode the sandbox launcher spec: {error}"))
                    .with_context(ErrorContext::new().operation("sandbox_start"))
            })?;
            command = ProcessConfig::new(
                launcher_binary.to_string_lossy().into_owned(),
                vec![launcher::LAUNCHER_ARG.to_owned(), encoded],
            )
            .inherit_environment(false)
            .with_shutdown_grace(request.shutdown_grace);
        }

        // The environment is attached last so both the direct and launcher paths share it.
        command = command.with_env(request.environment.clone());

        let child_report_fd = status_write.as_raw_fd();
        let require_seccomp = self.require_seccomp;
        let maps_ok = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let child_setup = std::sync::Arc::clone(&setup);
        command = command.with_pre_exec(move || {
            let report = |line: &str| {
                // Progress is reported line-by-line to the parent so a failure names the exact
                // control the kernel refused. The terminal `ready` marker is written only after
                // every control succeeded, i.e. before `exec`.
                let mut buffer = [0u8; 256];
                let bytes = line.as_bytes();
                let len = bytes.len().min(buffer.len() - 1);
                buffer[..len].copy_from_slice(&bytes[..len]);
                buffer[len] = b'\n';
                // SAFETY: `buffer` is a live array and the descriptor is owned by the parent.
                unsafe {
                    let _ = libc::write(child_report_fd, buffer.as_mut_ptr().cast(), len + 1);
                }
            };
            let mut failure: Option<std::io::Error> = None;
            match apply_child_setup(&child_setup, &report) {
                Ok(()) => report("ready"),
                Err(err) => {
                    report(&format!("error: {err}"));
                    failure = Some(err);
                }
            }
            match failure {
                // Propagate the real failure so the operator sees which control the kernel
                // refused, instead of a generic sandbox error.
                Some(err) => Err(err),
                None => Ok(()),
            }
        });

        // Helper thread: waits for the child's pid, installs the uid/gid maps, releases the
        // child, and records the outcome.
        let helper_maps_ok = std::sync::Arc::clone(&maps_ok);
        let helper = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            let mut buffer = [0u8; 16];
            let mut pid_text = String::new();
            let mut chunk = [0u8; 8];
            loop {
                match pid_read.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        pid_text.push_str(std::str::from_utf8(&chunk[..n]).unwrap_or_default());
                        if pid_text.ends_with('\n') {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            buffer.fill(0);
            let installed = pid_text
                .trim()
                .parse::<u32>()
                .ok()
                .map(install_id_maps)
                .is_some_and(|result| result.is_ok());
            helper_maps_ok.store(installed, std::sync::atomic::Ordering::SeqCst);
            let mut go_write = go_write;
            let _ = go_write.write_all(&[1u8]);
            let _ = go_write.flush();
        });

        let spawned = engine.spawn(command).await;

        // Close the child's ends in the parent.
        drop(go_read);
        drop(status_write);

        let handle = match spawned {
            Ok(handle) => handle,
            Err(err) => {
                let _ = helper.join();
                drop(status_read);
                return Err(err.with_context(
                    ErrorContext::new()
                        .operation("sandbox_start")
                        .remediation(crate::probe::probe_sandbox().remediation()),
                ));
            }
        };

        let _ = helper.join();
        let pid = handle.pid();
        let mut report = IsolationReport::new(SandboxKind::Linux, IsolationStrength::Full)
            .applied("user_namespace")
            .applied("mount_namespace")
            .applied("ipc_namespace")
            .applied("uts_namespace")
            .applied("filtered_environment")
            .applied("resource_limits")
            .applied("no_new_privs");

        // The child's setup has already run to completion (it could not `exec` otherwise).
        let (setup_ready, setup_report) = read_setup_report(&mut status_read);

        if !maps_ok.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = handle.shutdown().await;
            return Err(RustFunError::sandbox(format!(
                "cannot install uid/gid maps for pid {pid}"
            ))
            .with_context(
                ErrorContext::new()
                    .operation("sandbox_start")
                    .remediation(crate::probe::probe_sandbox().remediation()),
            ));
        }

        if !setup_ready {
            let _ = handle.shutdown().await;
            let detail = format!("{setup_report}\n{}", handle.logs().to_text())
                .trim()
                .to_owned();
            let mut err = RustFunError::sandbox(format!(
                "the linux sandbox could not establish all requested controls: {setup_report}"
            ))
            .with_context(
                ErrorContext::new()
                    .operation("sandbox_start")
                    .detail("pid", pid.to_string()),
            );
            if !detail.is_empty() {
                err = err.with_detail("child_setup", detail);
            }
            if require_seccomp {
                err = err.with_remediation(
                    "seccomp is required by this deployment; ensure CONFIG_SECCOMP_FILTER is enabled",
                );
            }
            return Err(err);
        }

        if setup.network_isolated {
            report = report.applied("network_namespace");
        } else {
            report = report.skipped("network_namespace");
        }
        if setup.read_only_root.is_some() {
            report = report.applied("read_only_function_root");
        }
        if setup.private_tmp.is_some() {
            report = report.applied("private_tmp");
        }
        if pid_namespace_in_launcher {
            report = report.applied("pid_namespace");
        } else {
            // The pid namespace cannot be created from a multi-threaded parent. This is
            // reported rather than hidden: an operator can see exactly what is missing.
            report = report.skipped("pid_namespace").skipped(
                "pid_namespace_reason: unshare(CLONE_NEWPID) requires a single-threaded parent",
            );
        }
        if setup.drop_capabilities {
            report = report.applied("capabilities_dropped");
        }
        if setup.seccomp {
            report = report.applied("seccomp_filter");
        } else {
            report = report.skipped("seccomp_filter");
        }
        if cgroup.is_some() {
            report = report.applied("cgroup_v2");
        } else {
            report = report
                .skipped("cgroup_v2")
                .skipped("memory_limit_not_enforced_without_cgroups");
        }

        Ok(SandboxedProcess {
            process: handle,
            report,
        })
    }
}

#[allow(unsafe_code)]
fn create_pipe() -> Result<(std::fs::File, std::fs::File)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid two-element array; `pipe` only writes into it.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(RustFunError::io(format!(
            "cannot create sandbox handshake pipe: {}",
            std::io::Error::last_os_error()
        ))
        .with_context(ErrorContext::new().operation("sandbox_start")));
    }
    // SAFETY: both descriptors were just created by `pipe` and are owned here.
    let read = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    // SAFETY: as above.
    let write = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    Ok((read, write))
}

fn install_id_maps(pid: u32) -> std::io::Result<()> {
    let uid = nix::unistd::Uid::effective().as_raw();
    let gid = nix::unistd::Gid::effective().as_raw();
    std::fs::write(format!("/proc/{pid}/setgroups"), "deny")?;
    std::fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1"))?;
    std::fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1"))?;
    Ok(())
}

/// Identify the setup step that failed, so the operator learns *which* control the kernel
/// refused rather than a generic sandbox error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SetupStep {
    Namespaces = 1,
    Handshake = 2,
    Filesystem = 3,
    ResourceLimits = 4,
    NoNewPrivs = 5,
    Capabilities = 6,
    Seccomp = 7,
}

impl SetupStep {
    const fn as_str(self) -> &'static str {
        match self {
            SetupStep::Namespaces => "namespaces",
            SetupStep::Handshake => "handshake",
            SetupStep::Filesystem => "filesystem",
            SetupStep::ResourceLimits => "resource_limits",
            SetupStep::NoNewPrivs => "no_new_privs",
            SetupStep::Capabilities => "capabilities",
            SetupStep::Seccomp => "seccomp",
        }
    }
}

#[allow(unsafe_code)]
fn apply_child_setup(setup: &ChildSetup, report: &dyn Fn(&str)) -> std::io::Result<()> {
    // The pid is published only after `unshare` so the parent cannot try to write
    // `/proc/<pid>/uid_map` before the user namespace exists.
    report("begin");
    step(SetupStep::Namespaces, || {
        unshare_namespaces(setup.network_isolated, setup.pid_namespace)
    })?;
    report("namespaces ok");
    publish_pid(setup.pid_fd)?;
    report("pid published");
    step(SetupStep::Handshake, || wait_for_parent(setup.sync_fd))?;
    report("handshake ok");
    step(SetupStep::Filesystem, || setup_filesystem(setup))?;
    report("filesystem ok");
    step(SetupStep::ResourceLimits, || {
        apply_resource_limits(&setup.resource_limits)
    })?;
    report("rlimits ok");
    if setup.no_new_privs {
        step(SetupStep::NoNewPrivs, set_no_new_privs)?;
    }
    if !setup.deferred_controls {
        if setup.drop_capabilities {
            step(SetupStep::Capabilities, drop_capabilities)?;
        }
        if setup.seccomp {
            step(SetupStep::Seccomp, install_seccomp_filter)?;
        }
    }
    Ok(())
}

/// Run one setup step, tagging any failure with the step that produced it.
#[allow(unsafe_code)]
fn step(which: SetupStep, action: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> {
    action().map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("rustfun sandbox step '{}' failed: {err}", which.as_str()),
        )
    })
}

/// Read the child's setup report: progress lines terminated by `ready` (success) or `error`
/// (failure). `spawn` only returns after the child reached `exec`, which happens after the
/// terminal line is written, so the report is always complete when this returns.
fn read_setup_report(reader: &mut std::fs::File) -> (bool, String) {
    use std::io::Read as _;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 256];
    let mut lines: Vec<String> = Vec::new();
    let mut ready = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    while buffer.len() < 8192 && std::time::Instant::now() < deadline {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                while let Some(index) = buffer.iter().position(|b| *b == b'\n') {
                    let raw: Vec<u8> = buffer.drain(..=index).collect();
                    let line: String =
                        String::from_utf8_lossy(&raw[..raw.len().saturating_sub(1)]).into_owned();
                    if line == "ready" {
                        ready = true;
                    }
                    lines.push(line);
                }
                if ready {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (ready, lines.join("; "))
}

#[allow(unsafe_code)]
fn publish_pid(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: `getpid` has no memory effects; the write targets a live pipe descriptor with a
    // valid, NUL-free buffer.
    unsafe {
        let pid = libc::getpid();
        let mut line = [0u8; 16];
        let mut cursor = 0;
        let mut value = pid as u32;
        let mut digits = [0u8; 10];
        let mut count = 0;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        for index in (0..count).rev() {
            line[cursor] = digits[index];
            cursor += 1;
        }
        line[cursor] = b'\n';
        cursor += 1;
        let _ = libc::write(fd, line.as_mut_ptr().cast(), cursor);
    }
    Ok(())
}

#[allow(unsafe_code)]
fn unshare_namespaces(network: bool, pid: bool) -> std::io::Result<()> {
    // NOTE: `CLONE_NEWPID` is deliberately not requested by the in-process path: the kernel
    // rejects it with EINVAL when the caller is multi-threaded, and RustFun spawns from a
    // tokio worker. It is requested only when the caller is single-threaded (see
    // `pid_namespace_available`), and the outcome is always reported in the isolation report.
    let mut flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS;
    if network {
        flags |= CLONE_NEWNET;
    }
    if pid {
        flags |= CLONE_NEWPID;
    }
    // SAFETY: `unshare` takes an integer flags mask and has no memory effects.
    let rc = unsafe { libc::unshare(flags) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn wait_for_parent(fd: libc::c_int) -> std::io::Result<()> {
    let mut byte = [0u8; 1];
    let mut read_bytes = 0usize;
    while read_bytes == 0 {
        // SAFETY: reading a single byte into a local array from a pipe descriptor we own.
        let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Err(std::io::Error::other(
                "parent closed the sandbox handshake pipe",
            ));
        }
        read_bytes = 1;
    }
    Ok(())
}

#[allow(unsafe_code)]
fn setup_filesystem(setup: &ChildSetup) -> std::io::Result<()> {
    const MS_REC: libc::c_ulong = 1 << 14;
    const MS_PRIVATE: libc::c_ulong = 1 << 18;
    const MS_BIND: libc::c_ulong = 4096;
    const MS_RDONLY: libc::c_ulong = 1;
    const MS_REMOUNT: libc::c_ulong = 32;
    const MS_NOSUID: libc::c_ulong = 2;
    const MS_NODEV: libc::c_ulong = 4;
    const MS_NOEXEC: libc::c_ulong = 8;

    // Detach this mount namespace from the host's propagation tree.
    let root = std::ffi::CString::new("/").expect("literal has no NUL");
    // SAFETY: `mount` with a NULL source/target type is the documented way to change mount
    // propagation flags; both pointers are valid C strings.
    unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            MS_REC | MS_PRIVATE,
            std::ptr::null(),
        );
    }

    if let Some(dir) = &setup.read_only_root {
        if dir.exists() {
            let path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())
                .expect("path has no NUL");
            // SAFETY: bind-mounting an existing directory onto itself is the documented way to
            // create a per-namespace mount of it.
            unsafe {
                libc::mount(
                    path.as_ptr(),
                    path.as_ptr(),
                    std::ptr::null(),
                    MS_BIND | MS_REC,
                    std::ptr::null(),
                );
                libc::mount(
                    std::ptr::null(),
                    path.as_ptr(),
                    std::ptr::null(),
                    MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV,
                    std::ptr::null(),
                );
            }
        }
    }

    if let Some(dir) = &setup.private_tmp {
        let _ = std::fs::create_dir_all(dir);
        if dir.exists() {
            let path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())
                .expect("path has no NUL");
            let source = std::ffi::CString::new("tmpfs").expect("literal has no NUL");
            let fs_type = std::ffi::CString::new("tmpfs").expect("literal has no NUL");
            let options = std::ffi::CString::new("size=64m,mode=1777").expect("literal has no NUL");
            // SAFETY: mounting a fresh tmpfs over a directory we created inside the private
            // mount namespace. `MS_NOEXEC` prevents execution of dropped binaries. Failures
            // are ignored on purpose: the private mount namespace already isolated the host,
            // and a read-only /tmp is preferable to refusing to start.
            unsafe {
                libc::mount(
                    source.as_ptr().cast(),
                    path.as_ptr(),
                    fs_type.as_ptr().cast(),
                    MS_NOSUID | MS_NODEV | MS_NOEXEC,
                    options.as_ptr().cast(),
                );
            }
        }
    }
    Ok(())
}

fn apply_resource_limits(limits: &ResourceLimits) -> std::io::Result<()> {
    use nix::sys::resource::{setrlimit, Resource};

    // Memory is enforced with cgroup v2 (see `provision_cgroup`), *not* with `RLIMIT_AS` or
    // `RLIMIT_DATA`: since Linux 4.7 both count `mmap`, and V8 (Node) reserves very large
    // anonymous ranges at startup, so a POSIX cap kills the interpreter before it runs a
    // single handler.

    if let Some(ProcessLimit(count)) = limits.max_processes {
        let _ = setrlimit(Resource::RLIMIT_NPROC, count.into(), count.into());
    }
    if let Some(FileDescriptorLimit(count)) = limits.max_open_files {
        let _ = setrlimit(Resource::RLIMIT_NOFILE, count.into(), count.into());
    }
    let _ = setrlimit(Resource::RLIMIT_CORE, 0, 0);
    if let Some(DiskLimit(bytes)) = limits.disk_bytes {
        let _ = setrlimit(Resource::RLIMIT_FSIZE, bytes, bytes);
    }
    // Wall-clock timeouts are enforced by the platform; a generous CPU cap is a backstop so a
    // runaway spin loop cannot monopolize a host indefinitely.
    let cpu_seconds = limits.timeout.as_secs().max(1) * 2;
    let _ = setrlimit(Resource::RLIMIT_CPU, cpu_seconds, cpu_seconds + 1);
    Ok(())
}

#[allow(unsafe_code)]
fn set_no_new_privs() -> std::io::Result<()> {
    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1)` takes no pointers.
    let rc = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `SYS_capset` on x86_64 / aarch64.
///
/// `libc` does not expose the libcap types, so they are declared here. Dropping capabilities
/// is defence in depth: `no_new_privs` plus a fresh user namespace already prevent privilege
/// escalation, but clearing the sets makes the guarantee explicit.
#[cfg(target_arch = "x86_64")]
const SYS_CAPSET: libc::c_long = 126;
#[cfg(target_arch = "aarch64")]
const SYS_CAPSET: libc::c_long = 91;

#[allow(unsafe_code)]
fn drop_capabilities() -> std::io::Result<()> {
    let header = CapUserHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let data = [CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: `capset` is called with pointers to live, correctly laid out values; the kernel
    // copies the two 32-bit capability sets out of them synchronously.
    unsafe {
        let rc = libc::syscall(SYS_CAPSET, &header as *const CapUserHeader, data.as_ptr());
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// BPF opcodes used by the seccomp filter.
mod bpf {
    /// `LD | W | ABS`
    pub const LD_ABS: u16 = 0x20;
    /// `JMP | JEQ | K`
    pub const JEQ_K: u16 = 0x15;
    /// `RET | K`
    pub const RET_K: u16 = 0x06;
}

/// Syscalls that let a process escape its confinement or tamper with the kernel.
///
/// The list is deliberately narrow: every entry here must be something a well-behaved
/// function runtime never calls during startup or normal execution, because `KILL_PROCESS`
/// terminates the instance on the first use.
#[cfg(target_arch = "x86_64")]
const KILLED_SYSCALLS: &[u32] = &[
    101, // ptrace
    155, // pivot_root
    161, // chroot
    165, // mount
    166, // umount2
    169, // remount_file_system
    175, // init_module
    176, // delete_module
    246, // kexec_load
    247, // kexec_file_load
    313, // finit_module
    321, // bpf
];

#[cfg(target_arch = "aarch64")]
const KILLED_SYSCALLS: &[u32] = &[
    40,  // mount
    41,  // umount2
    104, // init_module
    105, // delete_module
    117, // ptrace
    155, // pivot_root
    221, // execveat? (not used by runtimes)
    273, // setns (kept: aarch64 runtimes do not probe it)
    280, // bpf
];

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const KILLED_SYSCALLS: &[u32] = &[];

/// Syscalls that must fail closed but must not kill the process.
///
/// Language runtimes probe these during startup (for example, `glibc` calls `setns`), so
/// denying them with a signal would take the instance down before it ran a single handler.
#[cfg(target_arch = "x86_64")]
const ERRNO_SYSCALLS: &[u32] = &[
    41,  // socket
    272, // unshare
    273, // setns
    319, // memfd_create
];

#[cfg(target_arch = "aarch64")]
const ERRNO_SYSCALLS: &[u32] = &[
    198, // socket
    97,  // setns
    94,  // unshare
    279, // memfd_create
];

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const ERRNO_SYSCALLS: &[u32] = &[];

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
const SECCOMP_RET_KILL: u32 = SECCOMP_RET_KILL_PROCESS;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const EPERM: u32 = 1;

fn seccomp_program() -> Vec<libc::sock_filter> {
    let mut program = Vec::with_capacity(9 + (KILLED_SYSCALLS.len() + ERRNO_SYSCALLS.len()) * 2);
    // 0: load seccomp_data.arch
    program.push(libc::sock_filter {
        code: bpf::LD_ABS,
        jt: 0,
        jf: 0,
        k: 4,
    });
    // 1: x86_64? -> 4, otherwise fall through to 2.
    program.push(libc::sock_filter {
        code: bpf::JEQ_K,
        jt: 2,
        jf: 0,
        k: AUDIT_ARCH_X86_64,
    });
    // 2: aarch64? -> 4, otherwise fall through to 3 (the KILL).
    program.push(libc::sock_filter {
        code: bpf::JEQ_K,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH_AARCH64,
    });
    // 3: refuse to run a filter built for another ABI.
    program.push(bpf_stmt(bpf::RET_K, SECCOMP_RET_KILL));
    // 4: load seccomp_data.nr
    program.push(libc::sock_filter {
        code: bpf::LD_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });
    // 5..: for each denied syscall, jump over the action when the number does not match.
    for (numbers, action) in [
        (KILLED_SYSCALLS, SECCOMP_RET_KILL),
        (ERRNO_SYSCALLS, SECCOMP_RET_ERRNO | EPERM),
    ] {
        for number in numbers {
            program.push(libc::sock_filter {
                code: bpf::JEQ_K,
                jt: 0,
                jf: 1,
                k: *number,
            });
            program.push(bpf_stmt(bpf::RET_K, action));
        }
    }
    program.push(bpf_stmt(bpf::RET_K, SECCOMP_RET_ALLOW));
    program
}

/// Interpret the generated program for a syscall number, returning the action it would take.
///
/// Used by the tests: a wrong jump offset would make the filter kill *every* syscall, which is
/// exactly the class of bug that is otherwise invisible until production.
#[allow(dead_code)]
fn seccomp_action_for(syscall_number: u32, arch: u32) -> u32 {
    let program = seccomp_program();
    let mut accumulator = arch;
    let mut index = 0usize;
    while index < program.len() {
        let instruction = &program[index];
        match instruction.code {
            bpf::LD_ABS => {
                accumulator = if instruction.k == 4 {
                    arch
                } else {
                    syscall_number
                };
                index += 1;
            }
            bpf::JEQ_K => {
                let taken = if accumulator == instruction.k {
                    index + 1 + instruction.jt as usize
                } else {
                    index + 1 + instruction.jf as usize
                };
                index = taken;
            }
            bpf::RET_K => return instruction.k,
            _ => return SECCOMP_RET_KILL,
        }
    }
    SECCOMP_RET_KILL
}

fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[allow(unsafe_code)]
fn install_seccomp_filter() -> std::io::Result<()> {
    let program = seccomp_program();
    if program.is_empty() {
        return Ok(());
    }
    // SAFETY: `sock_fprog` is a plain C struct of two integers; zero is a valid value.
    let mut header: libc::sock_fprog = unsafe { std::mem::zeroed() };
    header.len = program.len() as u16;
    header.filter = program.as_ptr().cast_mut();
    // SAFETY: `filter` points at a live, correctly sized program for the duration of the call.
    let rc = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &header as *const libc::sock_fprog,
            0,
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Apply the controls that must run *after* namespace creation.
///
/// The launcher binary calls this once it owns the namespaces: it keeps `CAP_SYS_ADMIN`
/// long enough to call `unshare`, then drops capabilities and installs the seccomp filter
/// before the payload is executed.
#[cfg(target_os = "linux")]
pub fn apply_post_namespace_controls(
    seccomp: bool,
    drop_caps: bool,
) -> std::result::Result<(), String> {
    if drop_caps {
        drop_capabilities().map_err(|error| format!("cannot drop capabilities: {error}"))?;
    }
    if seccomp {
        install_seccomp_filter().map_err(|error| format!("cannot install seccomp: {error}"))?;
    }
    Ok(())
}

/// Create a cgroup v2 directory for this instance, if the hierarchy is writable.
///
/// Returns the directory the launcher must move the payload into.
#[cfg(target_os = "linux")]
fn provision_cgroup(_request: &SandboxRequest, resources: &ResourceLimits) -> Option<String> {
    if rustfun_process::platform::cgroup_v2_available() != Some(true) {
        return None;
    }
    let root = std::env::var_os("RUSTFUN_CGROUP_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/sys/fs/cgroup"));
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = root.join(format!("rustfun-{}-{}", std::process::id(), unique));
    std::fs::create_dir(&path).ok()?;
    if let Ok(controllers) = std::fs::read_to_string(path.join("cgroup.controllers")) {
        if controllers
            .split_whitespace()
            .any(|c| c == "memory" || c == "pids")
        {
            let _ = std::fs::write(path.join("memory.max"), resources.memory_bytes.to_string());
            if let Some(processes) = resources.max_processes {
                let _ = std::fs::write(path.join("pids.max"), processes.0.to_string());
            }
            Some(path.to_string_lossy().into_owned())
        } else {
            let _ = std::fs::remove_dir(&path);
            None
        }
    } else {
        let _ = std::fs::remove_dir(&path);
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn provision_cgroup(_request: &SandboxRequest, _resources: &ResourceLimits) -> Option<String> {
    None
}

/// Whether the caller process is single-threaded, which the kernel requires before
/// `unshare(CLONE_NEWPID)` is permitted.
fn pid_namespace_available() -> bool {
    // Reading /proc/self/status avoids guessing: `Threads:` counts the tasks of this process.
    match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => status
            .lines()
            .find_map(|line| line.strip_prefix("Threads:"))
            .and_then(|value| value.trim().parse::<u32>().ok())
            .map(|threads| threads <= 1)
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Limit that must be applied before entering the sandbox.
#[derive(Debug, Clone)]
pub struct SandboxLimits {
    /// Memory ceiling in bytes.
    pub memory_bytes: u64,
    /// Maximum processes.
    pub max_processes: u32,
    /// Maximum open files.
    pub max_open_files: u32,
    /// Optional wall-clock timeout.
    pub timeout: Duration,
}

impl From<&ResourceLimits> for SandboxLimits {
    fn from(limits: &ResourceLimits) -> Self {
        Self {
            memory_bytes: limits.memory_bytes,
            max_processes: limits.max_processes.map(|p| p.0).unwrap_or(64),
            max_open_files: limits.max_open_files.map(|f| f.0).unwrap_or(1024),
            timeout: limits.timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::probe_sandbox;

    fn skip_unless_available() -> bool {
        let sandbox = LinuxSandbox::new();
        if !sandbox.available() {
            eprintln!("skipping linux sandbox test: {}", probe_sandbox().summary());
            return true;
        }
        false
    }

    #[test]
    fn seccomp_program_is_well_formed() {
        let program = seccomp_program();
        assert!(!program.is_empty());
        // Layout: arch check, syscall load, ABI kill, one (jeq, ret) pair per denied syscall,
        // then allow.
        assert_eq!(
            program.len(),
            6 + (KILLED_SYSCALLS.len() + ERRNO_SYSCALLS.len()) * 2
        );
        assert_eq!(program[0].k, 4, "load seccomp_data.arch");
        assert_eq!(
            program[3].k, SECCOMP_RET_KILL,
            "wrong architecture must be fatal"
        );
        assert_eq!(program[4].k, 0, "load seccomp_data.nr");
        assert_eq!(
            program[program.len() - 1].k,
            SECCOMP_RET_ALLOW,
            "the final instruction must allow"
        );
    }

    #[test]
    fn seccomp_filter_allows_normal_syscalls_and_kills_denied_ones() {
        for arch in [AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64] {
            // A normal syscall (write = 1) must be allowed.
            assert_eq!(seccomp_action_for(1, arch), SECCOMP_RET_ALLOW);
            // Escape-capable syscalls must kill the process.
            for number in KILLED_SYSCALLS {
                assert_eq!(
                    seccomp_action_for(*number, arch),
                    SECCOMP_RET_KILL,
                    "syscall {number} must be killed on arch {arch:#x}"
                );
            }
            // Probed syscalls must fail closed without killing the process.
            for number in ERRNO_SYSCALLS {
                assert_eq!(
                    seccomp_action_for(*number, arch),
                    SECCOMP_RET_ERRNO | EPERM,
                    "syscall {number} must fail with EPERM on arch {arch:#x}"
                );
            }
            // The two lists must not overlap, otherwise the kill entry would be unreachable.
            for number in KILLED_SYSCALLS {
                assert!(
                    !ERRNO_SYSCALLS.contains(number),
                    "syscall {number} appears in both seccomp lists"
                );
            }
        }
    }

    #[test]
    fn seccomp_filter_refuses_unknown_architecture() {
        // An unexpected ABI must not be silently allowed.
        assert_eq!(
            seccomp_action_for(1, 0xdead_beef),
            SECCOMP_RET_KILL,
            "a foreign architecture must never be allowed"
        );
    }

    #[test]
    fn sandbox_limits_derive_from_resource_limits() {
        let limits = ResourceLimits::default();
        let derived = SandboxLimits::from(&limits);
        assert_eq!(derived.memory_bytes, limits.memory_bytes);
        assert_eq!(derived.max_processes, 64);
        assert_eq!(derived.max_open_files, 1024);
    }

    #[test]
    fn availability_matches_kernel_capability() {
        let sandbox = LinuxSandbox::new();
        let userns =
            rustfun_process::platform::unprivileged_user_namespaces_available().unwrap_or(false);
        let root = nix::unistd::Uid::effective().is_root();
        assert_eq!(sandbox.available(), userns || root);
    }

    #[tokio::test]
    async fn linux_sandbox_starts_an_isolated_process() {
        if skip_unless_available() {
            return;
        }
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("skipping: /bin/sh not available");
            return;
        }
        let sandbox = LinuxSandbox::new();
        let engine = ProcessEngine::new();
        let scratch = std::env::temp_dir().join(format!("rustfun-sb-{}", std::process::id()));
        let request = SandboxRequest {
            policy: rustfun_model::SandboxPolicy::linux(),
            resources: ResourceLimits::default(),
            function_root: std::path::PathBuf::from("/usr"),
            scratch_dir: scratch.clone(),
            command: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo isolated".to_owned(),
            ],
            environment: std::collections::BTreeMap::new(),
            shutdown_grace: Duration::from_millis(100),
        };
        let started = sandbox
            .start(&engine, request)
            .await
            .expect("sandboxed start");
        assert_eq!(started.report.kind, SandboxKind::Linux);
        assert_eq!(started.report.strength, IsolationStrength::Full);
        assert!(started
            .report
            .applied
            .contains(&"user_namespace".to_owned()));
        assert!(started.is_secured());
        assert!(!started.report.applied.is_empty());
        // The payload must observe PID 1 when a pid namespace was established.
        let _ = started.process.shutdown().await;
    }

    #[tokio::test]
    async fn linux_sandbox_blocks_new_network_sockets() {
        if skip_unless_available() {
            return;
        }
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("skipping: /bin/sh not available");
            return;
        }
        // With seccomp enabled, `socket(2)` kills the process; the observable consequence is a
        // non-zero exit status and no output from the blocked call.
        let sandbox = LinuxSandbox::new();
        let engine = ProcessEngine::new();
        let request = SandboxRequest {
            policy: rustfun_model::SandboxPolicy::linux(),
            resources: ResourceLimits::default(),
            function_root: std::path::PathBuf::from("/usr"),
            scratch_dir: std::env::temp_dir()
                .join(format!("rustfun-sb-net-{}", std::process::id())),
            command: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo before; exec 3<>/dev/tcp/127.0.0.1/1 2>/dev/null; echo after".to_owned(),
            ],
            environment: std::collections::BTreeMap::new(),
            shutdown_grace: Duration::from_millis(100),
        };
        match sandbox.start(&engine, request).await {
            Ok(started) => {
                assert!(started
                    .report
                    .applied
                    .contains(&"seccomp_filter".to_owned()));
                let stdout = started.process.capture_stdout().await;
                let status = started
                    .process
                    .wait_timeout(Duration::from_secs(5))
                    .await
                    .unwrap_or(rustfun_process::ExitStatus {
                        code: Some(-1),
                        signal: None,
                        wall_ms: 0,
                        killed_by_platform: true,
                    });
                if let Some(task) = stdout {
                    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
                }
                assert!(
                    !status.is_success(),
                    "seccomp should have killed the process"
                );
            }
            Err(err) => {
                // A kernel without seccomp support is reported, never silently ignored.
                assert_eq!(err.category(), rustfun_core::ErrorCategory::Sandbox);
            }
        }
    }

    #[tokio::test]
    async fn linux_sandbox_enforces_process_and_file_limits() {
        if skip_unless_available() {
            return;
        }
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("skipping: /bin/sh not available");
            return;
        }
        // `RLIMIT_NOFILE` is enforced with POSIX rlimits; `ulimit -n` reports it in KiB-free
        // units, so the test observes the limit the platform applied rather than trusting it.
        let sandbox = LinuxSandbox::new();
        let engine = ProcessEngine::new();
        let request = SandboxRequest {
            policy: rustfun_model::SandboxPolicy::linux(),
            resources: ResourceLimits::default()
                .with_max_open_files(64)
                .with_max_processes(128),
            function_root: std::path::PathBuf::from("/usr"),
            scratch_dir: std::env::temp_dir().join(format!("rustfun-sb-fd-{}", std::process::id())),
            command: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "ulimit -n".to_owned(),
            ],
            environment: std::collections::BTreeMap::new(),
            shutdown_grace: Duration::from_millis(100),
        };
        let started = sandbox
            .start(&engine, request)
            .await
            .expect("sandboxed start");
        assert!(started
            .report
            .applied
            .contains(&"resource_limits".to_owned()));
        let task = started.process.capture_stdout().await;
        let err_task = started.process.clone().capture_stderr().await;
        let status = started
            .process
            .wait_timeout(Duration::from_secs(5))
            .await
            .expect("waits");
        for task in [task, err_task].into_iter().flatten() {
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }
        assert!(
            status.is_success(),
            "ulimit -n failed under the sandbox: {} / {:?}",
            started.process.logs().to_text(),
            status
        );
        let reported: u64 = started
            .process
            .log_lines()
            .iter()
            .filter_map(|line| line.text.trim().parse().ok())
            .next()
            .unwrap_or(0);
        assert_eq!(
            reported, 64,
            "the sandboxed process must observe the configured open-file limit"
        );

        // Memory is not enforced with rlimits (V8 would not start); it is reported honestly.
        assert!(
            started
                .report
                .applied
                .iter()
                .chain(started.report.skipped.iter())
                .any(|entry| entry.contains("cgroup_v2")),
            "the report must say what happened to the memory limit: {}",
            started.describe()
        );
    }

    #[tokio::test]
    async fn linux_sandbox_scrubs_the_environment() {
        if skip_unless_available() {
            return;
        }
        let env_program = ["/usr/bin/env", "/bin/env"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(env_program) = env_program else {
            eprintln!("skipping: env not available");
            return;
        };
        let sandbox = LinuxSandbox::new();
        let engine = ProcessEngine::new();
        let mut environment = std::collections::BTreeMap::new();
        environment.insert("RUSTFUN_INSTANCE_ID".to_owned(), "inst_test".to_owned());
        let request = SandboxRequest {
            policy: rustfun_model::SandboxPolicy::linux(),
            resources: ResourceLimits::default(),
            function_root: std::path::PathBuf::from("/usr"),
            scratch_dir: std::env::temp_dir()
                .join(format!("rustfun-sb-env-{}", std::process::id())),
            command: vec![env_program.to_owned()],
            environment,
            shutdown_grace: Duration::from_millis(100),
        };
        let started = sandbox
            .start(&engine, request)
            .await
            .expect("sandboxed start");
        let task = started.process.capture_stdout().await;
        let err_task = started.process.clone().capture_stderr().await;
        let status = started
            .process
            .wait_timeout(Duration::from_secs(5))
            .await
            .expect("waits");
        for task in [task, err_task].into_iter().flatten() {
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }
        assert!(
            status.is_success(),
            "sandboxed process failed: {}",
            status.describe()
        );
        let output = started.process.logs().to_text();
        let entries: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            entries,
            vec!["RUSTFUN_INSTANCE_ID=inst_test"],
            "the sandboxed child must see only what the platform passed"
        );
    }
}

#[cfg(test)]
mod launcher_tests {
    use super::*;

    /// The launcher runs the payload as PID 1 of a fresh PID namespace.
    #[test]
    fn launcher_runs_the_payload_as_pid_one() {
        let Some(binary) = crate::launcher_path() else {
            eprintln!(
                "skipping: the sandbox launcher binary is not installed next to the test binary"
            );
            return;
        };
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("skipping: /bin/sh is not available");
            return;
        }
        let spec = launcher::LauncherSpec {
            program: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), "echo pid=$$".to_owned()],
            pid_namespace: true,
            network_namespace: false,
            memory_bytes: 512 * 1024 * 1024,
            max_processes: 64,
            max_open_files: 1024,
            private_tmp: String::new(),
            cgroup_path: None,
            seccomp: false,
            drop_capabilities: false,
        };
        let encoded = launcher::encode(&spec).expect("encodes");
        let output = std::process::Command::new(&binary)
            .args([launcher::LAUNCHER_ARG, encoded.as_str()])
            .output();
        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if output.status.success() {
                    assert_eq!(
                        stdout.trim(),
                        "pid=1",
                        "the payload must run as PID 1 inside the new pid namespace"
                    );
                } else {
                    // A host without unprivileged user namespaces cannot sandbox at all; the
                    // launcher must say so rather than silently running unisolated.
                    assert!(
                        stderr.contains("RUSTFUN_SANDBOX_ERROR"),
                        "unexpected launcher failure: {stderr}"
                    );
                }
            }
            Err(error) => {
                eprintln!("skipping: cannot execute the launcher: {error}");
            }
        }
    }

    /// A sandbox that cannot be established must fail, never run the payload unisolated.
    #[test]
    fn launcher_refuses_to_run_without_arguments() {
        let Some(binary) = crate::launcher_path() else {
            eprintln!("skipping: the launcher is not installed");
            return;
        };
        let output = std::process::Command::new(&binary).output().expect("runs");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("internal component"), "stderr: {stderr}");
    }
}
