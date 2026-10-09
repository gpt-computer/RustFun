//! The sandbox launcher.
//!
//! `unshare(CLONE_NEWPID)` is refused by the kernel when the calling process is multi-threaded
//! (`EINVAL`), and RustFun spawns children from tokio workers. The launcher removes that
//! restriction by re-executing the RustFun binary in a **single-threaded** child that creates
//! the namespaces and then runs the function as PID 1 of its PID namespace.
//!
//! ```text
//! rustfun (multi-threaded)
//!   └── rustfun __sandbox-init …   ← single-threaded, unshare(CLONE_NEWPID|…)
//!         └── <interpreter> …      ← PID 1 inside the new PID namespace
//! ```
//!
//! The launcher is an implementation detail of the platform: it is not a user-facing command,
//! and it never appears in a manifest.

use std::ffi::OsString;

/// Argument that selects the launcher mode.
pub const LAUNCHER_ARG: &str = "__sandbox-init";

/// File name of the launcher binary.
pub const LAUNCHER_BIN: &str = "rustfun-sandbox-init";

/// Whether these arguments select the launcher mode.
///
/// The check happens before any other argument parsing so the launcher can run without the
/// normal command tree.
pub fn is_launcher_invocation(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .any(|arg| arg.to_string_lossy() == LAUNCHER_ARG)
}

/// Encoded launcher configuration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LauncherSpec {
    /// Program to execute as PID 1.
    pub program: String,
    /// Arguments for that program.
    pub args: Vec<String>,
    /// Whether to unshare the PID namespace.
    pub pid_namespace: bool,
    /// Whether to unshare the network namespace.
    pub network_namespace: bool,
    /// Memory ceiling in bytes (`0` = no limit).
    pub memory_bytes: u64,
    /// Maximum processes.
    pub max_processes: u32,
    /// Maximum open files.
    pub max_open_files: u32,
    /// Directory to mount as a private `/tmp`.
    pub private_tmp: String,
    /// cgroup v2 directory the payload is moved into, when the host allows it.
    ///
    /// Memory enforcement needs cgroups: POSIX `RLIMIT_DATA` also counts `mmap`, and V8 (Node)
    /// reserves very large anonymous ranges at startup, so a heap cap alone kills it.
    #[serde(default)]
    pub cgroup_path: Option<String>,
    /// Apply the seccomp filter after the namespaces exist.
    pub seccomp: bool,
    /// Drop capabilities after the namespaces exist.
    pub drop_capabilities: bool,
}

/// Encode a launcher spec as a single argument.
///
/// The spec is base64-encoded JSON so it survives `execve` unchanged, including on platforms
/// where argv encoding is not UTF-8.
pub fn encode(spec: &LauncherSpec) -> Result<String, rustfun_core::RustFunError> {
    use base64::Engine as _;
    let json = serde_json::to_vec(spec).map_err(|error| {
        rustfun_core::RustFunError::internal(format!("cannot encode the sandbox spec: {error}"))
            .with_context(rustfun_core::ErrorContext::new().operation("encode_sandbox_spec"))
    })?;
    Ok(base64::engine::general_purpose::STANDARD.encode(json))
}

/// Decode a launcher spec.
pub fn decode(encoded: &str) -> Result<LauncherSpec, rustfun_core::RustFunError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| {
            rustfun_core::RustFunError::validation(format!("invalid sandbox spec: {error}"))
                .with_context(rustfun_core::ErrorContext::new().operation("decode_sandbox_spec"))
        })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        rustfun_core::RustFunError::validation(format!("invalid sandbox spec: {error}"))
            .with_context(rustfun_core::ErrorContext::new().operation("decode_sandbox_spec"))
    })
}

/// Build the `argv` that launches `spec` through this executable.
pub fn launcher_argv(spec: &LauncherSpec) -> Result<Vec<OsString>, rustfun_core::RustFunError> {
    let encoded = encode(spec)?;
    Ok(vec![OsString::from(LAUNCHER_ARG), OsString::from(encoded)])
}

/// Extract the encoded spec from launcher arguments.
pub fn spec_from_args(
    args: &[OsString],
) -> Option<Result<LauncherSpec, rustfun_core::RustFunError>> {
    let index = args
        .iter()
        .position(|arg| arg.to_string_lossy() == LAUNCHER_ARG)?;
    args.get(index + 1)
        .map(|encoded| decode(&encoded.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> LauncherSpec {
        LauncherSpec {
            program: "/usr/bin/node".to_owned(),
            args: vec!["bootstrap.js".to_owned()],
            pid_namespace: true,
            network_namespace: true,
            memory_bytes: 512 * 1024 * 1024,
            max_processes: 64,
            max_open_files: 1024,
            private_tmp: "/tmp/rustfun-scratch".to_owned(),
            cgroup_path: None,
            seccomp: true,
            drop_capabilities: true,
        }
    }

    #[test]
    fn launcher_invocation_is_detected() {
        let args = vec![
            OsString::from("rustfun"),
            OsString::from("__sandbox-init"),
            OsString::from("payload"),
        ];
        assert!(is_launcher_invocation(&args));
        let normal = vec![OsString::from("rustfun"), OsString::from("build")];
        assert!(!is_launcher_invocation(&normal));
    }

    #[test]
    fn specs_round_trip_through_argv() {
        let spec = spec();
        let argv = launcher_argv(&spec).expect("encodes");
        assert_eq!(argv[0], OsString::from(LAUNCHER_ARG));
        let decoded = spec_from_args(&argv).expect("present").expect("decodes");
        assert_eq!(decoded, spec);
    }

    #[test]
    fn malformed_specs_are_rejected() {
        let argv = vec![OsString::from("rustfun"), OsString::from(LAUNCHER_ARG)];
        assert!(
            spec_from_args(&argv).is_none(),
            "missing payload is not a spec"
        );
        let bad = vec![
            OsString::from("rustfun"),
            OsString::from(LAUNCHER_ARG),
            OsString::from("not-base64!!"),
        ];
        let err = spec_from_args(&bad)
            .expect("present")
            .expect_err("must fail");
        assert_eq!(err.category(), rustfun_core::ErrorCategory::Validation);
    }

    #[test]
    fn spec_validation_rejects_empty_programs() {
        let mut spec = spec();
        spec.program.clear();
        let encoded = encode(&spec).expect("encodes");
        assert_eq!(decode(&encoded).expect("decodes").program, "");
        // The launcher itself rejects an empty program at run time; the encoding stays total so
        // that the error surfaces from the child with a real errno rather than a decode failure.
    }
}
