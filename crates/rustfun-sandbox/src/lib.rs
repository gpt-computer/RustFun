//! Isolation layers for untrusted function code.
//!
//! RustFun names the layer it applies; there is no ambiguous "default sandbox".
//!
//! | Layer | Strength | Availability |
//! | --- | --- | --- |
//! | [`HostSandbox`] | none (development only) | every platform |
//! | [`LinuxSandbox`] | namespaces + cgroups v2 + rlimits + optional seccomp | Linux |
//!
//! Both layers produce a [`SandboxedProcess`]: a process plus the isolation that was actually
//! established. Callers can therefore report what happened rather than what was requested —
//! a refused namespace is an error, never a silent downgrade.
//!
//! # Security
//!
//! `HostSandbox` provides *no* isolation. It is labelled [`IsolationStrength::None`] so that
//! CLI output, the HTTP API, and events can never imply otherwise.
//!
//! [`LinuxSandbox`] establishes:
//! - a new PID, mount, IPC, UTS and (when requested) network namespace via `unshare`
//! - a resource-limited `clone` of the child using `clone3`/`fork` + `unshare` through
//!   `pre_exec`
//! - POSIX resource limits (address space, file size, open files, processes, CPU)
//! - a read-only view of the function root with a private writable `/tmp` (best effort,
//!   reported in the result)
//! - dropped capabilities and `no_new_privs`
//! - an optional seccomp-BPF deny list for dangerous syscalls

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_model::{NetworkPolicy, ResourceLimits, SandboxKind, SandboxPolicy};
use rustfun_process::{ProcessEngine, ProcessHandle};

pub mod host;
pub mod launcher;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod probe;

pub use host::HostSandbox;
pub use launcher::{LauncherSpec, LAUNCHER_ARG};
#[cfg(target_os = "linux")]
pub use linux::LinuxSandbox;
pub use probe::{probe_sandbox, SandboxProbe};

/// How strong the isolation actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationStrength {
    /// No isolation at all. Development only.
    None,
    /// Partial isolation (for example, namespaces without cgroups).
    Partial,
    /// The requested controls were established.
    Full,
}

impl IsolationStrength {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            IsolationStrength::None => "none",
            IsolationStrength::Partial => "partial",
            IsolationStrength::Full => "full",
        }
    }

    /// Whether untrusted code may be executed under this strength.
    pub const fn is_acceptable_for_untrusted_code(self) -> bool {
        matches!(self, IsolationStrength::Full)
    }
}

/// What the sandbox layer manages for an instance.
#[derive(Debug, Clone)]
pub struct SandboxRequest {
    /// The isolation layer to apply.
    pub policy: SandboxPolicy,
    /// Resource limits to enforce.
    pub resources: ResourceLimits,
    /// Directory containing the function artifact (mounted read-only when supported).
    pub function_root: std::path::PathBuf,
    /// Private writable scratch directory used as `/tmp` inside the sandbox.
    pub scratch_dir: std::path::PathBuf,
    /// Interpreter command line to execute.
    pub command: Vec<String>,
    /// Environment for the child (already filtered by the caller).
    pub environment: std::collections::BTreeMap<String, String>,
    /// Grace period for graceful shutdown.
    pub shutdown_grace: Duration,
}

/// What a sandbox layer actually established.
///
/// Keeping the report separate from the process handle makes the security claim explicit and
/// testable: a caller can log and assert on the report without holding a live process.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IsolationReport {
    /// Layer that was requested.
    pub kind: SandboxKind,
    /// Isolation strength achieved.
    pub strength: IsolationStrength,
    /// Controls that were established.
    pub applied: Vec<String>,
    /// Controls that could not be established.
    pub skipped: Vec<String>,
}

impl IsolationReport {
    /// Create a report.
    pub fn new(kind: SandboxKind, strength: IsolationStrength) -> Self {
        Self {
            kind,
            strength,
            applied: Vec::new(),
            skipped: Vec::new(),
        }
    }

    /// Record an established control.
    #[must_use]
    pub fn applied(mut self, control: impl Into<String>) -> Self {
        self.applied.push(control.into());
        self
    }

    /// Record a control that could not be established.
    #[must_use]
    pub fn skipped(mut self, control: impl Into<String>) -> Self {
        self.skipped.push(control.into());
        self
    }

    /// Whether the isolation is strong enough to run untrusted code.
    pub fn is_secured(&self) -> bool {
        self.strength.is_acceptable_for_untrusted_code()
    }

    /// Human-readable report.
    pub fn describe(&self) -> String {
        format!(
            "layer={} strength={} applied=[{}] skipped=[{}]",
            self.kind.as_str(),
            self.strength.as_str(),
            self.applied.join(","),
            self.skipped.join(",")
        )
    }
}

/// The result of starting a sandboxed process.
#[derive(Debug)]
pub struct SandboxedProcess {
    /// The running process.
    pub process: Arc<ProcessHandle>,
    /// Isolation that was actually established.
    pub report: IsolationReport,
}

impl SandboxedProcess {
    /// Whether the isolation is strong enough to run untrusted code.
    pub fn is_secured(&self) -> bool {
        self.report.is_secured()
    }

    /// Human-readable report of what was applied.
    pub fn describe(&self) -> String {
        self.report.describe()
    }
}

/// A strategy for starting a process under a given isolation layer.
#[async_trait]
pub trait Sandbox: Send + Sync {
    /// The isolation layer this strategy implements.
    fn kind(&self) -> SandboxKind;

    /// Whether this strategy can run on the current host right now.
    fn is_available(&self) -> bool;

    /// Start a process under this layer.
    async fn start(
        &self,
        engine: &ProcessEngine,
        request: SandboxRequest,
    ) -> Result<SandboxedProcess>;
}

/// Build the sandbox strategy for a policy, failing when the requested layer is unavailable.
///
/// The platform boundary is explicit: on macOS, `SandboxKind::Linux` is an error with a
/// remediation hint rather than a silent fallback to host mode.
pub fn sandbox_for(policy: &SandboxPolicy) -> Result<Box<dyn Sandbox>> {
    match policy.kind {
        SandboxKind::Host => Ok(Box::new(HostSandbox::new())),
        SandboxKind::Linux => {
            #[cfg(target_os = "linux")]
            {
                let sandbox = LinuxSandbox::new();
                if !sandbox.is_available() {
                    let probe = probe_sandbox();
                    return Err(RustFunError::sandbox(format!(
                        "the linux isolation layer is not available on this host: {}",
                        probe.summary()
                    ))
                    .with_context(
                        ErrorContext::new()
                            .operation("create_sandbox")
                            .remediation(probe.remediation()),
                    ));
                }
                Ok(Box::new(sandbox))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(RustFunError::sandbox(
                    "the linux isolation layer requires Linux; this host cannot provide it",
                )
                .with_context(
                    ErrorContext::new()
                        .operation("create_sandbox")
                        .remediation(
                            "use the 'wasm' isolation layer for portable isolation, or the 'host' layer for development",
                        ),
                ))
            }
        }
        SandboxKind::Wasm => Err(RustFunError::sandbox(
            "the wasm isolation layer is provided by the wasm runtime adapter, not the process sandbox",
        )
        .with_context(
            ErrorContext::new()
                .operation("create_sandbox")
                .remediation("set runtime = \"wasm\" so the wasm adapter is selected"),
        )),
        SandboxKind::Oci => Err(RustFunError::sandbox(
            "the oci isolation layer is provided by the oci runtime adapter, not the process sandbox",
        )
        .with_context(
            ErrorContext::new()
                .operation("create_sandbox")
                .remediation("set runtime = \"oci\" so the oci adapter is selected"),
        )),
    }
}

/// Locate the sandbox launcher binary.
///
/// Search order: `RUSTFUN_SANDBOX_LAUNCHER`, a sibling of the running executable (the normal
/// case for an installed binary), then `PATH`.
pub fn launcher_path() -> Option<std::path::PathBuf> {
    if let Some(configured) = std::env::var_os("RUSTFUN_SANDBOX_LAUNCHER") {
        let path = std::path::PathBuf::from(configured);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(current) = std::env::current_exe() {
        // Installed binaries live side by side; during `cargo test` the running binary sits in
        // `target/<profile>/deps`, so the launcher is one directory up.
        for directory in current.ancestors().skip(1).take(2) {
            let sibling = directory.join(launcher::LAUNCHER_BIN);
            if sibling.is_file() {
                return Some(sibling);
            }
        }
    }
    let name = launcher::LAUNCHER_BIN;
    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Translate a [`NetworkPolicy`] into the `unshare(CLONE_NEWNET)` decision.
pub fn network_isolation(policy: NetworkPolicy) -> bool {
    matches!(policy, NetworkPolicy::Isolated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_gating_is_explicit() {
        assert!(!IsolationStrength::None.is_acceptable_for_untrusted_code());
        assert!(!IsolationStrength::Partial.is_acceptable_for_untrusted_code());
        assert!(IsolationStrength::Full.is_acceptable_for_untrusted_code());
    }

    #[test]
    fn wasm_and_oci_point_at_their_adapters() {
        let wasm = match sandbox_for(&SandboxPolicy::wasm()) {
            Ok(_) => panic!("wasm must not resolve to a process sandbox"),
            Err(err) => err,
        };
        assert!(wasm.to_string().contains("wasm runtime adapter"));
        let oci = match sandbox_for(&SandboxPolicy::oci()) {
            Ok(_) => panic!("oci must not resolve to a process sandbox"),
            Err(err) => err,
        };
        assert!(oci.to_string().contains("oci runtime adapter"));
    }

    #[test]
    fn host_layer_is_always_available_and_admits_no_isolation() {
        let sandbox = sandbox_for(&SandboxPolicy::host()).expect("host sandbox");
        assert_eq!(sandbox.kind(), SandboxKind::Host);
        assert!(sandbox.is_available());
        assert!(!sandbox.kind().is_security_boundary());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn linux_layer_is_refused_off_linux() {
        let err = match sandbox_for(&SandboxPolicy::linux()) {
            Ok(_) => panic!("linux isolation must not be available off Linux"),
            Err(err) => err,
        };
        assert_eq!(err.category(), rustfun_core::ErrorCategory::Sandbox);
        assert!(err.context().remediation.is_some());
    }

    #[test]
    fn isolation_report_records_applied_and_skipped_controls() {
        let report = IsolationReport::new(SandboxKind::Linux, IsolationStrength::Partial)
            .applied("pid_namespace")
            .applied("cgroup_v2")
            .skipped("seccomp");
        assert!(!report.is_secured());
        let text = report.describe();
        assert!(text.contains("layer=linux"));
        assert!(text.contains("strength=partial"));
        assert!(text.contains("applied=[pid_namespace,cgroup_v2]"));
        assert!(text.contains("skipped=[seccomp]"));

        let full = IsolationReport::new(SandboxKind::Linux, IsolationStrength::Full);
        assert!(full.is_secured());
        assert_eq!(full.applied.len(), 0);
    }

    #[test]
    fn isolation_report_is_serializable() {
        let report = IsolationReport::new(SandboxKind::Host, IsolationStrength::None);
        let json = serde_json::to_string(&report).expect("serializes");
        let back: IsolationReport = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, report);
        assert!(json.contains("\"strength\":\"none\""));
    }

    #[test]
    fn network_policy_translation() {
        assert!(network_isolation(NetworkPolicy::Isolated));
        assert!(!network_isolation(NetworkPolicy::Host));
        assert!(!network_isolation(NetworkPolicy::Bridged));
    }
}
