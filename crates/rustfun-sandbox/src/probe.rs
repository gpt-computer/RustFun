//! Sandbox capability probes.
//!
//! `rustfun doctor` and the HTTP `/health` endpoint report what the host can actually do, so
//! operators never have to guess why a sandbox failed.

use rustfun_core::{ErrorContext, RustFunError};
use serde::{Deserialize, Serialize};

/// A single capability probe result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProbe {
    /// Capability name.
    pub name: String,
    /// Whether it is available.
    pub available: bool,
    /// Human-readable detail.
    pub detail: String,
    /// How to fix a missing capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl SandboxProbe {
    /// Create a probe result.
    pub fn new(
        name: impl Into<String>,
        available: bool,
        detail: impl Into<String>,
        remediation: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            available,
            detail: detail.into(),
            remediation,
        }
    }
}

/// The aggregated probe report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReport {
    /// Platform name.
    pub platform: String,
    /// Individual probes.
    pub probes: Vec<SandboxProbe>,
}

impl ProbeReport {
    /// Summary line for the CLI.
    pub fn summary(&self) -> String {
        let failed: Vec<&str> = self
            .probes
            .iter()
            .filter(|p| !p.available)
            .map(|p| p.name.as_str())
            .collect();
        if failed.is_empty() {
            format!("{}: all probes passed", self.platform)
        } else {
            format!("{}: unavailable -> {}", self.platform, failed.join(", "))
        }
    }

    /// First remediation hint for a missing capability.
    pub fn remediation(&self) -> String {
        self.probes
            .iter()
            .find(|p| !p.available)
            .and_then(|p| p.remediation.clone())
            .unwrap_or_else(|| {
                "no action required: the requested isolation layer is fully available".to_owned()
            })
    }

    /// Whether a named probe passed.
    pub fn is_available(&self, name: &str) -> bool {
        self.probes.iter().any(|p| p.name == name && p.available)
    }
}

/// Whether the cgroup v2 hierarchy exposes the CPU controller.
///
/// A hierarchy can be mounted without delegating any controller into child cgroups, so the
/// mounted check alone would overpromise.
fn cgroup_cpu_available() -> Option<bool> {
    if rustfun_process::platform::cgroup_v2_available() != Some(true) {
        return None;
    }
    let root = std::env::var_os("RUSTFUN_CGROUP_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/sys/fs/cgroup"));
    let controllers = std::fs::read_to_string(root.join("cgroup.controllers")).ok()?;
    Some(controllers.split_whitespace().any(|c| c == "cpu"))
}

/// Probe the host for sandbox capabilities.
pub fn probe_sandbox() -> ProbeReport {
    let platform = rustfun_process::Platform::current();
    let mut probes = Vec::new();

    probes.push(SandboxProbe::new(
        "posix_process_groups",
        platform.is_posix(),
        if platform.is_posix() {
            "process groups and signals are available".to_owned()
        } else {
            format!("{platform} does not support POSIX process groups")
        },
        (!platform.is_posix())
            .then(|| "use a Linux or macOS host for process isolation".to_owned()),
    ));

    match rustfun_process::platform::unprivileged_user_namespaces_available() {
        Some(true) => probes.push(SandboxProbe::new(
            "user_namespaces",
            true,
            "unprivileged user namespaces are enabled".to_owned(),
            None,
        )),
        Some(false) => probes.push(SandboxProbe::new(
            "user_namespaces",
            false,
            "unprivileged user namespaces are disabled by the kernel".to_owned(),
            Some(
                "enable unprivileged user namespaces (sysctl kernel.unprivileged_userns_clone=1) or run rustfun as root"
                    .to_owned(),
            ),
        )),
        None => probes.push(SandboxProbe::new(
            "user_namespaces",
            false,
            "user namespaces require Linux".to_owned(),
            Some("use the wasm isolation layer for portable isolation".to_owned()),
        )),
    }

    match rustfun_process::platform::cgroup_v2_available() {
        Some(true) => probes.push(SandboxProbe::new(
            "cgroup_v2",
            true,
            "a cgroup v2 hierarchy is mounted".to_owned(),
            None,
        )),
        Some(false) => probes.push(SandboxProbe::new(
            "cgroup_v2",
            false,
            "no cgroup v2 hierarchy is mounted".to_owned(),
            Some("mount a cgroup v2 hierarchy (systemd unified hierarchy)".to_owned()),
        )),
        None => probes.push(SandboxProbe::new(
            "cgroup_v2",
            false,
            "cgroups require Linux".to_owned(),
            Some("use the wasm isolation layer for portable isolation".to_owned()),
        )),
    }

    // The PID namespace needs the launcher binary next to the running executable. A development
    // checkout without it falls back to the in-process path and skips the namespace, so the
    // probe reports the binary rather than the capability.
    match crate::launcher_path() {
        Some(path) => probes.push(SandboxProbe::new(
            "sandbox_launcher",
            true,
            format!("{} is installed", path.display()),
            None,
        )),
        None => probes.push(SandboxProbe::new(
            "sandbox_launcher",
            false,
            "rustfun-sandbox-init was not found next to the binary".to_owned(),
            Some(
                "the PID namespace is skipped without it; install the binary next to rustfun or run the launcher test suite"
                    .to_owned(),
            ),
        )),
    }

    // Whether the cgroup hierarchy can actually throttle CPU, not merely account for it.
    match cgroup_cpu_available() {
        Some(true) => probes.push(SandboxProbe::new(
            "cgroup_cpu",
            true,
            "the cpu controller is available in the cgroup v2 hierarchy".to_owned(),
            None,
        )),
        Some(false) => probes.push(SandboxProbe::new(
            "cgroup_cpu",
            false,
            "the cpu controller is not delegated in the cgroup v2 hierarchy".to_owned(),
            Some(
                "delegate the cpu controller (write +cpu to cgroup.subtree_control) to enforce cpu limits"
                    .to_owned(),
            ),
        )),
        None => probes.push(SandboxProbe::new(
            "cgroup_cpu",
            false,
            "cgroups require Linux".to_owned(),
            Some("cpu limits are enforced with the Wasm fuel budget off Linux".to_owned()),
        )),
    }

    match rustfun_process::platform::seccomp_available() {
        Some(true) => probes.push(SandboxProbe::new(
            "seccomp",
            true,
            "seccomp filters can be installed (with no_new_privs)".to_owned(),
            None,
        )),
        other => probes.push(SandboxProbe::new(
            "seccomp",
            false,
            match other {
                Some(_) => "seccomp is unavailable".to_owned(),
                None => "seccomp requires Linux".to_owned(),
            },
            Some(
                "seccomp is applied on Linux only; other layers rely on namespaces and cgroups"
                    .to_owned(),
            ),
        )),
    }

    ProbeReport {
        platform: platform.as_str().to_owned(),
        probes,
    }
}

/// Convert a probe failure into a structured error.
pub fn probe_error(operation: &str, report: &ProbeReport) -> RustFunError {
    RustFunError::sandbox(format!("sandbox unavailable: {}", report.summary())).with_context(
        ErrorContext::new()
            .operation(operation)
            .remediation(report.remediation()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_report_lists_every_capability() {
        let report = probe_sandbox();
        let names: Vec<&str> = report.probes.iter().map(|p| p.name.as_str()).collect();
        for expected in [
            "posix_process_groups",
            "user_namespaces",
            "cgroup_v2",
            "sandbox_launcher",
            "cgroup_cpu",
            "seccomp",
        ] {
            assert!(
                names.contains(&expected),
                "the probe report must list {expected}: {names:?}"
            );
        }
        assert!(!report.platform.is_empty());
        assert!(report.is_available("posix_process_groups"));
    }

    #[test]
    fn the_launcher_probe_reports_the_binary_not_the_capability() {
        let report = probe_sandbox();
        let probe = report
            .probes
            .iter()
            .find(|p| p.name == "sandbox_launcher")
            .expect("the launcher probe exists");
        // The binary being present is what makes the PID namespace possible, so the detail names
        // the file rather than repeating the kernel capability.
        assert!(
            probe.detail.contains("rustfun-sandbox-init") || probe.detail.contains("installed"),
            "the detail should name the launcher: {}",
            probe.detail
        );
    }

    #[test]
    fn the_cpu_probe_distinguishes_a_mounted_hierarchy_from_a_delegated_controller() {
        let report = probe_sandbox();
        let probe = report
            .probes
            .iter()
            .find(|p| p.name == "cgroup_cpu")
            .expect("the cpu probe exists");
        // On a host with a read-only hierarchy the probe must say the controller is missing
        // rather than reporting the mounted hierarchy as usable.
        if !probe.available {
            assert!(
                probe.detail.contains("not delegated") || probe.detail.contains("require Linux"),
                "the detail should explain what is missing: {}",
                probe.detail
            );
        }
    }

    #[test]
    fn summary_and_remediation_are_human_readable() {
        let report = ProbeReport {
            platform: "test".to_owned(),
            probes: vec![
                SandboxProbe::new("a", true, "ok", None),
                SandboxProbe::new("b", false, "missing", Some("enable b".to_owned())),
            ],
        };
        assert_eq!(report.summary(), "test: unavailable -> b");
        assert_eq!(report.remediation(), "enable b");
        assert!(!report.is_available("b"));
        assert!(report.is_available("a"));
    }

    #[test]
    fn clean_report_has_no_remediation() {
        let report = ProbeReport {
            platform: "test".to_owned(),
            probes: vec![SandboxProbe::new("a", true, "ok", None)],
        };
        assert!(report.summary().contains("all probes passed"));
        assert!(report.remediation().contains("no action required"));
    }

    #[test]
    fn probe_error_is_structured() {
        let report = probe_sandbox();
        let err = probe_error("create_sandbox", &report);
        assert_eq!(err.category(), rustfun_core::ErrorCategory::Sandbox);
        assert!(err.context().remediation.is_some());
    }

    #[test]
    fn probe_report_serializes() {
        let report = probe_sandbox();
        let json = serde_json::to_string(&report).expect("serializes");
        let back: ProbeReport = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, report);
    }
}
