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
    fn probe_report_always_lists_four_capabilities() {
        let report = probe_sandbox();
        assert_eq!(report.probes.len(), 4);
        assert!(!report.platform.is_empty());
        assert!(report.is_available("posix_process_groups"));
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
