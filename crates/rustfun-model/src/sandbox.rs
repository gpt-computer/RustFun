//! Sandbox / isolation policy.
//!
//! The policy is explicit data: a function declares which isolation layer it wants, and the
//! platform reports which layer was actually applied. There is no "default sandbox": host
//! process mode is always visible as `host` and is documented as not being a security
//! boundary (see `SECURITY.md`).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, ModelResult};

/// The isolation layer to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxKind {
    /// A child process of the RustFun process. **Not a security boundary.**
    Host,
    /// Linux namespaces + cgroups v2 (+ optional seccomp).
    Linux,
    /// WebAssembly with scoped capabilities.
    Wasm,
    /// An OCI container.
    Oci,
}

impl fmt::Display for SandboxKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SandboxKind {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            SandboxKind::Host => "host",
            SandboxKind::Linux => "linux",
            SandboxKind::Wasm => "wasm",
            SandboxKind::Oci => "oci",
        }
    }

    /// Whether this layer provides a security boundary against untrusted code.
    pub const fn is_security_boundary(self) -> bool {
        matches!(
            self,
            SandboxKind::Linux | SandboxKind::Wasm | SandboxKind::Oci
        )
    }

    /// Whether this layer executes an OS process.
    pub const fn is_process(self) -> bool {
        matches!(
            self,
            SandboxKind::Host | SandboxKind::Linux | SandboxKind::Oci
        )
    }
}

/// Filesystem policy for the instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    /// Function source/artifact root, mounted read-only when the layer supports it.
    pub function_root: bool,
    /// Whether a writable ephemeral `/tmp` is provided.
    pub writable_tmp: bool,
    /// Whether host paths outside the function root are visible at all.
    pub allow_host_paths: bool,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            function_root: true,
            writable_tmp: true,
            allow_host_paths: false,
        }
    }
}

/// Network policy for the instance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    #[default]
    /// No network namespace: host networking (development only).
    Host,
    /// Isolated network namespace with no interfaces beyond loopback.
    Isolated,
    /// Network namespace with a veth pair attached to a user-mode bridge.
    Bridged,
}

impl NetworkPolicy {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            NetworkPolicy::Host => "host",
            NetworkPolicy::Isolated => "isolated",
            NetworkPolicy::Bridged => "bridged",
        }
    }
}

/// Complete isolation policy for a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Isolation layer.
    pub kind: SandboxKind,
    /// Filesystem policy.
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    /// Network policy.
    #[serde(default)]
    pub network: NetworkPolicy,
    /// Apply a seccomp filter (Linux layer only).
    #[serde(default)]
    pub seccomp: bool,
    /// Drop Linux capabilities from the child.
    #[serde(default = "default_true")]
    pub drop_capabilities: bool,
    /// Set `no_new_privs`.
    #[serde(default = "default_true")]
    pub no_new_privileges: bool,
}

fn default_true() -> bool {
    true
}

impl Default for SandboxPolicy {
    /// Development default: host process with a filtered environment.
    ///
    /// This is deliberately visible and documented as insecure.
    fn default() -> Self {
        Self {
            kind: SandboxKind::Host,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::Isolated,
            seccomp: false,
            drop_capabilities: true,
            no_new_privileges: true,
        }
    }
}

impl SandboxPolicy {
    /// Development host-process policy.
    pub fn host() -> Self {
        Self {
            network: NetworkPolicy::Host,
            ..Self::default()
        }
    }

    /// Linux namespace/cgroup policy.
    pub fn linux() -> Self {
        Self {
            kind: SandboxKind::Linux,
            seccomp: true,
            ..Self::default()
        }
    }

    /// WASM policy (no network, no host paths).
    pub fn wasm() -> Self {
        Self {
            kind: SandboxKind::Wasm,
            network: NetworkPolicy::Isolated,
            ..Self::default()
        }
    }

    /// OCI container policy.
    pub fn oci() -> Self {
        Self {
            kind: SandboxKind::Oci,
            seccomp: true,
            ..Self::default()
        }
    }

    /// Alias for [`SandboxPolicy::host`] used by call sites that pass a kind.
    pub fn process(kind: SandboxKind) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }

    /// Whether the selected layer is a real security boundary.
    pub const fn is_secured(&self) -> bool {
        self.kind.is_security_boundary()
    }

    /// Validate internal consistency of the policy.
    pub fn validate(&self) -> ModelResult<()> {
        if self.seccomp && self.kind != SandboxKind::Linux && self.kind != SandboxKind::Oci {
            return Err(ModelError::invalid_sandbox(format!(
                "seccomp is only available for the linux and oci layers, not '{}'",
                self.kind
            )));
        }
        if self.kind == SandboxKind::Wasm && self.network != NetworkPolicy::Isolated {
            return Err(ModelError::invalid_sandbox(
                "the wasm layer does not support network access",
            ));
        }
        if self.filesystem.allow_host_paths && self.kind != SandboxKind::Host {
            return Err(ModelError::invalid_sandbox(format!(
                "host paths cannot be exposed in the '{}' layer",
                self.kind
            )));
        }
        if self.kind == SandboxKind::Linux && self.network == NetworkPolicy::Bridged {
            return Err(ModelError::invalid_sandbox(
                "bridged networking requires a configured bridge and is not supported yet",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_host_and_insecure() {
        let policy = SandboxPolicy::default();
        assert_eq!(policy.kind, SandboxKind::Host);
        assert!(!policy.is_secured());
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn linux_policy_is_secured_and_consistent() {
        let policy = SandboxPolicy::linux();
        assert!(policy.is_secured());
        assert!(policy.seccomp);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn wasm_rejects_networks() {
        let mut policy = SandboxPolicy::wasm();
        assert!(policy.validate().is_ok());
        policy.network = NetworkPolicy::Host;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn seccomp_requires_linux_or_oci() {
        let mut policy = SandboxPolicy::wasm();
        policy.seccomp = true;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn host_paths_require_host_layer() {
        let mut policy = SandboxPolicy::linux();
        policy.filesystem.allow_host_paths = true;
        assert!(policy.validate().is_err());
    }
}
