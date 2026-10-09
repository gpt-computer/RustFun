//! Runtime identity: family, version, capabilities, and the `family@version` id.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, ModelResult};

/// A runtime family, i.e. the kind of interpreter or execution engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeFamily {
    /// Node.js (V8).
    Node,
    /// CPython.
    Python,
    /// A user-provided executable that speaks the RustFun invocation protocol on stdio.
    Executable,
    /// A Rust-native binary built by the RustFun SDK.
    Rust,
    /// A WebAssembly module/component executed by Wasmtime.
    Wasm,
    /// An OCI container image.
    Oci,
    /// A test-only in-process runtime, used by the conformance suite.
    Echo,
}

impl RuntimeFamily {
    /// Canonical lowercase name.
    pub const fn name(self) -> &'static str {
        match self {
            RuntimeFamily::Node => "node",
            RuntimeFamily::Python => "python",
            RuntimeFamily::Executable => "executable",
            RuntimeFamily::Rust => "rust",
            RuntimeFamily::Wasm => "wasm",
            RuntimeFamily::Oci => "oci",
            RuntimeFamily::Echo => "echo",
        }
    }

    /// Parse a family name. Accepts common aliases.
    pub fn parse(raw: &str) -> ModelResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "node" | "nodejs" | "node.js" => Ok(RuntimeFamily::Node),
            "python" | "python3" | "cpython" | "py" => Ok(RuntimeFamily::Python),
            "executable" | "exec" | "binary" | "provided" => Ok(RuntimeFamily::Executable),
            "rust" | "rs" => Ok(RuntimeFamily::Rust),
            "wasm" | "wasm32" | "wasi" => Ok(RuntimeFamily::Wasm),
            "oci" | "container" | "docker" => Ok(RuntimeFamily::Oci),
            "echo" => Ok(RuntimeFamily::Echo),
            other => Err(ModelError::invalid_runtime(format!(
                "unknown runtime family '{other}' (expected one of: node, python, executable, rust, wasm, oci)"
            ))),
        }
    }

    /// Whether this family executes code as a host process by default.
    pub const fn is_process_based(self) -> bool {
        matches!(
            self,
            RuntimeFamily::Node
                | RuntimeFamily::Python
                | RuntimeFamily::Executable
                | RuntimeFamily::Rust
                | RuntimeFamily::Oci
        )
    }
}

impl fmt::Display for RuntimeFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for RuntimeFamily {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RuntimeFamily::parse(s)
    }
}

/// A runtime version requirement.
///
/// RustFun distinguishes *unpinned* versions (`node@*`) from concrete ones so that a
/// manifest never silently depends on "whatever is installed" without saying so.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeVersion {
    /// Any version of the family satisfies the requirement.
    Any,
    /// Exactly this major version.
    Major(u32),
    /// Exactly this major.minor version.
    Minor(u32, u32),
    /// Exactly this major.minor.patch version.
    Patch(u32, u32, u32),
}

impl RuntimeVersion {
    /// Whether `candidate` satisfies this requirement.
    pub fn matches(&self, candidate: &RuntimeVersion) -> bool {
        use RuntimeVersion::{Any, Major, Minor, Patch};
        match (self, candidate) {
            (Any, _) => true,
            (_, Any) => false,
            (Major(want), Major(have)) => want == have,
            (Major(want), Minor(have, _)) | (Major(want), Patch(have, _, _)) => want == have,
            (Minor(want_major, want_minor), Minor(have_major, have_minor)) => {
                want_major == have_major && want_minor == have_minor
            }
            (Minor(want_major, want_minor), Patch(have_major, have_minor, _)) => {
                want_major == have_major && want_minor == have_minor
            }
            (Patch(wmaj, wmin, wpatch), Patch(hmaj, hmin, hpatch)) => {
                wmaj == hmaj && wmin == hmin && wpatch == hpatch
            }
            // A coarser candidate (e.g. "3" from a runtime that only reports a major
            // version) cannot satisfy a more specific requirement.
            (Minor(..) | Patch(..), Major(_) | Minor(..)) => false,
        }
    }

    /// Parse a version token such as `*`, `24`, `3.12`, or `3.12.1`.
    pub fn parse(raw: &str) -> ModelResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "*" || trimmed == "latest" {
            return Ok(RuntimeVersion::Any);
        }
        let parts: Vec<&str> = trimmed.split('.').collect();
        let numbers: ModelResult<Vec<u32>> = parts
            .iter()
            .map(|p| {
                p.parse::<u32>().map_err(|_| {
                    ModelError::invalid_runtime(format!(
                        "runtime version component '{p}' is not a number"
                    ))
                })
            })
            .collect();
        let numbers = numbers?;
        match numbers.as_slice() {
            [major] => Ok(RuntimeVersion::Major(*major)),
            [major, minor] => Ok(RuntimeVersion::Minor(*major, *minor)),
            [major, minor, patch] => Ok(RuntimeVersion::Patch(*major, *minor, *patch)),
            _ => Err(ModelError::invalid_runtime(format!(
                "runtime version '{trimmed}' has too many components"
            ))),
        }
    }
}

impl fmt::Display for RuntimeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeVersion::Any => f.write_str("*"),
            RuntimeVersion::Major(major) => write!(f, "{major}"),
            RuntimeVersion::Minor(major, minor) => write!(f, "{major}.{minor}"),
            RuntimeVersion::Patch(major, minor, patch) => write!(f, "{major}.{minor}.{patch}"),
        }
    }
}

/// Fully qualified runtime identity, e.g. `node@24`, `python@3.12`, `executable@*`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RuntimeId {
    family: RuntimeFamily,
    version: RuntimeVersion,
}

impl RuntimeId {
    /// Compose a runtime id from a family and version requirement.
    pub fn new(family: RuntimeFamily, version: RuntimeVersion) -> Self {
        Self { family, version }
    }

    /// Parse a `family@version` string. The `@version` suffix is optional and defaults to
    /// [`RuntimeVersion::Any`].
    pub fn parse(raw: &str) -> ModelResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ModelError::invalid_runtime("runtime id must not be empty"));
        }
        let (family_raw, version_raw) = match trimmed.split_once('@') {
            Some((f, v)) => (f, v),
            None => (trimmed, "*"),
        };
        Ok(Self {
            family: RuntimeFamily::parse(family_raw)?,
            version: RuntimeVersion::parse(version_raw)?,
        })
    }

    /// Runtime family.
    pub const fn family(&self) -> RuntimeFamily {
        self.family
    }

    /// Version requirement.
    pub const fn version(&self) -> &RuntimeVersion {
        &self.version
    }

    /// Whether this runtime runs an OS process.
    pub const fn is_process_based(&self) -> bool {
        self.family.is_process_based()
    }
}

impl fmt::Display for RuntimeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.family, self.version)
    }
}

impl FromStr for RuntimeId {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RuntimeId::parse(s)
    }
}

impl TryFrom<String> for RuntimeId {
    type Error = ModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        RuntimeId::parse(&value)
    }
}

impl From<RuntimeId> for String {
    fn from(value: RuntimeId) -> Self {
        value.to_string()
    }
}

/// Declared capabilities of a runtime adapter.
///
/// Capabilities are negotiated: the core asks a runtime what it supports before deciding how
/// to drive it, so an adapter never has to guess.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapabilities {
    /// Warm reuse of a single instance across invocations.
    pub warm_instances: bool,
    /// Concurrent invocations on one instance.
    pub concurrency: bool,
    /// Request-scoped environment mutation.
    pub per_invocation_environment: bool,
    /// Request-scoped metadata (headers, context) delivery.
    pub metadata: bool,
    /// Deadline propagation.
    pub deadlines: bool,
    /// Streaming responses.
    pub streaming: bool,
    /// Coarse network policy enforcement.
    pub network_policy: bool,
    /// Binary (non-JSON) payload support.
    pub binary_payloads: bool,
}

impl RuntimeCapabilities {
    /// Capabilities of the in-process echo runtime, used by tests and benchmarks.
    pub const ECHO: Self = Self {
        warm_instances: true,
        concurrency: false,
        per_invocation_environment: true,
        metadata: true,
        deadlines: true,
        streaming: false,
        network_policy: false,
        binary_payloads: true,
    };

    /// Capabilities of the Wasmtime runtime.
    ///
    /// A Wasm instance has no process to hand a per-invocation environment to and no OS-level
    /// network namespace, so both are false: the network is absent from the guest rather than
    /// merely denied, and request metadata arrives as a host call argument.
    pub const WASM: Self = Self {
        warm_instances: true,
        concurrency: false,
        per_invocation_environment: false,
        metadata: true,
        deadlines: true,
        streaming: true,
        network_policy: true,
        binary_payloads: true,
    };

    /// Capabilities typical of a stdio-driven process runtime.
    pub const PROCESS: Self = Self {
        warm_instances: true,
        concurrency: false,
        per_invocation_environment: true,
        metadata: true,
        deadlines: true,
        streaming: true,
        network_policy: false,
        binary_payloads: true,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_family_and_version() {
        let id = RuntimeId::parse("node@24").expect("valid");
        assert_eq!(id.family(), RuntimeFamily::Node);
        assert_eq!(id.version(), &RuntimeVersion::Major(24));
        assert_eq!(id.to_string(), "node@24");
    }

    #[test]
    fn version_suffix_is_optional() {
        let id = RuntimeId::parse("python").expect("valid");
        assert_eq!(id.version(), &RuntimeVersion::Any);
        assert_eq!(id.to_string(), "python@*");
    }

    #[test]
    fn parses_multi_component_versions() {
        assert_eq!(
            RuntimeId::parse("python@3.12.1").expect("valid").version(),
            &RuntimeVersion::Patch(3, 12, 1)
        );
        assert!(RuntimeId::parse("python@3.x").is_err());
    }

    #[test]
    fn wasm_capabilities_do_not_claim_host_network_policy() {
        // There is no guest interface to sockets at all, so the capability is only true because
        // the network is unreachable rather than filtered.
        const _: () = assert!(RuntimeCapabilities::WASM.network_policy);
        const _: () = assert!(!RuntimeCapabilities::WASM.per_invocation_environment);
        const _: () = assert!(RuntimeCapabilities::WASM.warm_instances);
    }

    #[test]
    fn rejects_unknown_family() {
        assert!(RuntimeId::parse("cobol@1").is_err());
        assert!(RuntimeId::parse("").is_err());
    }

    #[test]
    fn aliases_resolve() {
        assert_eq!(
            RuntimeFamily::parse("nodejs").expect("alias"),
            RuntimeFamily::Node
        );
        assert_eq!(
            RuntimeFamily::parse("python3").expect("alias"),
            RuntimeFamily::Python
        );
        assert_eq!(
            RuntimeFamily::parse("provided").expect("alias"),
            RuntimeFamily::Executable
        );
    }

    #[test]
    fn version_matching() {
        assert!(RuntimeVersion::Any.matches(&RuntimeVersion::Patch(3, 12, 1)));
        assert!(RuntimeVersion::Major(24).matches(&RuntimeVersion::Minor(24, 1)));
        assert!(!RuntimeVersion::Major(24).matches(&RuntimeVersion::Minor(22, 1)));
        assert!(RuntimeVersion::Minor(3, 12).matches(&RuntimeVersion::Patch(3, 12, 4)));
        assert!(!RuntimeVersion::Minor(3, 12).matches(&RuntimeVersion::Patch(3, 13, 0)));
        assert!(!RuntimeVersion::Patch(3, 12, 4).matches(&RuntimeVersion::Minor(3, 12)));
    }

    #[test]
    fn serde_roundtrip() {
        let id = RuntimeId::parse("python@3.12").expect("valid");
        let json = serde_json::to_string(&id).expect("serializes");
        assert_eq!(json, "\"python@3.12\"");
        let back: RuntimeId = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, id);
    }
}
