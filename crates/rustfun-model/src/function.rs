//! Function domain types: name validation, spec, status, source, and metadata.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::environment::Environment;
use crate::error::{ModelError, ModelResult};
use crate::handler::HandlerSpec;
use crate::ids::{ArtifactId, FunctionId};
use crate::resource::ResourceLimits;
use crate::runtime::RuntimeId;
use crate::sandbox::SandboxPolicy;

/// Maximum function name length.
const MAX_NAME_LEN: usize = 63;

/// A validated function name.
///
/// Names follow the portable-subdomain rules used by hosting platforms: lowercase ASCII
/// alphanumerics and dashes, starting and ending with an alphanumeric. This keeps names safe
/// for URLs, filesystem paths, and metrics labels.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FunctionName(String);

impl FunctionName {
    /// Validate and create a function name.
    pub fn new(raw: impl Into<String>) -> ModelResult<Self> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(ModelError::invalid_name("name must not be empty"));
        }
        if raw.len() > MAX_NAME_LEN {
            return Err(ModelError::invalid_name(format!(
                "name exceeds {MAX_NAME_LEN} bytes"
            )));
        }
        if !raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(ModelError::invalid_name(format!(
                "name '{raw}' may contain only lowercase ASCII letters, digits, and '-'"
            )));
        }
        let bytes = raw.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return Err(ModelError::invalid_name(format!(
                "name '{raw}' must start and end with a letter or digit"
            )));
        }
        Ok(Self(raw))
    }

    /// Borrow the name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the name, yielding the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for FunctionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for FunctionName {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FunctionName::new(s)
    }
}

impl TryFrom<String> for FunctionName {
    type Error = ModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        FunctionName::new(value)
    }
}

impl From<FunctionName> for String {
    fn from(value: FunctionName) -> Self {
        value.0
    }
}

/// Where a function's code comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FunctionSource {
    /// A directory on the local filesystem.
    Directory {
        /// Path to the directory containing the function source.
        path: String,
    },
    /// A prebuilt, content-addressed artifact.
    Artifact {
        /// Artifact identifier (usually derived from the digest).
        id: ArtifactId,
        /// Content digest of the artifact.
        digest: Digest,
    },
    /// Source supplied inline (used by tests and remote control planes).
    Inline {
        /// Files mapping relative path to contents.
        files: BTreeMap<String, String>,
    },
}

impl FunctionSource {
    /// Short description used in human-readable output.
    pub fn describe(&self) -> String {
        match self {
            FunctionSource::Directory { path } => format!("directory:{path}"),
            FunctionSource::Artifact { digest, .. } => format!("artifact:{digest}"),
            FunctionSource::Inline { files } => format!("inline:{} files", files.len()),
        }
    }
}

/// Lifecycle status of a function definition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionStatus {
    #[default]
    /// Declared but not yet built into an artifact.
    Pending,
    /// Currently being built.
    Building,
    /// An artifact is available and the function can be invoked.
    Ready,
    /// Invocation failed in a way that requires operator attention.
    Failed,
    /// Function was destroyed.
    Destroyed,
}

impl FunctionStatus {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            FunctionStatus::Pending => "pending",
            FunctionStatus::Building => "building",
            FunctionStatus::Ready => "ready",
            FunctionStatus::Failed => "failed",
            FunctionStatus::Destroyed => "destroyed",
        }
    }

    /// Whether invocations are allowed in this state.
    pub const fn is_invocable(self) -> bool {
        matches!(self, FunctionStatus::Ready)
    }
}

impl fmt::Display for FunctionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Free-form, user-visible metadata attached to a function.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionMetadata {
    /// Arbitrary string labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The deployable description of a function.
///
/// A `FunctionSpec` is the first element of the execution spine and is intentionally free of
/// infrastructure concerns: it names a runtime and a handler and carries limits, but it does
/// not know how a runtime will be started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSpec {
    /// Stable identifier.
    pub id: FunctionId,
    /// Validated name.
    pub name: FunctionName,
    /// Requested runtime.
    pub runtime: RuntimeId,
    /// Handler within the artifact.
    pub handler: HandlerSpec,
    /// Source of the function code.
    pub source: FunctionSource,
    /// Environment variables visible to the function.
    #[serde(default)]
    pub environment: Environment,
    /// Resource limits.
    #[serde(default)]
    pub resources: ResourceLimits,
    /// Isolation policy applied when the function runs.
    #[serde(default)]
    pub sandbox: SandboxPolicy,
    /// Maximum concurrent invocations on one instance.
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: u32,
    /// Lifecycle status.
    #[serde(default)]
    pub status: FunctionStatus,
    /// User metadata.
    #[serde(default)]
    pub metadata: FunctionMetadata,
    /// Creation time (seconds since the Unix epoch).
    #[serde(default = "default_timestamp")]
    pub created_at: u64,
    /// Free-form configuration carried from the manifest.
    #[serde(default)]
    pub config: BTreeMap<String, serde_json::Value>,
}

fn default_max_concurrency() -> u32 {
    1
}

fn default_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl FunctionSpec {
    /// Create a spec with defaults for environment, resources, and sandbox policy.
    pub fn new(name: FunctionName, runtime: RuntimeId, handler: HandlerSpec) -> Self {
        Self {
            id: FunctionId::new(),
            name,
            runtime,
            handler,
            source: FunctionSource::Inline {
                files: BTreeMap::new(),
            },
            environment: Environment::default(),
            resources: ResourceLimits::default(),
            sandbox: SandboxPolicy::default(),
            max_concurrency: default_max_concurrency(),
            status: FunctionStatus::Pending,
            metadata: FunctionMetadata::default(),
            created_at: default_timestamp(),
            config: BTreeMap::new(),
        }
    }

    /// Attach a source.
    #[must_use]
    pub fn with_source(mut self, source: FunctionSource) -> Self {
        self.source = source;
        self
    }

    /// Attach an environment.
    #[must_use]
    pub fn with_environment(mut self, environment: Environment) -> Self {
        self.environment = environment;
        self
    }

    /// Attach resource limits.
    #[must_use]
    pub fn with_resources(mut self, resources: ResourceLimits) -> Self {
        self.resources = resources;
        self
    }

    /// Attach a sandbox policy.
    #[must_use]
    pub fn with_sandbox(mut self, sandbox: SandboxPolicy) -> Self {
        self.sandbox = sandbox;
        self
    }

    /// Validate cross-field invariants.
    pub fn validate(&self) -> ModelResult<()> {
        self.resources.validate()?;
        self.environment.validate()?;
        self.sandbox.validate()?;
        if self.max_concurrency == 0 {
            return Err(ModelError::validation("max_concurrency must be at least 1"));
        }
        // A process runtime needs a layer that can actually contain a process; an in-process
        // runtime (wasm, echo) must not be paired with a process-only hardening layer, because
        // that would claim containment the runtime cannot provide.
        let process_kinds = [
            crate::sandbox::SandboxKind::Host,
            crate::sandbox::SandboxKind::Linux,
            crate::sandbox::SandboxKind::Oci,
        ];
        if self.runtime.is_process_based() && !process_kinds.contains(&self.sandbox.kind) {
            return Err(ModelError::invalid_sandbox(format!(
                "runtime '{}' executes as an OS process and cannot use sandbox kind '{}'",
                self.runtime, self.sandbox.kind
            )));
        }
        if !self.runtime.is_process_based()
            && matches!(
                self.sandbox.kind,
                crate::sandbox::SandboxKind::Linux | crate::sandbox::SandboxKind::Oci
            )
        {
            return Err(ModelError::invalid_sandbox(format!(
                "runtime '{}' does not execute as an OS process and cannot use sandbox kind '{}'",
                self.runtime, self.sandbox.kind
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        for name in ["a", "hello", "hello-world", "fn1", "1fn"] {
            assert!(FunctionName::new(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn invalid_names() {
        for name in [
            "",
            "Hello",
            "-hello",
            "hello-",
            "hello_world",
            "hello world",
            "a/b",
        ] {
            let err = FunctionName::new(name);
            assert!(err.is_err(), "{name} should be rejected");
        }
    }

    #[test]
    fn name_too_long_is_rejected() {
        let long = "a".repeat(MAX_NAME_LEN + 1);
        assert!(FunctionName::new(long).is_err());
        let ok = "a".repeat(MAX_NAME_LEN);
        assert!(FunctionName::new(ok).is_ok());
    }

    #[test]
    fn default_spec_is_valid() {
        let spec = FunctionSpec::new(
            FunctionName::new("hello").expect("valid"),
            RuntimeId::parse("node@24").expect("valid"),
            HandlerSpec::parse("index.handler").expect("valid"),
        );
        assert_eq!(spec.status, FunctionStatus::Pending);
        assert_eq!(spec.max_concurrency, 1);
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn wasm_cannot_use_process_sandbox() {
        let mut spec = FunctionSpec::new(
            FunctionName::new("hello").expect("valid"),
            RuntimeId::parse("wasm").expect("valid"),
            HandlerSpec::parse("function.wasm").expect("valid"),
        );
        spec.sandbox = SandboxPolicy::process(crate::sandbox::SandboxKind::Linux);
        assert!(spec.validate().is_err());
    }

    #[test]
    fn spec_serde_roundtrip_preserves_identity() {
        let spec = FunctionSpec::new(
            FunctionName::new("hello").expect("valid"),
            RuntimeId::parse("node@24").expect("valid"),
            HandlerSpec::parse("index.handler").expect("valid"),
        )
        .with_environment(Environment::from_pairs([("HELLO", "world")]));
        let json = serde_json::to_string(&spec).expect("serializes");
        let back: FunctionSpec = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, spec);
        assert_eq!(back.id, spec.id);
    }
}
