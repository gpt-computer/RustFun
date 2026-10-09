//! The `rustfun.toml` manifest.
//!
//! A manifest is the developer-facing form of a [`FunctionSpec`]: defaults, validation,
//! environment overrides, and a schema version so old manifests can be migrated rather than
//! silently reinterpreted.
//!
//! ```toml
//! name = "hello"
//! runtime = "node@24"
//! handler = "index.handler"
//!
//! [build]
//! source = "."
//! command = ["npm", "ci", "&&", "npm", "run", "build"]
//!
//! [resources]
//! memory = "512MiB"
//! timeout = "30s"
//!
//! [sandbox]
//! kind = "linux"
//!
//! [environment]
//! HELLO = "world"
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rustfun_core::{
    FunctionName, FunctionSpec, FunctionStatus, HandlerSpec, ResourceLimits, RuntimeId,
    SandboxKind, SandboxPolicy,
};
use serde::{Deserialize, Serialize};

/// Environment variables that override manifest values when `rustfun` runs.
///
/// Precedence: manifest < environment override < CLI flag.
pub const ENV_MANIFEST: &str = "RUSTFUN_MANIFEST";
/// Override for the function name.
pub const ENV_FUNCTION_NAME: &str = "RUSTFUN_FUNCTION";
/// Override for the runtime id.
pub const ENV_RUNTIME: &str = "RUSTFUN_RUNTIME";
/// Override for the handler.
pub const ENV_HANDLER: &str = "RUSTFUN_HANDLER";
/// Override for the memory limit.
pub const ENV_MEMORY: &str = "RUSTFUN_MEMORY";
/// Override for the timeout.
pub const ENV_TIMEOUT: &str = "RUSTFUN_TIMEOUT";
/// Override for the isolation layer.
pub const ENV_SANDBOX: &str = "RUSTFUN_SANDBOX";

/// The parsed manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version of this manifest.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Function name.
    pub name: String,
    /// Runtime id, e.g. `node@24`.
    pub runtime: String,
    /// Handler, e.g. `index.handler`.
    pub handler: String,
    /// Optional build settings.
    #[serde(default)]
    pub build: BuildSection,
    /// Resource limits.
    #[serde(default)]
    pub resources: ResourceSection,
    /// Isolation policy.
    #[serde(default)]
    pub sandbox: SandboxSection,
    /// Environment variables.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Maximum concurrent invocations per instance.
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: u32,
    /// Free-form metadata.
    #[serde(default)]
    pub metadata: MetadataSection,
    /// Anything the platform does not know about yet, preserved on rewrite.
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

/// `[build]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSection {
    /// Source directory, relative to the manifest.
    #[serde(default = "default_source")]
    pub source: String,
    /// Build command, executed without a shell.
    #[serde(default)]
    pub command: Vec<String>,
    /// Files excluded from the artifact.
    #[serde(default)]
    pub exclude: Vec<String>,
}

fn default_source() -> String {
    ".".to_owned()
}

/// `[resources]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSection {
    /// Memory limit, e.g. `512MiB`.
    #[serde(default)]
    pub memory: Option<String>,
    /// Invocation timeout, e.g. `30s`.
    #[serde(default)]
    pub timeout: Option<String>,
    /// CPU quota in milliseconds per second.
    #[serde(default)]
    pub cpu_millis_per_second: Option<u64>,
    /// Maximum processes.
    #[serde(default)]
    pub max_processes: Option<u32>,
    /// Maximum open files.
    #[serde(default)]
    pub max_open_files: Option<u32>,
    /// Maximum request payload size in bytes.
    #[serde(default)]
    pub max_payload_bytes: Option<usize>,
}

/// `[sandbox]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxSection {
    /// Isolation layer.
    #[serde(default)]
    pub kind: Option<String>,
    /// Allow host paths to be visible to the function.
    #[serde(default)]
    pub allow_host_paths: bool,
    /// Apply a seccomp filter.
    #[serde(default)]
    pub seccomp: Option<bool>,
}

/// `[metadata]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSection {
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Arbitrary labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

fn default_schema_version() -> u32 {
    rustfun_model::MANIFEST_SCHEMA_VERSION
}

fn default_max_concurrency() -> u32 {
    1
}

impl Manifest {
    /// Parse a manifest from TOML text.
    pub fn parse(text: &str) -> rustfun_core::Result<Self> {
        let manifest: Manifest = toml::from_str(text).map_err(|error| {
            rustfun_core::RustFunError::validation(format!("invalid rustfun.toml: {error}"))
                .with_context(
                    rustfun_core::ErrorContext::new()
                        .operation("parse_manifest")
                        .detail("toml", error.to_string()),
                )
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Read and parse a manifest from disk.
    pub fn load(path: &Path) -> rustfun_core::Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            rustfun_core::RustFunError::io(format!("cannot read {}: {error}", path.display()))
                .with_context(
                    rustfun_core::ErrorContext::new()
                        .operation("load_manifest")
                        .remediation("run `rustfun init` to create a manifest"),
                )
        })?;
        let mut manifest = Self::parse(&text)?;
        manifest.apply_environment_overrides(&std::env::vars().collect())?;
        Ok(manifest)
    }

    /// Serialize the manifest back to TOML.
    pub fn to_toml(&self) -> rustfun_core::Result<String> {
        toml::to_string_pretty(self).map_err(|error| {
            rustfun_core::RustFunError::validation(format!("cannot serialize manifest: {error}"))
        })
    }

    /// Validate the manifest, returning actionable errors.
    pub fn validate(&self) -> rustfun_core::Result<()> {
        if self.schema_version > rustfun_model::MANIFEST_SCHEMA_VERSION {
            return Err(rustfun_core::RustFunError::validation(format!(
                "manifest schema version {} is newer than this build supports ({}); upgrade rustfun",
                self.schema_version,
                rustfun_model::MANIFEST_SCHEMA_VERSION
            ))
            .with_context(
                rustfun_core::ErrorContext::new()
                    .operation("validate_manifest")
                    .remediation("upgrade rustfun or lower `schema_version`"),
            ));
        }
        FunctionName::new(self.name.clone())?;
        RuntimeId::parse(&self.runtime)?;
        HandlerSpec::parse(&self.handler)?;
        if let Some(kind) = &self.sandbox.kind {
            parse_sandbox_kind(kind)?;
        }
        if let Some(memory) = &self.resources.memory {
            rustfun_model::parse_bytes(memory).map_err(rustfun_core::RustFunError::from)?;
        }
        if let Some(timeout) = &self.resources.timeout {
            rustfun_model::parse_duration(timeout).map_err(rustfun_core::RustFunError::from)?;
        }
        for (key, value) in &self.environment {
            rustfun_model::Environment::try_from_iter([(key.clone(), value.clone())])?;
        }
        if self.max_concurrency == 0 {
            return Err(rustfun_core::RustFunError::validation(
                "max_concurrency must be at least 1",
            ));
        }
        Ok(())
    }

    /// Apply `RUSTFUN_*` environment overrides.
    pub fn apply_environment_overrides(
        &mut self,
        environment: &BTreeMap<String, String>,
    ) -> rustfun_core::Result<()> {
        if let Some(name) = environment.get(ENV_FUNCTION_NAME) {
            FunctionName::new(name.clone())?;
            self.name = name.clone();
        }
        if let Some(runtime) = environment.get(ENV_RUNTIME) {
            RuntimeId::parse(runtime)?;
            self.runtime = runtime.clone();
        }
        if let Some(handler) = environment.get(ENV_HANDLER) {
            HandlerSpec::parse(handler)?;
            self.handler = handler.clone();
        }
        if let Some(memory) = environment.get(ENV_MEMORY) {
            rustfun_model::parse_bytes(memory).map_err(rustfun_core::RustFunError::from)?;
            self.resources.memory = Some(memory.clone());
        }
        if let Some(timeout) = environment.get(ENV_TIMEOUT) {
            rustfun_model::parse_duration(timeout).map_err(rustfun_core::RustFunError::from)?;
            self.resources.timeout = Some(timeout.clone());
        }
        if let Some(kind) = environment.get(ENV_SANDBOX) {
            parse_sandbox_kind(kind)?;
            self.sandbox.kind = Some(kind.clone());
        }
        Ok(())
    }

    /// Build the domain spec, resolving `source` relative to `manifest_dir`.
    pub fn to_spec(&self, manifest_dir: &Path) -> rustfun_core::Result<FunctionSpec> {
        let name = FunctionName::new(self.name.clone())?;
        let runtime = RuntimeId::parse(&self.runtime)?;
        let handler = HandlerSpec::parse(&self.handler)?;
        // `source = "."` must resolve to the manifest directory itself, not `<dir>/.`.
        let source = {
            let joined = manifest_dir.join(&self.build.source);
            if self.build.source == "." {
                manifest_dir.to_path_buf()
            } else {
                joined
            }
        };

        let mut environment = rustfun_model::Environment::new();
        for (key, value) in &self.environment {
            environment.insert_user(key, value)?;
        }

        let resources = self.to_resource_limits()?;
        let sandbox = self.to_sandbox_policy()?;

        let mut spec = FunctionSpec::new(name, runtime, handler)
            .with_source(rustfun_model::FunctionSource::Directory {
                path: source.to_string_lossy().into_owned(),
            })
            .with_environment(environment)
            .with_resources(resources)
            .with_sandbox(sandbox);
        spec.max_concurrency = self.max_concurrency;
        spec.status = FunctionStatus::Pending;
        spec.metadata.description = self.metadata.description.clone();
        spec.metadata.labels = self.metadata.labels.clone();
        spec.validate()?;
        Ok(spec)
    }

    /// Convert `[resources]` into the domain resource limits.
    pub fn to_resource_limits(&self) -> rustfun_core::Result<ResourceLimits> {
        let mut limits = ResourceLimits::default();
        if let Some(memory) = &self.resources.memory {
            limits.memory_bytes = rustfun_model::parse_bytes(memory)?;
        }
        if let Some(timeout) = &self.resources.timeout {
            limits.timeout = rustfun_model::parse_duration(timeout)?;
        }
        if let Some(cpu) = self.resources.cpu_millis_per_second {
            limits.cpu = Some(rustfun_model::CpuLimit::from_millis_per_second(cpu)?);
        }
        if let Some(processes) = self.resources.max_processes {
            limits.max_processes = Some(rustfun_model::ProcessLimit(processes));
        }
        if let Some(files) = self.resources.max_open_files {
            limits.max_open_files = Some(rustfun_model::FileDescriptorLimit(files));
        }
        if let Some(payload) = self.resources.max_payload_bytes {
            limits.max_payload_bytes = payload;
        }
        limits.validate()?;
        Ok(limits)
    }

    /// Convert `[sandbox]` into the domain sandbox policy.
    pub fn to_sandbox_policy(&self) -> rustfun_core::Result<SandboxPolicy> {
        let mut policy = match &self.sandbox.kind {
            Some(kind) => match parse_sandbox_kind(kind)? {
                SandboxKind::Host => SandboxPolicy::host(),
                SandboxKind::Linux => SandboxPolicy::linux(),
                SandboxKind::Wasm => SandboxPolicy::wasm(),
                SandboxKind::Oci => SandboxPolicy::oci(),
            },
            None => SandboxPolicy::default(),
        };
        if let Some(seccomp) = self.sandbox.seccomp {
            policy.seccomp = seccomp;
        }
        if self.sandbox.allow_host_paths {
            policy.filesystem.allow_host_paths = true;
        }
        policy.validate()?;
        Ok(policy)
    }

    /// The build command, if any.
    pub fn build_command(&self) -> Option<Vec<String>> {
        if self.build.command.is_empty() {
            None
        } else {
            Some(self.build.command.clone())
        }
    }

    /// Locate the manifest for `dir`, walking upwards.
    pub fn discover(dir: &Path) -> Option<PathBuf> {
        let mut current = Some(dir);
        while let Some(path) = current {
            let candidate = path.join("rustfun.toml");
            if candidate.is_file() {
                return Some(candidate);
            }
            current = path.parent();
        }
        None
    }
}

fn parse_sandbox_kind(raw: &str) -> rustfun_core::Result<SandboxKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "host" | "none" | "dev" => Ok(SandboxKind::Host),
        "linux" => Ok(SandboxKind::Linux),
        "wasm" => Ok(SandboxKind::Wasm),
        "oci" | "container" => Ok(SandboxKind::Oci),
        other => Err(rustfun_core::RustFunError::validation(format!(
            "unknown sandbox kind '{other}' (expected host, linux, wasm, or oci)"
        ))
        .with_context(
            rustfun_core::ErrorContext::new()
                .operation("parse_manifest")
                .remediation("set `[sandbox] kind` to one of: host, linux, wasm, oci"),
        )),
    }
}

/// Discover, load, and convert a manifest in one step.
pub fn load_spec(dir: &Path) -> rustfun_core::Result<(PathBuf, FunctionSpec)> {
    let path = Manifest::discover(dir).ok_or_else(|| {
        rustfun_core::RustFunError::not_found(format!(
            "no rustfun.toml found in {} or its parents",
            dir.display()
        ))
        .with_context(
            rustfun_core::ErrorContext::new()
                .operation("load_manifest")
                .remediation("run `rustfun init` to create a manifest"),
        )
    })?;
    let manifest = Manifest::load(&path)?;
    let dir = path.parent().unwrap_or(dir).to_path_buf();
    let spec = manifest.to_spec(&dir)?;
    Ok((path, spec))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
name = "hello"
runtime = "node@24"
handler = "index.handler"

[build]
source = "."

[resources]
memory = "512MiB"
timeout = "30s"

[sandbox]
kind = "host"

[environment]
HELLO = "world"
"#;

    #[test]
    fn parses_the_documented_example() {
        let manifest = Manifest::parse(EXAMPLE).expect("parses");
        assert_eq!(manifest.name, "hello");
        assert_eq!(manifest.runtime, "node@24");
        assert_eq!(manifest.handler, "index.handler");
        assert_eq!(
            manifest.environment.get("HELLO").map(String::as_str),
            Some("world")
        );
        assert_eq!(manifest.resources.memory.as_deref(), Some("512MiB"));
        assert_eq!(manifest.sandbox.kind.as_deref(), Some("host"));
    }

    #[test]
    fn converts_to_a_domain_spec() {
        let manifest = Manifest::parse(EXAMPLE).expect("parses");
        let spec = manifest
            .to_spec(Path::new("/tmp/functions/hello"))
            .expect("converts");
        assert_eq!(spec.name.as_str(), "hello");
        assert_eq!(spec.runtime.to_string(), "node@24");
        assert_eq!(spec.handler.as_str(), "index.handler");
        assert_eq!(spec.environment.get("HELLO"), Some("world"));
        assert_eq!(spec.resources.memory_bytes, 512 * 1024 * 1024);
        assert_eq!(spec.resources.timeout.as_secs(), 30);
        assert_eq!(spec.status, FunctionStatus::Pending);
        match &spec.source {
            rustfun_model::FunctionSource::Directory { path } => {
                assert_eq!(path, "/tmp/functions/hello");
            }
            other => panic!("unexpected source: {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_manifests_with_actionable_errors() {
        assert!(Manifest::parse("runtime = \"node@24\"").is_err());
        let err = Manifest::parse("name = \"Hello\"\nruntime = \"node@24\"\nhandler = \"a.b\"")
            .expect_err("invalid name");
        assert_eq!(err.code(), "RUSTFUN_VALIDATION");

        let err = Manifest::parse("name = \"a\"\nruntime = \"cobol@1\"\nhandler = \"a.b\"")
            .expect_err("unknown runtime");
        assert!(err.to_string().contains("cobol"));
    }

    #[test]
    fn rejects_newer_schema_versions() {
        let text = format!(
            "schema_version = {}\nname = \"a\"\nruntime = \"node@24\"\nhandler = \"a.b\"",
            rustfun_model::MANIFEST_SCHEMA_VERSION + 1
        );
        let err = Manifest::parse(&text).expect_err("future schema");
        assert!(err.context().remediation.is_some());
    }

    #[test]
    fn environment_overrides_win() {
        let mut manifest = Manifest::parse(EXAMPLE).expect("parses");
        let overrides = BTreeMap::from([
            (ENV_FUNCTION_NAME.to_owned(), "overridden".to_owned()),
            (ENV_RUNTIME.to_owned(), "python@3.12".to_owned()),
            (ENV_MEMORY.to_owned(), "1GiB".to_owned()),
            (ENV_TIMEOUT.to_owned(), "5s".to_owned()),
            (ENV_SANDBOX.to_owned(), "wasm".to_owned()),
        ]);
        manifest
            .apply_environment_overrides(&overrides)
            .expect("applies");
        assert_eq!(manifest.name, "overridden");
        assert_eq!(manifest.runtime, "python@3.12");
        assert_eq!(manifest.resources.memory.as_deref(), Some("1GiB"));
        assert_eq!(manifest.sandbox.kind.as_deref(), Some("wasm"));
    }

    #[test]
    fn invalid_overrides_are_rejected() {
        let mut manifest = Manifest::parse(EXAMPLE).expect("parses");
        let overrides = BTreeMap::from([(ENV_RUNTIME.to_owned(), "cobol@1".to_owned())]);
        assert!(manifest.apply_environment_overrides(&overrides).is_err());
    }

    #[test]
    fn sandbox_policies_are_converted() {
        let mut manifest = Manifest::parse(EXAMPLE).expect("parses");
        manifest.sandbox.kind = Some("linux".to_owned());
        manifest.sandbox.seccomp = Some(true);
        let policy = manifest.to_sandbox_policy().expect("converts");
        assert_eq!(policy.kind, SandboxKind::Linux);
        assert!(policy.seccomp);
        assert!(policy.is_secured());
    }

    #[test]
    fn reserved_environment_names_are_rejected() {
        let text = concat!(
            "name = \"a\"\n",
            "runtime = \"node@24\"\n",
            "handler = \"a.b\"\n\n",
            "[environment]\n",
            "RUSTFUN_FUNCTION_ID = \"spoof\"\n"
        );
        let manifest = Manifest::parse(text).expect("parses");
        let err = manifest.to_spec(Path::new("/tmp")).expect_err("reserved");
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn manifests_round_trip_through_toml() {
        let manifest = Manifest::parse(EXAMPLE).expect("parses");
        let text = manifest.to_toml().expect("serializes");
        let again = Manifest::parse(text.as_str()).expect("re-parses");
        assert_eq!(again.name, manifest.name);
        assert_eq!(again.environment, manifest.environment);
        assert_eq!(again.resources.timeout, manifest.resources.timeout);
    }

    #[test]
    fn build_commands_are_exposed_without_a_shell() {
        let text = concat!(
            "name = \"a\"\n",
            "runtime = \"node@24\"\n",
            "handler = \"a.b\"\n\n",
            "[build]\n",
            "command = [\"npm\", \"run\", \"build\"]\n"
        );
        let manifest = Manifest::parse(text).expect("parses");
        assert_eq!(
            manifest.build_command(),
            Some(vec!["npm".to_owned(), "run".to_owned(), "build".to_owned()])
        );
    }

    #[test]
    fn discovery_walks_upwards() {
        let root = std::env::temp_dir().join(format!("rustfun-discover-{}", std::process::id()));
        let nested = root.join("a/b/c");
        std::fs::create_dir_all(&nested).expect("creates");
        std::fs::write(root.join("rustfun.toml"), EXAMPLE).expect("writes");
        let found = Manifest::discover(&nested).expect("finds");
        assert_eq!(found, root.join("rustfun.toml"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_fields_are_preserved() {
        // Top-level keys must appear before the first table, otherwise they belong to it.
        let head = EXAMPLE.split("\n[build]").next().unwrap_or(EXAMPLE);
        let text = format!("{head}\nfuture_option = \"kept\"\n");
        let manifest = Manifest::parse(text.as_str()).expect("parses");
        assert!(manifest.extra.contains_key("future_option"));
    }
}
