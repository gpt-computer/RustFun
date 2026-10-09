//! The host layer: a filtered child process with no isolation.
//!
//! This exists for development and for embedding. It is **not** a security boundary and every
//! report it produces says so (`IsolationStrength::None`).

use std::collections::BTreeMap;

use async_trait::async_trait;
use rustfun_core::{Result, RustFunError};
use rustfun_model::SandboxKind;
use rustfun_process::{ProcessConfig, ProcessEngine};

use crate::{IsolationReport, IsolationStrength, Sandbox, SandboxRequest, SandboxedProcess};

/// The host (development) isolation layer.
#[derive(Debug, Clone, Default)]
pub struct HostSandbox;

impl HostSandbox {
    /// Create the host sandbox.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Sandbox for HostSandbox {
    fn kind(&self) -> SandboxKind {
        SandboxKind::Host
    }

    fn is_available(&self) -> bool {
        true
    }

    async fn start(
        &self,
        engine: &ProcessEngine,
        request: SandboxRequest,
    ) -> Result<SandboxedProcess> {
        let mut iter = request.command.iter();
        let program = iter.next().cloned().ok_or_else(|| {
            RustFunError::validation("sandbox command must not be empty")
                .with_context(crate::ErrorContext::new().operation("sandbox_start"))
        })?;
        let args: Vec<String> = iter.cloned().collect();
        let config = ProcessConfig::new(program, args)
            .with_env(request.environment)
            .inherit_environment(false)
            .with_current_dir(request.function_root.clone())
            .with_shutdown_grace(request.shutdown_grace);

        let process = engine.spawn(config).await?;
        let report = IsolationReport::new(SandboxKind::Host, IsolationStrength::None)
            .applied("filtered_environment")
            .applied("dedicated_process_group")
            .applied("deadline_enforcement")
            .skipped("namespaces")
            .skipped("cgroups")
            .skipped("filesystem_isolation");
        tracing::warn!(
            layer = "host",
            "executing function code without isolation; host mode is a development convenience, not a security boundary"
        );
        Ok(SandboxedProcess { process, report })
    }
}

/// Build the environment handed to a function child.
///
/// The host environment is *not* inherited: only explicitly declared variables plus the
/// platform-reserved `RUSTFUN_*` set are passed through. This is the environment-leakage
/// defence described in `SECURITY.md`.
pub fn filtered_environment(
    declared: &rustfun_model::Environment,
    extra: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = declared
        .iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    for (key, value) in extra {
        env.insert(key.clone(), value.clone());
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfun_process::ProcessEngine;
    use std::time::Duration;

    fn request(command: Vec<String>) -> SandboxRequest {
        SandboxRequest {
            policy: rustfun_model::SandboxPolicy::host(),
            resources: rustfun_model::ResourceLimits::development(),
            function_root: std::env::temp_dir(),
            scratch_dir: std::env::temp_dir().join("rustfun-scratch"),
            command,
            environment: BTreeMap::new(),
            shutdown_grace: Duration::from_millis(100),
        }
    }

    #[tokio::test]
    async fn host_layer_starts_a_process_and_admits_no_isolation() {
        if !std::path::Path::new("/bin/sh").exists() {
            eprintln!("skipping: /bin/sh not available");
            return;
        }
        let sandbox = HostSandbox::new();
        let engine = ProcessEngine::new();
        let mut req = request(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "echo hi".to_owned(),
        ]);
        req.function_root = std::path::PathBuf::from("/");
        let started = sandbox.start(&engine, req).await.expect("starts");
        assert_eq!(started.report.kind, SandboxKind::Host);
        assert_eq!(started.report.strength, IsolationStrength::None);
        assert!(!started.is_secured());
        assert!(started.describe().contains("strength=none"));
        let _ = started.process.shutdown().await;
    }

    #[tokio::test]
    async fn empty_command_is_rejected() {
        let sandbox = HostSandbox::new();
        let engine = ProcessEngine::new();
        let err = sandbox
            .start(&engine, request(Vec::new()))
            .await
            .expect_err("empty");
        assert_eq!(err.category(), rustfun_core::ErrorCategory::Validation);
    }

    #[test]
    fn filtered_environment_uses_only_declared_values() {
        let declared = rustfun_model::Environment::from_pairs([("HELLO", "world")]);
        let mut extra = BTreeMap::new();
        extra.insert("RUSTFUN_INSTANCE_ID".to_owned(), "inst_1".to_owned());
        let env = filtered_environment(&declared, &extra);
        assert_eq!(env.len(), 2);
        assert_eq!(env.get("HELLO").map(String::as_str), Some("world"));
        assert_eq!(
            env.get("RUSTFUN_INSTANCE_ID").map(String::as_str),
            Some("inst_1")
        );
        assert!(!env.contains_key("PATH"));
    }
}
