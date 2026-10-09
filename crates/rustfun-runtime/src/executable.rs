//! The generic executable runtime adapter.
//!
//! The user's binary is expected to speak the RustFun framed invocation protocol on
//! stdin/stdout: it receives an [`InvocationRequest`](rustfun_protocol::InvocationRequest)
//! frame and replies with an [`InvocationResponse`](rustfun_protocol::InvocationResponse)
//! frame. This keeps "any language" support honest — the contract is explicit and testable
//! rather than "we shell out and hope".
//!
//! `crates/rustfun-sdk` and the conformance suite in `crates/rustfun-test` both implement the
//! contract.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use rustfun_core::runtime::{
    PrepareRequest, PreparedRuntime, RuntimeAdapter, RuntimeDiscovery, RuntimeInstance,
    StartRequest,
};
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_model::{Environment, RuntimeCapabilities, RuntimeFamily, RuntimeId, RuntimeVersion};

use crate::node::to_map;
use crate::process::{ProcessInstance, ProcessLaunch, ProcessRuntimeAdapter};

/// The generic executable adapter.
#[derive(Debug, Clone, Default)]
pub struct ExecutableAdapter {
    base: ProcessRuntimeAdapter,
}

impl ExecutableAdapter {
    /// Create the adapter.
    pub fn new() -> Self {
        Self {
            base: ProcessRuntimeAdapter::new("executable"),
        }
    }

    /// Resolve the handler path inside the function root, refusing escapes.
    fn resolve_handler_path(&self, workdir: &std::path::Path, handler: &str) -> Result<PathBuf> {
        let candidate = PathBuf::from(handler);
        if candidate.is_absolute() {
            return Err(RustFunError::validation(format!(
                "the executable handler '{handler}' must be relative to the function root"
            ))
            .with_context(ErrorContext::new().operation("prepare_runtime")));
        }
        for segment in candidate.components() {
            if matches!(segment, std::path::Component::ParentDir) {
                return Err(RustFunError::validation(format!(
                    "the executable handler '{handler}' must not traverse outside the function root"
                ))
                .with_context(ErrorContext::new().operation("prepare_runtime")));
            }
        }
        let resolved = workdir.join(&candidate);
        if !resolved.exists() {
            return Err(RustFunError::not_found(format!(
                "executable handler '{handler}' does not exist in the function root"
            ))
            .with_context(
                ErrorContext::new()
                    .operation("prepare_runtime")
                    .remediation("check the `handler` field in rustfun.toml"),
            ));
        }
        Ok(resolved)
    }
}

#[async_trait]
impl RuntimeAdapter for ExecutableAdapter {
    fn family(&self) -> RuntimeFamily {
        RuntimeFamily::Executable
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::PROCESS
    }

    async fn discover(&self) -> Result<Vec<RuntimeDiscovery>> {
        // The executable runtime has nothing to discover on the host: the binary ships with the
        // function artifact.
        Ok(vec![RuntimeDiscovery::new(
            RuntimeId::new(RuntimeFamily::Executable, RuntimeVersion::Any),
            "<function artifact>",
        )])
    }

    async fn prepare(&self, request: PrepareRequest) -> Result<PreparedRuntime> {
        let path = self.resolve_handler_path(&request.workdir, request.handler.as_str())?;
        if !path.is_file() {
            return Err(RustFunError::validation(format!(
                "the executable handler '{}' is not a file",
                request.handler
            ))
            .with_context(ErrorContext::new().operation("prepare_runtime")));
        }
        let mut environment: Environment = request.environment.clone();
        environment.insert("RUSTFUN_HANDLER", request.handler.as_str())?;
        Ok(PreparedRuntime::new(
            request.runtime.clone(),
            vec![path.to_string_lossy().into_owned()],
            request.workdir.clone(),
            environment,
            self.capabilities(),
        ))
    }

    async fn start(&self, request: StartRequest) -> Result<Box<dyn RuntimeInstance>> {
        let environment = self.base.instance_environment(
            &request.spec,
            &request.instance_id,
            &to_map(&request.prepared.environment),
        )?;
        let launch = ProcessLaunch {
            command: request.prepared.command.clone(),
            workdir: request.prepared.workdir.clone(),
            environment,
            resources: request.spec.resources,
            sandbox: request.spec.sandbox.clone(),
            runtime: request.prepared.runtime.clone(),
            shutdown_grace: Duration::from_millis(500),
        };
        let instance =
            ProcessInstance::start(request.instance_id, request.spec.id.clone(), launch).await?;
        Ok(Box::new(instance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfun_model::{FunctionName, FunctionSpec, HandlerSpec, ResourceLimits, SandboxPolicy};

    fn request(dir: PathBuf, handler: &str) -> PrepareRequest {
        let spec = FunctionSpec::new(
            FunctionName::new("hello").expect("valid"),
            RuntimeId::parse("executable").expect("valid"),
            HandlerSpec::parse(handler).expect("valid handler"),
        );
        PrepareRequest {
            function_id: spec.id,
            function_name: spec.name.clone(),
            runtime: spec.runtime.clone(),
            handler: spec.handler.clone(),
            workdir: dir,
            environment: Environment::new(),
            resources: ResourceLimits::default(),
            sandbox: SandboxPolicy::host(),
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rustfun-exec-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("creates dir");
        dir
    }

    #[test]
    fn handler_paths_cannot_escape_the_function_root() {
        let adapter = ExecutableAdapter::new();
        let dir = temp_dir("escape");
        let err = adapter
            .resolve_handler_path(&dir, "../etc/passwd")
            .expect_err("must reject");
        assert_eq!(err.category(), rustfun_core::ErrorCategory::Validation);
        assert!(adapter
            .resolve_handler_path(&dir, "/etc/passwd")
            .expect_err("must reject absolute")
            .to_string()
            .contains("relative"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_handlers_are_reported_with_remediation() {
        let adapter = ExecutableAdapter::new();
        let dir = temp_dir("missing");
        let err = adapter
            .resolve_handler_path(&dir, "./bin/server")
            .expect_err("must fail");
        assert_eq!(err.category(), rustfun_core::ErrorCategory::NotFound);
        assert!(err.context().remediation.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn prepare_resolves_an_existing_binary() {
        let dir = temp_dir("ok");
        let binary = dir.join("server");
        std::fs::write(&binary, "#!/bin/sh\nexit 0\n").expect("writes");
        let prepared = ExecutableAdapter::new()
            .prepare(request(dir.clone(), "./server"))
            .await
            .expect("prepares");
        assert_eq!(prepared.command.len(), 1);
        assert!(prepared.command[0].ends_with("server"));
        assert_eq!(
            prepared.environment.get("RUSTFUN_HANDLER"),
            Some("./server")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn discover_reports_the_artifact_as_the_executable() {
        let discovered = ExecutableAdapter::new()
            .discover()
            .await
            .expect("discovers");
        assert_eq!(discovered.len(), 1);
        assert!(discovered[0].available);
        assert_eq!(discovered[0].id.family(), RuntimeFamily::Executable);
    }
}
