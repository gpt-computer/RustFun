//! The Node.js runtime adapter.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use rustfun_core::runtime::{
    PrepareRequest, PreparedRuntime, RuntimeAdapter, RuntimeDiscovery, StartRequest,
};
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_model::{Environment, RuntimeCapabilities, RuntimeFamily, RuntimeId, RuntimeVersion};

use crate::bootstrap::NODE_BOOTSTRAP;
use crate::process::{ProcessInstance, ProcessLaunch, ProcessRuntimeAdapter};
use crate::{find_executable, interpreter_missing};

/// Executables probed when looking for Node.js, in priority order.
const NODE_CANDIDATES: &[&str] = &["node", "nodejs"];

/// Name of the generated bootstrap file inside the function root.
pub const BOOTSTRAP_FILE: &str = ".rustfun-bootstrap.cjs";

/// The Node.js adapter.
///
/// The bootstrap is written as CommonJS so it can `require()` user modules directly; ES module
/// handlers are still supported because CommonJS may `await import()` them.
#[derive(Debug, Clone, Default)]
pub struct NodeAdapter {
    base: ProcessRuntimeAdapter,
}

impl NodeAdapter {
    /// Create the adapter.
    pub fn new() -> Self {
        Self {
            base: ProcessRuntimeAdapter::new("node"),
        }
    }

    /// Write the bootstrap script into the function root.
    async fn write_bootstrap(&self, workdir: &std::path::Path) -> Result<PathBuf> {
        let path = workdir.join(BOOTSTRAP_FILE);
        tokio::fs::write(&path, NODE_BOOTSTRAP).await.map_err(|e| {
            RustFunError::io(format!(
                "cannot write the node bootstrap to {}: {e}",
                path.display()
            ))
            .with_context(ErrorContext::new().operation("prepare_runtime"))
        })?;
        Ok(path)
    }
}

#[async_trait]
impl RuntimeAdapter for NodeAdapter {
    fn family(&self) -> RuntimeFamily {
        RuntimeFamily::Node
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::PROCESS
    }

    async fn discover(&self) -> Result<Vec<RuntimeDiscovery>> {
        let Some(executable) = find_executable(NODE_CANDIDATES) else {
            return Ok(vec![RuntimeDiscovery::new(
                RuntimeId::new(RuntimeFamily::Node, RuntimeVersion::Any),
                "",
            )
            .unavailable()]);
        };
        let version = self
            .base
            .probe_version(NODE_CANDIDATES)
            .await
            .unwrap_or_else(|| "unknown".to_owned());
        let mut discovery = RuntimeDiscovery::new(
            RuntimeId::new(RuntimeFamily::Node, RuntimeVersion::Any),
            executable,
        )
        .with_reported_version(version.clone());
        if let Some(major) = parse_node_major(&version) {
            discovery.id = RuntimeId::new(RuntimeFamily::Node, RuntimeVersion::Major(major));
        }
        Ok(vec![discovery])
    }

    async fn prepare(&self, request: PrepareRequest) -> Result<PreparedRuntime> {
        let executable = find_executable(NODE_CANDIDATES)
            .ok_or_else(|| interpreter_missing("node", NODE_CANDIDATES))?;
        let bootstrap = self.write_bootstrap(&request.workdir).await?;

        // The handler may be `index.handler`, `src/api.handler`, or `app.js:handler`.
        let (module_path, export_name) = match request.handler.split_export() {
            Some((module, export)) => (module.to_owned(), export.to_owned()),
            None => (String::new(), String::new()),
        };
        if module_path.is_empty() {
            return Err(RustFunError::validation(
                "the node handler must name a module and an export, e.g. `index.handler`",
            )
            .with_context(
                ErrorContext::new()
                    .operation("prepare_runtime")
                    .function(request.function_name.as_str()),
            ));
        }

        let mut environment: Environment = request.environment.clone();
        environment.insert("RUSTFUN_HANDLER_MODULE", module_path)?;
        environment.insert("RUSTFUN_HANDLER_EXPORT", export_name)?;
        environment.insert("NODE_ENV", "production")?;
        // Function code must not be able to keep the event loop alive between invocations.
        environment.insert("RUSTFUN_NODE_OPTIONS", "--max-old-space-size=0")?;

        Ok(PreparedRuntime::new(
            request.runtime.clone(),
            vec![executable, bootstrap.to_string_lossy().into_owned()],
            request.workdir.clone(),
            environment,
            self.capabilities(),
        ))
    }

    async fn start(
        &self,
        request: StartRequest,
    ) -> Result<Box<dyn rustfun_core::runtime::RuntimeInstance>> {
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

pub(crate) fn to_map(environment: &Environment) -> std::collections::BTreeMap<String, String> {
    environment
        .iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// Extract the major version from `v24.1.0`.
pub(crate) fn parse_node_major(version: &str) -> Option<u32> {
    version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfun_model::{FunctionName, FunctionSpec, HandlerSpec, ResourceLimits, SandboxPolicy};

    fn request(dir: PathBuf) -> PrepareRequest {
        let spec = FunctionSpec::new(
            FunctionName::new("hello").expect("valid"),
            RuntimeId::parse("node@24").expect("valid"),
            HandlerSpec::parse("index.handler").expect("valid"),
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

    #[test]
    fn parses_node_major_versions() {
        assert_eq!(parse_node_major("v24.1.0"), Some(24));
        assert_eq!(parse_node_major("v20.11.1"), Some(20));
        assert_eq!(parse_node_major("unknown"), None);
    }

    #[test]
    fn adapter_reports_node_family_and_process_capabilities() {
        let adapter = NodeAdapter::new();
        assert_eq!(adapter.family(), RuntimeFamily::Node);
        let capabilities = adapter.capabilities();
        assert!(capabilities.warm_instances);
        assert!(capabilities.deadlines);
        assert!(!capabilities.concurrency);
    }

    #[tokio::test]
    async fn prepare_writes_a_bootstrap_and_resolves_the_handler() {
        if find_executable(NODE_CANDIDATES).is_none() {
            eprintln!("skipping: node is not installed");
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "rustfun-node-prepare-{}-{}",
            std::process::id(),
            uuid_like()
        ));
        tokio::fs::create_dir_all(&dir).await.expect("creates dir");
        let prepared = NodeAdapter::new()
            .prepare(request(dir.clone()))
            .await
            .expect("prepares");
        assert!(prepared.command[0].ends_with("node") || prepared.command[0].ends_with("nodejs"));
        assert!(prepared.command[1].ends_with(BOOTSTRAP_FILE));
        assert_eq!(
            prepared.environment.get("RUSTFUN_HANDLER_MODULE"),
            Some("index")
        );
        assert_eq!(
            prepared.environment.get("RUSTFUN_HANDLER_EXPORT"),
            Some("handler")
        );
        assert!(dir.join(BOOTSTRAP_FILE).exists());
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn prepare_rejects_path_only_handlers() {
        if find_executable(NODE_CANDIDATES).is_none() {
            eprintln!("skipping: node is not installed");
            return;
        }
        let dir = std::env::temp_dir().join(format!("rustfun-node-bad-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.expect("creates dir");
        let mut req = request(dir.clone());
        req.handler = HandlerSpec::parse("./bin/server").expect("valid");
        let err = NodeAdapter::new().prepare(req).await.expect_err("rejects");
        assert_eq!(err.category(), rustfun_core::ErrorCategory::Validation);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    fn uuid_like() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}
