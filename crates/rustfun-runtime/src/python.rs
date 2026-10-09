//! The Python runtime adapter.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use rustfun_core::runtime::{
    PrepareRequest, PreparedRuntime, RuntimeAdapter, RuntimeDiscovery, RuntimeInstance,
    StartRequest,
};
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_model::{Environment, RuntimeCapabilities, RuntimeFamily, RuntimeId, RuntimeVersion};

use crate::bootstrap::PYTHON_BOOTSTRAP;
use crate::node::to_map;
use crate::process::{ProcessInstance, ProcessLaunch, ProcessRuntimeAdapter};
use crate::{find_executable, interpreter_missing};

/// Executables probed when looking for CPython, in priority order.
const PYTHON_CANDIDATES: &[&str] = &["python3", "python"];

/// Name of the generated bootstrap file inside the function root.
pub const BOOTSTRAP_FILE: &str = ".rustfun_bootstrap.py";

/// The Python adapter.
#[derive(Debug, Clone, Default)]
pub struct PythonAdapter {
    base: ProcessRuntimeAdapter,
}

impl PythonAdapter {
    /// Create the adapter.
    pub fn new() -> Self {
        Self {
            base: ProcessRuntimeAdapter::new("python"),
        }
    }

    async fn write_bootstrap(&self, workdir: &std::path::Path) -> Result<PathBuf> {
        let path = workdir.join(BOOTSTRAP_FILE);
        tokio::fs::write(&path, PYTHON_BOOTSTRAP)
            .await
            .map_err(|e| {
                RustFunError::io(format!(
                    "cannot write the python bootstrap to {}: {e}",
                    path.display()
                ))
                .with_context(ErrorContext::new().operation("prepare_runtime"))
            })?;
        Ok(path)
    }
}

#[async_trait]
impl RuntimeAdapter for PythonAdapter {
    fn family(&self) -> RuntimeFamily {
        RuntimeFamily::Python
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::PROCESS
    }

    async fn discover(&self) -> Result<Vec<RuntimeDiscovery>> {
        let Some(executable) = find_executable(PYTHON_CANDIDATES) else {
            return Ok(vec![RuntimeDiscovery::new(
                RuntimeId::new(RuntimeFamily::Python, RuntimeVersion::Any),
                "",
            )
            .unavailable()]);
        };
        let version = self
            .base
            .probe_version(PYTHON_CANDIDATES)
            .await
            .unwrap_or_else(|| "unknown".to_owned());
        let mut discovery = RuntimeDiscovery::new(
            RuntimeId::new(RuntimeFamily::Python, RuntimeVersion::Any),
            executable,
        )
        .with_reported_version(version.clone());
        if let Some((major, minor)) = parse_python_version(&version) {
            discovery.id =
                RuntimeId::new(RuntimeFamily::Python, RuntimeVersion::Minor(major, minor));
        }
        Ok(vec![discovery])
    }

    async fn prepare(&self, request: PrepareRequest) -> Result<PreparedRuntime> {
        let executable = find_executable(PYTHON_CANDIDATES)
            .ok_or_else(|| interpreter_missing("python", PYTHON_CANDIDATES))?;
        let bootstrap = self.write_bootstrap(&request.workdir).await?;

        // `main.handler`, `handlers.greet`, or `app.py:handler`.
        let (module_path, export_name) = match request.handler.split_export() {
            Some((module, export)) => (module.to_owned(), export.to_owned()),
            None => (String::new(), String::new()),
        };
        if module_path.is_empty() {
            return Err(RustFunError::validation(
                "the python handler must name a module and an export, e.g. `main.handler` or `app.py:handler`",
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
        environment.insert("PYTHONUNBUFFERED", "1")?;
        // Keep the interpreter from writing .pyc files into a read-only function root.
        environment.insert("PYTHONDONTWRITEBYTECODE", "1")?;

        let mut command = vec![
            executable,
            "-u".to_owned(),
            bootstrap.to_string_lossy().into_owned(),
        ];
        // Honour a virtualenv selected by the manifest.
        if let Some(venv) = request.environment.get("RUSTFUN_PYTHON") {
            command[0] = format!("{venv}/bin/python3");
        }

        Ok(PreparedRuntime::new(
            request.runtime.clone(),
            command,
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

/// Extract `(major, minor)` from `Python 3.12.1`.
pub(crate) fn parse_python_version(version: &str) -> Option<(u32, u32)> {
    // `Python 3.12.1`, `3.11`, `Python v3.9.2` all describe major.minor.
    let token = version
        .split_whitespace()
        .find(|part| part.chars().any(|c| c.is_ascii_digit()))?;
    let mut components = token
        .trim_start_matches('v')
        .split('.')
        .filter_map(|part| part.parse::<u32>().ok());
    let major = components.next()?;
    let minor = components.next().unwrap_or(0);
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfun_model::{FunctionName, FunctionSpec, HandlerSpec, ResourceLimits, SandboxPolicy};

    fn request(dir: PathBuf) -> PrepareRequest {
        let spec = FunctionSpec::new(
            FunctionName::new("hello").expect("valid"),
            RuntimeId::parse("python@3.12").expect("valid"),
            HandlerSpec::parse("main.handler").expect("valid"),
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
    fn parses_python_versions() {
        assert_eq!(parse_python_version("Python 3.12.1"), Some((3, 12)));
        assert_eq!(parse_python_version("3.11"), Some((3, 11)));
        assert_eq!(parse_python_version("unknown"), None);
    }

    #[test]
    fn adapter_reports_python_family() {
        let adapter = PythonAdapter::new();
        assert_eq!(adapter.family(), RuntimeFamily::Python);
        assert!(adapter.capabilities().warm_instances);
    }

    #[tokio::test]
    async fn prepare_resolves_module_and_export() {
        if find_executable(PYTHON_CANDIDATES).is_none() {
            eprintln!("skipping: python is not installed");
            return;
        }
        let dir = std::env::temp_dir().join(format!("rustfun-py-prepare-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.expect("creates dir");
        let prepared = PythonAdapter::new()
            .prepare(request(dir.clone()))
            .await
            .expect("prepares");
        assert_eq!(
            prepared.environment.get("RUSTFUN_HANDLER_MODULE"),
            Some("main")
        );
        assert_eq!(
            prepared.environment.get("RUSTFUN_HANDLER_EXPORT"),
            Some("handler")
        );
        assert!(prepared
            .command
            .iter()
            .any(|c| c.contains("rustfun_bootstrap")));
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_colon_export_is_supported() {
        if find_executable(PYTHON_CANDIDATES).is_none() {
            eprintln!("skipping: python is not installed");
            return;
        }
        let dir = std::env::temp_dir().join(format!("rustfun-py-colon-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.expect("creates dir");
        let mut req = request(dir.clone());
        req.handler = HandlerSpec::parse("app.py:greet").expect("valid");
        let prepared = PythonAdapter::new().prepare(req).await.expect("prepares");
        assert_eq!(
            prepared.environment.get("RUSTFUN_HANDLER_MODULE"),
            Some("app.py")
        );
        assert_eq!(
            prepared.environment.get("RUSTFUN_HANDLER_EXPORT"),
            Some("greet")
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
