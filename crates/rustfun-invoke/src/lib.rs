//! The invocation service.
//!
//! One façade that wires a [`FunctionManager`] to a scheduler and an artifact store, and that
//! the CLI, the HTTP API, and embedders all use. Business logic lives here so that every entry
//! point behaves identically — the CLI never re-implements lifecycle rules.
//!
//! ```text
//! CLI ─┐
//! HTTP ├─▶ InvocationService ─▶ FunctionManager ─▶ Scheduler ─▶ InstancePool
//! SDK ─┘
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustfun_core::artifact::ArtifactStore;
use rustfun_core::protocol::InvocationResponse;
use rustfun_core::{
    ErrorCategory, ErrorContext, EventBus, FunctionManager, FunctionManagerConfig, FunctionName,
    FunctionSpec, Result, RuntimeRegistry, RustFunError,
};
use rustfun_instance::{PoolConfig, Scheduler, SchedulerConfig, SchedulerSnapshot};
use serde_json::json;

/// Service configuration.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Directory holding function manifests and sources.
    pub project_dir: PathBuf,
    /// Platform state directory (artifacts, extracted trees, build output).
    pub state_dir: PathBuf,
    /// Default pool policy.
    pub pool: PoolConfig,
    /// Scheduler policy.
    pub scheduler: SchedulerConfig,
    /// Whether artifacts are verified after extraction.
    pub verify_artifacts: bool,
}

impl ServiceConfig {
    /// Default configuration rooted at `project_dir`.
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        let project_dir = project_dir.into();
        let state_dir = default_state_dir();
        Self {
            scheduler: SchedulerConfig {
                pool: PoolConfig::default(),
                ..SchedulerConfig::default()
            },
            pool: PoolConfig::default(),
            project_dir,
            state_dir,
            verify_artifacts: true,
        }
    }

    /// Override the state directory.
    #[must_use]
    pub fn with_state_dir(mut self, state_dir: impl Into<PathBuf>) -> Self {
        self.state_dir = state_dir.into();
        self
    }

    /// Override the pool policy.
    #[must_use]
    pub fn with_pool(mut self, pool: PoolConfig) -> Self {
        self.pool = pool.clone();
        self.scheduler.pool = pool;
        self
    }
}

/// `RUSTFUN_HOME`, or `~/.rustfun`.
pub fn default_state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("RUSTFUN_HOME") {
        return PathBuf::from(dir);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".rustfun")
}

/// The invocation service.
pub struct InvocationService {
    config: ServiceConfig,
    registry: RuntimeRegistry,
    manager: Arc<FunctionManager>,
    scheduler: Arc<Scheduler>,
    bus: EventBus,
}

impl std::fmt::Debug for InvocationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvocationService")
            .field("project_dir", &self.config.project_dir)
            .field("state_dir", &self.config.state_dir)
            .field("functions", &self.manager.len())
            .finish()
    }
}

impl InvocationService {
    /// Build a service from configuration.
    pub async fn new(config: ServiceConfig) -> Result<Self> {
        let registry = rustfun_runtime::default_registry();
        Self::with_registry(config, registry).await
    }

    /// Build a service with an explicit runtime registry (used by embedders and tests).
    pub async fn with_registry(config: ServiceConfig, registry: RuntimeRegistry) -> Result<Self> {
        let bus = EventBus::new();
        let manager = FunctionManager::new(
            FunctionManagerConfig {
                workdir: config.state_dir.clone(),
                base_dir: config.project_dir.clone(),
                verify_artifacts: config.verify_artifacts,
                max_payload_bytes: 8 * 1024 * 1024,
            },
            registry.clone(),
        );
        manager.set_event_bus(bus.clone());

        let scheduler = Scheduler::new(config.scheduler.clone(), registry.clone(), bus.clone());
        manager.set_invoker(Arc::clone(&scheduler) as Arc<dyn rustfun_core::Invoker + Send + Sync>);

        let store =
            rustfun_artifact::FileArtifactStore::open(config.state_dir.join("artifacts")).await?;
        manager.set_artifact_store(Arc::new(store));

        Ok(Self {
            config,
            registry,
            manager: Arc::new(manager),
            scheduler,
            bus,
        })
    }

    /// The function manager.
    pub fn manager(&self) -> &Arc<FunctionManager> {
        &self.manager
    }

    /// The scheduler.
    pub fn scheduler(&self) -> &Arc<Scheduler> {
        &self.scheduler
    }

    /// The runtime registry.
    pub fn registry(&self) -> &RuntimeRegistry {
        &self.registry
    }

    /// The event bus.
    pub fn events(&self) -> &EventBus {
        &self.bus
    }

    /// Service configuration.
    pub fn config(&self) -> &ServiceConfig {
        &self.config
    }

    /// Register a function.
    pub fn create(&self, spec: FunctionSpec) -> Result<Arc<FunctionSpec>> {
        self.manager.create(spec)
    }

    /// Load and register every manifest found directly under the project directory.
    pub async fn load_project(&self) -> Result<Vec<Arc<FunctionSpec>>> {
        let mut loaded = Vec::new();
        let mut stack = vec![self.config.project_dir.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with('.') || name == "node_modules" || name == "target" {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                if path.file_name().and_then(|n| n.to_str()) == Some("rustfun.toml") {
                    match rustfun_config::Manifest::load(&path) {
                        Ok(manifest) => {
                            let dir = path.parent().unwrap_or(&dir).to_path_buf();
                            let spec = manifest.to_spec(&dir)?;
                            match self.manager.create(spec.clone()) {
                                Ok(_) => {
                                    // Restore the cached artifact so a fresh process sees the
                                    // same lifecycle state as the one that built it.
                                    let _ = self.restore_state(&spec).await;
                                    loaded.push(Arc::new(spec));
                                }
                                Err(err) if err.category() == ErrorCategory::Conflict => {
                                    tracing::debug!(name = %spec.name, "function already registered");
                                }
                                Err(err) => return Err(err),
                            }
                        }
                        Err(err) => {
                            tracing::warn!(path = %path.display(), error = %err, "skipping manifest");
                        }
                    }
                }
            }
        }
        loaded.sort_by_key(|spec| spec.name.as_str().to_owned());
        Ok(loaded)
    }

    /// Build a function's artifact and record it so later processes can reuse it.
    pub async fn build(
        &self,
        id: &rustfun_model::FunctionId,
        force: bool,
    ) -> Result<rustfun_core::artifact::BuiltArtifact> {
        let artifact = self.manager.build(id, force).await?;
        let spec = self.manager.get(id)?;
        self.record_state(spec.name.as_str(), &artifact).await;
        Ok(artifact)
    }

    /// Build-state file for a function.
    ///
    /// Keyed by *name*, not by id: ids are generated per process, so an id-keyed file would
    /// never be found again by the next `rustfun` invocation.
    fn state_file(&self, name: &str) -> PathBuf {
        self.config
            .state_dir
            .join("functions")
            .join(format!("{name}.json"))
    }

    /// Record that a function has a usable artifact.
    async fn record_state(&self, name: &str, artifact: &rustfun_core::artifact::BuiltArtifact) {
        let path = self.state_file(name);
        if let Some(parent) = path.parent() {
            if tokio::fs::create_dir_all(parent).await.is_err() {
                return;
            }
        }
        let payload = json!({
            "name": name,
            "digest": artifact.digest.to_string(),
            "file_count": artifact.file_count,
        });
        let _ = tokio::fs::write(
            path,
            serde_json::to_vec_pretty(&payload).unwrap_or_default(),
        )
        .await;
    }

    /// Restore a previously built artifact from the cache, if it is still present.
    ///
    /// Manifests on disk carry no build state, so this is what makes `rustfun function list`
    /// report a function as `ready` in a fresh process without rebuilding it.
    pub async fn restore_state(
        &self,
        spec: &FunctionSpec,
    ) -> Option<rustfun_core::artifact::BuiltArtifact> {
        let bytes = tokio::fs::read(self.state_file(spec.name.as_str()))
            .await
            .ok()?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let digest = value["digest"]
            .as_str()?
            .parse::<rustfun_core::Digest>()
            .ok()?;
        let store =
            rustfun_artifact::FileArtifactStore::open(self.config.state_dir.join("artifacts"))
                .await
                .ok()?;
        let summary = store.metadata(&digest).await.ok().flatten()?;
        let path = store
            .extract(&digest, &self.config.state_dir.join("artifacts"))
            .await
            .ok()?;
        let artifact = rustfun_core::artifact::BuiltArtifact::new(&summary, path);
        self.manager
            .attach_artifact(&spec.id, artifact.clone())
            .ok()?;
        Some(artifact)
    }

    /// Invoke a function by name.
    pub async fn invoke_by_name(
        &self,
        name: &str,
        payload: Vec<u8>,
        timeout: Option<Duration>,
    ) -> Result<InvocationResponse> {
        let spec = self.function(name)?;
        self.ensure_built(&spec).await?;
        self.manager
            .invoke(
                &spec.id,
                payload,
                timeout,
                Default::default(),
                Default::default(),
            )
            .await
    }

    /// Invoke a function by id.
    pub async fn invoke(
        &self,
        id: &rustfun_model::FunctionId,
        payload: Vec<u8>,
        timeout: Option<Duration>,
    ) -> Result<InvocationResponse> {
        let spec = self.manager.get(id)?;
        self.ensure_built(&spec).await?;
        self.manager
            .invoke(id, payload, timeout, Default::default(), Default::default())
            .await
    }

    /// Build a function if it has no artifact yet.
    ///
    /// Development ergonomics: each `rustfun` process starts from manifests, so an explicit
    /// `rustfun build` from a previous process would otherwise be invisible. Building is
    /// content-addressed, so the repeat cost is a digest computation and a cache lookup.
    pub async fn ensure_built(&self, spec: &FunctionSpec) -> Result<()> {
        if spec.status == rustfun_core::FunctionStatus::Ready {
            return Ok(());
        }
        self.build(&spec.id, false).await?;
        Ok(())
    }

    /// Look up a function by name.
    pub fn function(&self, name: &str) -> Result<Arc<FunctionSpec>> {
        let name = FunctionName::new(name).map_err(RustFunError::from)?;
        self.manager.get_by_name(&name)
    }

    /// Destroy a function and drain its instances.
    pub async fn destroy(&self, name: &str) -> Result<()> {
        let spec = self.function(name)?;
        self.manager.destroy(&spec.id).await?;
        let _ = tokio::fs::remove_file(self.state_file(name)).await;
        self.scheduler.drain().await.map(|_| ())
    }

    /// Current scheduler snapshot.
    pub async fn metrics(&self) -> SchedulerSnapshot {
        self.scheduler.snapshot().await
    }

    /// Prometheus rendering of the platform metrics.
    pub fn prometheus(&self) -> String {
        self.manager.metrics().to_prometheus()
    }

    /// Stop every instance and release resources.
    pub async fn shutdown(&self) -> Result<usize> {
        self.scheduler.drain().await
    }
}

/// Build a service rooted at `dir` using the default state directory.
pub async fn service_for(dir: &Path) -> Result<InvocationService> {
    InvocationService::new(ServiceConfig::new(dir)).await
}

/// Error helper used by entry points that need a not-found error for a function name.
pub fn function_not_found(name: &str) -> RustFunError {
    RustFunError::not_found(format!("function '{name}' does not exist")).with_context(
        ErrorContext::new()
            .operation("resolve_function")
            .function(name)
            .remediation("run `rustfun function list` to see registered functions"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_project(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "rustfun-service-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("creates");
        dir
    }

    fn write_function(root: &Path, name: &str, runtime: &str, handler: &str, source: &str) {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).expect("creates function dir");
        std::fs::write(dir.join("index.js"), source).expect("writes handler");
        std::fs::write(
            dir.join("rustfun.toml"),
            format!(
                "name = \"{name}\"\nruntime = \"{runtime}\"\nhandler = \"{handler}\"\n\n[build]\nsource = \".\"\n"
            ),
        )
        .expect("writes manifest");
    }

    #[tokio::test]
    async fn loads_manifests_and_invokes_them() {
        let project = temp_project("load");
        write_function(
            &project,
            "hello",
            "echo@*",
            "index.handler",
            "exports.handler = () => 1;\n",
        );
        let service = service_for(&project).await.expect("builds service");
        let loaded = service.load_project().await.expect("loads project");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name.as_str(), "hello");

        service.build(&loaded[0].id, false).await.expect("builds");
        let response = service
            .invoke_by_name("hello", b"{\"n\":1}".to_vec(), None)
            .await
            .expect("invokes");
        assert!(response.is_success());
        let _ = std::fs::remove_dir_all(&project);
    }

    #[tokio::test]
    async fn destroy_removes_the_function() {
        let project = temp_project("destroy");
        write_function(&project, "hello", "echo@*", "index.handler", "");
        let service = service_for(&project).await.expect("builds service");
        service.load_project().await.expect("loads");
        service.destroy("hello").await.expect("destroys");
        let err = service
            .invoke_by_name("hello", b"{}".to_vec(), None)
            .await
            .expect_err("gone");
        assert_eq!(err.category(), ErrorCategory::NotFound);
        let _ = std::fs::remove_dir_all(&project);
    }

    #[tokio::test]
    async fn unknown_function_names_are_reported_with_remediation() {
        let project = temp_project("unknown");
        let service = service_for(&project).await.expect("builds service");
        let err = service.function("missing").expect_err("must fail");
        assert_eq!(err.category(), ErrorCategory::NotFound);
        let _ = std::fs::remove_dir_all(&project);
    }

    #[tokio::test]
    async fn invalid_function_names_are_validation_errors() {
        let project = temp_project("invalid");
        let service = service_for(&project).await.expect("builds service");
        let err = service.function("Bad Name").expect_err("must fail");
        assert_eq!(err.category(), ErrorCategory::Validation);
        let _ = std::fs::remove_dir_all(&project);
    }

    #[tokio::test]
    async fn prometheus_metrics_are_exposed() {
        let project = temp_project("metrics");
        write_function(&project, "hello", "echo@*", "index.handler", "");
        let service = service_for(&project).await.expect("builds service");
        let loaded = service.load_project().await.expect("loads");
        service.build(&loaded[0].id, false).await.expect("builds");
        service
            .invoke_by_name("hello", b"{}".to_vec(), None)
            .await
            .expect("invokes");
        let text = service.prometheus();
        assert!(text.contains("rustfun_invocations_total 1"));
        let snapshot = service.metrics().await;
        assert_eq!(snapshot.cold_starts + snapshot.warm_invocations, 1);
        let _ = std::fs::remove_dir_all(&project);
    }

    #[tokio::test]
    async fn state_directory_is_configurable() {
        let project = temp_project("state");
        let state = project.join("custom-state");
        let service = InvocationService::new(ServiceConfig::new(&project).with_state_dir(&state))
            .await
            .expect("builds service");
        assert_eq!(service.config().state_dir, state);
        assert!(state.join("artifacts").exists());
        let _ = std::fs::remove_dir_all(&project);
    }
}
