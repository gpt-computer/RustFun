//! The function manager: the control-plane entry point.
//!
//! The manager owns function *definitions* and their lifecycle:
//! `create → build → ready → invoke* → destroy`.
//!
//! It does **not** own instances. Instances, pooling, and scheduling live behind the
//! [`Invoker`] trait, which `rustfun-instance` implements. That inversion is what keeps the
//! dependency direction correct: core knows *what* must happen, the instance layer knows
//! *how* it happens.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use rustfun_events::{Event, EventKind};
use rustfun_model::{
    Digest, FunctionId, FunctionName, FunctionSpec, FunctionStatus, InstanceId, InvocationId,
    RequestId, RuntimeId,
};

use crate::artifact::{ArtifactStore, BuiltArtifact};
use crate::error::{ErrorContext, Result, RustFunError};
use crate::event::{EventBus, LogLevel, LogRecord};
use crate::observability::Metrics;
use crate::protocol::{InvocationRequest, InvocationResponse, InvocationStatus};
use crate::runtime::RuntimeRegistry;

/// Public description of a live instance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstanceInfo {
    /// Instance identifier.
    pub instance_id: InstanceId,
    /// Function served.
    pub function_id: FunctionId,
    /// Function name.
    pub function_name: String,
    /// Runtime backing the instance.
    pub runtime: String,
    /// Current lifecycle state name.
    pub state: String,
    /// Invocations served so far.
    pub invocation_count: u64,
    /// Seconds since the Unix epoch when the instance was created.
    pub created_at: u64,
    /// Seconds since the Unix epoch when the instance last served an invocation.
    pub last_used_at: u64,
}

/// The execution backend used by the manager.
///
/// Implemented by `rustfun-instance` (warm pool + scheduler). Tests and embedders may
/// implement it directly.
#[async_trait]
pub trait Invoker: Send + Sync {
    /// Invoke a function on a suitable instance.
    async fn invoke(
        &self,
        spec: Arc<FunctionSpec>,
        artifact: Arc<BuiltArtifact>,
        request: InvocationRequest,
    ) -> Result<InvocationResponse>;

    /// Describe live instances.
    async fn instances(&self) -> Vec<InstanceInfo>;

    /// Release all instances held by this invoker.
    async fn drain(&self) -> Result<()> {
        Ok(())
    }
}

/// A function manager that never starts instances (used before an invoker is attached).
#[derive(Debug, Default)]
pub struct NoopInvoker;

#[async_trait]
impl Invoker for NoopInvoker {
    async fn invoke(
        &self,
        _spec: Arc<FunctionSpec>,
        _artifact: Arc<BuiltArtifact>,
        _request: InvocationRequest,
    ) -> Result<InvocationResponse> {
        Err(
            RustFunError::unavailable("no execution backend is attached to this function manager")
                .with_remediation("attach an invoker (rustfun-instance) before invoking functions"),
        )
    }

    async fn instances(&self) -> Vec<InstanceInfo> {
        Vec::new()
    }
}

/// Manager configuration.
#[derive(Debug, Clone)]
pub struct FunctionManagerConfig {
    /// Root directory for build outputs and extracted artifacts.
    pub workdir: PathBuf,
    /// Directory relative source paths resolve against (normally the manifest's directory).
    pub base_dir: PathBuf,
    /// Whether to verify artifact digests on extraction.
    pub verify_artifacts: bool,
    /// Maximum payload accepted by `invoke` when a spec does not set a smaller limit.
    pub max_payload_bytes: usize,
}

impl Default for FunctionManagerConfig {
    fn default() -> Self {
        Self {
            workdir: std::env::temp_dir().join("rustfun"),
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            verify_artifacts: true,
            max_payload_bytes: 4 * 1024 * 1024,
        }
    }
}

struct FunctionEntry {
    spec: Arc<FunctionSpec>,
    artifact: Option<Arc<BuiltArtifact>>,
}

/// The function control plane.
pub struct FunctionManager {
    config: FunctionManagerConfig,
    functions: RwLock<BTreeMap<FunctionId, FunctionEntry>>,
    by_name: RwLock<BTreeMap<FunctionName, FunctionId>>,
    registry: RuntimeRegistry,
    artifacts: Mutex<Option<Arc<dyn ArtifactStore>>>,
    invoker: RwLock<Arc<dyn Invoker + Send + Sync>>,
    bus: std::sync::RwLock<EventBus>,
    metrics: Arc<Metrics>,
    sequence: AtomicU64,
}

impl std::fmt::Debug for FunctionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionManager")
            .field("workdir", &self.config.workdir)
            .field("functions", &self.len())
            .finish()
    }
}

impl FunctionManager {
    /// Create a manager.
    pub fn new(config: FunctionManagerConfig, registry: RuntimeRegistry) -> Self {
        Self {
            config,
            functions: RwLock::new(BTreeMap::new()),
            by_name: RwLock::new(BTreeMap::new()),
            registry,
            artifacts: Mutex::new(None),
            invoker: RwLock::new(Arc::new(NoopInvoker)),
            bus: std::sync::RwLock::new(EventBus::new()),
            metrics: Arc::new(Metrics::new()),
            sequence: AtomicU64::new(0),
        }
    }

    /// Attach an artifact store. Building requires one.
    pub fn set_artifact_store(&self, store: Arc<dyn ArtifactStore>) {
        if let Ok(mut slot) = self.artifacts.lock() {
            *slot = Some(store);
        }
    }

    /// Replace the event bus, so the manager and the scheduler publish to one stream.
    ///
    /// Without this, lifecycle events would be split across two buses and no single consumer
    /// could reconstruct an invocation end to end.
    pub fn set_event_bus(&self, bus: EventBus) {
        let mut slot = self.bus.write().expect("event bus lock");
        *slot = bus;
    }

    /// Attach an execution backend.
    pub fn set_invoker(&self, invoker: Arc<dyn Invoker + Send + Sync>) {
        if let Ok(mut slot) = self.invoker.write() {
            *slot = invoker;
        }
    }

    /// Event bus used by the manager.
    pub fn events(&self) -> EventBus {
        self.bus
            .read()
            .map(|bus| bus.clone())
            .unwrap_or_else(|_| EventBus::new())
    }

    /// Metrics registry.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Runtime registry.
    pub fn registry(&self) -> &RuntimeRegistry {
        &self.registry
    }

    /// Manager configuration.
    pub fn config(&self) -> &FunctionManagerConfig {
        &self.config
    }

    /// Number of registered functions.
    pub fn len(&self) -> usize {
        self.functions.read().map(|f| f.len()).unwrap_or(0)
    }

    /// Whether no functions are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Register a function definition.
    pub fn create(&self, spec: FunctionSpec) -> Result<Arc<FunctionSpec>> {
        spec.validate()?;
        let spec = Arc::new(spec);
        if self
            .by_name
            .read()
            .map(|names| names.contains_key(&spec.name))
            .unwrap_or(true)
        {
            return Err(
                RustFunError::conflict(format!("function '{}' already exists", spec.name))
                    .with_context(
                        ErrorContext::new()
                            .operation("create_function")
                            .function(spec.name.as_str()),
                    ),
            );
        }
        if self
            .functions
            .read()
            .map(|f| f.contains_key(&spec.id))
            .unwrap_or(true)
        {
            return Err(RustFunError::conflict(format!(
                "function id '{}' already exists",
                spec.id
            )));
        }

        self.events().emit(Event::new(EventKind::FunctionCreated {
            function_id: spec.id.clone(),
            name: spec.name.as_str().to_owned(),
            runtime: spec.runtime.to_string(),
        }));

        let stored = Arc::clone(&spec);
        if let Ok(mut functions) = self.functions.write() {
            functions.insert(
                spec.id.clone(),
                FunctionEntry {
                    spec: Arc::clone(&stored),
                    artifact: None,
                },
            );
        }
        if let Ok(mut names) = self.by_name.write() {
            names.insert(spec.name.clone(), spec.id.clone());
        }
        Ok(stored)
    }

    /// Look up a function by id.
    pub fn get(&self, id: &FunctionId) -> Result<Arc<FunctionSpec>> {
        self.functions
            .read()
            .ok()
            .and_then(|f| f.get(id).map(|e| Arc::clone(&e.spec)))
            .ok_or_else(|| {
                RustFunError::not_found(format!("function '{id}' does not exist")).with_context(
                    ErrorContext::new()
                        .operation("get_function")
                        .function_id(id.clone()),
                )
            })
    }

    /// Look up a function by name.
    pub fn get_by_name(&self, name: &FunctionName) -> Result<Arc<FunctionSpec>> {
        let id = self
            .by_name
            .read()
            .ok()
            .and_then(|names| names.get(name).cloned())
            .ok_or_else(|| {
                RustFunError::not_found(format!("function '{name}' does not exist")).with_context(
                    ErrorContext::new()
                        .operation("get_function")
                        .function(name.as_str()),
                )
            })?;
        self.get(&id)
    }

    /// List all functions, ordered by id.
    pub fn list(&self) -> Vec<Arc<FunctionSpec>> {
        match self.functions.read() {
            Ok(functions) => functions.values().map(|e| Arc::clone(&e.spec)).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// The artifact built for a function, if any.
    pub fn artifact_of(&self, id: &FunctionId) -> Option<Arc<BuiltArtifact>> {
        self.functions
            .read()
            .ok()
            .and_then(|f| f.get(id).and_then(|e| e.artifact.clone()))
    }

    /// Update the mutable state of a function.
    fn with_entry<R>(&self, id: &FunctionId, f: impl FnOnce(&mut FunctionEntry) -> R) -> Result<R> {
        let mut functions = self.functions.write().map_err(|_| {
            RustFunError::internal("function registry lock is poisoned")
                .with_context(ErrorContext::new().operation("update_function"))
        })?;
        let entry = functions.get_mut(id).ok_or_else(|| {
            RustFunError::not_found(format!("function '{id}' does not exist")).with_context(
                ErrorContext::new()
                    .operation("update_function")
                    .function_id(id.clone()),
            )
        })?;
        Ok(f(entry))
    }

    /// Build (or reuse a cached) artifact for a function.
    pub async fn build(&self, id: &FunctionId, force: bool) -> Result<BuiltArtifact> {
        let spec = self.get(id)?;
        let store = self
            .artifacts
            .lock()
            .ok()
            .and_then(|s| s.clone())
            .ok_or_else(|| {
                RustFunError::unavailable("no artifact store is attached")
                    .with_context(ErrorContext::new().operation("build_function"))
            })?;

        let source_dir = self.source_dir(&spec)?;
        let mut request =
            crate::artifact::BuildRequest::new(spec.id.clone(), Arc::clone(&spec), source_dir);
        request.force_rebuild = force;
        let started = std::time::Instant::now();
        let summary = store.build(request).await.map_err(|e| {
            e.with_context(
                ErrorContext::new()
                    .operation("build_function")
                    .function(spec.name.as_str())
                    .function_id(spec.id.clone()),
            )
        })?;
        let duration_ms = started.elapsed().as_millis() as u64;
        self.metrics.record_build(duration_ms);

        let extraction_root = self.config.workdir.join("artifacts");
        let path = store
            .extract(&summary.digest, &extraction_root)
            .await
            .map_err(|e| {
                e.with_context(
                    ErrorContext::new()
                        .operation("extract_artifact")
                        .function(spec.name.as_str()),
                )
            })?;
        let artifact = Arc::new(BuiltArtifact::new(&summary, path));

        let cached = !force && self.sequence.load(Ordering::Relaxed) > 0 && summary.file_count > 0;
        self.events().emit(if cached {
            Event::new(EventKind::ArtifactCached {
                function_id: spec.id.clone(),
                digest: summary.digest.clone(),
            })
        } else {
            Event::new(EventKind::ArtifactBuilt {
                function_id: spec.id.clone(),
                digest: summary.digest.clone(),
                size_bytes: summary.size_bytes,
                duration_ms,
            })
        });

        let updated = Arc::new(FunctionSpec {
            status: FunctionStatus::Ready,
            ..(*spec).clone()
        });
        self.with_entry(id, |entry| {
            entry.spec = Arc::clone(&updated);
            entry.artifact = Some(Arc::clone(&artifact));
        })?;

        Ok(BuiltArtifact {
            digest: summary.digest,
            path: artifact.path.clone(),
            size_bytes: summary.size_bytes,
            file_count: summary.file_count,
        })
    }

    fn source_dir(&self, spec: &FunctionSpec) -> Result<PathBuf> {
        match &spec.source {
            rustfun_model::FunctionSource::Directory { path } => {
                // Relative source paths are resolved against the manifest's directory, which is
                // what an author writing `source = "."` expects.
                let dir = PathBuf::from(path);
                if dir.is_absolute() {
                    Ok(dir)
                } else {
                    Ok(self.config.base_dir.join(dir))
                }
            }
            rustfun_model::FunctionSource::Artifact { digest, .. } => {
                let dir = self.config.workdir.join("sources").join(digest.hex());
                Ok(dir)
            }
            rustfun_model::FunctionSource::Inline { .. } => Ok(self.config.workdir.join("inline")),
        }
    }

    /// Invoke a function by id.
    pub async fn invoke(
        &self,
        id: &FunctionId,
        payload: Vec<u8>,
        timeout: Option<Duration>,
        metadata: BTreeMap<String, String>,
        environment: BTreeMap<String, String>,
    ) -> Result<InvocationResponse> {
        let spec = self.get(id)?;
        if spec.status != FunctionStatus::Ready {
            return Err(RustFunError::conflict(format!(
                "function '{}' is {} and cannot be invoked",
                spec.name, spec.status
            ))
            .with_context(
                ErrorContext::new()
                    .operation("invoke")
                    .function(spec.name.as_str())
                    .function_id(spec.id.clone())
                    .remediation("run `rustfun build` (or POST /functions/:id/build) first"),
            ));
        }
        let artifact = self.artifact_of(id).ok_or_else(|| {
            RustFunError::unavailable(format!("function '{}' has no artifact", spec.name))
                .with_context(
                    ErrorContext::new()
                        .operation("invoke")
                        .function_id(spec.id.clone()),
                )
        })?;

        let max_payload = spec
            .resources
            .max_payload_bytes
            .min(self.config.max_payload_bytes);
        if payload.len() > max_payload {
            return Err(RustFunError::resource(format!(
                "payload of {} bytes exceeds the limit of {max_payload} bytes",
                payload.len()
            ))
            .with_context(
                ErrorContext::new()
                    .operation("invoke")
                    .function(spec.name.as_str())
                    .detail("limit_bytes", max_payload.to_string()),
            ));
        }

        let deadline = timeout.unwrap_or(spec.resources.timeout);
        let request_id = RequestId::new();
        let invocation_id = InvocationId::new();
        let mut request =
            InvocationRequest::new(request_id, invocation_id.clone(), spec.id.clone(), payload)
                .with_function_name(spec.name.as_str())
                .with_deadline(deadline);
        for (key, value) in metadata {
            request = request.with_metadata(key, value);
        }
        for (key, value) in environment {
            request = request.with_environment(key, value);
        }

        self.events().emit(Event::new(EventKind::InvocationStarted {
            invocation_id: invocation_id.clone(),
            function_id: spec.id.clone(),
            instance_id: None,
        }));

        let invoker = self.invoker();
        let started = std::time::Instant::now();
        let outcome = invoker.invoke(Arc::clone(&spec), artifact, request).await;
        let elapsed = started.elapsed();

        match outcome {
            Ok(mut response) => {
                let success = response.status == InvocationStatus::Success;
                response.duration_ms = response.duration_ms.max(elapsed.as_millis() as u64);
                self.metrics
                    .record_invocation(elapsed.as_millis() as u64, success);
                let context = ErrorContext::new()
                    .operation("invoke")
                    .function(spec.name.as_str())
                    .function_id(spec.id.clone())
                    .invocation_id(invocation_id.clone());
                if success {
                    if let Some(instance) = response.instance_id.clone() {
                        self.events()
                            .emit(Event::new(EventKind::InvocationCompleted {
                                invocation_id: invocation_id.clone(),
                                function_id: spec.id.clone(),
                                instance_id: instance,
                                duration_ms: response.duration_ms,
                                response_bytes: response.payload.len(),
                            }));
                    }
                } else {
                    let (code, message) = response.error.as_ref().map_or(
                        (
                            "RUSTFUN_FUNCTION_ERROR".to_owned(),
                            "invocation failed".to_owned(),
                        ),
                        |e| (e.code.clone(), e.message.clone()),
                    );
                    self.events().emit(Event::new(EventKind::InvocationFailed {
                        invocation_id: invocation_id.clone(),
                        function_id: spec.id.clone(),
                        instance_id: response.instance_id.clone(),
                        code: code.clone(),
                        message: message.clone(),
                    }));
                    self.events().log(LogRecord::new(
                        LogLevel::Warn,
                        "manager",
                        format!("invocation {invocation_id} failed: {message}"),
                    ));
                    let _ = context;
                }
                Ok(response)
            }
            Err(err) => {
                self.metrics
                    .record_invocation(elapsed.as_millis() as u64, false);
                self.events().emit(Event::new(EventKind::InvocationFailed {
                    invocation_id: invocation_id.clone(),
                    function_id: spec.id.clone(),
                    instance_id: None,
                    code: err.code().to_owned(),
                    message: err.message().to_owned(),
                }));
                Err(err.with_context(
                    ErrorContext::new()
                        .operation("invoke")
                        .function(spec.name.as_str())
                        .function_id(spec.id.clone())
                        .invocation_id(invocation_id.clone()),
                ))
            }
        }
    }

    /// Invoke a function by name.
    pub async fn invoke_by_name(&self, name: &str, payload: Vec<u8>) -> Result<InvocationResponse> {
        let spec = self
            .get_by_name(&FunctionName::new(name).map_err(RustFunError::from)?)
            .map_err(|e| e.with_context(ErrorContext::new().operation("invoke")))?;
        self.invoke(&spec.id, payload, None, BTreeMap::new(), BTreeMap::new())
            .await
    }

    /// The attached execution backend.
    fn invoker(&self) -> Arc<dyn Invoker + Send + Sync> {
        self.invoker
            .read()
            .map(|invoker| Arc::clone(&invoker))
            .unwrap_or_else(|_| Arc::new(NoopInvoker))
    }

    /// Describe live instances across all functions.
    pub async fn instances(&self) -> Vec<InstanceInfo> {
        // Clone the backend out of the lock before awaiting: a lock guard must never be held
        // across an await point.
        self.invoker().instances().await
    }

    /// Destroy a function and release its instances and artifact reference.
    pub async fn destroy(&self, id: &FunctionId) -> Result<()> {
        let spec = self.get(id)?;

        self.events().emit(Event::new(EventKind::InstanceDestroyed {
            instance_id: InstanceId::new(),
        }));
        if let Ok(mut functions) = self.functions.write() {
            functions.remove(id);
        }
        if let Ok(mut names) = self.by_name.write() {
            names.remove(&spec.name);
        }
        self.events().emit(Event::new(EventKind::FunctionDestroyed {
            function_id: spec.id.clone(),
            name: spec.name.as_str().to_owned(),
        }));
        Ok(())
    }

    /// Destroy every function, draining the invoker.
    pub async fn destroy_all(&self) -> Result<usize> {
        let ids: Vec<FunctionId> = self.list().iter().map(|s| s.id.clone()).collect();
        for id in &ids {
            self.destroy(id).await?;
        }
        self.invoker().drain().await?;
        Ok(ids.len())
    }

    /// Attach a previously built artifact to a function.
    ///
    /// Used to restore state across processes: a manifest on disk carries no build state, so a
    /// fresh process re-attaches the cached artifact instead of rebuilding it.
    pub fn attach_artifact(&self, id: &FunctionId, artifact: BuiltArtifact) -> Result<()> {
        self.with_entry(id, |entry| {
            entry.spec = Arc::new(FunctionSpec {
                status: FunctionStatus::Ready,
                ..(*entry.spec).clone()
            });
            entry.artifact = Some(Arc::new(artifact));
        })
    }

    /// Verify a function's artifact digest.
    pub async fn verify_artifact(&self, id: &FunctionId) -> Result<bool> {
        let artifact = self.artifact_of(id).ok_or_else(|| {
            RustFunError::not_found(format!("function '{id}' has no artifact"))
                .with_context(ErrorContext::new().operation("verify_artifact"))
        })?;
        let store = self
            .artifacts
            .lock()
            .ok()
            .and_then(|s| s.clone())
            .ok_or_else(|| RustFunError::unavailable("no artifact store is attached"))?;
        store.verify(&artifact.digest).await
    }

    /// Digest of a function's artifact, if built.
    pub fn digest_of(&self, id: &FunctionId) -> Option<Digest> {
        self.artifact_of(id).map(|a| a.digest.clone())
    }

    /// Resolve a runtime for a function, verifying it is registered.
    pub fn resolve_runtime(&self, runtime: &RuntimeId) -> Result<()> {
        self.registry.adapter(runtime).map(|_| ())
    }

    /// Create the manager's working directory if needed.
    pub async fn ensure_workdir(&self) -> Result<PathBuf> {
        let dir = &self.config.workdir;
        tokio::fs::create_dir_all(dir).await.map_err(|e| {
            RustFunError::io(format!("cannot create workdir {}: {e}", dir.display()))
                .with_context(ErrorContext::new().operation("ensure_workdir"))
        })?;
        Ok(dir.clone())
    }

    /// Path of a function's source directory.
    pub fn source_path(&self, spec: &FunctionSpec) -> Result<PathBuf> {
        self.source_dir(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{ArtifactStore, ArtifactSummary, BuildRequest};
    use rustfun_model::{FunctionSource, HandlerSpec, RuntimeCapabilities, SandboxKind};

    struct StubStore {
        builds: AtomicU64,
    }

    #[async_trait]
    impl ArtifactStore for StubStore {
        async fn build(&self, _request: BuildRequest) -> Result<ArtifactSummary> {
            let n = self.builds.fetch_add(1, Ordering::Relaxed);
            Ok(ArtifactSummary {
                digest: Digest::sha256(format!("artifact-{n}").as_bytes()),
                size_bytes: 10,
                file_count: 2,
                created_at: 0,
            })
        }

        async fn metadata(&self, _digest: &Digest) -> Result<Option<ArtifactSummary>> {
            Ok(None)
        }

        async fn contains(&self, _digest: &Digest) -> Result<bool> {
            Ok(true)
        }

        async fn extract(&self, digest: &Digest, destination: &std::path::Path) -> Result<PathBuf> {
            Ok(destination.join(digest.hex()))
        }

        async fn remove(&self, _digest: &Digest) -> Result<()> {
            Ok(())
        }

        async fn size_bytes(&self) -> Result<u64> {
            Ok(10)
        }

        async fn evict(&self, _max_age: Duration) -> Result<usize> {
            Ok(0)
        }

        async fn verify(&self, _digest: &Digest) -> Result<bool> {
            Ok(true)
        }
    }

    struct EchoInvoker {
        calls: AtomicU64,
    }

    #[async_trait]
    impl Invoker for EchoInvoker {
        async fn invoke(
            &self,
            spec: Arc<FunctionSpec>,
            _artifact: Arc<BuiltArtifact>,
            request: InvocationRequest,
        ) -> Result<InvocationResponse> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let payload = request.payload.clone();
            Ok(InvocationResponse::success(
                request.invocation_id,
                spec.id.clone(),
                payload,
            ))
        }

        async fn instances(&self) -> Vec<InstanceInfo> {
            Vec::new()
        }
    }

    fn manager() -> FunctionManager {
        let manager = FunctionManager::new(
            FunctionManagerConfig {
                workdir: std::env::temp_dir()
                    .join(format!("rustfun-manager-test-{}", std::process::id())),
                base_dir: std::env::temp_dir(),
                ..FunctionManagerConfig::default()
            },
            RuntimeRegistry::new(),
        );
        manager.set_artifact_store(Arc::new(StubStore {
            builds: AtomicU64::new(0),
        }));
        manager
    }

    fn spec(name: &str) -> FunctionSpec {
        FunctionSpec::new(
            FunctionName::new(name).expect("valid"),
            RuntimeId::parse("node@24").expect("valid"),
            HandlerSpec::parse("index.handler").expect("valid"),
        )
        .with_source(FunctionSource::Directory {
            path: ".".to_owned(),
        })
    }

    #[tokio::test]
    async fn create_get_list_destroy() {
        let manager = manager();
        let created = manager.create(spec("hello")).expect("creates");
        assert_eq!(manager.len(), 1);
        assert!(!manager.is_empty());
        assert_eq!(manager.get(&created.id).expect("gets"), created);
        assert_eq!(
            manager
                .get_by_name(&FunctionName::new("hello").expect("valid"))
                .expect("gets by name")
                .id,
            created.id
        );
        assert_eq!(manager.list().len(), 1);

        manager.destroy(&created.id).await.expect("destroys");
        assert_eq!(manager.len(), 0);
        assert!(manager.get(&created.id).is_err());
    }

    #[tokio::test]
    async fn duplicate_names_conflict() {
        let manager = manager();
        manager.create(spec("hello")).expect("creates");
        let err = manager.create(spec("hello")).expect_err("conflict");
        assert_eq!(err.category(), crate::ErrorCategory::Conflict);
    }

    #[tokio::test]
    async fn build_marks_ready_and_stores_artifact() {
        let manager = manager();
        let created = manager.create(spec("hello")).expect("creates");
        assert_eq!(created.status, FunctionStatus::Pending);
        let artifact = manager.build(&created.id, false).await.expect("builds");
        let updated = manager.get(&created.id).expect("gets");
        assert_eq!(updated.status, FunctionStatus::Ready);
        assert_eq!(manager.digest_of(&created.id), Some(artifact.digest));
        assert_eq!(artifact.file_count, 2);
    }

    #[tokio::test]
    async fn invoke_requires_ready_function() {
        let manager = manager();
        let created = manager.create(spec("hello")).expect("creates");
        let err = manager
            .invoke(
                &created.id,
                b"{}".to_vec(),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .await
            .expect_err("not ready");
        assert_eq!(err.category(), crate::ErrorCategory::Conflict);
        assert!(err.context().remediation.is_some());
    }

    #[tokio::test]
    async fn invoke_roundtrip_through_invoker() {
        let manager = manager();
        let invoker = Arc::new(EchoInvoker {
            calls: AtomicU64::new(0),
        });
        manager.set_invoker(invoker.clone());
        let created = manager.create(spec("hello")).expect("creates");
        manager.build(&created.id, false).await.expect("builds");

        let response = manager
            .invoke(
                &created.id,
                b"{\"x\":1}".to_vec(),
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .await
            .expect("invokes");
        assert_eq!(response.status, InvocationStatus::Success);
        assert_eq!(response.payload, b"{\"x\":1}");
        assert_eq!(invoker.calls.load(Ordering::Relaxed), 1);
        assert_eq!(manager.metrics().snapshot().invocations_total, 1);
    }

    #[tokio::test]
    async fn invoke_enforces_payload_limits() {
        let manager = manager();
        manager.set_invoker(Arc::new(EchoInvoker {
            calls: AtomicU64::new(0),
        }));
        let created = manager.create(spec("hello")).expect("creates");
        manager.build(&created.id, false).await.expect("builds");
        let err = manager
            .invoke(
                &created.id,
                vec![0u8; 5 * 1024 * 1024],
                None,
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .await
            .expect_err("too large");
        assert_eq!(err.category(), crate::ErrorCategory::Resource);
    }

    #[tokio::test]
    async fn sandbox_mismatch_is_rejected_at_create() {
        let manager = manager();
        let mut bad = spec("hello");
        bad.sandbox = rustfun_model::SandboxPolicy {
            kind: SandboxKind::Wasm,
            ..rustfun_model::SandboxPolicy::default()
        };
        let err = manager.create(bad).expect_err("invalid");
        assert_eq!(err.category(), crate::ErrorCategory::Validation);
    }

    #[tokio::test]
    async fn missing_functions_report_not_found() {
        let manager = manager();
        let missing = FunctionId::new();
        assert_eq!(
            manager.get(&missing).expect_err("missing").category(),
            crate::ErrorCategory::NotFound
        );
        assert_eq!(
            manager
                .get_by_name(&FunctionName::new("ghost").expect("valid"))
                .expect_err("missing")
                .category(),
            crate::ErrorCategory::NotFound
        );
        assert!(manager
            .destroy(&missing)
            .await
            .expect_err("missing")
            .code()
            .contains("NOT_FOUND"));
    }

    #[tokio::test]
    async fn destroy_all_clears_the_registry() {
        let manager = manager();
        manager.create(spec("one")).expect("creates");
        manager.create(spec("two")).expect("creates");
        assert_eq!(manager.destroy_all().await.expect("destroys"), 2);
        assert!(manager.is_empty());
    }

    #[test]
    fn runtime_resolution_reports_unregistered_families() {
        let manager = manager();
        let err = manager
            .resolve_runtime(&RuntimeId::parse("node@24").expect("valid"))
            .expect_err("unregistered");
        assert_eq!(err.category(), crate::ErrorCategory::Unavailable);
        assert!(err.context().remediation.is_some());
    }

    #[test]
    fn runtime_capabilities_are_exposed_for_negotiation() {
        let process = RuntimeCapabilities::PROCESS;
        let process_flags: Vec<bool> = vec![process.warm_instances, process.deadlines];
        assert_eq!(process_flags, vec![true, true]);

        // The default capability set describes a runtime that can do nothing; adapters opt in.
        let defaults = RuntimeCapabilities::default();
        let default_flags: Vec<bool> = vec![
            defaults.warm_instances,
            defaults.deadlines,
            defaults.metadata,
        ];
        assert_eq!(default_flags, vec![false, false, false]);
    }
}
