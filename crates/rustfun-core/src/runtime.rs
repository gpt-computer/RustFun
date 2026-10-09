//! Runtime abstraction: adapters, instances, discovery, and the registry.
//!
//! A runtime adapter owns *runtime-specific behavior only*. It knows how to prepare a
//! runtime, start an instance of a function, and invoke that instance. It does **not** know
//! about pooling, scheduling, or global lifecycle management — those belong to
//! [`crate::manager::FunctionManager`] and `rustfun-instance`.
//!
//! ```text
//! FunctionManager ──▶ RuntimeRegistry ──▶ RuntimeAdapter ──▶ RuntimeInstance
//!        (policy)          (resolution)      (runtime)         (one live unit)
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustfun_model::{
    Environment, FunctionName, FunctionSpec, HandlerSpec, InstanceId, InvocationId, ResourceLimits,
    RuntimeCapabilities, RuntimeFamily, RuntimeId, RuntimeVersion, SandboxPolicy,
};
use serde::{Deserialize, Serialize};

use crate::error::{ErrorContext, Result, RustFunError};
use crate::protocol::{InvocationRequest, InvocationResponse};

/// Health of a runtime instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// The instance is running and able to serve invocations.
    Healthy,
    /// The instance is running but degraded (e.g. slow, high memory).
    Degraded,
    /// The instance is not usable.
    Unhealthy,
    /// Health could not be determined.
    Unknown,
}

impl HealthStatus {
    /// Whether the instance may serve new invocations.
    pub const fn is_serving(self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Degraded)
    }
}

/// Information about a runtime discovered on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDiscovery {
    /// Runtime identity (family plus detected version).
    pub id: RuntimeId,
    /// Path to the runtime executable.
    pub executable: String,
    /// Reported version string, if the runtime could report one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_version: Option<String>,
    /// Whether this runtime satisfies the capability requirements.
    pub available: bool,
}

impl RuntimeDiscovery {
    /// Create a discovery record.
    pub fn new(id: RuntimeId, executable: impl Into<String>) -> Self {
        Self {
            id,
            executable: executable.into(),
            reported_version: None,
            available: true,
        }
    }

    /// Attach the version string reported by the runtime binary.
    #[must_use]
    pub fn with_reported_version(mut self, version: impl Into<String>) -> Self {
        self.reported_version = Some(version.into());
        self
    }

    /// Mark the runtime as unavailable.
    #[must_use]
    pub fn unavailable(mut self) -> Self {
        self.available = false;
        self
    }
}

/// Request to prepare a runtime for a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareRequest {
    /// Function being prepared.
    pub function_id: rustfun_model::FunctionId,
    /// Function name.
    pub function_name: FunctionName,
    /// Requested runtime.
    pub runtime: RuntimeId,
    /// Handler to resolve.
    pub handler: HandlerSpec,
    /// Directory containing the function source/artifact.
    pub workdir: std::path::PathBuf,
    /// Environment for the instance.
    pub environment: Environment,
    /// Resource limits.
    pub resources: ResourceLimits,
    /// Isolation policy.
    pub sandbox: SandboxPolicy,
}

impl PrepareRequest {
    /// Create a prepare request.
    pub fn new(
        function_id: rustfun_model::FunctionId,
        spec: &FunctionSpec,
        workdir: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            function_id,
            function_name: spec.name.clone(),
            runtime: spec.runtime.clone(),
            handler: spec.handler.clone(),
            workdir: workdir.into(),
            environment: spec.environment.clone(),
            resources: spec.resources,
            sandbox: spec.sandbox.clone(),
        }
    }
}

/// A runtime that has been resolved and validated for a specific function.
#[derive(Debug, Clone)]
pub struct PreparedRuntime {
    /// Resolved runtime id (with the concrete discovered version when known).
    pub runtime: RuntimeId,
    /// Command line used to launch instances.
    pub command: Vec<String>,
    /// Working directory for instances.
    pub workdir: std::path::PathBuf,
    /// Environment handed to every instance.
    pub environment: Environment,
    /// Capabilities of the adapter.
    pub capabilities: RuntimeCapabilities,
}

impl PreparedRuntime {
    /// Create a prepared runtime.
    pub fn new(
        runtime: RuntimeId,
        command: Vec<String>,
        workdir: impl Into<std::path::PathBuf>,
        environment: Environment,
        capabilities: RuntimeCapabilities,
    ) -> Self {
        Self {
            runtime,
            command,
            workdir: workdir.into(),
            environment,
            capabilities,
        }
    }
}

/// Request to start an instance.
#[derive(Debug, Clone)]
pub struct StartRequest {
    /// Function the instance serves.
    pub spec: Arc<FunctionSpec>,
    /// Identifier to give the new instance.
    pub instance_id: InstanceId,
    /// Prepared runtime information.
    pub prepared: PreparedRuntime,
    /// Whether this instance is being pre-warmed (idle) rather than created for an invocation.
    pub prewarm: bool,
}

/// Outcome of an invocation as reported by the platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationOutcome {
    /// Response returned by the runtime.
    pub response: InvocationResponse,
    /// Whether the instance remains healthy and reusable.
    pub instance_healthy: bool,
}

/// A live, invokable instance of a runtime.
///
/// Instances are single-purpose: they serve exactly one function. Warm reuse is a pool
/// concern, not an instance concern.
#[async_trait]
pub trait RuntimeInstance: Send + Sync {
    /// Identifier of this instance.
    fn instance_id(&self) -> &InstanceId;

    /// Runtime backing this instance.
    fn runtime(&self) -> &RuntimeId;

    /// Invoke the function.
    async fn invoke(&self, request: InvocationRequest) -> Result<InvocationOutcome>;

    /// Check instance health.
    async fn health(&self) -> HealthStatus;

    /// Stop the instance, releasing its resources.
    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

/// A runtime adapter: runtime-specific behavior for one runtime family.
#[async_trait]
pub trait RuntimeAdapter: Send + Sync {
    /// Runtime family this adapter serves.
    fn family(&self) -> RuntimeFamily;

    /// Capabilities this adapter supports.
    fn capabilities(&self) -> RuntimeCapabilities;

    /// Discover concrete runtime installations on the host.
    async fn discover(&self) -> Result<Vec<RuntimeDiscovery>>;

    /// Resolve a concrete runtime for a function, validating handler and environment.
    async fn prepare(&self, request: PrepareRequest) -> Result<PreparedRuntime>;

    /// Start an instance.
    async fn start(&self, request: StartRequest) -> Result<Box<dyn RuntimeInstance>>;
}

/// Constructor for a runtime adapter.
pub type RuntimeFactory = Arc<dyn Fn() -> Arc<dyn RuntimeAdapter> + Send + Sync>;

/// Resolves runtime ids to adapters.
///
/// The registry holds factories rather than instances so that adapters can hold shared state
/// (caches, sockets, discovery results) without the registry owning their lifecycle.
#[derive(Clone)]
pub struct RuntimeRegistry {
    factories: Arc<std::sync::RwLock<BTreeMap<RuntimeFamily, RuntimeFactory>>>,
}

impl std::fmt::Debug for RuntimeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeRegistry")
            .field("families", &self.families())
            .finish()
    }
}

impl Default for RuntimeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            factories: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
        }
    }

    /// Register an adapter factory for a family, replacing any previous registration.
    pub fn register(&self, factory: RuntimeFactory) {
        if let Ok(mut map) = self.factories.write() {
            map.insert(factory().family(), factory);
        }
    }

    /// Register an already-constructed adapter.
    pub fn register_adapter(&self, adapter: Arc<dyn RuntimeAdapter>) {
        if let Ok(mut map) = self.factories.write() {
            map.insert(adapter.family(), {
                let adapter = Arc::clone(&adapter);
                Arc::new(move || Arc::clone(&adapter))
            });
        }
    }

    /// Remove an adapter for a family.
    pub fn unregister(&self, family: RuntimeFamily) -> bool {
        match self.factories.write() {
            Ok(mut map) => map.remove(&family).is_some(),
            Err(_) => false,
        }
    }

    /// Registered runtime families.
    pub fn families(&self) -> Vec<RuntimeFamily> {
        match self.factories.read() {
            Ok(map) => map.keys().copied().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Whether an adapter is registered for a family.
    pub fn contains(&self, family: RuntimeFamily) -> bool {
        self.factories
            .read()
            .map(|map| map.contains_key(&family))
            .unwrap_or(false)
    }

    /// Resolve the adapter for a runtime id, failing when the family is unsupported.
    pub fn adapter(&self, runtime: &RuntimeId) -> Result<Arc<dyn RuntimeAdapter>> {
        let factory = self
            .factories
            .read()
            .ok()
            .and_then(|map| map.get(&runtime.family()).cloned())
            .ok_or_else(|| {
                RustFunError::unavailable(format!(
                    "no runtime adapter registered for '{}'",
                    runtime.family()
                ))
                .with_context(
                    ErrorContext::new()
                        .operation("resolve_runtime")
                        .runtime_id(runtime.clone())
                        .remediation(format!(
                            "register an adapter for '{}' or choose a different runtime",
                            runtime.family()
                        )),
                )
            })?;
        Ok(factory())
    }

    /// Discover every registered runtime family on the host.
    ///
    /// A failing adapter is reported as unavailable rather than aborting discovery: one
    /// broken runtime must not hide the others.
    pub async fn discover_all(
        &self,
    ) -> Vec<(
        RuntimeId,
        std::result::Result<Vec<RuntimeDiscovery>, RustFunError>,
    )> {
        let mut out = Vec::new();
        for family in self.families() {
            let runtime = RuntimeId::new(family, RuntimeVersion::Any);
            match self.adapter(&runtime) {
                Ok(adapter) => {
                    let result = adapter.discover().await;
                    out.push((runtime, result));
                }
                Err(err) => out.push((runtime, Err(err))),
            }
        }
        out
    }

    /// Discover every concrete installation matching `runtime`.
    pub async fn discover(&self, runtime: &RuntimeId) -> Result<Vec<RuntimeDiscovery>> {
        let adapter = self.adapter(runtime)?;
        let found = adapter.discover().await?;
        let matches: Vec<RuntimeDiscovery> = found
            .into_iter()
            .filter(|d| runtime.version().matches(d.id.version()))
            .collect();
        if matches.is_empty() {
            return Err(RustFunError::unavailable(format!(
                "no installation of runtime '{}' matching version requirement '{}' was found",
                runtime.family(),
                runtime.version()
            ))
            .with_context(
                ErrorContext::new()
                    .operation("discover_runtime")
                    .runtime_id(runtime.clone())
                    .remediation(
                        "run `rustfun doctor` to see available runtimes and install paths",
                    ),
            ));
        }
        Ok(matches)
    }

    /// Prepare a runtime for a function, resolving the concrete version first.
    pub async fn prepare(&self, request: PrepareRequest) -> Result<PreparedRuntime> {
        let adapter = self.adapter(&request.runtime)?;
        if !adapter.capabilities().deadlines {
            tracing::warn!(
                runtime = %request.runtime,
                "runtime does not support deadline propagation"
            );
        }
        adapter.prepare(request).await
    }
}

/// Bind a function's reserved environment variables.
///
/// Reserved variables are added last so that a user manifest can never shadow them.
pub fn reserved_environment(
    function: &FunctionSpec,
    instance_id: &InstanceId,
    invocation_id: Option<&InvocationId>,
) -> Result<Environment> {
    let mut env = function.environment.clone();
    env.insert("RUSTFUN_FUNCTION_ID", function.id.to_string())?;
    env.insert("RUSTFUN_FUNCTION_NAME", function.name.as_str())?;
    env.insert("RUSTFUN_RUNTIME", function.runtime.to_string())?;
    env.insert("RUSTFUN_HANDLER", function.handler.as_str())?;
    env.insert("RUSTFUN_INSTANCE_ID", instance_id.to_string())?;
    if let Some(id) = invocation_id {
        env.insert("RUSTFUN_INVOCATION_ID", id.to_string())?;
    }
    Ok(env)
}

/// Default idle timeout for a warm instance.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;
    use rustfun_model::FunctionId;

    struct StubAdapter {
        family: RuntimeFamily,
    }

    #[async_trait]
    impl RuntimeAdapter for StubAdapter {
        fn family(&self) -> RuntimeFamily {
            self.family
        }

        fn capabilities(&self) -> RuntimeCapabilities {
            RuntimeCapabilities::ECHO
        }

        async fn discover(&self) -> Result<Vec<RuntimeDiscovery>> {
            Ok(vec![RuntimeDiscovery::new(
                RuntimeId::new(self.family, RuntimeVersion::Major(1)),
                "/usr/bin/stub",
            )])
        }

        async fn prepare(&self, request: PrepareRequest) -> Result<PreparedRuntime> {
            Ok(PreparedRuntime::new(
                request.runtime,
                vec!["stub".to_owned()],
                request.workdir,
                request.environment,
                self.capabilities(),
            ))
        }

        async fn start(&self, _request: StartRequest) -> Result<Box<dyn RuntimeInstance>> {
            Err(RustFunError::internal(
                "stub adapter cannot start instances",
            ))
        }
    }

    #[tokio::test]
    async fn registry_resolves_registered_families() {
        let registry = RuntimeRegistry::new();
        assert!(registry.families().is_empty());
        let adapter = registry.adapter(&RuntimeId::parse("node@24").expect("valid"));
        let err = match adapter {
            Ok(_) => panic!("unregistered family must not resolve"),
            Err(err) => err,
        };
        assert_eq!(err.code(), "RUSTFUN_UNAVAILABLE");
        assert!(err.context().remediation.is_some());

        registry.register_adapter(Arc::new(StubAdapter {
            family: RuntimeFamily::Echo,
        }));
        assert!(registry.contains(RuntimeFamily::Echo));
        let adapter = registry
            .adapter(&RuntimeId::parse("echo@1").expect("valid"))
            .expect("registered");
        assert_eq!(adapter.family(), RuntimeFamily::Echo);
    }

    #[tokio::test]
    async fn discovery_filters_by_version_requirement() {
        let registry = RuntimeRegistry::new();
        registry.register_adapter(Arc::new(StubAdapter {
            family: RuntimeFamily::Echo,
        }));

        let found = registry
            .discover(&RuntimeId::parse("echo@1").expect("valid"))
            .await
            .expect("matches");
        assert_eq!(found.len(), 1);

        let result = registry
            .discover(&RuntimeId::parse("echo@9").expect("valid"))
            .await;
        let err = match result {
            Ok(found) => panic!("expected no match, found {found:?}"),
            Err(err) => err,
        };
        assert_eq!(err.category(), crate::ErrorCategory::Unavailable);
    }

    #[tokio::test]
    async fn discovery_of_all_reports_failures_per_family() {
        let registry = RuntimeRegistry::new();
        registry.register_adapter(Arc::new(StubAdapter {
            family: RuntimeFamily::Echo,
        }));
        let results = registry.discover_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_ok());
    }

    #[test]
    fn reserved_environment_cannot_be_shadowed() {
        let mut spec = FunctionSpec::new(
            FunctionName::new("hello").expect("valid"),
            RuntimeId::parse("node@24").expect("valid"),
            HandlerSpec::parse("index.handler").expect("valid"),
        );
        // The user environment cannot contain reserved names (validated on insert), but a
        // manifest could try; reserved values are applied last and must win.
        spec.environment = Environment::from_pairs([("RUSTFUN_FUNCTION_ID", "spoofed")]);
        let instance_id = InstanceId::new();
        let env = reserved_environment(&spec, &instance_id, None).expect("env");
        assert_eq!(
            env.get("RUSTFUN_FUNCTION_ID"),
            Some(spec.id.to_string().as_str())
        );
        assert_eq!(env.get("RUSTFUN_FUNCTION_NAME"), Some("hello"));
        assert!(env.get("RUSTFUN_INVOCATION_ID").is_none());
    }

    #[test]
    fn reserved_environment_includes_invocation_when_present() {
        let spec = FunctionSpec::new(
            FunctionName::new("hello").expect("valid"),
            RuntimeId::parse("node@24").expect("valid"),
            HandlerSpec::parse("index.handler").expect("valid"),
        );
        let invocation = InvocationId::new();
        let env = reserved_environment(&spec, &InstanceId::new(), Some(&invocation)).expect("env");
        assert_eq!(
            env.get("RUSTFUN_INVOCATION_ID"),
            Some(invocation.to_string().as_str())
        );
    }

    #[test]
    fn health_gating() {
        assert!(HealthStatus::Healthy.is_serving());
        assert!(HealthStatus::Degraded.is_serving());
        assert!(!HealthStatus::Unhealthy.is_serving());
        assert!(!HealthStatus::Unknown.is_serving());
    }

    #[test]
    fn discovery_serialization_is_stable() {
        let discovery =
            RuntimeDiscovery::new(RuntimeId::parse("node@24").expect("valid"), "/usr/bin/node")
                .with_reported_version("v24.1.0");
        let json = serde_json::to_string(&discovery).expect("serializes");
        let back: RuntimeDiscovery = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, discovery);
        assert_eq!(discovery.id, RuntimeId::parse("node@24").expect("valid"));
        let _ = FunctionId::new();
    }
}
