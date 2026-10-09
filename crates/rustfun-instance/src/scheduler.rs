//! The local scheduler.
//!
//! The scheduler owns *policy*: how many invocations may run at once, how long a caller waits,
//! and what happens when capacity is exhausted. It knows nothing about how an instance runs.
//!
//! ```text
//! invoke ──▶ global semaphore ──▶ per-function pool ──▶ instance
//!              (capacity)          (warm reuse)
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rustfun_core::artifact::BuiltArtifact;
use rustfun_core::manager::{InstanceInfo, Invoker};
use rustfun_core::protocol::InvocationRequest;
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_model::FunctionId;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};

use crate::lifecycle::ManagedInstance;
use crate::pool::{InstancePool, PoolConfig, PoolSnapshot};
use crate::{emit_failure, response_from_outcome, ExecutionMetrics};

/// Scheduler policy.
/// Scheduler configuration.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Maximum invocations running at once across all functions.
    pub max_concurrent_invocations: usize,
    /// Maximum time a caller waits for global capacity.
    pub queue_timeout: Duration,
    /// Default pool policy.
    pub pool: PoolConfig,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_invocations: 32,
            queue_timeout: Duration::from_secs(30),
            pool: PoolConfig::default(),
        }
    }
}

/// A point-in-time view of the scheduler.
#[derive(Debug, Clone, PartialEq)]
pub struct SchedulerSnapshot {
    /// Invocations currently running.
    pub in_flight: usize,
    /// Invocations waiting for capacity.
    pub queued: usize,
    /// Cold starts performed.
    pub cold_starts: u64,
    /// Invocations served by a warm instance.
    pub warm_invocations: u64,
    /// Warm reuse ratio.
    pub warm_ratio: f64,
    /// Instances discarded after failures.
    pub failed_instances: u64,
    /// Per-function snapshots.
    pub pools: BTreeMap<FunctionId, PoolSnapshot>,
}

/// Routes invocations to warm instances, creating them when necessary.
pub struct Scheduler {
    config: SchedulerConfig,
    registry: rustfun_core::RuntimeRegistry,
    bus: rustfun_core::EventBus,
    metrics: Arc<ExecutionMetrics>,
    permits: Arc<Semaphore>,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    pools: RwLock<BTreeMap<FunctionId, Arc<InstancePool>>>,
    pending: Arc<std::sync::atomic::AtomicUsize>,
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler")
            .field("config", &self.config)
            .finish()
    }
}

impl Scheduler {
    /// Create a scheduler.
    pub fn new(
        config: SchedulerConfig,
        registry: rustfun_core::RuntimeRegistry,
        bus: rustfun_core::EventBus,
    ) -> Arc<Self> {
        Arc::new(Self {
            permits: Arc::new(Semaphore::new(config.max_concurrent_invocations.max(1))),
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            pending: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            config,
            registry,
            bus,
            metrics: Arc::new(ExecutionMetrics::default()),
            pools: RwLock::new(BTreeMap::new()),
        })
    }

    /// Scheduler metrics.
    pub fn metrics(&self) -> &Arc<ExecutionMetrics> {
        &self.metrics
    }

    /// Create (or fetch) the pool for a function.
    ///
    /// `workdir` is the materialized artifact instances run from; it is part of the pool
    /// identity because an instance must never execute code from a stale artifact.
    pub async fn pool_for(
        &self,
        spec: Arc<rustfun_model::FunctionSpec>,
        workdir: std::path::PathBuf,
        config: Option<PoolConfig>,
    ) -> Result<Arc<InstancePool>> {
        if let Some(existing) = self.pools.read().await.get(&spec.id) {
            if existing.workdir() == workdir {
                return Ok(Arc::clone(existing));
            }
        }
        let adapter = self.registry.adapter(&spec.runtime).map_err(|err| {
            err.with_context(
                ErrorContext::new()
                    .operation("schedule")
                    .function(spec.name.as_str())
                    .runtime(spec.runtime.to_string()),
            )
        })?;
        let pool = InstancePool::new(
            spec.id.clone(),
            config.unwrap_or_else(|| self.config.pool.clone()),
            adapter,
            workdir,
            self.bus.clone(),
            Arc::clone(&self.metrics),
        );
        let mut pools = self.pools.write().await;
        Ok(pools
            .entry(spec.id.clone())
            .or_insert_with(|| Arc::clone(&pool))
            .clone())
    }

    /// Acquire an instance for an invocation: warm first, cold start otherwise.
    pub async fn acquire_instance(
        &self,
        pool: &Arc<InstancePool>,
        spec: Arc<rustfun_model::FunctionSpec>,
    ) -> Result<(Arc<ManagedInstance>, bool)> {
        if let Some(instance) = pool.acquire(None).await {
            self.metrics.record_warm_invocation();
            return Ok((instance, true));
        }
        let instance = pool.cold_start(spec, false).await?;
        Ok((instance, false))
    }

    /// Invoke a function through the scheduler.
    pub async fn invoke(
        &self,
        spec: Arc<rustfun_model::FunctionSpec>,
        artifact: Arc<BuiltArtifact>,
        request: InvocationRequest,
        pool_config: Option<PoolConfig>,
    ) -> Result<rustfun_core::protocol::InvocationResponse> {
        let invocation_id = request.invocation_id.clone();

        let permit: OwnedSemaphorePermit = match tokio::time::timeout(
            self.config.queue_timeout,
            self.permits.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return Err(RustFunError::cancelled("the scheduler is shutting down")),
            Err(_) => {
                return Err(RustFunError::resource(format!(
                    "invocation waited more than {}ms for scheduler capacity",
                    self.config.queue_timeout.as_millis()
                ))
                .with_context(
                    ErrorContext::new()
                        .operation("schedule")
                        .function(spec.name.as_str())
                        .invocation_id(invocation_id.clone())
                        .remediation("reduce traffic or raise max_concurrent_invocations"),
                ))
            }
        };
        self.in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.pending
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.metrics.record_queued();

        let result = self
            .invoke_inner(spec, artifact, request, pool_config)
            .await;

        self.pending
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        self.in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        drop(permit);
        result
    }

    async fn invoke_inner(
        &self,
        spec: Arc<rustfun_model::FunctionSpec>,
        artifact: Arc<BuiltArtifact>,
        request: InvocationRequest,
        pool_config: Option<PoolConfig>,
    ) -> Result<rustfun_core::protocol::InvocationResponse> {
        let invocation_id = request.invocation_id.clone();
        let function_id = spec.id.clone();
        let pool = self
            .pool_for(Arc::clone(&spec), artifact.path.clone(), pool_config)
            .await?;
        let (instance, warm) = match self.acquire_instance(&pool, Arc::clone(&spec)).await {
            Ok(pair) => pair,
            Err(err) => {
                emit_failure(&self.bus, invocation_id, function_id, None, &err);
                return Err(err);
            }
        };

        if !instance.try_lease(&invocation_id).await {
            // The instance was leased between selection and use: retry with a fresh one.
            pool.release(&instance, true).await;
            let (instance, warm) = match self.acquire_instance(&pool, Arc::clone(&spec)).await {
                Ok(pair) => pair,
                Err(err) => {
                    emit_failure(&self.bus, invocation_id, function_id, None, &err);
                    return Err(err);
                }
            };
            let _ = (instance, warm);
        }

        let started = Instant::now();
        // The platform enforces the deadline, not the runtime: a runtime that ignores it must
        // not be able to run forever.
        let deadline = request.remaining_deadline();
        let outcome = match deadline {
            Some(deadline) => {
                match tokio::time::timeout(deadline, instance.invoke(request)).await {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        pool.release(&instance, false).await;
                        let mut response = rustfun_core::protocol::InvocationResponse::timeout(
                            invocation_id.clone(),
                            function_id.clone(),
                            deadline.as_millis() as u64,
                        )
                        .with_instance(instance.instance_id().clone());
                        response.duration_ms = started.elapsed().as_millis() as u64;
                        emit_failure(
                            &self.bus,
                            invocation_id.clone(),
                            function_id.clone(),
                            Some(instance.instance_id().clone()),
                            &RustFunError::timeout("invocation exceeded its deadline"),
                        );
                        return Ok(response);
                    }
                }
            }
            None => instance.invoke(request).await,
        };
        match outcome {
            Ok(outcome) => {
                let healthy = outcome.instance_healthy && instance.health().await.is_serving();
                pool.release(&instance, healthy).await;
                let warm_started = warm;
                let response =
                    response_from_outcome(outcome, invocation_id.clone(), function_id.clone())?;
                if response.status == rustfun_core::protocol::InvocationStatus::Success {
                    self.bus.emit(EventShim::completed(
                        invocation_id,
                        function_id,
                        instance.instance_id().clone(),
                        started,
                        response.payload.len(),
                    ));
                } else {
                    self.bus.emit(EventShim::failed(
                        invocation_id,
                        function_id,
                        Some(instance.instance_id().clone()),
                        &response,
                    ));
                }
                let _ = warm_started;
                Ok(response)
            }
            Err(err) => {
                pool.release(&instance, false).await;
                emit_failure(
                    &self.bus,
                    invocation_id.clone(),
                    function_id.clone(),
                    Some(instance.instance_id().clone()),
                    &err,
                );
                Err(err.with_context(
                    ErrorContext::new()
                        .operation("invoke")
                        .function(spec.name.as_str())
                        .invocation_id(invocation_id),
                ))
            }
        }
    }

    /// Describe live instances.
    pub async fn instances(&self) -> Vec<InstanceInfo> {
        let pools: Vec<Arc<InstancePool>> = self.pools.read().await.values().cloned().collect();
        let mut out = Vec::new();
        for pool in pools {
            let function_id = pool.function_id().clone();
            for instance in pool.instances().await {
                let state = instance.state().await;
                out.push(InstanceInfo {
                    instance_id: instance.instance_id().clone(),
                    function_id: function_id.clone(),
                    function_name: String::new(),
                    runtime: instance.runtime().to_string(),
                    state: state.as_str().to_owned(),
                    invocation_count: instance.invocation_count(),
                    created_at: instance.created_at(),
                    last_used_at: instance.last_used_at().await,
                });
            }
        }
        out
    }

    /// Current snapshot.
    pub async fn snapshot(&self) -> SchedulerSnapshot {
        let pools: Vec<(FunctionId, Arc<InstancePool>)> = self
            .pools
            .read()
            .await
            .iter()
            .map(|(id, pool)| (id.clone(), Arc::clone(pool)))
            .collect();
        let mut pool_snapshots = BTreeMap::new();
        for (id, pool) in pools {
            pool_snapshots.insert(id, pool.snapshot().await);
        }
        SchedulerSnapshot {
            in_flight: self.in_flight.load(std::sync::atomic::Ordering::SeqCst),
            queued: self.pending.load(std::sync::atomic::Ordering::SeqCst),
            cold_starts: self.metrics.cold_starts(),
            warm_invocations: self.metrics.warm_invocations(),
            warm_ratio: self.metrics.warm_ratio(),
            failed_instances: self.metrics.failed_instances(),
            pools: pool_snapshots,
        }
    }

    /// Drain every pool.
    pub async fn drain(&self) -> Result<usize> {
        let pools: Vec<Arc<InstancePool>> = self.pools.read().await.values().cloned().collect();
        let mut stopped = 0;
        for pool in pools {
            stopped += pool.drain().await?;
        }
        Ok(stopped)
    }
}

/// Event construction helpers kept out of the hot path for readability.
struct EventShim;

impl EventShim {
    fn completed(
        invocation_id: rustfun_model::InvocationId,
        function_id: FunctionId,
        instance_id: rustfun_model::InstanceId,
        started: Instant,
        response_bytes: usize,
    ) -> rustfun_events::Event {
        rustfun_events::Event::new(rustfun_events::EventKind::InvocationCompleted {
            invocation_id,
            function_id,
            instance_id,
            duration_ms: started.elapsed().as_millis() as u64,
            response_bytes,
        })
    }

    fn failed(
        invocation_id: rustfun_model::InvocationId,
        function_id: FunctionId,
        instance_id: Option<rustfun_model::InstanceId>,
        response: &rustfun_core::protocol::InvocationResponse,
    ) -> rustfun_events::Event {
        let (code, message) = response.error.as_ref().map_or_else(
            || {
                (
                    "RUSTFUN_FUNCTION_ERROR".to_owned(),
                    "invocation failed".to_owned(),
                )
            },
            |error| (error.code.clone(), error.message.clone()),
        );
        rustfun_events::Event::new(rustfun_events::EventKind::InvocationFailed {
            invocation_id,
            function_id,
            instance_id,
            code,
            message,
        })
    }
}

#[async_trait]
impl Invoker for Scheduler {
    async fn invoke(
        &self,
        spec: Arc<rustfun_model::FunctionSpec>,
        artifact: Arc<BuiltArtifact>,
        request: InvocationRequest,
    ) -> Result<rustfun_core::protocol::InvocationResponse> {
        Scheduler::invoke(self, spec, artifact, request, None).await
    }

    async fn instances(&self) -> Vec<InstanceInfo> {
        Scheduler::instances(self).await
    }

    async fn drain(&self) -> Result<()> {
        Scheduler::drain(self).await.map(|_| ())
    }
}
