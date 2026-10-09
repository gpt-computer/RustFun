//! The warm instance pool.
//!
//! One pool per function. The pool is the only component that decides *when* to create an
//! instance and *when* to keep one alive, which keeps the scheduler free of runtime detail and
//! keeps runtime adapters free of lifecycle policy.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustfun_core::runtime::{PrepareRequest, RuntimeAdapter, StartRequest};
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_events::{Event, EventKind};
use rustfun_model::{FunctionId, FunctionSpec, InstanceId};
use tokio::sync::{Mutex, Notify, Semaphore};

use crate::lifecycle::{InstanceState, ManagedInstance};
use crate::{emit_stopped, ExecutionMetrics};

/// Pool policy.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Instances kept warm ahead of demand.
    pub min_instances: usize,
    /// Maximum instances per function.
    pub max_instances: usize,
    /// Idle time after which an instance is reclaimed.
    pub idle_timeout: Duration,
    /// Maximum time a caller waits for a warm instance before a cold start.
    pub acquire_timeout: Duration,
    /// Maximum concurrent cold starts.
    pub max_concurrent_cold_starts: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_instances: 0,
            max_instances: 8,
            idle_timeout: Duration::from_secs(60),
            acquire_timeout: Duration::from_millis(250),
            max_concurrent_cold_starts: 4,
        }
    }
}

/// A point-in-time view of a pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSnapshot {
    /// Function this pool serves.
    pub function_id: FunctionId,
    /// Instances currently alive.
    pub instances: usize,
    /// Instances ready for reuse.
    pub idle: usize,
    /// Instances serving an invocation.
    pub busy: usize,
    /// Invocations served by this pool.
    pub invocations: u64,
    /// Time since the pool was created.
    pub uptime_ms: u64,
}

/// Warm pool for a single function.
pub struct InstancePool {
    function_id: FunctionId,
    config: PoolConfig,
    adapter: Arc<dyn RuntimeAdapter>,
    workdir: std::path::PathBuf,
    idle: Mutex<VecDeque<Arc<ManagedInstance>>>,
    all: Mutex<Vec<Arc<ManagedInstance>>>,
    cold_starts: Arc<Semaphore>,
    notify: Arc<Notify>,
    bus: rustfun_core::EventBus,
    metrics: Arc<ExecutionMetrics>,
    created: Instant,
    stopping: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for InstancePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstancePool")
            .field("function_id", &self.function_id)
            .field("config", &self.config)
            .finish()
    }
}

impl InstancePool {
    /// Create a pool for `function_id` driven by `adapter`.
    pub fn new(
        function_id: FunctionId,
        config: PoolConfig,
        adapter: Arc<dyn RuntimeAdapter>,
        workdir: std::path::PathBuf,
        bus: rustfun_core::EventBus,
        metrics: Arc<ExecutionMetrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            function_id,
            cold_starts: Arc::new(Semaphore::new(config.max_concurrent_cold_starts.max(1))),
            config,
            adapter,
            workdir,
            idle: Mutex::new(VecDeque::new()),
            all: Mutex::new(Vec::new()),
            notify: Arc::new(Notify::new()),
            bus,
            metrics,
            created: Instant::now(),
            stopping: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Function served by this pool.
    pub fn function_id(&self) -> &FunctionId {
        &self.function_id
    }

    /// Pool configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Directory instances are started from (the materialized artifact).
    pub fn workdir(&self) -> &std::path::Path {
        &self.workdir
    }

    /// Borrow an idle instance, if one is immediately available.
    pub async fn try_acquire(self: &Arc<Self>) -> Option<Arc<ManagedInstance>> {
        loop {
            // Take the queue guard before awaiting on the instance so another caller can pop
            // the next candidate in the meantime.
            let candidate = self.idle.lock().await.pop_front();
            let instance = candidate?;
            if instance.is_available().await {
                return Some(instance);
            }
            self.discard(&instance, "unhealthy on acquire").await;
        }
    }

    /// Wait briefly for an idle instance to appear.
    pub async fn acquire(
        self: &Arc<Self>,
        timeout: Option<Duration>,
    ) -> Option<Arc<ManagedInstance>> {
        let deadline = timeout.unwrap_or(self.config.acquire_timeout);
        let waiter = self.notify.notified();
        if let Some(instance) = self.try_acquire().await {
            return Some(instance);
        }
        let _ = tokio::time::timeout(deadline, waiter).await;
        self.try_acquire().await
    }

    /// Create a new instance for `spec`, bounded by `max_instances` and the cold-start budget.
    pub async fn cold_start(
        self: &Arc<Self>,
        spec: Arc<FunctionSpec>,
        prewarm: bool,
    ) -> Result<Arc<ManagedInstance>> {
        if self.stopping.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(RustFunError::cancelled(format!(
                "the pool for '{}' is shutting down",
                spec.name
            ))
            .with_context(ErrorContext::new().operation("cold_start")));
        }
        let live = self.all.lock().await.len();
        if live >= self.config.max_instances {
            return Err(RustFunError::resource(format!(
                "function '{}' is at its limit of {} instances",
                spec.name, self.config.max_instances
            ))
            .with_context(
                ErrorContext::new()
                    .operation("cold_start")
                    .function(spec.name.as_str())
                    .remediation("raise max_instances or reduce concurrency"),
            ));
        }

        let permit = self
            .cold_starts
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RustFunError::cancelled("the pool is shutting down"))?;

        let started = Instant::now();
        let prepare = PrepareRequest::new(spec.id.clone(), &spec, self.workdir.clone());
        let prepared = self.adapter.prepare(prepare).await.map_err(|err| {
            err.with_context(
                ErrorContext::new()
                    .operation("cold_start")
                    .function(spec.name.as_str())
                    .function_id(spec.id.clone())
                    .runtime(spec.runtime.to_string()),
            )
        })?;

        let instance_id = InstanceId::new();
        self.bus.emit(Event::new(EventKind::InstanceCreated {
            instance_id: instance_id.clone(),
            function_id: spec.id.clone(),
            runtime: prepared.runtime.to_string(),
        }));

        let start = StartRequest {
            spec: Arc::clone(&spec),
            instance_id: instance_id.clone(),
            prepared,
            prewarm,
        };
        let runtime_instance = match self.adapter.start(start).await {
            Ok(instance) => instance,
            Err(err) => {
                self.bus.emit(Event::new(EventKind::RuntimeError {
                    runtime: spec.runtime.to_string(),
                    code: err.code().to_owned(),
                    message: err.message().to_owned(),
                }));
                self.metrics.record_failed_instance();
                return Err(err);
            }
        };
        drop(permit);

        let managed = Arc::new(ManagedInstance::new(
            instance_id.clone(),
            spec.id.clone(),
            spec.runtime.clone(),
            runtime_instance,
            spec.max_concurrency,
        ));
        managed
            .transition(InstanceState::Starting)
            .await
            .map_err(RustFunError::from)?;
        managed
            .transition(InstanceState::Ready)
            .await
            .map_err(RustFunError::from)?;

        let duration_ms = started.elapsed().as_millis() as u64;
        self.metrics.record_cold_start();
        self.bus.emit(Event::new(EventKind::InstanceStarted {
            instance_id: instance_id.clone(),
            duration_ms,
            warm: false,
        }));
        self.bus.emit(Event::new(EventKind::InstanceReady {
            instance_id: instance_id.clone(),
        }));

        // The instance is handed directly to the caller; it returns to the idle queue when the
        // invocation completes.
        self.all.lock().await.push(Arc::clone(&managed));
        self.notify.notify_waiters();
        Ok(managed)
    }

    /// Return an instance to the pool after an invocation.
    pub async fn release(&self, instance: &Arc<ManagedInstance>, healthy: bool) {
        instance.release_lease().await;
        if healthy && instance.is_available().await {
            self.idle.lock().await.push_back(Arc::clone(instance));
            self.notify.notify_waiters();
        } else if !healthy {
            self.discard(instance, "unhealthy after invocation").await;
        }
    }

    /// Remove and shut down an instance.
    pub async fn discard(&self, instance: &Arc<ManagedInstance>, reason: &str) {
        {
            let mut all = self.all.lock().await;
            all.retain(|candidate| candidate.instance_id() != instance.instance_id());
        }
        {
            let mut idle = self.idle.lock().await;
            idle.retain(|candidate| candidate.instance_id() != instance.instance_id());
        }
        self.metrics.record_failed_instance();
        emit_stopped(
            &self.bus,
            instance.instance_id().clone(),
            instance.invocation_count(),
            reason,
        );
        if let Err(err) = instance.shutdown().await {
            tracing::warn!(instance = %instance.instance_id(), error = %err, "shutdown failed");
        }
        self.bus.emit(Event::new(EventKind::InstanceDestroyed {
            instance_id: instance.instance_id().clone(),
        }));
    }

    /// Evict instances idle for longer than the configured timeout.
    pub async fn evict_idle(self: &Arc<Self>) -> usize {
        let candidates: Vec<Arc<ManagedInstance>> = {
            let mut idle = self.idle.lock().await;
            let mut keep = VecDeque::new();
            let mut evict = Vec::new();
            while let Some(instance) = idle.pop_front() {
                let idle_for = instance.idle_for().await.unwrap_or_default();
                if instance.state().await == InstanceState::Idle
                    && idle_for >= self.config.idle_timeout
                    && instance.invocation_count() > 0
                {
                    evict.push(instance);
                } else {
                    keep.push_back(instance);
                }
            }
            *idle = keep;
            evict
        };
        let count = candidates.len();
        for instance in candidates {
            self.discard(&instance, "idle timeout").await;
        }
        if count > 0 {
            self.notify.notify_waiters();
        }
        count
    }

    /// Top the pool up to `min_instances`.
    pub async fn ensure_minimum(self: &Arc<Self>, spec: Arc<FunctionSpec>) -> usize {
        let mut created = 0;
        while self.all.lock().await.len() < self.config.min_instances {
            match self.cold_start(Arc::clone(&spec), true).await {
                Ok(_) => created += 1,
                Err(err) => {
                    tracing::debug!(error = %err, "prewarm stopped early");
                    break;
                }
            }
        }
        created
    }

    /// Every instance this pool owns.
    pub async fn instances(&self) -> Vec<Arc<ManagedInstance>> {
        self.all.lock().await.clone()
    }

    /// Current snapshot.
    pub async fn snapshot(&self) -> PoolSnapshot {
        let instances = self.all.lock().await.clone();
        let mut idle = 0;
        let mut busy = 0;
        let mut invocations = 0;
        for instance in &instances {
            match instance.state().await {
                InstanceState::Idle | InstanceState::Ready | InstanceState::Creating => idle += 1,
                InstanceState::Busy => busy += 1,
                _ => {}
            }
            invocations += instance.invocation_count();
        }
        PoolSnapshot {
            function_id: self.function_id.clone(),
            instances: instances.len(),
            idle,
            busy,
            invocations,
            uptime_ms: self.created.elapsed().as_millis() as u64,
        }
    }

    /// Shut every instance down.
    pub async fn drain(&self) -> Result<usize> {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let instances = self.all.lock().await.clone();
        for instance in &instances {
            self.discard(instance, "pool drained").await;
        }
        Ok(instances.len())
    }
}
