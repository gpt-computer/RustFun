//! The instance state machine.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rustfun_core::runtime::{HealthStatus, InvocationOutcome, RuntimeInstance};
use rustfun_core::{Result, RustFunError};
use rustfun_model::{FunctionId, InstanceId, InvocationId, RuntimeId};
use tokio::sync::Mutex;

/// Lifecycle state of an instance.
///
/// ```text
/// Creating → Starting → Ready → Busy → Idle → Stopping → Stopped
///                          ↘ Failed
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceState {
    /// Allocated, not started yet.
    Creating,
    /// The runtime process is starting.
    Starting,
    /// Ready to serve invocations.
    Ready,
    /// Currently serving an invocation.
    Busy,
    /// Was busy, now waiting for work.
    Idle,
    /// Frozen; not scheduled but not destroyed.
    Suspended,
    /// Shutdown in progress.
    Stopping,
    /// Shut down.
    Stopped,
    /// Failed; must not be reused.
    Failed,
}

impl InstanceState {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            InstanceState::Creating => "creating",
            InstanceState::Starting => "starting",
            InstanceState::Ready => "ready",
            InstanceState::Busy => "busy",
            InstanceState::Idle => "idle",
            InstanceState::Suspended => "suspended",
            InstanceState::Stopping => "stopping",
            InstanceState::Stopped => "stopped",
            InstanceState::Failed => "failed",
        }
    }

    /// Whether the instance may serve a new invocation.
    pub const fn is_serving(self) -> bool {
        matches!(
            self,
            InstanceState::Ready | InstanceState::Idle | InstanceState::Busy
        )
    }

    /// Whether the instance is finished and must not be reused.
    pub const fn is_terminal(self) -> bool {
        matches!(self, InstanceState::Stopped | InstanceState::Failed)
    }

    /// Whether a transition to `next` is legal.
    pub const fn can_transition_to(self, next: InstanceState) -> bool {
        use InstanceState::*;
        matches!(
            (self, next),
            (Creating, Starting)
                | (Creating, Failed)
                | (Starting, Ready)
                | (Starting, Failed)
                | (Ready, Busy)
                | (Ready, Stopping)
                | (Ready, Failed)
                | (Busy, Idle)
                | (Busy, Stopping)
                | (Busy, Failed)
                | (Idle, Busy)
                | (Idle, Suspended)
                | (Idle, Stopping)
                | (Idle, Failed)
                | (Suspended, Stopping)
                | (Suspended, Failed)
                | (Stopping, Stopped)
                | (Stopping, Failed)
        )
    }
}

impl std::fmt::Display for InstanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rejected state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTransitionError {
    /// State before the attempted transition.
    pub from: InstanceState,
    /// State that was requested.
    pub to: InstanceState,
    /// Instance the transition was attempted on.
    pub instance_id: InstanceId,
}

impl std::fmt::Display for StateTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "instance {} cannot move from {} to {}",
            self.instance_id, self.from, self.to
        )
    }
}

impl std::error::Error for StateTransitionError {}

impl From<StateTransitionError> for RustFunError {
    fn from(value: StateTransitionError) -> Self {
        RustFunError::conflict(value.to_string()).with_detail("from", value.from.as_str())
    }
}

/// A live instance plus its lifecycle bookkeeping.
pub struct ManagedInstance {
    instance_id: InstanceId,
    function_id: FunctionId,
    runtime: RuntimeId,
    inner: Mutex<Box<dyn RuntimeInstance>>,
    state: Mutex<InstanceState>,
    created_at: u64,
    started_at: Mutex<Option<Instant>>,
    last_used_at: Mutex<Option<Instant>>,
    invocations: AtomicU64,
    concurrency: AtomicU64,
    max_concurrency: u32,
    lease: Mutex<Option<InvocationId>>,
}

impl std::fmt::Debug for ManagedInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedInstance")
            .field("instance_id", &self.instance_id)
            .field("function_id", &self.function_id)
            .field("runtime", &self.runtime)
            .field("invocations", &self.invocations.load(Ordering::Relaxed))
            .finish()
    }
}

impl ManagedInstance {
    /// Wrap a started runtime instance.
    pub fn new(
        instance_id: InstanceId,
        function_id: FunctionId,
        runtime: RuntimeId,
        inner: Box<dyn RuntimeInstance>,
        max_concurrency: u32,
    ) -> Self {
        Self {
            instance_id,
            function_id,
            runtime,
            inner: Mutex::new(inner),
            state: Mutex::new(InstanceState::Creating),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            started_at: Mutex::new(None),
            last_used_at: Mutex::new(None),
            invocations: AtomicU64::new(0),
            concurrency: AtomicU64::new(0),
            max_concurrency: max_concurrency.max(1),
            lease: Mutex::new(None),
        }
    }

    /// Identifier.
    pub fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    /// Function served.
    pub fn function_id(&self) -> &FunctionId {
        &self.function_id
    }

    /// Runtime backing this instance.
    pub fn runtime(&self) -> &RuntimeId {
        &self.runtime
    }

    /// Current state.
    pub async fn state(&self) -> InstanceState {
        *self.state.lock().await
    }

    /// Invocations served.
    pub fn invocation_count(&self) -> u64 {
        self.invocations.load(Ordering::Relaxed)
    }

    /// Seconds since the Unix epoch when the instance was created.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Seconds since the Unix epoch when the instance last served an invocation.
    pub async fn last_used_at(&self) -> u64 {
        let guard = self.last_used_at.lock().await;
        guard
            .map(|instant| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    .saturating_sub(instant.elapsed().as_secs())
            })
            .unwrap_or(self.created_at)
    }

    /// How long the instance has been idle, if it is idle.
    pub async fn idle_for(&self) -> Option<std::time::Duration> {
        let guard = self.last_used_at.lock().await;
        guard.map(|instant| instant.elapsed())
    }

    /// Maximum concurrent invocations.
    pub fn max_concurrency(&self) -> u32 {
        self.max_concurrency
    }

    /// Attempt a state transition, rejecting invalid ones.
    pub async fn transition(
        &self,
        next: InstanceState,
    ) -> std::result::Result<(), StateTransitionError> {
        let mut state = self.state.lock().await;
        if !state.can_transition_to(next) {
            return Err(StateTransitionError {
                from: *state,
                to: next,
                instance_id: self.instance_id.clone(),
            });
        }
        *state = next;
        if next == InstanceState::Starting {
            *self.started_at.lock().await = Some(Instant::now());
        }
        Ok(())
    }

    /// Take the invocation lease, or `None` when the instance is busy or unusable.
    pub async fn try_lease(&self, invocation_id: &InvocationId) -> bool {
        if self.concurrency.load(Ordering::Relaxed) >= u64::from(self.max_concurrency) {
            return false;
        }
        let mut lease = self.lease.lock().await;
        if lease.is_some() && self.max_concurrency == 1 {
            return false;
        }
        self.concurrency.fetch_add(1, Ordering::Relaxed);
        *lease = Some(invocation_id.clone());
        drop(lease);
        let mut state = self.state.lock().await;
        if state.can_transition_to(InstanceState::Busy) {
            *state = InstanceState::Busy;
        }
        true
    }

    /// Release the lease and move back to `Idle`.
    pub async fn release_lease(&self) {
        let _ = self.lease.lock().await.take();
        // Saturating decrement: a double release must not wrap the counter.
        let current = self.concurrency.load(Ordering::Relaxed);
        let _ = self.concurrency.compare_exchange(
            current,
            current.saturating_sub(1),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        let mut state = self.state.lock().await;
        if *state == InstanceState::Busy {
            *state = InstanceState::Idle;
        }
    }

    /// Invoke the underlying runtime instance while holding the lease.
    pub async fn invoke(
        &self,
        request: rustfun_core::protocol::InvocationRequest,
    ) -> Result<InvocationOutcome> {
        self.invocations.fetch_add(1, Ordering::Relaxed);
        *self.last_used_at.lock().await = Some(Instant::now());
        let inner = self.inner.lock().await;
        inner.invoke(request).await
    }

    /// Ask the runtime instance for its health.
    pub async fn health(&self) -> HealthStatus {
        let inner = self.inner.lock().await;
        inner.health().await
    }

    /// Shut the instance down and mark it `Stopped`.
    pub async fn shutdown(&self) -> Result<()> {
        let _ = self.transition(InstanceState::Stopping).await;
        let mut inner = self.inner.lock().await;
        inner.shutdown().await?;
        *self.state.lock().await = InstanceState::Stopped;
        Ok(())
    }

    /// Mark the instance as failed; failed instances are never reused.
    pub async fn mark_failed(&self) {
        *self.state.lock().await = InstanceState::Failed;
    }

    /// Whether the instance is ready to be handed out.
    pub async fn is_available(&self) -> bool {
        self.state().await.is_serving() && self.health().await.is_serving()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use rustfun_core::protocol::{InvocationRequest, InvocationResponse};
    use rustfun_core::runtime::RuntimeInstance;
    use std::sync::Mutex as StdMutex;

    struct Stub {
        instance_id: InstanceId,
        runtime: RuntimeId,
        fail: bool,
    }

    #[async_trait]
    impl RuntimeInstance for Stub {
        fn instance_id(&self) -> &InstanceId {
            &self.instance_id
        }

        fn runtime(&self) -> &RuntimeId {
            &self.runtime
        }

        async fn invoke(&self, request: InvocationRequest) -> Result<InvocationOutcome> {
            if self.fail {
                return Err(RustFunError::runtime("stub failure"));
            }
            Ok(InvocationOutcome {
                response: InvocationResponse::success(
                    request.invocation_id,
                    request.function_id,
                    b"ok".to_vec(),
                ),
                instance_healthy: true,
            })
        }

        async fn health(&self) -> HealthStatus {
            HealthStatus::Healthy
        }
    }

    fn managed(fail: bool, max_concurrency: u32) -> std::sync::Arc<ManagedInstance> {
        let instance_id = InstanceId::new();
        std::sync::Arc::new(ManagedInstance::new(
            instance_id.clone(),
            FunctionId::new(),
            RuntimeId::parse("echo").expect("valid"),
            Box::new(Stub {
                instance_id,
                runtime: RuntimeId::parse("echo").expect("valid"),
                fail,
            }),
            max_concurrency,
        ))
    }

    #[test]
    fn legal_transitions_are_accepted_by_the_state_machine() {
        use InstanceState::*;
        assert!(Creating.can_transition_to(Starting));
        assert!(Starting.can_transition_to(Ready));
        assert!(Ready.can_transition_to(Busy));
        assert!(Busy.can_transition_to(Idle));
        assert!(Idle.can_transition_to(Suspended));
        assert!(Suspended.can_transition_to(Stopping));
        assert!(Stopping.can_transition_to(Stopped));
        assert!(Starting.can_transition_to(Failed));
    }

    #[test]
    fn illegal_transitions_are_rejected() {
        use InstanceState::*;
        assert!(!Stopped.can_transition_to(Ready));
        assert!(!Failed.can_transition_to(Busy));
        assert!(!Creating.can_transition_to(Busy));
        assert!(!Ready.can_transition_to(Starting));
        assert!(Stopped.is_terminal());
        assert!(Failed.is_terminal());
    }

    #[tokio::test]
    async fn invalid_transitions_return_a_structured_error() {
        let instance = managed(false, 1);
        instance
            .transition(InstanceState::Starting)
            .await
            .expect("starting");
        instance
            .transition(InstanceState::Ready)
            .await
            .expect("ready");
        let err = instance
            .transition(InstanceState::Starting)
            .await
            .expect_err("must reject");
        assert_eq!(err.from, InstanceState::Ready);
        assert_eq!(err.to, InstanceState::Starting);
        let converted: RustFunError = err.into();
        assert_eq!(converted.category(), rustfun_core::ErrorCategory::Conflict);
    }

    #[tokio::test]
    async fn leases_are_exclusive_at_concurrency_one() {
        let instance = managed(false, 1);
        instance
            .transition(InstanceState::Starting)
            .await
            .expect("starting");
        instance
            .transition(InstanceState::Ready)
            .await
            .expect("ready");
        let first = InvocationId::new();
        let second = InvocationId::new();
        assert!(instance.try_lease(&first).await);
        assert!(!instance.try_lease(&second).await, "must not double-lease");
        assert_eq!(instance.state().await, InstanceState::Busy);
        instance.release_lease().await;
        assert_eq!(instance.state().await, InstanceState::Idle);
        assert!(
            instance.try_lease(&second).await,
            "released lease is reusable"
        );
    }

    #[tokio::test]
    async fn concurrent_leases_are_allowed_when_configured() {
        let instance = managed(false, 4);
        instance
            .transition(InstanceState::Starting)
            .await
            .expect("starting");
        instance
            .transition(InstanceState::Ready)
            .await
            .expect("ready");
        let a = InvocationId::new();
        let b = InvocationId::new();
        assert!(instance.try_lease(&a).await);
        assert!(instance.try_lease(&b).await);
        assert_eq!(instance.max_concurrency(), 4);
    }

    #[tokio::test]
    async fn invocation_count_and_last_used_are_tracked() {
        let instance = managed(false, 1);
        instance
            .transition(InstanceState::Starting)
            .await
            .expect("starting");
        instance
            .transition(InstanceState::Ready)
            .await
            .expect("ready");
        let request = InvocationRequest::new(
            rustfun_model::RequestId::new(),
            InvocationId::new(),
            FunctionId::new(),
            Vec::new(),
        );
        instance.invoke(request.clone()).await.expect("invokes");
        instance.invoke(request).await.expect("invokes");
        assert_eq!(instance.invocation_count(), 2);
        assert!(instance.idle_for().await.is_some());
        assert!(instance.created_at() > 0);
    }

    #[tokio::test]
    async fn shutdown_moves_to_stopped() {
        let instance = managed(false, 1);
        instance
            .transition(InstanceState::Starting)
            .await
            .expect("starting");
        instance
            .transition(InstanceState::Ready)
            .await
            .expect("ready");
        instance.shutdown().await.expect("shuts down");
        assert_eq!(instance.state().await, InstanceState::Stopped);
        assert!(!instance.is_available().await);
    }

    #[tokio::test]
    async fn failed_instances_are_not_available() {
        let instance = managed(false, 1);
        instance.mark_failed().await;
        assert_eq!(instance.state().await, InstanceState::Failed);
        assert!(!instance.is_available().await);
    }

    #[test]
    fn state_display_and_serving_predicates() {
        assert_eq!(InstanceState::Idle.to_string(), "idle");
        assert!(InstanceState::Idle.is_serving());
        assert!(!InstanceState::Suspended.is_serving());
        let _guard = StdMutex::new(());
    }
}
