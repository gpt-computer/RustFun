//! Instance lifecycle, warm pooling, and the local scheduler.
//!
//! ```text
//! invoke ──▶ Scheduler ──▶ InstancePool ──▶ RuntimeAdapter
//!              (queue,       (idle reuse,     (one live unit)
//!               capacity)     min/max)
//! ```
//!
//! # Lifecycle
//!
//! ```text
//! Creating → Starting → Ready → Busy → Idle → Stopping → Stopped
//!                          ↘ Failed
//! ```
//!
//! Invalid transitions are rejected: the pool must never resurrect a stopped instance or
//! double-start a live one.
//!
//! # Concurrency
//!
//! An instance is leased for exactly one invocation at a time unless the runtime declares
//! `concurrency`. Cold starts are bounded by a semaphore so a burst of traffic cannot create an
//! unbounded number of processes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::atomic::{AtomicU64, Ordering};

use rustfun_core::protocol::{InvocationResponse, InvocationStatus};
use rustfun_core::runtime::InvocationOutcome;
use rustfun_core::{Result, RustFunError};
use rustfun_events::{Event, EventKind};
use rustfun_model::{FunctionId, InstanceId, InvocationId};

mod lifecycle;
mod pool;
mod scheduler;

pub use lifecycle::{InstanceState, ManagedInstance, StateTransitionError};
pub use pool::{InstancePool, PoolConfig, PoolSnapshot};
pub use scheduler::{Scheduler, SchedulerConfig, SchedulerSnapshot};

/// Counters describing execution behavior.
///
/// These are the numbers the performance milestone asks for: cold starts versus warm reuse,
/// queueing, and failures.
#[derive(Debug, Default)]
pub struct ExecutionMetrics {
    cold_starts: AtomicU64,
    warm_invocations: AtomicU64,
    queued: AtomicU64,
    failed_instances: AtomicU64,
}

impl ExecutionMetrics {
    /// Record a cold start.
    pub fn record_cold_start(&self) {
        self.cold_starts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a warm invocation.
    pub fn record_warm_invocation(&self) {
        self.warm_invocations.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an invocation that had to wait for capacity.
    pub fn record_queued(&self) {
        self.queued.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an instance discarded after a failure.
    pub fn record_failed_instance(&self) {
        self.failed_instances.fetch_add(1, Ordering::Relaxed);
    }

    /// Cold starts.
    pub fn cold_starts(&self) -> u64 {
        self.cold_starts.load(Ordering::Relaxed)
    }

    /// Warm invocations.
    pub fn warm_invocations(&self) -> u64 {
        self.warm_invocations.load(Ordering::Relaxed)
    }

    /// Queued invocations.
    pub fn queued(&self) -> u64 {
        self.queued.load(Ordering::Relaxed)
    }

    /// Failed instances.
    pub fn failed_instances(&self) -> u64 {
        self.failed_instances.load(Ordering::Relaxed)
    }

    /// Warm reuse ratio in `0.0..=1.0`.
    pub fn warm_ratio(&self) -> f64 {
        let total = self.cold_starts() + self.warm_invocations();
        if total == 0 {
            return 0.0;
        }
        self.warm_invocations() as f64 / total as f64
    }
}

/// Normalize an invocation outcome into a complete response.
pub(crate) fn response_from_outcome(
    outcome: InvocationOutcome,
    invocation_id: InvocationId,
    function_id: FunctionId,
) -> Result<InvocationResponse> {
    let mut response = outcome.response;
    if response.invocation_id != invocation_id {
        response.invocation_id = invocation_id;
    }
    if response.function_id != function_id {
        response.function_id = function_id;
    }
    if response.status == InvocationStatus::PlatformError && response.error.is_none() {
        response.error = Some(rustfun_core::protocol::InvocationError::new(
            "RUSTFUN_RUNTIME_ERROR",
            "the runtime reported a platform error without details",
        ));
    }
    Ok(response)
}

/// Emit an invocation failure event.
pub(crate) fn emit_failure(
    bus: &rustfun_core::EventBus,
    invocation_id: InvocationId,
    function_id: FunctionId,
    instance_id: Option<InstanceId>,
    error: &RustFunError,
) {
    bus.emit(Event::new(EventKind::InvocationFailed {
        invocation_id,
        function_id,
        instance_id,
        code: error.code().to_owned(),
        message: error.message().to_owned(),
    }));
}

/// Emit an `InstanceStopped` event.
pub(crate) fn emit_stopped(
    bus: &rustfun_core::EventBus,
    instance_id: InstanceId,
    invocations: u64,
    reason: &str,
) {
    bus.emit(Event::new(EventKind::InstanceStopped {
        instance_id,
        invocation_count: invocations,
        reason: reason.to_owned(),
    }));
}
