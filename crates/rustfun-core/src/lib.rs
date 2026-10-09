//! RustFun core: the platform's contracts.
//!
//! `rustfun-core` defines what the execution spine *is*, without deciding how any particular
//! piece of infrastructure implements it:
//!
//! - [`error::RustFunError`] — the structured error hierarchy used across the workspace.
//! - [`runtime`] — the [`runtime::RuntimeAdapter`] / [`runtime::RuntimeInstance`] traits and
//!   the [`runtime::RuntimeRegistry`] that resolves them.
//! - [`event`] — an in-process event bus plus sinks (tracing, metrics, tests).
//! - [`observability`] — metric collection and Prometheus rendering.
//! - [`manager::FunctionManager`] — function lifecycle (create / build / invoke / destroy).
//! - [`artifact`] — the artifact store traits, backed by `rustfun-artifact`.
//!
//! Core never depends on a CLI, a concrete runtime, or a concrete sandbox. Adapters
//! implement the traits; the core decides when they run and how many run at once.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod artifact;
pub mod error;
pub mod event;
pub mod manager;
pub mod observability;
pub mod runtime;

pub use artifact::{not_found, ArtifactStore, ArtifactSummary, BuildRequest, BuiltArtifact};
pub use error::{ErrorCategory, ErrorContext, Result, RustFunError};
pub use event::{EventBus, EventSink, LogRecord, LogStream};
pub use manager::{FunctionManager, FunctionManagerConfig, InstanceInfo, Invoker};
pub use observability::{Metrics, MetricsSnapshot};
pub use runtime::{
    HealthStatus, InvocationOutcome, PrepareRequest, PreparedRuntime, RuntimeFactory,
    RuntimeInstance, RuntimeRegistry, StartRequest,
};

/// Re-export of the domain model for convenience.
pub use rustfun_model as model;

pub use rustfun_model::{
    ArtifactId, Digest, Environment, FunctionId, FunctionName, FunctionSource, FunctionSpec,
    FunctionStatus, HandlerSpec, InstanceId, InvocationId, RequestId, ResourceLimits,
    RuntimeCapabilities, RuntimeFamily, RuntimeId, RuntimeVersion, SandboxKind, SandboxPolicy,
};

/// Re-export of the invocation protocol for convenience.
pub use rustfun_protocol as protocol;

/// Re-export of the event types for convenience.
pub use rustfun_events as events;
