//! RustFun structured lifecycle events.
//!
//! Every state change in the execution spine emits an [`Event`]. Events are the observable
//! output of the platform: logs, metrics, and traces are all derived from the same stream, so
//! an invocation can always be reconstructed from its events.
//!
//! ```
//! use rustfun_events::{Event, EventKind};
//! use rustfun_model::FunctionId;
//!
//! let event = Event::new(EventKind::FunctionCreated {
//!     function_id: FunctionId::new(),
//!     name: "hello".to_owned(),
//!     runtime: "node@24".to_owned(),
//! });
//! let json = serde_json::to_string(&event).expect("serializes");
//! assert!(json.contains("function_created"));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::time::{SystemTime, UNIX_EPOCH};

use rustfun_model::EventId;
use serde::{Deserialize, Serialize};

/// Correlation context attached to every event.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventContext {
    /// Trace identifier propagated across services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Span identifier within the trace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    /// Component that emitted the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
}

impl EventContext {
    /// Create a context for a component.
    pub fn new(component: impl Into<String>) -> Self {
        Self {
            component: Some(component.into()),
            ..Self::default()
        }
    }

    /// Attach a trace id.
    #[must_use]
    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Attach a span id.
    #[must_use]
    pub fn with_span_id(mut self, span_id: impl Into<String>) -> Self {
        self.span_id = Some(span_id.into());
        self
    }
}

/// A structured event payload.
///
/// The variants correspond one-to-one with the lifecycle transitions of the execution spine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EventKind {
    /// A function definition was created.
    FunctionCreated {
        /// Function identifier.
        function_id: rustfun_model::FunctionId,
        /// Function name.
        name: String,
        /// Requested runtime.
        runtime: String,
    },
    /// A function definition was destroyed.
    FunctionDestroyed {
        /// Function identifier.
        function_id: rustfun_model::FunctionId,
        /// Function name.
        name: String,
    },
    /// An artifact was built from source.
    ArtifactBuilt {
        /// Function identifier.
        function_id: rustfun_model::FunctionId,
        /// Content digest of the artifact.
        digest: rustfun_model::Digest,
        /// Artifact size in bytes.
        size_bytes: u64,
        /// Build duration in milliseconds.
        duration_ms: u64,
    },
    /// An artifact was found in the content-addressed cache.
    ArtifactCached {
        /// Function identifier.
        function_id: rustfun_model::FunctionId,
        /// Content digest of the artifact.
        digest: rustfun_model::Digest,
    },
    /// A runtime instance was created.
    InstanceCreated {
        /// Instance identifier.
        instance_id: rustfun_model::InstanceId,
        /// Function identifier.
        function_id: rustfun_model::FunctionId,
        /// Runtime in use.
        runtime: String,
    },
    /// A runtime instance finished starting.
    InstanceStarted {
        /// Instance identifier.
        instance_id: rustfun_model::InstanceId,
        /// Startup latency in milliseconds.
        duration_ms: u64,
        /// Whether the instance was reused (warm) rather than created (cold).
        warm: bool,
    },
    /// A runtime instance is ready to serve invocations.
    InstanceReady {
        /// Instance identifier.
        instance_id: rustfun_model::InstanceId,
    },
    /// An instance was suspended (e.g. after exceeding an idle budget).
    InstanceSuspended {
        /// Instance identifier.
        instance_id: rustfun_model::InstanceId,
        /// Reason for suspension.
        reason: String,
    },
    /// An instance was shut down.
    InstanceStopped {
        /// Instance identifier.
        instance_id: rustfun_model::InstanceId,
        /// Total invocations served by the instance.
        invocation_count: u64,
        /// Reason for stopping.
        reason: String,
    },
    /// An instance was destroyed.
    InstanceDestroyed {
        /// Instance identifier.
        instance_id: rustfun_model::InstanceId,
    },
    /// An invocation was accepted.
    InvocationStarted {
        /// Invocation identifier.
        invocation_id: rustfun_model::InvocationId,
        /// Function identifier.
        function_id: rustfun_model::FunctionId,
        /// Instance that will serve the invocation, when known.
        instance_id: Option<rustfun_model::InstanceId>,
    },
    /// An invocation completed successfully.
    InvocationCompleted {
        /// Invocation identifier.
        invocation_id: rustfun_model::InvocationId,
        /// Function identifier.
        function_id: rustfun_model::FunctionId,
        /// Instance that served the invocation.
        instance_id: rustfun_model::InstanceId,
        /// Duration in milliseconds.
        duration_ms: u64,
        /// Response payload size in bytes.
        response_bytes: usize,
    },
    /// An invocation failed.
    InvocationFailed {
        /// Invocation identifier.
        invocation_id: rustfun_model::InvocationId,
        /// Function identifier.
        function_id: rustfun_model::FunctionId,
        /// Instance that served the invocation, when known.
        instance_id: Option<rustfun_model::InstanceId>,
        /// Stable error code.
        code: String,
        /// Human-readable message.
        message: String,
    },
    /// A runtime reported an error outside of an invocation.
    RuntimeError {
        /// Runtime identifier.
        runtime: String,
        /// Stable error code.
        code: String,
        /// Human-readable message.
        message: String,
    },
    /// A sandbox boundary was violated or could not be established.
    SandboxViolation {
        /// Function identifier, when known.
        function_id: Option<rustfun_model::FunctionId>,
        /// Instance identifier, when known.
        instance_id: Option<rustfun_model::InstanceId>,
        /// Isolation layer involved.
        layer: String,
        /// Description of the violation.
        detail: String,
    },
    /// A worker (remote executor) registered itself.
    WorkerRegistered {
        /// Worker identifier.
        worker_id: rustfun_model::WorkerId,
        /// Runtimes the worker can serve.
        runtimes: Vec<String>,
    },
    /// A runtime was installed into the local runtime cache.
    RuntimeInstalled {
        /// Runtime identifier.
        runtime: String,
        /// Version discovered or installed.
        version: String,
    },
}

impl EventKind {
    /// Stable snake_case name of the event.
    pub fn name(&self) -> &'static str {
        match self {
            EventKind::FunctionCreated { .. } => "function_created",
            EventKind::FunctionDestroyed { .. } => "function_destroyed",
            EventKind::ArtifactBuilt { .. } => "artifact_built",
            EventKind::ArtifactCached { .. } => "artifact_cached",
            EventKind::InstanceCreated { .. } => "instance_created",
            EventKind::InstanceStarted { .. } => "instance_started",
            EventKind::InstanceReady { .. } => "instance_ready",
            EventKind::InstanceSuspended { .. } => "instance_suspended",
            EventKind::InstanceStopped { .. } => "instance_stopped",
            EventKind::InstanceDestroyed { .. } => "instance_destroyed",
            EventKind::InvocationStarted { .. } => "invocation_started",
            EventKind::InvocationCompleted { .. } => "invocation_completed",
            EventKind::InvocationFailed { .. } => "invocation_failed",
            EventKind::RuntimeError { .. } => "runtime_error",
            EventKind::SandboxViolation { .. } => "sandbox_violation",
            EventKind::WorkerRegistered { .. } => "worker_registered",
            EventKind::RuntimeInstalled { .. } => "runtime_installed",
        }
    }
}

/// A complete event with identity, timestamp, and correlation context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unique event identifier.
    pub id: EventId,
    /// Milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Correlation context.
    #[serde(default, skip_serializing_if = "is_default_context")]
    pub context: EventContext,
    /// Payload.
    #[serde(flatten)]
    pub kind: EventKind,
}

fn is_default_context(context: &EventContext) -> bool {
    context.trace_id.is_none() && context.span_id.is_none() && context.component.is_none()
}

impl Event {
    /// Create an event with the current wall-clock timestamp.
    pub fn new(kind: EventKind) -> Self {
        Self {
            id: EventId::new(),
            timestamp_ms: now_ms(),
            context: EventContext::default(),
            kind,
        }
    }

    /// Attach correlation context.
    #[must_use]
    pub fn with_context(mut self, context: EventContext) -> Self {
        self.context = context;
        self
    }

    /// Stable event name.
    pub fn name(&self) -> &'static str {
        self.kind.name()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfun_model::{Digest, FunctionId, InstanceId, InvocationId};

    #[test]
    fn event_names_are_stable() {
        let event = Event::new(EventKind::FunctionCreated {
            function_id: FunctionId::new(),
            name: "hello".into(),
            runtime: "node@24".into(),
        });
        assert_eq!(event.name(), "function_created");
    }

    #[test]
    fn events_serialize_with_tagged_payload() {
        let event = Event::new(EventKind::InvocationFailed {
            invocation_id: InvocationId::new(),
            function_id: FunctionId::new(),
            instance_id: Some(InstanceId::new()),
            code: "RUSTFUN_TIMEOUT".into(),
            message: "deadline exceeded".into(),
        })
        .with_context(EventContext::new("scheduler").with_trace_id("trace-1"));
        let json = serde_json::to_value(&event).expect("serializes");
        assert_eq!(json["event"], "invocation_failed");
        assert_eq!(json["code"], "RUSTFUN_TIMEOUT");
        assert_eq!(json["context"]["trace_id"], "trace-1");
        let back: Event = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back.kind, event.kind);
    }

    #[test]
    fn artifact_events_carry_digest() {
        let event = Event::new(EventKind::ArtifactBuilt {
            function_id: FunctionId::new(),
            digest: Digest::sha256(b"artifact"),
            size_bytes: 42,
            duration_ms: 7,
        });
        let json = serde_json::to_string(&event).expect("serializes");
        assert!(json.contains("sha256:"));
    }

    #[test]
    fn empty_context_is_omitted() {
        let event = Event::new(EventKind::InstanceReady {
            instance_id: InstanceId::new(),
        });
        let json = serde_json::to_value(&event).expect("serializes");
        assert!(json.get("context").is_none());
    }
}
