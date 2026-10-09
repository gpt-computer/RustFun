//! The structured error hierarchy.
//!
//! Every error carries a stable code, a category, a human-readable message, the operation
//! that failed, and the domain identifiers involved. The CLI renders it for humans; the HTTP
//! API and the library expose the machine-readable form.
//!
//! ```
//! use rustfun_core::{ErrorContext, RustFunError};
//!
//! let err = RustFunError::timeout("invocation exceeded deadline")
//!     .with_context(ErrorContext::new().operation("invoke").function("hello"));
//! assert!(err.is_timeout());
//! assert_eq!(err.code(), "RUSTFUN_TIMEOUT");
//! let json = serde_json::to_value(&err).expect("serializes");
//! assert_eq!(json["category"], "timeout");
//! ```

use rustfun_model::{FunctionId, InstanceId, InvocationId, RuntimeId};
use serde::{Deserialize, Serialize};

/// Result alias used across the workspace.
pub type Result<T> = std::result::Result<T, RustFunError>;

/// Stable, machine-readable error categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// A caller supplied invalid input.
    Validation,
    /// A requested entity does not exist.
    NotFound,
    /// The request conflicts with current state (e.g. creating a duplicate function).
    Conflict,
    /// A runtime, dependency, or platform capability is unavailable.
    Unavailable,
    /// An invocation or operation exceeded its deadline.
    Timeout,
    /// A function raised an error.
    Function,
    /// The runtime or platform failed.
    Runtime,
    /// A protocol violation occurred.
    Protocol,
    /// An artifact could not be built, read, or verified.
    Artifact,
    /// A sandbox could not be established or was violated.
    Sandbox,
    /// A resource limit was hit.
    Resource,
    /// An operating-system or I/O failure.
    Io,
    /// An internal invariant was violated.
    Internal,
    /// The operation was cancelled.
    Cancelled,
}

impl ErrorCategory {
    /// Stable string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCategory::Validation => "validation",
            ErrorCategory::NotFound => "not_found",
            ErrorCategory::Conflict => "conflict",
            ErrorCategory::Unavailable => "unavailable",
            ErrorCategory::Timeout => "timeout",
            ErrorCategory::Function => "function",
            ErrorCategory::Runtime => "runtime",
            ErrorCategory::Protocol => "protocol",
            ErrorCategory::Artifact => "artifact",
            ErrorCategory::Sandbox => "sandbox",
            ErrorCategory::Resource => "resource",
            ErrorCategory::Io => "io",
            ErrorCategory::Internal => "internal",
            ErrorCategory::Cancelled => "cancelled",
        }
    }

    /// Suggested HTTP status for this category when surfaced by the dev API.
    pub const fn http_status(self) -> u16 {
        match self {
            ErrorCategory::Validation => 400,
            ErrorCategory::NotFound => 404,
            ErrorCategory::Conflict => 409,
            ErrorCategory::Unavailable => 503,
            ErrorCategory::Timeout => 504,
            ErrorCategory::Function => 500,
            ErrorCategory::Runtime => 500,
            ErrorCategory::Protocol => 502,
            ErrorCategory::Artifact => 500,
            ErrorCategory::Sandbox => 500,
            ErrorCategory::Resource => 429,
            ErrorCategory::Io => 500,
            ErrorCategory::Internal => 500,
            ErrorCategory::Cancelled => 499,
        }
    }
}

/// Domain context attached to an error.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorContext {
    /// Operation that failed (e.g. `invoke`, `build`, `start_instance`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Function involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Function identifier involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_id: Option<FunctionId>,
    /// Runtime involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Instance involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,
    /// Invocation involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<InvocationId>,
    /// Remediation hint for a human operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Additional structured key/value diagnostics (never secrets).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub details: std::collections::BTreeMap<String, String>,
}

impl ErrorContext {
    /// Empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the operation.
    #[must_use]
    pub fn operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }

    /// Set the function name.
    #[must_use]
    pub fn function(mut self, name: impl Into<String>) -> Self {
        self.function = Some(name.into());
        self
    }

    /// Set the function identifier.
    #[must_use]
    pub fn function_id(mut self, id: FunctionId) -> Self {
        self.function_id = Some(id);
        self
    }

    /// Set the runtime.
    #[must_use]
    pub fn runtime(mut self, runtime: impl Into<String>) -> Self {
        self.runtime = Some(runtime.into());
        self
    }

    /// Set the runtime from a [`RuntimeId`].
    #[must_use]
    pub fn runtime_id(mut self, runtime: RuntimeId) -> Self {
        self.runtime = Some(runtime.to_string());
        self
    }

    /// Set the instance identifier.
    #[must_use]
    pub fn instance_id(mut self, id: InstanceId) -> Self {
        self.instance_id = Some(id);
        self
    }

    /// Set the invocation identifier.
    #[must_use]
    pub fn invocation_id(mut self, id: InvocationId) -> Self {
        self.invocation_id = Some(id);
        self
    }

    /// Set a remediation hint.
    #[must_use]
    pub fn remediation(mut self, hint: impl Into<String>) -> Self {
        self.remediation = Some(hint.into());
        self
    }

    /// Add a diagnostic detail.
    #[must_use]
    pub fn detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

/// The platform error type.
#[derive(Debug, thiserror::Error)]
pub enum RustFunError {
    /// Invalid caller input.
    #[error("[RUSTFUN_VALIDATION] {message}")]
    Validation {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// The requested entity does not exist.
    #[error("[RUSTFUN_NOT_FOUND] {message}")]
    NotFound {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// The request conflicts with current state.
    #[error("[RUSTFUN_CONFLICT] {message}")]
    Conflict {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// A runtime or capability is unavailable.
    #[error("[RUSTFUN_UNAVAILABLE] {message}")]
    Unavailable {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// An operation exceeded its deadline.
    #[error("[RUSTFUN_TIMEOUT] {message}")]
    Timeout {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// The function raised an error.
    #[error("[RUSTFUN_FUNCTION_ERROR] {message}")]
    Function {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// The runtime failed.
    #[error("[RUSTFUN_RUNTIME_ERROR] {message}")]
    Runtime {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// A protocol violation.
    #[error("[RUSTFUN_PROTOCOL_ERROR] {message}")]
    Protocol {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// An artifact problem.
    #[error("[RUSTFUN_ARTIFACT_ERROR] {message}")]
    Artifact {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// A sandbox problem or violation.
    #[error("[RUSTFUN_SANDBOX_ERROR] {message}")]
    Sandbox {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// A resource limit was hit.
    #[error("[RUSTFUN_RESOURCE_ERROR] {message}")]
    Resource {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// An I/O failure.
    #[error("[RUSTFUN_IO_ERROR] {message}")]
    Io {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// An internal invariant was violated.
    #[error("[RUSTFUN_INTERNAL_ERROR] {message}")]
    Internal {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
    /// The operation was cancelled.
    #[error("[RUSTFUN_CANCELLED] {message}")]
    Cancelled {
        /// Human-readable message.
        message: String,
        /// Domain context.
        context: ErrorContext,
    },
}

impl RustFunError {
    fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        let message = message.into();
        match category {
            ErrorCategory::Validation => RustFunError::Validation {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::NotFound => RustFunError::NotFound {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Conflict => RustFunError::Conflict {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Unavailable => RustFunError::Unavailable {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Timeout => RustFunError::Timeout {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Function => RustFunError::Function {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Runtime => RustFunError::Runtime {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Protocol => RustFunError::Protocol {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Artifact => RustFunError::Artifact {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Sandbox => RustFunError::Sandbox {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Resource => RustFunError::Resource {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Io => RustFunError::Io {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Cancelled => RustFunError::Cancelled {
                message,
                context: ErrorContext::new(),
            },
            ErrorCategory::Internal => RustFunError::Internal {
                message,
                context: ErrorContext::new(),
            },
        }
    }

    /// Validation failure.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Validation, message)
    }

    /// Entity not found.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::NotFound, message)
    }

    /// State conflict.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Conflict, message)
    }

    /// Runtime or capability unavailable.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Unavailable, message)
    }

    /// Deadline exceeded.
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Timeout, message)
    }

    /// Function raised an error.
    pub fn function(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Function, message)
    }

    /// Runtime failure.
    pub fn runtime(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Runtime, message)
    }

    /// Protocol violation.
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Protocol, message)
    }

    /// Artifact failure.
    pub fn artifact(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Artifact, message)
    }

    /// Sandbox failure or violation.
    pub fn sandbox(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Sandbox, message)
    }

    /// Resource limit failure.
    pub fn resource(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Resource, message)
    }

    /// I/O failure.
    pub fn io(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Io, message)
    }

    /// Internal invariant failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Internal, message)
    }

    /// Cancellation.
    pub fn cancelled(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Cancelled, message)
    }

    /// Attach (or extend) the error context.
    #[must_use]
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        let slot = self.context_mut();
        slot.operation = slot.operation.clone().or(context.operation);
        slot.function = slot.function.clone().or(context.function);
        slot.function_id = slot.function_id.clone().or(context.function_id);
        slot.runtime = slot.runtime.clone().or(context.runtime);
        slot.instance_id = slot.instance_id.clone().or(context.instance_id);
        slot.invocation_id = slot.invocation_id.clone().or(context.invocation_id);
        slot.remediation = slot.remediation.clone().or(context.remediation);
        for (key, value) in context.details {
            slot.details.insert(key, value);
        }
        self
    }

    /// Add a single diagnostic detail.
    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context_mut().details.insert(key.into(), value.into());
        self
    }

    /// Attach a remediation hint.
    #[must_use]
    pub fn with_remediation(mut self, hint: impl Into<String>) -> Self {
        self.context_mut().remediation = Some(hint.into());
        self
    }

    /// Error category.
    pub fn category(&self) -> ErrorCategory {
        match self {
            RustFunError::Validation { .. } => ErrorCategory::Validation,
            RustFunError::NotFound { .. } => ErrorCategory::NotFound,
            RustFunError::Conflict { .. } => ErrorCategory::Conflict,
            RustFunError::Unavailable { .. } => ErrorCategory::Unavailable,
            RustFunError::Timeout { .. } => ErrorCategory::Timeout,
            RustFunError::Function { .. } => ErrorCategory::Function,
            RustFunError::Runtime { .. } => ErrorCategory::Runtime,
            RustFunError::Protocol { .. } => ErrorCategory::Protocol,
            RustFunError::Artifact { .. } => ErrorCategory::Artifact,
            RustFunError::Sandbox { .. } => ErrorCategory::Sandbox,
            RustFunError::Resource { .. } => ErrorCategory::Resource,
            RustFunError::Io { .. } => ErrorCategory::Io,
            RustFunError::Internal { .. } => ErrorCategory::Internal,
            RustFunError::Cancelled { .. } => ErrorCategory::Cancelled,
        }
    }

    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            RustFunError::Validation { .. } => "RUSTFUN_VALIDATION",
            RustFunError::NotFound { .. } => "RUSTFUN_NOT_FOUND",
            RustFunError::Conflict { .. } => "RUSTFUN_CONFLICT",
            RustFunError::Unavailable { .. } => "RUSTFUN_UNAVAILABLE",
            RustFunError::Timeout { .. } => "RUSTFUN_TIMEOUT",
            RustFunError::Function { .. } => "RUSTFUN_FUNCTION_ERROR",
            RustFunError::Runtime { .. } => "RUSTFUN_RUNTIME_ERROR",
            RustFunError::Protocol { .. } => "RUSTFUN_PROTOCOL_ERROR",
            RustFunError::Artifact { .. } => "RUSTFUN_ARTIFACT_ERROR",
            RustFunError::Sandbox { .. } => "RUSTFUN_SANDBOX_ERROR",
            RustFunError::Resource { .. } => "RUSTFUN_RESOURCE_ERROR",
            RustFunError::Io { .. } => "RUSTFUN_IO_ERROR",
            RustFunError::Internal { .. } => "RUSTFUN_INTERNAL_ERROR",
            RustFunError::Cancelled { .. } => "RUSTFUN_CANCELLED",
        }
    }

    /// Human-readable message without the code prefix.
    pub fn message(&self) -> &str {
        match self {
            RustFunError::Validation { message, .. }
            | RustFunError::NotFound { message, .. }
            | RustFunError::Conflict { message, .. }
            | RustFunError::Unavailable { message, .. }
            | RustFunError::Timeout { message, .. }
            | RustFunError::Function { message, .. }
            | RustFunError::Runtime { message, .. }
            | RustFunError::Protocol { message, .. }
            | RustFunError::Artifact { message, .. }
            | RustFunError::Sandbox { message, .. }
            | RustFunError::Resource { message, .. }
            | RustFunError::Io { message, .. }
            | RustFunError::Internal { message, .. }
            | RustFunError::Cancelled { message, .. } => message,
        }
    }

    /// Domain context.
    pub fn context(&self) -> &ErrorContext {
        match self {
            RustFunError::Validation { context, .. }
            | RustFunError::NotFound { context, .. }
            | RustFunError::Conflict { context, .. }
            | RustFunError::Unavailable { context, .. }
            | RustFunError::Timeout { context, .. }
            | RustFunError::Function { context, .. }
            | RustFunError::Runtime { context, .. }
            | RustFunError::Protocol { context, .. }
            | RustFunError::Artifact { context, .. }
            | RustFunError::Sandbox { context, .. }
            | RustFunError::Resource { context, .. }
            | RustFunError::Io { context, .. }
            | RustFunError::Internal { context, .. }
            | RustFunError::Cancelled { context, .. } => context,
        }
    }

    /// Whether retrying the same operation could succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            RustFunError::Unavailable { .. }
                | RustFunError::Io { .. }
                | RustFunError::Timeout { .. }
        )
    }

    /// Whether this is a timeout.
    pub fn is_timeout(&self) -> bool {
        self.category() == ErrorCategory::Timeout
    }

    /// Suggested HTTP status code.
    pub fn http_status(&self) -> u16 {
        self.category().http_status()
    }

    /// Multi-line rendering for the CLI, including context and remediation.
    pub fn to_human_string(&self) -> String {
        let mut out = self.to_string();
        let ctx = self.context();
        if let Some(function) = &ctx.function {
            out.push_str(&format!("\n  function: {function}"));
        }
        if let Some(runtime) = &ctx.runtime {
            out.push_str(&format!("\n  runtime: {runtime}"));
        }
        if let Some(instance) = &ctx.instance_id {
            out.push_str(&format!("\n  instance: {instance}"));
        }
        if let Some(invocation) = &ctx.invocation_id {
            out.push_str(&format!("\n  invocation: {invocation}"));
        }
        for (key, value) in &ctx.details {
            out.push_str(&format!("\n  {key}: {value}"));
        }
        if let Some(hint) = &ctx.remediation {
            out.push_str(&format!("\n  hint: {hint}"));
        }
        out
    }

    fn context_mut(&mut self) -> &mut ErrorContext {
        match self {
            RustFunError::Validation { context, .. }
            | RustFunError::NotFound { context, .. }
            | RustFunError::Conflict { context, .. }
            | RustFunError::Unavailable { context, .. }
            | RustFunError::Timeout { context, .. }
            | RustFunError::Function { context, .. }
            | RustFunError::Runtime { context, .. }
            | RustFunError::Protocol { context, .. }
            | RustFunError::Artifact { context, .. }
            | RustFunError::Sandbox { context, .. }
            | RustFunError::Resource { context, .. }
            | RustFunError::Io { context, .. }
            | RustFunError::Internal { context, .. }
            | RustFunError::Cancelled { context, .. } => context,
        }
    }
}

impl Serialize for RustFunError {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("code", self.code())?;
        map.serialize_entry("category", &self.category())?;
        map.serialize_entry("message", self.message())?;
        map.serialize_entry("retryable", &self.is_retryable())?;
        map.serialize_entry("context", self.context())?;
        map.end()
    }
}

impl From<rustfun_model::ModelError> for RustFunError {
    fn from(value: rustfun_model::ModelError) -> Self {
        RustFunError::validation(value.to_string())
    }
}

impl From<rustfun_protocol::ProtocolError> for RustFunError {
    fn from(value: rustfun_protocol::ProtocolError) -> Self {
        let category = match value {
            rustfun_protocol::ProtocolError::VersionMismatch { .. }
            | rustfun_protocol::ProtocolError::BadMagic { .. }
            | rustfun_protocol::ProtocolError::UnknownCodec { .. }
            | rustfun_protocol::ProtocolError::Violation(_)
            | rustfun_protocol::ProtocolError::DecodeFailed { .. }
            | rustfun_protocol::ProtocolError::EncodeFailed { .. } => ErrorCategory::Protocol,
            rustfun_protocol::ProtocolError::FrameTooLarge { .. } => ErrorCategory::Resource,
            rustfun_protocol::ProtocolError::TransportClosed { .. } => ErrorCategory::Runtime,
            rustfun_protocol::ProtocolError::Io { .. } => ErrorCategory::Io,
        };
        match category {
            ErrorCategory::Protocol => RustFunError::protocol(value.to_string()),
            ErrorCategory::Resource => RustFunError::resource(value.to_string()),
            ErrorCategory::Runtime => RustFunError::runtime(value.to_string()),
            _ => RustFunError::io(value.to_string()),
        }
    }
}

impl From<std::io::Error> for RustFunError {
    fn from(value: std::io::Error) -> Self {
        RustFunError::io(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_categories_are_stable() {
        assert_eq!(RustFunError::validation("bad").code(), "RUSTFUN_VALIDATION");
        assert_eq!(
            RustFunError::not_found("x").category(),
            ErrorCategory::NotFound
        );
        assert_eq!(RustFunError::timeout("slow").http_status(), 504);
        assert!(RustFunError::timeout("slow").is_retryable());
        assert!(!RustFunError::validation("bad").is_retryable());
    }

    #[test]
    fn context_is_merged_not_overwritten() {
        let err = RustFunError::runtime("boom")
            .with_context(ErrorContext::new().operation("start").runtime("node@24"))
            .with_context(ErrorContext::new().function("hello").detail("pid", "42"));
        let ctx = err.context();
        assert_eq!(ctx.operation.as_deref(), Some("start"));
        assert_eq!(ctx.runtime.as_deref(), Some("node@24"));
        assert_eq!(ctx.function.as_deref(), Some("hello"));
        assert_eq!(ctx.details.get("pid").map(String::as_str), Some("42"));
    }

    #[test]
    fn serializes_machine_readably() {
        let err = RustFunError::timeout("deadline exceeded")
            .with_context(ErrorContext::new().operation("invoke"));
        let json = serde_json::to_value(&err).expect("serializes");
        assert_eq!(json["code"], "RUSTFUN_TIMEOUT");
        assert_eq!(json["category"], "timeout");
        assert_eq!(json["retryable"], true);
        assert_eq!(json["context"]["operation"], "invoke");
    }

    #[test]
    fn human_string_contains_hint() {
        let err = RustFunError::unavailable("node not found")
            .with_context(ErrorContext::new().runtime("node@24"))
            .with_remediation("install Node.js or change the runtime in rustfun.toml");
        let text = err.to_human_string();
        assert!(text.contains("runtime: node@24"));
        assert!(text.contains("hint: install Node.js"));
    }

    #[test]
    fn model_errors_map_to_validation() {
        let model_err = rustfun_model::FunctionName::new("BAD").expect_err("invalid");
        let err: RustFunError = model_err.into();
        assert_eq!(err.category(), ErrorCategory::Validation);
    }
}
