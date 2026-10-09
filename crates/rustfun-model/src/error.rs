//! Domain-level error type.
//!
//! Domain errors are machine-readable by construction: every error carries a stable code and
//! a human-readable message. Infrastructure layers (process, runtime, HTTP) map these into
//! their own structured error types while preserving the code.

use std::fmt;

/// Result alias for domain operations.
pub type ModelResult<T> = Result<T, ModelError>;

/// Stable, machine-readable codes for domain errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// A name failed validation.
    InvalidName,
    /// A handler specification failed validation.
    InvalidHandler,
    /// A runtime identifier could not be parsed.
    InvalidRuntime,
    /// A digest string was malformed or used an unsupported algorithm.
    InvalidDigest,
    /// A resource limit was out of range.
    InvalidResource,
    /// An environment variable name or value was rejected.
    InvalidEnvironment,
    /// A duration string could not be parsed.
    InvalidDuration,
    /// A sandbox policy was inconsistent.
    InvalidSandboxPolicy,
    /// A generic domain validation failure.
    Validation,
}

impl ErrorCode {
    /// Stable string code used in machine-readable output.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidName => "MODEL_INVALID_NAME",
            ErrorCode::InvalidHandler => "MODEL_INVALID_HANDLER",
            ErrorCode::InvalidRuntime => "MODEL_INVALID_RUNTIME",
            ErrorCode::InvalidDigest => "MODEL_INVALID_DIGEST",
            ErrorCode::InvalidResource => "MODEL_INVALID_RESOURCE",
            ErrorCode::InvalidEnvironment => "MODEL_INVALID_ENVIRONMENT",
            ErrorCode::InvalidDuration => "MODEL_INVALID_DURATION",
            ErrorCode::InvalidSandboxPolicy => "MODEL_INVALID_SANDBOX_POLICY",
            ErrorCode::Validation => "MODEL_VALIDATION_FAILED",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A domain error with a stable code, a message, and optional context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelError {
    code: ErrorCode,
    message: String,
    context: Option<String>,
}

impl ModelError {
    /// Build an error with a code and message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            context: None,
        }
    }

    /// Attach human-readable context (never secrets).
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Stable machine-readable code.
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Optional diagnostic context.
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }

    /// Domain errors are deterministic; retrying the same invalid input cannot help.
    pub const fn is_retryable(&self) -> bool {
        false
    }

    pub(crate) fn invalid_name(detail: impl Into<String>) -> Self {
        ModelError::new(ErrorCode::InvalidName, detail)
    }

    pub(crate) fn invalid_handler(detail: impl Into<String>) -> Self {
        ModelError::new(ErrorCode::InvalidHandler, detail)
    }

    pub(crate) fn invalid_runtime(detail: impl Into<String>) -> Self {
        ModelError::new(ErrorCode::InvalidRuntime, detail)
    }

    pub(crate) fn invalid_digest(detail: impl Into<String>) -> Self {
        ModelError::new(ErrorCode::InvalidDigest, detail)
    }

    pub(crate) fn invalid_resource(detail: impl Into<String>) -> Self {
        ModelError::new(ErrorCode::InvalidResource, detail)
    }

    pub(crate) fn invalid_environment(detail: impl Into<String>) -> Self {
        ModelError::new(ErrorCode::InvalidEnvironment, detail)
    }

    pub(crate) fn invalid_duration(detail: impl Into<String>) -> Self {
        ModelError::new(ErrorCode::InvalidDuration, detail)
    }

    pub(crate) fn invalid_sandbox(detail: impl Into<String>) -> Self {
        ModelError::new(ErrorCode::InvalidSandboxPolicy, detail)
    }

    pub(crate) fn validation(detail: impl Into<String>) -> Self {
        ModelError::new(ErrorCode::Validation, detail)
    }
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.context {
            Some(ctx) => write!(f, "[{}] {} ({})", self.code, self.message, ctx),
            None => write!(f, "[{}] {}", self.code, self.message),
        }
    }
}

impl std::error::Error for ModelError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_code_and_context() {
        let err = ModelError::invalid_name("must match ^[a-z]").with_context("function name");
        let text = err.to_string();
        assert!(text.contains("MODEL_INVALID_NAME"));
        assert!(text.contains("function name"));
    }

    #[test]
    fn codes_are_unique_strings() {
        let all = [
            ErrorCode::InvalidName,
            ErrorCode::InvalidHandler,
            ErrorCode::InvalidRuntime,
            ErrorCode::InvalidDigest,
            ErrorCode::InvalidResource,
            ErrorCode::InvalidEnvironment,
            ErrorCode::InvalidDuration,
            ErrorCode::InvalidSandboxPolicy,
            ErrorCode::Validation,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for code in all {
            assert!(seen.insert(code.as_str()), "duplicate code {code}");
        }
    }
}
