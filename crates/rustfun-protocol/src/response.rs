//! Invocation responses.

use std::collections::BTreeMap;

use rustfun_model::{FunctionId, InstanceId, InvocationId};
use serde::{Deserialize, Serialize};

/// Outcome of an invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationStatus {
    /// The function ran and returned a payload.
    Success,
    /// The function ran and raised an error.
    FunctionError,
    /// The invocation exceeded its deadline.
    Timeout,
    /// The runtime or transport failed (crash, protocol violation, unavailable).
    PlatformError,
}

impl InvocationStatus {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            InvocationStatus::Success => "success",
            InvocationStatus::FunctionError => "function_error",
            InvocationStatus::Timeout => "timeout",
            InvocationStatus::PlatformError => "platform_error",
        }
    }

    /// Whether the invocation produced a usable result.
    pub const fn is_success(self) -> bool {
        matches!(self, InvocationStatus::Success)
    }

    /// Whether retrying the same invocation could plausibly succeed.
    pub const fn is_retryable(self) -> bool {
        matches!(self, InvocationStatus::PlatformError)
    }
}

/// An error reported by the runtime or the platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationError {
    /// Stable machine-readable code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Optional stack trace or runtime detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl InvocationError {
    /// Create an error with a code and message.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            detail: None,
        }
    }

    /// Attach runtime detail (stack trace, stderr excerpt).
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// A captured log line produced during an invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// `stdout`, `stderr`, or `platform`.
    pub stream: String,
    /// Log line.
    pub message: String,
    /// Milliseconds since the invocation started.
    pub offset_ms: u64,
}

/// Runtime-reported metrics for a single invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metrics {
    /// Resident memory observed by the runtime, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    /// CPU time consumed, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_ms: Option<u64>,
    /// Custom counters reported by the runtime.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counters: BTreeMap<String, u64>,
}

impl Metrics {
    /// Record a custom counter.
    pub fn counter(&mut self, key: impl Into<String>, value: u64) {
        self.counters.insert(key.into(), value);
    }
}

/// A runtime-independent invocation response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationResponse {
    /// Protocol version.
    pub protocol_version: u8,
    /// Invocation this response belongs to.
    pub invocation_id: InvocationId,
    /// Function that was invoked.
    pub function_id: FunctionId,
    /// Instance that served the invocation, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,
    /// Outcome.
    pub status: InvocationStatus,
    /// Response payload (empty for errors).
    #[serde(default, with = "crate::payload_bytes")]
    pub payload: Vec<u8>,
    /// Error, present unless the status is `success`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<InvocationError>,
    /// Logs captured during the invocation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logs: Vec<LogEntry>,
    /// Runtime metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Metrics>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
}

impl InvocationResponse {
    /// Create a success response.
    pub fn success(invocation_id: InvocationId, function_id: FunctionId, payload: Vec<u8>) -> Self {
        Self {
            protocol_version: crate::PROTOCOL_VERSION.0,
            invocation_id,
            function_id,
            instance_id: None,
            status: InvocationStatus::Success,
            payload,
            error: None,
            logs: Vec::new(),
            metrics: None,
            duration_ms: 0,
        }
    }

    /// Create a failure response.
    pub fn failure(
        invocation_id: InvocationId,
        function_id: FunctionId,
        status: InvocationStatus,
        error: InvocationError,
    ) -> Self {
        Self {
            protocol_version: crate::PROTOCOL_VERSION.0,
            invocation_id,
            function_id,
            instance_id: None,
            status,
            payload: Vec::new(),
            error: Some(error),
            logs: Vec::new(),
            metrics: None,
            duration_ms: 0,
        }
    }

    /// Create a timeout response.
    pub fn timeout(invocation_id: InvocationId, function_id: FunctionId, deadline_ms: u64) -> Self {
        Self::failure(
            invocation_id,
            function_id,
            InvocationStatus::Timeout,
            InvocationError::new(
                "RUSTFUN_INVOCATION_TIMEOUT",
                format!("invocation exceeded its deadline of {deadline_ms}ms"),
            ),
        )
    }

    /// Attach the serving instance.
    #[must_use]
    pub fn with_instance(mut self, instance_id: InstanceId) -> Self {
        self.instance_id = Some(instance_id);
        self
    }

    /// Attach captured logs.
    #[must_use]
    pub fn with_logs(mut self, logs: Vec<LogEntry>) -> Self {
        self.logs = logs;
        self
    }

    /// Attach metrics.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Attach a duration.
    #[must_use]
    pub fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }

    /// Whether the response reports success.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Validate protocol invariants.
    pub fn validate(&self) -> crate::error::ProtocolResult<()> {
        if self.protocol_version != crate::PROTOCOL_VERSION.0 {
            return Err(crate::error::ProtocolError::VersionMismatch {
                expected: crate::PROTOCOL_VERSION.0,
                actual: self.protocol_version,
            });
        }
        if self.status.is_success() && self.error.is_some() {
            return Err(crate::error::ProtocolError::Violation(
                "successful response must not carry an error".to_owned(),
            ));
        }
        if !self.status.is_success() && self.error.is_none() {
            return Err(crate::error::ProtocolError::Violation(format!(
                "response with status '{}' must carry an error",
                self.status.as_str()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfun_model::RequestId;

    fn ids() -> (InvocationId, FunctionId) {
        (InvocationId::new(), FunctionId::new())
    }

    #[test]
    fn success_response_is_valid() {
        let (invocation, function) = ids();
        let response = InvocationResponse::success(invocation, function, b"{}".to_vec())
            .with_duration_ms(12)
            .with_metrics(Metrics {
                memory_bytes: Some(1024),
                ..Metrics::default()
            });
        assert!(response.is_success());
        assert!(response.validate().is_ok());
        let json = serde_json::to_string(&response).expect("serializes");
        let back: InvocationResponse = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back.payload, b"{}");
        assert_eq!(back, response);
    }

    #[test]
    fn failure_requires_error() {
        let (invocation, function) = ids();
        let mut response =
            InvocationResponse::success(invocation.clone(), function.clone(), Vec::new());
        response.status = InvocationStatus::FunctionError;
        assert!(response.validate().is_err());

        let response = InvocationResponse::failure(
            invocation,
            function,
            InvocationStatus::FunctionError,
            InvocationError::new("BOOM", "handler threw"),
        );
        assert!(response.validate().is_ok());
    }

    #[test]
    fn timeout_response_shape() {
        let (invocation, function) = ids();
        let response = InvocationResponse::timeout(invocation, function, 5000);
        assert_eq!(response.status, InvocationStatus::Timeout);
        assert!(!response.status.is_retryable());
        let error = response.error.expect("error present");
        assert_eq!(error.code, "RUSTFUN_INVOCATION_TIMEOUT");
    }

    #[test]
    fn request_context_roundtrip_in_json() {
        let request = crate::InvocationRequest::new(
            RequestId::new(),
            InvocationId::new(),
            FunctionId::new(),
            b"\x00\x01\x02".to_vec(),
        );
        let json = serde_json::to_string(&request).expect("serializes");
        let back: crate::InvocationRequest = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back.payload, vec![0, 1, 2]);
    }
}
