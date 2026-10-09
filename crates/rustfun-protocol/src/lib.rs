//! RustFun invocation protocol.
//!
//! The protocol is runtime-independent: a Node handler, a Python handler, a Rust binary, and
//! a WASM module all speak the same request/response contract over a length-prefixed frame.
//! Nothing in this crate knows about a specific language runtime.
//!
//! # Wire format
//!
//! ```text
//! +--------+--------+----------+---------------------+
//! | "RFN1" | codec  | u32 len  | payload (len bytes) |
//! +--------+--------+----------+---------------------+
//! ```
//!
//! `codec` is `1` for JSON (developer-facing, debuggable) and `2` for MessagePack (compact,
//! used by default for hot paths). Frames larger than the configured maximum are rejected
//! before allocation grows unbounded.
//!
//! # Example
//!
//! ```
//! use rustfun_protocol::{decode_frame, encode_frame, Codec, InvocationRequest};
//! use rustfun_model::{FunctionId, InvocationId, RequestId};
//!
//! let request = InvocationRequest::new(
//!     RequestId::new(),
//!     InvocationId::new(),
//!     FunctionId::new(),
//!     b"hello".to_vec(),
//! );
//! let frame = encode_frame(Codec::Json, &request).expect("encodes");
//! let decoded: InvocationRequest = decode_frame(&frame).expect("decodes");
//! assert_eq!(decoded.payload, b"hello");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::time::Duration;

use rustfun_model::{FunctionId, InvocationId, RequestId};
use serde::{Deserialize, Serialize};

/// Shared base64 (RFC 4648) helpers for byte payloads in JSON.
pub(crate) mod payload_bytes {
    use serde::Deserialize;
    use serde::{Deserializer, Serializer};

    /// Serialize a byte payload as base64 text.
    pub fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::base64_encode(value))
    }

    /// Deserialize a byte payload from base64 text.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = <String as Deserialize>::deserialize(d)?;
        super::base64_decode(&text).map_err(serde::de::Error::custom)
    }
}

mod codec;
mod error;
mod frame;
mod response;
mod transport;

pub use codec::Codec;
pub use error::{human_readable, machine_readable, ProtocolError, ProtocolResult};
pub use frame::{
    decode_frame, encode_frame, peek_frame_length, FrameHeader, HEADER_LEN, MAX_FRAME_BYTES,
    PROTOCOL_MAGIC,
};
pub use response::{InvocationError, InvocationResponse, InvocationStatus, LogEntry, Metrics};
#[doc(no_inline)]
pub use rustfun_model as model;
pub use transport::{FramedReader, FramedTransport, FramedWriter};

/// Protocol version implemented by this crate.
///
/// The first byte on the wire is the major version; the frame header carries the minor
/// version so that additive changes do not break existing runtimes.
pub const PROTOCOL_VERSION: (u8, u8) = (1, 0);

/// Maximum payload size accepted by default, independent of function resource limits.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;

/// Correlation and tracing context carried with a request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    /// Trace identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Parent span identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    /// Human-readable client identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}

impl RequestContext {
    /// Create an empty context.
    pub fn new() -> Self {
        Self::default()
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

    /// Attach a client identifier.
    #[must_use]
    pub fn with_client(mut self, client: impl Into<String>) -> Self {
        self.client = Some(client.into());
        self
    }
}

/// A runtime-independent invocation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationRequest {
    /// Protocol version, so a runtime can detect a mismatch.
    pub protocol_version: u8,
    /// Correlation id of the inbound request.
    pub request_id: RequestId,
    /// Unique id of this invocation.
    pub invocation_id: InvocationId,
    /// Function being invoked.
    pub function_id: FunctionId,
    /// Function name, provided for diagnostics and handler resolution.
    pub function_name: String,
    /// Request payload (opaque bytes; usually JSON or CBOR).
    #[serde(with = "crate::payload_bytes")]
    pub payload: Vec<u8>,
    /// Relative deadline in milliseconds. `0` means "no deadline".
    pub deadline_ms: u64,
    /// Request metadata (headers, routing info, etc.).
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
    /// Per-invocation environment overlays.
    #[serde(default)]
    pub environment: std::collections::BTreeMap<String, String>,
    /// Tracing context.
    #[serde(default)]
    pub context: RequestContext,
}

pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn base64_decode(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|e| e.to_string())
}

impl InvocationRequest {
    /// Create a request with default deadline and no metadata.
    pub fn new(
        request_id: RequestId,
        invocation_id: InvocationId,
        function_id: FunctionId,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.0,
            request_id,
            invocation_id,
            function_id,
            function_name: String::new(),
            payload,
            deadline_ms: 0,
            metadata: std::collections::BTreeMap::new(),
            environment: std::collections::BTreeMap::new(),
            context: RequestContext::default(),
        }
    }

    /// Attach the function name.
    #[must_use]
    pub fn with_function_name(mut self, name: impl Into<String>) -> Self {
        self.function_name = name.into();
        self
    }

    /// Attach a deadline.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline_ms = deadline.as_millis() as u64;
        self
    }

    /// Attach a metadata entry.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Attach a per-invocation environment overlay.
    #[must_use]
    pub fn with_environment(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Attach tracing context.
    #[must_use]
    pub fn with_context(mut self, context: RequestContext) -> Self {
        self.context = context;
        self
    }

    /// The remaining deadline, if any.
    pub fn remaining_deadline(&self) -> Option<Duration> {
        if self.deadline_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(self.deadline_ms))
        }
    }

    /// Validate protocol-level invariants (not payload size, which is limit-dependent).
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.protocol_version != PROTOCOL_VERSION.0 {
            return Err(ProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION.0,
                actual: self.protocol_version,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        for len in 0..64usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            let encoded = base64_encode(&bytes);
            let decoded = base64_decode(&encoded).expect("decodes");
            assert_eq!(decoded, bytes, "len {len}");
        }
    }

    #[test]
    fn base64_rejects_malformed() {
        assert!(base64_decode("abc").is_err());
        assert!(base64_decode("ab*d").is_err());
    }

    #[test]
    fn payload_survives_json_roundtrip() {
        let mut request = InvocationRequest::new(
            RequestId::new(),
            InvocationId::new(),
            FunctionId::new(),
            vec![0, 1, 2, 255],
        )
        .with_function_name("hello")
        .with_deadline(Duration::from_millis(1500))
        .with_metadata("header:x-test", "1")
        .with_context(RequestContext::new().with_trace_id("trace-1"));

        let json = serde_json::to_string(&request).expect("serializes");
        let back: InvocationRequest = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, request);

        request.deadline_ms = 0;
        assert!(request.remaining_deadline().is_none());
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let mut request = InvocationRequest::new(
            RequestId::new(),
            InvocationId::new(),
            FunctionId::new(),
            Vec::new(),
        );
        request.protocol_version = 9;
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::VersionMismatch {
                expected: 1,
                actual: 9
            })
        ));
    }
}
