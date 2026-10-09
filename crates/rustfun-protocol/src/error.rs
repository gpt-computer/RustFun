//! Protocol-level errors.

use rustfun_model::ModelError;

/// Result alias for protocol operations.
pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// A structured protocol error.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// The peer speaks a different major protocol version.
    #[error(
        "[PROTOCOL_VERSION_MISMATCH] peer speaks protocol v{actual}, this build speaks v{expected}"
    )]
    VersionMismatch {
        /// Version implemented by this build.
        expected: u8,
        /// Version announced by the peer.
        actual: u8,
    },
    /// The frame magic bytes were not recognized.
    #[error("[PROTOCOL_BAD_MAGIC] expected frame magic {expected:?}, found {found:?}")]
    BadMagic {
        /// Expected magic bytes.
        expected: [u8; 4],
        /// Bytes actually found.
        found: [u8; 4],
    },
    /// The frame announced a length above the configured maximum.
    #[error(
        "[PROTOCOL_FRAME_TOO_LARGE] frame of {length} bytes exceeds the limit of {limit} bytes"
    )]
    FrameTooLarge {
        /// Announced length.
        length: usize,
        /// Configured limit.
        limit: usize,
    },
    /// The codec byte was not recognized.
    #[error("[PROTOCOL_UNKNOWN_CODEC] codec id {id} is not supported")]
    UnknownCodec {
        /// Unknown codec identifier.
        id: u8,
    },
    /// The payload could not be decoded with the announced codec.
    #[error("[PROTOCOL_DECODE_FAILED] {message}")]
    DecodeFailed {
        /// Decoder message.
        message: String,
    },
    /// The payload could not be encoded.
    #[error("[PROTOCOL_ENCODE_FAILED] {message}")]
    EncodeFailed {
        /// Encoder message.
        message: String,
    },
    /// The transport closed while a message was in flight.
    #[error("[PROTOCOL_TRANSPORT_CLOSED] connection closed: {reason}")]
    TransportClosed {
        /// Why the connection ended.
        reason: String,
    },
    /// An I/O error occurred on the transport.
    #[error("[PROTOCOL_IO] {message}")]
    Io {
        /// Underlying I/O message.
        message: String,
    },
    /// The peer violated a protocol invariant.
    #[error("[PROTOCOL_VIOLATION] {0}")]
    Violation(String),
}

impl ProtocolError {
    /// Stable machine-readable code.
    pub const fn code(&self) -> &'static str {
        match self {
            ProtocolError::VersionMismatch { .. } => "PROTOCOL_VERSION_MISMATCH",
            ProtocolError::BadMagic { .. } => "PROTOCOL_BAD_MAGIC",
            ProtocolError::FrameTooLarge { .. } => "PROTOCOL_FRAME_TOO_LARGE",
            ProtocolError::UnknownCodec { .. } => "PROTOCOL_UNKNOWN_CODEC",
            ProtocolError::DecodeFailed { .. } => "PROTOCOL_DECODE_FAILED",
            ProtocolError::EncodeFailed { .. } => "PROTOCOL_ENCODE_FAILED",
            ProtocolError::TransportClosed { .. } => "PROTOCOL_TRANSPORT_CLOSED",
            ProtocolError::Io { .. } => "PROTOCOL_IO",
            ProtocolError::Violation(_) => "PROTOCOL_VIOLATION",
        }
    }

    /// Whether retrying the same operation could succeed.
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            ProtocolError::TransportClosed { .. } | ProtocolError::Io { .. }
        )
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(value: std::io::Error) -> Self {
        ProtocolError::Io {
            message: value.to_string(),
        }
    }
}

impl From<ModelError> for ProtocolError {
    fn from(value: ModelError) -> Self {
        ProtocolError::Violation(value.to_string())
    }
}

/// Render an error for human consumption (CLI).
pub fn human_readable(error: &ProtocolError) -> String {
    format!("{error}")
}

/// Render an error for machine consumption.
pub fn machine_readable(error: &ProtocolError) -> serde_json::Value {
    serde_json::json!({
        "code": error.code(),
        "message": error.to_string(),
        "retryable": error.is_retryable(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        assert_eq!(
            ProtocolError::TransportClosed {
                reason: "eof".into()
            }
            .code(),
            "PROTOCOL_TRANSPORT_CLOSED"
        );
        assert!(ProtocolError::Io {
            message: "reset".into()
        }
        .is_retryable());
        assert!(!ProtocolError::BadMagic {
            expected: *b"RFN1",
            found: [0, 0, 0, 0]
        }
        .is_retryable());
    }

    #[test]
    fn machine_readable_includes_code_and_retryability() {
        let err = ProtocolError::FrameTooLarge {
            length: 10,
            limit: 5,
        };
        let value = machine_readable(&err);
        assert_eq!(value["code"], "PROTOCOL_FRAME_TOO_LARGE");
        assert_eq!(value["retryable"], false);
    }
}
