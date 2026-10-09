//! Length-prefixed frame encoding.
//!
//! ```text
//! +--------+--------+----------+-------------------+
//! | "RFN1" | ver    | codec/id | u32 length (BE)    |
//! +--------+--------+----------+-------------------+
//! | payload ...                                            |
//! +------------------------------------------------------+
//! ```

use crate::codec::Codec;
use crate::error::{ProtocolError, ProtocolResult};

/// Magic bytes at the start of every frame.
pub const PROTOCOL_MAGIC: [u8; 4] = *b"RFN1";

/// Length of the fixed frame header.
pub const HEADER_LEN: usize = 4 + 1 + 1 + 4;

/// Default maximum frame size: 256 MiB.
pub const MAX_FRAME_BYTES: usize = 256 * 1024 * 1024;

/// Parsed frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Protocol major version.
    pub version: u8,
    /// Frame body codec.
    pub codec: Codec,
    /// Body length in bytes.
    pub length: usize,
}

impl FrameHeader {
    /// Serialize the header.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..4].copy_from_slice(&PROTOCOL_MAGIC);
        buf[4] = self.version;
        buf[5] = self.codec.id();
        let len = u32::try_from(self.length).unwrap_or(u32::MAX);
        buf[6..10].copy_from_slice(&len.to_be_bytes());
        buf
    }

    /// Parse a header from the first `HEADER_LEN` bytes.
    pub fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(ProtocolError::TransportClosed {
                reason: format!("incomplete frame header: {} bytes", bytes.len()),
            });
        }
        let found: [u8; 4] = bytes[0..4].try_into().unwrap_or([0; 4]);
        if found != PROTOCOL_MAGIC {
            return Err(ProtocolError::BadMagic {
                expected: PROTOCOL_MAGIC,
                found,
            });
        }
        let version = bytes[4];
        let codec = Codec::from_id(bytes[5])?;
        let length = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
        Ok(Self {
            version,
            codec,
            length,
        })
    }
}

/// Encode a value into a complete frame.
pub fn encode_frame<T: serde::Serialize>(codec: Codec, value: &T) -> ProtocolResult<Vec<u8>> {
    encode_frame_with_limit(codec, value, MAX_FRAME_BYTES)
}

/// Encode a value into a complete frame, rejecting payloads above `max_frame_bytes`.
pub fn encode_frame_with_limit<T: serde::Serialize>(
    codec: Codec,
    value: &T,
    max_frame_bytes: usize,
) -> ProtocolResult<Vec<u8>> {
    let body = codec.encode(value)?;
    if body.len() > max_frame_bytes {
        return Err(ProtocolError::FrameTooLarge {
            length: body.len(),
            limit: max_frame_bytes,
        });
    }
    let header = FrameHeader {
        version: crate::PROTOCOL_VERSION.0,
        codec,
        length: body.len(),
    };
    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decode a complete frame into a value.
pub fn decode_frame<T: serde::de::DeserializeOwned>(frame: &[u8]) -> ProtocolResult<T> {
    decode_frame_with_limit(frame, MAX_FRAME_BYTES)
}

/// Decode a complete frame into a value, rejecting frames above `max_frame_bytes`.
pub fn decode_frame_with_limit<T: serde::de::DeserializeOwned>(
    frame: &[u8],
    max_frame_bytes: usize,
) -> ProtocolResult<T> {
    let header = FrameHeader::decode(frame)?;
    if header.length > max_frame_bytes {
        return Err(ProtocolError::FrameTooLarge {
            length: header.length,
            limit: max_frame_bytes,
        });
    }
    let body = frame
        .get(HEADER_LEN..HEADER_LEN + header.length)
        .ok_or_else(|| ProtocolError::TransportClosed {
            reason: format!(
                "frame body truncated: expected {} bytes, have {}",
                header.length,
                frame.len().saturating_sub(HEADER_LEN)
            ),
        })?;
    header.codec.decode(body)
}

/// Check the header of an in-progress frame and report the body length.
///
/// Returns `None` when more bytes are needed.
pub fn peek_frame_length(buffer: &[u8]) -> ProtocolResult<Option<(FrameHeader, usize)>> {
    if buffer.len() < HEADER_LEN {
        return Ok(None);
    }
    let header = FrameHeader::decode(buffer)?;
    Ok(Some((header, HEADER_LEN + header.length)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frame = encode_frame(Codec::Json, &vec![1u8, 2, 3]).expect("encodes");
        assert_eq!(&frame[0..4], b"RFN1");
        let value: Vec<u8> = decode_frame(&frame).expect("decodes");
        assert_eq!(value, vec![1, 2, 3]);
    }

    #[test]
    fn header_roundtrip() {
        let header = FrameHeader {
            version: 1,
            codec: Codec::MessagePack,
            length: 12345,
        };
        let bytes = header.encode();
        assert_eq!(FrameHeader::decode(&bytes).expect("decodes"), header);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut frame = encode_frame(Codec::Json, &1u8).expect("encodes");
        frame[0] = b'X';
        let err = decode_frame::<u8>(&frame).expect_err("must fail");
        assert_eq!(err.code(), "PROTOCOL_BAD_MAGIC");
    }

    #[test]
    fn rejects_oversized_frames() {
        let err =
            encode_frame_with_limit(Codec::Json, &vec![0u8; 1024], 16).expect_err("must fail");
        assert_eq!(err.code(), "PROTOCOL_FRAME_TOO_LARGE");
    }

    #[test]
    fn rejects_truncated_body() {
        let frame = encode_frame(Codec::Json, &vec![1u8; 100]).expect("encodes");
        let err = decode_frame::<Vec<u8>>(&frame[..HEADER_LEN + 10]).expect_err("must fail");
        assert_eq!(err.code(), "PROTOCOL_TRANSPORT_CLOSED");
    }

    #[test]
    fn peek_reports_pending_length() {
        let frame = encode_frame(Codec::Json, &vec![7u8; 8]).expect("encodes");
        assert!(peek_frame_length(&frame[..4]).expect("no error").is_none());
        let (header, total) = peek_frame_length(&frame)
            .expect("no error")
            .expect("complete");
        assert_eq!(total, frame.len());
        assert_eq!(header.length, total - HEADER_LEN);
    }

    #[test]
    fn rejects_lying_length_without_allocating() {
        // Announce a huge length with a small buffer; decoding must fail cleanly.
        let mut frame = encode_frame(Codec::Json, &vec![1u8; 4]).expect("encodes");
        frame[6..10].copy_from_slice(&(1_000_000u32).to_be_bytes());
        let err = decode_frame::<Vec<u8>>(&frame).expect_err("must fail");
        assert_eq!(err.code(), "PROTOCOL_TRANSPORT_CLOSED");
    }
}
