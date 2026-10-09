//! Wire codec selection.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{ProtocolError, ProtocolResult};

/// Encoding used for a protocol frame body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Codec {
    /// Human-readable JSON. The default for developer-facing tooling.
    Json,
    /// Compact MessagePack. Used for hot paths, and the default for binary peers.
    #[default]
    MessagePack,
}

impl Codec {
    /// Stable codec id as written on the wire.
    pub const fn id(self) -> u8 {
        match self {
            Codec::Json => 1,
            Codec::MessagePack => 2,
        }
    }

    /// Decode a codec from its wire id.
    pub const fn from_id(id: u8) -> ProtocolResult<Self> {
        match id {
            1 => Ok(Codec::Json),
            2 => Ok(Codec::MessagePack),
            other => Err(ProtocolError::UnknownCodec { id: other }),
        }
    }

    /// Stable lowercase name.
    pub const fn name(self) -> &'static str {
        match self {
            Codec::Json => "json",
            Codec::MessagePack => "msgpack",
        }
    }

    /// Encode a value.
    pub fn encode<T: Serialize>(self, value: &T) -> ProtocolResult<Vec<u8>> {
        match self {
            Codec::Json => serde_json::to_vec(value).map_err(|e| ProtocolError::EncodeFailed {
                message: e.to_string(),
            }),
            Codec::MessagePack => {
                rmp_serde::to_vec_named(value).map_err(|e| ProtocolError::EncodeFailed {
                    message: e.to_string(),
                })
            }
        }
    }

    /// Decode a value.
    pub fn decode<T: DeserializeOwned>(self, bytes: &[u8]) -> ProtocolResult<T> {
        match self {
            Codec::Json => serde_json::from_slice(bytes).map_err(|e| ProtocolError::DecodeFailed {
                message: e.to_string(),
            }),
            Codec::MessagePack => {
                rmp_serde::from_slice(bytes).map_err(|e| ProtocolError::DecodeFailed {
                    message: e.to_string(),
                })
            }
        }
    }
}

impl std::fmt::Display for Codec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip() {
        let value = vec![1u32, 2, 3];
        let bytes = Codec::Json.encode(&value).expect("encodes");
        let back: Vec<u32> = Codec::Json.decode(&bytes).expect("decodes");
        assert_eq!(back, value);
    }

    #[test]
    fn msgpack_roundtrip() {
        let value = vec![Some(1u8), None, Some(3)];
        let bytes = Codec::MessagePack.encode(&value).expect("encodes");
        let back: Vec<Option<u8>> = Codec::MessagePack.decode(&bytes).expect("decodes");
        assert_eq!(back, value);
    }

    #[test]
    fn codec_ids_roundtrip() {
        for codec in [Codec::Json, Codec::MessagePack] {
            assert_eq!(Codec::from_id(codec.id()).expect("known"), codec);
        }
        assert!(Codec::from_id(99).is_err());
    }

    #[test]
    fn decode_garbage_fails_cleanly() {
        let err = Codec::Json
            .decode::<u32>(b"not json")
            .expect_err("must fail");
        assert_eq!(err.code(), "PROTOCOL_DECODE_FAILED");
    }
}
