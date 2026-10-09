//! Content digests used for content-addressed artifacts and runtime identities.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::error::{ModelError, ModelResult};

/// Hash algorithm used for content addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// SHA-256, the default and only currently supported algorithm.
    Sha256,
}

impl Algorithm {
    /// Textual name of the algorithm.
    pub const fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
        }
    }

    /// Number of hex characters in a digest of this algorithm.
    pub const fn hex_len(self) -> usize {
        match self {
            Algorithm::Sha256 => 64,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A content digest, e.g. `sha256:9f86d0818...`.
///
/// Digests are the identity of artifacts: identical content always produces an identical
/// digest, which is what makes the artifact cache content-addressed (ADR-0004).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest {
    algorithm: Algorithm,
    hex: String,
}

impl Digest {
    /// Compute the digest of `bytes` with the given algorithm.
    pub fn of(algorithm: Algorithm, bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hex = hex::encode(hasher.finalize());
        Self { algorithm, hex }
    }

    /// Compute a SHA-256 digest of `bytes`.
    pub fn sha256(bytes: &[u8]) -> Self {
        Self::of(Algorithm::Sha256, bytes)
    }

    /// Parse a digest string of the form `<algorithm>:<hex>`.
    pub fn parse(raw: &str) -> ModelResult<Self> {
        let (alg, hex) = raw.split_once(':').ok_or_else(|| {
            ModelError::invalid_digest(format!("missing algorithm prefix: {raw}"))
        })?;
        let algorithm = match alg {
            "sha256" => Algorithm::Sha256,
            other => {
                return Err(ModelError::invalid_digest(format!(
                    "unsupported digest algorithm '{other}', expected 'sha256'"
                )))
            }
        };
        if hex.len() != algorithm.hex_len() {
            return Err(ModelError::invalid_digest(format!(
                "expected {} hex characters, found {}",
                algorithm.hex_len(),
                hex.len()
            )));
        }
        if !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ModelError::invalid_digest(
                "digest must be lowercase hexadecimal",
            ));
        }
        Ok(Self {
            algorithm,
            hex: hex.to_owned(),
        })
    }

    /// Hash algorithm of this digest.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Hexadecimal portion of the digest, without the algorithm prefix.
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Return a `Digest` for `bytes` if it matches `self`.
    pub fn verify(&self, bytes: &[u8]) -> bool {
        Digest::of(self.algorithm, bytes) == *self
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hex)
    }
}

impl FromStr for Digest {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Digest::parse(s)
    }
}

impl TryFrom<String> for Digest {
    type Error = ModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Digest::parse(&value)
    }
}

impl From<Digest> for String {
    fn from(value: Digest) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sha256_vector() {
        let digest = Digest::sha256(b"rustfun");
        assert!(digest.verify(b"rustfun"));
        assert!(!digest.verify(b"rustfun!"));
        assert_eq!(digest.algorithm(), Algorithm::Sha256);
    }

    #[test]
    fn roundtrip_through_string() {
        let digest = Digest::sha256(b"payload");
        let text = digest.to_string();
        assert!(text.starts_with("sha256:"));
        let parsed = Digest::parse(&text).expect("valid digest");
        assert_eq!(parsed, digest);
    }

    #[test]
    fn rejects_bad_digests() {
        assert!(Digest::parse("nope").is_err());
        assert!(Digest::parse("md5:abcd").is_err());
        assert!(Digest::parse("sha256:short").is_err());
        assert!(Digest::parse(&format!("sha256:{}", "A".repeat(64))).is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let digest = Digest::sha256(b"artifact");
        let json = serde_json::to_string(&digest).expect("serializes");
        assert_eq!(json, format!("\"{digest}\""));
        let back: Digest = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, digest);
    }
}
