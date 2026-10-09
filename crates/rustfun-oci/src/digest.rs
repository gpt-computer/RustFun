//! OCI content digests.
//!
//! A digest is the only identity a blob has in OCI: the manifest refers to config and layers by
//! digest, and the cache is keyed by it. Verification happens before anything is extracted, so a
//! malicious or truncated layer fails closed.

use sha2::{Digest as Sha256Digest, Sha256};

/// A content digest, e.g. `sha256:abc123...`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest {
    /// Algorithm, always `sha256` in this platform.
    pub algorithm: String,
    /// Lowercase hex digest.
    pub hex: String,
}

impl Digest {
    /// Parse a digest, rejecting anything that is not `sha256:<64 lowercase hex>`.
    ///
    /// The strict form matters: a digest that can be parsed leniently can also be *compared*
    /// leniently, which is how a wrong blob ends up cached under the right name.
    pub fn parse(value: &str) -> Option<Self> {
        let (algorithm, hex) = value.split_once(':')?;
        // Lowercase only: a digest that parses leniently can also be compared leniently, which
        // is how a wrong blob ends up cached under the right name.
        if algorithm != "sha256"
            || hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        Some(Self {
            algorithm: algorithm.to_owned(),
            hex: hex.to_owned(),
        })
    }

    /// Compute the digest of a byte slice.
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self {
            algorithm: "sha256".to_owned(),
            hex: hex::encode(hasher.finalize()),
        }
    }

    /// The canonical string form, `sha256:<hex>`.
    pub fn as_str(&self) -> String {
        format!("{}:{}", self.algorithm, self.hex)
    }

    /// Verify that `bytes` match this digest.
    pub fn verify(&self, bytes: &[u8]) -> bool {
        self == &Self::of(bytes)
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_str())
    }
}

impl std::str::FromStr for Digest {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or_else(|| format!("`{value}` is not a valid sha256 digest"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_digest() {
        let digest = Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("valid");
        assert_eq!(
            digest.as_str(),
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn rejects_anything_that_is_not_a_strict_sha256_digest() {
        for bad in [
            "sha256:abc",
            "sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            "",
        ] {
            assert!(Digest::parse(bad).is_none(), "`{bad}` must be rejected");
        }
    }

    #[test]
    fn uppercase_hex_is_rejected_as_non_canonical() {
        assert!(
            Digest::parse(
                "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .is_none(),
            "a digest that parses leniently can also be compared leniently"
        );
    }

    #[test]
    fn verification_is_exact() {
        let digest = Digest::of(b"payload");
        assert!(digest.verify(b"payload"));
        assert!(!digest.verify(b"payloaD"));
        assert!(!digest.verify(b""));
    }

    #[test]
    fn a_known_digest_matches_its_hex() {
        // `sha256("")` is a published constant.
        let digest = Digest::of(b"");
        assert_eq!(
            digest.hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn display_is_the_canonical_form() {
        let digest = Digest::of(b"x");
        assert_eq!(digest.to_string(), digest.as_str());
    }
}
