//! Stable identifiers used across the execution spine.
//!
//! Identifiers are opaque, URL-safe strings. Domain types wrap them in newtypes so that a
//! `FunctionId` can never be passed where an `InstanceId` is expected, and provide a short
//! display form for logs.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, ModelResult};

/// Generate a new random identifier with the given prefix and length.
fn random_id(prefix: &str, len: usize) -> String {
    let uuid = uuid::Uuid::new_v4();
    let raw = uuid.simple().to_string();
    let mut out = String::with_capacity(prefix.len() + 1 + len);
    out.push_str(prefix);
    out.push('_');
    out.push_str(&raw[..len]);
    out
}

macro_rules! identifier {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl Default for $name {
            /// Generates a fresh random identifier.
            fn default() -> Self {
                Self(random_id($prefix, 22))
            }
        }

        impl $name {
            /// Create a new random identifier.
            pub fn new() -> Self {
                Self::default()
            }

            /// Create an identifier from an existing string, validating its shape.
            pub fn parse(raw: &str) -> ModelResult<Self> {
                if raw.is_empty() {
                    return Err(ModelError::validation(format!(
                        "{} must not be empty",
                        stringify!($name)
                    )));
                }
                if !raw
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
                {
                    return Err(ModelError::validation(format!(
                        "{} contains unsupported characters: {raw}",
                        stringify!($name)
                    )));
                }
                Ok(Self(raw.to_owned()))
            }

            /// Borrow the identifier as a string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Short form suitable for logs (last 8 characters).
            pub fn short(&self) -> &str {
                let start = self.0.len().saturating_sub(8);
                &self.0[start..]
            }

            /// Consume the identifier, yielding the inner string.
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $name {
            /// Infallible conversion for internally generated identifiers. Prefer
            /// [`$name::parse`] for untrusted input.
            fn from(value: String) -> Self {
                Self(value)
            }
        }
    };
}

identifier!(
    /// Stable identifier of a function.
    FunctionId,
    "fn"
);
identifier!(
    /// Identifier of a single invocation attempt.
    InvocationId,
    "inv"
);
identifier!(
    /// Correlation identifier of an inbound request.
    RequestId,
    "req"
);
identifier!(
    /// Identifier of a runtime instance (a live process/WASM instance).
    InstanceId,
    "inst"
);
identifier!(
    /// Identifier of a built artifact, derived from its digest.
    ArtifactId,
    "art"
);
identifier!(
    /// Identifier of an event on the event stream.
    EventId,
    "evt"
);
identifier!(
    /// Identifier of a (future) remote execution worker.
    WorkerId,
    "wrk"
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn generated_ids_are_unique_and_prefixed() {
        let ids: BTreeSet<String> = (0..256).map(|_| FunctionId::new().to_string()).collect();
        assert_eq!(ids.len(), 256);
        assert!(ids.iter().all(|id| id.starts_with("fn_")));
    }

    #[test]
    fn ids_of_different_types_have_different_prefixes() {
        assert!(InvocationId::new().as_str().starts_with("inv_"));
        assert!(InstanceId::new().as_str().starts_with("inst_"));
        assert!(ArtifactId::new().as_str().starts_with("art_"));
        assert!(EventId::new().as_str().starts_with("evt_"));
        assert!(WorkerId::new().as_str().starts_with("wrk_"));
        assert!(RequestId::new().as_str().starts_with("req_"));
    }

    #[test]
    fn parse_rejects_unsafe_characters() {
        assert!(FunctionId::parse("").is_err());
        assert!(FunctionId::parse("../../etc/passwd").is_err());
        assert!(FunctionId::parse("fn ok").is_err());
        assert!(FunctionId::parse("fn-ok.1").is_ok());
    }

    #[test]
    fn short_is_a_suffix() {
        let id = FunctionId::parse("fn_abcdefghijklmnopqrstuvwxyz").expect("valid");
        assert_eq!(id.short(), "stuvwxyz");
    }
}
