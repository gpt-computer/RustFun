//! Parsed OCI image references.
//!
//! Accepted shapes follow what users actually write:
//!
//! ```text
//! ghcr.io/rustfun/hello:1.2.3
//! ghcr.io/rustfun/hello@sha256:abc...
//! ghcr.io/rustfun/hello:1.2.3@sha256:abc...
//! rustfun/hello            # tag defaults to `latest`
//! ```
//!
//! The registry defaults to `ghcr.io` only when the reference carries no registry; a reference
//! with a port (`localhost:5000/hello`) is treated as a registry reference, which is the rule the
//! OCI spec uses.

use crate::{OciError, OciResult};

/// A parsed image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    /// Registry host, e.g. `ghcr.io`.
    pub registry: String,
    /// Repository path, e.g. `rustfun/hello`.
    pub repository: String,
    /// Tag, when one was given.
    pub tag: Option<String>,
    /// Digest, when one was given.
    pub digest: Option<crate::Digest>,
}

impl ImageReference {
    /// Parse an image reference.
    pub fn parse(value: &str) -> OciResult<Self> {
        let value = value.trim();
        if value.is_empty() {
            return Err(OciError::new(
                "parse_reference",
                "the image reference is empty",
            ));
        }
        // A digest may follow a tag, so split it off first.
        let (without_digest, digest) = match value.rsplit_once('@') {
            Some((head, tail)) => (
                head,
                Some(crate::Digest::parse(tail).ok_or_else(|| {
                    OciError::new("parse_reference", format!("`{tail}` is not a valid digest"))
                })?),
            ),
            None => (value, None),
        };

        let mut registry = "ghcr.io".to_owned();
        let rest = match without_digest.split_once('/') {
            // A leading segment is a registry only when it looks like a host: a dot, a port, or
            // `localhost`. `./bin/handler` starts with a dot but is a path, and treating its
            // first component as a registry would produce a reference that only fails later, at
            // the registry.
            Some((first, path))
                if first.starts_with('[')
                    || (first
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphanumeric())
                        && (first.contains('.')
                            || first.contains(':')
                            || first == "localhost")) =>
            {
                registry = first.to_owned();
                path.to_owned()
            }
            _ => without_digest.to_owned(),
        };
        if rest.is_empty() {
            return Err(OciError::new(
                "parse_reference",
                format!("`{value}` names no repository"),
            ));
        }

        let (repository, tag) = match rest.rsplit_once(':') {
            // A colon after the last slash is a tag separator; before it, it is part of the
            // registry host (handled above) or an invalid reference.
            Some((repo, tag)) if !tag.contains('/') && !repo.is_empty() => {
                (repo.to_owned(), Some(tag.to_owned()))
            }
            _ => (rest, None),
        };
        if repository.is_empty() {
            return Err(OciError::new(
                "parse_reference",
                format!("`{value}` names no repository"),
            ));
        }
        // The OCI grammar for a repository component is
        // `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`. Enforcing it here is what separates an image
        // reference from a filesystem path: `./bin/handler` is a path, and calling it an image
        // would turn a clear mistake into a confusing registry error later.
        for component in repository.split('/') {
            if !is_repository_component(component) {
                return Err(OciError::new(
                    "parse_reference",
                    format!("`{component}` is not a valid OCI repository component in `{value}`"),
                ));
            }
        }
        if let Some(tag) = &tag {
            if tag.is_empty() {
                return Err(OciError::new(
                    "parse_reference",
                    format!("`{value}` has an empty tag"),
                ));
            }
        }
        Ok(Self {
            registry,
            repository,
            tag,
            digest,
        })
    }

    /// The reference as it should be sent to the registry, without the digest.
    pub fn name(&self) -> String {
        match &self.tag {
            Some(tag) => format!("{}/{}:{}", self.registry, self.repository, tag),
            None => format!("{}/{}", self.registry, self.repository),
        }
    }

    /// Full identity including the digest, when one was given.
    pub fn canonical(&self) -> String {
        match &self.digest {
            Some(digest) => format!("{}@{}", self.name(), digest.as_str()),
            None => self.name(),
        }
    }

    /// Whether this reference pins an exact digest.
    ///
    /// A digest-pinned reference is reproducible; a tag is not, and callers that care about
    /// reproducibility should say so.
    pub fn is_pinned(&self) -> bool {
        self.digest.is_some()
    }
}

/// Whether a path component matches the OCI repository grammar.
fn is_repository_component(component: &str) -> bool {
    if component.is_empty() {
        return false;
    }
    let bytes = component.as_bytes();
    if !is_alphanumeric(bytes[0]) || !is_alphanumeric(bytes[bytes.len() - 1]) {
        return false;
    }
    let mut previous_separator = false;
    for byte in bytes {
        if is_alphanumeric(*byte) {
            previous_separator = false;
        } else if matches!(byte, b'.' | b'_' | b'-') {
            if previous_separator {
                // Two separators in a row are only legal as the single `__` form, which is
                // handled by rejecting `___` and allowing `__`.
                if component.contains("___") {
                    return false;
                }
            }
            previous_separator = true;
        } else {
            return false;
        }
    }
    true
}

fn is_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

impl std::fmt::Display for ImageReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical())
    }
}

impl std::str::FromStr for ImageReference {
    type Err = OciError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_tagged_reference() {
        let reference = ImageReference::parse("ghcr.io/rustfun/hello:1.2.3").expect("valid");
        assert_eq!(reference.registry, "ghcr.io");
        assert_eq!(reference.repository, "rustfun/hello");
        assert_eq!(reference.tag.as_deref(), Some("1.2.3"));
        assert_eq!(reference.digest, None);
        assert_eq!(reference.name(), "ghcr.io/rustfun/hello:1.2.3");
    }

    #[test]
    fn a_single_name_gets_the_default_registry() {
        let reference = ImageReference::parse("rustfun/hello").expect("valid");
        assert_eq!(reference.registry, "ghcr.io");
        assert_eq!(reference.repository, "rustfun/hello");
        assert_eq!(reference.tag, None);
    }

    #[test]
    fn a_local_registry_with_a_port_is_recognised() {
        let reference = ImageReference::parse("localhost:5000/hello:1").expect("valid");
        assert_eq!(reference.registry, "localhost:5000");
        assert_eq!(reference.repository, "hello");
    }

    #[test]
    fn a_digest_is_split_off_the_tag() {
        let digest = crate::Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("valid digest");
        let reference =
            ImageReference::parse(&format!("ghcr.io/rustfun/hello:1.2.3@{digest}")).expect("valid");
        assert_eq!(reference.tag.as_deref(), Some("1.2.3"));
        assert_eq!(reference.digest, Some(digest));
        assert!(reference.is_pinned());
    }

    #[test]
    fn a_filesystem_path_is_not_an_image_reference() {
        for path in [
            "./bin/handler",
            "/app/handler",
            "app/../handler",
            "UPPER/case",
        ] {
            assert!(
                ImageReference::parse(path).is_err(),
                "`{path}` is a path, not an image reference"
            );
        }
    }

    #[test]
    fn accepts_the_repository_shapes_registries_actually_use() {
        for reference in [
            "ghcr.io/rustfun/hello:1",
            "rustfun/hello_wasm",
            "rustfun/hello.wasm",
            "registry.example.com:5000/team/app",
            "library/alpine",
            "my_repo__with_underscores",
        ] {
            assert!(
                ImageReference::parse(reference).is_ok(),
                "`{reference}` is a valid reference"
            );
        }
    }

    #[test]
    fn rejects_references_that_cannot_be_pinned_down() {
        for bad in [
            "",
            "ghcr.io/",
            "ghcr.io/rustfun/hello:",
            "ghcr.io/rustfun/hello@sha256:abc",
            "ghcr.io/rustfun/hello@notadigest",
        ] {
            assert!(
                ImageReference::parse(bad).is_err(),
                "`{bad}` must be rejected"
            );
        }
    }

    #[test]
    fn display_includes_the_digest_when_present() {
        let reference = ImageReference::parse(
            "ghcr.io/rustfun/hello:1.2.3@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("valid");
        let text = reference.to_string();
        assert!(text.contains("1.2.3"));
        assert!(text.contains("sha256:"));
    }
}
