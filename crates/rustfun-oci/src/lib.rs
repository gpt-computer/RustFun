//! OCI image support for RustFun.
//!
//! This crate turns an OCI image reference into a verified, cached root filesystem:
//!
//! ```text
//! reference ──► registry ──► manifest ──► config + layers ──► cache ──► rootfs
//! ```
//!
//! It deliberately does **not** implement a container runtime. Starting a container is delegated
//! to `runc` (or `crun`) when one is installed and can actually run, and reported as unavailable
//! otherwise — the same honest capability reporting the rest of the platform uses.
//!
//! # Security properties
//!
//! - **Every blob is verified against its digest** before it is used. A layer whose bytes do not
//!   match the manifest digest is an error, never a silently extracted file.
//! - **Extraction is traversal-safe.** A layer containing `../../etc/passwd` is rejected, and OCI
//!   whiteout files are honoured so a layer cannot resurrect a file an earlier layer deleted.
//! - **The cache is content-addressed.** Two references to the same digest share one copy, and a
//!   corrupted cached blob is re-fetched rather than trusted.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cache;
pub mod container;
pub mod digest;
pub mod manifest;
pub mod reference;
pub mod registry;
pub mod rootfs;

pub use cache::OciImageCache;
pub use container::{ContainerHandle, ContainerRuntime, RuncRuntime};
pub use digest::Digest;
pub use manifest::{Descriptor, ImageConfig, ImageManifest, Platform};
pub use reference::ImageReference;
pub use registry::RegistryClient;
pub use rootfs::RootfsBuilder;

/// Media types this crate accepts.
pub mod media_types {
    /// Docker schema 2 image manifest.
    pub const MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
    /// Docker schema 2 image manifest list (multi-arch).
    pub const MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
    /// OCI image manifest.
    pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    /// OCI image index (multi-arch).
    pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
    /// Docker schema 2 image config.
    pub const CONFIG: &str = "application/vnd.docker.container.image.v1+json";
    /// OCI image config.
    pub const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
    /// A gzipped tar layer.
    pub const LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
    /// An uncompressed tar layer.
    pub const LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
    /// A gzipped tar layer (OCI spelling).
    pub const LAYER_GZIP_OCI: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
}

/// Error type for OCI operations.
///
/// A dedicated type keeps OCI failures distinguishable from artifact and runtime failures, which
/// matters because the remediation differs: a registry error is transient, a digest mismatch is
/// not.
#[derive(Debug)]
pub struct OciError {
    /// What was being attempted.
    pub operation: String,
    /// Human-readable reason.
    pub message: String,
    /// Underlying cause, when there is one.
    pub source: Option<String>,
}

impl OciError {
    /// Build an OCI error.
    pub fn new(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Attach the underlying cause.
    pub fn with_source(mut self, source: impl std::fmt::Display) -> Self {
        self.source = Some(source.to_string());
        self
    }
}

impl std::fmt::Display for OciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "oci {}: {}", self.operation, self.message)?;
        if let Some(source) = &self.source {
            write!(f, " ({source})")?;
        }
        Ok(())
    }
}

impl std::error::Error for OciError {}

/// Result alias for OCI operations.
pub type OciResult<T> = Result<T, OciError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oci_error_reports_operation_and_cause() {
        let error = OciError::new("pull", "manifest not found").with_source("http 404");
        let text = error.to_string();
        assert!(text.contains("pull"));
        assert!(text.contains("manifest not found"));
        assert!(text.contains("http 404"));
    }

    #[test]
    fn media_types_are_distinct() {
        assert_ne!(media_types::MANIFEST, media_types::OCI_MANIFEST);
        assert_ne!(media_types::LAYER_GZIP, media_types::LAYER_TAR);
    }
}
