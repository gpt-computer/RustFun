//! Artifact store contracts.
//!
//! The core defines what an artifact store must do; `rustfun-artifact` implements it on top of
//! a content-addressed directory. Keeping the trait here means the function manager depends on
//! a contract, not on storage.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use rustfun_model::{Digest, FunctionId, FunctionSpec};

use crate::error::{ErrorContext, Result, RustFunError};

/// A request to build an artifact from a function's source.
#[derive(Debug, Clone)]
pub struct BuildRequest {
    /// Function to build.
    pub function_id: FunctionId,
    /// Function spec (handler, runtime, etc.).
    pub spec: std::sync::Arc<FunctionSpec>,
    /// Directory containing the function source.
    pub source_dir: PathBuf,
    /// Optional build command. When `None`, the builder packages the directory as-is.
    pub build_command: Option<Vec<String>>,
    /// Skip the cache lookup and force a rebuild.
    pub force_rebuild: bool,
}

impl BuildRequest {
    /// Create a build request without a custom build command.
    pub fn new(
        function_id: FunctionId,
        spec: std::sync::Arc<FunctionSpec>,
        source_dir: PathBuf,
    ) -> Self {
        Self {
            function_id,
            spec,
            source_dir,
            build_command: None,
            force_rebuild: false,
        }
    }

    /// Set a build command.
    #[must_use]
    pub fn with_build_command(mut self, command: Vec<String>) -> Self {
        self.build_command = Some(command);
        self
    }

    /// Force a rebuild, bypassing the cache.
    #[must_use]
    pub fn force_rebuild(mut self) -> Self {
        self.force_rebuild = true;
        self
    }
}

/// Summary of a stored artifact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactSummary {
    /// Content digest (the artifact's identity).
    pub digest: Digest,
    /// Artifact size in bytes.
    pub size_bytes: u64,
    /// Number of files in the artifact.
    pub file_count: usize,
    /// When the artifact was created, in seconds since the epoch.
    pub created_at: u64,
}

/// A built artifact: its identity and where its content lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltArtifact {
    /// Content digest.
    pub digest: Digest,
    /// Directory holding the extracted artifact.
    pub path: PathBuf,
    /// Artifact size in bytes.
    pub size_bytes: u64,
    /// File count.
    pub file_count: usize,
}

impl BuiltArtifact {
    /// Build a reference from a summary and a path.
    pub fn new(summary: &ArtifactSummary, path: PathBuf) -> Self {
        Self {
            digest: summary.digest.clone(),
            path,
            size_bytes: summary.size_bytes,
            file_count: summary.file_count,
        }
    }
}

/// A content-addressed artifact store.
#[async_trait]
pub trait ArtifactStore: Send + Sync {
    /// Build (or reuse) an artifact for a function.
    async fn build(&self, request: BuildRequest) -> Result<ArtifactSummary>;

    /// Look up an artifact by digest without extracting it.
    async fn metadata(&self, digest: &Digest) -> Result<Option<ArtifactSummary>>;

    /// Check whether an artifact exists.
    async fn contains(&self, digest: &Digest) -> Result<bool>;

    /// Materialize an artifact into a directory, verifying its digest.
    ///
    /// Returns the path the artifact was extracted to. Repeated calls for the same digest
    /// return the same directory.
    async fn extract(&self, digest: &Digest, destination: &std::path::Path) -> Result<PathBuf>;

    /// Remove an artifact from the store.
    async fn remove(&self, digest: &Digest) -> Result<()>;

    /// Total bytes currently stored.
    async fn size_bytes(&self) -> Result<u64>;

    /// Drop entries not accessed within `max_age`, returning how many were removed.
    async fn evict(&self, max_age: Duration) -> Result<usize>;

    /// Verify a stored artifact against its digest, removing it when corrupt.
    async fn verify(&self, digest: &Digest) -> Result<bool>;
}

/// Helper error for stores that cannot satisfy a request.
#[allow(dead_code)]
pub fn not_found(digest: &Digest, operation: &str) -> RustFunError {
    RustFunError::not_found(format!("artifact {digest} not found")).with_context(
        ErrorContext::new()
            .operation(operation)
            .detail("digest", digest.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Default)]
    struct InMemoryStore {
        builds: MutexCount,
    }

    struct MutexCount(std::sync::Mutex<u32>);

    impl Default for MutexCount {
        fn default() -> Self {
            MutexCount(std::sync::Mutex::new(0))
        }
    }

    #[async_trait]
    impl ArtifactStore for InMemoryStore {
        async fn build(&self, _request: BuildRequest) -> Result<ArtifactSummary> {
            let mut guard = self
                .builds
                .0
                .lock()
                .map_err(|_| RustFunError::internal("poisoned"))?;
            *guard += 1;
            Ok(ArtifactSummary {
                digest: Digest::sha256(b"artifact"),
                size_bytes: 7,
                file_count: 1,
                created_at: 0,
            })
        }

        async fn metadata(&self, digest: &Digest) -> Result<Option<ArtifactSummary>> {
            Ok(Some(ArtifactSummary {
                digest: digest.clone(),
                size_bytes: 7,
                file_count: 1,
                created_at: 0,
            }))
        }

        async fn contains(&self, _digest: &Digest) -> Result<bool> {
            Ok(true)
        }

        async fn extract(&self, digest: &Digest, destination: &std::path::Path) -> Result<PathBuf> {
            Ok(destination.join(digest.hex()))
        }

        async fn remove(&self, _digest: &Digest) -> Result<()> {
            Ok(())
        }

        async fn size_bytes(&self) -> Result<u64> {
            Ok(7)
        }

        async fn evict(&self, _max_age: Duration) -> Result<usize> {
            Ok(0)
        }

        async fn verify(&self, _digest: &Digest) -> Result<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn store_trait_is_object_safe_and_usable() {
        let store: Arc<dyn ArtifactStore> = Arc::new(InMemoryStore::default());
        let summary = store
            .build(BuildRequest::new(
                FunctionId::new(),
                Arc::new(FunctionSpec::new(
                    rustfun_model::FunctionName::new("hello").expect("valid"),
                    rustfun_model::RuntimeId::parse("node@24").expect("valid"),
                    rustfun_model::HandlerSpec::parse("index.handler").expect("valid"),
                )),
                PathBuf::from("/tmp"),
            ))
            .await
            .expect("builds");
        assert_eq!(summary.file_count, 1);
        assert!(store.contains(&summary.digest).await.expect("contains"));
        let dest = std::path::Path::new("/tmp/extract");
        let path = store
            .extract(&summary.digest, dest)
            .await
            .expect("extracts");
        assert!(path.starts_with(dest));
    }

    #[test]
    fn not_found_error_has_context() {
        let digest = Digest::sha256(b"missing");
        let err = not_found(&digest, "extract");
        assert_eq!(err.category(), crate::ErrorCategory::NotFound);
        assert_eq!(
            err.context().details.get("digest").map(String::as_str),
            Some(digest.to_string().as_str())
        );
    }
}
