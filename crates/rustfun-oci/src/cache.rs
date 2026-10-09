//! Content-addressed cache for OCI blobs.
//!
//! Blobs live under `<root>/blobs/sha256/<hex>`, keyed by the digest the manifest advertised. A
//! cached blob is verified before it is returned, so a corrupted file is re-fetched rather than
//! trusted — a cache that trusts its contents is just a slower registry.

use std::path::{Path, PathBuf};

use crate::digest::Digest;
use crate::{OciError, OciResult};

/// A content-addressed blob cache.
#[derive(Debug, Clone)]
pub struct OciImageCache {
    root: PathBuf,
}

impl OciImageCache {
    /// Open (creating if necessary) a cache under `root`.
    pub fn open(root: impl Into<PathBuf>) -> OciResult<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join("blobs")).map_err(|error| {
            OciError::new(
                "open_cache",
                format!("cannot create {}: {error}", root.display()),
            )
        })?;
        Ok(Self { root })
    }

    /// The cache root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where a blob with this digest lives.
    pub fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.root
            .join("blobs")
            .join(&digest.algorithm)
            .join(&digest.hex)
    }

    /// Whether a verified blob is already cached.
    pub fn contains(&self, digest: &Digest) -> bool {
        let path = self.blob_path(digest);
        match std::fs::read(&path) {
            Ok(bytes) => digest.verify(&bytes),
            Err(_) => false,
        }
    }

    /// Read a cached blob, verifying it first.
    pub fn read(&self, digest: &Digest) -> OciResult<Vec<u8>> {
        let path = self.blob_path(digest);
        let bytes = std::fs::read(&path).map_err(|error| {
            OciError::new(
                "read_cache",
                format!("cannot read {}: {error}", path.display()),
            )
        })?;
        if !digest.verify(&bytes) {
            // A corrupted cached blob is worse than a missing one: it would be served as valid
            // content. Remove it so the caller re-fetches.
            let _ = std::fs::remove_file(&path);
            return Err(OciError::new(
                "read_cache",
                format!("the cached blob for {digest} does not match its digest and was removed"),
            ));
        }
        Ok(bytes)
    }

    /// Write a blob into the cache.
    ///
    /// The caller must have verified `bytes` against `digest`; this method refuses to write
    /// anything else so a cache entry can never exist without a matching digest.
    pub fn write(&self, digest: &Digest, bytes: &[u8]) -> OciResult<PathBuf> {
        if !digest.verify(bytes) {
            return Err(OciError::new(
                "write_cache",
                format!("refusing to cache {digest} because the bytes do not match"),
            ));
        }
        let path = self.blob_path(digest);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                OciError::new(
                    "write_cache",
                    format!("cannot create {}: {error}", parent.display()),
                )
            })?;
        }
        // Write to a temporary name and rename, so a concurrent reader never sees a partial blob.
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, bytes).map_err(|error| {
            OciError::new(
                "write_cache",
                format!("cannot write {}: {error}", temporary.display()),
            )
        })?;
        std::fs::rename(&temporary, &path).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            OciError::new(
                "write_cache",
                format!("cannot move {}: {error}", path.display()),
            )
        })?;
        Ok(path)
    }

    /// Fetch a blob, using the cache when it holds a verified copy.
    pub async fn get(&self, client: &crate::RegistryClient, digest: &Digest) -> OciResult<Vec<u8>> {
        if let Ok(bytes) = self.read(digest) {
            return Ok(bytes);
        }
        let bytes = client.fetch_blob(digest).await?;
        // Cache write is best effort: a read-only cache directory must not break a pull.
        if let Err(error) = self.write(digest, &bytes) {
            tracing::debug!(digest = %digest, error = %error, "the blob was not cached");
        }
        Ok(bytes)
    }

    /// Total bytes held by the cache.
    pub fn size_bytes(&self) -> u64 {
        let blobs = self.root.join("blobs");
        let mut total = 0;
        let Ok(entries) = std::fs::read_dir(&blobs) else {
            return 0;
        };
        for algorithm in entries.flatten() {
            let Ok(blobs) = std::fs::read_dir(algorithm.path()) else {
                continue;
            };
            for blob in blobs.flatten() {
                if let Ok(metadata) = blob.metadata() {
                    total += metadata.len();
                }
            }
        }
        total
    }

    /// Remove every cached blob, keeping the directory itself.
    pub fn clear(&self) -> OciResult<u64> {
        let mut removed = 0;
        let blobs = self.root.join("blobs");
        let Ok(entries) = std::fs::read_dir(&blobs) else {
            return Ok(0);
        };
        for algorithm in entries.flatten() {
            let Ok(inner) = std::fs::read_dir(algorithm.path()) else {
                continue;
            };
            for blob in inner.flatten() {
                if std::fs::remove_file(blob.path()).is_ok() {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(label: &str) -> OciImageCache {
        let root = std::env::temp_dir().join(format!(
            "rustfun-oci-cache-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        OciImageCache::open(&root).expect("opens cache")
    }

    #[test]
    fn a_blob_round_trips_through_the_cache() {
        let cache = cache("roundtrip");
        let digest = Digest::of(b"layer bytes");
        assert!(!cache.contains(&digest));
        cache.write(&digest, b"layer bytes").expect("writes");
        assert!(cache.contains(&digest));
        assert_eq!(cache.read(&digest).expect("reads"), b"layer bytes");
        assert!(cache.size_bytes() >= 11);
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn writing_bytes_that_do_not_match_the_digest_is_refused() {
        let cache = cache("mismatch");
        let digest = Digest::of(b"expected");
        let error = cache
            .write(&digest, b"unexpected")
            .expect_err("must refuse");
        assert!(error.to_string().contains("do not match"));
        assert!(!cache.contains(&digest));
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn a_corrupted_cached_blob_is_removed_and_reported() {
        let cache = cache("corrupt");
        let digest = Digest::of(b"good");
        cache.write(&digest, b"good").expect("writes");
        // Corrupt the file behind the cache's back.
        let path = cache.blob_path(&digest);
        std::fs::write(&path, b"bad").expect("corrupts");
        let error = cache.read(&digest).expect_err("must refuse");
        assert!(error.to_string().contains("does not match"));
        assert!(!path.exists(), "the corrupted blob must be removed");
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn clear_removes_every_blob() {
        let cache = cache("clear");
        for index in 0..3 {
            let digest = Digest::of(format!("blob{index}").as_bytes());
            cache
                .write(&digest, format!("blob{index}").as_bytes())
                .expect("writes");
        }
        assert_eq!(cache.clear().expect("clears"), 3);
        assert_eq!(cache.size_bytes(), 0);
        let _ = std::fs::remove_dir_all(cache.root());
    }

    #[test]
    fn a_missing_blob_is_an_error_naming_the_digest() {
        let cache = cache("missing");
        let digest = Digest::of(b"absent");
        let error = cache.read(&digest).expect_err("must fail");
        assert!(error.to_string().contains("cannot read"));
        let _ = std::fs::remove_dir_all(cache.root());
    }
}
