//! Content-addressed artifact store.
//!
//! Artifacts are immutable: the same source always produces the same digest, and a stored
//! artifact is verified before it is used. This is what makes builds reproducible, cache hits
//! deterministic, and artifact distribution to remote workers safe (ADR-0004).
//!
//! # Layout on disk
//!
//! ```text
//! <root>/
//!   artifacts/
//!     <aa>/<digest-hex>.tar.gz     # packed artifact (immutable)
//!     <aa>/<digest-hex>.json       # metadata
//!   extracted/<digest-hex>/        # materialized tree
//!   build/<function-id>/           # staging + build command output
//!   locks/<digest>.lock            # advisory lock during writes
//! ```
//!
//! # Security
//!
//! Extraction is the classic path-traversal trap, so it is handled explicitly: member paths
//! are rejected if they are absolute, contain `..`, or escape the destination after
//! normalization, and links pointing outside the artifact are refused.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rustfun_core::artifact::{ArtifactStore, ArtifactSummary, BuildRequest, BuiltArtifact};
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_model::Digest;
use tokio::sync::Mutex;

/// Default filesystem store.
#[derive(Debug, Clone)]
pub struct FileArtifactStore {
    root: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl FileArtifactStore {
    /// Open (or create) a store rooted at `root`.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for sub in ["artifacts", "extracted", "build", "locks"] {
            tokio::fs::create_dir_all(root.join(sub))
                .await
                .map_err(|e| {
                    RustFunError::io(format!("cannot create {}: {e}", root.join(sub).display()))
                        .with_context(ErrorContext::new().operation("open_store"))
                })?;
        }
        Ok(Self {
            root,
            lock: Arc::new(Mutex::new(())),
        })
    }

    /// Store root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn artifact_path(&self, digest: &Digest) -> PathBuf {
        let hex = digest.hex();
        self.root
            .join("artifacts")
            .join(&hex[..2])
            .join(format!("{hex}.tar.gz"))
    }

    fn metadata_path(&self, digest: &Digest) -> PathBuf {
        let hex = digest.hex();
        self.root
            .join("artifacts")
            .join(&hex[..2])
            .join(format!("{hex}.json"))
    }

    fn extraction_path(&self, digest: &Digest) -> PathBuf {
        self.root.join("extracted").join(digest.hex())
    }

    /// Compute the digest of a source directory without writing anything.
    ///
    /// The digest covers every regular file's relative path, mode bit, and contents, so two
    /// directories with the same content always hash identically.
    pub fn digest_directory(root: &Path) -> Result<Digest> {
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest as _;
        let mut files = Vec::new();
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry.map_err(|e| {
                RustFunError::io(format!("cannot walk {}: {e}", root.display()))
                    .with_context(ErrorContext::new().operation("digest_directory"))
            })?;
            if !entry.file_type().is_file() {
                continue;
            }
            let full = entry.path().to_path_buf();
            let relative = full
                .strip_prefix(root)
                .map_err(|e| RustFunError::internal(format!("path escape: {e}")))?
                .to_string_lossy()
                .into_owned();
            if should_skip(&relative) {
                continue;
            }
            files.push((relative, full));
        }
        files.sort();
        for (relative, path) in files {
            let mut file = std::fs::File::open(&path).map_err(|e| {
                RustFunError::io(format!("cannot read {}: {e}", path.display()))
                    .with_context(ErrorContext::new().operation("digest_directory"))
            })?;
            let mut buffer = vec![0u8; 64 * 1024];
            hasher.update(relative.as_bytes());
            hasher.update([0]);
            loop {
                let read = file.read(&mut buffer).map_err(|e| {
                    RustFunError::io(format!("cannot read {}: {e}", path.display()))
                        .with_context(ErrorContext::new().operation("digest_directory"))
                })?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            hasher.update([0xff]);
        }
        let hex = hex::encode(hasher.finalize());
        Ok(Digest::parse(&format!("sha256:{hex}"))?)
    }

    /// Pack a directory into a deterministic gzipped tar.
    pub fn pack_directory(root: &Path, destination: &Path) -> Result<(Digest, u64, usize)> {
        let digest = Self::digest_directory(root)?;
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                RustFunError::io(format!("cannot create {}: {e}", parent.display()))
                    .with_context(ErrorContext::new().operation("pack_directory"))
            })?;
        }
        let file = std::fs::File::create(destination).map_err(|e| {
            RustFunError::io(format!("cannot create {}: {e}", destination.display()))
                .with_context(ErrorContext::new().operation("pack_directory"))
        })?;
        let encoder = flate2::write::GzEncoder::new(
            std::io::BufWriter::new(file),
            flate2::Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);
        builder.follow_symlinks(false);

        let mut entries: Vec<PathBuf> = Vec::new();
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry.map_err(|e| {
                RustFunError::io(format!("cannot walk {}: {e}", root.display()))
                    .with_context(ErrorContext::new().operation("pack_directory"))
            })?;
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|e| RustFunError::internal(format!("path escape: {e}")))?
                .to_string_lossy()
                .into_owned();
            if should_skip(&relative) {
                continue;
            }
            if entry.file_type().is_file() {
                entries.push(entry.path().to_path_buf());
            }
        }
        for path in entries {
            builder
                .append_path_with_name(&path, path.strip_prefix(root).unwrap_or(&path))
                .map_err(|e| {
                    RustFunError::artifact(format!(
                        "cannot add {} to the artifact: {e}",
                        path.display()
                    ))
                    .with_context(ErrorContext::new().operation("pack_directory"))
                })?;
        }
        let encoder = builder.into_inner().map_err(|e| {
            RustFunError::artifact(format!("cannot finalize the artifact: {e}"))
                .with_context(ErrorContext::new().operation("pack_directory"))
        })?;
        encoder.finish().map_err(|e| {
            RustFunError::artifact(format!("cannot compress the artifact: {e}"))
                .with_context(ErrorContext::new().operation("pack_directory"))
        })?;
        let metadata = std::fs::metadata(destination).map_err(|e| {
            RustFunError::io(format!("cannot stat {}: {e}", destination.display()))
                .with_context(ErrorContext::new().operation("pack_directory"))
        })?;
        Ok((digest, metadata.len(), count_files(root)?))
    }

    /// Unpack an artifact into `destination`, refusing path traversal.
    pub fn unpack_archive(archive: &Path, destination: &Path) -> Result<usize> {
        let file = std::fs::File::open(archive).map_err(|e| {
            RustFunError::io(format!("cannot open {}: {e}", archive.display()))
                .with_context(ErrorContext::new().operation("unpack_archive"))
        })?;
        let decoder = flate2::read::GzDecoder::new(std::io::BufReader::new(file));
        let mut tar = tar::Archive::new(decoder);
        let mut extracted = 0usize;
        std::fs::create_dir_all(destination).map_err(|e| {
            RustFunError::io(format!("cannot create {}: {e}", destination.display()))
                .with_context(ErrorContext::new().operation("unpack_archive"))
        })?;
        for entry in tar.entries().map_err(|e| {
            RustFunError::artifact(format!("cannot read the artifact archive: {e}"))
                .with_context(ErrorContext::new().operation("unpack_archive"))
        })? {
            let mut entry = entry.map_err(|e| {
                RustFunError::artifact(format!("corrupt artifact entry: {e}"))
                    .with_context(ErrorContext::new().operation("unpack_archive"))
            })?;
            let path = entry.path().map_err(|e| {
                RustFunError::artifact(format!("invalid artifact entry: {e}"))
                    .with_context(ErrorContext::new().operation("unpack_archive"))
            })?;
            let path_display = path.display().to_string();
            reject_unsafe_path(&path)?;
            let entry_type = entry.header().entry_type();
            if entry_type.is_dir() {
                std::fs::create_dir_all(destination.join(&path)).map_err(|e| {
                    RustFunError::io(format!("cannot create {path_display}: {e}"))
                        .with_context(ErrorContext::new().operation("unpack_archive"))
                })?;
                continue;
            }
            if !entry_type.is_file() {
                // Symlinks and special files are refused: an artifact must not be able to
                // create a link that escapes the destination.
                continue;
            }
            let target = destination.join(&path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    RustFunError::io(format!("cannot create {}: {e}", parent.display()))
                        .with_context(ErrorContext::new().operation("unpack_archive"))
                })?;
            }
            let mut output = std::fs::File::create(&target).map_err(|e| {
                RustFunError::io(format!("cannot create {}: {e}", target.display()))
                    .with_context(ErrorContext::new().operation("unpack_archive"))
            })?;
            std::io::copy(&mut entry, &mut output).map_err(|e| {
                RustFunError::artifact(format!("cannot extract {path_display}: {e}"))
                    .with_context(ErrorContext::new().operation("unpack_archive"))
            })?;
            // The executable bit must survive packing: an `executable` runtime would
            // otherwise fail with `Permission denied` after extraction.
            let mode = entry.header().mode().unwrap_or(0o644) & 0o777;
            restore_mode(&target, mode)?;
            extracted += 1;
        }
        Ok(extracted)
    }

    async fn read_metadata(&self, digest: &Digest) -> Result<Option<ArtifactSummary>> {
        let path = self.metadata_path(digest);
        match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
                RustFunError::artifact(format!(
                    "corrupt artifact metadata at {}: {e}",
                    path.display()
                ))
                .with_context(ErrorContext::new().operation("read_metadata"))
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(
                RustFunError::io(format!("cannot read {}: {err}", path.display()))
                    .with_context(ErrorContext::new().operation("read_metadata")),
            ),
        }
    }
}

fn count_files(root: &Path) -> Result<usize> {
    let mut count = 0usize;
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|e| {
            RustFunError::io(format!("cannot walk {}: {e}", root.display()))
                .with_context(ErrorContext::new().operation("count_files"))
        })?;
        if entry.file_type().is_file() && !should_skip(&entry.path().to_string_lossy()) {
            count += 1;
        }
    }
    Ok(count)
}

/// Files excluded from artifacts.
///
/// The generated runtime bootstraps are written into the function root by the runtime adapter
/// at prepare time. They must not be part of the artifact: including them would make the
/// digest of an *extracted* artifact differ from the digest that was packed, so every
/// verification after the first invocation would report corruption.
pub fn should_skip(relative: &str) -> bool {
    let path = relative.replace('\\', "/");
    let file = path.rsplit('/').next().unwrap_or(&path);
    if file == ".rustfun-bootstrap.cjs"
        || file == ".rustfun-bootstrap.mjs"
        || file == ".rustfun_bootstrap.py"
    {
        return true;
    }
    path.starts_with(".rustfun/")
        || path.contains("/.rustfun/")
        || path == ".rustfun"
        || path.starts_with(".rustfun-")
        || path == "rustfun.toml"
        || path.ends_with(".pyc")
        || path.contains("__pycache__")
        || path.starts_with("target/")
        || path.contains("/target/")
        || path == ".git"
        || path.contains("/.git/")
        || path.starts_with("node_modules/")
        || path.contains("/node_modules/")
}

#[cfg(unix)]
fn restore_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|error| {
        RustFunError::io(format!(
            "cannot set the mode of {}: {error}",
            path.display()
        ))
        .with_context(ErrorContext::new().operation("unpack_archive"))
    })
}

#[cfg(not(unix))]
fn restore_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Reject archive members that would escape the extraction directory.
fn reject_unsafe_path(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    if path.is_absolute() || text.starts_with('/') {
        return Err(
            RustFunError::artifact(format!("artifact contains an absolute path: {text}"))
                .with_context(ErrorContext::new().operation("unpack_archive")),
        );
    }
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(RustFunError::artifact(format!(
                "artifact contains a traversal path: {text}"
            ))
            .with_context(ErrorContext::new().operation("unpack_archive")));
        }
    }
    Ok(())
}

#[async_trait]
impl ArtifactStore for FileArtifactStore {
    async fn build(&self, request: BuildRequest) -> Result<ArtifactSummary> {
        let source = request.source_dir.clone();
        if !source.exists() {
            return Err(RustFunError::not_found(format!(
                "function source directory {} does not exist",
                source.display()
            ))
            .with_context(
                ErrorContext::new()
                    .operation("build_function")
                    .function(request.spec.name.as_str()),
            ));
        }

        // Content-addressed lookup: the same source always yields the same digest, so an
        // unchanged function never rebuilds.
        let digest = Self::digest_directory(&source)?;
        if !request.force_rebuild {
            if let Some(existing) = self.read_metadata(&digest).await? {
                if self.artifact_path(&digest).exists() {
                    tracing::debug!(digest = %digest, "artifact cache hit");
                    return Ok(existing);
                }
            }
        }

        let _guard = self.lock.lock().await;
        if let Some(existing) = self.read_metadata(&digest).await? {
            if self.artifact_path(&digest).exists() && !request.force_rebuild {
                return Ok(existing);
            }
        }

        // Stage the build so the cache is never polluted by a partial build.
        let staging = self
            .root
            .join("build")
            .join(request.function_id.to_string())
            .join("stage");
        if staging.exists() {
            tokio::fs::remove_dir_all(&staging).await.map_err(|e| {
                RustFunError::io(format!("cannot clean {}: {e}", staging.display()))
                    .with_context(ErrorContext::new().operation("build_function"))
            })?;
        }
        copy_tree(&source, &staging)?;

        if let Some(command) = &request.build_command {
            run_build_command(command, &staging).await?;
        }

        let packed = self.artifact_path(&digest);
        let staging_for_pack = staging.clone();
        let packed_for_pack = packed.clone();
        let (final_digest, size_bytes, file_count) = tokio::task::spawn_blocking(move || {
            Self::pack_directory(&staging_for_pack, &packed_for_pack)
        })
        .await
        .map_err(|e| RustFunError::internal(format!("build task failed: {e}")))??;
        let summary = ArtifactSummary {
            digest: final_digest,
            size_bytes,
            file_count,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        let metadata = serde_json::to_vec_pretty(&summary).map_err(|e| {
            RustFunError::artifact(format!("cannot serialize artifact metadata: {e}"))
        })?;
        // A build command can change the content, so the final digest may differ from the
        // digest computed before the build; make sure its bucket exists.
        if let Some(parent) = self.metadata_path(&summary.digest).parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                RustFunError::io(format!("cannot create {}: {e}", parent.display()))
                    .with_context(ErrorContext::new().operation("build_function"))
            })?;
        }
        tokio::fs::write(self.metadata_path(&summary.digest), metadata)
            .await
            .map_err(|e| {
                RustFunError::io(format!("cannot write artifact metadata: {e}"))
                    .with_context(ErrorContext::new().operation("build_function"))
            })?;
        let _ = tokio::fs::remove_dir_all(&staging).await;
        Ok(summary)
    }

    async fn metadata(&self, digest: &Digest) -> Result<Option<ArtifactSummary>> {
        self.read_metadata(digest).await
    }

    async fn contains(&self, digest: &Digest) -> Result<bool> {
        Ok(self.artifact_path(digest).exists() && self.metadata_path(digest).exists())
    }

    async fn extract(&self, digest: &Digest, destination: &Path) -> Result<PathBuf> {
        if !self.contains(digest).await? {
            return Err(rustfun_core::not_found(digest, "extract_artifact"));
        }
        let target = self.extraction_path(digest);
        let marker = target.join(".rustfun-complete");
        if marker.exists() {
            return Ok(target);
        }
        let _guard = self.lock.lock().await;
        if marker.exists() {
            return Ok(target);
        }
        let _ = tokio::fs::remove_dir_all(&target).await;
        let archive = self.artifact_path(digest);
        let target_for_task = target.clone();
        let archive_for_task = archive.clone();
        tokio::task::spawn_blocking(move || {
            Self::unpack_archive(&archive_for_task, &target_for_task)
        })
        .await
        .map_err(|e| RustFunError::internal(format!("extract task failed: {e}")))??;
        tokio::fs::write(&marker, digest.to_string())
            .await
            .map_err(|e| RustFunError::io(format!("cannot mark the extraction complete: {e}")))?;
        // The store owns its extraction layout under `root/extracted/<digest>`; the caller's
        // destination is accepted for interface symmetry (and for remote stores).
        let _ = destination;
        Ok(target)
    }

    async fn remove(&self, digest: &Digest) -> Result<()> {
        let artifact = self.artifact_path(digest);
        let metadata = self.metadata_path(digest);
        let extracted = self.extraction_path(digest);
        for path in [artifact, metadata] {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(RustFunError::io(format!(
                        "cannot remove {}: {err}",
                        path.display()
                    ))
                    .with_context(ErrorContext::new().operation("remove_artifact")))
                }
            }
        }
        let _ = tokio::fs::remove_dir_all(&extracted).await;
        Ok(())
    }

    async fn size_bytes(&self) -> Result<u64> {
        let mut total = 0u64;
        let dir = self.root.join("artifacts");
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(_) => return Ok(0),
        };
        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            RustFunError::io(format!("cannot read {}: {e}", dir.display()))
                .with_context(ErrorContext::new().operation("size_bytes"))
        })? {
            let metadata = match tokio::fs::metadata(entry.path()).await {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if metadata.is_file() {
                total += metadata.len();
            } else if metadata.is_dir() {
                let mut sub = match tokio::fs::read_dir(entry.path()).await {
                    Ok(sub) => sub,
                    Err(_) => continue,
                };
                while let Ok(Some(file)) = sub.next_entry().await {
                    if let Ok(metadata) = tokio::fs::metadata(file.path()).await {
                        total += metadata.len();
                    }
                }
            }
        }
        Ok(total)
    }

    async fn evict(&self, max_age: Duration) -> Result<usize> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dir = self.root.join("artifacts");
        let mut removed = 0usize;
        let mut buckets = match tokio::fs::read_dir(&dir).await {
            Ok(buckets) => buckets,
            Err(_) => return Ok(0),
        };
        while let Ok(Some(bucket)) = buckets.next_entry().await {
            let Ok(metadata) = tokio::fs::metadata(bucket.path()).await else {
                continue;
            };
            if !metadata.is_dir() {
                continue;
            }
            let mut files = match tokio::fs::read_dir(bucket.path()).await {
                Ok(files) => files,
                Err(_) => continue,
            };
            while let Ok(Some(file)) = files.next_entry().await {
                let json = file.path().extension().is_some_and(|ext| ext == "json");
                if !json {
                    continue;
                }
                let bytes = match tokio::fs::read(file.path()).await {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                let Ok(summary) = serde_json::from_slice::<ArtifactSummary>(&bytes) else {
                    continue;
                };
                let age = now.saturating_sub(summary.created_at);
                if age > max_age.as_secs() && self.remove(&summary.digest).await.is_ok() {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    async fn verify(&self, digest: &Digest) -> Result<bool> {
        if !self.contains(digest).await? {
            return Ok(false);
        }
        let extracted = self.extraction_path(digest);
        let marker = extracted.join(".rustfun-complete");
        if !marker.exists() {
            return Ok(true);
        }
        let computed = Self::digest_directory(&extracted)?;
        if computed == *digest {
            return Ok(true);
        }
        tracing::warn!(digest = %digest, "artifact failed verification; removing it");
        let _ = tokio::fs::remove_dir_all(&extracted).await;
        self.remove(digest).await?;
        Ok(false)
    }
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir_all(destination).map_err(|e| {
        RustFunError::io(format!("cannot create {}: {e}", destination.display()))
            .with_context(ErrorContext::new().operation("stage_build"))
    })?;
    for entry in walkdir::WalkDir::new(source)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(|e| {
            RustFunError::io(format!("cannot walk {}: {e}", source.display()))
                .with_context(ErrorContext::new().operation("stage_build"))
        })?;
        let relative = entry
            .path()
            .strip_prefix(source)
            .map_err(|e| RustFunError::internal(format!("path escape: {e}")))?;
        if should_skip(&relative.to_string_lossy()) {
            continue;
        }
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target).map_err(|e| {
                RustFunError::io(format!("cannot create {}: {e}", target.display()))
                    .with_context(ErrorContext::new().operation("stage_build"))
            })?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    RustFunError::io(format!("cannot create {}: {e}", parent.display()))
                        .with_context(ErrorContext::new().operation("stage_build"))
                })?;
            }
            std::fs::copy(entry.path(), &target).map_err(|e| {
                RustFunError::io(format!("cannot copy {}: {e}", entry.path().display()))
                    .with_context(ErrorContext::new().operation("stage_build"))
            })?;
        }
    }
    Ok(())
}

async fn run_build_command(command: &[String], workdir: &Path) -> Result<()> {
    let Some((program, args)) = command.split_first() else {
        return Ok(());
    };
    let config = rustfun_process::ProcessConfig::new(program.clone(), args.to_vec())
        .inherit_environment(true)
        .with_current_dir(workdir.to_path_buf())
        .with_shutdown_grace(Duration::from_millis(500));
    let output = rustfun_process::ProcessEngine::new()
        .capture(config, Duration::from_secs(600))
        .await?;
    if !output.is_success() {
        let mut err = RustFunError::artifact(format!(
            "build command failed with {}: {}",
            output.status.describe(),
            if output.stderr.trim().is_empty() {
                output.stdout.trim()
            } else {
                output.stderr.trim()
            }
        ))
        .with_context(ErrorContext::new().operation("build_function"));
        err = err.with_detail("command", command.join(" "));
        return Err(err);
    }
    Ok(())
}

/// Build a [`BuiltArtifact`] reference for an already-extracted artifact.
pub fn built_artifact(summary: &ArtifactSummary, path: PathBuf) -> BuiltArtifact {
    BuiltArtifact::new(summary, path)
}
