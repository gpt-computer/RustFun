//! Root filesystem assembly from OCI layers.
//!
//! Layers are extracted in manifest order into a single directory. Extraction is where a malicious
//! image can attack the host, so it is deliberately strict:
//!
//! - **Path traversal is rejected.** A member whose path escapes the target directory —
//!   `../../etc/passwd`, an absolute path, or a symlink pointing outside — aborts the extraction.
//! - **OCI whiteouts are honoured.** A `.wh.<name>` file deletes `<name>` from the result, and
//!   `.wh..wh..opq` clears opaque directories, so a lower layer cannot be resurrected.
//! - **Only regular files, directories, and symlinks are extracted.** Device nodes, fifos, and
//!   hard links are refused: a container image must not be able to create a device.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::{OciError, OciResult};

/// Maximum size of a single extracted file (1 GiB).
///
/// A layer is attacker-controlled, so an unbounded file is a disk-exhaustion attack. The ceiling
/// is generous for real images and small enough to matter.
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

/// A root filesystem under construction.
#[derive(Debug)]
pub struct RootfsBuilder {
    root: PathBuf,
}

impl RootfsBuilder {
    /// Create a builder that assembles a root at `root`.
    pub fn new(root: impl Into<PathBuf>) -> OciResult<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|error| {
            OciError::new(
                "create_rootfs",
                format!("cannot create {}: {error}", root.display()),
            )
        })?;
        Ok(Self { root })
    }

    /// The directory being assembled.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Extract a layer (tar or tar+gzip) into the root.
    pub fn extract_layer(&self, bytes: &[u8], media_type: &str) -> OciResult<()> {
        let reader: Box<dyn Read> = if media_type.ends_with("gzip") {
            Box::new(flate2::read::GzDecoder::new(bytes))
        } else {
            Box::new(bytes)
        };
        let mut archive = tar::Archive::new(reader);
        archive.set_preserve_permissions(false);
        archive.set_unpack_xattrs(false);
        archive.set_overwrite(true);

        for entry in archive.entries().map_err(|error| {
            OciError::new("extract_layer", "the layer is not a valid tar archive")
                .with_source(error)
        })? {
            let mut entry = entry.map_err(|error| {
                OciError::new("extract_layer", "a layer entry could not be read").with_source(error)
            })?;
            let path = entry.path().map_err(|error| {
                OciError::new("extract_layer", "a layer entry has an invalid path")
                    .with_source(error)
            })?;
            let path = path.into_owned();
            if is_whiteout(&path) {
                self.apply_whiteout(&path)?;
                continue;
            }
            let target = self.safe_target(&path)?;
            match entry.header().entry_type() {
                tar::EntryType::Regular => {
                    self.extract_file(&mut entry, &target)?;
                }
                tar::EntryType::Directory => {
                    std::fs::create_dir_all(&target).map_err(|error| {
                        OciError::new(
                            "extract_layer",
                            format!("cannot create {}: {error}", target.display()),
                        )
                    })?;
                }
                tar::EntryType::Symlink => {
                    let link = entry
                        .link_name()
                        .map_err(|error| {
                            OciError::new(
                                "extract_layer",
                                format!(
                                    "cannot read a symlink target in {}: {error}",
                                    path.display()
                                ),
                            )
                        })?
                        .ok_or_else(|| {
                            OciError::new(
                                "extract_layer",
                                format!("the symlink {path:?} has no target"),
                            )
                        })?;
                    // The link must stay inside the root.
                    let resolved = self.inside_root(&target, &link)?;
                    if let Some(parent) = resolved.parent() {
                        std::fs::create_dir_all(parent).map_err(|error| {
                            OciError::new(
                                "extract_layer",
                                format!("cannot create {}: {error}", parent.display()),
                            )
                        })?;
                    }
                    // Replace any existing entry (a later layer may re-point the link).
                    let _ = std::fs::remove_file(&resolved);
                    std::os::unix::fs::symlink(&link, &resolved).map_err(|error| {
                        OciError::new(
                            "extract_layer",
                            format!("cannot create the symlink {}: {error}", resolved.display()),
                        )
                    })?;
                }
                other => {
                    return Err(OciError::new(
                        "extract_layer",
                        format!("the layer contains {other:?}, which RustFun does not extract"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Extract a regular file, enforcing the size ceiling.
    fn extract_file(&self, entry: &mut tar::Entry<'_, impl Read>, target: &Path) -> OciResult<()> {
        let declared = entry.header().size().unwrap_or(0);
        if declared > MAX_FILE_BYTES {
            return Err(OciError::new(
                "extract_layer",
                format!(
                    "a layer file declares {declared} bytes, above the {MAX_FILE_BYTES}-byte limit"
                ),
            ));
        }
        let mut bytes = Vec::with_capacity(declared.min(1024 * 1024) as usize);
        let mut limited = entry.by_ref().take(MAX_FILE_BYTES + 1);
        limited.read_to_end(&mut bytes).map_err(|error| {
            OciError::new(
                "extract_layer",
                format!("cannot read {}: {error}", target.display()),
            )
        })?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(OciError::new(
                "extract_layer",
                format!("a layer file exceeds the {MAX_FILE_BYTES}-byte limit"),
            ));
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                OciError::new(
                    "extract_layer",
                    format!("cannot create {}: {error}", parent.display()),
                )
            })?;
        }
        std::fs::write(target, &bytes).map_err(|error| {
            OciError::new(
                "extract_layer",
                format!("cannot write {}: {error}", target.display()),
            )
        })?;
        Ok(())
    }

    /// Resolve a layer member path inside the root, refusing anything that escapes.
    fn safe_target(&self, member: &Path) -> OciResult<PathBuf> {
        let mut target = self.root.clone();
        for component in member.components() {
            match component {
                Component::Normal(part) => {
                    // A normal component that is not a valid filename cannot exist inside the root.
                    if part.is_empty() || part == "." || part == ".." {
                        return Err(OciError::new(
                            "extract_layer",
                            format!("the layer member {member:?} is not a usable path"),
                        ));
                    }
                    target.push(part);
                }
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(OciError::new(
                        "extract_layer",
                        format!("the layer member {member:?} escapes the root filesystem"),
                    ));
                }
            }
        }
        Ok(target)
    }

    /// Whether `link`, resolved from `target`, stays inside the root.
    fn inside_root(&self, target: &Path, link: &Path) -> OciResult<std::path::PathBuf> {
        let mut resolved = target
            .parent()
            .map_or_else(|| self.root.clone(), Path::to_path_buf);
        for component in Path::new(link).components() {
            match component {
                Component::Normal(part) => resolved.push(part),
                Component::CurDir => {}
                Component::ParentDir => {
                    if !resolved.pop() {
                        return Err(OciError::new(
                            "extract_layer",
                            format!("the symlink {link:?} escapes the root filesystem"),
                        ));
                    }
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(OciError::new(
                        "extract_layer",
                        format!("the symlink {link:?} escapes the root filesystem"),
                    ));
                }
            }
        }
        Ok(resolved)
    }

    /// Apply an OCI whiteout.
    ///
    /// `.wh.<name>` deletes `<name>` from the assembled filesystem; `.wh..wh..opq` marks its
    /// directory opaque, so nothing from a lower layer may remain visible there.
    fn apply_whiteout(&self, member: &Path) -> OciResult<()> {
        let file = member
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                OciError::new(
                    "extract_layer",
                    format!("the whiteout {member:?} is malformed"),
                )
            })?;
        let parent = member.parent().ok_or_else(|| {
            OciError::new(
                "extract_layer",
                format!("the whiteout {member:?} has no parent"),
            )
        })?;
        let directory = self.safe_target(parent)?;
        if file == ".wh..wh..opq" {
            let entries = std::fs::read_dir(&directory).map_err(|error| {
                OciError::new(
                    "extract_layer",
                    format!("cannot clear {}: {error}", directory.display()),
                )
            })?;
            for entry in entries.flatten() {
                let path = entry.path();
                let metadata = entry.metadata().map_err(|error| {
                    OciError::new(
                        "extract_layer",
                        format!("cannot inspect {}: {error}", path.display()),
                    )
                })?;
                let result = if metadata.is_dir() {
                    std::fs::remove_dir_all(&path)
                } else {
                    std::fs::remove_file(&path)
                };
                result.map_err(|error| {
                    OciError::new(
                        "extract_layer",
                        format!("cannot clear {}: {error}", path.display()),
                    )
                })?;
            }
            return Ok(());
        }
        let name = file.strip_prefix(".wh.").ok_or_else(|| {
            OciError::new(
                "extract_layer",
                format!("the whiteout {member:?} is malformed"),
            )
        })?;
        let removed = directory.join(name);
        if removed.exists() {
            let metadata = std::fs::symlink_metadata(&removed).map_err(|error| {
                OciError::new(
                    "extract_layer",
                    format!("cannot inspect {}: {error}", removed.display()),
                )
            })?;
            let result = if metadata.is_dir() {
                std::fs::remove_dir_all(&removed)
            } else {
                std::fs::remove_file(&removed)
            };
            result.map_err(|error| {
                OciError::new(
                    "extract_layer",
                    format!("cannot remove {}: {error}", removed.display()),
                )
            })?;
        }
        Ok(())
    }
}

/// Whether a path is an OCI whiteout file.
fn is_whiteout(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == ".wh..wh..opq" || name.starts_with(".wh."))
}

/// Build a root filesystem from already-extracted layer bytes.
pub fn assemble(root: impl Into<PathBuf>, layers: &[(String, Vec<u8>)]) -> OciResult<PathBuf> {
    let builder = RootfsBuilder::new(root)?;
    for (media_type, bytes) in layers {
        builder.extract_layer(bytes, media_type)?;
    }
    Ok(builder.root().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tar (optionally gzipped) from `members`: `(path, contents)`.
    fn tar(members: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, contents) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, *path, contents.as_bytes())
                .expect("appends");
        }
        builder.into_inner().expect("tar bytes")
    }

    /// Build a raw ustar tar containing `members`, bypassing the builder's path checks.
    ///
    /// The `tar` crate refuses to *write* a `..` or absolute path, which is exactly the input the
    /// extractor must defend against, so those archives are assembled by hand.
    fn raw_tar(members: &[(&str, &str)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (path, contents) in members {
            let mut header = [0u8; 512];
            let name = path.as_bytes();
            header[..name.len()].copy_from_slice(name);
            header[100..108].copy_from_slice(b"0000644\0");
            header[108..116].copy_from_slice(b"0000000\0");
            header[116..124].copy_from_slice(b"0000000\0");
            header[124..136].copy_from_slice(format!("{:011o}\0", contents.len()).as_bytes());
            header[136..148].copy_from_slice(b"00000000000\0");
            header[148..156].copy_from_slice(b"        ");
            header[156] = b'0';
            header[257..262].copy_from_slice(b"ustar");
            header[263..265].copy_from_slice(b"00");
            let checksum: u32 = header.iter().map(|b| u32::from(*b)).sum();
            header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
            bytes.extend_from_slice(&header);
            bytes.extend_from_slice(contents.as_bytes());
            let padding = (512 - contents.len() % 512) % 512;
            bytes.extend(std::iter::repeat_n(0u8, padding));
        }
        // Two empty blocks terminate a tar archive.
        bytes.extend(std::iter::repeat_n(0u8, 1024));
        bytes
    }

    fn root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "rustfun-oci-rootfs-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).expect("creates root");
        root
    }

    #[test]
    fn layers_extract_in_order() {
        let root = root("order");
        let builder = RootfsBuilder::new(&root).expect("builder");
        builder
            .extract_layer(
                &tar(&[("app/index.js", "one\n")]),
                crate::media_types::LAYER_TAR,
            )
            .expect("layer one");
        builder
            .extract_layer(
                &tar(&[("app/index.js", "two\n"), ("app/data.txt", "d\n")]),
                crate::media_types::LAYER_TAR,
            )
            .expect("layer two");
        assert_eq!(
            std::fs::read_to_string(root.join("app/index.js")).expect("reads"),
            "two\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("app/data.txt")).expect("reads"),
            "d\n"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_gzipped_layer_extracts() {
        let root = root("gzip");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        use std::io::Write;
        encoder
            .write_all(&tar(&[("bin/sh", "#!/bin/sh\n")]))
            .expect("compresses");
        let bytes = encoder.finish().expect("compressed bytes");
        RootfsBuilder::new(&root)
            .expect("builder")
            .extract_layer(&bytes, crate::media_types::LAYER_GZIP)
            .expect("extracts");
        assert_eq!(
            std::fs::read_to_string(root.join("bin/sh")).expect("reads"),
            "#!/bin/sh\n"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_path_traversal_member_is_refused() {
        let root = root("traversal");
        let layer = raw_tar(&[("../../etc/evil", "pwned\n")]);
        let error = RootfsBuilder::new(&root)
            .expect("builder")
            .extract_layer(&layer, crate::media_types::LAYER_TAR)
            .expect_err("must refuse");
        assert!(error.to_string().contains("escapes"), "{error}");
        assert!(!std::path::Path::new("/etc/evil").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_absolute_path_member_is_refused() {
        let root = root("absolute");
        let layer = raw_tar(&[("/etc/evil", "pwned\n")]);
        let error = RootfsBuilder::new(&root)
            .expect("builder")
            .extract_layer(&layer, crate::media_types::LAYER_TAR)
            .expect_err("must refuse");
        assert!(error.to_string().contains("escapes"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_whiteout_removes_a_file_from_a_lower_layer() {
        let root = root("whiteout");
        let builder = RootfsBuilder::new(&root).expect("builder");
        builder
            .extract_layer(
                &tar(&[("app/index.js", "old\n")]),
                crate::media_types::LAYER_TAR,
            )
            .expect("layer one");
        builder
            .extract_layer(
                &tar(&[("app/.wh.index.js", "")]),
                crate::media_types::LAYER_TAR,
            )
            .expect("layer two");
        assert!(
            !root.join("app/index.js").exists(),
            "the whiteout must remove the file"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_opaque_marker_clears_a_directory() {
        let root = root("opaque");
        let builder = RootfsBuilder::new(&root).expect("builder");
        builder
            .extract_layer(
                &tar(&[("app/keep.js", "k\n"), ("app/drop.js", "d\n")]),
                crate::media_types::LAYER_TAR,
            )
            .expect("layer one");
        builder
            .extract_layer(
                &tar(&[("app/.wh..wh..opq", "")]),
                crate::media_types::LAYER_TAR,
            )
            .expect("layer two");
        assert!(!root.join("app/keep.js").exists());
        assert!(!root.join("app/drop.js").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlink_escaping_the_root_is_refused() {
        let root = root("symlink");
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        builder
            .append_link(&mut header, "app/evil", "/etc/passwd")
            .expect("appends");
        let bytes = builder.into_inner().expect("tar bytes");
        let error = RootfsBuilder::new(&root)
            .expect("builder")
            .extract_layer(&bytes, crate::media_types::LAYER_TAR)
            .expect_err("must refuse");
        assert!(error.to_string().contains("escapes"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_device_node_is_refused() {
        let root = root("device");
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Block);
        header.set_device_major(0).expect("major");
        header.set_device_minor(0).expect("minor");
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "dev/null", &mut std::io::empty())
            .expect("appends");
        let bytes = builder.into_inner().expect("tar bytes");
        let error = RootfsBuilder::new(&root)
            .expect("builder")
            .extract_layer(&bytes, crate::media_types::LAYER_TAR)
            .expect_err("must refuse");
        assert!(error.to_string().contains("does not extract"), "{error}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn assemble_builds_a_root_from_layers() {
        let root = root("assemble");
        let layers = vec![
            (
                crate::media_types::LAYER_TAR.to_owned(),
                tar(&[("a.txt", "a\n")]),
            ),
            (
                crate::media_types::LAYER_TAR.to_owned(),
                tar(&[("b.txt", "b\n")]),
            ),
        ];
        let built = assemble(&root, &layers).expect("assembles");
        assert_eq!(built, root);
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).expect("reads"),
            "a\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("b.txt")).expect("reads"),
            "b\n"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
