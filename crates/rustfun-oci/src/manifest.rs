//! OCI image manifest and config types.
//!
//! The manifest is the only thing a registry hands back for a tag: it names the config blob and
//! the layer blobs by digest. Everything else — the entrypoint, the environment, the architecture
//! — lives in the config.

use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::{OciError, OciResult};

/// A content descriptor: a blob's media type, digest, and size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    /// Media type, e.g. `application/vnd.docker.image.rootfs.diff.tar.gzip`.
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// Content digest.
    pub digest: String,
    /// Size in bytes.
    pub size: u64,
}

impl Descriptor {
    /// The parsed digest.
    pub fn parsed_digest(&self) -> OciResult<Digest> {
        Digest::parse(&self.digest).ok_or_else(|| {
            OciError::new(
                "parse_descriptor",
                format!("`{}` is not a valid digest", self.digest),
            )
        })
    }

    /// Whether this descriptor is a layer RustFun can extract.
    pub fn is_layer(&self) -> bool {
        matches!(
            self.media_type.as_str(),
            crate::media_types::LAYER_GZIP
                | crate::media_types::LAYER_TAR
                | crate::media_types::LAYER_GZIP_OCI
        )
    }

    /// Whether this descriptor is a config blob.
    pub fn is_config(&self) -> bool {
        matches!(
            self.media_type.as_str(),
            crate::media_types::CONFIG | crate::media_types::OCI_CONFIG
        )
    }
}

/// An image manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageManifest {
    /// Schema version.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    /// Manifest media type.
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    /// Config descriptor.
    pub config: Descriptor,
    /// Layer descriptors, in order.
    pub layers: Vec<Descriptor>,
}

impl ImageManifest {
    /// Parse a manifest, rejecting anything that cannot be extracted.
    pub fn parse(bytes: &[u8]) -> OciResult<Self> {
        let manifest: Self = serde_json::from_slice(bytes).map_err(|error| {
            OciError::new("parse_manifest", "the manifest is not valid JSON").with_source(error)
        })?;
        if manifest.schema_version != 2 {
            return Err(OciError::new(
                "parse_manifest",
                format!(
                    "schema version {} is not supported (expected 2)",
                    manifest.schema_version
                ),
            ));
        }
        if !manifest.config.is_config() {
            return Err(OciError::new(
                "parse_manifest",
                format!(
                    "the config media type `{}` is not an image config",
                    manifest.config.media_type
                ),
            ));
        }
        if manifest.layers.is_empty() {
            return Err(OciError::new(
                "parse_manifest",
                "the manifest has no layers",
            ));
        }
        for layer in &manifest.layers {
            if !layer.is_layer() {
                return Err(OciError::new(
                    "parse_manifest",
                    format!(
                        "layer media type `{}` is not a tar or tar+gzip layer",
                        layer.media_type
                    ),
                ));
            }
        }
        Ok(manifest)
    }

    /// The manifest's own digest, as the registry would compute it.
    pub fn digest(&self, bytes: &[u8]) -> Digest {
        Digest::of(bytes)
    }
}

/// Platform selector from a manifest list or index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Platform {
    /// Architecture, e.g. `amd64`.
    pub architecture: String,
    /// OS, e.g. `linux`.
    pub os: String,
}

/// An image config: the metadata that turns layers into a runnable root filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageConfig {
    /// Architecture the image was built for.
    #[serde(default)]
    pub architecture: String,
    /// OS the image was built for.
    #[serde(default)]
    pub os: String,
    /// Container entrypoint.
    #[serde(rename = "config", default)]
    pub config: ImageConfigContainer,
    /// Root filesystem metadata.
    #[serde(rename = "rootfs", default)]
    pub rootfs: ImageRootfs,
}

/// The `config` section of an image config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImageConfigContainer {
    /// Entrypoint.
    #[serde(rename = "Entrypoint", default)]
    pub entrypoint: Vec<String>,
    /// Command arguments.
    #[serde(rename = "Cmd", default)]
    pub cmd: Vec<String>,
    /// Environment variables.
    #[serde(rename = "Env", default)]
    pub env: Vec<String>,
    /// Working directory.
    #[serde(rename = "WorkingDir", default)]
    pub working_dir: String,
    /// User the container runs as.
    #[serde(rename = "User", default)]
    pub user: String,
}

impl ImageConfigContainer {
    /// The full command the container starts with.
    pub fn command(&self) -> Vec<String> {
        let mut command = self.entrypoint.clone();
        command.extend(self.cmd.clone());
        command
    }

    /// Whether a command is defined.
    pub fn has_command(&self) -> bool {
        !self.command().is_empty()
    }
}

/// The `rootfs` section of an image config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImageRootfs {
    /// Layer diff IDs.
    #[serde(rename = "diff_ids", default)]
    pub diff_ids: Vec<String>,
    /// Always `layers` for schema 2.
    #[serde(rename = "type", default)]
    pub layer_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "size": 7023
  },
  "layers": [
    {
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "digest": "sha256:22222222222222222222222222222222222222222222222222222222222222222",
      "size": 1024
    }
  ]
}"#;

    #[test]
    fn parses_a_manifest_and_validates_it() {
        let manifest = ImageManifest::parse(MANIFEST.as_bytes()).expect("valid manifest");
        assert_eq!(manifest.schema_version, 2);
        assert!(manifest.config.is_config());
        assert_eq!(manifest.layers.len(), 1);
        assert!(manifest.layers[0].is_layer());
        assert_eq!(manifest.layers[0].size, 1024);
    }

    #[test]
    fn rejects_a_manifest_with_no_layers() {
        let manifest = MANIFEST.replace(
            r#""layers": [
    {
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "digest": "sha256:22222222222222222222222222222222222222222222222222222222222222222",
      "size": 1024
    }
  ]"#,
            r#""layers": []"#,
        );
        let error = ImageManifest::parse(manifest.as_bytes()).expect_err("must refuse");
        assert!(error.to_string().contains("no layers"));
    }

    #[test]
    fn rejects_an_unknown_layer_media_type() {
        let manifest = MANIFEST.replace(
            "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "application/vnd.unknown.layer",
        );
        let error = ImageManifest::parse(manifest.as_bytes()).expect_err("must refuse");
        assert!(error.to_string().contains("not a tar"));
    }

    #[test]
    fn rejects_a_wrong_schema_version() {
        let manifest = MANIFEST.replace(r#""schemaVersion": 2"#, r#""schemaVersion": 1"#);
        let error = ImageManifest::parse(manifest.as_bytes()).expect_err("must refuse");
        assert!(error.to_string().contains("schema version"));
    }

    #[test]
    fn parses_a_config_and_builds_the_command() {
        let config: ImageConfig = serde_json::from_str(
            r#"{
  "architecture": "amd64",
  "os": "linux",
  "config": {
    "Entrypoint": ["/bin/sh"],
    "Cmd": ["-c", "echo hi"],
    "Env": ["PATH=/usr/bin"],
    "WorkingDir": "/app",
    "User": "1000"
  },
  "rootfs": {"diff_ids": ["sha256:abc"], "type": "layers"}
}"#,
        )
        .expect("valid config");
        assert_eq!(config.architecture, "amd64");
        assert_eq!(config.config.command(), vec!["/bin/sh", "-c", "echo hi"]);
        assert!(config.config.has_command());
        assert_eq!(config.config.working_dir, "/app");
        assert_eq!(config.rootfs.layer_type, "layers");
    }

    #[test]
    fn a_config_without_a_command_is_reported_as_such() {
        let config: ImageConfig =
            serde_json::from_str(r#"{"architecture":"amd64","os":"linux"}"#).expect("valid config");
        assert!(!config.config.has_command());
        assert!(config.config.command().is_empty());
    }

    #[test]
    fn descriptor_digest_must_be_valid() {
        let descriptor = Descriptor {
            media_type: crate::media_types::LAYER_GZIP.to_owned(),
            digest: "sha256:abc".to_owned(),
            size: 1,
        };
        assert!(descriptor.parsed_digest().is_err());
    }
}
