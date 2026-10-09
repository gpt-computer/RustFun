//! Tests for the content-addressed artifact store.
//!
//! The store is the platform's supply chain boundary, so the tests cover immutability,
//! determinism, integrity verification, and the path-traversal defences that a malicious
//! artifact would attack.

use std::path::{Path, PathBuf};

use rustfun_artifact::FileArtifactStore;
use rustfun_core::artifact::{ArtifactStore, BuildRequest};
use rustfun_core::{
    ErrorCategory, FunctionManager, FunctionManagerConfig, FunctionName, FunctionSpec, HandlerSpec,
    RuntimeId,
};
use rustfun_model::FunctionSource;

fn temp_root(label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!(
        "rustfun-artifact-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("creates root");
    root
}

fn write_source(dir: &Path) {
    std::fs::create_dir_all(dir.join("src")).expect("creates src");
    std::fs::write(dir.join("src/index.js"), "exports.handler = () => 1;\n")
        .expect("writes handler");
    std::fs::write(dir.join("package.json"), "{\"name\":\"hello\"}\n").expect("writes package");
}

fn spec() -> std::sync::Arc<FunctionSpec> {
    std::sync::Arc::new(
        FunctionSpec::new(
            FunctionName::new("hello").expect("valid"),
            RuntimeId::parse("node@24").expect("valid"),
            HandlerSpec::parse("src/index.handler").expect("valid"),
        )
        .with_source(FunctionSource::Directory {
            path: ".".to_owned(),
        }),
    )
}

#[tokio::test]
async fn builds_are_deterministic_and_cached() {
    let root = temp_root("deterministic");
    let source = root.join("src-function");
    write_source(&source);
    let store = FileArtifactStore::open(root.join("store"))
        .await
        .expect("opens");

    let first = store
        .build(BuildRequest::new(spec().id.clone(), spec(), source.clone()))
        .await
        .expect("builds");
    let second = store
        .build(BuildRequest::new(spec().id.clone(), spec(), source.clone()))
        .await
        .expect("builds again");
    assert_eq!(first.digest, second.digest, "digests must be deterministic");
    assert_eq!(first.file_count, 2);

    // A content change must produce a different digest.
    std::fs::write(source.join("src/index.js"), "exports.handler = () => 2;\n").expect("writes");
    let third = store
        .build(BuildRequest::new(spec().id.clone(), spec(), source))
        .await
        .expect("rebuilds");
    assert_ne!(first.digest, third.digest);

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn extract_roundtrips_the_source_tree() {
    let root = temp_root("extract");
    let source = root.join("src-function");
    write_source(&source);
    let store = FileArtifactStore::open(root.join("store"))
        .await
        .expect("opens");
    let summary = store
        .build(BuildRequest::new(spec().id.clone(), spec(), source))
        .await
        .expect("builds");

    let destination = root.join("dest");
    let path = store
        .extract(&summary.digest, &destination)
        .await
        .expect("extracts");
    assert!(path.join("src/index.js").exists());
    assert!(path.join("package.json").exists());
    assert!(!path.join("rustfun.toml").exists());

    // Extraction is idempotent: the same digest yields the same directory.
    let again = store
        .extract(&summary.digest, &destination)
        .await
        .expect("extracts again");
    assert_eq!(path, again);
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn verification_detects_corruption() {
    let root = temp_root("verify");
    let source = root.join("src-function");
    write_source(&source);
    let store = FileArtifactStore::open(root.join("store"))
        .await
        .expect("opens");
    let summary = store
        .build(BuildRequest::new(spec().id.clone(), spec(), source))
        .await
        .expect("builds");
    let destination = root.join("dest");
    store
        .extract(&summary.digest, &destination)
        .await
        .expect("extracts");
    assert!(store.verify(&summary.digest).await.expect("verifies"));

    // Corrupt the extracted tree; verification must fail and drop the artifact.
    std::fs::write(
        store
            .root()
            .join("extracted")
            .join(summary.digest.hex())
            .join("package.json"),
        "corrupted",
    )
    .expect("corrupts");
    assert!(!store.verify(&summary.digest).await.expect("verifies"));
    assert!(!store.contains(&summary.digest).await.expect("contains"));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn missing_artifacts_report_not_found() {
    let root = temp_root("missing");
    let store = FileArtifactStore::open(root.join("store"))
        .await
        .expect("opens");
    let digest = rustfun_model::Digest::sha256(b"nothing");
    assert!(!store.contains(&digest).await.expect("contains"));
    let err = store
        .extract(&digest, &root.join("dest"))
        .await
        .expect_err("missing");
    assert_eq!(err.category(), ErrorCategory::NotFound);
    assert_eq!(err.code(), "RUSTFUN_NOT_FOUND");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn removal_and_eviction_work() {
    let root = temp_root("evict");
    let source = root.join("src-function");
    write_source(&source);
    let store = FileArtifactStore::open(root.join("store"))
        .await
        .expect("opens");
    let summary = store
        .build(BuildRequest::new(spec().id.clone(), spec(), source))
        .await
        .expect("builds");
    assert!(store.size_bytes().await.expect("sizes") > 0);
    // Age the artifact so it becomes eligible for eviction.
    let metadata_path = store
        .root()
        .join("artifacts")
        .join(&summary.digest.hex()[..2])
        .join(format!("{}.json", summary.digest.hex()));
    let raw = std::fs::read_to_string(&metadata_path).expect("reads metadata");
    let mut value: serde_json::Value = serde_json::from_str(&raw).expect("parses");
    value["created_at"] = serde_json::json!(0);
    std::fs::write(
        &metadata_path,
        serde_json::to_vec(&value).expect("serializes"),
    )
    .expect("writes metadata");
    assert_eq!(
        store
            .evict(std::time::Duration::from_secs(60))
            .await
            .expect("evicts"),
        1
    );
    assert!(!store.contains(&summary.digest).await.expect("contains"));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn build_commands_run_and_failures_are_structured() {
    let root = temp_root("build-cmd");
    let source = root.join("src-function");
    write_source(&source);
    let store = FileArtifactStore::open(root.join("store"))
        .await
        .expect("opens");

    let ok = store
        .build(
            BuildRequest::new(spec().id.clone(), spec(), source.clone()).with_build_command(vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo built > out.txt".to_owned(),
            ]),
        )
        .await
        .expect("builds");
    assert!(ok.file_count >= 3);

    let err = store
        .build(
            BuildRequest::new(spec().id.clone(), spec(), source).with_build_command(vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "exit 3".to_owned(),
            ]),
        )
        .await
        .expect_err("fails");
    assert_eq!(err.category(), ErrorCategory::Artifact);
    assert!(err.context().details.contains_key("command"));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn missing_source_directory_is_reported() {
    let root = temp_root("no-source");
    let store = FileArtifactStore::open(root.join("store"))
        .await
        .expect("opens");
    let err = store
        .build(BuildRequest::new(
            spec().id.clone(),
            spec(),
            root.join("does-not-exist"),
        ))
        .await
        .expect_err("missing");
    assert_eq!(err.category(), ErrorCategory::NotFound);
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn unpack_refuses_path_traversal_members() {
    // Build a malicious archive by hand: the tar crate writes whatever paths it is given.
    let root = temp_root("traversal");
    let archive = root.join("evil.tar.gz");
    // Write the archive bytes by hand: the `tar` crate deliberately sanitizes paths, and a
    // malicious artifact is exactly the case where sanitization must not be assumed.
    let mut tar_bytes = Vec::new();
    tar_bytes.extend_from_slice(&ustar_header("../escaped.txt", 6));
    tar_bytes.extend_from_slice(b"pwned\0");
    tar_bytes.resize(tar_bytes.len() + (512 - tar_bytes.len() % 512), 0);
    tar_bytes.extend_from_slice(&[0u8; 1024]); // two zero blocks terminate the archive
    {
        use std::io::Write as _;
        let file = std::fs::File::create(&archive).expect("creates");
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        encoder.write_all(&tar_bytes).expect("writes");
        encoder.finish().expect("compresses");
    }
    let err = FileArtifactStore::unpack_archive(&archive, &root.join("dest")).expect_err("rejects");
    assert_eq!(err.category(), ErrorCategory::Artifact);
    assert!(err.to_string().contains("traversal"));
    assert!(!root.join("escaped.txt").exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn function_manager_builds_and_verifies_artifacts() {
    let root = temp_root("manager");
    let source = root.join("src-function");
    write_source(&source);
    let store = std::sync::Arc::new(
        FileArtifactStore::open(root.join("store"))
            .await
            .expect("opens"),
    );

    let manager = FunctionManager::new(
        FunctionManagerConfig {
            workdir: root.join("work"),
            base_dir: root.clone(),
            ..FunctionManagerConfig::default()
        },
        rustfun_runtime::default_registry(),
    );
    manager.set_artifact_store(store);

    let mut function_spec = (*spec()).clone();
    function_spec.source = FunctionSource::Directory {
        path: source.to_string_lossy().into_owned(),
    };
    let function = manager.create(function_spec).expect("creates");
    let artifact = manager.build(&function.id, false).await.expect("builds");
    assert_eq!(manager.digest_of(&function.id), Some(artifact.digest));
    assert!(manager
        .verify_artifact(&function.id)
        .await
        .expect("verifies"));
    let _ = std::fs::remove_dir_all(&root);
}

/// Build a minimal ustar header for a regular file.
fn ustar_header(name: &str, size: usize) -> [u8; 512] {
    let mut header = [0u8; 512];
    let name_bytes = name.as_bytes();
    header[..name_bytes.len()].copy_from_slice(name_bytes);
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        "); // checksum placeholder
    header[156] = b'0';
    header[257..262].copy_from_slice(b"ustar");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    let checksum = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum.as_bytes());
    header
}

#[cfg(unix)]
#[tokio::test]
async fn executable_bits_survive_packing_and_extraction() {
    // The `executable` runtime invokes the artifact directly: losing the executable bit during
    // extraction would surface as a confusing "Permission denied" at invocation time.
    let root = temp_root("exec-bit");
    let source = root.join("src-function");
    std::fs::create_dir_all(&source).expect("creates source");
    let binary = source.join("handler");
    std::fs::write(&binary, "#!/bin/sh\nexit 0\n").expect("writes");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let store = FileArtifactStore::open(root.join("store"))
        .await
        .expect("opens");
    let summary = store
        .build(BuildRequest::new(spec().id.clone(), spec(), source))
        .await
        .expect("builds");
    let path = store
        .extract(&summary.digest, &root.join("dest"))
        .await
        .expect("extracts");
    let extracted = path.join("handler");
    assert!(extracted.exists());
    let mode = std::fs::metadata(&extracted)
        .expect("stats")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o111,
        0o111,
        "the extracted artifact must still be executable"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn generated_runtime_bootstraps_are_not_part_of_the_digest() {
    let root = temp_root("bootstrap");
    let source = root.join("source");
    write_source(&source);
    let store = FileArtifactStore::open(root.join("store"))
        .await
        .expect("opens");
    let artifact = store
        .build(BuildRequest::new(spec().id.clone(), spec(), source.clone()))
        .await
        .expect("builds");
    let digest = artifact.digest.clone();

    // The runtime adapter writes its bootstrap into the extracted function root at prepare
    // time. Verification must still hold afterwards, otherwise every invocation would report
    // the artifact as corrupted.
    let extracted = store
        .extract(&digest, &root.join("extracted"))
        .await
        .expect("extracts");
    assert!(store.verify(&digest).await.expect("verifies"));
    std::fs::write(extracted.join(".rustfun-bootstrap.cjs"), "// generated\n")
        .expect("writes bootstrap");
    std::fs::create_dir_all(extracted.join("src")).expect("creates src");
    std::fs::write(extracted.join("src/.rustfun_bootstrap.py"), "# generated\n")
        .expect("writes bootstrap");

    assert!(store.verify(&digest).await.expect("still verifies"));
    let repacked = FileArtifactStore::digest_directory(&extracted).expect("re-digests");
    assert_eq!(
        digest.to_string(),
        repacked.to_string(),
        "the generated bootstraps must not change the digest"
    );
    let _ = std::fs::remove_dir_all(&root);
}
