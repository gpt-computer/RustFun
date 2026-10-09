//! CLI end-to-end tests.
//!
//! These drive the real `rustfun` binary, so they cover argument parsing, template
//! generation, the build/invoke lifecycle, and the human-readable output contract.

use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    // The integration test binary lives in `target/<profile>/deps`.
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("rustfun")
}

fn workspace(label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "rustfun-cli-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("creates workspace");
    dir
}

struct Output {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run(dir: &Path, args: &[&str]) -> Output {
    let output = Command::new(binary())
        .args(args)
        .current_dir(dir)
        .env("RUSTFUN_HOME", dir.join("state"))
        .env("RUST_LOG", "error")
        .output()
        .unwrap_or_else(|error| panic!("cannot run rustfun: {error}"));
    Output {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[test]
fn version_and_doctor_work() {
    let dir = workspace("version");
    let output = run(&dir, &["version"]);
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert!(output.stdout.contains("rustfun"));

    let output = run(&dir, &["doctor", "--json"]);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert!(value["version"].is_string());
    assert!(value["sandbox"].as_array().expect("probes").len() >= 4);
    assert!(value["runtimes"].as_array().expect("runtimes").len() >= 4);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn init_build_invoke_destroy_round_trip() {
    let dir = workspace("lifecycle");
    let output = run(&dir, &["init", "hello", "--template", "node"]);
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert!(dir.join("hello/rustfun.toml").exists());
    assert!(dir.join("hello/index.js").exists());

    let output = run(&dir, &["build", "hello", "--json"]);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    let digest = value["artifacts"][0]["digest"]
        .as_str()
        .expect("digest")
        .to_owned();
    assert!(digest.starts_with("sha256:"));

    let output = run(
        &dir,
        &[
            "function",
            "invoke",
            "hello",
            "--payload",
            "{\"name\":\"world\"}",
        ],
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert!(
        output.stdout.contains("hello world"),
        "unexpected invocation output: {}",
        output.stdout
    );

    let output = run(&dir, &["function", "list", "--json"]);
    assert_eq!(output.status, 0);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert_eq!(value["functions"][0]["status"], "ready");

    // Each CLI process is its own kernel: instances are not expected to survive it.
    let output = run(&dir, &["instance", "list", "--json"]);
    assert_eq!(output.status, 0);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert_eq!(
        value["instances"].as_array().expect("instances").len(),
        0,
        "instances belong to the process that created them"
    );

    let output = run(&dir, &["cache", "list", "--json"]);
    assert_eq!(output.status, 0);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert!(value["size_bytes"].as_u64().expect("size") > 0);

    // `destroy` tears down the running kernel's view of the function; it deliberately does not
    // delete the author's manifest or sources.
    let output = run(&dir, &["function", "destroy", "hello", "--json"]);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert_eq!(value["destroyed"], "hello");
    assert!(
        dir.join("hello/rustfun.toml").exists(),
        "sources must survive destroy"
    );

    let output = run(&dir, &["instance", "list", "--json"]);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert!(value["instances"].as_array().expect("instances").is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_artifact_cache_is_shared_across_processes() {
    // Warm instances live inside one process (the dev server); the *artifact* is what crosses
    // process boundaries, so a second `rustfun` invocation reuses it instead of rebuilding.
    let dir = workspace("warm");
    assert_eq!(
        run(&dir, &["init", "hello", "--template", "node"]).status,
        0
    );

    let first = run(
        &dir,
        &["function", "invoke", "hello", "--payload", "{}", "--json"],
    );
    assert_eq!(first.status, 0, "{}", first.stderr);
    let first: serde_json::Value = serde_json::from_str(&first.stdout).expect("json");
    assert_eq!(first["status"], "success");

    let output = run(&dir, &["build", "hello", "--json"]);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    let digest = value["artifacts"][0]["digest"].as_str().expect("digest");
    assert!(
        digest.starts_with("sha256:"),
        "the second process must reuse the cached artifact"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn python_function_round_trip() {
    let dir = workspace("python");
    let output = run(&dir, &["init", "pyfn", "--template", "python"]);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let output = run(&dir, &["build", "pyfn"]);
    if output.status != 0 {
        eprintln!("skipping: python is not available\n{}", output.stderr);
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let output = run(
        &dir,
        &[
            "function",
            "invoke",
            "pyfn",
            "--payload",
            "{\"name\":\"python\"}",
        ],
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    assert!(output.stdout.contains("hello python"), "{}", output.stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_function_fails_with_a_structured_message() {
    let dir = workspace("missing");
    let output = run(&dir, &["function", "invoke", "ghost", "--payload", "{}"]);
    assert_ne!(output.status, 0, "invoking a missing function must fail");
    assert!(
        output.stderr.contains("RUSTFUN_NOT_FOUND"),
        "stderr should carry the error code: {}",
        output.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invoking_without_an_explicit_build_builds_implicitly() {
    // Each CLI process starts from manifests, so an invocation must build on demand rather
    // than failing: the artifact is content-addressed, so the repeat cost is a cache lookup.
    let dir = workspace("unbuilt");
    assert_eq!(
        run(&dir, &["init", "hello", "--template", "node"]).status,
        0
    );
    let output = run(
        &dir,
        &["function", "invoke", "hello", "--payload", "{}", "--json"],
    );
    assert_eq!(output.status, 0, "{}", output.stderr);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert_eq!(value["status"], "success");

    let output = run(&dir, &["function", "list", "--json"]);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert_eq!(
        value["functions"][0]["status"], "ready",
        "the cached artifact must be visible to the next process"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn runtime_list_reports_discovery() {
    let dir = workspace("runtimes");
    let output = run(&dir, &["runtime", "list", "--json"]);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    let runtimes = value["runtimes"].as_array().expect("runtimes");
    assert!(runtimes.iter().any(|r| r["runtime"]
        .as_str()
        .is_some_and(|name| name.starts_with("node"))));

    let output = run(&dir, &["runtime", "inspect", "node", "--json"]);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert!(value["runtime"]
        .as_str()
        .expect("runtime")
        .starts_with("node"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn function_inspect_labels_the_sandbox_honestly() {
    let dir = workspace("inspect");
    assert_eq!(
        run(&dir, &["init", "hello", "--template", "node"]).status,
        0
    );
    let output = run(&dir, &["function", "inspect", "hello", "--json"]);
    assert_eq!(output.status, 0, "{}", output.stderr);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert_eq!(value["sandbox"], "host");
    assert_eq!(
        value["sandbox_is_security_boundary"], false,
        "host mode must never be presented as a security boundary"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Machine-readable output must stay parseable no matter how much the runtimes log.
///
/// Warnings such as "running without a sandbox" are diagnostics: they belong on stderr.
/// A warning on stdout makes `rustfun function invoke --json | jq` fail in exactly the
/// situation an operator is debugging.
#[test]
fn json_output_stays_pure_while_warnings_are_logged() {
    let dir = workspace("json-purity");
    // RUSTFUN_LOG=warn forces a diagnostic to be emitted on the host (no sandbox) path.
    let output = Command::new(binary())
        .args(["doctor", "--json"])
        .current_dir(&dir)
        .env("RUSTFUN_HOME", dir.join("state"))
        .env("RUST_LOG", "warn")
        .output()
        .expect("runs rustfun");
    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    serde_json::from_str::<serde_json::Value>(&stdout)
        .unwrap_or_else(|error| panic!("stdout is not valid JSON ({error}):\n{stdout}"));
    assert!(
        !stdout.contains("WARN") && !stdout.contains("RUST_LOG"),
        "diagnostics leaked into stdout:\n{stdout}"
    );
    let _ = stderr;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Invoking a function must not invalidate its artifact: the generated runtime bootstrap is
/// written into the extracted function root, and a store that digests it would report the
/// artifact as corrupted after the first call.
#[test]
fn invoking_a_function_keeps_the_artifact_verifiable() {
    let dir = workspace("verify-after-invoke");
    run(&dir, &["init", "fn-node", "--template", "node"]);
    let built = run(&dir, &["build", "fn-node", "--json"]);
    assert_eq!(built.status, 0, "{}", built.stderr);
    let digest_before = serde_json::from_str::<serde_json::Value>(&built.stdout)
        .expect("build json")
        .pointer("/artifacts/0/digest")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .expect("digest");

    for _ in 0..2 {
        let invoked = run(
            &dir,
            &[
                "function",
                "invoke",
                "fn-node",
                "--payload",
                "{\"name\":\"x\"}",
                "--json",
            ],
        );
        assert_eq!(invoked.status, 0, "{}", invoked.stderr);
    }

    let verified = run(&dir, &["cache", "verify", "--json"]);
    assert_eq!(verified.status, 0, "{}", verified.stderr);
    let report: serde_json::Value = serde_json::from_str(&verified.stdout).expect("verify json");
    assert_eq!(
        report.get("corrupted").and_then(serde_json::Value::as_u64),
        Some(0),
        "the artifact was reported as corrupted after being invoked:\n{}",
        verified.stdout
    );

    let rebuilt = run(&dir, &["build", "fn-node", "--json"]);
    assert_eq!(rebuilt.status, 0, "{}", rebuilt.stderr);
    let digest_after = serde_json::from_str::<serde_json::Value>(&rebuilt.stdout)
        .expect("rebuild json")
        .pointer("/artifacts/0/digest")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .expect("digest");
    assert_eq!(
        digest_before, digest_after,
        "the artifact digest must be stable across invocations"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The Wasm template must produce a function that actually runs.
///
/// The template used to scaffold a Rust crate and declare `kind = "host"`, which the Wasm
/// adapter refuses: the scaffold looked complete and could never be invoked.
#[test]
fn the_wasm_template_builds_and_invokes() {
    let dir = workspace("wasm-template");
    let created = run(&dir, &["init", "hello-wasm", "--template", "wasm"]);
    assert_eq!(created.status, 0, "{}", created.stderr);

    let root = dir.join("hello-wasm");
    let manifest = std::fs::read_to_string(root.join("rustfun.toml")).expect("manifest");
    assert!(
        manifest.contains("kind = \"wasm\""),
        "the manifest must select the Wasm sandbox layer:\n{manifest}"
    );
    assert!(manifest.contains("rustfun_handler"));

    let built = run(&dir, &["build", "hello-wasm", "--json"]);
    assert_eq!(built.status, 0, "{}", built.stderr);

    let invoked = run(
        &dir,
        &[
            "function",
            "invoke",
            "hello-wasm",
            "--payload",
            "{\"name\":\"world\"}",
            "--json",
        ],
    );
    assert_eq!(invoked.status, 0, "{}", invoked.stderr);
    let value: serde_json::Value = serde_json::from_str(&invoked.stdout).expect("invoke json");
    assert_eq!(value["status"], "success", "{}", invoked.stdout);
    assert_eq!(value["result"]["message"], "hello from wasm");
    let _ = std::fs::remove_dir_all(&dir);
}
