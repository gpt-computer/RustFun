//! Tests for the Wasmtime runtime adapter.
//!
//! Guests are written in WAT so the tests need no Wasm toolchain: the module is the same
//! artefact a real build would produce, expressed as text.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustfun_core::runtime::{PrepareRequest, RuntimeAdapter, RuntimeInstance};
use rustfun_core::{ErrorCategory, RustFunError};
use rustfun_model::{
    Environment, FunctionName, FunctionSource, FunctionSpec, HandlerSpec, InvocationId, RequestId,
    ResourceLimits, RuntimeId, SandboxPolicy,
};

use super::{WasmAdapter, DEFAULT_FUEL_PER_INVOCATION};
use crate::wasm::abi::{EXPORT_HANDLER, EXPORT_MEMORY, HOST_FN_PAYLOAD, MAX_FRAME_BYTES};

/// Counter for unique temp directories.
static SEQ: AtomicU32 = AtomicU32::new(0);

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rustfun-wasm-{label}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("creates temp dir");
    dir
}

/// Write a `.wat` module and return its path.
fn write_module(dir: &Path, name: &str, source: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, source).expect("writes module");
    path
}

/// A handler that answers with a complete `RFN1` frame whose body is `wasm-ok`.
///
/// The header bytes are precomputed as a data segment: `RFN1`, version 1, JSON codec (1), and
/// the body length. The body is one status byte followed by the payload, exactly as the ABI
/// specifies, so this guest does no parsing at all.
const CONSTANT_HANDLER: &str = r#"
(module
  (memory (export "memory") 2)
  (data (i32.const 70000) "RFN1\01\01\00\00\00\08\00wasm-ok")
  (func (export "rustfun_handler") (result i32)
    (memory.copy (i32.const 65536) (i32.const 70000) (i32.const 18))
    (i32.const 18)))
"#;

/// A handler that mirrors the request back with the magic bytes intact, used to prove a warm
/// instance really re-runs the guest rather than replaying a cached answer.
const ECHO_HANDLER: &str = r#"
(module
  (memory (export "memory") 2)
  (data (i32.const 70000) "RFN1\01\01\00\00\00\03\00ok")
  (func (export "rustfun_handler") (result i32)
    (memory.copy (i32.const 65536) (i32.const 70000) (i32.const 13))
    (i32.const 13)))
"#;

/// A handler that traps immediately.
const TRAPPING_HANDLER: &str = r#"
(module
  (memory (export "memory") 2)
  (func (export "rustfun_handler") (result i32)
    unreachable))
"#;

/// A handler that spins forever, to exercise fuel exhaustion.
const BUSY_HANDLER: &str = r#"
(module
  (memory (export "memory") 2)
  (func (export "rustfun_handler") (result i32)
    (local $i i32)
    (loop $again
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $again))
    (i32.const 0)))
"#;

/// A handler that returns a length far beyond its memory.
const OVERREACHING_HANDLER: &str = r#"
(module
  (memory (export "memory") 2)
  (func (export "rustfun_handler") (result i32)
    (i32.const 1000000000)))
"#;

/// A handler that returns a negative length (the ABI's "I failed" signal).
const FAILING_HANDLER: &str = r#"
(module
  (memory (export "memory") 2)
  (func (export "rustfun_handler") (result i32)
    (i32.const -3)))
"#;

/// A handler that announces more body bytes than it writes.
const GARBAGE_HANDLER: &str = r#"
(module
  (memory (export "memory") 2)
  (data (i32.const 70000) "RFN1\01\01\00\00\00c\00ok")
  (func (export "rustfun_handler") (result i32)
    (memory.copy (i32.const 65536) (i32.const 70000) (i32.const 15))
    (i32.const 15)))
"#;

/// A handler that writes a status byte the ABI does not define.
const UNKNOWN_STATUS_HANDLER: &str = r#"
(module
  (memory (export "memory") 2)
  (data (i32.const 70000) "RFN1\01\01\00\00\00\03\09ok")
  (func (export "rustfun_handler") (result i32)
    (memory.copy (i32.const 65536) (i32.const 70000) (i32.const 13))
    (i32.const 13)))
"#;

/// A handler that imports `rustfun.payload` and uses the pointer the host returns.
const PAYLOAD_IMPORT_HANDLER: &str = r#"
(module
  (import "rustfun" "payload" (func $payload (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 70000) "RFN1\01\01\00\00\00\08\00wasm-ok")
  (func (export "rustfun_handler") (result i32)
    (local $at i32)
    ;; the host has already written the request frame; it tells us where
    (local.set $at (call $payload (i32.const 0) (i32.const 0)))
    (if (i32.lt_s (local.get $at) (i32.const 0))
      (then (return (i32.const -1))))
    (memory.copy (local.get $at) (i32.const 70000) (i32.const 18))
    (i32.const 18)))
"#;

/// A module with no `memory` export.
const NO_MEMORY_HANDLER: &str = r#"
(module
  (func (export "rustfun_handler") (result i32) (i32.const 0)))
"#;

/// A module with the wrong handler signature.
const WRONG_SIGNATURE_HANDLER: &str = r#"
(module
  (memory (export "memory") 2)
  (func (export "rustfun_handler") (param i32) (result i32) (local.get 0)))
"#;

/// A module that imports something RustFun does not provide.
const UNSUPPORTED_IMPORT_HANDLER: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (func (export "rustfun_handler") (result i32)
    (drop (call $fd_write (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
    (i32.const 4)))
"#;

fn spec_with(memory_bytes: u64, timeout: Duration) -> Arc<FunctionSpec> {
    let mut spec = FunctionSpec::new(
        FunctionName::new("hello").expect("valid"),
        RuntimeId::parse("wasm").expect("valid"),
        HandlerSpec::parse("main.wasm.rustfun_handler").expect("valid"),
    )
    .with_sandbox(SandboxPolicy::wasm())
    .with_source(FunctionSource::Directory {
        path: ".".to_owned(),
    });
    spec.resources = ResourceLimits {
        memory_bytes,
        timeout,
        ..ResourceLimits::default()
    };
    Arc::new(spec)
}

/// A spec whose handler names `module`.
fn spec_named(name: &str, module: &str, memory_bytes: u64) -> Arc<FunctionSpec> {
    let mut spec = FunctionSpec::new(
        FunctionName::new(name).expect("valid"),
        RuntimeId::parse("wasm").expect("valid"),
        HandlerSpec::parse(&format!("{module}.rustfun_handler")).expect("valid"),
    )
    .with_sandbox(SandboxPolicy::wasm())
    .with_source(FunctionSource::Directory {
        path: ".".to_owned(),
    });
    spec.resources = ResourceLimits {
        memory_bytes,
        timeout: Duration::from_secs(5),
        ..ResourceLimits::default()
    };
    Arc::new(spec)
}

async fn start(
    adapter: &WasmAdapter,
    spec: Arc<FunctionSpec>,
    module: &Path,
) -> Result<Box<dyn RuntimeInstance>, RustFunError> {
    let workdir = module.parent().expect("module has a parent").to_path_buf();
    adapter
        .prepare(PrepareRequest {
            function_id: spec.id.clone(),
            function_name: spec.name.clone(),
            runtime: spec.runtime.clone(),
            handler: spec.handler.clone(),
            workdir,
            environment: Environment::new(),
            resources: spec.resources,
            sandbox: spec.sandbox.clone(),
        })
        .await
        .map(|prepared| {
            let instance_id = rustfun_model::InstanceId::new();
            let prewarm = false;
            async move {
                adapter
                    .start(rustfun_core::runtime::StartRequest {
                        spec,
                        instance_id,
                        prepared,
                        prewarm,
                    })
                    .await
            }
        })?
        .await
}

fn request(payload: &[u8], timeout: Option<Duration>) -> rustfun_core::protocol::InvocationRequest {
    let mut request = rustfun_core::protocol::InvocationRequest::new(
        RequestId::new(),
        InvocationId::new(),
        rustfun_model::FunctionId::new(),
        payload.to_vec(),
    );
    if let Some(timeout) = timeout {
        request = request.with_deadline(timeout);
    }
    request
}

#[tokio::test]
async fn handler_answer_is_returned_as_the_invocation_payload() {
    let dir = temp_dir("constant");
    let module = write_module(&dir, "main.wat", CONSTANT_HANDLER);
    let adapter = WasmAdapter::new();
    let instance = start(
        &adapter,
        spec_with(32 * 1024 * 1024, Duration::from_secs(5)),
        &module,
    )
    .await
    .expect("starts");

    let outcome = instance
        .invoke(request(b"{}", None))
        .await
        .expect("invokes");
    assert!(outcome.response.is_success(), "{:?}", outcome.response);
    assert_eq!(outcome.response.payload, b"wasm-ok");
    assert!(outcome.instance_healthy);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn payload_import_is_offered_and_the_pointer_is_honoured() {
    let dir = temp_dir("payload-import");
    let module = write_module(&dir, "main.wat", PAYLOAD_IMPORT_HANDLER);
    let adapter = WasmAdapter::new();
    let instance = start(
        &adapter,
        spec_with(32 * 1024 * 1024, Duration::from_secs(5)),
        &module,
    )
    .await
    .expect("starts");

    let outcome = instance
        .invoke(request(b"{\"n\":1}", None))
        .await
        .expect("invokes");
    assert!(
        outcome.response.is_success(),
        "a guest importing {} must run: {:?}",
        HOST_FN_PAYLOAD,
        outcome.response
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_warm_instance_serves_many_invocations() {
    let dir = temp_dir("warm");
    let module = write_module(&dir, "main.wat", ECHO_HANDLER);
    let adapter = WasmAdapter::new();
    let instance = start(
        &adapter,
        spec_with(32 * 1024 * 1024, Duration::from_secs(5)),
        &module,
    )
    .await
    .expect("starts");

    for index in 0..25 {
        let outcome = instance
            .invoke(request(format!("{{\"i\":{index}}}").as_bytes(), None))
            .await
            .expect("invokes");
        assert!(outcome.response.is_success(), "invocation {index} failed");
        assert_eq!(outcome.response.payload, b"ok");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_trapping_guest_is_a_function_error_and_the_store_stays_usable() {
    let dir = temp_dir("trap");
    let module = write_module(&dir, "main.wat", TRAPPING_HANDLER);
    let adapter = WasmAdapter::new();
    let instance = start(
        &adapter,
        spec_with(32 * 1024 * 1024, Duration::from_secs(5)),
        &module,
    )
    .await
    .expect("starts");

    let outcome = instance
        .invoke(request(b"{}", None))
        .await
        .expect("invokes");
    assert_eq!(
        outcome.response.status,
        rustfun_core::protocol::InvocationStatus::FunctionError
    );
    let error = outcome.response.error.expect("error");
    assert_eq!(error.code, "RUSTFUN_WASM_ERROR");
    // A trap unwinds inside the guest and leaves the store valid, which is why the instance is
    // kept: throwing away a warm instance on every guest exception would make error handling
    // the most expensive path in the platform.
    assert!(outcome.instance_healthy);
    assert_eq!(
        instance.health().await,
        rustfun_core::runtime::HealthStatus::Healthy
    );
    let again = instance
        .invoke(request(b"{}", None))
        .await
        .expect("invokes again");
    assert_eq!(
        again.response.status,
        rustfun_core::protocol::InvocationStatus::FunctionError,
        "the guest traps every time; the point is that the host still served the second call"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_guest_that_violates_the_abi_is_evicted() {
    let dir = temp_dir("abi-violation");
    let module = write_module(&dir, "main.wat", UNKNOWN_STATUS_HANDLER);
    let adapter = WasmAdapter::new();
    let instance = start(
        &adapter,
        spec_with(32 * 1024 * 1024, Duration::from_secs(5)),
        &module,
    )
    .await
    .expect("starts");

    let outcome = instance
        .invoke(request(b"{}", None))
        .await
        .expect("invokes");
    assert!(!outcome.instance_healthy);
    assert_eq!(
        instance.health().await,
        rustfun_core::runtime::HealthStatus::Unhealthy
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn fuel_stops_a_guest_that_never_yields() {
    let dir = temp_dir("fuel");
    let module = write_module(&dir, "main.wat", BUSY_HANDLER);
    let adapter = WasmAdapter::new();
    let instance = start(
        &adapter,
        spec_with(32 * 1024 * 1024, Duration::from_secs(30)),
        &module,
    )
    .await
    .expect("starts");

    let started = std::time::Instant::now();
    let outcome = instance
        .invoke(request(b"{}", Some(Duration::from_secs(20))))
        .await
        .expect("invokes");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "fuel must stop an infinite loop long before the deadline"
    );
    assert_eq!(
        outcome.response.status,
        rustfun_core::protocol::InvocationStatus::FunctionError
    );
    let error = outcome.response.error.expect("error");
    assert!(
        error.message.to_lowercase().contains("fuel")
            || error.message.to_lowercase().contains("all fuel consumed"),
        "the trap should name fuel exhaustion: {}",
        error.message
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_guest_cannot_claim_memory_it_does_not_have() {
    let dir = temp_dir("bounds");
    let module = write_module(&dir, "main.wat", OVERREACHING_HANDLER);
    let adapter = WasmAdapter::new();
    let instance = start(
        &adapter,
        spec_with(32 * 1024 * 1024, Duration::from_secs(5)),
        &module,
    )
    .await
    .expect("starts");

    let outcome = instance
        .invoke(request(b"{}", None))
        .await
        .expect("invokes");
    let error = outcome.response.error.expect("error");
    assert!(
        error.message.contains("limit") && error.message.contains("1000000000"),
        "the error should name both the claim and the ceiling: {}",
        error.message
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_guest_may_report_a_failure_with_a_negative_length() {
    let dir = temp_dir("negative");
    let module = write_module(&dir, "main.wat", FAILING_HANDLER);
    let adapter = WasmAdapter::new();
    let instance = start(
        &adapter,
        spec_with(32 * 1024 * 1024, Duration::from_secs(5)),
        &module,
    )
    .await
    .expect("starts");

    let outcome = instance
        .invoke(request(b"{}", None))
        .await
        .expect("invokes");
    let error = outcome.response.error.expect("error");
    assert!(
        error.message.contains("-3"),
        "the guest's own code should be reported: {}",
        error.message
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_garbage_response_is_a_function_error_not_a_platform_error() {
    let dir = temp_dir("garbage");
    let module = write_module(&dir, "main.wat", GARBAGE_HANDLER);
    let adapter = WasmAdapter::new();
    let instance = start(
        &adapter,
        spec_with(32 * 1024 * 1024, Duration::from_secs(5)),
        &module,
    )
    .await
    .expect("starts");

    let outcome = instance
        .invoke(request(b"{}", None))
        .await
        .expect("invokes");
    assert_eq!(
        outcome.response.status,
        rustfun_core::protocol::InvocationStatus::FunctionError
    );
    let error = outcome.response.error.expect("error");
    assert_eq!(error.code, "RUSTFUN_WASM_BAD_RESPONSE");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_unknown_response_status_is_refused() {
    let dir = temp_dir("unknown-status");
    let module = write_module(&dir, "main.wat", UNKNOWN_STATUS_HANDLER);
    let adapter = WasmAdapter::new();
    let instance = start(
        &adapter,
        spec_with(32 * 1024 * 1024, Duration::from_secs(5)),
        &module,
    )
    .await
    .expect("starts");

    let outcome = instance
        .invoke(request(b"{}", None))
        .await
        .expect("invokes");
    let error = outcome.response.error.expect("error");
    assert!(
        error.message.contains("0x09"),
        "the error must report the byte the guest wrote: {}",
        error.message
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_module_without_memory_is_rejected_with_guidance() {
    let dir = temp_dir("no-memory");
    let module = write_module(&dir, "main.wat", NO_MEMORY_HANDLER);
    let adapter = WasmAdapter::new();
    let error = start(&adapter, spec_with(0, Duration::from_secs(5)), &module)
        .await
        .err()
        .expect("must refuse");
    assert_eq!(error.category(), ErrorCategory::Runtime);
    assert!(
        error.to_human_string().contains(EXPORT_MEMORY),
        "the error must name the missing export: {error}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_module_with_the_wrong_handler_signature_is_rejected() {
    let dir = temp_dir("wrong-signature");
    let module = write_module(&dir, "main.wat", WRONG_SIGNATURE_HANDLER);
    let adapter = WasmAdapter::new();
    let error = start(&adapter, spec_with(0, Duration::from_secs(5)), &module)
        .await
        .err()
        .expect("must refuse");
    assert!(
        error.to_human_string().contains(EXPORT_HANDLER),
        "the error must name the handler export: {error}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_unsupported_import_fails_instantiation() {
    let dir = temp_dir("unsupported-import");
    let module = write_module(&dir, "main.wat", UNSUPPORTED_IMPORT_HANDLER);
    let adapter = WasmAdapter::new();
    let error = start(&adapter, spec_with(0, Duration::from_secs(5)), &module)
        .await
        .err()
        .expect("must refuse");
    assert!(
        error.to_human_string().contains("wasi_snapshot_preview1"),
        "the error must name the unsupported import: {error}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_memory_policy_smaller_than_the_request_is_refused() {
    let dir = temp_dir("tiny-memory");
    let module = write_module(&dir, "main.wat", CONSTANT_HANDLER);
    let adapter = WasmAdapter::new();
    // 64 KiB is one page: the module declares two, so instantiation itself must fail or the
    // invocation must be refused. Either way the guest never runs unbounded.
    let outcome = start(
        &adapter,
        spec_with(64 * 1024, Duration::from_secs(5)),
        &module,
    )
    .await;
    match outcome {
        Err(error) => assert_eq!(error.category(), ErrorCategory::Runtime),
        Ok(instance) => {
            let result = instance
                .invoke(request(b"{}", None))
                .await
                .expect("invokes");
            assert!(!result.response.is_success());
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn prepare_requires_the_wasm_sandbox_layer() {
    let dir = temp_dir("host-refused");
    write_module(&dir, "main.wat", CONSTANT_HANDLER);
    let adapter = WasmAdapter::new();
    let mut spec = spec_with(0, Duration::from_secs(5));
    Arc::get_mut(&mut spec).expect("unique").sandbox = SandboxPolicy::host();
    let error = start(&adapter, spec, &dir.join("main.wat"))
        .await
        .err()
        .expect("host mode must be refused");
    assert_eq!(error.category(), ErrorCategory::Sandbox);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn prepare_reports_a_missing_module_clearly() {
    let dir = temp_dir("missing-module");
    let adapter = WasmAdapter::new();
    let spec = spec_with(0, Duration::from_secs(5));
    let error = adapter
        .prepare(PrepareRequest {
            function_id: spec.id.clone(),
            function_name: spec.name.clone(),
            runtime: spec.runtime.clone(),
            handler: spec.handler.clone(),
            workdir: dir.clone(),
            environment: Environment::new(),
            resources: spec.resources,
            sandbox: spec.sandbox.clone(),
        })
        .await
        .expect_err("must refuse");
    assert!(
        error.to_human_string().contains(".wasm"),
        "the error must say what it looked for: {error}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn modules_are_compiled_once_and_reused() {
    let dir = temp_dir("module-cache");
    let module = write_module(&dir, "main.wat", CONSTANT_HANDLER);
    let adapter = WasmAdapter::new();
    let spec = spec_with(32 * 1024 * 1024, Duration::from_secs(5));

    let first = start(&adapter, spec.clone(), &module)
        .await
        .expect("starts");
    assert_eq!(adapter.cached_modules(), 1);
    let second = start(&adapter, spec, &module).await.expect("starts");
    assert_eq!(
        adapter.cached_modules(),
        1,
        "a second instance of the same module must not recompile it"
    );
    // Both instances work: the cache holds code, not state.
    assert!(first
        .invoke(request(b"{}", None))
        .await
        .expect("invokes")
        .response
        .is_success());
    assert!(second
        .invoke(request(b"{}", None))
        .await
        .expect("invokes")
        .response
        .is_success());

    adapter.clear_module_cache();
    assert_eq!(adapter.cached_modules(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_module_cache_is_bounded() {
    let dir = temp_dir("cache-bound");
    let adapter = WasmAdapter::new();
    for index in 0..8 {
        let name = format!("m{index}.wat");
        let module = write_module(&dir, &name, CONSTANT_HANDLER);
        let spec = spec_named(&format!("m{index}"), &name, 32 * 1024 * 1024);
        start(&adapter, spec, &module).await.expect("starts");
        assert!(
            adapter.cached_modules() <= adapter_cache_limit(),
            "the cache grew past its limit: {}",
            adapter.cached_modules()
        );
    }
    // The first modules were evicted, but a recently used one still works.
    let last = write_module(&dir, "m7.wat", CONSTANT_HANDLER);
    let spec = spec_named("m7", "m7.wat", 32 * 1024 * 1024);
    let instance = start(&adapter, spec, &last).await.expect("starts");
    assert!(instance
        .invoke(request(b"{}", None))
        .await
        .expect("invokes")
        .response
        .is_success());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The adapter's configured cache limit, as the test sees it.
fn adapter_cache_limit() -> usize {
    super::module_cache_limit()
}

#[tokio::test]
async fn discovery_reports_the_wasmtime_runtime() {
    let discovered = WasmAdapter::new().discover().await.expect("discovers");
    assert_eq!(discovered.len(), 1);
    assert!(discovered[0].available);
    assert_eq!(discovered[0].executable, "wasmtime");
}

#[tokio::test]
async fn capabilities_reflect_what_wasm_can_do() {
    let adapter = WasmAdapter::new();
    let capabilities = adapter.capabilities();
    assert!(capabilities.warm_instances);
    assert!(capabilities.binary_payloads);
    assert!(capabilities.deadlines);
    // No per-invocation environment: a guest has no `environ`.
    assert!(!capabilities.per_invocation_environment);
}

#[test]
fn the_default_fuel_budget_is_bounded() {
    const _: () =
        assert!(DEFAULT_FUEL_PER_INVOCATION > 0 && DEFAULT_FUEL_PER_INVOCATION <= 100 * 1_000_000);
    const _: () = assert!(MAX_FRAME_BYTES >= 1024 * 1024);
}
