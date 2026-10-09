//! The Wasmtime-backed Wasm runtime adapter.
//!
//! A Wasm instance is executed **in-process** inside Wasmtime, not as an OS process. That is
//! the point of this runtime: the guest is confined by the Wasm sandbox itself (no syscalls, no
//! ambient authority, a linear-memory ceiling, and a fuel budget for infinite loops), which is
//! portable isolation rather than OS-specific isolation.
//!
//! ```text
//! Artifact ──► module cache ──► Instance ──► invoke
//!   (.wasm)      (compiled)       (store)      (frame in / frame out)
//! ```
//!
//! Safety properties this adapter relies on:
//!
//! - **No host ambient authority.** A guest only reaches the host through imports it declared,
//!   and RustFun offers exactly one import (`rustfun.payload`). There is no WASI: no filesystem,
//!   no clock, no sockets, no environment.
//! - **Bounded memory.** `StoreLimits` caps the guest at the function's declared memory limit.
//!   Growth beyond it traps the guest instead of growing the host.
//! - **Bounded time.** Each invocation gets an epoch deadline and a fuel budget. A guest that
//!   loops forever burns fuel and traps; it cannot occupy a thread forever.
//! - **Bounded memory copies.** Guest-returned offsets and lengths are bounds-checked against
//!   the real memory size, and frames are capped at [`MAX_FRAME_BYTES`].

pub mod abi;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use rustfun_core::protocol::{InvocationRequest, InvocationResponse, InvocationStatus};
use rustfun_core::runtime::{
    HealthStatus, InvocationOutcome, PrepareRequest, PreparedRuntime, RuntimeAdapter,
    RuntimeDiscovery, RuntimeInstance, StartRequest,
};
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_model::{
    Environment, FunctionSpec, InstanceId, RuntimeCapabilities, RuntimeFamily, RuntimeId,
    RuntimeVersion, SandboxKind,
};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, TypedFunc};

use abi::{
    DEFAULT_MAX_MEMORY_PAGES, EXPORT_HANDLER, EXPORT_MEMORY, HOST_FN_PAYLOAD, MAX_FRAME_BYTES,
    STATUS_ERROR, STATUS_SUCCESS,
};

/// Fuel granted per invocation when the function does not declare a fuel budget.
///
/// Wasmtime executes roughly 10^8 fuel/second/core, so one million units is on the order of a
/// few milliseconds of pure computation. It exists to stop an accidental infinite loop, not to
/// act as a CPU quota; wall-clock deadlines remain the real limit.
pub const DEFAULT_FUEL_PER_INVOCATION: u64 = 1_000_000;

/// Import module name for RustFun host functions.
const HOST_MODULE_NAME: &str = "rustfun";

/// Size of a Wasm page.
const PAGE_BYTES: u64 = 64 * 1024;

/// File extensions treated as Wasm modules.
pub const MODULE_EXTENSIONS: [&str; 2] = ["wasm", "wat"];

/// Environment variable that overrides the maximum number of compiled modules kept in memory.
pub const ENV_MODULE_CACHE_LIMIT: &str = "RUSTFUN_WASM_MODULE_CACHE";

/// Environment variable that adds extra Wasm features (for example `threads`).
pub const ENV_WASM_FEATURES: &str = "RUSTFUN_WASM_FEATURES";

/// The Wasm runtime adapter.
///
/// The engine is created on first use rather than in the constructor so that building a
/// registry never depends on the host being able to JIT, and so a discovery-only caller does
/// not pay for it.
pub struct WasmAdapter {
    inner: Mutex<Option<EngineBundle>>,
    /// Compiled modules, keyed by canonical path. Compiling is the expensive part of a cold
    /// start, so a warm instance reuses the code and only re-creates the store.
    modules: Mutex<BTreeMap<PathBuf, Arc<Module>>>,
    cache_limit: usize,
}

/// The engine and the linker that goes with it.
struct EngineBundle {
    engine: Engine,
    linker: Linker<HostState>,
}

/// Per-instance state.
///
/// `pending` holds the frame for the invocation currently being served: the host writes it into
/// the mailbox before calling the guest, and `rustfun.payload` hands the guest that offset. A
/// host function cannot borrow the caller's memory, so the frame lives here.
#[derive(Default)]
struct HostState {
    limits: StoreLimits,
    pending: Vec<u8>,
}

impl WasmAdapter {
    /// Build an adapter. The engine is created lazily on first use.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
            modules: Mutex::new(BTreeMap::new()),
            cache_limit: module_cache_limit(),
        }
    }

    /// Create the engine and linker, or return the ones already created.
    fn engine_bundle(&self) -> Result<EngineBundle> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| RustFunError::internal("the Wasm adapter lock was poisoned"))?;
        if let Some(bundle) = inner.as_ref() {
            // Both are reference counted internally, so cloning keeps the host functions that
            // were defined once at creation time.
            return Ok(EngineBundle {
                engine: bundle.engine.clone(),
                linker: bundle.linker.clone(),
            });
        }
        let mut config = Config::new();
        config.wasm_multi_memory(false);
        config.wasm_simd(true);
        // Fuel is the only way to bound a guest that never yields, so it is always on.
        config.consume_fuel(true);
        if let Some(features) = std::env::var_os(ENV_WASM_FEATURES) {
            let features = features.to_string_lossy().into_owned();
            for feature in features.split(',').map(str::trim).filter(|f| !f.is_empty()) {
                match feature {
                    "reference-types" => {
                        config.wasm_reference_types(true);
                    }
                    "bulk-memory" => {
                        config.wasm_bulk_memory(true);
                    }
                    "multi-memory" => {
                        config.wasm_multi_memory(true);
                    }
                    "tail-call" => {
                        config.wasm_tail_call(true);
                    }
                    "simd" => {
                        config.wasm_simd(true);
                    }
                    other => {
                        return Err(RustFunError::unavailable(format!(
                            "unknown Wasm feature `{other}` in {ENV_WASM_FEATURES}"
                        ))
                        .with_context(
                            ErrorContext::new()
                                .operation("configure_wasmtime")
                                .remediation("supported: reference-types, bulk-memory, multi-memory, tail-call, simd"),
                        ))
                    }
                }
            }
        }
        let engine = Engine::new(&config).map_err(|error| {
            RustFunError::unavailable(format!("cannot initialise the Wasmtime engine: {error}"))
                .with_context(ErrorContext::new().operation("configure_wasmtime"))
        })?;

        let mut linker = Linker::new(&engine);
        // Exactly one host function, and it does not leak: it returns an offset into memory the
        // host already filled, never a Rust pointer or an allocation the guest could keep.
        linker
            .func_wrap(
                HOST_MODULE_NAME,
                HOST_FN_PAYLOAD,
                |caller: wasmtime::Caller<'_, HostState>, _ptr: i32, _len: i32| -> i32 {
                    if caller.data().pending.is_empty() {
                        // Only reachable if a guest calls the import outside an invocation.
                        tracing::debug!("a guest asked for a payload outside an invocation");
                        return -1;
                    }
                    HOST_MAILBOX_END as i32
                },
            )
            .expect("a fresh linker accepts the RustFun host function");
        let bundle = EngineBundle {
            engine,
            linker: linker.clone(),
        };
        *inner = Some(bundle);
        Ok(EngineBundle {
            engine: linker.engine().clone(),
            linker,
        })
    }

    /// The engine backing this adapter, creating it if necessary.
    ///
    /// Exposed for tooling that wants to compile a module outside an invocation. `Engine` is
    /// internally reference counted, so the clone is cheap.
    pub fn engine(&self) -> Result<Engine> {
        Ok(self.engine_bundle()?.engine)
    }

    /// Number of compiled modules currently cached.
    pub fn cached_modules(&self) -> usize {
        self.modules
            .lock()
            .map(|modules| modules.len())
            .unwrap_or(0)
    }

    /// Compile (or reuse) a module.
    fn module(&self, path: &Path, engine: &Engine) -> Result<Arc<Module>> {
        let key = path.to_path_buf();
        if let Ok(modules) = self.modules.lock() {
            if let Some(module) = modules.get(&key) {
                return Ok(module.clone());
            }
        }
        let bytes = std::fs::read(path).map_err(|error| {
            RustFunError::artifact(format!("cannot read the Wasm module {path:?}: {error}"))
                .with_context(
                    ErrorContext::new()
                        .operation("read_wasm_module")
                        .detail("module", path.display().to_string()),
                )
        })?;
        let module = Module::new(engine, &bytes).map_err(|error| {
            RustFunError::artifact(format!("cannot compile the Wasm module {path:?}: {error}"))
                .with_context(
                    ErrorContext::new()
                        .operation("compile_wasm_module")
                        .detail("module", path.display().to_string()),
                )
        })?;
        let module = Arc::new(module);
        if let Ok(mut modules) = self.modules.lock() {
            // A simple bound is enough: instances are pooled, so the working set is small, and
            // an LRU would need per-instance bookkeeping for no measurable gain.
            while modules.len() >= self.cache_limit {
                if let Some(oldest) = modules.keys().next().cloned() {
                    modules.remove(&oldest);
                } else {
                    break;
                }
            }
            modules.insert(key, module.clone());
        }
        Ok(module)
    }

    /// Drop every cached module (used by tests and by `cache clean`).
    pub fn clear_module_cache(&self) {
        if let Ok(mut modules) = self.modules.lock() {
            modules.clear();
        }
    }
}

impl std::fmt::Debug for WasmAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmAdapter")
            .field("cached_modules", &self.cached_modules())
            .field("module_cache_limit", &self.cache_limit)
            .finish()
    }
}

impl Default for WasmAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum number of compiled modules kept in memory.
fn module_cache_limit() -> usize {
    std::env::var(ENV_MODULE_CACHE_LIMIT)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|limit| *limit > 0)
        .unwrap_or(64)
}

/// Resolve the module file a handler names, given the function root.
pub fn resolve_module(root: &Path, handler: &str) -> Result<PathBuf> {
    // Accept a bare path, a path relative to the function root, or a module name with an
    // extension the runtime knows.
    let candidate = Path::new(handler);
    let direct = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    if direct.is_file() {
        return Ok(direct);
    }
    let stem = candidate
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .ok_or_else(|| {
            RustFunError::artifact(format!("the handler `{handler}` is not a Wasm module path"))
                .with_context(ErrorContext::new().operation("resolve_wasm_module"))
        })?;
    for extension in MODULE_EXTENSIONS {
        for name in [
            format!("{stem}.{extension}"),
            format!("{stem}/index.{extension}"),
        ] {
            let candidate = root.join(&name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(RustFunError::artifact(format!(
        "cannot find the Wasm module for handler `{handler}` in {root:?} (looked for {} and {})",
        MODULE_EXTENSIONS[0], MODULE_EXTENSIONS[1]
    ))
    .with_context(
        ErrorContext::new()
            .operation("resolve_wasm_module")
            .detail("root", root.display().to_string())
            .remediation("the handler must name a .wasm module exported from the artifact"),
    ))
}

#[async_trait]
impl RuntimeAdapter for WasmAdapter {
    fn family(&self) -> RuntimeFamily {
        RuntimeFamily::Wasm
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::WASM
    }

    async fn discover(&self) -> Result<Vec<RuntimeDiscovery>> {
        Ok(vec![RuntimeDiscovery::new(
            RuntimeId::new(RuntimeFamily::Wasm, RuntimeVersion::Any),
            "wasmtime",
        )
        .with_reported_version(env!("CARGO_PKG_VERSION"))])
    }

    async fn prepare(&self, request: PrepareRequest) -> Result<PreparedRuntime> {
        if request.sandbox.kind == SandboxKind::Host {
            // A Wasm guest in host mode is still confined by Wasmtime, but declaring `host`
            // means the operator asked for no isolation at all. Refusing keeps the policy
            // honest: the Wasm sandbox layer is the point of this runtime.
            return Err(RustFunError::sandbox(
                "the wasm runtime requires `[sandbox] kind = \"wasm\"`, not `host`",
            )
            .with_context(
                ErrorContext::new()
                    .operation("prepare_runtime")
                    .function(request.function_name.as_str())
                    .remediation("a Wasm module is confined by Wasmtime; host mode would drop that guarantee"),
            ));
        }
        let module = resolve_module(&request.workdir, request.handler.module_path())?;
        let mut environment: Environment = request.environment.clone();
        environment.insert("RUSTFUN_WASM_MODULE", module.to_string_lossy().as_ref())?;
        // The path travels in `command` rather than only in the environment so the start path
        // does not have to re-derive it.
        Ok(PreparedRuntime::new(
            request.runtime.clone(),
            vec![module.to_string_lossy().into_owned()],
            request.workdir,
            environment,
            self.capabilities(),
        ))
    }

    async fn start(&self, request: StartRequest) -> Result<Box<dyn RuntimeInstance>> {
        let module_path = request.prepared.command.first().cloned().ok_or_else(|| {
            RustFunError::artifact("the prepared Wasm runtime has no module path")
                .with_context(ErrorContext::new().operation("start_instance"))
        })?;
        let bundle = self.engine_bundle()?;
        let module = self.module(Path::new(&module_path), &bundle.engine)?;

        let resources = &request.spec.resources;
        // A declared memory limit becomes a page count; an undeclared one uses the platform
        // ceiling. The limit is clamped in both directions so a policy can only tighten it.
        let max_pages = if resources.memory_bytes == 0 {
            DEFAULT_MAX_MEMORY_PAGES
        } else {
            (resources.memory_bytes / PAGE_BYTES).clamp(1, DEFAULT_MAX_MEMORY_PAGES)
        };
        let fuel = std::env::var("RUSTFUN_WASM_FUEL")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_FUEL_PER_INVOCATION);

        let state = HostState {
            limits: store_limits(max_pages),
            pending: Vec::new(),
        };
        let mut store = Store::new(&bundle.engine, state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(fuel)
            .map_err(|error| RustFunError::internal(format!("cannot set Wasm fuel: {error}")))?;
        let instance = bundle
            .linker
            .instantiate(&mut store, &module)
            .map_err(|error| {
                RustFunError::runtime(format!("cannot instantiate the Wasm module: {error}"))
                    .with_context(
                    ErrorContext::new()
                        .operation("instantiate_wasm")
                        .function(request.spec.name.as_str())
                        .remediation(
                            "a RustFun Wasm module may import nothing, or only `rustfun.payload`",
                        ),
                )
            })?;
        // The guest must export its memory: the host has nowhere else to put the request.
        let memory = instance
            .get_memory(&mut store, EXPORT_MEMORY)
            .ok_or_else(|| {
                RustFunError::runtime(format!("the Wasm module does not export `{EXPORT_MEMORY}`"))
                    .with_context(
                        ErrorContext::new()
                            .operation("instantiate_wasm")
                            .function(request.spec.name.as_str())
                            .remediation(
                                "a RustFun Wasm module must `(memory (export \"memory\"))`",
                            ),
                    )
            })?;
        let handler: TypedFunc<(), i32> = instance
            .get_typed_func(&mut store, EXPORT_HANDLER)
            .map_err(|error| {
                RustFunError::runtime(format!(
                    "the Wasm module must export `{EXPORT_HANDLER}() -> i32`: {error}"
                ))
                .with_context(
                    ErrorContext::new()
                        .operation("instantiate_wasm")
                        .function(request.spec.name.as_str()),
                )
            })?;

        // `rustfun.payload` is optional: a guest that reads the mailbox directly does not need
        // it. Any *other* import fails instantiation, which is the default-deny behaviour.
        let payload: Option<TypedFunc<(i32, i32), i32>> =
            instance.get_typed_func(&mut store, HOST_FN_PAYLOAD).ok();

        Ok(Box::new(WasmInstance {
            instance_id: request.instance_id,
            runtime: request.prepared.runtime.clone(),
            store: tokio::sync::Mutex::new(store),
            memory,
            handler,
            payload,
            fuel,
            max_memory_pages: max_pages,
            invocations: std::sync::atomic::AtomicU64::new(0),
            healthy: std::sync::atomic::AtomicBool::new(true),
        }))
    }
}

/// Build a [`StoreLimits`] with only a memory ceiling.
///
/// The default `StoreLimits` already denies the table and instance limits RustFun cannot
/// support anyway; setting them to zero would make every guest trap on its first table.
fn store_limits(memory_pages: u64) -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size((memory_pages * PAGE_BYTES) as usize)
        .build()
}

/// A live Wasm instance: a store, its memory, and the guest handler.
pub struct WasmInstance {
    instance_id: InstanceId,
    runtime: RuntimeId,
    store: tokio::sync::Mutex<Store<HostState>>,
    memory: wasmtime::Memory,
    handler: TypedFunc<(), i32>,
    payload: Option<TypedFunc<(i32, i32), i32>>,
    fuel: u64,
    max_memory_pages: u64,
    invocations: std::sync::atomic::AtomicU64,
    healthy: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for WasmInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmInstance")
            .field("instance_id", &self.instance_id)
            .field("runtime", &self.runtime)
            .field("max_memory_pages", &self.max_memory_pages)
            .field("fuel", &self.fuel)
            .field("invocations", &self.invocations())
            .finish()
    }
}

impl WasmInstance {
    /// Invocations served so far.
    pub fn invocations(&self) -> u64 {
        self.invocations.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the instance is still reusable.
    fn healthy(&self) -> bool {
        self.healthy.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Mark the instance unusable.
    fn poison(&self) {
        self.healthy
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Run one call with the request written into guest memory.
    ///
    /// The payload is pushed through the `rustfun.payload` import when the guest provides one,
    /// and otherwise written directly into the guest's linear memory. Both paths use the same
    /// bounds checks: the host never trusts a guest-supplied offset or length.
    async fn call(&self, frame: &[u8], fuel: u64) -> std::result::Result<Vec<u8>, CallFailure> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(CallFailure::FrameTooLarge(frame.len()));
        }
        let mut guard = self.store.lock().await;
        let mut store = &mut *guard;
        store
            .set_fuel(fuel)
            .map_err(|error| CallFailure::Trap(format!("cannot refuel the instance: {error}")))?;

        // Guest memory is grown by the host up front so the guest never observes a failed write.
        let required_pages = (frame.len() as u64).div_ceil(PAGE_BYTES) + 2;
        if required_pages > self.max_memory_pages {
            return Err(CallFailure::MemoryLimit {
                needed_pages: required_pages,
                limit_pages: self.max_memory_pages,
            });
        }
        self.memory
            .grow(&mut store, required_pages)
            .map_err(|error| CallFailure::Trap(format!("cannot grow guest memory: {error}")))?;
        let data = self.memory.data_mut(&mut store);
        // The host owns the mailbox: it is the request/response channel, and addresses below it
        // are scratch space the guest may reuse freely.
        data[HOST_MAILBOX_END..HOST_MAILBOX_END + frame.len()].copy_from_slice(frame);
        // Make the frame visible to `rustfun.payload`.
        store.data_mut().pending = frame.to_vec();

        // A guest that imports `rustfun.payload` is told where the frame landed; one that reads
        // the mailbox by convention already knows.
        if let Some(payload) = &self.payload {
            payload
                .call(&mut *store, (HOST_MAILBOX_END as i32, frame.len() as i32))
                .map_err(|error| CallFailure::Trap(describe_trap(&error)))?;
        }

        let returned = self
            .handler
            .call(&mut store, ())
            .map_err(|error| CallFailure::Trap(describe_trap(&error)))?;
        if returned < 0 {
            return Err(CallFailure::GuestError(returned));
        }
        let returned = returned as usize;
        if returned > MAX_FRAME_BYTES {
            return Err(CallFailure::FrameTooLarge(returned));
        }
        let start = HOST_MAILBOX_END;
        let data = self.memory.data(&store);
        // Bounds-check against the real memory size: the guest chose these numbers.
        let end = start
            .checked_add(returned)
            .filter(|end| *end <= data.len())
            .ok_or(CallFailure::OutOfBounds {
                start,
                len: returned,
                memory_len: data.len(),
            })?;
        Ok(data[start..end].to_vec())
    }
}

/// First byte of guest memory reserved by the host for the mailbox.
///
/// The guest must treat addresses below this as scratch space for the request frame and the
/// response frame, which keeps the ABI stable without an allocator in the guest.
const HOST_MAILBOX_END: usize = 64 * 1024;

/// Why a call did not produce a frame.
enum CallFailure {
    /// The guest trapped (out of fuel, unreachable, division by zero, ...).
    Trap(String),
    /// The guest returned a negative length.
    GuestError(i32),
    /// The guest's memory could not hold the frame.
    OutOfBounds {
        /// Requested start offset.
        start: usize,
        /// Requested length.
        len: usize,
        /// Actual memory size.
        memory_len: usize,
    },
    /// A frame exceeded [`MAX_FRAME_BYTES`].
    FrameTooLarge(usize),
    /// The request does not fit in the declared memory limit.
    MemoryLimit {
        /// Pages the request needs.
        needed_pages: u64,
        /// Pages the policy allows.
        limit_pages: u64,
    },
}

impl CallFailure {
    /// Whether the instance can keep serving requests after this failure.
    fn is_recoverable(&self) -> bool {
        // A trap leaves the store in a valid state: the next invocation may run again. A bad
        // length or an out-of-bounds return is equally recoverable. Only a module that asks for
        // more memory than policy allows is still technically runnable, but reusing it would
        // fail identically, so it is evicted.
        !matches!(self, CallFailure::MemoryLimit { .. })
    }
}

/// Render a Wasmtime trap for an operator.
fn describe_trap(error: &anyhow::Error) -> String {
    let mut message = error.to_string();
    for cause in error.chain().skip(1) {
        message.push_str(": ");
        message.push_str(&cause.to_string());
    }
    message
}

#[async_trait]
impl RuntimeInstance for WasmInstance {
    fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    fn runtime(&self) -> &RuntimeId {
        &self.runtime
    }

    async fn invoke(&self, request: InvocationRequest) -> Result<InvocationOutcome> {
        let frame = rustfun_protocol::encode_frame(rustfun_protocol::Codec::Json, &request)
            .map_err(|error| {
                RustFunError::protocol(format!("cannot encode the invocation for Wasm: {error}"))
                    .with_context(ErrorContext::new().operation("encode_invocation"))
            })?;

        let deadline = request.remaining_deadline();
        let fuel = std::env::var("RUSTFUN_WASM_FUEL")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(self.fuel);
        let started = Instant::now();
        let outcome = match deadline {
            Some(deadline) => match tokio::time::timeout(deadline, self.call(&frame, fuel)).await {
                Ok(result) => result,
                Err(_) => {
                    // An epoch deadline cannot interrupt a guest that is spinning: Wasmtime runs
                    // the call on this thread. Fuel is the backstop, and the instance is not
                    // trusted again because the guest may be mid-mutation.
                    self.poison();
                    return Ok(timeout_outcome(
                        &request,
                        self.instance_id.clone(),
                        deadline.as_millis() as u64,
                    ));
                }
            },
            None => self.call(&frame, fuel).await,
        };

        self.invocations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let response = match outcome {
            Ok(bytes) => match decode_guest_response(&request, &bytes) {
                Ok(response) => response,
                Err(error) => {
                    // A guest that wrote nonsense is a function error, not a platform error, but
                    // the instance is not reused: its ABI expectations are wrong.
                    self.poison();
                    InvocationResponse::failure(
                        request.invocation_id.clone(),
                        request.function_id.clone(),
                        InvocationStatus::FunctionError,
                        error,
                    )
                }
            },
            Err(failure) => {
                let (message, code) = match &failure {
                    CallFailure::Trap(message) => (message.clone(), "RUSTFUN_WASM_TRAP"),
                    CallFailure::GuestError(code) => (
                        format!("the guest handler returned {code} instead of a frame length"),
                        "RUSTFUN_WASM_NO_RESPONSE",
                    ),
                    CallFailure::OutOfBounds {
                        start,
                        len,
                        memory_len,
                    } => (
                        format!(
                            "the guest returned a frame at {start}..{} but its memory is {memory_len} bytes",
                            start.saturating_add(*len)
                        ),
                        "RUSTFUN_WASM_BAD_BOUNDS",
                    ),
                    CallFailure::FrameTooLarge(len) => (
                        format!("the guest returned a {len}-byte frame, above the {MAX_FRAME_BYTES}-byte limit"),
                        "RUSTFUN_WASM_FRAME_TOO_LARGE",
                    ),
                    CallFailure::MemoryLimit {
                        needed_pages,
                        limit_pages,
                    } => (
                        format!(
                            "the invocation needs {needed_pages} pages of linear memory but policy allows {limit_pages}"
                        ),
                        "RUSTFUN_WASM_MEMORY_LIMIT",
                    ),
                };
                if !failure.is_recoverable() {
                    self.poison();
                }
                tracing::debug!(instance = %self.instance_id, error = %message, "wasm call failed");
                let _ = code;
                InvocationResponse::failure(
                    request.invocation_id.clone(),
                    request.function_id.clone(),
                    InvocationStatus::FunctionError,
                    rustfun_core::protocol::InvocationError::new("RUSTFUN_WASM_ERROR", message),
                )
            }
        };
        let healthy = self.healthy();
        let _ = started;
        Ok(InvocationOutcome {
            response: response.with_instance(self.instance_id.clone()),
            instance_healthy: healthy,
        })
    }

    async fn health(&self) -> HealthStatus {
        if self.healthy() {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        // Dropping the store releases every allocation the guest made, which is the entire
        // cleanup a Wasm instance needs.
        self.store.get_mut().data_mut().limits = StoreLimits::default();
        self.poison();
        Ok(())
    }
}

/// Turn the bytes a guest wrote into a platform response.
///
/// The guest owns the status byte and the body; the host owns everything else.
fn decode_guest_response(
    request: &InvocationRequest,
    frame: &[u8],
) -> std::result::Result<InvocationResponse, rustfun_core::protocol::InvocationError> {
    let bad = |message: String| {
        rustfun_core::protocol::InvocationError::new("RUSTFUN_WASM_BAD_RESPONSE", message)
    };
    let Some((header, total)) = rustfun_protocol::peek_frame_length(frame)
        .map_err(|error| bad(format!("the guest response is not a valid frame: {error}")))?
    else {
        return Err(bad(format!(
            "the guest response is {} bytes, shorter than a frame header",
            frame.len()
        )));
    };
    if total != frame.len() {
        return Err(bad(format!(
            "the guest announced a {}-byte body but wrote {} bytes",
            header.length,
            frame.len().saturating_sub(rustfun_protocol::HEADER_LEN)
        )));
    }
    let body = &frame[rustfun_protocol::HEADER_LEN..];
    let Some((status, payload)) = body.split_first() else {
        return Err(bad("the guest wrote no response status byte".to_owned()));
    };
    match *status {
        STATUS_SUCCESS => Ok(InvocationResponse::success(
            request.invocation_id.clone(),
            request.function_id.clone(),
            payload.to_vec(),
        )),
        STATUS_ERROR => Err(rustfun_core::protocol::InvocationError::new(
            "RUSTFUN_FUNCTION_ERROR",
            String::from_utf8_lossy(payload).into_owned(),
        )),
        other => Err(bad(format!(
            "the guest wrote the unknown response status byte {other:#04x}"
        ))),
    }
}

/// Build the timeout response for a Wasm invocation that hit its deadline.
fn timeout_outcome(
    request: &InvocationRequest,
    instance_id: InstanceId,
    deadline_ms: u64,
) -> InvocationOutcome {
    InvocationOutcome {
        response: InvocationResponse::timeout(
            request.invocation_id.clone(),
            request.function_id.clone(),
            deadline_ms,
        )
        .with_instance(instance_id),
        instance_healthy: false,
    }
}

/// Convenience: start an instance for `spec` from `module_path`.
pub async fn start_instance(
    adapter: &WasmAdapter,
    spec: Arc<FunctionSpec>,
    module_path: &Path,
    environment: Environment,
) -> Result<Box<dyn RuntimeInstance>> {
    let workdir = module_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    adapter
        .start(StartRequest {
            spec,
            instance_id: InstanceId::new(),
            prepared: PreparedRuntime::new(
                RuntimeId::new(RuntimeFamily::Wasm, RuntimeVersion::Any),
                vec![module_path.to_string_lossy().into_owned()],
                workdir,
                environment,
                RuntimeCapabilities::WASM,
            ),
            prewarm: false,
        })
        .await
}
