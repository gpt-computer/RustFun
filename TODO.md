# RustFun — Full Implementation TODO

> Rust-native successor to `vercel/fun`: a function execution kernel with runtime adapters, artifacts, warm instances, sandboxing, observability, and a path to WASM/OCI and distributed execution.

**Status legend:** `[x]` implemented and tested · `[~]` partially implemented (the note says what is missing) · `[ ]` not implemented.

`[~]` entries are deliberate: they record work that is *real but partial*, so the checklist
never claims more than the repository delivers. See `PROGRESS.md` for the current phase and
`DECISIONS.md` for the reasoning behind each design choice.

## 0. Product Definition
- [x] Define project name and package identity
- [x] Define compatibility target with `vercel/fun`
- [x] Define scope and non-goals
- [x] Define supported OS/architectures
- [x] Define runtime support policy
- [x] Define security model
- [x] Define local-development UX
- [x] Define production execution model
- [x] Create README.md
- [x] Create ARCHITECTURE.md
- [x] Create SECURITY.md
- [x] Create COMPATIBILITY.md
- [x] Create CONTRIBUTING.md

## 1. Repository & Cargo Workspace
- [x] Root Cargo workspace
- [x] Shared dependencies
- [x] Rust edition/lints/profiles
- [ ] `rustfun-model`
- [ ] `rustfun-protocol`
- [ ] `rustfun-core`
- [ ] `rustfun-runtime`
- [ ] `rustfun-process`
- [ ] `rustfun-instance`
- [ ] `rustfun-invoke`
- [ ] `rustfun-cli`
- [ ] `rustfun-config`
- [ ] `rustfun-test`
- [x] Establish dependency DAG
- [x] Prevent circular dependencies
- [x] Add crate docs and test skeletons

## 2. Core Domain Model
- [x] FunctionId
- [x] FunctionName
- [x] FunctionSpec
- [x] FunctionStatus
- [x] FunctionMetadata
- [x] FunctionSource
- [x] HandlerSpec
- [x] RuntimeId
- [x] RuntimeFamily
- [x] RuntimeVersion
- [x] RuntimeCapabilities
- [x] Environment
- [x] ResourceLimits
- [x] Serialization/deserialization
- [x] Stable identifiers and digests

## 3. Configuration System
- [x] `rustfun.toml` manifest
- [x] TOML parser
- [~] JSON support
- [x] Environment interpolation
- [x] CLI overrides
- [x] Defaults
- [x] Validation
- [x] Schema versioning
- [ ] Migration support

Example:
```toml
name = "hello"
runtime = "node@24"
handler = "index.handler"

[build]
source = "."

[resources]
memory = "512MiB"
timeout = "30s"

[environment]
HELLO = "world"
```

## 4. Runtime Registry
- [x] RuntimeAdapter trait
- [x] RuntimeInstance trait
- [x] RuntimeRegistry
- [x] RuntimeCapabilities
- [x] Runtime discovery
- [x] Runtime aliases
- [x] Version matching
- [x] Capability negotiation
- [x] Runtime health checks

## 5. Process Engine
- [x] Process spawning
- [x] stdin/stdout/stderr
- [x] working directory
- [x] environment injection
- [x] process groups
- [x] signal handling
- [x] exit handling
- [x] graceful shutdown
- [x] force kill
- [x] timeout kill
- [x] child-process cleanup
- [x] zombie prevention
- [x] Unix/macOS strategy
- [x] Linux strategy

## 6. Invocation Protocol
- [x] InvocationRequest
- [x] InvocationResponse
- [x] Request/Invocation/Function IDs
- [x] payload
- [x] deadline
- [x] metadata
- [x] tracing context
- [x] success/error/timeout semantics
- [x] JSON encoding
- [x] MessagePack/CBOR option
- [x] binary framing
- [x] stdin/stdout transport
- [x] Unix socket transport
- [x] HTTP transport
- [~] streaming

## 7. Function Runtime
- [x] FunctionManager
- [x] create
- [x] get
- [x] list
- [x] invoke
- [x] destroy
- [x] lifecycle state machine
- [x] cancellation
- [x] lifecycle events
- [x] invalid-transition protection
- [x] cleanup guarantees

## 8. Node.js Runtime
- [x] Node discovery
- [x] version detection
- [x] version compatibility
- [x] CommonJS
- [x] ESM
- [x] handler resolution
- [x] async handlers
- [x] Promise support
- [x] errors
- [x] environment
- [x] filesystem
- [x] timeout
- [x] repeated invocation
- [x] runtime conformance tests

## 9. Python Runtime
- [x] Python discovery
- [x] version detection
- [x] module resolution
- [x] handler resolution
- [x] sync functions
- [x] async functions
- [x] exceptions
- [x] environment
- [x] filesystem
- [x] virtualenv support
- [x] timeout
- [x] repeated invocation
- [x] runtime conformance tests

## 10. Generic Executable Runtime
- [x] Executable discovery
- [x] command/args
- [x] environment
- [x] stdin protocol
- [x] stdout protocol
- [x] stderr
- [x] exit codes
- [x] timeout
- [x] signal handling
- [ ] conformance tests

## 11. Artifact Builder
- [x] Source scanner
- [~] Dependency analysis
- [~] Runtime detection
- [x] Build command
- [x] Packaging
- [x] Artifact metadata
- [x] Artifact digest
- [x] Artifact validation
- [x] Reproducible build strategy

## 12. Content-Addressed Cache
- [ ] `~/.rustfun/`
- [x] artifact cache
- [ ] build cache
- [ ] runtime cache
- [ ] layer cache
- [x] SHA-256 digests
- [x] cache lookup
- [x] insertion
- [x] locking
- [x] corruption detection
- [x] eviction
- [x] garbage collection

## 13. Instance Manager
- [x] Instance struct
- [x] start
- [~] stop
- [~] restart
- [x] suspend
- [ ] resume
- [x] health check
- [x] invoke
- [x] destroy
- [x] lifecycle events
- [x] failure handling
- [x] race protection

## 14. Warm Instance Pool
- [x] Per-function pool
- [x] min instances
- [x] max instances
- [x] idle timeout
- [x] instance reuse
- [x] health checks
- [x] failed-instance eviction
- [x] concurrency policy
- [x] cold-start tracking
- [x] reuse-rate tracking

## 15. Concurrency & Scheduler
- [x] Invocation queue
- [x] FIFO
- [~] priority support
- [x] per-function concurrency
- [x] global concurrency
- [x] backpressure
- [x] cancellation
- [x] timeout propagation
- [~] worker scheduling

## 16. HTTP Development Server
- [x] `rustfun dev`
- [x] HTTP router
- [x] POST invoke endpoint
- [x] function discovery
- [x] health endpoint
- [x] functions endpoint
- [x] instances endpoint
- [x] metrics endpoint
- [x] JSON payloads
- [x] binary payloads
- [x] headers
- [ ] request context
- [x] response headers
- [~] streaming
- [x] graceful shutdown

## 17. CLI
- [x] init
- [x] dev
- [x] build
- [~] run
- [x] invoke
- [x] list
- [x] inspect
- [~] logs
- [x] ps
- [~] stop
- [x] destroy
- [x] runtime
- [x] cache
- [x] doctor
- [x] version
- [x] JSON output
- [~] shell completion
- [x] useful diagnostics

## 18. Hot Reload
- [ ] Filesystem watcher
- [ ] source change detection
- [ ] artifact invalidation
- [ ] incremental rebuild
- [ ] instance invalidation
- [ ] automatic restart
- [ ] recovery from build failure

## 19. Environment & Filesystem
- [x] Function root
- [x] `/tmp`
- [x] source read-only mode
- [x] writable temp
- [x] artifact mount
- [x] runtime filesystem
- [x] cleanup
- [x] reserved environment variables
- [~] secret references

## 20. Resource Management
- [x] Memory limits
- [x] CPU limits
- [x] timeout
- [x] process limits
- [x] filesystem quota
- [~] network limits
- [x] open-file limits
- [x] instance quotas
- [x] resource accounting

## 21. Linux Sandbox
- [~] PID namespace
- [x] mount namespace
- [x] network namespace
- [x] user namespace
- [x] IPC namespace
- [x] UTS namespace
- [x] isolated root filesystem
- [x] read-only mounts
- [x] ephemeral `/tmp`
- [x] cgroups v2 — memory, PID, and CPU limits, each reported per controller (ADR-0021)
- [x] CPU limits
- [x] memory limits
- [x] process limits
- [x] seccomp
- [x] capability dropping
- [x] no privileged mode
- [x] no ptrace
- [x] no raw sockets

## 22. WASM Runtime
- [x] Wasmtime integration — `WasmAdapter` in `rustfun-runtime/src/wasm`, engine created lazily
- [x] WASM module loading — `.wasm` and `.wat`, resolved from the handler path
- [x] component model — deliberately **not** supported: the ABI is core-module only (ADR-0018)
- [x] WASI — deliberately **not** provided: no filesystem, clock, sockets, or environment
- [x] memory limits — `StoreLimits` page ceiling from the function policy
- [x] timeout — wall-clock deadline plus a fuel budget for guests that never yield
- [x] filesystem permissions — none: the guest has no filesystem at all
- [x] network permissions — none: the guest has no sockets at all
- [x] host functions — exactly one, `rustfun.payload`, returning the request offset
- [x] module cache — compiled modules reused across instances, bounded
- [x] lifecycle — prepare/start/invoke/health/shutdown, warm reuse, eviction on ABI violation
- [x] WASM conformance tests — `wasm_runtime_passes_conformance` plus 24 adapter tests

## 23. OCI Runtime
- [x] OCI image support — `rustfun-oci`: manifests, configs, descriptors, media types
- [x] image pull — registry client with token auth, TLS (rustls), local-registry HTTP
- [x] image cache — content-addressed blobs, corrupted entries removed on read
- [x] digest verification — every blob and the manifest verified before use
- [x] container creation — OCI runtime spec generated from the image config and the policy
- [x] filesystem layers — traversal-safe extraction, whiteouts, opaque markers, no device nodes
- [x] network configuration — a network namespace per container via the OCI spec
- [x] resource limits — memory from the function policy, no capabilities, `noNewPrivileges`
- [x] lifecycle — create/run/wait/delete through `runc`, cleanup on shutdown
- [x] cleanup — the container is deleted when its process exits or the instance is destroyed
- [x] OCI conformance tests — availability or an explicit, reasoned skip

## 24. Runtime Manager
- [x] Runtime discovery
- [ ] Runtime installation
- [ ] Runtime versions
- [ ] Runtime cache
- [ ] Runtime health
- [ ] Runtime upgrade
- [ ] Runtime removal
- [ ] `rustfun runtime list`
- [ ] `rustfun runtime install`
- [ ] `rustfun runtime doctor`

## 25. Logging
- [x] stdout capture
- [x] stderr capture
- [x] structured logs
- [x] invocation logs
- [x] instance logs
- [x] runtime logs
- [x] log levels
- [ ] filtering
- [~] streaming
- [ ] `rustfun logs`

## 26. Metrics
- [x] invocations total
- [x] successes
- [x] failures
- [x] duration
- [x] cold starts
- [x] warm starts
- [x] instance count
- [~] memory usage
- [~] CPU usage
- [x] queue time
- [x] build duration
- [x] cache hits/misses
- [x] Prometheus endpoint

## 27. Tracing
- [x] trace IDs
- [x] span IDs
- [x] invocation spans
- [~] build spans
- [x] runtime spans
- [x] sandbox spans
- [x] instance lifecycle spans
- [~] OpenTelemetry compatibility

## 28. Error System
- [x] Structured RustFunError
- [x] stable error codes
- [x] human-readable messages
- [x] machine-readable output
- [x] context/chaining
- [x] remediation hints
- [x] timeout errors
- [x] sandbox errors
- [x] resource errors

## 29. Doctor
- [x] Runtime checks
- [x] process checks
- [x] filesystem checks
- [~] network checks
- [x] sandbox checks
- [x] cgroup checks
- [x] namespace checks
- [x] seccomp checks
- [~] WASM checks
- [~] OCI checks
- [x] cache checks
- [x] permissions checks

## 30. Testing Foundation
- [x] Unit tests
- [x] Integration tests
- [x] Runtime tests
- [x] Sandbox tests
- [x] Compatibility tests
- [~] Stress tests
- [x] Security tests
- [x] Test fixtures
- [x] deterministic tests
- [~] failure injection

## 31. Runtime Conformance
- [x] startup
- [x] invocation
- [x] response
- [x] environment
- [x] filesystem
- [x] timeout
- [x] errors
- [x] shutdown
- [x] repeated invocation
- [~] malformed payload
- [~] large payload

## 32. `vercel/fun` Compatibility
- [x] createFunction-equivalent API
- [x] invoke-equivalent API
- [x] environment
- [x] handler
- [x] runtime
- [x] memory
- [x] destroy
- [x] error semantics
- [x] lifecycle semantics
- [~] compatibility fixtures
- [x] document intentional differences

## 33. Performance
- [ ] cold start benchmark
- [ ] warm invocation benchmark
- [ ] build benchmark
- [ ] artifact extraction benchmark
- [ ] runtime startup benchmark
- [ ] memory overhead
- [ ] CPU overhead
- [ ] IPC latency
- [ ] scheduler latency
- [ ] sandbox startup
- [ ] native/WASM/OCI comparison

## 34. Stress
- [ ] 1k invocations
- [ ] 10k invocations
- [ ] concurrent functions
- [ ] concurrent runtimes
- [ ] memory pressure
- [ ] CPU pressure
- [ ] runtime crash
- [ ] instance leak
- [ ] cache corruption
- [ ] network failure
- [ ] cancellation storm

## 35. Security
- [x] Path traversal
- [x] environment leakage
- [x] process escape
- [x] filesystem escape
- [x] network escape
- [x] privilege escalation
- [x] signal abuse
- [x] fork bomb
- [x] memory exhaustion
- [x] CPU exhaustion
- [x] malicious artifact
- [~] malicious runtime
- [x] malformed protocol
- [x] oversized payload
- [x] symlink attacks

## 36. Developer Experience
- [x] `rustfun init`
- [x] templates
- [x] Node template
- [x] Python template
- [x] Rust template
- [x] WASM template
- [x] executable template
- [~] interactive initialization
- [x] useful errors
- [~] examples

## 37. Rust SDK
- [x] `rustfun-sdk`
- [x] Function trait
- [~] Context
- [x] Request
- [x] Response
- [x] Error model
- [~] logging
- [x] environment
- [x] metadata
- [~] tracing
- [~] optional `#[rustfun::function]`
- [x] local invocation helpers

## 38. Rust Native Runtime
- [~] Cargo integration
- [~] release builds
- [~] target selection
- [~] static-link strategy
- [~] artifact stripping
- [x] reproducible builds
- [~] dependency cache
- [~] incremental builds

## 39. Remote Execution
- [ ] Worker protocol
- [ ] worker registration
- [ ] worker health
- [ ] job queue
- [ ] artifact distribution
- [ ] result streaming
- [ ] worker draining
- [ ] retry
- [x] cancellation

## 40. Distributed Artifact Store
- [ ] Artifact registry
- [ ] Content addressing
- [ ] Deduplication
- [ ] Upload
- [ ] Download
- [ ] Verification
- [ ] Garbage collection
- [ ] Remote cache

## 41. Distributed Scheduler
- [ ] Worker selection
- [ ] Runtime capability matching
- [ ] Resource-aware scheduling
- [ ] Locality
- [ ] Queue management
- [ ] Retries
- [ ] Failure recovery
- [ ] Worker draining

## 42. Production Control Plane
- [ ] API
- [ ] Authentication
- [ ] Authorization
- [ ] Tenants
- [ ] Quotas
- [ ] API keys
- [ ] Audit logs
- [ ] Rate limits
- [ ] Worker management

## 43. Persistence
- [~] SQLite local metadata
- [ ] functions table
- [ ] artifacts table
- [ ] runtimes table
- [ ] instances table
- [ ] invocations table
- [ ] workers table
- [ ] jobs table
- [ ] PostgreSQL strategy for distributed mode

## 44. Event System
- [x] rustfun-events
- [x] FunctionCreated
- [~] FunctionBuilt
- [x] ArtifactCreated
- [x] InstanceStarted
- [x] InstanceReady
- [x] InvocationStarted
- [x] InvocationCompleted
- [x] InvocationFailed
- [x] InstanceSuspended
- [x] InstanceDestroyed
- [~] RuntimeInstalled
- [~] WorkerRegistered

## 45. Stability
- [ ] Versioned protocol
- [ ] Versioned manifest
- [ ] Stable CLI
- [ ] Stable SDK
- [ ] API compatibility tests
- [ ] Deprecation policy
- [ ] Migration tools

## 46. Documentation
- [x] Getting started
- [x] Architecture
- [x] Functions
- [x] Runtimes
- [x] Invocation
- [x] Sandbox
- [ ] WASM
- [ ] Containers
- [x] Configuration
- [x] CLI
- [x] SDK
- [x] Security
- [~] Performance
- [~] Troubleshooting
- [x] Compatibility

## 47. CI/CD
- [~] Linux x86_64
- [~] Linux ARM64
- [~] macOS ARM64
- [~] macOS x86_64
- [x] tests
- [x] clippy
- [x] rustfmt
- [~] docs
- [~] benchmarks
- [~] releases

## 48. Release Engineering
- [x] SemVer
- [ ] Git tags
- [ ] GitHub releases
- [ ] binaries
- [ ] Homebrew
- [ ] cargo install
- [ ] shell installer
- [ ] checksums
- [ ] SBOM
- [ ] signed artifacts
- [ ] provenance

## 49. Production Hardening
- [ ] Crash recovery
- [ ] instance leak detection
- [ ] artifact corruption recovery
- [x] graceful shutdown
- [ ] worker draining
- [ ] resource exhaustion recovery
- [ ] retries
- [x] backpressure
- [ ] circuit breakers
- [ ] watchdog
- [x] health checks

## 50. Final Architecture
Non-negotiable execution spine:

```text
Function
  ↓
Artifact
  ↓
Runtime
  ↓
Sandbox
  ↓
Instance
  ↓
Invocation
  ↓
Event
  ↓
Result / Error
```

### MVP gate
- [x] `cargo test --workspace`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo fmt --all -- --check`
- [x] Node invocation works
- [x] Python invocation works
- [x] Generic executable works
- [x] Warm invocation works
- [x] Cold invocation works
- [x] Timeout works
- [x] Environment works
- [x] Destroy works
- [x] Artifact cache works
- [x] HTTP invocation works
- [x] CLI invocation works

### Recommended order
1. Product definition
2. Cargo workspace
3. Domain model
4. Configuration
5. Runtime registry
6. Process engine
7. Invocation protocol
8. Function lifecycle
9. Node runtime
10. Python runtime
11. Generic executable
12. Artifact builder
13. Content-addressed cache
14. Instance manager
15. Warm pool
16. Scheduler
17. HTTP server
18. CLI
19. Hot reload
20. Filesystem/resources
21. Linux sandbox
22. WASM
23. OCI
24. Runtime manager
25. Observability
26. Doctor
27. Testing/security/performance
28. Rust SDK
29. Remote execution
30. Distributed control plane

### Architectural rule

The system must remain useful as a local embedded execution kernel before distributed features are introduced.
