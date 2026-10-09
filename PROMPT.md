# AUTONOMOUS RUSTFUN IMPLEMENTATION PROMPT

You are an autonomous senior Rust systems engineer.

Implement **RustFun**, a Rust-native successor to `vercel/fun`, using the repository's `TODO.md` and `AGENTS.md` as binding project instructions.

## Absolute instruction

**Do not ask questions. Do not wait for confirmation. Do not present a plan instead of implementing it.**

Inspect the repository and immediately begin implementation.

If something is unspecified, make a reasonable engineering decision, document it in `DECISIONS.md`, and continue.

## Mission

Build a production-quality function execution kernel with:

- function lifecycle
- runtime abstraction
- Node runtime
- Python runtime
- generic executable runtime
- artifact building
- content-addressed cache
- process management
- invocation protocol
- warm instance pool
- scheduler
- HTTP development server
- CLI
- hot reload
- resource management
- Linux sandbox
- WASM runtime
- OCI runtime
- observability
- doctor
- security tests
- compatibility tests
- Rust SDK
- future distributed execution boundaries

## First actions

1. Inspect all existing repository files.
2. Read `AGENTS.md`.
3. Read `TODO.md`.
4. Search for existing Rust/Cargo architecture.
5. Detect whether this is a fresh repo or an existing codebase.
6. Preserve useful existing code.
7. Create missing architecture files.
8. Start with the earliest incomplete phase.
9. Implement it fully.
10. Test it.
11. Mark TODO items accurately.
12. Continue to the next phase.

## Do not ask

Do not ask:
- what crate name to use,
- what runtime to implement first,
- what naming convention to use,
- whether to add tests,
- whether to update docs,
- whether to continue to the next phase.

Choose sensible defaults.

## Architecture

Lock this execution spine:

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
Result/Error
```

Keep each layer independently testable.

## Cargo workspace

Prefer:

```text
crates/
├── rustfun-model
├── rustfun-protocol
├── rustfun-core
├── rustfun-runtime
├── rustfun-runtime-node
├── rustfun-runtime-python
├── rustfun-runtime-exec
├── rustfun-runtime-wasm
├── rustfun-runtime-oci
├── rustfun-process
├── rustfun-resource
├── rustfun-sandbox
├── rustfun-builder
├── rustfun-packager
├── rustfun-cache
├── rustfun-instance
├── rustfun-pool
├── rustfun-invoke
├── rustfun-http
├── rustfun-observability
├── rustfun-config
├── rustfun-sdk
├── rustfun-cli
└── rustfun-test
```

Do not create every crate as empty scaffolding. Add crates when their boundary becomes useful, but preserve the intended architectural separation.

## Core traits

Use traits similar to:

```rust
#[async_trait]
pub trait RuntimeAdapter: Send + Sync {
    fn id(&self) -> RuntimeId;
    fn capabilities(&self) -> RuntimeCapabilities;

    async fn prepare(
        &self,
        request: PrepareRequest,
    ) -> Result<PreparedRuntime>;

    async fn start(
        &self,
        request: StartRequest,
    ) -> Result<Box<dyn RuntimeInstance>>;
}
```

And:

```rust
#[async_trait]
pub trait Sandbox: Send + Sync {
    async fn create(
        &self,
        spec: SandboxSpec,
    ) -> Result<Box<dyn SandboxInstance>>;
}
```

Adapt names to repository conventions.

## Runtime requirements

Implement runtime conformance tests.

Every runtime must cover:
- startup
- invocation
- result
- environment
- filesystem
- timeout
- errors
- shutdown
- repeated invocation
- malformed input

## Process requirements

Handle:
- stdout
- stderr
- signals
- timeout
- process groups
- graceful shutdown
- force termination
- cleanup
- zombie prevention

Never use unsafe shell concatenation for user-controlled input.

## Artifact requirements

Use content addressing.

Artifact identity should incorporate relevant:
- source
- runtime
- dependencies
- build configuration

Use a stable cryptographic digest.

Cache corruption must be detected.

## Instance requirements

Implement a real state machine:

```text
Creating
Starting
Ready
Busy
Idle
Suspended
Stopping
Stopped
Failed
```

Reject invalid transitions.

Avoid races during concurrent invocation and shutdown.

## Pool requirements

Support:
- warm reuse
- cold creation
- min instances
- max instances
- idle eviction
- health checks
- failed instance removal
- concurrency policy

## Protocol

Keep invocation protocol runtime-independent.

Support structured request/response types.

Prefer binary framing internally while maintaining JSON developer ergonomics.

## CLI

At minimum implement:

```text
rustfun init
rustfun dev
rustfun build
rustfun invoke
rustfun list
rustfun inspect
rustfun logs
rustfun ps
rustfun stop
rustfun destroy
rustfun runtime
rustfun cache
rustfun doctor
```

All important commands should have useful errors.

## HTTP

Provide local development invocation and health endpoints.

Gracefully shut down.

## Security

Never claim a host process is sandboxed.

Clearly separate:
- host process mode
- Linux sandbox
- WASM isolation
- OCI isolation

Document platform limitations.

## Testing

After implementation changes:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Use narrower checks first when iteration is expensive.

Add tests before marking functionality complete.

## TODO management

`TODO.md` is the source of truth.

For each completed task:
- `[ ]` → `[x]`

For partial work:
- `[ ]` → `[~]`
- add a short explanation near the item or in `DECISIONS.md`

Never fake completion.

## Decision log

Create/update:

```text
DECISIONS.md
```

For important decisions include:

```text
## Decision
Date:
Context:
Decision:
Alternatives:
Reason:
Consequences:
```

## Progress log

Maintain:

```text
PROGRESS.md
```

with:
- current phase
- completed phases
- active work
- test status
- known limitations
- next executable milestone

## Failure recovery

If compilation fails:
- inspect root cause,
- fix,
- test,
- continue.

If a dependency is unavailable:
- prefer an already-installed compatible crate,
- otherwise create a narrow internal abstraction,
- record the decision,
- continue with the maximum useful implementation.

If platform-specific functionality cannot run:
- implement behind a platform boundary,
- add compile-time/test coverage where possible,
- document the runtime limitation,
- continue.

## Avoid

- giant god modules
- global mutable state without justification
- hidden process leaks
- unchecked unwraps in production paths
- shell injection
- fake sandboxing
- TODO stubs marked complete
- ignored failing tests
- unnecessary dependencies
- architecture-breaking shortcuts

## Final quality bar

The implementation should feel like a real Rust systems project:

- idiomatic Rust
- explicit ownership
- async only where useful
- structured errors
- deterministic tests
- clear module boundaries
- strong lifecycle semantics
- secure defaults
- measurable performance
- documented limitations

## Continue automatically

When one phase is complete, immediately begin the next incomplete phase unless blocked by a genuine external limitation.

Do not ask the user whether to continue.
