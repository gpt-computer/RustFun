# RustFun Product Definition

## 1. Identity

- **Name:** RustFun
- **Crate prefix:** `rustfun-*`
- **Binary:** `rustfun`
- **Manifest:** `rustfun.toml`
- **State/cache directory:** `$RUSTFUN_HOME` or `~/.rustfun`
- **Description:** A Rust-native serverless function execution kernel: build a function into a
  content-addressed artifact, resolve a runtime, run it inside an explicit isolation layer,
  keep instances warm, and invoke them over a runtime-independent protocol.

RustFun is inspired by the architectural capabilities of `vercel/fun`, but it is an
independent system. See `COMPATIBILITY.md`.

## 2. Compatibility target

`vercel/fun` is a compatibility target, not the architecture. RustFun aims to reproduce the
*developer-visible concepts* — function creation, handler semantics, environment behavior,
warm invocation, teardown, CLI ergonomics — while improving on the original where the original
was constrained by its historical implementation (see ADR-0002).

## 3. Scope

In scope:

- Local, embedded execution kernel (Function → Artifact → Runtime → Sandbox → Instance →
  Invocation → Event → Result/Error).
- Runtime adapters: Node.js, Python, generic executable, Rust-native, WASM, OCI.
- Content-addressed artifact building and caching.
- Warm instance pooling, scheduling, concurrency, backpressure.
- Local development HTTP API and CLI.
- Observability: structured logs, metrics, traces, structured errors.
- Explicit isolation layers, with Linux isolation as the native-hardening path.
- Extensible contracts (traits) so that remote/distributed execution can be added without
  changing the kernel.

Out of scope (non-goals) for the first production-grade milestone:

- A hosted control plane, billing, tenancy, or public multi-tenant SaaS behavior.
- A managed distributed scheduler. Local scheduling is the contract; distributed is a later
  adapter over the same contracts.
- Reproducing `vercel/fun` implementation internals or its exact CLI text output.
- Language-runtime installation/download of arbitrary upstream toolchains (discovery is
  supported; provisioning is opt-in and out of the kernel's critical path).

## 4. Supported platforms

| Platform | Isolation support | Notes |
| --- | --- | --- |
| Linux x86_64 / aarch64 | host, Linux namespaces + cgroups v2, WASM, OCI | Primary production target. |
| macOS (arm64, x86_64) | host (developer), WASM, OCI | No Linux namespace/cgroup isolation; documented capability boundary, never silently claimed. |
| Windows | host (developer) | Not a primary target in the first milestone. |

Runtime discovery is platform-agnostic. Isolation capability is explicit and reported by
`rustfun doctor` and by the runtime/sandbox capability structures.

## 5. Runtime support policy

- A runtime adapter must implement the runtime conformance contract
  (prepare → start → invoke → repeated invoke → environment → timeout → error → shutdown)
  before it is advertised as supported.
- Runtimes are discovered from the host by probing well-known executables; versions are
  reported, not assumed.
- Unsupported or unavailable runtimes produce a structured `RuntimeUnavailable` error with
  remediation hints, never a silent fallback.
- Runtime adapters own runtime behavior only. Scheduling, pooling, and lifecycle management
  belong to the core.

## 6. Security model

Function code is untrusted. See `SECURITY.md` for the full model.

- Host-process mode is a **development** convenience and is explicitly not a security
  boundary.
- Isolation layers, in increasing strength: host process → Linux isolation (namespaces,
  cgroups v2, seccomp, capability dropping, read-only root) → WASM (Wasmtime + WASI with
  capability-scoped preopens) → OCI (container).
- The environment passed to function code is allow-listed by default; host environment
  variables are not inherited implicitly.
- Timeouts, memory limits, process limits, and payload size limits are enforced by the
  platform, not by the function.

## 7. Local development UX

- `rustfun init` scaffolds a function from a template (node, python, rust, wasm, executable).
- `rustfun dev` runs a local control plane: HTTP API, function discovery, hot reload, logs.
- `rustfun function invoke <name>` invokes from the terminal and prints JSON results.
- `rustfun doctor` explains exactly what is missing and how to fix it.
- Errors are human-readable in the CLI and machine-readable in the library/API.

## 8. Production execution model

- Functions are built once into immutable, content-addressed artifacts.
- Artifacts are distributed to workers by digest; workers verify digests before use.
- Instances are pooled per function with configurable min/max, idle timeout, and
  concurrency; scheduler enforces per-function and global capacity with backpressure.
- Isolation is mandatory in production mode; development mode may relax it explicitly.
- Observability is first-class: every invocation carries correlation identifiers and emits
  structured events, logs, and metrics.

## 9. Success criteria (MVP gate)

`cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and
`cargo fmt --all -- --check` pass; and Node, Python, and generic-executable functions can be
created, built, cached, invoked (cold and warm), timed out, error, and destroyed through both
the CLI and the HTTP API.
