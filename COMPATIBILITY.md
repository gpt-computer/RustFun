# RustFun ↔ `vercel/fun` Compatibility

RustFun is **not** a port of `vercel/fun`. This document defines the compatibility boundary
(see ADR-0002).

## What is compatible (concepts)

| `vercel/fun` concept | RustFun equivalent |
| --- | --- |
| `createFunction({ name, runtime, handler, memory, environment, ... })` | `FunctionManager::create(FunctionSpec)` / `POST /functions` |
| `invoke(function, payload)` | `FunctionManager::invoke(...)` / `POST /functions/:id/invoke` / `rustfun function invoke` |
| `destroy(function)` | `FunctionManager::destroy(...)` / `DELETE /functions/:id` |
| runtime string such as `node@18`, `python3.11`, `provided.al2` | `RuntimeId` (`node@24`, `python@3.12`, `executable`, `rust`, `wasm`, `oci`) |
| handler string such as `index.handler` | `HandlerSpec` (same textual shape) |
| memory limit in MB | `ResourceLimits.memory` in bytes (human-readable `MiB` parsing in config) |
| environment variables | `Environment` map with reserved-prefix rules |
| warm instance reuse | `InstancePool` with idle timeout and max instances |
| `destroy` stopping instances | pool eviction + instance shutdown events |

## Intentional differences

1. **Isolation.** `vercel/fun` executed functions as host child processes. RustFun names the
   isolation layer and can apply Linux namespaces, cgroups, WASM, or OCI. Host-process mode
   exists for development and is labelled as insecure.
2. **Artifacts.** `vercel/fun` used a directory cache. RustFun artifacts are immutable and
   content-addressed (`sha256:`), with digest verification on every read.
3. **Errors.** RustFun errors are structured (category, code, context, retryability,
   remediation) rather than message strings. CLI output is human-readable; the library and
   HTTP API are machine-readable.
4. **Protocol.** The invocation protocol is versioned and framed, and is independent of any
   particular language runtime. `vercel/fun` coupled invocation to Node/Python handler shapes.
5. **Runtime ids.** RustFun uses explicit family + version and rejects ambiguous version
   ranges at configuration time instead of silently picking an installed runtime.
6. **Concurrency.** RustFun instances may serve concurrent invocations up to a configured
   limit; `vercel/fun` was strictly one invocation per instance.

## Non-goals

- Byte-identical CLI output or help text.
- Reimplementation of `vercel/fun`'s internal module layout.
- Backwards compatibility of the `fun` JavaScript API inside the Rust core.

## Compatibility tests

`crates/rustfun-test` provides a conformance suite. Compatibility expectations live in
`crates/rustfun-test/src/compat.rs` and are executed as workspace integration tests.
