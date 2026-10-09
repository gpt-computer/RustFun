# RustFun Architectural Decisions

## Decision Log

This file is intentionally initialized before implementation.

Agents must append important architectural decisions rather than blocking for clarification.

### ADR-0001 — Execution spine
**Decision:** Keep Function → Artifact → Runtime → Sandbox → Instance → Invocation → Event → Result/Error as the primary architecture.

**Reason:** Each layer has independent lifecycle, testing, security, and replacement concerns.

### ADR-0002 — Compatibility boundary
**Decision:** `vercel/fun` compatibility is an adapter/test target, not the internal architecture.

**Reason:** The Rust implementation should support richer sandboxing, artifact caching, WASM, OCI, and distributed execution without inheriting legacy API constraints.

### ADR-0003 — Local-first
**Decision:** The local execution kernel must be useful without a distributed control plane.

**Reason:** This makes development, testing, and embedding possible before production orchestration exists.

### ADR-0004 — Content-addressed artifacts
**Decision:** Artifacts use stable cryptographic digests.

**Reason:** Enables deterministic cache lookup, deduplication, reproducibility, and eventual remote artifact distribution.

### ADR-0005 — Workspace layout and dependency direction
**Context:** The execution spine has seven stages with different ownership rules; if they share
a crate, the rules cannot be enforced by the compiler.

**Decision:** One crate per concern, with the dependency direction
`model → protocol/events → core → process/sandbox/runtime/artifact → instance → invoke → http → cli`.
`rustfun-core` defines the `Invoker` trait so the instance layer can be attached later without
core knowing about pools.

**Alternatives:** A single crate with modules (rejected: nothing stops `cli` code importing
runtime internals); a plugin ABI (rejected: premature).

**Consequences:** `cargo build` enforces the architecture. Adding a crate means justifying its
position in the DAG.

### ADR-0006 — Error handling
**Context:** `vercel/fun` surfaces strings. Operators and callers both need machine-readable
errors.

**Decision:** One `RustFunError` enum with a stable code, a category, a human message, structured
context (function/runtime/instance/invocation/operation), remediation hints, and a
retryability flag. Serialized for the API, rendered multi-line for the CLI.

**Alternatives:** `anyhow` everywhere (rejected: not machine-readable); string errors
(rejected: no codes, no classification).

**Consequences:** Every layer maps its own errors into `RustFunError`; the HTTP layer derives the
status code from the category, so a new error category automatically gets sensible HTTP
semantics.

### ADR-0007 — Versioned framed protocol
**Context:** Node, Python, and arbitrary executables must speak the same thing, and a corrupted
or hostile peer must not be able to exhaust memory.

**Decision:** `RFN1` magic + major version + codec id + `u32` length + body. Two codecs (JSON,
MessagePack). Frames above the configured maximum are rejected *before* allocation. The same
framing is used over stdin/stdout, Unix sockets, and TCP, so runtimes are transport-agnostic.

**Alternatives:** Line-delimited JSON (rejected: payload bytes may contain newlines);
length-prefixed JSON only (kept for interpreted runtimes where readability matters).

**Consequences:** Adding a field to the request is additive; a runtime that ignores it keeps
working. Protocol errors are distinguishable from function errors.

### ADR-0008 — Host-process mode is labelled insecure, everywhere
**Context:** Development ergonomics require running untrusted code without a sandbox, but a
platform that quietly downgrades isolation is worse than one that refuses.

**Decision:** `IsolationStrength::None` is a first-class value. The host layer reports it, the
CLI prints "NOT a security boundary", the HTTP API exposes
`sandbox_is_security_boundary`, and every conformance report includes it.

**Alternatives:** Calling it "sandboxed" (rejected: dishonest); refusing to run without a
sandbox (rejected: unusable on macOS and in CI).

**Consequences:** A caller can always answer "what actually contained this code?".

### ADR-0009 — Linux isolation: no silent downgrade, PID namespace reported as skipped
**Context:** `unshare(CLONE_NEWPID)` fails with `EINVAL` when the caller is multi-threaded, and
RustFun spawns children from a tokio worker thread. Silently skipping the flag would overstate
the isolation that was established.

**Decision:** The child publishes its pid through a pipe and blocks until the parent installs
the uid/gid maps (breaking the fork/exec cycle the way a container runtime's init goroutine
does). A helper thread performs the handshake while the main thread blocks in `spawn`. The
child reports each setup step back over a status pipe, so a refusal names the exact control.
Anything not established is listed in `IsolationReport::skipped`.

**Alternatives:** Fork a launcher process to obtain a real PID namespace (planned, ADR-0010);
drop the feature (rejected: PID namespace is a real control);pretend it worked (rejected).

**Consequences:** The linux layer is honest about what it provides; upgrading to a launcher
adds the PID namespace without changing the report format.

### ADR-0010 — Planned: sandbox launcher for full PID-namespace isolation
**Context:** See ADR-0009.

**Decision:** Re-exec the `rustfun` binary with a hidden `__sandbox-init` subcommand from a
single-threaded context, have it create the namespaces, then fork+exec the real interpreter so
the function runs as PID 1 of its namespace. The launcher inherits the uid/gid mapping
handshake unchanged.

**Consequences:** Adds one process per instance start; removes the "skipped" entry from the
isolation report.

### ADR-0011 — Seccomp uses KILL for escapes and EPERM for probed syscalls
**Context:** A blanket `SECCOMP_RET_KILL_PROCESS` on a broad deny list kills legitimate programs
(`glibc` calls `setns` during startup), while allowing a broad list to fail open is worthless.

**Decision:** Two lists. `KILLED_SYSCALLS` contains escapes and kernel-tampering calls that a
runtime never makes (`ptrace`, `mount`, `*module`, `kexec_*`, `bpf`, `pivot_root`, `chroot`).
`ERRNO_SYSCALLS` contains calls that runtimes probe and must simply fail closed (`socket`,
`setns`, `unshare`, `memfd_create`). A test interprets the generated BPF program and asserts both
behaviours, because a wrong jump offset would otherwise kill every syscall in production.

**Alternatives:** libseccomp (rejected: a C dependency for ~60 lines of generated BPF);
`SECCOMP_RET_TRAP` (rejected: delivers SIGSYS to the handler).

**Consequences:** The filter is small, auditable, and covered by an interpreter test rather than
by trusting hand-computed jump offsets.

### ADR-0012 — Instances run from the materialized artifact
**Context:** The scheduler originally used a shared working directory, so an instance could
execute code from a stale artifact after a rebuild.

**Decision:** The pool key includes the artifact path, and instances are started with the
extracted artifact as their working directory. A new digest produces a new pool.

**Consequences:** A rebuild never serves stale code; an old pool is drained rather than reused.

### ADR-0013 — Invoking builds implicitly; `rustfun destroy` does not delete sources
**Context:** Each CLI process starts from manifests, so an explicit `rustfun build` from a
previous process would be invisible; and a CLI that deletes a developer's manifest on
`destroy` is destructive.

**Decision:** `InvocationService` builds on demand when a function has no artifact, and records
the resulting digest in `<state>/functions/<name>.json` so later processes restore the `ready`
state without rebuilding. `destroy` tears down the kernel's view and the recorded state, and
leaves the manifest and sources untouched.

**Alternatives:** Persisting build state in SQLite (planned, §43); requiring an explicit build
(rejected: breaks the most common CLI flow).

**Consequences:** `rustfun function invoke <name>` works from a clean checkout; the manifest is
never destroyed by a CLI command.

### ADR-0014 — In-process `echo` runtime
**Context:** The conformance suite must be able to validate the platform without Node or Python
installed, and benchmarks must be able to measure platform overhead separately from runtime
startup.

**Decision:** `echo` is a registered runtime that answers with the payload it received and can
simulate slow or failing handlers through its declared environment. It refuses non-host sandbox
layers, so it can never be mistaken for an isolation mechanism.

**Alternatives:** A test-only mock behind `#[cfg(test)]` (rejected: conformance would then not
exercise the real adapter path); requiring interpreters in CI (rejected: CI environments vary).

**Consequences:** The platform's own test suite runs everywhere; `rustfun init --template echo`
gives a working demo on a machine with no toolchain.

### ADR-0015 — Local scheduler first
**Context:** Distributed scheduling is a large surface (workers, heartbeats, queues, retries) and
the local kernel has not yet proven its invariants.

**Decision:** The scheduler is local, with capacity, backpressure, and deadline propagation.
Instances sit behind the `Invoker` trait so a remote executor can be introduced without changing
the core.

**Alternatives:** Building a distributed scheduler now (rejected: premature; the invariants are
still moving).

**Consequences:** `rustfun-instance` owns policy, `rustfun-runtime` owns runtime behaviour, and
neither has to know about the other's future.

### ADR-0016 — Memory is enforced with cgroups, not POSIX rlimits
**Context:** The first sandbox implementation applied `RLIMIT_AS` to cap memory. Node.js then
died at startup: V8 reserves very large anonymous mappings, and since Linux 4.7 `RLIMIT_DATA`
counts `mmap` as well, so both rlimits have the same effect on modern kernels.

**Decision:** Memory is enforced with cgroup v2 (`memory.max`) when the hierarchy is writable,
and the isolation report states which of the two happened. POSIX rlimits are kept for the
controls they do enforce reliably: open files, processes, core dumps, file size, and CPU time.
`RLIMIT_AS`/`RLIMIT_DATA` are never used as a memory ceiling.

**Alternatives:** Disabling the memory limit entirely (rejected: silently unbounded); a
per-runtime heap flag (`--max-old-space-size`) (rejected: language-specific and bypassable).

**Consequences:** On a host with a writable cgroup hierarchy the memory limit is enforced
exactly. On a host without one (most CI containers) the report contains
`memory_limit_not_enforced_without_cgroups` and `rustfun doctor` explains it.

### ADR-0017 — A dedicated launcher binary for PID-namespace isolation
**Context:** `unshare(CLONE_NEWPID)` is refused with `EINVAL` for multi-threaded callers, and
the launcher needs `CAP_SYS_ADMIN` long enough to unshare.

**Decision:** `rustfun-sandbox-init` is a small separate binary. The parent creates the *user*
namespace through `pre_exec` (where it can install `/proc/<pid>/uid_map` on the child's
behalf), execs the launcher, and the launcher creates the remaining namespaces from a
single-threaded process, then spawns the payload so it runs as PID 1. Capabilities are dropped
and the seccomp filter installed *after* the namespaces exist, in the order
`no_new_privs → seccomp → drop capabilities`.

**Alternatives:** Skipping the PID namespace (rejected: it is a real control); using `clone3`
directly from tokio (rejected: unsafe fork/exec machinery in a multi-threaded runtime).

**Consequences:** The full namespace set is established on Linux with the launcher installed,
which is the normal case for an installed binary. The launcher is located next to the running
executable, so a release build gets PID isolation by default; development checkouts without
the sibling binary fall back to the in-process path and report the skip.

### ADR-0018 — The Wasm runtime is core-module only, with no WASI
**Context:** Wasmtime supports two guest shapes: core modules (a flat linear memory plus
exported functions) and components (the component model with typed interfaces and WASI preview 2).
Supporting both would double the ABI surface for a second guest language that no caller asked for.

**Decision:** RustFun runs **core modules** that export `memory` and `rustfun_handler() -> i32`.
There is no WASI: no filesystem, no clock, no sockets, no environment, no `argv`. The guest
reaches the host through exactly one import, `rustfun.payload`, which returns the offset of the
request frame the host already wrote.

**Alternatives:** WASI preview 2 (rejected: it grants a filesystem and clock by default, which
reopens the sandbox questions the Wasm layer is meant to close); the component model (rejected:
typed imports/exports are a second ABI for no current caller).

**Consequences:** A Wasm function is confined by construction — there is no ambient authority to
revoke. The trade-off is that a guest cannot read a file or check the time, which is the point of
the layer. Guests that need input beyond the invocation payload must get it through the request.

### ADR-0019 — The guest owns a status byte and a body; the host owns everything else
**Context:** A Wasm guest could in principle return a complete `InvocationResponse` frame, but
that would let it forge the invocation id, the function id, the duration, and the instance id.

**Decision:** The response body is `[status: u8][payload bytes]`:

| status | meaning | payload |
| --- | --- | --- |
| `0x00` | success | the response body, verbatim (JSON or binary) |
| `0x01` | failure | a UTF-8 message |

The host wraps the payload in a real `InvocationResponse` and stamps identity, timing, and
metrics. A guest that writes anything else is a `RUSTFUN_WASM_BAD_RESPONSE` function error and
the instance is evicted.

**Alternatives:** Full response frames from the guest (rejected: forgery); a JSON-only body
(rejected: `binary_payloads` is a declared capability and Wasm is the natural home for it).

**Consequences:** The ABI is two bytes wide, which keeps hand-written guests (including the WAT
fixtures and the CLI template) trivial, and keeps the host the only source of truth about what
happened.

### ADR-0020 — A trapped guest does not invalidate the instance
**Context:** The first implementation evicted an instance whose guest trapped. Wasmtime traps
unwind cleanly inside the guest, leaving the store valid.

**Decision:** A trap is reported as `RUSTFUN_WASM_ERROR` and the instance keeps serving. An
out-of-bounds frame, an unknown status byte, or a request that does not fit the memory policy is
an ABI violation and evicts the instance.

**Alternatives:** Evict on every trap (rejected: it makes ordinary error handling the most
expensive path in the platform and contradicts Wasmtime's own store-lifetime guarantees).

**Consequences:** A guest bug produces a per-invocation error without destroying warm capacity,
while a guest that lies about the protocol cannot keep serving.
