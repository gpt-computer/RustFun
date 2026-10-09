# RustFun Progress

## Current phase

**MVP complete.** The execution spine is implemented end to end and verified by automated
tests; the remaining work is the next tier of features (WASM, OCI, persistence, remote
execution) listed in `TODO.md`.

## Completed phases

| Phase | Status | Notes |
| --- | --- | --- |
| 0. Product definition | done | `PRODUCT.md`, `SECURITY.md`, `COMPATIBILITY.md`, `CONTRIBUTING.md` |
| 1. Cargo workspace | done | 15 crates, dependency DAG enforced by the compiler |
| 2. Domain model | done | ids, function specs, digests, environments, resources, sandbox policy |
| 3. Configuration | done | `rustfun.toml`, validation, defaults, env overrides; JSON manifests pending |
| 4. Runtime registry | done | adapter traits, discovery, aliases, version matching, capabilities |
| 5. Process engine | done | process groups, signals, bounded logs, timeouts, resource accounting |
| 6. Invocation protocol | done | versioned framing, JSON + MessagePack, stdio/Unix/TCP transports |
| 7. Function lifecycle | done | create/build/invoke/destroy with structured events and guards |
| 8. Node.js runtime | done | CommonJS + ESM, async handlers, conformance-tested |
| 9. Python runtime | done | sync + async handlers, conformance-tested |
| 10. Generic executable runtime | done | reference handler in `rustfun-test`, conformance-tested |
| 11. Artifact builder | done | staging, build commands, deterministic packing |
| 12. Content-addressed cache | done | SHA-256, digest verification, eviction, traversal-safe extraction |
| 13. Instance manager | done | explicit state machine, invalid transitions rejected |
| 14. Warm pool | done | min/max, idle timeout, reuse, failed-instance eviction |
| 15. Concurrency | done | global + per-function limits, backpressure, deadline propagation |
| 16. HTTP dev server | done | `/health`, `/metrics`, `/runtimes`, `/functions`, `/instances` |
| 17. CLI | done | init, doctor, dev, build, cache, function, runtime, instance, version |
| 19. Environment & filesystem | done | filtered environment, reserved vars, private tmp, read-only root |
| 20. Resource management | done | memory/fd/process/CPU limits, payload caps |
| 21. Linux sandbox | done | user/mount/net/ipc/uts/PID namespaces (launcher), rlimits, seccomp, caps, cgroup memory when available |
| 25–28. Observability & errors | done | event bus, logs, metrics + Prometheus, structured errors |
| 29. Doctor | done | runtime, sandbox, namespace, seccomp, cache, permission probes |
| 30. Testing foundation | done | unit, integration, conformance, security tests |
| 31. Runtime conformance | done | all shipped runtimes pass the contract |
| 32. `vercel/fun` compatibility | done | API/behaviour parity documented in `COMPATIBILITY.md` |
| 35. Security tests | done | traversal, env leakage, isolation, limits, oversized payloads |
| 36. Developer experience | done | templates for node/python/rust/wasm/executable/echo |
| 37. Rust SDK | partial | `Function`, `Request`, `Response`; `#[rustfun::function]` pending |
| 44. Event system | done | `rustfun-events` with the full lifecycle event set |
| 46. Documentation | done | product, architecture, security, compatibility, contributing, README |
| 47. CI | partial | local quality gate enforced; GitHub Actions not wired yet |

## Quality gates

Run from the repository root:

```bash
cargo fmt --all -- --check                                   # PASS
cargo test --workspace                                        # PASS (369 tests)
cargo clippy --workspace --all-targets -- -D warnings         # PASS
```

Last verified: see the "Tests run" section of the session report.

## Test inventory

| Suite | Count | What it proves |
| --- | --- | --- |
| `rustfun-model` | 52 | domain validation, serialization, versioning |
| `rustfun-events` | 4 | event shape and stability |
| `rustfun-protocol` | 30 | framing, codecs, transports, malformed input |
| `rustfun-core` | 34 | errors, registry, event bus, metrics, manager lifecycle |
| `rustfun-process` | 22 | process groups, signals, timeouts, log bounds, env filtering |
| `rustfun-sandbox` | 32 | isolation layers, seccomp, environment scrubbing, launcher, PID namespace, per-controller cgroup reporting |
| `rustfun-runtime` | 25 | adapter discovery, preparation, handler resolution, in-process runtime |
| `rustfun-artifact` | 11 (+ store suite) | determinism, caching, verification, traversal defence, exec bit, bootstrap exclusion |
| `rustfun-instance` | 9 (+ execution suite) | state machine, leases, cold→warm reuse, scheduling, timeouts |
| `rustfun-config` | 12 | manifest parsing, defaults, overrides, validation |
| `rustfun-invoke` | 6 | service wiring, project loading, metrics |
| `rustfun-http` | 8 | routing, status codes, structured errors over real TCP |
| `rustfun-cli` | 8 (+ cli suite) | argument parsing, templates, full CLI lifecycle |
| `rustfun-test` | 9 | conformance for echo/node/python/executable/wasm/oci, statefulness, linux sandbox |
| `rustfun-sdk` | 4 | handler types and request mapping |

## Known limitations

- **cgroup v2 availability.** Limits are enforced only when the hierarchy delegates the
  controller; most CI containers mount it read-only, and the isolation report then names each
  controller it could not write instead of pretending. `rustfun doctor` reports the same
  distinction through the `cgroup_cpu` and `sandbox_launcher` probes.
- **Launcher discovery.** The PID namespace needs `rustfun-sandbox-init` next to the running
  binary. A development checkout that runs the sandbox tests without that sibling binary falls
  back to the in-process path and reports `pid_namespace` as skipped.
- **WASM and OCI runtimes.** Declared in the model and in the CLI, not implemented.
- **Persistence.** Build state is stored as one small JSON file per function; there is no
  SQLite metadata store.
- **Remote execution.** No worker protocol; the scheduler is local by design (ADR-0003).
- **Instances do not survive a process.** Each `rustfun` invocation is its own kernel; warm
  reuse is observable within one process (`rustfun dev`, the HTTP API, or the SDK).
- **Streaming responses.** The protocol is request/response; there is no streaming body yet.

## Next executable milestone

Phase 24 (runtime manager): installation, version resolution, and a runtime cache, so
`rustfun runtime install` can put an interpreter on a host that does not have one. Unblocked and
has no external dependency.