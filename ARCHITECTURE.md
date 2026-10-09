# RustFun Architecture Contract

## Execution spine

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

## Control plane

```text
CLI / SDK / HTTP
      ↓
FunctionManager
      ↓
Scheduler
      ↓
InstancePool
      ↓
InstanceManager
      ↓
RuntimeAdapter
      ↓
Sandbox
      ↓
Process / WASM / OCI
```

## Data plane

The function execution data path must remain independent from CLI presentation.

## Runtime model

Runtime adapters own runtime-specific behavior.

The core owns:
- lifecycle
- scheduling
- invocation
- resource contracts
- state
- events

## Isolation

Development host-process mode is allowed.

Production-capable isolation must be explicit:
- Linux sandbox
- WASM
- OCI

## Artifact model

Artifacts are immutable and content-addressed.

## Event model

Lifecycle transitions should emit structured events.

## Compatibility

`vercel/fun` semantics should be represented by compatibility adapters/tests rather than contaminating the core domain model.


## Crate map

| Crate | Owns | Never does |
| --- | --- | --- |
| `rustfun-model` | ids, function specs, digests, resources, sandbox policy | anything requiring I/O |
| `rustfun-events` | the structured event vocabulary | deciding when events fire |
| `rustfun-protocol` | framing, codecs, transports | starting processes |
| `rustfun-core` | errors, runtime traits, registry, event bus, metrics, function manager | pooling, adapters, CLI |
| `rustfun-process` | every `execve` in the workspace | policy about when to start |
| `rustfun-sandbox` | host / Linux isolation layers and capability probes | runtime-specific concerns |
| `rustfun-runtime` | node, python, executable, echo, wasm adapters | pooling or scheduling |
| `rustfun-artifact` | build staging, deterministic packing, content-addressed cache | lifecycle decisions |
| `rustfun-instance` | state machine, warm pool, scheduler | runtime behaviour |
| `rustfun-config` | `rustfun.toml` parsing and validation | running anything |
| `rustfun-invoke` | the service façade every entry point shares | duplicating manager rules |
| `rustfun-http` | routing, status codes, JSON encoding | business logic |
| `rustfun-cli` | argument parsing, templates, presentation | business logic |
| `rustfun-test` | the runtime conformance suite | platform code |
| `rustfun-sdk` | types for Rust-native functions | platform code |

## Ownership of the spine

| Stage | Owner | Contract |
| --- | --- | --- |
| Function | `rustfun-model` + `rustfun-core::FunctionManager` | `FunctionSpec`, validated at creation |
| Artifact | `rustfun-artifact` | immutable, content-addressed, digest-verified |
| Runtime | `rustfun-runtime` | `RuntimeAdapter` / `RuntimeInstance` |
| Sandbox | `rustfun-sandbox` | `Sandbox` + `IsolationReport` (what was *actually* applied) |
| Instance | `rustfun-instance` | `InstanceState` transitions, one invocation at a time |
| Invocation | `rustfun-protocol` | `InvocationRequest` / `InvocationResponse` |
| Event | `rustfun-events` | emitted by the manager, scheduler, pool, and process engine |
| Result/Error | `rustfun-core::RustFunError` | machine-readable, context-carrying |

## Control plane

```text
CLI / HTTP / SDK
      ↓
InvocationService            (rustfun-invoke: one façade, no duplicated rules)
      ↓
FunctionManager              (lifecycle: create → build → ready → invoke → destroy)
      ↓
Scheduler                    (capacity, backpressure, deadlines, FIFO)
      ↓
InstancePool                 (warm reuse, min/max, idle timeout, eviction)
      ↓
RuntimeAdapter               (prepare → start → invoke → shutdown)
      ↓
Sandbox                      (host | linux)
      ↓
Process / WASM / OCI          (the execution substrate)
```

## Rules that are enforced, not documented

- The compiler rejects `core → cli`, `runtime → cli`, `protocol → runtime`, and
  `model → infrastructure`, because the crate graph forbids them.
- A sandbox refusal is an error, never a silent fallback: `IsolationReport` lists every control
  that was applied and every control that was skipped, with a reason.
- A state-machine violation is rejected: `ManagedInstance::transition` returns a structured
  error for an illegal move.
- The host environment is never inherited: the process engine calls `env_clear()` unless a
  caller explicitly opts in, and the runtime adapters build environments from the declared set
  plus reserved `RUSTFUN_*` variables.
