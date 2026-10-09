# RustFun

A Rust-native serverless function execution platform: build a function into an immutable,
content-addressed artifact, resolve a runtime, execute it inside an explicit isolation layer,
keep instances warm, and invoke them over a runtime-independent protocol.

```text
Function → Artifact → Runtime → Sandbox → Instance → Invocation → Event → Result/Error
```

## Status

The MVP is complete and verified by automated tests: create → build → invoke (cold and warm) →
timeout/error → destroy works for the in-process, Node.js, Python, and generic-executable
runtimes, through both the CLI and the HTTP API. See `PROGRESS.md` for the current state and
`TODO.md` for the authoritative checklist.

## Quick start

```bash
# Create a function from a template
cargo run --bin rustfun -- init hello --template node

# Build the artifact (content-addressed, cached)
cargo run --bin rustfun -- build hello

# Invoke it (an explicit build is optional; invoking builds on demand)
cargo run --bin rustfun -- function invoke hello --payload '{"name":"world"}'

# Run the local development control plane (HTTP API)
cargo run --bin rustfun -- dev --port 8787
curl -s localhost:8787/health
curl -s -X POST localhost:8787/functions/hello/invoke \
  -H 'content-type: application/json' -d '{"payload":{"name":"world"}}'

# Inspect the platform
cargo run --bin rustfun -- doctor
cargo run --bin rustfun -- function inspect hello --json
cargo run --bin rustfun -- instance list
cargo run --bin rustfun -- cache list
```

Try it without a toolchain:

```bash
cargo run --bin rustfun -- init demo --template echo
cargo run --bin rustfun -- function invoke demo --payload '{"name":"world"}'
```

## Workspace layout

| Crate | Responsibility |
| --- | --- |
| `rustfun-model` | Domain types: ids, function specs, artifacts, resources, runtime ids |
| `rustfun-events` | Structured lifecycle events |
| `rustfun-protocol` | Versioned invocation protocol, framing, transports |
| `rustfun-core` | Errors, runtime traits, registry, function manager, observability |
| `rustfun-process` | Centralized process lifecycle engine |
| `rustfun-sandbox` | Isolation layers (host, Linux namespaces/cgroups/seccomp) |
| `rustfun-runtime` | Runtime adapters (node, python, executable, echo, wasm, oci) |
| `rustfun-oci` | OCI image references, pull, verification, cache, and layer extraction |
| `rustfun-artifact` | Artifact builder and content-addressed cache |
| `rustfun-instance` | Instance manager, warm pool, scheduler |
| `rustfun-config` | `rustfun.toml` manifest parsing, defaults, validation |
| `rustfun-invoke` | Invocation service facade |
| `rustfun-http` | Local development HTTP API |
| `rustfun-cli` | `rustfun` command line interface |
| `rustfun-test` | Runtime conformance and compatibility test harness |
| `rustfun-sdk` | Rust SDK for writing RustFun-native functions |

## Security

Host-process execution of function code is a development convenience, **not** a sandbox.
See `SECURITY.md` for the isolation layers and the threat model.

## Documentation

- `PRODUCT.md` — product definition, scope, supported platforms
- `ARCHITECTURE.md` — architecture contract
- `SECURITY.md` — threat model and isolation layers
- `COMPATIBILITY.md` — `vercel/fun` compatibility boundary
- `CONTRIBUTING.md` — development rules and quality gate
- `DECISIONS.md` — architectural decision records

## Quality gate

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
