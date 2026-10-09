# Contributing to RustFun

## Prerequisites

- Rust stable (see `rust-toolchain.toml`).
- Node.js and Python are needed for those runtime tests; tests that require a missing runtime
  are skipped explicitly (never silently ignored), and `rustfun doctor` explains what is
  missing.

## Quality gate

Every change must pass:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Architecture rules

The dependency direction is fixed:

```text
rustfun-model
  ↓
rustfun-events / rustfun-protocol
  ↓
rustfun-core
  ↓
rustfun-process / rustfun-sandbox / rustfun-runtime / rustfun-artifact
  ↓
rustfun-instance / rustfun-config
  ↓
rustfun-invoke / rustfun-http
  ↓
rustfun-cli
```

(An arrow `a ↓ b` means `a` may depend on `b`.)

Never introduce `core → cli`, `runtime → cli`, `protocol → runtime`, or `model → infrastructure`.
Runtime adapters must not contain scheduling or pooling logic; they implement
`RuntimeAdapter`/`RuntimeInstance` and nothing else.

## Style

- Follow the existing code style; `cargo fmt` is authoritative.
- `clippy -D warnings` is authoritative. Fix lints, do not allow them.
- No `unwrap()` in production paths unless the invariant genuinely cannot be violated (for
  example, a literal `Some`).
- No `#[ignore]` to make CI green. If a test cannot run in the current environment, gate it on
  a runtime/version check and report why it was skipped.
- Errors must be structured (`RustFunError`), never opaque strings.
- Public items need documentation. Security-sensitive behavior needs tests.

## Adding a runtime adapter

1. Implement `RuntimeAdapter` and `RuntimeInstance` in `crates/rustfun-runtime`.
2. Do not add scheduling, pooling, or lifecycle management.
3. Add the adapter to the runtime registry in `rustfun-core`'s default registry construction.
4. Add it to the conformance suite in `crates/rustfun-test` and make the suite pass.
5. Record any architectural decision in `DECISIONS.md`.

## Process

Keep the checklist in `TODO.md` honest: `[x]` complete, `[~]` partial (with a note), `[ ]`
not started. Update `PROGRESS.md` and `DECISIONS.md` in the same change as the code.
