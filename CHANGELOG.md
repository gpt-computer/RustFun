# Changelog

All notable changes to RustFun.

## [Unreleased]

### Added
- Wasm runtime: `WasmAdapter` on Wasmtime with a core-module ABI, `rustfun.payload` host
  function, `StoreLimits` memory ceiling, fuel budget, bounded module cache, and warm reuse
  (ADR-0018, ADR-0019, ADR-0020).
- `rustfun init --template wasm` scaffolds a runnable WAT module that selects the `wasm`
  sandbox layer; it previously scaffolded a Rust crate that could never be invoked.
- Wasm conformance test, CLI template test, and HTTP build/invoke test for the Wasm path.
- cgroup v2 CPU limits (`cpu.max` for a quota, `cpu.weight` for a share) alongside memory and
  PID limits, with the isolation report naming each controller it could or could not write.
- `rustfun doctor` probes for the sandbox launcher binary and the delegated CPU controller.

### Added
- Linux PID namespace via the `rustfun-sandbox-init` launcher; the payload runs as PID 1
  (ADR-0017).
- cgroup v2 `memory.max`/`pids.max` provisioning when the hierarchy is writable (ADR-0016).
- `rustfun doctor` reports launcher availability, namespace support, seccomp, and cgroups.
- CLI tests for JSON output purity and artifact digest stability across invocations.

### Fixed
- Memory limits no longer use `RLIMIT_AS`/`RLIMIT_DATA`, which killed Node.js at startup;
  cgroup v2 is used instead and the isolation report states which controls applied.
- Generated runtime bootstraps are excluded from artifact digests, so verification no longer
  reports corruption after the first invocation.
- Diagnostics (`tracing`) go to stderr, so `--json` output on stdout is always parseable.
