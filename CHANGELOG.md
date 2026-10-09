# Changelog

All notable changes to RustFun.

## [Unreleased]

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
