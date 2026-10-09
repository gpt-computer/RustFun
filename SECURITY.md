# RustFun Security Model

## Threat model

RustFun executes developer-supplied code. That code is **untrusted**: a function may be a
malicious artifact, a buggy script, or a supply-chain compromise. The platform must contain
it as far as the selected isolation layer allows, and it must never *claim* containment it
does not provide.

Assets worth protecting:

- The host filesystem outside the function root.
- Host environment variables and credentials.
- The host process tree, other functions, and platform control data.
- Host network reachability and the loopback interface.
- Platform availability (CPU, memory, PIDs, file descriptors, disk).

## Isolation layers

RustFun names the layer it is using. There is no "default sandbox" ambiguity.

### 1. Host process (`host`)

A child process of the RustFun process with a filtered environment, a bounded timeout, and a
deadline-enforced invocation protocol.

- Provides: environment filtering, timeout, payload limits, process-group cleanup,
  read-only-ish working directory by convention.
- Does **not** provide: filesystem isolation, network isolation, syscall filtering,
  privilege separation, resource enforcement beyond timeouts.
- **This is a development convenience and is not a security boundary.** `rustfun doctor`
  and the CLI label it accordingly.

### 2. Linux isolation (`linux`)

Namespaces (pid, mount, net, ipc, uts, user), cgroups v2 resource control, optional seccomp
filter, capability dropping, no-new-privileges, read-only root with an ephemeral writable
`/tmp`, and a restricted environment.

- Provides: filesystem and process isolation from the host, resource enforcement, optional
  network-off.
- Requires: Linux with unprivileged user namespaces enabled, or root. Availability is probed
  and reported; failures are structured errors, never silent downgrades.

### 3. WASM (`wasm`)

Wasmtime with WASI. Memory ceiling, fuel/epoch-based execution limits, scoped filesystem
preopens, no ambient network, and an explicit host-function allowlist.

- Provides: strong language-level memory and syscall isolation, portable across host
  platforms.
- Requires: functions compiled to WASM and adapted to the RustFun WASM ABI.

### 4. OCI (`oci`)

Container execution with image digest pinning, resource limits, and a controlled filesystem.

- Provides: image-isolated filesystem and dependency set, resource limits.
- Requires: a working OCI runtime on the host; probed by `rustfun doctor`.

## Rules

- Function code, artifact content, runtime binaries, and function output are all untrusted
  inputs and are validated defensively (path traversal, symlink attacks, oversized payloads,
  malformed protocol frames, digest verification).
- The host environment is **not** inherited implicitly. Function environments are built from
  an allowlist plus declared manifest values; reserved `RUSTFUN_*` variables are reserved.
- Command execution never uses a shell and never interpolates untrusted strings into a
  command line.
- Every invocation has a deadline. Exceeding it kills the instance's process group and
  produces a structured timeout error.
- Artifact digests are verified on every cache read and on artifact extraction.
- Limits on payload size, log size, and message size are enforced before allocation where
  practical, and always before parsing unbounded input.

## Reporting

Suspected sandbox violations emit a `SandboxViolation` event, are recorded as
`SandboxViolation` errors with the attempted operation, and cause the offending instance to be
terminated rather than reused.

## What RustFun actually enforces today

The `linux` layer, on a host with unprivileged user namespaces enabled, establishes:

| Control | Mechanism | Reported as |
| --- | --- | --- |
| User namespace | `unshare(CLONE_NEWUSER)` + uid/gid maps | `user_namespace` |
| PID namespace | `rustfun-sandbox-init` launcher; payload runs as PID 1 | `pid_namespace` |
| Mount namespace | `unshare(CLONE_NEWNS)` + private propagation | `mount_namespace` |
| Network namespace | `unshare(CLONE_NEWNET)` | `network_namespace` |
| IPC / UTS namespaces | `unshare(CLONE_NEWIPC|CLONE_NEWUTS)` | `ipc_namespace`, `uts_namespace` |
| Read-only function root | bind mount + `MS_RDONLY` remount | `read_only_function_root` |
| Private `/tmp` | tmpfs, `MS_NOEXEC`, 64 MiB | `private_tmp` |
| Capabilities | `capset` to the empty set | `capabilities_dropped` |
| Privilege escalation | `PR_SET_NO_NEW_PRIVS` | `no_new_privs` |
| Syscall escapes | seccomp-BPF (KILL) + fail-closed EPERM list | `seccomp_filter` |
| Open files / processes / CPU / core / file size | POSIX rlimits | `resource_limits` |
| Memory | cgroup v2 `memory.max` when the hierarchy is writable | `cgroup_v2` |
| Environment | `env_clear()` + declared variables + reserved `RUSTFUN_*` | `filtered_environment` |

Anything not established appears in `IsolationReport::skipped` with a reason, and
`rustfun doctor` reports the host capabilities behind those decisions.

### Two limits worth stating plainly

- **Memory without cgroups is not enforced.** POSIX `RLIMIT_AS`/`RLIMIT_DATA` are deliberately
  not used: since Linux 4.7 both count `mmap`, and V8 reserves very large anonymous ranges, so
  a POSIX cap kills Node at startup. Where the cgroup hierarchy is read-only, the report says
  `memory_limit_not_enforced_without_cgroups` instead of implying a limit exists (ADR-0016).
- **seccomp is an allow-list-by-exclusion.** The filter kills escape-capable syscalls
  (`ptrace`, `mount`, `*module`, `kexec_*`, `bpf`, `pivot_root`, `chroot`) and returns `EPERM`
  for calls runtimes probe (`socket`, `setns`, `unshare`, `memfd_create`). A test interprets the
  generated BPF program and asserts both behaviours, because a wrong jump offset would
  otherwise kill every syscall in production (ADR-0011).
