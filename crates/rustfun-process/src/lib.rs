//! The RustFun process engine.
//!
//! Every OS process RustFun starts goes through [`ProcessHandle`]. Nothing else in the
//! workspace calls `std::process::Command` or `tokio::process::Command` directly. Centralizing
//! this is what makes the platform's guarantees possible:
//!
//! - process groups, so killing an instance kills its descendants (no orphans, no zombies)
//! - a captured, size-bounded log buffer for stdout/stderr
//! - explicit, structured shutdown (SIGTERM → grace period → SIGKILL)
//! - resource accounting (wall time, exit status, peak RSS where available)
//! - a filtered environment: the host environment is never inherited implicitly
//!
//! # Example
//!
//! ```no_run
//! use rustfun_process::{ProcessConfig, ProcessEngine};
//! use std::collections::BTreeMap;
//!
//! # async fn demo() -> rustfun_core::Result<()> {
//! let engine = ProcessEngine::new();
//! let config = ProcessConfig::new("/bin/echo", ["hello"])
//!     .with_env(BTreeMap::from([("HELLO".to_owned(), "world".to_owned())]))
//!     .inherit_environment(false);
//! let mut process = engine.spawn(config).await?;
//! let status = process.wait().await?;
//! println!("{status:?}");
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustfun_core::{ErrorCategory, ErrorContext, Result, RustFunError};

pub mod engine;
pub mod handle;
pub mod log;
pub mod platform;

pub use engine::CapturedOutput;
pub use engine::ProcessEngine;
pub use handle::{ExitStatus, ProcessHandle, ProcessPipes};
pub use log::{LogBuffer, LogLine, LogStreamKind};
pub use platform::Platform;

/// How to launch a process.
#[derive(Clone)]
pub struct ProcessConfig {
    /// Executable path or name resolved on `PATH`.
    pub program: String,
    /// Arguments (never passed through a shell).
    pub args: Vec<String>,
    /// Environment variables to set.
    pub env: BTreeMap<String, String>,
    /// Whether to inherit the host environment.
    pub inherit_environment: bool,
    /// Working directory.
    pub current_dir: Option<std::path::PathBuf>,
    /// Grace period between SIGTERM and SIGKILL during shutdown.
    pub shutdown_grace: Duration,
    /// Maximum number of log lines retained per stream.
    pub max_log_lines: usize,
    /// Whether to place the child in its own process group.
    pub new_process_group: bool,
    /// Optional startup deadline.
    pub startup_timeout: Option<Duration>,
    /// Hook executed in the forked child between `fork` and `exec`.
    ///
    /// Used by the sandbox layer to establish namespaces and resource limits. The hook runs in
    /// a forked child of a possibly multi-threaded process, so it must only perform
    /// async-signal-safe work (this is why it takes `Fn`, not `FnMut`, and cannot capture
    /// non-`Sync` state).
    pub pre_exec: Option<Arc<dyn Fn() -> std::io::Result<()> + Send + Sync>>,
}

impl std::fmt::Debug for ProcessConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessConfig")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .field("inherit_environment", &self.inherit_environment)
            .field("current_dir", &self.current_dir)
            .field("new_process_group", &self.new_process_group)
            .field("has_pre_exec", &self.pre_exec.is_some())
            .finish()
    }
}

impl PartialEq for ProcessConfig {
    fn eq(&self, other: &Self) -> bool {
        self.program == other.program
            && self.args == other.args
            && self.env == other.env
            && self.inherit_environment == other.inherit_environment
            && self.current_dir == other.current_dir
            && self.shutdown_grace == other.shutdown_grace
            && self.max_log_lines == other.max_log_lines
            && self.new_process_group == other.new_process_group
    }
}

impl Eq for ProcessConfig {}

impl ProcessConfig {
    /// Create a configuration for `program` with `args`.
    pub fn new<I, S>(program: impl Into<String>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            env: BTreeMap::new(),
            inherit_environment: false,
            current_dir: None,
            shutdown_grace: Duration::from_millis(500),
            max_log_lines: 1024,
            new_process_group: true,
            startup_timeout: None,
            pre_exec: None,
        }
    }

    /// Install a `pre_exec` hook (used by the sandbox layer).
    #[must_use]
    pub fn with_pre_exec(
        mut self,
        hook: impl Fn() -> std::io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.pre_exec = Some(Arc::new(hook));
        self
    }

    /// Set environment variables.
    #[must_use]
    pub fn with_env(mut self, env: BTreeMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// Choose whether the host environment is inherited. Defaults to `false`.
    #[must_use]
    pub fn inherit_environment(mut self, inherit: bool) -> Self {
        self.inherit_environment = inherit;
        self
    }

    /// Set the working directory.
    #[must_use]
    pub fn with_current_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.current_dir = Some(dir.into());
        self
    }

    /// Set the graceful-shutdown grace period.
    #[must_use]
    pub fn with_shutdown_grace(mut self, grace: Duration) -> Self {
        self.shutdown_grace = grace;
        self
    }

    /// Set the retained log line budget.
    #[must_use]
    pub fn with_max_log_lines(mut self, lines: usize) -> Self {
        self.max_log_lines = lines;
        self
    }

    /// Set the startup deadline.
    #[must_use]
    pub fn with_startup_timeout(mut self, timeout: Duration) -> Self {
        self.startup_timeout = Some(timeout);
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.program.trim().is_empty() {
            return Err(RustFunError::validation("program must not be empty")
                .with_context(ErrorContext::new().operation("spawn")));
        }
        if self.program.contains('\0') || self.args.iter().any(|a| a.contains('\0')) {
            return Err(
                RustFunError::validation("program and arguments must not contain NUL")
                    .with_context(ErrorContext::new().operation("spawn")),
            );
        }
        if self.max_log_lines == 0 {
            return Err(RustFunError::validation("max_log_lines must be at least 1")
                .with_context(ErrorContext::new().operation("spawn")));
        }
        Ok(())
    }
}

/// The immutable description of how a process was launched.
///
/// Retained so that logs and diagnostics can describe a process after it exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpec {
    /// Executable path or name.
    pub program: String,
    /// Arguments.
    pub args: Vec<String>,
    /// Working directory, when set.
    pub current_dir: Option<std::path::PathBuf>,
    /// Whether the host environment was inherited.
    pub inherit_environment: bool,
    /// Grace period used during shutdown.
    pub shutdown_grace: Duration,
}

impl ProcessSpec {
    /// Render the command line for diagnostics.
    pub fn command_line(&self) -> String {
        std::iter::once(&self.program)
            .chain(self.args.iter())
            .map(|part| {
                if part.contains(' ') {
                    format!("'{part}'")
                } else {
                    part.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Resource accounting for a process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceUsage {
    /// Wall-clock lifetime in milliseconds.
    pub wall_ms: u64,
    /// Peak resident set size in kilobytes, when the platform reports it.
    pub max_rss_kb: Option<u64>,
    /// User + system CPU time in milliseconds, when the platform reports it.
    pub cpu_ms: Option<u64>,
}

/// Shared counters for a process tree.
#[derive(Debug, Default)]
pub struct ProcessCounters {
    /// Bytes written to the process stdin.
    pub stdin_bytes: AtomicU64,
    /// Bytes read from the process stdout.
    pub stdout_bytes: AtomicU64,
    /// Bytes read from the process stderr.
    pub stderr_bytes: AtomicU64,
}

impl ProcessCounters {
    /// Snapshot of the counters.
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.stdin_bytes.load(Ordering::Relaxed),
            self.stdout_bytes.load(Ordering::Relaxed),
            self.stderr_bytes.load(Ordering::Relaxed),
        )
    }
}

/// Convert a timeout into a structured error.
pub(crate) fn timeout_error(operation: &str, waited: Duration) -> RustFunError {
    RustFunError::timeout(format!(
        "{operation} exceeded its deadline after {}ms",
        waited.as_millis()
    ))
    .with_context(ErrorContext::new().operation(operation))
}

/// Classify a spawn failure.
pub(crate) fn spawn_error(program: &str, error: std::io::Error) -> RustFunError {
    let category = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCategory::Unavailable,
        std::io::ErrorKind::PermissionDenied => ErrorCategory::Sandbox,
        _ => ErrorCategory::Io,
    };
    let message = format!("cannot execute '{program}': {error}");
    let mut err = match category {
        ErrorCategory::Unavailable => RustFunError::unavailable(message),
        ErrorCategory::Sandbox => RustFunError::sandbox(message),
        _ => RustFunError::io(message),
    };
    if category == ErrorCategory::Unavailable {
        err = err.with_remediation(format!(
            "install '{program}' or set an explicit interpreter path for the runtime"
        ));
    }
    err.with_context(
        ErrorContext::new()
            .operation("spawn")
            .detail("program", program),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_validation_rejects_empty_program_and_nul() {
        assert!(ProcessConfig::new("", Vec::<String>::new())
            .validate()
            .is_err());
        assert!(ProcessConfig::new("sh\u{0}", Vec::<String>::new())
            .validate()
            .is_err());
        assert!(ProcessConfig::new("sh", vec!["-c\u{0}ls".to_owned()])
            .validate()
            .is_err());
        assert!(ProcessConfig::new("/bin/sh", Vec::<String>::new())
            .validate()
            .is_ok());
    }

    #[test]
    fn config_defaults_do_not_inherit_host_environment() {
        let config = ProcessConfig::new("/bin/true", Vec::<String>::new());
        assert!(!config.inherit_environment);
        assert!(config.new_process_group);
    }

    #[test]
    fn zero_log_budget_is_rejected() {
        let config = ProcessConfig::new("/bin/true", Vec::<String>::new()).with_max_log_lines(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn spawn_error_classifies_missing_program() {
        let err = spawn_error(
            "definitely-not-a-real-binary",
            std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert_eq!(err.category(), ErrorCategory::Unavailable);
        assert!(err.context().remediation.is_some());
    }

    #[test]
    fn counters_snapshot_is_stable() {
        let counters = ProcessCounters::default();
        counters.stdin_bytes.store(5, Ordering::Relaxed);
        counters.stdout_bytes.store(7, Ordering::Relaxed);
        counters.stderr_bytes.store(9, Ordering::Relaxed);
        assert_eq!(counters.snapshot(), (5, 7, 9));
    }
}
