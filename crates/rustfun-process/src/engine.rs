//! The process engine: the only place in RustFun that spawns OS processes.

use std::sync::Arc;
use std::time::Duration;

use rustfun_core::{ErrorContext, Result, RustFunError};
use tokio::process::Command;

use crate::handle::ProcessHandle;
use crate::log::LogBuffer;
use crate::{spawn_error, timeout_error, ProcessConfig, ProcessCounters, ProcessSpec};

/// Spawns and supervises child processes.
#[derive(Debug, Clone, Default)]
pub struct ProcessEngine;

impl ProcessEngine {
    /// Create an engine.
    pub fn new() -> Self {
        Self
    }

    /// Spawn a process.
    ///
    /// The child is placed in its own process group so that the whole tree can be terminated
    /// later, and the environment is filtered unless explicitly inherited.
    ///
    /// # Safety-relevant implementation note
    ///
    /// A `pre_exec` hook, when supplied, is installed with `std::process::Command::pre_exec`,
    /// which requires `unsafe` because it runs in the forked child. This is the only `unsafe`
    /// block in the crate; the hooks RustFun installs (see `rustfun-sandbox`) perform
    /// async-signal-safe syscalls only.
    #[allow(unsafe_code)]
    pub async fn spawn(&self, config: ProcessConfig) -> Result<Arc<ProcessHandle>> {
        config.validate()?;
        let spec = ProcessSpec::from(&config);

        let mut command = Command::new(&config.program);
        command
            .args(&config.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        // Environment: start from an empty map unless inheritance is requested.
        command.env_clear();
        if config.inherit_environment {
            for (key, value) in std::env::vars() {
                command.env(key, value);
            }
        }
        for (key, value) in &config.env {
            command.env(key, value);
        }
        if let Some(dir) = &config.current_dir {
            command.current_dir(dir);
        }

        #[cfg(unix)]
        {
            if config.new_process_group {
                // 0 means "use the child's own pid as the new process group id". This is the
                // safe, race-free way to create a group without forking ourselves.
                command.process_group(0);
            }
            if let Some(hook) = config.pre_exec.clone() {
                // SAFETY: `pre_exec` runs the hook in the forked child between `fork` and
                // `exec`. This is the only place RustFun uses that facility, and the hooks we
                // install perform async-signal-safe syscalls only (see `rustfun-sandbox`).
                unsafe {
                    command.pre_exec(move || hook());
                }
            }
        }

        let mut child = command
            .spawn()
            .map_err(|e| spawn_error(&config.program, e))?;
        let pid = child.id().ok_or_else(|| {
            RustFunError::internal("spawned process has no pid")
                .with_context(ErrorContext::new().operation("spawn"))
        })?;

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let logs = Arc::new(LogBuffer::new(config.max_log_lines));
        let counters = Arc::new(ProcessCounters::default());
        let handle = Arc::new(ProcessHandle::new(
            spec,
            pid,
            child,
            crate::ProcessPipes {
                stdin,
                stdout,
                stderr,
            },
            logs,
            counters,
        ));

        if let Some(timeout) = config.startup_timeout {
            // A startup deadline only bounds how long we wait for a *reported* failure; the
            // process itself is validated by the runtime adapter's handshake.
            if timeout.is_zero() {
                return Err(RustFunError::validation("startup timeout must be positive")
                    .with_context(ErrorContext::new().operation("spawn")));
            }
        }
        Ok(handle)
    }

    /// Spawn a process and wait for it to exit within `timeout`.
    pub async fn run(
        &self,
        config: ProcessConfig,
        timeout: std::time::Duration,
    ) -> Result<(Arc<ProcessHandle>, crate::handle::ExitStatus)> {
        let handle = self.spawn(config).await?;
        let stdout_task = handle.capture_stdout().await;
        let stderr_task = handle.capture_stderr().await;
        let status = handle.wait_timeout(timeout).await?;
        drain_tasks([stdout_task, stderr_task]).await;
        Ok((handle, status))
    }

    /// Run a command, capturing its output.
    ///
    /// Used for build steps and runtime version probes, never for function execution.
    pub async fn capture(
        &self,
        config: ProcessConfig,
        timeout: std::time::Duration,
    ) -> Result<CapturedOutput> {
        let handle = self.spawn(config).await?;
        let stdout_task = handle.capture_stdout().await;
        let stderr_task = handle.capture_stderr().await;
        let status = match handle.wait_timeout(timeout).await {
            Ok(status) => status,
            Err(err) if err.is_timeout() => {
                let _ = handle.shutdown().await;
                return Err(timeout_error("capture", timeout));
            }
            Err(err) => return Err(err),
        };
        drain_tasks([stdout_task, stderr_task]).await;
        Ok(CapturedOutput {
            stdout: handle.logs().to_text(),
            stderr: handle
                .log_lines()
                .into_iter()
                .filter(|l| l.stream == crate::log::LogStreamKind::Stderr)
                .map(|l| l.text)
                .collect::<Vec<_>>()
                .join("\n"),
            status,
        })
    }
}

/// Wait for the stream-capture tasks to finish, bounded so a stuck reader cannot hang a
/// caller after the child has already exited.
async fn drain_tasks(tasks: [Option<tokio::task::JoinHandle<()>>; 2]) {
    for task in tasks.into_iter().flatten() {
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }
}

/// Output of a captured command.
#[derive(Debug, Clone)]
pub struct CapturedOutput {
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
    /// Exit status.
    pub status: crate::handle::ExitStatus,
}

impl CapturedOutput {
    /// Whether the command exited successfully.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// First line of stdout, trimmed. Useful for version probes.
    pub fn first_line(&self) -> &str {
        self.stdout.lines().next().unwrap_or("").trim()
    }
}

impl From<&ProcessConfig> for ProcessSpec {
    fn from(config: &ProcessConfig) -> Self {
        ProcessSpec {
            program: config.program.clone(),
            args: config.args.clone(),
            current_dir: config.current_dir.clone(),
            inherit_environment: config.inherit_environment,
            shutdown_grace: config.shutdown_grace,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn have(program: &str) -> bool {
        std::path::Path::new(program).exists()
    }

    #[tokio::test]
    async fn spawn_captures_stdout_and_exit_code() {
        if !have("/bin/sh") {
            eprintln!("skipping: /bin/sh not available");
            return;
        }
        let engine = ProcessEngine::new();
        let config = ProcessConfig::new("/bin/sh", ["-c", "printf 'hello\\n'; exit 0"])
            .with_env(BTreeMap::from([("GREETING".to_owned(), "hi".to_owned())]));
        let (handle, status) = engine
            .run(config, Duration::from_secs(5))
            .await
            .expect("runs");
        assert!(status.is_success());
        assert!(handle.log_lines().iter().any(|l| l.text == "hello"));
    }

    #[tokio::test]
    async fn environment_is_not_inherited_by_default() {
        if !have("/usr/bin/env") && !have("/bin/env") {
            eprintln!("skipping: env not available");
            return;
        }
        let env_program = if have("/usr/bin/env") {
            "/usr/bin/env"
        } else {
            "/bin/env"
        };
        let engine = ProcessEngine::new();
        let (handle, status) = engine
            .run(
                ProcessConfig::new(env_program, Vec::<String>::new()),
                Duration::from_secs(5),
            )
            .await
            .expect("runs");
        assert!(status.is_success());
        let text = handle.logs().to_text();
        // The host environment (which always contains PATH) must not be inherited.
        assert!(
            !text.contains("PATH="),
            "host environment leaked into child: {text}"
        );
    }

    #[tokio::test]
    async fn explicit_environment_is_passed() {
        if !have("/bin/sh") {
            eprintln!("skipping: /bin/sh not available");
            return;
        }
        let engine = ProcessEngine::new();
        let config =
            ProcessConfig::new("/bin/sh", ["-c", "printf '%s' \"$RUSTFUN_TEST_VAR\""]).with_env(
                BTreeMap::from([("RUSTFUN_TEST_VAR".to_owned(), "value".to_owned())]),
            );
        let (handle, _) = engine
            .run(config, Duration::from_secs(5))
            .await
            .expect("runs");
        assert_eq!(handle.logs().to_text().trim(), "value");
    }

    #[tokio::test]
    async fn timeout_kills_the_process_group() {
        if !have("/bin/sh") {
            eprintln!("skipping: /bin/sh not available");
            return;
        }
        let engine = ProcessEngine::new();
        let config = ProcessConfig::new("/bin/sh", ["-c", "sleep 30"]);
        let handle = engine.spawn(config).await.expect("spawns");
        let err = handle
            .wait_timeout(Duration::from_millis(200))
            .await
            .expect_err("must time out");
        assert!(err.is_timeout());
        assert!(handle.was_terminated());
    }

    #[tokio::test]
    async fn shutdown_kills_long_running_children() {
        if !have("/bin/sh") {
            eprintln!("skipping: /bin/sh not available");
            return;
        }
        let engine = ProcessEngine::new();
        let handle = engine
            .spawn(ProcessConfig::new("/bin/sh", ["-c", "sleep 30"]))
            .await
            .expect("spawns");
        let status = handle
            .shutdown()
            .await
            .expect("shuts down")
            .expect("status");
        assert!(!status.is_success());
        assert!(status.killed_by_platform);
    }

    #[tokio::test]
    async fn missing_program_reports_unavailable() {
        let engine = ProcessEngine::new();
        let err = engine
            .spawn(ProcessConfig::new(
                "rustfun-definitely-missing-binary",
                Vec::<String>::new(),
            ))
            .await
            .expect_err("must fail");
        assert_eq!(err.category(), rustfun_core::ErrorCategory::Unavailable);
    }

    #[tokio::test]
    async fn capture_reports_both_streams() {
        if !have("/bin/sh") {
            eprintln!("skipping: /bin/sh not available");
            return;
        }
        let engine = ProcessEngine::new();
        let output = engine
            .capture(
                ProcessConfig::new("/bin/sh", ["-c", "echo out; echo err 1>&2"]),
                Duration::from_secs(5),
            )
            .await
            .expect("captures");
        assert!(output.is_success());
        assert_eq!(output.first_line(), "out");
        assert!(output.stderr.contains("err"));
    }

    #[tokio::test]
    async fn stdin_is_writable() {
        if !have("/bin/cat") {
            eprintln!("skipping: cat not available");
            return;
        }
        let engine = ProcessEngine::new();
        let handle = engine
            .spawn(ProcessConfig::new("/bin/cat", Vec::<String>::new()))
            .await
            .expect("spawns");
        let stdout_task = handle.capture_stdout().await;
        handle.write_stdin(b"payload").await.expect("writes");
        handle.close_stdin().await;
        let status = handle
            .wait_timeout(Duration::from_secs(5))
            .await
            .expect("waits");
        drain_tasks([stdout_task, None]).await;
        assert!(status.is_success());
        let (stdin_bytes, stdout_bytes, _) = handle.counters().snapshot();
        assert_eq!(stdin_bytes, 7);
        assert!(stdout_bytes >= 7);
    }
}
