//! Process handles: lifecycle control, IO, and resource accounting.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustfun_core::{ErrorContext, Result, RustFunError};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

use crate::log::{LogBuffer, LogLine, LogStreamKind};
use crate::platform::{self, Platform};
use crate::{timeout_error, ProcessCounters, ProcessSpec, ResourceUsage};

/// Extract the terminating signal from a Unix exit status.
#[cfg(unix)]
fn exit_signal(status: std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal()
}

/// On non-Unix platforms RustFun cannot observe signals directly.
#[cfg(not(unix))]
fn exit_signal(_status: std::process::ExitStatus) -> Option<i32> {
    None
}

/// The pipes taken from a freshly spawned child.
pub struct ProcessPipes {
    /// Standard input.
    pub stdin: Option<ChildStdin>,
    /// Standard output.
    pub stdout: Option<ChildStdout>,
    /// Standard error.
    pub stderr: Option<ChildStderr>,
}

/// How a process exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    /// Exit code, when the process exited normally.
    pub code: Option<i32>,
    /// Terminating signal, when the process was killed.
    pub signal: Option<i32>,
    /// Wall-clock lifetime in milliseconds.
    pub wall_ms: u64,
    /// Whether the process was terminated by RustFun (deadline or shutdown).
    pub killed_by_platform: bool,
}

impl ExitStatus {
    /// Whether the process exited successfully.
    pub fn is_success(&self) -> bool {
        self.code == Some(0) && self.signal.is_none()
    }

    /// Human-readable description.
    pub fn describe(&self) -> String {
        match (self.code, self.signal) {
            (Some(0), _) => "exited successfully".to_owned(),
            (Some(code), _) => format!("exited with code {code}"),
            (None, Some(signal)) => format!("terminated by signal {signal}"),
            (None, None) => "terminated".to_owned(),
        }
    }
}

/// A running child process.
///
/// The handle owns the child, its pipes, and the captured log buffer. Dropping the handle
/// does **not** kill the process: call [`ProcessHandle::shutdown`] (or [`ProcessHandle::kill`])
/// so that teardown is always explicit.
pub struct ProcessHandle {
    spec: ProcessSpec,
    pid: u32,
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<ChildStdin>>,
    stdout: Mutex<Option<ChildStdout>>,
    stderr: Mutex<Option<ChildStderr>>,
    logs: Arc<LogBuffer>,
    counters: Arc<ProcessCounters>,
    started: Instant,
    terminated: AtomicBool,
}

impl std::fmt::Debug for ProcessHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessHandle")
            .field("program", &self.spec.program)
            .field("pid", &self.pid)
            .field("started_ms", &(self.started.elapsed().as_millis() as u64))
            .finish()
    }
}

impl ProcessHandle {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        spec: ProcessSpec,
        pid: u32,
        child: Child,
        pipes: ProcessPipes,
        logs: Arc<LogBuffer>,
        counters: Arc<ProcessCounters>,
    ) -> Self {
        Self {
            spec,
            pid,
            child: Mutex::new(Some(child)),
            stdin: Mutex::new(pipes.stdin),
            stdout: Mutex::new(pipes.stdout),
            stderr: Mutex::new(pipes.stderr),
            logs,
            counters,
            started: Instant::now(),
            terminated: AtomicBool::new(false),
        }
    }

    /// Process id.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The configuration this process was started with.
    pub fn spec(&self) -> &ProcessSpec {
        &self.spec
    }

    /// Captured log buffer.
    pub fn logs(&self) -> Arc<LogBuffer> {
        Arc::clone(&self.logs)
    }

    /// Retained log lines.
    pub fn log_lines(&self) -> Vec<LogLine> {
        self.logs.snapshot()
    }

    /// Resource counters.
    pub fn counters(&self) -> Arc<ProcessCounters> {
        Arc::clone(&self.counters)
    }

    /// Wall time since spawn.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Resource usage snapshot.
    pub fn usage(&self) -> ResourceUsage {
        ResourceUsage {
            wall_ms: self.started.elapsed().as_millis() as u64,
            max_rss_kb: platform::peak_rss_kb(self.pid),
            cpu_ms: None,
        }
    }

    /// Whether RustFun terminated this process.
    pub fn was_terminated(&self) -> bool {
        self.terminated.load(Ordering::Relaxed)
    }

    /// Take ownership of the child's stdin.
    pub async fn take_stdin(&self) -> Option<ChildStdin> {
        self.stdin.lock().await.take()
    }

    /// Take ownership of the child's stdout.
    pub async fn take_stdout(&self) -> Option<ChildStdout> {
        self.stdout.lock().await.take()
    }

    /// Write bytes to the child's stdin.
    pub async fn write_stdin(&self, bytes: &[u8]) -> Result<usize> {
        let mut guard = self.stdin.lock().await;
        let stdin = guard.as_mut().ok_or_else(|| {
            RustFunError::runtime("process stdin has already been taken").with_context(
                ErrorContext::new()
                    .operation("write_stdin")
                    .detail("pid", self.pid.to_string()),
            )
        })?;
        let written = stdin.write(bytes).await?;
        stdin.flush().await?;
        self.counters
            .stdin_bytes
            .fetch_add(written as u64, Ordering::Relaxed);
        Ok(written)
    }

    /// Close the child's stdin, signalling end of input.
    pub async fn close_stdin(&self) {
        if let Some(mut stdin) = self.stdin.lock().await.take() {
            let _ = stdin.shutdown().await;
        }
    }

    /// Continuously capture stdout into the log buffer.
    ///
    /// Used when the child does not speak the framed protocol on stdout. The returned
    /// handle completes once the stream reaches EOF, i.e. after the child exits.
    pub async fn capture_stdout(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let mut stdout = self.take_stdout().await?;
        let logs = Arc::clone(&self.logs);
        let counters = Arc::clone(&self.counters);
        Some(tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut lines = tokio::io::BufReader::new(&mut stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let len = line.len() as u64 + 1;
                counters.stdout_bytes.fetch_add(len, Ordering::Relaxed);
                logs.push(LogStreamKind::Stdout, line);
            }
        }))
    }

    /// Continuously capture stderr into the log buffer.
    pub async fn capture_stderr(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let mut stderr = self.stderr.lock().await.take()?;
        let logs = Arc::clone(&self.logs);
        let counters = Arc::clone(&self.counters);
        Some(tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut lines = tokio::io::BufReader::new(&mut stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let len = line.len() as u64 + 1;
                counters.stderr_bytes.fetch_add(len, Ordering::Relaxed);
                logs.push(LogStreamKind::Stderr, line);
            }
        }))
    }

    /// Wait for the process to exit.
    pub async fn wait(&self) -> Result<ExitStatus> {
        let mut guard = self.child.lock().await;
        let mut child = guard.take().ok_or_else(|| {
            RustFunError::runtime("process has already been reaped").with_context(
                ErrorContext::new()
                    .operation("wait")
                    .detail("pid", self.pid.to_string()),
            )
        })?;
        drop(guard);
        let status = child.wait().await?;
        Ok(self.finish_status(status.code(), exit_signal(status), false))
    }

    /// Wait with a deadline. On expiry the process group is killed and a timeout error is
    /// returned, so callers never leak a running child.
    pub async fn wait_timeout(&self, timeout: Duration) -> Result<ExitStatus> {
        let mut guard = self.child.lock().await;
        let Some(child) = guard.as_mut() else {
            drop(guard);
            return Err(RustFunError::runtime("process has already been reaped")
                .with_context(ErrorContext::new().operation("wait_timeout")));
        };
        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) => {
                drop(guard);
                Ok(self.finish_status(status.code(), exit_signal(status), false))
            }
            Ok(Err(err)) => {
                drop(guard);
                Err(
                    RustFunError::io(format!("waiting for process failed: {err}"))
                        .with_context(ErrorContext::new().operation("wait_timeout")),
                )
            }
            Err(_) => {
                drop(guard);
                self.terminate().await?;
                let _ = self.reap().await;
                Err(timeout_error("wait_timeout", timeout))
            }
        }
    }

    /// Send a signal to the process group (falling back to the process itself).
    pub async fn signal(&self, signal: i32) -> Result<()> {
        self.terminated.store(true, Ordering::Relaxed);
        if Platform::current().is_posix() {
            // Negative pid targets the process group created at spawn, so descendants die too.
            let group = -i32::try_from(self.pid).unwrap_or(i32::MAX);
            let sent = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(group),
                nix::sys::signal::Signal::try_from(signal)
                    .unwrap_or(nix::sys::signal::Signal::SIGTERM),
            );
            if let Err(nix::errno::Errno::ESRCH) = sent {
                return Ok(());
            }
            if sent.is_err() {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(self.pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            return Ok(());
        }
        let mut guard = self.child.lock().await;
        if let Some(child) = guard.as_mut() {
            child.start_kill()?;
        }
        Ok(())
    }

    /// Ask the process to terminate (SIGTERM on POSIX).
    pub async fn terminate(&self) -> Result<()> {
        self.signal(libc::SIGTERM).await
    }

    /// Kill the process group immediately (SIGKILL on POSIX).
    pub async fn kill(&self) -> Result<()> {
        self.signal(libc::SIGKILL).await
    }

    /// Graceful shutdown: terminate, wait for the grace period, then kill.
    pub async fn shutdown(&self) -> Result<Option<ExitStatus>> {
        let grace = self.spec.shutdown_grace;
        if let Err(err) = self.terminate().await {
            tracing::debug!(pid = self.pid, error = %err, "terminate failed during shutdown");
        }
        match self.wait_timeout(grace).await {
            Ok(status) => Ok(Some(status)),
            Err(err) if err.is_timeout() => {
                let _ = self.kill().await;
                let status = self.reap().await?;
                Ok(status)
            }
            Err(err) => Err(err),
        }
    }

    async fn reap(&self) -> Result<Option<ExitStatus>> {
        let mut guard = self.child.lock().await;
        let Some(mut child) = guard.take() else {
            return Ok(None);
        };
        drop(guard);
        match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
            Ok(Ok(status)) => Ok(Some(self.finish_status(
                status.code(),
                exit_signal(status),
                true,
            ))),
            _ => Ok(None),
        }
    }

    fn finish_status(&self, code: Option<i32>, signal: Option<i32>, killed: bool) -> ExitStatus {
        ExitStatus {
            code,
            signal,
            wall_ms: self.started.elapsed().as_millis() as u64,
            killed_by_platform: killed || self.was_terminated(),
        }
    }

    /// Whether the process is still tracked by this handle.
    pub async fn is_running(&self) -> bool {
        self.child.lock().await.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_status_description() {
        assert!(ExitStatus {
            code: Some(0),
            signal: None,
            wall_ms: 1,
            killed_by_platform: false
        }
        .is_success());
        assert_eq!(
            ExitStatus {
                code: Some(3),
                signal: None,
                wall_ms: 1,
                killed_by_platform: false
            }
            .describe(),
            "exited with code 3"
        );
        assert_eq!(
            ExitStatus {
                code: None,
                signal: Some(9),
                wall_ms: 1,
                killed_by_platform: true
            }
            .describe(),
            "terminated by signal 9"
        );
    }
}
