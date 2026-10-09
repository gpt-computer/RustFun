//! The shared process-backed runtime instance.
//!
//! Node, Python, and generic-executable runtimes all differ only in *how they are launched*.
//! Once launched, they speak the same framed protocol on stdin/stdout, so the instance
//! implementation — deadlines, timeouts, log capture, health, shutdown — lives here and is
//! shared.
//!
//! # Security
//!
//! The process is started through the sandbox layer, so the environment is filtered and, when
//! the Linux layer is selected, namespaces and resource limits are applied. The instance never
//! shells out: the command line is a vector passed directly to `execve`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustfun_core::protocol::{
    Codec, FramedReader, FramedWriter, InvocationRequest, InvocationResponse, InvocationStatus,
    LogEntry, PROTOCOL_VERSION,
};
use rustfun_core::runtime::{
    reserved_environment, HealthStatus, InvocationOutcome, RuntimeInstance,
};
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_process::{LogStreamKind, ProcessEngine, ProcessHandle};
use rustfun_sandbox::{sandbox_for, SandboxRequest, SandboxedProcess};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

/// A runtime instance backed by a sandboxed OS process.
pub struct ProcessInstance {
    instance_id: rustfun_model::InstanceId,
    runtime: rustfun_model::RuntimeId,
    /// Function this instance serves; kept for diagnostics and pool bookkeeping.
    #[allow(dead_code)]
    function_id: rustfun_model::FunctionId,
    process: Arc<ProcessHandle>,
    report: rustfun_sandbox::IsolationReport,
    transport: Mutex<Box<dyn FramedChannel + Send>>,
    healthy: std::sync::atomic::AtomicBool,
    invocations: std::sync::atomic::AtomicU64,
    stderr_task: Option<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl std::fmt::Debug for ProcessInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessInstance")
            .field("instance_id", &self.instance_id)
            .field("runtime", &self.runtime)
            .field("pid", &self.process.pid())
            .field("report", &self.report)
            .finish()
    }
}

/// Object-safe framed channel over the process pipes.
///
/// `FramedTransport` requires a single `AsyncRead + AsyncWrite` value; the child's stdin and
/// stdout are separate pipes, so the channel is composed from two halves here. This keeps the
/// protocol crate free of any process dependency.
pub trait FramedChannel: Send {
    /// Send a request frame.
    fn send_request<'a>(
        &'a mut self,
        request: &'a InvocationRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;

    /// Receive a response frame.
    fn recv_response<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<InvocationResponse>> + Send + 'a>>;
}

struct PipeChannel {
    writer: FramedWriter<PipeWriter>,
    reader: FramedReader<PipeReader>,
}

impl PipeChannel {
    fn new(writer: PipeWriter, reader: PipeReader) -> Self {
        Self {
            // JSON is the default on the wire for interpreted runtimes: their bootstraps are
            // the peers here, and a human-readable frame is far easier to debug.
            writer: FramedWriter::new(writer).with_codec(Codec::Json),
            reader: FramedReader::new(reader),
        }
    }
}

impl FramedChannel for PipeChannel {
    fn send_request<'a>(
        &'a mut self,
        request: &'a InvocationRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move { self.writer.send(request).await.map_err(RustFunError::from) })
    }

    fn recv_response<'a>(
        &'a mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<InvocationResponse>> + Send + 'a>>
    {
        Box::pin(async move { self.reader.recv().await.map_err(RustFunError::from) })
    }
}

/// Write half of the channel (child stdin).
pub struct PipeWriter(tokio::process::ChildStdin);

impl AsyncWrite for PipeWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Read half of the channel (child stdout).
pub struct PipeReader(tokio::process::ChildStdout);

impl AsyncRead for PipeReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

/// Everything needed to launch a process-backed instance.
#[derive(Clone)]
pub struct ProcessLaunch {
    /// Command line (no shell).
    pub command: Vec<String>,
    /// Working directory (the function root).
    pub workdir: std::path::PathBuf,
    /// Per-instance environment.
    pub environment: BTreeMap<String, String>,
    /// Resource limits.
    pub resources: rustfun_model::ResourceLimits,
    /// Isolation policy.
    pub sandbox: rustfun_model::SandboxPolicy,
    /// Runtime identity, for reporting.
    pub runtime: rustfun_model::RuntimeId,
    /// Grace period before SIGKILL during shutdown.
    pub shutdown_grace: Duration,
}

impl ProcessLaunch {}

impl ProcessInstance {
    /// Start a sandboxed process and wrap it in a protocol-speaking instance.
    pub async fn start(
        instance_id: rustfun_model::InstanceId,
        function_id: rustfun_model::FunctionId,
        launch: ProcessLaunch,
    ) -> Result<ProcessInstance> {
        let strategy = sandbox_for(&launch.sandbox)?;
        let scratch = launch.workdir.join(".rustfun").join("tmp");
        tokio::fs::create_dir_all(&scratch).await.map_err(|e| {
            RustFunError::io(format!(
                "cannot create scratch dir {}: {e}",
                scratch.display()
            ))
            .with_context(ErrorContext::new().operation("start_instance"))
        })?;

        let request = SandboxRequest {
            policy: launch.sandbox.clone(),
            resources: launch.resources,
            function_root: launch.workdir.clone(),
            scratch_dir: scratch,
            command: launch.command.clone(),
            environment: launch.environment.clone(),
            shutdown_grace: launch.shutdown_grace,
        };
        let sandboxed: SandboxedProcess = strategy.start(&ProcessEngine::new(), request).await?;

        let stdin = sandboxed.process.take_stdin().await.ok_or_else(|| {
            RustFunError::runtime("sandboxed process has no stdin")
                .with_context(ErrorContext::new().operation("start_instance"))
        })?;
        let stdout = sandboxed.process.take_stdout().await.ok_or_else(|| {
            RustFunError::runtime("sandboxed process has no stdout")
                .with_context(ErrorContext::new().operation("start_instance"))
        })?;
        // stderr is not part of the protocol; it is captured so runtime diagnostics survive.
        let stderr_task = sandboxed.process.clone().capture_stderr().await;
        tracing::info!(
            instance = %instance_id,
            "instance started: {}",
            sandboxed.describe()
        );

        Ok(ProcessInstance {
            instance_id,
            runtime: launch.runtime,
            function_id,
            process: Arc::clone(&sandboxed.process),
            report: sandboxed.report,
            transport: Mutex::new(Box::new(PipeChannel::new(
                PipeWriter(stdin),
                PipeReader(stdout),
            ))),
            healthy: std::sync::atomic::AtomicBool::new(true),
            invocations: std::sync::atomic::AtomicU64::new(0),
            stderr_task: stderr_task.map(|task| std::sync::Mutex::new(Some(task))),
        })
    }

    /// Number of invocations served.
    pub fn invocation_count(&self) -> u64 {
        self.invocations.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Isolation that was actually established.
    pub fn report(&self) -> &rustfun_sandbox::IsolationReport {
        &self.report
    }
}

#[async_trait]
impl RuntimeInstance for ProcessInstance {
    fn instance_id(&self) -> &rustfun_model::InstanceId {
        &self.instance_id
    }

    fn runtime(&self) -> &rustfun_model::RuntimeId {
        &self.runtime
    }

    async fn invoke(&self, request: InvocationRequest) -> Result<InvocationOutcome> {
        if !self.healthy.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(RustFunError::runtime(format!(
                "instance {} is unhealthy",
                self.instance_id
            ))
            .with_context(
                ErrorContext::new()
                    .operation("invoke")
                    .instance_id(self.instance_id.clone())
                    .invocation_id(request.invocation_id.clone()),
            ));
        }
        self.invocations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let started = std::time::Instant::now();
        let invocation_id = request.invocation_id.clone();
        let function_id = request.function_id.clone();
        let deadline = request
            .remaining_deadline()
            .unwrap_or(Duration::from_secs(30));

        let outcome = {
            let mut channel = self.transport.lock().await;
            let send = channel.send_request(&request).await;
            if let Err(err) = send {
                self.mark_unhealthy();
                return Err(err.with_context(
                    ErrorContext::new()
                        .operation("invoke")
                        .instance_id(self.instance_id.clone())
                        .invocation_id(invocation_id),
                ));
            }
            match tokio::time::timeout(deadline, channel.recv_response()).await {
                Ok(Ok(response)) => response,
                Ok(Err(err)) => {
                    // A protocol failure leaves the stream in an unknown state: the instance is
                    // not reusable.
                    self.mark_unhealthy();
                    return Err(err.with_context(
                        ErrorContext::new()
                            .operation("invoke")
                            .instance_id(self.instance_id.clone())
                            .invocation_id(invocation_id),
                    ));
                }
                Err(_) => {
                    // Deadline exceeded: kill the process group; a timed-out function must not
                    // keep running in the background.
                    self.mark_unhealthy();
                    let _ = self.process.kill().await;
                    let mut response = InvocationResponse::timeout(
                        invocation_id.clone(),
                        function_id.clone(),
                        deadline.as_millis() as u64,
                    )
                    .with_instance(self.instance_id.clone());
                    response.duration_ms = started.elapsed().as_millis() as u64;
                    response.logs = self.logs();
                    return Ok(InvocationOutcome {
                        response,
                        instance_healthy: false,
                    });
                }
            }
        };

        let mut response = outcome;
        response.protocol_version = PROTOCOL_VERSION.0;
        response.instance_id = Some(self.instance_id.clone());
        response.duration_ms = started.elapsed().as_millis() as u64;
        if response.logs.is_empty() {
            response.logs = self.logs();
        }
        let healthy = response.status != InvocationStatus::PlatformError;
        if !healthy {
            self.mark_unhealthy();
        }
        Ok(InvocationOutcome {
            response,
            instance_healthy: healthy,
        })
    }

    async fn health(&self) -> HealthStatus {
        if !self.healthy.load(std::sync::atomic::Ordering::Relaxed) {
            return HealthStatus::Unhealthy;
        }
        match self.process.is_running().await {
            true => HealthStatus::Healthy,
            false => HealthStatus::Unhealthy,
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.mark_unhealthy();
        // Stop the stderr reader first so it cannot outlive the process it is reading from.
        if let Some(Ok(Some(task))) = self.stderr_task.take().map(std::sync::Mutex::into_inner) {
            task.abort();
        }
        let _ = self.process.shutdown().await;
        Ok(())
    }
}

impl ProcessInstance {
    fn mark_unhealthy(&self) {
        self.healthy
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Captured runtime output as protocol log entries.
    pub fn logs(&self) -> Vec<LogEntry> {
        self.process
            .log_lines()
            .into_iter()
            .map(|line| LogEntry {
                stream: match line.stream {
                    LogStreamKind::Stdout => "stdout".to_owned(),
                    LogStreamKind::Stderr => "stderr".to_owned(),
                },
                message: line.text,
                offset_ms: line.offset_ms,
            })
            .collect()
    }
}

/// Shared adapter behavior for runtimes that are launched as a process.
#[derive(Debug, Clone, Default)]
pub struct ProcessRuntimeAdapter {
    label: String,
}

impl ProcessRuntimeAdapter {
    /// Create a labelled adapter base.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }

    /// Label used in diagnostics.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Probe the interpreter and report its version.
    pub async fn probe_version(&self, candidates: &[&str]) -> Option<String> {
        let executable = crate::find_executable(candidates)?;
        let engine = ProcessEngine::new();
        let config = rustfun_process::ProcessConfig::new(executable, vec!["--version".to_owned()])
            .inherit_environment(true);
        let output = engine.capture(config, Duration::from_secs(10)).await.ok()?;
        if !output.is_success() {
            return None;
        }
        let text = if output.stdout.trim().is_empty() {
            output.stderr
        } else {
            output.stdout
        };
        let first = text.lines().next().unwrap_or("").trim().to_owned();
        if first.is_empty() {
            None
        } else {
            Some(first)
        }
    }

    /// Build the environment for an instance, including reserved variables.
    pub fn instance_environment(
        &self,
        spec: &rustfun_model::FunctionSpec,
        instance_id: &rustfun_model::InstanceId,
        extra: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>> {
        let reserved = reserved_environment(spec, instance_id, None)?;
        let mut environment = BTreeMap::new();
        for (key, value) in reserved.iter() {
            environment.insert(key.to_owned(), value.to_owned());
        }
        for (key, value) in extra {
            environment.insert(key.clone(), value.clone());
        }
        Ok(environment)
    }
}
