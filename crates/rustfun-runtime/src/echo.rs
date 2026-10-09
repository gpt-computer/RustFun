//! The in-process echo runtime.
//!
//! `echo` runs no external process: it answers with the payload it received (optionally
//! prefixed). It exists for three reasons:
//!
//! 1. the runtime conformance suite can validate the *platform* without depending on Node or
//!    Python being installed;
//! 2. benchmarks can measure platform overhead with the runtime cost removed;
//! 3. `rustfun dev` works on a machine with no interpreters installed.
//!
//! It is registered as a real runtime, but it is never a security boundary and never pretends
//! to be one.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustfun_core::protocol::{InvocationRequest, InvocationResponse};
use rustfun_core::runtime::{
    HealthStatus, InvocationOutcome, PrepareRequest, PreparedRuntime, RuntimeAdapter,
    RuntimeDiscovery, RuntimeInstance, StartRequest,
};
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_model::{
    Environment, InstanceId, InvocationId, RuntimeCapabilities, RuntimeFamily, RuntimeId,
    RuntimeVersion, SandboxKind,
};
use tokio::sync::Mutex;

/// Marker payload prefix: `{"echo": <payload>, "seq": <n>}`.
pub const ECHO_PREFIX: &str = "rustfun-echo:";

/// The in-process echo adapter.
#[derive(Debug, Clone, Default)]
pub struct EchoAdapter;

impl EchoAdapter {
    /// Create the adapter.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RuntimeAdapter for EchoAdapter {
    fn family(&self) -> RuntimeFamily {
        RuntimeFamily::Echo
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        RuntimeCapabilities::ECHO
    }

    async fn discover(&self) -> Result<Vec<RuntimeDiscovery>> {
        Ok(vec![RuntimeDiscovery::new(
            RuntimeId::new(RuntimeFamily::Echo, RuntimeVersion::Any),
            "in-process",
        )
        .with_reported_version(env!("CARGO_PKG_VERSION"))])
    }

    async fn prepare(&self, request: PrepareRequest) -> Result<PreparedRuntime> {
        let mut environment: Environment = request.environment.clone();
        environment.insert("RUSTFUN_HANDLER", request.handler.as_str())?;
        Ok(PreparedRuntime::new(
            request.runtime.clone(),
            vec!["echo".to_owned()],
            request.workdir,
            environment,
            self.capabilities(),
        ))
    }

    async fn start(&self, request: StartRequest) -> Result<Box<dyn RuntimeInstance>> {
        if request.spec.sandbox.kind != SandboxKind::Host {
            return Err(RustFunError::sandbox(
                "the echo runtime does not execute a process and only supports the host layer",
            )
            .with_context(
                ErrorContext::new()
                    .operation("start_instance")
                    .function(request.spec.name.as_str()),
            ));
        }
        let prefix = request
            .prepared
            .environment
            .get("RUSTFUN_ECHO_PREFIX")
            .map(str::to_owned)
            .unwrap_or_else(|| ECHO_PREFIX.to_owned());
        let delay = request
            .prepared
            .environment
            .get("RUSTFUN_ECHO_DELAY_MS")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let fail = request
            .prepared
            .environment
            .get("RUSTFUN_ECHO_FAIL")
            .map(str::to_owned);
        Ok(Box::new(EchoInstance {
            instance_id: request.instance_id,
            runtime: request.prepared.runtime.clone(),
            prefix,
            delay: Duration::from_millis(delay),
            fail,
            sequence: Arc::new(Mutex::new(0u64)),
        }))
    }
}

/// A live echo instance.
pub struct EchoInstance {
    instance_id: InstanceId,
    runtime: RuntimeId,
    prefix: String,
    delay: Duration,
    fail: Option<String>,
    sequence: Arc<Mutex<u64>>,
}

impl std::fmt::Debug for EchoInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EchoInstance")
            .field("instance_id", &self.instance_id)
            .field("runtime", &self.runtime)
            .field("delay_ms", &self.delay.as_millis())
            .finish()
    }
}

#[async_trait]
impl RuntimeInstance for EchoInstance {
    fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    fn runtime(&self) -> &RuntimeId {
        &self.runtime
    }

    async fn invoke(&self, request: InvocationRequest) -> Result<InvocationOutcome> {
        // The deadline is honoured by the runtime itself: a runtime that ignored it would let a
        // runaway handler occupy an instance forever.
        let deadline = request.remaining_deadline();
        let work = async {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
        };
        if let Some(deadline) = deadline {
            if tokio::time::timeout(deadline, work).await.is_err() {
                return Ok(InvocationOutcome {
                    response: InvocationResponse::timeout(
                        request.invocation_id.clone(),
                        request.function_id.clone(),
                        deadline.as_millis() as u64,
                    )
                    .with_instance(self.instance_id.clone()),
                    instance_healthy: true,
                });
            }
        } else {
            work.await;
        }
        let mut sequence = self.sequence.lock().await;
        *sequence += 1;
        let current = *sequence;
        drop(sequence);

        let response = match &self.fail {
            Some(message) => InvocationResponse::failure(
                request.invocation_id.clone(),
                request.function_id.clone(),
                rustfun_core::protocol::InvocationStatus::FunctionError,
                rustfun_core::protocol::InvocationError::new(
                    "RUSTFUN_FUNCTION_ERROR",
                    message.clone(),
                ),
            )
            .with_instance(self.instance_id.clone()),
            None => {
                let body = format!(
                    "{{\"prefix\":\"{}\",\"seq\":{current},\"payload\":{}}}",
                    self.prefix,
                    String::from_utf8_lossy(&request.payload)
                );
                InvocationResponse::success(
                    request.invocation_id.clone(),
                    request.function_id.clone(),
                    body.into_bytes(),
                )
                .with_instance(self.instance_id.clone())
            }
        };
        Ok(InvocationOutcome {
            response,
            instance_healthy: true,
        })
    }

    async fn health(&self) -> HealthStatus {
        HealthStatus::Healthy
    }
}

/// Helper used by tests to build an echo invocation request.
pub fn echo_request(payload: &[u8]) -> InvocationRequest {
    InvocationRequest::new(
        rustfun_model::RequestId::new(),
        InvocationId::new(),
        rustfun_model::FunctionId::new(),
        payload.to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfun_model::{FunctionName, FunctionSpec, HandlerSpec, SandboxPolicy};

    fn spec() -> std::sync::Arc<FunctionSpec> {
        std::sync::Arc::new(
            FunctionSpec::new(
                FunctionName::new("echo").expect("valid"),
                RuntimeId::parse("echo").expect("valid"),
                HandlerSpec::parse("index.handler").expect("valid"),
            )
            .with_sandbox(SandboxPolicy::host()),
        )
    }

    fn start_request(environment: &[(&str, &str)]) -> StartRequest {
        let spec = spec();
        let mut env = Environment::new();
        for (key, value) in environment {
            env.insert(*key, *value).expect("valid env");
        }
        let prepared = PreparedRuntime::new(
            RuntimeId::parse("echo").expect("valid"),
            vec!["echo".to_owned()],
            std::env::temp_dir(),
            env,
            RuntimeCapabilities::ECHO,
        );
        StartRequest {
            spec,
            instance_id: InstanceId::new(),
            prepared,
            prewarm: false,
        }
    }

    #[tokio::test]
    async fn echo_instance_roundtrips_a_payload() {
        let adapter = EchoAdapter::new();
        let instance = adapter.start(start_request(&[])).await.expect("starts");
        let outcome = instance
            .invoke(echo_request(b"{\"name\":\"world\"}"))
            .await
            .expect("invokes");
        assert!(outcome.response.is_success());
        let body = String::from_utf8_lossy(&outcome.response.payload);
        assert!(body.contains("rustfun-echo:"));
        assert!(body.contains("\"name\":\"world\""));
        assert!(outcome.instance_healthy);
    }

    #[tokio::test]
    async fn echo_instance_tracks_per_instance_sequence() {
        let adapter = EchoAdapter::new();
        let first = adapter.start(start_request(&[])).await.expect("starts");
        let second = adapter.start(start_request(&[])).await.expect("starts");
        let a = first.invoke(echo_request(b"1")).await.expect("invokes");
        let b = second.invoke(echo_request(b"1")).await.expect("invokes");
        assert!(String::from_utf8_lossy(&a.response.payload).contains("\"seq\":1"));
        assert!(String::from_utf8_lossy(&b.response.payload).contains("\"seq\":1"));
    }

    #[tokio::test]
    async fn echo_instance_can_simulate_a_function_error() {
        let adapter = EchoAdapter::new();
        let instance = adapter
            .start(start_request(&[("RUSTFUN_ECHO_FAIL", "boom")]))
            .await
            .expect("starts");
        let outcome = instance.invoke(echo_request(b"{}")).await.expect("invokes");
        assert_eq!(
            outcome.response.status,
            rustfun_core::protocol::InvocationStatus::FunctionError
        );
        assert_eq!(outcome.response.error.expect("error").message, "boom");
    }

    #[tokio::test]
    async fn echo_instance_can_simulate_a_slow_handler() {
        let adapter = EchoAdapter::new();
        let instance = adapter
            .start(start_request(&[("RUSTFUN_ECHO_DELAY_MS", "120")]))
            .await
            .expect("starts");
        let started = std::time::Instant::now();
        instance.invoke(echo_request(b"{}")).await.expect("invokes");
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn echo_refuses_process_sandbox_layers() {
        let adapter = EchoAdapter::new();
        let mut request = start_request(&[]);
        request.spec = std::sync::Arc::new(FunctionSpec {
            sandbox: SandboxPolicy {
                kind: SandboxKind::Linux,
                ..SandboxPolicy::default()
            },
            ..(*request.spec).clone()
        });
        let err = match adapter.start(request).await {
            Ok(_) => panic!("the echo runtime must refuse a process sandbox layer"),
            Err(err) => err,
        };
        assert_eq!(err.category(), rustfun_core::ErrorCategory::Sandbox);
    }

    #[tokio::test]
    async fn discovery_reports_the_in_process_runtime() {
        let discovered = EchoAdapter::new().discover().await.expect("discovers");
        assert_eq!(discovered.len(), 1);
        assert!(discovered[0].available);
        assert_eq!(discovered[0].executable, "in-process");
    }

    #[tokio::test]
    async fn health_is_healthy_until_shutdown() {
        let mut instance = EchoAdapter::new()
            .start(start_request(&[]))
            .await
            .expect("starts");
        assert_eq!(instance.health().await, HealthStatus::Healthy);
        instance.shutdown().await.expect("shuts down");
    }
}
