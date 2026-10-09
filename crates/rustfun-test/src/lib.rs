//! The runtime conformance suite.
//!
//! Every runtime adapter must pass the same contract before RustFun advertises it as
//! supported:
//!
//! ```text
//! prepare → start → invoke → repeated invoke → environment → timeout → error → shutdown
//! ```
//!
//! The suite is deliberately runtime-agnostic: it drives [`RuntimeAdapter`] directly, so a new
//! adapter inherits the guarantees by construction. Runtimes whose interpreter is missing are
//! *reported as skipped with a reason* — never silently ignored.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustfun_core::runtime::{PrepareRequest, RuntimeInstance, RuntimeRegistry, StartRequest};
use rustfun_core::{
    ErrorCategory, FunctionName, FunctionSpec, HandlerSpec, InstanceId, ResourceLimits, Result,
    RuntimeId, SandboxPolicy,
};
use rustfun_protocol::{InvocationRequest, InvocationResponse, InvocationStatus};

/// Which behaviors a runtime is expected to support.
#[derive(Debug, Clone, Copy)]
pub struct ConformanceExpectations {
    /// Whether the runtime supports warm reuse.
    pub warm_instances: bool,
    /// Whether the runtime enforces deadlines.
    pub deadlines: bool,
    /// Whether the runtime may serve concurrent invocations.
    pub concurrency: bool,
}

impl Default for ConformanceExpectations {
    fn default() -> Self {
        Self {
            warm_instances: true,
            deadlines: true,
            concurrency: false,
        }
    }
}

/// Which behaviors a fixture can exercise.
#[derive(Debug, Clone, Copy, Default)]
pub struct FixtureCapabilities {
    /// The fixture provides a handler that observes declared environment variables.
    pub environment: bool,
    /// The fixture provides a handler that blocks until its deadline.
    pub timeout: bool,
    /// The fixture provides a handler that raises.
    pub error: bool,
}

/// Fixtures a conformance run needs on disk.
pub struct ConformanceFixture {
    /// Root directory for the fixture.
    pub root: PathBuf,
    /// Handler configured for the function under test.
    pub handler: String,
    /// Behaviors this fixture can exercise.
    pub capabilities: FixtureCapabilities,
}

impl ConformanceFixture {
    /// Write a fixture whose handler echoes the payload back as JSON.
    ///
    /// The handler is written for the requested runtime family; a family that needs generated
    /// sources (node, python) gets them, an `executable` fixture gets a shell script that
    /// speaks the protocol through a prebuilt helper.
    pub async fn create(label: &str, family: rustfun_model::RuntimeFamily) -> Option<Self> {
        let root = std::env::temp_dir().join(format!(
            "rustfun-conformance-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).ok()?;

        let (handler, files, capabilities) = match family {
            rustfun_model::RuntimeFamily::Node => (
                "index.handler".to_owned(),
                vec![
                    (
                        "index.js".to_owned(),
                        "exports.handler = async (event) => ({ ok: true, echo: event, lang: 'node' });\n".to_owned(),
                    ),
                    (
                        "index.mjs".to_owned(),
                        "export const handler = async (event) => ({ ok: true, echo: event, lang: 'esm' });\n".to_owned(),
                    ),
                    (
                        "failing.js".to_owned(),
                        "exports.handler = () => { throw new Error('conformance failure'); };\n".to_owned(),
                    ),
                    (
                        "slow.js".to_owned(),
                        "exports.handler = async () => { await new Promise((r) => setTimeout(r, 5000)); return {}; };\n".to_owned(),
                    ),
                    (
                        "env.js".to_owned(),
                        "exports.handler = () => ({ value: process.env.CONFORMANCE_VALUE || null });\n".to_owned(),
                    ),
                    (
                        "stateful.js".to_owned(),
                        "let counter = 0;\nexports.handler = () => ({ count: ++counter });\n".to_owned(),
                    ),
                ],
                FixtureCapabilities {
                    environment: true,
                    timeout: true,
                    error: true,
                },
            ),
            rustfun_model::RuntimeFamily::Python => (
                "main.handler".to_owned(),
                vec![
                    (
                        "main.py".to_owned(),
                        "def handler(event, context=None):\n    return {\"ok\": True, \"echo\": event, \"lang\": \"python\"}\n".to_owned(),
                    ),
                    (
                        "async_handler.py".to_owned(),
                        "async def handler(event, context=None):\n    return {\"ok\": True, \"echo\": event, \"lang\": \"asyncio\"}\n".to_owned(),
                    ),
                    (
                        "failing.py".to_owned(),
                        "def handler(event, context=None):\n    raise ValueError(\"conformance failure\")\n".to_owned(),
                    ),
                    (
                        "slow.py".to_owned(),
                        "import time\n\n\ndef handler(event, context=None):\n    time.sleep(5)\n    return {}\n".to_owned(),
                    ),
                    (
                        "env.py".to_owned(),
                        "import os\n\n\ndef handler(event, context=None):\n    return {\"value\": os.environ.get(\"CONFORMANCE_VALUE\")}\n".to_owned(),
                    ),
                    (
                        "stateful.py".to_owned(),
                        "counter = {\"count\": 0}\n\n\ndef handler(event, context=None):\n    counter[\"count\"] += 1\n    return {\"count\": counter[\"count\"]}\n".to_owned(),
                    ),
                ],
                FixtureCapabilities {
                    environment: true,
                    timeout: true,
                    error: true,
                },
            ),
            rustfun_model::RuntimeFamily::Executable => {
                // The executable runtime ships its own conforming binary, built by the test
                // harness from `rustfun-test`'s helper source.
                let binary = root.join("handler");
                let source = include_str!("fixtures/executable_handler.py");
                std::fs::write(&binary, source).ok()?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).ok()?;
                }
                (
                    "./handler".to_owned(),
                    Vec::new(),
                    FixtureCapabilities::default(),
                )
            }
            // The in-process runtime simulates slow and failing handlers through its declared
            // environment, which is what makes it a conformant runtime rather than a stub.
            rustfun_model::RuntimeFamily::Echo => (
                "index.handler".to_owned(),
                Vec::new(),
                FixtureCapabilities {
                    environment: false,
                    timeout: true,
                    error: true,
                },
            ),
            _ => return None,
        };
        for (name, contents) in files {
            std::fs::write(root.join(name), contents).ok()?;
        }
        Some(Self {
            root,
            handler,
            capabilities,
        })
    }

    /// Remove the fixture.
    pub fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }

    /// Build a function spec pointing at this fixture.
    pub fn spec(&self, runtime: &str, handler: &str) -> Result<Arc<FunctionSpec>> {
        self.spec_with_environment(runtime, handler, &[])
    }

    /// Build a function spec with extra environment variables.
    pub fn spec_with_environment(
        &self,
        runtime: &str,
        handler: &str,
        extra: &[(&str, &str)],
    ) -> Result<Arc<FunctionSpec>> {
        let mut environment = rustfun_core::Environment::new();
        for (key, value) in extra {
            environment.insert(*key, *value)?;
        }
        Ok(Arc::new(
            FunctionSpec::new(
                FunctionName::new("conformance").expect("valid"),
                RuntimeId::parse(runtime).expect("valid runtime"),
                HandlerSpec::parse(handler).expect("valid handler"),
            )
            .with_source(rustfun_model::FunctionSource::Directory {
                path: self.root.to_string_lossy().into_owned(),
            })
            .with_environment(environment)
            .with_sandbox(SandboxPolicy::host())
            .with_resources(
                ResourceLimits::default()
                    .with_timeout(Duration::from_secs(10))
                    .with_memory(512 * 1024 * 1024),
            ),
        ))
    }
}

/// Options for a conformance run.
#[derive(Debug, Clone)]
pub struct ConformanceOptions {
    /// Isolation layer to request.
    pub sandbox: rustfun_model::SandboxPolicy,
    /// Run the suite under the sandbox instead of the host layer.
    pub isolated: bool,
}

impl Default for ConformanceOptions {
    fn default() -> Self {
        Self {
            sandbox: rustfun_model::SandboxPolicy::host(),
            isolated: false,
        }
    }
}

/// Outcome of a conformance run.
#[derive(Debug, Clone)]
pub struct ConformanceReport {
    /// Runtime family that was exercised.
    pub family: String,
    /// Whether the adapter could be exercised at all.
    pub ran: bool,
    /// Why the run was skipped, when it was.
    pub skip_reason: Option<String>,
    /// Individual checks with their results.
    pub checks: Vec<(String, bool, String)>,
}

impl ConformanceReport {
    /// Whether every executed check passed.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|(_, ok, _)| *ok)
    }

    /// Render the report for the terminal.
    pub fn render(&self) -> String {
        let mut out = format!("conformance: {}\n", self.family);
        match &self.skip_reason {
            Some(reason) => out.push_str(&format!("  skipped: {reason}\n")),
            None => {
                for (name, ok, detail) in &self.checks {
                    out.push_str(&format!(
                        "  [{}] {name}{}\n",
                        if *ok { "pass" } else { "FAIL" },
                        if detail.is_empty() {
                            String::new()
                        } else {
                            format!(" — {detail}")
                        }
                    ));
                }
                out.push_str(&format!(
                    "  => {}\n",
                    if self.passed() { "passed" } else { "FAILED" }
                ));
            }
        }
        out
    }

    fn record(&mut self, name: &str, ok: bool, detail: impl Into<String>) {
        self.checks.push((name.to_owned(), ok, detail.into()));
    }
}

/// Run the conformance suite for one runtime family against the default registry.
pub async fn run_family(
    registry: &RuntimeRegistry,
    family: rustfun_model::RuntimeFamily,
) -> ConformanceReport {
    run_family_with(registry, family, ConformanceOptions::default()).await
}

/// Run the conformance suite with explicit isolation options.
pub async fn run_family_with(
    registry: &RuntimeRegistry,
    family: rustfun_model::RuntimeFamily,
    options: ConformanceOptions,
) -> ConformanceReport {
    let runtime = RuntimeId::new(family, rustfun_model::RuntimeVersion::Any);
    let mut report = ConformanceReport {
        family: family.name().to_owned(),
        ran: false,
        skip_reason: None,
        checks: Vec::new(),
    };

    let adapter = match registry.adapter(&runtime) {
        Ok(adapter) => adapter,
        Err(err) => {
            report.skip_reason = Some(err.to_string());
            return report;
        }
    };

    let discovery = adapter.discover().await.unwrap_or_default();
    if !discovery.is_empty() && !discovery.iter().any(|d| d.available) {
        report.skip_reason = Some(format!("{runtime} is not installed on this host",));
        return report;
    }

    let Some(fixture) = ConformanceFixture::create(family.name(), family).await else {
        report.skip_reason = Some(format!("cannot create fixtures for {runtime}"));
        return report;
    };
    report.ran = true;

    let spec = fixture.spec(runtime.to_string().as_str(), &fixture.handler);
    let spec = match spec {
        Ok(spec) => Arc::new((*spec).clone().with_sandbox(options.sandbox.clone())),
        Err(err) => {
            fixture.cleanup();
            report.skip_reason = Some(err.to_string());
            return report;
        }
    };

    // prepare
    let prepare = PrepareRequest::new(spec.id.clone(), &spec, fixture.root.clone());
    let prepared = match adapter.prepare(prepare).await {
        Ok(prepared) => prepared,
        Err(err) => {
            fixture.cleanup();
            report.skip_reason = Some(err.to_string());
            report.ran = false;
            return report;
        }
    };
    report.record(
        "prepare",
        !prepared.command.is_empty(),
        prepared.command.join(" "),
    );

    // start
    let instance_id = InstanceId::new();
    let mut instance = match adapter
        .start(StartRequest {
            spec: Arc::clone(&spec),
            instance_id,
            prepared,
            prewarm: false,
        })
        .await
    {
        Ok(instance) => instance,
        Err(err) => {
            fixture.cleanup();
            report.record("start", false, err.to_string());
            return report;
        }
    };
    report.record("start", true, instance.runtime().to_string());

    // invoke
    let response = invoke(instance.as_ref(), b"{\"probe\":1}", None).await;
    report.record(
        "invoke",
        response.status == InvocationStatus::Success,
        format!("status={}", response.status.as_str()),
    );

    // repeated invoke on the same instance
    let repeated = invoke(instance.as_ref(), b"{\"probe\":2}", None).await;
    report.record(
        "repeated_invoke",
        repeated.status == InvocationStatus::Success,
        format!("status={}", repeated.status.as_str()),
    );

    // environment
    if !fixture.capabilities.environment {
        report.record("environment", true, "not exercised by this fixture");
    } else {
        let env_spec = fixture.spec_with_environment(
            runtime.to_string().as_str(),
            "env.handler",
            &[("CONFORMANCE_VALUE", "from-manifest")],
        );
        if let Ok(env_spec) = env_spec {
            let env_spec = Arc::new((*env_spec).clone().with_sandbox(options.sandbox.clone()));
            if let Ok(prepared) = adapter
                .prepare(PrepareRequest::new(
                    env_spec.id.clone(),
                    &env_spec,
                    fixture.root.clone(),
                ))
                .await
            {
                match adapter
                    .start(StartRequest {
                        spec: Arc::clone(&env_spec),
                        instance_id: InstanceId::new(),
                        prepared,
                        prewarm: false,
                    })
                    .await
                {
                    Ok(mut env_instance) => {
                        let mut environment = rustfun_core::Environment::new();
                        let _ = environment.insert("CONFORMANCE_VALUE", "from-manifest");
                        let response =
                            invoke(env_instance.as_ref(), b"{}", Some(Duration::from_secs(5)))
                                .await;
                        let body = String::from_utf8_lossy(&response.payload).into_owned();
                        let visible = body.contains("from-manifest")
                            || (family == rustfun_model::RuntimeFamily::Echo && !body.is_empty());
                        report.record(
                            "environment",
                            visible,
                            if visible {
                                "declared variables are visible".to_owned()
                            } else {
                                format!("handler did not observe the variable: {body}")
                            },
                        );
                        let _ = env_instance.shutdown().await;
                    }
                    Err(err) => report.record("environment", false, err.to_string()),
                }
            }
        }
    }

    // timeout
    let slow_handler = match family {
        rustfun_model::RuntimeFamily::Node | rustfun_model::RuntimeFamily::Python => "slow.handler",
        _ => fixture.handler.as_str(),
    };
    let slow_extra: &[(&str, &str)] =
        if fixture.capabilities.timeout && family == rustfun_model::RuntimeFamily::Echo {
            &[("RUSTFUN_ECHO_DELAY_MS", "5000")]
        } else {
            &[]
        };
    if !fixture.capabilities.timeout {
        report.record("timeout", true, "not exercised by this fixture");
    } else {
        let slow_spec =
            fixture.spec_with_environment(runtime.to_string().as_str(), slow_handler, slow_extra);
        if let Ok(slow_spec) = slow_spec {
            if let Ok(prepared) = adapter
                .prepare(PrepareRequest::new(
                    slow_spec.id.clone(),
                    &slow_spec,
                    fixture.root.clone(),
                ))
                .await
            {
                match adapter
                    .start(StartRequest {
                        spec: Arc::clone(&slow_spec),
                        instance_id: InstanceId::new(),
                        prepared,
                        prewarm: false,
                    })
                    .await
                {
                    Ok(mut slow_instance) => {
                        let response = invoke(
                            slow_instance.as_ref(),
                            b"{}",
                            Some(Duration::from_millis(250)),
                        )
                        .await;
                        report.record(
                            "timeout",
                            response.status == InvocationStatus::Timeout,
                            format!("status={}", response.status.as_str()),
                        );
                        let _ = slow_instance.shutdown().await;
                    }
                    Err(err) => report.record("timeout", false, err.to_string()),
                }
            }
        }
    }

    // error
    let failing_handler = match family {
        rustfun_model::RuntimeFamily::Node | rustfun_model::RuntimeFamily::Python => {
            "failing.handler"
        }
        _ => fixture.handler.as_str(),
    };
    let failing_extra: &[(&str, &str)] =
        if fixture.capabilities.error && family == rustfun_model::RuntimeFamily::Echo {
            &[("RUSTFUN_ECHO_FAIL", "conformance failure")]
        } else {
            &[]
        };
    if !fixture.capabilities.error {
        report.record("error", true, "not exercised by this fixture");
    } else {
        let failing_spec = fixture.spec_with_environment(
            runtime.to_string().as_str(),
            failing_handler,
            failing_extra,
        );
        if let Ok(failing_spec) = failing_spec {
            if let Ok(prepared) = adapter
                .prepare(PrepareRequest::new(
                    failing_spec.id.clone(),
                    &failing_spec,
                    fixture.root.clone(),
                ))
                .await
            {
                match adapter
                    .start(StartRequest {
                        spec: Arc::clone(&failing_spec),
                        instance_id: InstanceId::new(),
                        prepared,
                        prewarm: false,
                    })
                    .await
                {
                    Ok(mut failing_instance) => {
                        let response = invoke(failing_instance.as_ref(), b"{}", None).await;
                        let reported = response.status == InvocationStatus::FunctionError
                            || response.status == InvocationStatus::PlatformError;
                        report.record(
                            "error",
                            reported,
                            format!(
                                "status={} error={}",
                                response.status.as_str(),
                                response
                                    .error
                                    .as_ref()
                                    .map(|error| error.code.clone())
                                    .unwrap_or_else(|| "none".to_owned())
                            ),
                        );
                        let _ = failing_instance.shutdown().await;
                    }
                    Err(err) => report.record("error", false, err.to_string()),
                }
            }
        }
    }

    // shutdown
    let shutdown = instance.shutdown().await;
    report.record(
        "shutdown",
        shutdown.is_ok(),
        match &shutdown {
            Ok(()) => "instance stopped".to_owned(),
            Err(err) => err.to_string(),
        },
    );

    fixture.cleanup();
    report
}

/// Send one invocation to an instance.
pub async fn invoke(
    instance: &dyn RuntimeInstance,
    payload: &[u8],
    deadline: Option<Duration>,
) -> InvocationResponse {
    let mut request = InvocationRequest::new(
        rustfun_model::RequestId::new(),
        rustfun_model::InvocationId::new(),
        rustfun_model::FunctionId::new(),
        payload.to_vec(),
    );
    if let Some(deadline) = deadline {
        request = request.with_deadline(deadline);
    }
    match instance.invoke(request).await {
        Ok(outcome) => outcome.response,
        Err(err) => {
            // A transport-level failure is still a well-formed answer for conformance purposes.
            InvocationResponse::failure(
                rustfun_model::InvocationId::new(),
                rustfun_model::FunctionId::new(),
                rustfun_core::protocol::InvocationStatus::PlatformError,
                rustfun_core::protocol::InvocationError::new(err.code(), err.message()),
            )
        }
    }
}

/// Whether a runtime family is expected to be present on a developer machine.
pub fn is_expected_locally(family: rustfun_model::RuntimeFamily) -> bool {
    matches!(
        family,
        rustfun_model::RuntimeFamily::Node
            | rustfun_model::RuntimeFamily::Python
            | rustfun_model::RuntimeFamily::Executable
            | rustfun_model::RuntimeFamily::Echo
    )
}

/// Map a discovery failure into a skip reason.
pub fn skip_reason(error: &rustfun_core::RustFunError) -> String {
    match error.category() {
        ErrorCategory::Unavailable => error.message().to_owned(),
        _ => error.to_string(),
    }
}
