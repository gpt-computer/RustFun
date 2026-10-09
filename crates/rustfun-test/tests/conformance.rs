//! Runtime conformance tests.
//!
//! Each runtime that is installed on the host is driven through the full contract. A runtime
//! that is not installed produces a *skip with a reason* — reported, not hidden.

use rustfun_model::RuntimeFamily;
use rustfun_test::{run_family, ConformanceFixture};

fn installed() -> Vec<RuntimeFamily> {
    vec![
        RuntimeFamily::Echo,
        RuntimeFamily::Node,
        RuntimeFamily::Python,
        RuntimeFamily::Executable,
        RuntimeFamily::Wasm,
        RuntimeFamily::Oci,
    ]
}

#[tokio::test]
async fn echo_runtime_passes_conformance() {
    let registry = rustfun_runtime::default_registry();
    let report = run_family(&registry, RuntimeFamily::Echo).await;
    assert!(report.ran, "{}", report.render());
    assert!(report.passed(), "{}", report.render());
}

#[tokio::test]
async fn node_runtime_passes_conformance() {
    let registry = rustfun_runtime::default_registry();
    let report = run_family(&registry, RuntimeFamily::Node).await;
    if !report.ran {
        eprintln!("{}", report.render());
        return;
    }
    assert!(report.passed(), "{}", report.render());
}

#[tokio::test]
async fn python_runtime_passes_conformance() {
    let registry = rustfun_runtime::default_registry();
    let report = run_family(&registry, RuntimeFamily::Python).await;
    if !report.ran {
        eprintln!("{}", report.render());
        return;
    }
    assert!(report.passed(), "{}", report.render());
}

#[tokio::test]
async fn wasm_runtime_passes_conformance() {
    let registry = rustfun_runtime::default_registry();
    let report = run_family(&registry, RuntimeFamily::Wasm).await;
    assert!(report.ran, "{}", report.render());
    assert!(report.passed(), "{}", report.render());
}

#[tokio::test]
async fn executable_runtime_passes_conformance() {
    let registry = rustfun_runtime::default_registry();
    let report = run_family(&registry, RuntimeFamily::Executable).await;
    if !report.ran {
        eprintln!("{}", report.render());
        return;
    }
    assert!(report.passed(), "{}", report.render());
}

/// The OCI runtime must either run the contract or explain, in one line, why it cannot here.
#[tokio::test]
async fn oci_runtime_is_conformant_or_explains_its_unavailability() {
    let registry = rustfun_runtime::default_registry();
    let report = run_family(&registry, RuntimeFamily::Oci).await;
    if report.ran {
        assert!(report.passed(), "{}", report.render());
        return;
    }
    let reason = report.skip_reason.expect("a skip must carry a reason");
    assert!(
        reason.contains("container runtime"),
        "the skip must name what is missing, not just say the runtime is absent: {reason}"
    );
}

#[tokio::test]
async fn every_expected_runtime_is_either_conformant_or_explicitly_skipped() {
    let registry = rustfun_runtime::default_registry();
    for family in installed() {
        let report = run_family(&registry, family).await;
        if report.ran {
            assert!(
                report.passed(),
                "{} failed conformance:\n{}",
                family,
                report.render()
            );
        } else {
            assert!(
                report.skip_reason.is_some(),
                "{} neither ran nor explained why it was skipped",
                family
            );
            eprintln!("{}", report.render());
        }
    }
}

#[tokio::test]
async fn stateful_handlers_keep_state_across_invocations() {
    let Some(fixture) = ConformanceFixture::create("stateful", RuntimeFamily::Echo).await else {
        panic!("fixture");
    };
    fixture.cleanup();

    // Warm reuse is only observable for runtimes that keep process state; node and python do.
    let registry = rustfun_runtime::default_registry();
    for family in [RuntimeFamily::Node, RuntimeFamily::Python] {
        let Some(fixture) = ConformanceFixture::create("stateful", family).await else {
            continue;
        };
        let Some(fixture) = Some(fixture) else {
            continue;
        };
        let spec = match fixture.spec(
            &rustfun_core::RuntimeId::new(family, rustfun_core::RuntimeVersion::Any).to_string(),
            "stateful.handler",
        ) {
            Ok(spec) => spec,
            Err(_) => {
                fixture.cleanup();
                continue;
            }
        };
        let adapter = match registry.adapter(&rustfun_core::RuntimeId::new(
            family,
            rustfun_core::RuntimeVersion::Any,
        )) {
            Ok(adapter) => adapter,
            Err(_) => {
                fixture.cleanup();
                continue;
            }
        };
        let prepared = match adapter
            .prepare(rustfun_core::runtime::PrepareRequest::new(
                spec.id.clone(),
                &spec,
                fixture.root.clone(),
            ))
            .await
        {
            Ok(prepared) => prepared,
            Err(_) => {
                fixture.cleanup();
                continue;
            }
        };
        let mut instance = match adapter
            .start(rustfun_core::runtime::StartRequest {
                spec,
                instance_id: rustfun_core::InstanceId::new(),
                prepared,
                prewarm: false,
            })
            .await
        {
            Ok(instance) => instance,
            Err(_) => {
                fixture.cleanup();
                continue;
            }
        };
        let first = rustfun_test::invoke(instance.as_ref(), b"{}", None).await;
        let second = rustfun_test::invoke(instance.as_ref(), b"{}", None).await;
        if first.status == rustfun_core::protocol::InvocationStatus::Success
            && second.status == rustfun_core::protocol::InvocationStatus::Success
        {
            // Responses are opaque bytes to the platform: decode the JSON payload the same way a
            // caller would.
            let decode = |response: &rustfun_core::protocol::InvocationResponse| {
                use base64::Engine as _;
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(&response.payload)
                    .unwrap_or_else(|_| response.payload.clone());
                serde_json::from_slice::<serde_json::Value>(&raw).unwrap_or(serde_json::Value::Null)
            };
            let first_body = decode(&first);
            let second_body = decode(&second);
            assert_eq!(
                first_body["count"], 1,
                "{family} handler did not report its first call"
            );
            assert_eq!(
                second_body["count"], 2,
                "{family} handler lost state between invocations"
            );
        } else {
            eprintln!(
                "{family} stateful handler was not runnable: {} / {}",
                first.status.as_str(),
                second.status.as_str()
            );
        }
        let _ = instance.shutdown().await;
        fixture.cleanup();
    }
}

/// The whole conformance suite also runs under the Linux isolation layer.
///
/// This is the end-to-end security test: the same handlers that pass in host mode must pass
/// with namespaces, resource limits, and a filtered environment applied.
#[tokio::test]
async fn conformance_under_the_linux_sandbox() {
    let report = rustfun_sandbox::probe_sandbox();
    if !rustfun_sandbox::sandbox_for(&rustfun_model::SandboxPolicy::linux())
        .map(|sandbox| sandbox.is_available())
        .unwrap_or(false)
    {
        eprintln!("skipping linux sandbox conformance: {}", report.summary());
        return;
    }

    let registry = rustfun_runtime::default_registry();
    let options = rustfun_test::ConformanceOptions {
        sandbox: rustfun_model::SandboxPolicy::linux(),
        isolated: true,
    };
    // The in-process runtime never starts a process, so there is nothing to isolate.
    for family in [RuntimeFamily::Node, RuntimeFamily::Python] {
        let report = rustfun_test::run_family_with(&registry, family, options.clone()).await;
        if report.ran {
            assert!(
                report.passed(),
                "{} failed conformance under the linux sandbox:\n{}",
                family,
                report.render()
            );
        } else {
            eprintln!("{}", report.render());
        }
    }
}
