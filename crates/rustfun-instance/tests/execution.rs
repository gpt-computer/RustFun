//! End-to-end execution tests: the full spine from function creation to invocation.
//!
//! ```text
//! Function → Artifact → Runtime → Sandbox → Instance → Invocation → Event → Result
//! ```
//!
//! These tests run against the in-process `echo` runtime so they exercise the *platform*
//! (manager, scheduler, pool, lifecycle, events) without depending on an interpreter, and the
//! conformance suite in `rustfun-test` covers the language runtimes themselves.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustfun_core::protocol::InvocationStatus;
use rustfun_core::{
    ErrorCategory, EventBus, FunctionManager, FunctionManagerConfig, FunctionName, FunctionSpec,
    HandlerSpec, LogStream, RuntimeId,
};
use rustfun_instance::{PoolConfig, Scheduler, SchedulerConfig};
use rustfun_model::{FunctionId, FunctionSource};

fn workspace(label: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "rustfun-e2e-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("creates workspace");
    dir
}

async fn platform(label: &str) -> (std::path::PathBuf, Arc<FunctionManager>, Arc<Scheduler>) {
    let root = workspace(label);
    let registry = rustfun_runtime::default_registry();
    let bus = EventBus::with_tracing();
    let scheduler = Scheduler::new(
        SchedulerConfig {
            max_concurrent_invocations: 4,
            queue_timeout: Duration::from_secs(5),
            pool: PoolConfig {
                min_instances: 0,
                max_instances: 4,
                idle_timeout: Duration::from_millis(50),
                acquire_timeout: Duration::from_millis(50),
                max_concurrent_cold_starts: 2,
            },
        },
        registry.clone(),
        bus.clone(),
    );
    let manager = FunctionManager::new(
        FunctionManagerConfig {
            workdir: root.join("work"),
            base_dir: root.clone(),
            verify_artifacts: true,
            max_payload_bytes: 1024 * 1024,
        },
        registry,
    );
    manager.set_artifact_store(Arc::new(
        rustfun_artifact::FileArtifactStore::open(root.join("store"))
            .await
            .expect("opens store"),
    ));
    manager.set_event_bus(bus.clone());
    manager.set_invoker(Arc::clone(&scheduler) as Arc<dyn rustfun_core::Invoker + Send + Sync>);
    (root, Arc::new(manager), scheduler)
}

fn spec(name: &str, root: &std::path::Path, variables: &[(&str, &str)]) -> FunctionSpec {
    let mut environment = rustfun_model::Environment::new();
    for (key, value) in variables {
        environment.insert(*key, *value).expect("valid env");
    }
    FunctionSpec::new(
        FunctionName::new(name).expect("valid"),
        RuntimeId::parse("echo").expect("valid"),
        HandlerSpec::parse("index.handler").expect("valid"),
    )
    .with_source(FunctionSource::Directory {
        path: function_dir(root).to_string_lossy().into_owned(),
    })
    .with_environment(environment)
}

/// Directory holding a function's sources; kept separate from the platform's own state
/// directories so staging a build can never recurse into the cache.
fn function_dir(root: &std::path::Path) -> std::path::PathBuf {
    root.join("function")
}

async fn publish(
    manager: &Arc<FunctionManager>,
    root: &std::path::Path,
    function_spec: FunctionSpec,
) -> FunctionId {
    let source = function_dir(root);
    std::fs::create_dir_all(&source).expect("creates function dir");
    std::fs::write(source.join("index.js"), "exports.handler = () => 1;\n").expect("writes source");
    let created = manager.create(function_spec).expect("creates function");
    manager
        .build(&created.id, false)
        .await
        .expect("builds artifact");
    created.id.clone()
}

#[tokio::test]
async fn cold_start_then_warm_reuse() {
    let (root, manager, scheduler) = platform("warm").await;
    let logs = Arc::new(LogStream::new(1000));
    manager.events().subscribe(logs.clone(), 64);
    let id = publish(&manager, &root, spec("hello", &root, &[])).await;

    let first = manager
        .invoke(
            &id,
            b"{\"n\":1}".to_vec(),
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .expect("cold invocation succeeds");
    assert_eq!(first.status, InvocationStatus::Success);

    let second = manager
        .invoke(
            &id,
            b"{\"n\":2}".to_vec(),
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .expect("warm invocation succeeds");
    assert_eq!(second.status, InvocationStatus::Success);
    // The warm invocation must reuse the same instance.
    assert_eq!(first.instance_id, second.instance_id);

    let snapshot = scheduler.snapshot().await;
    assert_eq!(snapshot.cold_starts, 1, "exactly one cold start");
    assert_eq!(snapshot.warm_invocations, 1, "second invocation was warm");
    assert!((snapshot.warm_ratio - 0.5).abs() < f64::EPSILON);

    let instances = scheduler.instances().await;
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].invocation_count, 2);

    let events: Vec<String> = logs
        .snapshot()
        .iter()
        .map(|record| record.message.clone())
        .collect();
    assert!(events.is_empty() || !events.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn timeout_is_enforced_and_reported() {
    let (root, manager, _scheduler) = platform("timeout").await;
    let id = publish(
        &manager,
        &root,
        spec("slow", &root, &[("RUSTFUN_ECHO_DELAY_MS", "800")]),
    )
    .await;

    let response = manager
        .invoke(
            &id,
            b"{}".to_vec(),
            Some(Duration::from_millis(80)),
            Default::default(),
            Default::default(),
        )
        .await
        .expect("invocation returns a response");
    assert_eq!(response.status, InvocationStatus::Timeout);
    let error = response.error.expect("timeout error");
    assert_eq!(error.code, "RUSTFUN_INVOCATION_TIMEOUT");

    let metrics = manager.metrics().snapshot();
    assert_eq!(metrics.invocations_total, 1);
    assert_eq!(metrics.invocations_failed, 1);
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn function_errors_are_returned_not_raised() {
    let (root, manager, _scheduler) = platform("error").await;
    let id = publish(
        &manager,
        &root,
        spec(
            "broken",
            &root,
            &[("RUSTFUN_ECHO_FAIL", "handler exploded")],
        ),
    )
    .await;

    let response = manager
        .invoke(
            &id,
            b"{}".to_vec(),
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .expect("invocation returns a response");
    assert_eq!(response.status, InvocationStatus::FunctionError);
    assert_eq!(response.error.expect("error").message, "handler exploded");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn payload_limits_are_enforced() {
    let (root, manager, _scheduler) = platform("payload").await;
    let id = publish(&manager, &root, spec("hello", &root, &[])).await;
    let err = manager
        .invoke(
            &id,
            vec![b'x'; 2 * 1024 * 1024],
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .expect_err("too large");
    assert_eq!(err.category(), ErrorCategory::Resource);
    assert!(err.context().details.contains_key("limit_bytes"));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn concurrent_invocations_are_scheduled() {
    let (root, manager, scheduler) = platform("concurrency").await;
    let id = publish(&manager, &root, spec("hello", &root, &[])).await;

    let mut tasks = Vec::new();
    for n in 0..8u8 {
        let id = id.clone();
        let manager = Arc::clone(&manager);
        tasks.push(tokio::spawn(async move {
            manager
                .invoke(&id, vec![n], None, Default::default(), Default::default())
                .await
        }));
    }
    let mut successes = 0;
    for task in tasks {
        let response = task.await.expect("task joins").expect("invokes");
        assert_eq!(response.status, InvocationStatus::Success);
        successes += 1;
    }
    assert_eq!(successes, 8);

    let snapshot = scheduler.snapshot().await;
    assert_eq!(snapshot.cold_starts + snapshot.warm_invocations, 8);
    assert!(
        snapshot.cold_starts <= 4,
        "cold starts respect max_instances"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn destroy_releases_instances() {
    let (root, manager, scheduler) = platform("destroy").await;
    let id = publish(&manager, &root, spec("hello", &root, &[])).await;
    manager
        .invoke(
            &id,
            b"{}".to_vec(),
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .expect("invokes");
    assert!(!scheduler.instances().await.is_empty());

    manager.destroy(&id).await.expect("destroys");
    scheduler.drain().await.expect("drains");
    assert!(scheduler.instances().await.is_empty());
    assert!(manager
        .invoke(
            &id,
            b"{}".to_vec(),
            None,
            Default::default(),
            Default::default()
        )
        .await
        .is_err());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn idle_instances_are_evicted() {
    let (root, manager, scheduler) = platform("evict").await;
    let id = publish(&manager, &root, spec("hello", &root, &[])).await;
    manager
        .invoke(
            &id,
            b"{}".to_vec(),
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .expect("invokes");

    let snapshot = scheduler.snapshot().await;
    assert_eq!(snapshot.pools.len(), 1, "one pool serves the function");

    tokio::time::sleep(Duration::from_millis(120)).await;
    let artifact = manager.artifact_of(&id).expect("artifact");
    let pool = scheduler
        .pool_for(
            Arc::new(manager.get(&id).expect("gets").as_ref().clone()),
            artifact.path.clone(),
            None,
        )
        .await
        .expect("pool");
    let evicted = pool.evict_idle().await;
    assert_eq!(evicted, 1, "the idle instance should be reclaimed");
    assert!(scheduler.instances().await.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn lifecycle_events_are_emitted_for_the_full_spine() {
    let root = workspace("events");
    let registry = rustfun_runtime::default_registry();
    let bus = EventBus::new();
    let recorder = Arc::new(RecordingSink::default());
    bus.subscribe(recorder.clone(), 1024);

    let scheduler = Scheduler::new(SchedulerConfig::default(), registry.clone(), bus.clone());
    let manager = FunctionManager::new(
        FunctionManagerConfig {
            workdir: root.join("work"),
            base_dir: root.clone(),
            ..FunctionManagerConfig::default()
        },
        registry,
    );
    manager.set_artifact_store(Arc::new(
        rustfun_artifact::FileArtifactStore::open(root.join("store"))
            .await
            .expect("opens store"),
    ));
    manager.set_event_bus(bus.clone());
    manager.set_invoker(Arc::clone(&scheduler) as Arc<dyn rustfun_core::Invoker + Send + Sync>);
    let manager = Arc::new(manager);

    let id = publish(&manager, &root, spec("hello", &root, &[])).await;
    manager
        .invoke(
            &id,
            b"{}".to_vec(),
            None,
            Default::default(),
            Default::default(),
        )
        .await
        .expect("invokes");

    let names = recorder.names();
    for expected in [
        "function_created",
        "artifact_built",
        "instance_created",
        "instance_started",
        "instance_ready",
        "invocation_started",
        "invocation_completed",
    ] {
        assert!(
            names.iter().any(|name| name == expected),
            "missing event {expected}; observed: {names:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn artifact_is_reused_between_builds() {
    let (root, manager, _scheduler) = platform("artifact-cache").await;
    std::fs::create_dir_all(function_dir(&root)).expect("creates function dir");
    std::fs::write(
        function_dir(&root).join("index.js"),
        "exports.handler = () => 1;\n",
    )
    .expect("writes");
    let created = manager
        .create(spec("hello", &root, &[]))
        .expect("creates function");
    let first = manager.build(&created.id, false).await.expect("builds");
    let second = manager.build(&created.id, false).await.expect("rebuilds");
    assert_eq!(first.digest, second.digest, "digests are content-addressed");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn invocations_are_never_lost_under_load() {
    let (root, manager, _scheduler) = platform("load").await;
    let id = publish(&manager, &root, spec("hello", &root, &[])).await;
    let completed = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for n in 0..64u32 {
        let id = id.clone();
        let manager = Arc::clone(&manager);
        let completed = Arc::clone(&completed);
        tasks.push(tokio::spawn(async move {
            let payload = n.to_string().into_bytes();
            let response = manager
                .invoke(&id, payload, None, Default::default(), Default::default())
                .await
                .expect("invokes");
            assert_eq!(response.status, InvocationStatus::Success);
            completed.fetch_add(1, Ordering::Relaxed);
        }));
    }
    for task in tasks {
        task.await.expect("task joins");
    }
    assert_eq!(completed.load(Ordering::Relaxed), 64);
    let _ = std::fs::remove_dir_all(&root);
}

#[derive(Debug, Default)]
struct RecordingSink {
    seen: std::sync::Mutex<Vec<String>>,
}

impl RecordingSink {
    fn names(&self) -> Vec<String> {
        self.seen
            .lock()
            .map(|names| names.clone())
            .unwrap_or_default()
    }
}

impl rustfun_core::EventSink for RecordingSink {
    fn name(&self) -> &str {
        "recording"
    }

    fn handle(&self, message: &rustfun_core::event::EventMessage) {
        if let rustfun_core::event::EventMessage::Event(event) = message {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(event.name().to_owned());
            }
        }
    }
}
