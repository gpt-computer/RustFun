//! HTTP API tests.
//!
//! The tests speak HTTP/1.1 over a real TCP connection so the router, the JSON encoding, and
//! the status-code mapping are all exercised end to end.

use std::net::SocketAddr;
use std::sync::Arc;

use rustfun_http::DevServer;
use rustfun_invoke::{InvocationService, ServiceConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (u16, serde_json::Value) {
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connects");
    let payload = body.map(|value| serde_json::to_vec(&value).unwrap_or_default());
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        payload.as_ref().map(|p| p.len()).unwrap_or(0)
    )
    .into_bytes();
    if let Some(payload) = payload {
        request.extend_from_slice(&payload);
    }
    stream.write_all(&request).await.expect("writes");
    stream.flush().await.expect("flushes");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("reads");
    let text = String::from_utf8_lossy(&response).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let value = serde_json::from_str(body.trim()).unwrap_or(serde_json::Value::Null);
    (status, value)
}

fn temp_project(label: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "rustfun-http-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("creates");
    dir
}

async fn server(label: &str) -> (SocketAddr, Arc<InvocationService>, std::path::PathBuf) {
    let project = temp_project(label);
    let dir = project.join("fn");
    std::fs::create_dir_all(&dir).expect("creates function");
    std::fs::write(dir.join("index.js"), "exports.handler = () => 1;\n").expect("writes");
    std::fs::write(
        dir.join("rustfun.toml"),
        "name = \"hello\"\nruntime = \"echo@*\"\nhandler = \"index.handler\"\n\n[build]\nsource = \".\"\n",
    )
    .expect("writes manifest");

    let service = Arc::new(
        InvocationService::new(ServiceConfig::new(&project).with_state_dir(project.join("state")))
            .await
            .expect("builds service"),
    );
    service.load_project().await.expect("loads project");
    let server = DevServer::start(Arc::clone(&service), "127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("starts server");
    let address = server.address();
    // Keep the server alive for the duration of the test.
    std::mem::forget(server);
    (address, service, project)
}

#[tokio::test]
async fn health_reports_version_and_counts() {
    let (address, _service, project) = server("health").await;
    let (status, body) = request(address, "GET", "/health", None).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["functions"], 1);
    assert!(body["version"].is_string());
    let _ = std::fs::remove_dir_all(&project);
}

#[tokio::test]
async fn functions_can_be_listed_fetched_and_invoked() {
    let (address, service, project) = server("functions").await;
    let (status, body) = request(address, "GET", "/functions", None).await;
    assert_eq!(status, 200);
    let functions = body.as_array().expect("array");
    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0]["name"], "hello");
    assert_eq!(functions[0]["status"], "pending");
    let id = functions[0]["id"].as_str().expect("id").to_owned();

    // Build before invoking: the API refuses to invoke an unbuilt function.
    let (status, _) = request(address, "GET", &format!("/functions/{id}"), None).await;
    assert_eq!(status, 200);
    let (status, body) = request(address, "POST", &format!("/functions/{id}/build"), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ready");
    assert!(body["digest"]
        .as_str()
        .expect("digest")
        .starts_with("sha256:"));

    let (status, body) = request(
        address,
        "POST",
        &format!("/functions/{id}/invoke"),
        Some(serde_json::json!({ "payload": { "name": "world" } })),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "success");
    assert!(body["invocation_id"].is_string());
    assert!(body["instance_id"].is_string());
    assert_eq!(
        body["result"]["payload"]["name"], "world",
        "the event reached the function"
    );

    let _ = std::fs::remove_dir_all(&project);
    let _ = service;
}

#[tokio::test]
async fn unknown_function_returns_404_with_structured_error() {
    let (address, _service, project) = server("missing").await;
    let (status, body) = request(address, "POST", "/functions/nope/invoke", None).await;
    assert_eq!(status, 404);
    assert_eq!(body["error"]["code"], "RUSTFUN_NOT_FOUND");
    assert!(body["error"]["message"].is_string());
    let _ = std::fs::remove_dir_all(&project);
}

#[tokio::test]
async fn invalid_requests_return_400_with_remediation() {
    let (address, _service, project) = server("invalid").await;
    let (status, body) = request(
        address,
        "POST",
        "/functions",
        Some(serde_json::json!({ "name": "Bad Name", "runtime": "echo", "handler": "a.b" })),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "RUSTFUN_VALIDATION");

    let (status, _) = request(address, "GET", "/not-a-route", None).await;
    assert_eq!(status, 404);
    let _ = std::fs::remove_dir_all(&project);
}

#[tokio::test]
async fn metrics_endpoint_is_prometheus_formatted() {
    let (address, _service, project) = server("metrics").await;
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connects");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .expect("writes");
    let mut response = String::new();
    stream.read_to_string(&mut response).await.expect("reads");
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("rustfun_invocations_total"));
    let _ = std::fs::remove_dir_all(&project);
}

#[tokio::test]
async fn instances_endpoint_reports_live_instances() {
    let (address, _service, project) = server("instances").await;
    let (status, body) = request(address, "GET", "/instances", None).await;
    assert_eq!(status, 200);
    assert_eq!(body.as_array().expect("array").len(), 0);
    let _ = std::fs::remove_dir_all(&project);
}

#[tokio::test]
async fn runtimes_endpoint_reports_discovery() {
    let (address, _service, project) = server("runtimes").await;
    let (status, body) = request(address, "GET", "/runtimes", None).await;
    assert_eq!(status, 200);
    let runtimes = body.as_array().expect("array");
    assert!(!runtimes.is_empty());
    assert!(runtimes.iter().any(|entry| entry["runtime"]
        .as_str()
        .is_some_and(|r| r.starts_with("node"))));
    let _ = std::fs::remove_dir_all(&project);
}

#[tokio::test]
async fn destroy_removes_the_function() {
    let (address, service, project) = server("destroy").await;
    let (_, body) = request(address, "GET", "/functions", None).await;
    let id = body[0]["id"].as_str().expect("id").to_owned();
    let (status, _) = request(address, "DELETE", &format!("/functions/{id}"), None).await;
    assert_eq!(status, 200);
    let (_, body) = request(address, "GET", "/functions", None).await;
    assert!(body.as_array().expect("array").is_empty());
    assert!(service
        .manager()
        .get_by_name(&rustfun_core::FunctionName::new("hello").expect("valid"))
        .is_err());
    let _ = std::fs::remove_dir_all(&project);
}

/// The API must serve a Wasm function end to end.
///
/// Wasm runs in-process rather than as a child process, so this exercises a different path
/// through the API than the echo/node fixtures do: build, instance creation, and invocation all
/// happen without a process ever being spawned.
#[tokio::test]
async fn a_wasm_function_builds_and_invokes_over_http() {
    let project = temp_project("wasm-api");
    let dir = project.join("fn");
    std::fs::create_dir_all(&dir).expect("creates function");
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../rustfun-cli/src/templates/echo.wat"
        ),
        dir.join("main.wat"),
    )
    .expect("copies module");
    std::fs::write(
        dir.join("rustfun.toml"),
        "name = \"wasmfn\"\nruntime = \"wasm@*\"\nhandler = \"main.wat.rustfun_handler\"\n\n[build]\nsource = \".\"\n\n[sandbox]\nkind = \"wasm\"\n",
    )
    .expect("writes manifest");

    let service = Arc::new(
        InvocationService::new(ServiceConfig::new(&project).with_state_dir(project.join("state")))
            .await
            .expect("builds service"),
    );
    service.load_project().await.expect("loads project");
    let server = DevServer::start(Arc::clone(&service), "127.0.0.1:0".parse().expect("addr"))
        .await
        .expect("starts server");
    let address = server.address();
    std::mem::forget(server);

    let (status, functions) = request(address, "GET", "/functions", None).await;
    assert_eq!(status, 200);
    let id = functions[0]["id"].as_str().expect("id").to_owned();

    let (status, _) = request(address, "POST", &format!("/functions/{id}/build"), None).await;
    assert_eq!(status, 200, "the Wasm module must build through the API");

    let (status, body) = request(
        address,
        "POST",
        &format!("/functions/{id}/invoke"),
        Some(serde_json::json!({ "payload": { "name": "http" } })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "success", "{body}");
    assert_eq!(body["result"]["message"], "hello from wasm");
    let _ = std::fs::remove_dir_all(&project);
}
