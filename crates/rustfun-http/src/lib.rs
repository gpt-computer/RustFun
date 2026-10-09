//! The local development HTTP API.
//!
//! Thin handlers over [`InvocationService`]: routing and serialization live here, every
//! business rule stays in the core. Errors are rendered as the platform's structured error
//! object with the matching status code.
//!
//! ```text
//! GET    /health
//! GET    /metrics
//! GET    /runtimes
//! GET    /functions
//! POST   /functions
//! GET    /functions/:id
//! POST   /functions/:id/build
//! POST   /functions/:id/invoke
//! DELETE /functions/:id
//! GET    /instances
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use rustfun_core::protocol::InvocationStatus;
use rustfun_core::{ErrorContext, FunctionSpec, Result, RustFunError};
use rustfun_invoke::InvocationService;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

mod routes;

pub use routes::{Api, ApiResponse};

/// Run the development API until the process is stopped.
pub async fn serve(service: Arc<InvocationService>, addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await.map_err(|error| {
        RustFunError::io(format!("cannot bind {addr}: {error}")).with_context(
            ErrorContext::new()
                .operation("serve")
                .remediation("choose a different port with `--port`"),
        )
    })?;
    let bound = listener.local_addr().unwrap_or(addr);
    tracing::info!(address = %bound, "rustfun dev server listening");
    println!("rustfun dev server listening on http://{bound}");

    let api = Api::new(service);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(error = %error, "accept failed");
                continue;
            }
        };
        let api = api.clone();
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let api = api.clone();
                async move { Ok::<_, Infallible>(api.handle(request, peer).await) }
            });
            if let Err(error) = http1::Builder::new().serve_connection(io, service).await {
                tracing::debug!(peer = %peer, error = %error, "connection closed");
            }
        });
    }
}

/// A JSON error body, as returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Structured error, including code, category, and context.
    pub error: serde_json::Value,
}

/// Build a JSON response.
pub fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(value).unwrap_or_else(|error| {
        format!(
            "{{\"error\":\"{{\\\"code\\\":\\\"RUSTFUN_INTERNAL_ERROR\\\",\\\"message\\\":{}}}}}",
            serde_json::to_string(&error.to_string()).unwrap_or_default()
        )
        .into_bytes()
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from_static(b"{}")))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"{}"))))
        })
}

/// Convert an error into a response.
pub fn error_response(error: &RustFunError) -> Response<Full<Bytes>> {
    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let value = serde_json::json!({ "error": error });
    json(status, &value)
}

/// Body of a `POST /functions` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFunctionRequest {
    /// Function name.
    pub name: String,
    /// Runtime id.
    pub runtime: String,
    /// Handler.
    pub handler: String,
    /// Build immediately after registering.
    #[serde(default)]
    pub build: bool,
    /// Environment variables.
    #[serde(default)]
    pub environment: std::collections::BTreeMap<String, String>,
}

/// Body of a `POST /functions/:id/invoke` request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvokeRequest {
    /// JSON payload forwarded to the function.
    #[serde(default)]
    pub payload: serde_json::Value,
    /// Invocation timeout in milliseconds.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Metadata delivered with the invocation.
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
}

/// Summary of a function, as returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    /// Function id.
    pub id: String,
    /// Function name.
    pub name: String,
    /// Runtime id.
    pub runtime: String,
    /// Handler.
    pub handler: String,
    /// Lifecycle status.
    pub status: String,
    /// Artifact digest, when built.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// File count of the artifact, when built.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_count: Option<usize>,
}

impl FunctionSummary {
    /// Summarize a function spec.
    pub fn from_spec(
        spec: &FunctionSpec,
        digest: Option<String>,
        file_count: Option<usize>,
    ) -> Self {
        Self {
            id: spec.id.to_string(),
            name: spec.name.as_str().to_owned(),
            runtime: spec.runtime.to_string(),
            handler: spec.handler.as_str().to_owned(),
            status: spec.status.as_str().to_owned(),
            digest,
            file_count,
        }
    }
}

/// Body of an invocation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeResponse {
    /// Invocation id.
    pub invocation_id: String,
    /// Function id.
    pub function_id: String,
    /// Instance that served the invocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// Outcome.
    pub status: String,
    /// Function result, when the invocation succeeded.
    #[serde(default)]
    pub result: serde_json::Value,
    /// Error, when the invocation failed.
    #[serde(default)]
    pub error: serde_json::Value,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

impl InvokeResponse {
    /// Convert a protocol response into the API body.
    pub fn from_response(response: &rustfun_core::protocol::InvocationResponse) -> Self {
        let result = if response.payload.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice::<serde_json::Value>(&response.payload).unwrap_or_else(|_| {
                serde_json::Value::String(String::from_utf8_lossy(&response.payload).into_owned())
            })
        };
        Self {
            invocation_id: response.invocation_id.to_string(),
            function_id: response.function_id.to_string(),
            instance_id: response.instance_id.as_ref().map(ToString::to_string),
            status: response.status.as_str().to_owned(),
            result: if response.status == InvocationStatus::Success {
                result
            } else {
                serde_json::Value::Null
            },
            error: response
                .error
                .as_ref()
                .map(|error| {
                    serde_json::json!({ "code": error.code, "message": error.message, "detail": error.detail })
                })
                .unwrap_or(serde_json::Value::Null),
            duration_ms: response.duration_ms,
        }
    }
}

/// A running development server.
pub struct DevServer {
    address: SocketAddr,
    handle: tokio::task::JoinHandle<Result<()>>,
}

impl std::fmt::Debug for DevServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevServer")
            .field("address", &self.address)
            .finish()
    }
}

impl DevServer {
    /// Start a server bound to `addr`.
    pub async fn start(service: Arc<InvocationService>, addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(addr).await.map_err(|error| {
            RustFunError::io(format!("cannot bind {addr}: {error}"))
                .with_context(ErrorContext::new().operation("serve"))
        })?;
        let bound = listener
            .local_addr()
            .map_err(|error| RustFunError::io(format!("cannot read the bound address: {error}")))?;
        let api = Api::new(service);
        let handle = tokio::spawn(async move { run(listener, api).await });
        Ok(Self {
            address: bound,
            handle,
        })
    }

    /// The address the server is listening on.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Stop the server.
    pub async fn stop(self) {
        self.handle.abort();
    }
}

async fn run(listener: TcpListener, api: Api) -> Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(error = %error, "accept failed");
                continue;
            }
        };
        let api = api.clone();
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let api = api.clone();
                async move { Ok::<_, Infallible>(api.handle(request, peer).await) }
            });
            if let Err(error) = http1::Builder::new().serve_connection(io, service).await {
                tracing::debug!(peer = %peer, error = %error, "connection closed");
            }
        });
    }
}

/// Body of `GET /health`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    /// Overall status.
    pub status: String,
    /// RustFun version.
    pub version: String,
    /// Number of registered functions.
    pub functions: usize,
    /// Live instances.
    pub instances: usize,
    /// Uptime-independent probe duration.
    pub probe_ms: u64,
}

/// Extract the invocation timeout from a request.
pub(crate) fn timeout_of(request: &InvokeRequest) -> Option<Duration> {
    request.timeout_ms.map(Duration::from_millis)
}
