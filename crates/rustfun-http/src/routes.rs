//! Routing for the development API.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use rustfun_core::{FunctionName, FunctionSource, FunctionSpec, HandlerSpec, RuntimeId};
use rustfun_invoke::InvocationService;

use crate::{error_response, json, CreateFunctionRequest, Health, InvokeRequest, InvokeResponse};

/// A response produced by the router, exposed for tests.
pub type ApiResponse = Response<http_body_util::Full<Bytes>>;

/// The API router.
#[derive(Clone)]
pub struct Api {
    service: Arc<InvocationService>,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api").finish()
    }
}

impl Api {
    /// Create a router over a service.
    pub fn new(service: Arc<InvocationService>) -> Self {
        Self { service }
    }

    /// Route a request.
    pub async fn handle(&self, request: Request<Incoming>, _peer: SocketAddr) -> ApiResponse {
        let method = request.method().clone();
        let path = request.uri().path().trim_end_matches('/').to_owned();
        let path = if path.is_empty() { "/" } else { path.as_str() };
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        match (method.as_str(), segments.as_slice()) {
            ("GET", ["health"]) => self.health().await,
            ("GET", ["metrics"]) => self.metrics(),
            ("GET", ["runtimes"]) => self.runtimes().await,
            ("GET", ["functions"]) => self.list_functions(),
            ("POST", ["functions"]) => self.create_function(request).await,
            ("GET", ["functions", id]) => self.get_function(id),
            ("DELETE", ["functions", id]) => self.destroy_function(id).await,
            ("POST", ["functions", id, "build"]) => self.build_function(id).await,
            ("POST", ["functions", id, "invoke"]) => self.invoke(id, request).await,
            ("GET", ["instances"]) => self.instances().await,
            _ => error_response(&not_found(path)),
        }
    }

    async fn health(&self) -> ApiResponse {
        let started = Instant::now();
        let snapshot = self.service.metrics().await;
        let health = Health {
            status: "ok".to_owned(),
            version: rustfun_core::model::VERSION.to_owned(),
            functions: self.service.manager().len(),
            instances: snapshot.pools.values().map(|pool| pool.instances).sum(),
            probe_ms: started.elapsed().as_millis() as u64,
        };
        json(StatusCode::OK, &health)
    }

    fn metrics(&self) -> ApiResponse {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4")
            .header("cache-control", "no-store")
            .body(http_body_util::Full::new(Bytes::from(
                self.service.prometheus(),
            )))
            .unwrap_or_else(|_| Response::new(http_body_util::Full::new(Bytes::from_static(b""))))
    }

    async fn runtimes(&self) -> ApiResponse {
        let discovered = self.service.registry().discover_all().await;
        let payload: Vec<serde_json::Value> = discovered
            .into_iter()
            .map(|(runtime, result)| match result {
                Ok(found) => serde_json::json!({
                    "runtime": runtime.to_string(),
                    "available": found.iter().any(|d| d.available),
                    "installations": found,
                }),
                Err(error) => serde_json::json!({
                    "runtime": runtime.to_string(),
                    "available": false,
                    "error": error.to_string(),
                }),
            })
            .collect();
        json(StatusCode::OK, &payload)
    }

    fn list_functions(&self) -> ApiResponse {
        let functions: Vec<crate::FunctionSummary> = self
            .service
            .manager()
            .list()
            .iter()
            .map(|spec| {
                let artifact = self.service.manager().artifact_of(&spec.id);
                crate::FunctionSummary::from_spec(
                    spec,
                    artifact.as_ref().map(|a| a.digest.to_string()),
                    artifact.map(|a| a.file_count),
                )
            })
            .collect();
        json(StatusCode::OK, &functions)
    }

    fn get_function(&self, id: &str) -> ApiResponse {
        match resolve(self.service.as_ref(), id) {
            Ok(spec) => {
                let artifact = self.service.manager().artifact_of(&spec.id);
                json(
                    StatusCode::OK,
                    &crate::FunctionSummary::from_spec(
                        &spec,
                        artifact.as_ref().map(|a| a.digest.to_string()),
                        artifact.map(|a| a.file_count),
                    ),
                )
            }
            Err(error) => error_response(&error),
        }
    }

    async fn create_function(&self, request: Request<Incoming>) -> ApiResponse {
        let body = match read_json::<CreateFunctionRequest>(request).await {
            Ok(body) => body,
            Err(error) => return error_response(&error),
        };
        let spec = match build_spec(&body) {
            Ok(spec) => spec,
            Err(error) => return error_response(&error),
        };
        match self.service.create(spec.clone()) {
            Ok(created) => {
                let mut status = StatusCode::CREATED;
                let mut summary = crate::FunctionSummary::from_spec(&created, None, None);
                if body.build {
                    match self.service.build(&created.id, false).await {
                        Ok(artifact) => {
                            summary.digest = Some(artifact.digest.to_string());
                            summary.file_count = Some(artifact.file_count);
                            summary.status = "ready".to_owned();
                        }
                        Err(error) => return error_response(&error),
                    }
                } else {
                    status = StatusCode::CREATED;
                }
                json(status, &summary)
            }
            Err(error) => error_response(&error),
        }
    }

    async fn build_function(&self, id: &str) -> ApiResponse {
        let spec = match resolve(self.service.as_ref(), id) {
            Ok(spec) => spec,
            Err(error) => return error_response(&error),
        };
        match self.service.build(&spec.id, false).await {
            Ok(artifact) => {
                let updated = self
                    .service
                    .manager()
                    .get(&spec.id)
                    .unwrap_or_else(|_| spec.clone());
                json(
                    StatusCode::OK,
                    &crate::FunctionSummary::from_spec(
                        &updated,
                        Some(artifact.digest.to_string()),
                        Some(artifact.file_count),
                    ),
                )
            }
            Err(error) => error_response(&error),
        }
    }

    async fn invoke(&self, id: &str, request: Request<Incoming>) -> ApiResponse {
        let spec = match resolve(self.service.as_ref(), id) {
            Ok(spec) => spec,
            Err(error) => return error_response(&error),
        };
        let body: InvokeRequest = match read_json(request).await {
            Ok(body) => body,
            Err(error) => return error_response(&error),
        };
        let payload = match serde_json::to_vec(&body.payload) {
            Ok(payload) => payload,
            Err(error) => {
                return error_response(&rustfun_core::RustFunError::validation(format!(
                    "cannot serialize the payload: {error}"
                )))
            }
        };
        match self
            .service
            .manager()
            .invoke(
                &spec.id,
                payload,
                crate::timeout_of(&body),
                body.metadata.clone(),
                Default::default(),
            )
            .await
        {
            Ok(response) => {
                let status = if response.status == rustfun_core::protocol::InvocationStatus::Success
                {
                    StatusCode::OK
                } else if response.status == rustfun_core::protocol::InvocationStatus::Timeout {
                    StatusCode::GATEWAY_TIMEOUT
                } else if response.status == rustfun_core::protocol::InvocationStatus::FunctionError
                {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                };
                json(status, &InvokeResponse::from_response(&response))
            }
            Err(error) => error_response(&error),
        }
    }

    async fn destroy_function(&self, id: &str) -> ApiResponse {
        let spec = match resolve(self.service.as_ref(), id) {
            Ok(spec) => spec,
            Err(error) => return error_response(&error),
        };
        match self.service.manager().destroy(&spec.id).await {
            Ok(()) => json(
                StatusCode::OK,
                &serde_json::json!({ "destroyed": spec.name.as_str() }),
            ),
            Err(error) => error_response(&error),
        }
    }

    async fn instances(&self) -> ApiResponse {
        let instances = self.service.manager().instances().await;
        json(StatusCode::OK, &instances)
    }
}

fn build_spec(body: &CreateFunctionRequest) -> rustfun_core::Result<FunctionSpec> {
    let name = FunctionName::new(body.name.clone())?;
    let runtime = RuntimeId::parse(&body.runtime)?;
    let handler = HandlerSpec::parse(&body.handler)?;
    let mut environment = rustfun_core::Environment::new();
    for (key, value) in &body.environment {
        environment.insert_user(key, value)?;
    }
    let spec = FunctionSpec::new(name, runtime, handler)
        .with_source(FunctionSource::Directory {
            path: std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .to_string_lossy()
                .into_owned(),
        })
        .with_environment(environment);
    spec.validate()?;
    Ok(spec)
}

/// Resolve a function by id or name.
fn resolve(service: &InvocationService, id: &str) -> rustfun_core::Result<Arc<FunctionSpec>> {
    if let Ok(function_id) = rustfun_core::FunctionId::parse(id) {
        if let Ok(spec) = service.manager().get(&function_id) {
            return Ok(spec);
        }
    }
    service.function(id)
}

async fn read_json<T: serde::de::DeserializeOwned>(
    request: Request<Incoming>,
) -> rustfun_core::Result<T> {
    let body = request
        .into_body()
        .collect()
        .await
        .map_err(|error| {
            rustfun_core::RustFunError::validation(format!("cannot read the request body: {error}"))
        })?
        .to_bytes();
    if body.is_empty() {
        // An empty body means "no options"; invocations default to an empty event.
        return serde_json::from_slice(b"{}").map_err(|error| {
            rustfun_core::RustFunError::validation(format!("invalid request body: {error}"))
        });
    }
    serde_json::from_slice(&body).map_err(|error| {
        rustfun_core::RustFunError::validation(format!("invalid JSON body: {error}"))
            .with_remediation("send a JSON object, e.g. {\"payload\": {\"name\": \"world\"}}")
    })
}

fn not_found(path: &str) -> rustfun_core::RustFunError {
    rustfun_core::RustFunError::not_found(format!("no route matches {path}")).with_context(
        rustfun_core::ErrorContext::new()
            .operation("route")
            .remediation("see `rustfun dev --help` for the available endpoints"),
    )
}
