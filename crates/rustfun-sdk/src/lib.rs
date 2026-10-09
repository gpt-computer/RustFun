//! The RustFun SDK.
//!
//! Write a RustFun function in Rust, or use these types to write a runtime that speaks the
//! invocation protocol.
//!
//! ```
//! use rustfun_sdk::{Function, Request, Response};
//!
//! # async fn demo() -> Result<(), rustfun_sdk::Error> {
//! let function = Function::new(|request: Request| async move {
//!     let name = request
//!         .event()
//!         .get("name")
//!         .and_then(|value| value.as_str())
//!         .unwrap_or("world")
//!         .to_owned();
//!     Ok(Response::json(serde_json::json!({ "hello": name })))
//! });
//! let request = Request::default();
//! let response = function.invoke(request).await?;
//! assert_eq!(response.payload, br#"{"hello":"world"}"#.to_vec());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::time::Duration;

use rustfun_protocol::{
    Codec, FramedReader, FramedWriter, InvocationError, InvocationRequest, InvocationResponse,
    InvocationStatus,
};
use serde::{Deserialize, Serialize};

/// The event delivered to a handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Request {
    /// Decoded JSON event, when the payload was JSON.
    #[serde(default)]
    pub event: serde_json::Value,
    /// Raw payload bytes.
    #[serde(skip)]
    pub raw: Vec<u8>,
    /// Invocation id.
    pub invocation_id: String,
    /// Request id.
    pub request_id: String,
    /// Function id.
    pub function_id: String,
    /// Function name.
    pub function_name: String,
    /// Deadline in milliseconds; `0` means no deadline.
    #[serde(default)]
    pub deadline_ms: u64,
    /// Metadata delivered with the invocation.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Environment variables visible to the function.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

impl Request {
    /// Build a request from a protocol frame.
    pub fn from_protocol(request: &InvocationRequest) -> Self {
        let event = serde_json::from_slice::<serde_json::Value>(&request.payload)
            .unwrap_or(serde_json::Value::Null);
        let mut environment: BTreeMap<String, String> = std::env::vars().collect();
        for (key, value) in &request.environment {
            environment.insert(key.clone(), value.clone());
        }
        Self {
            event,
            raw: request.payload.clone(),
            invocation_id: request.invocation_id.to_string(),
            request_id: request.request_id.to_string(),
            function_id: request.function_id.to_string(),
            function_name: request.function_name.clone(),
            deadline_ms: request.deadline_ms,
            metadata: request.metadata.clone(),
            environment,
        }
    }

    /// The decoded event.
    pub fn event(&self) -> &serde_json::Value {
        &self.event
    }

    /// Remaining deadline, if any.
    pub fn deadline(&self) -> Option<Duration> {
        if self.deadline_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(self.deadline_ms))
        }
    }
}

/// A handler response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// Error, when the handler failed.
    pub error: Option<InvocationError>,
}

impl Response {
    /// A response carrying `payload`.
    pub fn bytes(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            payload: payload.into(),
            error: None,
        }
    }

    /// A response carrying a JSON value.
    pub fn json(value: serde_json::Value) -> Self {
        Self {
            payload: serde_json::to_vec(&value).unwrap_or_else(|_| b"null".to_vec()),
            error: None,
        }
    }

    /// A response carrying text.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            payload: text.into().into_bytes(),
            error: None,
        }
    }

    /// A failed response.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            payload: Vec::new(),
            error: Some(InvocationError::new(code, message)),
        }
    }
}

/// An SDK error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The handler failed.
    #[error("handler error: {0}")]
    Handler(String),
    /// The protocol stream failed.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// An I/O error occurred on stdio.
    #[error("io error: {0}")]
    Io(String),
}

impl From<rustfun_protocol::ProtocolError> for Error {
    fn from(value: rustfun_protocol::ProtocolError) -> Self {
        Error::Protocol(value.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value.to_string())
    }
}

/// A RustFun function: a handler plus the serve loop.
pub struct Function {
    handler: Box<
        dyn Fn(Request) -> futures_lite_boxed::BoxFuture<'static, Result<Response, Error>>
            + Send
            + Sync,
    >,
}

impl std::fmt::Debug for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Function").finish()
    }
}

impl Function {
    /// Create a function from an async handler.
    pub fn new<F, Fut>(handler: F) -> Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Response, Error>> + Send + 'static,
    {
        let handler = Box::new(move |request| {
            Box::pin(handler(request)) as futures_lite_boxed::BoxFuture<'static, _>
        });
        Self { handler }
    }

    /// Invoke the handler once (used by tests and local invocation helpers).
    pub async fn invoke(&self, request: Request) -> Result<Response, Error> {
        (self.handler)(request).await
    }

    /// Serve the function over stdio until the platform closes the stream.
    pub fn serve(self) -> Result<(), Error> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|error| Error::Io(error.to_string()))?;
        runtime.block_on(self.serve_async())
    }

    /// Async variant of [`Function::serve`], for embedders that already have a runtime.
    pub async fn serve_async(self) -> Result<(), Error> {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        let mut reader = FramedReader::new(stdin);
        let mut writer = FramedWriter::new(stdout).with_codec(Codec::Json);
        let mut scratch = Vec::new();
        loop {
            let frame: InvocationRequest = match reader.recv_into(&mut scratch).await {
                Ok(frame) => frame,
                // The platform closed the stream: this instance is done.
                Err(_) => return Ok(()),
            };
            let request = Request::from_protocol(&frame);
            let invocation_id = frame.invocation_id.clone();
            let function_id = frame.function_id.clone();
            let started = std::time::Instant::now();
            let response = match (self.handler)(request).await {
                Ok(response) => response,
                Err(error) => Response::error("RUSTFUN_FUNCTION_ERROR", error.to_string()),
            };
            let protocol_response = match response.error {
                Some(error) => InvocationResponse::failure(
                    invocation_id,
                    function_id,
                    InvocationStatus::FunctionError,
                    error,
                )
                .with_duration_ms(started.elapsed().as_millis() as u64),
                None => InvocationResponse::success(invocation_id, function_id, response.payload)
                    .with_duration_ms(started.elapsed().as_millis() as u64),
            };
            writer.send(&protocol_response).await?;
        }
    }
}

/// Boxed-future alias used internally so the SDK does not depend on `futures`.
pub mod futures_lite_boxed {
    /// A boxed, sendable future.
    pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Error::Handler(value)
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Error::Handler(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handler_round_trips_through_the_sdk_types() {
        let function = Function::new(|request: Request| async move {
            let name = request
                .event()
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or("world")
                .to_owned();
            Ok(Response::json(serde_json::json!({ "hello": name })))
        });
        let protocol_request = InvocationRequest::new(
            rustfun_model::RequestId::new(),
            rustfun_model::InvocationId::new(),
            rustfun_model::FunctionId::new(),
            serde_json::to_vec(&serde_json::json!({ "name": "rustfun" })).expect("serializes"),
        )
        .with_function_name("hello");
        let request = Request::from_protocol(&protocol_request);
        assert_eq!(request.event()["name"], "rustfun");
        let response = function.invoke(request).await.expect("invokes");
        let value: serde_json::Value = serde_json::from_slice(&response.payload).expect("json");
        assert_eq!(value["hello"], "rustfun");
    }

    #[test]
    fn response_constructors_produce_the_expected_payloads() {
        assert_eq!(Response::text("hi").payload, b"hi");
        assert_eq!(Response::bytes(vec![1, 2]).payload, vec![1, 2]);
        let json = Response::json(serde_json::json!({ "a": 1 }));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&json.payload).expect("json")["a"],
            1
        );
        let failed = Response::error("CODE", "message");
        assert_eq!(failed.error.expect("error").code, "CODE");
        assert!(failed.payload.is_empty());
    }

    #[test]
    fn request_exposes_deadlines_and_metadata() {
        let protocol_request = InvocationRequest::new(
            rustfun_model::RequestId::new(),
            rustfun_model::InvocationId::new(),
            rustfun_model::FunctionId::new(),
            b"{}".to_vec(),
        )
        .with_deadline(Duration::from_millis(250))
        .with_metadata("header:x", "1");
        let request = Request::from_protocol(&protocol_request);
        assert_eq!(request.deadline(), Some(Duration::from_millis(250)));
        assert_eq!(
            request.metadata.get("header:x").map(String::as_str),
            Some("1")
        );
        assert!(request.environment.contains_key("PATH"));
    }

    #[test]
    fn errors_convert_from_protocol_and_io() {
        let protocol: Error = rustfun_protocol::ProtocolError::UnknownCodec { id: 9 }.into();
        assert!(protocol.to_string().contains("codec"));
        let io: Error = std::io::Error::other("broken pipe").into();
        assert!(io.to_string().contains("broken pipe"));
    }
}
