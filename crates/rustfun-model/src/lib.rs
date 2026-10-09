//! RustFun domain model.
//!
//! This crate is intentionally dependency-light: it contains only domain types and the
//! validation rules intrinsic to them. It must not depend on infrastructure (process,
//! runtime adapters, storage, HTTP, CLI).
//!
//! # Execution spine
//!
//! ```text
//! Function → Artifact → Runtime → Sandbox → Instance → Invocation → Event → Result/Error
//! ```
//!
//! Every stage of the spine has a type here: [`FunctionSpec`], [`ArtifactRef`],
//! [`RuntimeId`], [`SandboxPolicy`], [`InstanceId`], [`InvocationId`], and (in
//! `rustfun-events`) the [`rustfun_events::Event`] stream.
//!
//! # Example
//!
//! ```
//! use rustfun_model::{FunctionName, FunctionSpec, HandlerSpec, RuntimeId, RuntimeVersion};
//!
//! let runtime = RuntimeId::parse("node@24")?;
//! assert_eq!(runtime.family().name(), "node");
//! assert_eq!(runtime.version(), &RuntimeVersion::Major(24));
//!
//! let spec = FunctionSpec::new(FunctionName::new("hello")?, runtime, HandlerSpec::parse("index.handler")?);
//! assert_eq!(spec.name.as_str(), "hello");
//! # Ok::<(), rustfun_model::ModelError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod digest;
mod environment;
mod error;
mod function;
mod handler;
mod ids;
mod resource;
mod runtime;
mod sandbox;
mod time;

pub use digest::{Algorithm, Digest};
pub use environment::Environment;
pub use error::{ModelError, ModelResult};
pub use function::{FunctionMetadata, FunctionName, FunctionSource, FunctionSpec, FunctionStatus};
pub use handler::HandlerSpec;
pub use ids::{ArtifactId, EventId, FunctionId, InstanceId, InvocationId, RequestId, WorkerId};
pub use resource::{CpuLimit, DiskLimit, FileDescriptorLimit, ProcessLimit, ResourceLimits};
pub use runtime::{RuntimeCapabilities, RuntimeFamily, RuntimeId, RuntimeVersion};
pub use sandbox::{FilesystemPolicy, NetworkPolicy, SandboxKind, SandboxPolicy};
pub use time::{
    format_bytes, format_duration, parse_bytes, parse_duration, DurationExt, DurationWrapper,
};

/// Semantic version of the `rustfun.toml` manifest schema.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Semantic version of the invocation protocol understood by this build.
pub const PROTOCOL_VERSION: u32 = 1;

/// Version of the `rustfun` binary and libraries.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_error_is_machine_readable() {
        let err = ModelError::invalid_name("Bad Name");
        assert_eq!(err.code().as_str(), "MODEL_INVALID_NAME");
        assert!(!err.is_retryable());
        assert!(!err.message().is_empty());
    }

    #[test]
    fn json_roundtrip_of_function_spec() {
        let spec = FunctionSpec::new(
            FunctionName::new("hello").expect("valid name"),
            RuntimeId::parse("node@24").expect("valid runtime"),
            HandlerSpec::parse("index.handler").expect("valid handler"),
        );
        let encoded = serde_json::to_string(&spec).expect("serializes");
        let decoded: FunctionSpec = serde_json::from_str(&encoded).expect("deserializes");
        assert_eq!(decoded, spec);
    }
}
