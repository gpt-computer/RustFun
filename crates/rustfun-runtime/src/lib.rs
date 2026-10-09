//! RustFun runtime adapters.
//!
//! Each adapter implements [`RuntimeAdapter`] for one runtime family and nothing else: no
//! pooling, no scheduling, no global lifecycle. The instance crate drives them.
//!
//! | Family | How it runs | Isolation |
//! | --- | --- | --- |
//! | [`echo`] | in-process | none (test/benchmark runtime) |
//! | [`node`] | `node` + bootstrap on stdio | host or Linux |
//! | [`python`] | `python3` + bootstrap on stdio | host or Linux |
//! | [`executable`] | user binary speaking the protocol | host or Linux |
//!
//! Every process-backed runtime speaks the same framed protocol from
//! [`rustfun_protocol`]; the bootstrap scripts are thin adapters that translate the frame into
//! a language-level handler call.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;

use rustfun_core::{ErrorContext, RuntimeRegistry, RustFunError};

pub mod bootstrap;
pub mod echo;
pub mod executable;
pub mod node;
pub mod process;
pub mod python;

pub use echo::EchoAdapter;
pub use executable::ExecutableAdapter;
pub use node::NodeAdapter;
pub use process::{ProcessInstance, ProcessRuntimeAdapter};
pub use python::PythonAdapter;

/// Build a registry with every adapter that RustFun ships.
///
/// Adapters are registered regardless of whether the host has the interpreter installed:
/// availability is discovered, not assumed, and reported by `rustfun doctor`.
pub fn default_registry() -> RuntimeRegistry {
    let registry = RuntimeRegistry::new();
    registry.register_adapter(Arc::new(NodeAdapter::new()));
    registry.register_adapter(Arc::new(PythonAdapter::new()));
    registry.register_adapter(Arc::new(ExecutableAdapter::new()));
    registry.register_adapter(Arc::new(EchoAdapter::new()));
    registry
}

/// Locate an interpreter on `PATH`.
pub(crate) fn find_executable(candidates: &[&str]) -> Option<String> {
    for candidate in candidates {
        if candidate.contains('/') {
            let path = std::path::Path::new(candidate);
            if path.exists() {
                return Some(candidate.to_string());
            }
            continue;
        }
        if let Some(path) = std::env::var_os("PATH") {
            for directory in std::env::split_paths(&path) {
                let full = directory.join(candidate);
                if full.is_file() {
                    return Some(full.to_string_lossy().into_owned());
                }
            }
        }
    }
    None
}

/// Error returned when a runtime's interpreter is missing.
pub(crate) fn interpreter_missing(runtime: &str, candidates: &[&str]) -> RustFunError {
    RustFunError::unavailable(format!(
        "no {runtime} interpreter found (looked for: {})",
        candidates.join(", ")
    ))
    .with_context(
        ErrorContext::new()
            .operation("discover_runtime")
            .runtime(runtime)
            .remediation(format!(
                "install {runtime} and make sure it is on PATH, or set an explicit interpreter path"
            )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfun_model::RuntimeFamily;

    #[test]
    fn default_registry_registers_every_shipped_adapter() {
        let registry = default_registry();
        for family in [
            RuntimeFamily::Node,
            RuntimeFamily::Python,
            RuntimeFamily::Executable,
            RuntimeFamily::Echo,
        ] {
            assert!(registry.contains(family), "{family} must be registered");
        }
    }

    #[test]
    fn missing_interpreter_errors_are_actionable() {
        let err = interpreter_missing("node", &["definitely-not-node"]);
        assert_eq!(err.category(), rustfun_core::ErrorCategory::Unavailable);
        assert!(err.context().remediation.is_some());
        assert!(err.to_string().contains("definitely-not-node"));
    }

    #[test]
    fn absolute_executable_lookup_works() {
        let found = find_executable(&["/bin/sh"]);
        assert_eq!(found.as_deref(), Some("/bin/sh"));
        assert!(find_executable(&["/definitely/not/here"]).is_none());
    }
}
