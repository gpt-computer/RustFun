//! Handler specifications.
//!
//! The textual shape (`module.export`, `path/to/file:export`, or a bare executable path)
//! matches the `vercel/fun` convention for compatibility, but the parsed representation is a
//! domain type so that resolution rules can be tested independently of any runtime.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, ModelResult};

/// Maximum length of a handler string.
const MAX_HANDLER_LEN: usize = 512;

/// A parsed handler specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HandlerSpec {
    raw: String,
}

impl HandlerSpec {
    /// Parse and validate a handler string.
    ///
    /// Accepted shapes:
    /// - `index.handler` — module path plus export name
    /// - `src/index.handler` — module path may contain directories
    /// - `main.py:handler` — an explicit `file:export` form
    /// - `./bin/handler` — a relative path (executable / rust / oci runtimes)
    ///
    /// Absolute paths, parent-directory traversal, and control characters are rejected.
    pub fn parse(raw: &str) -> ModelResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ModelError::invalid_handler("handler must not be empty"));
        }
        if trimmed.len() > MAX_HANDLER_LEN {
            return Err(ModelError::invalid_handler(format!(
                "handler exceeds {MAX_HANDLER_LEN} bytes"
            )));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(ModelError::invalid_handler(
                "handler must not contain control characters",
            ));
        }
        if trimmed.starts_with('/') {
            return Err(ModelError::invalid_handler(
                "handler must be relative to the function root, absolute paths are rejected",
            ));
        }
        if trimmed.split(['/', '\\']).any(|segment| segment == "..") {
            return Err(ModelError::invalid_handler(
                "handler must not traverse outside the function root",
            ));
        }
        if trimmed.contains('\0') {
            return Err(ModelError::invalid_handler("handler must not contain NUL"));
        }
        Ok(Self {
            raw: trimmed.to_owned(),
        })
    }

    /// The handler exactly as written.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Split into `(module_path, export_name)` when the handler names an export.
    ///
    /// Returns `None` for path-only handlers, which the executable runtime uses directly.
    pub fn split_export(&self) -> Option<(&str, &str)> {
        if let Some((file, export)) = self.raw.rsplit_once(':') {
            if !export.is_empty() && !export.contains('/') {
                return Some((file, export));
            }
        }
        let (module, export) = self.raw.rsplit_once('.')?;
        if module.is_empty() || export.is_empty() || export.contains('/') || export.contains('\\') {
            return None;
        }
        Some((module, export))
    }

    /// The module or file portion of the handler.
    pub fn module_path(&self) -> &str {
        self.split_export().map_or(self.raw.as_str(), |(m, _)| m)
    }

    /// The export name, if the handler names one.
    pub fn export_name(&self) -> Option<&str> {
        self.split_export().map(|(_, e)| e)
    }
}

impl fmt::Display for HandlerSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for HandlerSpec {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HandlerSpec::parse(s)
    }
}

impl TryFrom<String> for HandlerSpec {
    type Error = ModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        HandlerSpec::parse(&value)
    }
}

impl From<HandlerSpec> for String {
    fn from(value: HandlerSpec) -> Self {
        value.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_module_dot_export() {
        let handler = HandlerSpec::parse("index.handler").expect("valid");
        assert_eq!(handler.split_export(), Some(("index", "handler")));
        assert_eq!(handler.module_path(), "index");
        assert_eq!(handler.export_name(), Some("handler"));
    }

    #[test]
    fn parses_nested_module() {
        let handler = HandlerSpec::parse("src/api/handlers.hello").expect("valid");
        assert_eq!(handler.split_export(), Some(("src/api/handlers", "hello")));
    }

    #[test]
    fn parses_file_colon_export() {
        let handler = HandlerSpec::parse("main.py:handler").expect("valid");
        assert_eq!(handler.split_export(), Some(("main.py", "handler")));
    }

    #[test]
    fn path_only_handler_has_no_export() {
        let handler = HandlerSpec::parse("./bin/server").expect("valid");
        assert_eq!(handler.split_export(), None);
        assert_eq!(handler.module_path(), "./bin/server");
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        assert!(HandlerSpec::parse("../secrets").is_err());
        assert!(HandlerSpec::parse("a/../../b").is_err());
        assert!(HandlerSpec::parse("/etc/passwd").is_err());
        assert!(HandlerSpec::parse("").is_err());
        assert!(HandlerSpec::parse("  ").is_err());
    }
}
