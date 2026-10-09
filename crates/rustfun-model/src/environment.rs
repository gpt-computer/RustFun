//! Function environments.
//!
//! Host environment variables are never inherited implicitly: a function's environment is
//! built from explicit declarations plus platform-reserved variables. This is the core of
//! the platform's environment-leakage defence (see `SECURITY.md`).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, ModelResult};

/// Prefix reserved for platform-provided variables.
pub const RESERVED_PREFIX: &str = "RUSTFUN_";

/// Maximum size of a single environment value.
const MAX_VALUE_LEN: usize = 64 * 1024;

/// Maximum number of environment variables.
const MAX_ENTRIES: usize = 1024;

/// A validated environment map.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Environment {
    entries: BTreeMap<String, String>,
}

impl Environment {
    /// Create an empty environment.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an environment from pairs without validating each entry.
    ///
    /// Prefer [`Environment::try_from_iter`] for untrusted input.
    pub fn from_pairs<K, V, I>(pairs: I) -> Self
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        let mut entries = BTreeMap::new();
        for (key, value) in pairs {
            entries.insert(key.into(), value.into());
        }
        Self { entries }
    }

    /// Build an environment, returning a structured error for the first invalid entry.
    pub fn try_from_iter<K, V, I>(pairs: I) -> ModelResult<Self>
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        let mut entries = BTreeMap::new();
        for (key, value) in pairs {
            let key = key.into();
            let value = value.into();
            validate_key(&key)?;
            validate_value(&value)?;
            entries.insert(key, value);
        }
        Ok(Self { entries })
    }

    /// Insert a variable, validating key and value.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) -> ModelResult<()> {
        let key = key.into();
        let value = value.into();
        validate_key(&key)?;
        validate_value(&value)?;
        self.entries.insert(key, value);
        Ok(())
    }

    /// Insert a variable declared by the user (must not use the reserved prefix).
    pub fn insert_user(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> ModelResult<()> {
        let key = key.into();
        if key.starts_with(RESERVED_PREFIX) {
            return Err(ModelError::invalid_environment(format!(
                "'{RESERVED_PREFIX}' is reserved for the platform; {key} cannot be set by a function manifest"
            )));
        }
        self.insert(key, value)
    }

    /// Remove a variable.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.entries.remove(key)
    }

    /// Look up a variable.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    /// Iterate over entries in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the environment is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Merge `other` on top of `self`; `other` wins. Reserved names in `other` must come
    /// from the platform, which is verified by the caller.
    pub fn merged(&self, other: &Environment) -> Environment {
        let mut entries = self.entries.clone();
        entries.extend(other.entries.clone());
        Environment { entries }
    }

    /// Redact values of variables that look like secrets, for safe logging.
    pub fn redacted(&self) -> Environment {
        let entries = self
            .entries
            .iter()
            .map(|(k, v)| {
                let looks_secret = k.to_ascii_uppercase().contains("SECRET")
                    || k.to_ascii_uppercase().contains("TOKEN")
                    || k.to_ascii_uppercase().contains("PASSWORD")
                    || k.to_ascii_uppercase().contains("KEY")
                    || k.to_ascii_uppercase().contains("CREDENTIAL");
                (
                    k.clone(),
                    if looks_secret && !v.is_empty() {
                        "[redacted]".to_owned()
                    } else {
                        v.clone()
                    },
                )
            })
            .collect();
        Environment { entries }
    }

    /// Validate all entries.
    pub fn validate(&self) -> ModelResult<()> {
        if self.entries.len() > MAX_ENTRIES {
            return Err(ModelError::invalid_environment(format!(
                "environment has {} entries, limit is {MAX_ENTRIES}",
                self.entries.len()
            )));
        }
        for (key, value) in &self.entries {
            validate_key(key)?;
            validate_value(value)?;
        }
        Ok(())
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rendered: Vec<String> = self
            .entries
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        f.write_str(&rendered.join(" "))
    }
}

impl FromIterator<(String, String)> for Environment {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        Environment::from_pairs(iter)
    }
}

fn validate_key(key: &str) -> ModelResult<()> {
    if key.is_empty() {
        return Err(ModelError::invalid_environment(
            "environment variable name must not be empty",
        ));
    }
    if key.len() > 256 {
        return Err(ModelError::invalid_environment(format!(
            "environment variable name '{key}' exceeds 256 bytes"
        )));
    }
    let valid = key
        .bytes()
        .enumerate()
        .all(|(i, b)| b == b'_' || b.is_ascii_alphanumeric() && (i > 0 || !b.is_ascii_digit()));
    if !valid {
        return Err(ModelError::invalid_environment(format!(
            "environment variable name '{key}' is invalid (expected [A-Za-z_][A-Za-z0-9_]*)"
        )));
    }
    Ok(())
}

fn validate_value(value: &str) -> ModelResult<()> {
    if value.len() > MAX_VALUE_LEN {
        return Err(ModelError::invalid_environment(format!(
            "environment value exceeds {MAX_VALUE_LEN} bytes"
        )));
    }
    if value.contains('\0') {
        return Err(ModelError::invalid_environment(
            "environment values must not contain NUL",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_validates_keys() {
        let mut env = Environment::new();
        assert!(env.insert("HELLO", "world").is_ok());
        assert!(env.insert("", "x").is_err());
        assert!(env.insert("1BAD", "x").is_err());
        assert!(env.insert("BAD-NAME", "x").is_err());
        assert!(env.insert("A=B", "x").is_err());
    }

    #[test]
    fn insert_validates_values() {
        let mut env = Environment::new();
        assert!(env.insert("KEY", "value\0with-nul").is_err());
        assert!(env.insert("KEY", "x".repeat(MAX_VALUE_LEN + 1)).is_err());
    }

    #[test]
    fn reserved_prefix_is_protected_from_user_declaration() {
        let mut env = Environment::new();
        assert!(env.insert_user("HELLO", "world").is_ok());
        let err = env.insert_user("RUSTFUN_FUNCTION_ID", "x");
        assert!(err.is_err());
        // The platform itself may still set reserved names.
        assert!(env.insert("RUSTFUN_FUNCTION_ID", "x").is_ok());
    }

    #[test]
    fn merge_prefers_the_overlay() {
        let base = Environment::from_pairs([("A", "1"), ("B", "2")]);
        let overlay = Environment::from_pairs([("B", "override"), ("C", "3")]);
        let merged = base.merged(&overlay);
        assert_eq!(merged.get("A"), Some("1"));
        assert_eq!(merged.get("B"), Some("override"));
        assert_eq!(merged.get("C"), Some("3"));
    }

    #[test]
    fn redaction_hides_secrets() {
        let env = Environment::from_pairs([
            ("API_TOKEN", "supersecret"),
            ("GREETING", "hello"),
            ("EMPTY_KEY", ""),
        ]);
        let redacted = env.redacted();
        assert_eq!(redacted.get("API_TOKEN"), Some("[redacted]"));
        assert_eq!(redacted.get("GREETING"), Some("hello"));
        assert_eq!(redacted.get("EMPTY_KEY"), Some(""));
    }

    #[test]
    fn iteration_is_deterministic() {
        let env = Environment::from_pairs([("B", "2"), ("A", "1")]);
        let keys: Vec<&str> = env.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["A", "B"]);
    }
}
