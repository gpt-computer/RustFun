//! Duration parsing and serialization helpers.
//!
//! Manifests express durations as human strings (`30s`, `1500ms`, `2m`). The domain model
//! stores `std::time::Duration`. This module keeps both representations in sync without
//! pulling a configuration crate into the model.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{ModelError, ModelResult};

/// Extension trait providing human-readable duration parsing.
pub trait DurationExt {
    /// Parse a duration such as `500ms`, `30s`, `2m`, `1h30m`.
    fn parse_human(raw: &str) -> ModelResult<Duration>;

    /// Render the duration in the shortest exact human form (for CLI output).
    fn to_human(&self) -> String;
}

impl DurationExt for Duration {
    fn parse_human(raw: &str) -> ModelResult<Duration> {
        parse_duration(raw)
    }

    fn to_human(&self) -> String {
        format_duration(*self)
    }
}

/// Parse a human duration string.
///
/// Accepted forms: a bare number of milliseconds (`500`), or a sequence of
/// `<number><unit>` pairs where unit is `ns`, `us`, `ms`, `s`, `m`, or `h`.
pub fn parse_duration(raw: &str) -> ModelResult<Duration> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ModelError::invalid_duration("duration must not be empty"));
    }
    if trimmed.bytes().all(|b| b.is_ascii_digit()) {
        // Bare number: milliseconds.
        let millis: u64 = trimmed
            .parse()
            .map_err(|_| ModelError::invalid_duration(format!("'{trimmed}' is not a duration")))?;
        return Ok(Duration::from_millis(millis));
    }

    let mut total = Duration::ZERO;
    let mut number = String::new();
    let mut unit = String::new();
    let mut saw_component = false;

    let flush = |number: &mut String, unit: &mut String, total: &mut Duration| -> ModelResult<()> {
        if number.is_empty() && unit.is_empty() {
            return Ok(());
        }
        if number.is_empty() || unit.is_empty() {
            return Err(ModelError::invalid_duration(
                "duration components must be a number followed by a unit, e.g. '30s'",
            ));
        }
        let value: u64 = number.parse().map_err(|_| {
            ModelError::invalid_duration(format!("'{}' is not a valid duration number", number))
        })?;
        let nanos = match unit.as_str() {
            "ns" => value,
            "us" | "µs" => value.saturating_mul(1_000),
            "ms" => value.saturating_mul(1_000_000),
            "s" => value.saturating_mul(1_000_000_000),
            "m" => value.saturating_mul(60_000_000_000),
            "h" => value.saturating_mul(3_600_000_000_000),
            other => {
                return Err(ModelError::invalid_duration(format!(
                    "unknown duration unit '{other}' (expected ns, us, ms, s, m, or h)"
                )))
            }
        };
        *total = total
            .checked_add(Duration::from_nanos(nanos.max(1)))
            .ok_or_else(|| {
                ModelError::invalid_duration("duration overflows the representable range")
            })?;
        number.clear();
        unit.clear();
        Ok(())
    };

    for ch in trimmed.chars() {
        if ch.is_ascii_digit() {
            if !unit.is_empty() {
                flush(&mut number, &mut unit, &mut total)?;
            }
            number.push(ch);
        } else {
            unit.push(ch);
            saw_component = true;
        }
    }
    flush(&mut number, &mut unit, &mut total)?;

    if !saw_component {
        return Err(ModelError::invalid_duration(format!(
            "'{trimmed}' is not a duration"
        )));
    }
    if total.is_zero() {
        return Err(ModelError::invalid_duration(
            "duration must be greater than zero",
        ));
    }
    Ok(total)
}

/// Render a duration compactly, e.g. `1s`, `1500ms`, `2m`.
pub fn format_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if duration.is_zero() {
        return "0s".to_owned();
    }
    if nanos % 3_600_000_000_000 == 0 {
        return format!("{}h", nanos / 3_600_000_000_000);
    }
    if nanos % 60_000_000_000 == 0 {
        return format!("{}m", nanos / 60_000_000_000);
    }
    if nanos % 1_000_000_000 == 0 {
        return format!("{}s", nanos / 1_000_000_000);
    }
    if nanos % 1_000_000 == 0 {
        return format!("{}ms", nanos / 1_000_000);
    }
    if nanos % 1_000 == 0 {
        return format!("{}us", nanos / 1_000);
    }
    format!("{nanos}ns")
}

/// Parse a human byte size such as `512MiB`, `1GiB`, `1048576`.
pub fn parse_bytes(raw: &str) -> ModelResult<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ModelError::invalid_resource("size must not be empty"));
    }
    let split = trimmed
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(trimmed.len());
    let (number_raw, unit_raw) = trimmed.split_at(split);
    let number: f64 = number_raw
        .parse()
        .map_err(|_| ModelError::invalid_resource(format!("'{number_raw}' is not a valid size")))?;
    let unit = unit_raw.trim().to_ascii_lowercase();
    let multiplier: f64 = match unit.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1e3,
        "ki" | "kib" => 1024.0,
        "m" | "mb" => 1e6,
        "mi" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" => 1e9,
        "gi" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" => 1e12,
        "ti" | "tib" => 1024.0f64.powi(4),
        other => {
            return Err(ModelError::invalid_resource(format!(
                "unknown size unit '{other}' (expected B, KiB, MiB, GiB, or TiB)"
            )))
        }
    };
    let bytes = number * multiplier;
    if bytes <= 0.0 || bytes > u64::MAX as f64 {
        return Err(ModelError::invalid_resource("size is out of range"));
    }
    Ok(bytes as u64)
}

/// Render a byte count using binary units.
pub fn format_bytes(bytes: u64) -> String {
    const KI: u64 = 1024;
    const MI: u64 = 1024 * KI;
    const GI: u64 = 1024 * MI;
    const TI: u64 = 1024 * GI;
    if bytes >= TI && bytes % TI == 0 {
        format!("{}TiB", bytes / TI)
    } else if bytes >= GI && bytes % GI == 0 {
        format!("{}GiB", bytes / GI)
    } else if bytes >= MI && bytes % MI == 0 {
        format!("{}MiB", bytes / MI)
    } else if bytes >= KI && bytes % KI == 0 {
        format!("{}KiB", bytes / KI)
    } else {
        format!("{bytes}B")
    }
}

/// Serde support storing `Duration` as a whole number of milliseconds.
///
/// Millisecond precision keeps JSON round-trips lossless for the sub-second timeouts used by
/// invocation deadlines.
pub mod serde_millis {
    use super::{Deserialize, Deserializer, Duration, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        value.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

impl FromStr for DurationWrapper {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_duration(s).map(DurationWrapper)
    }
}

/// Newtype wrapper enabling `FromStr` for `Duration` in derived code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DurationWrapper(pub Duration);

impl fmt::Display for DurationWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_duration(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_units() {
        assert_eq!(
            parse_duration("500ms").expect("valid"),
            Duration::from_millis(500)
        );
        assert_eq!(
            parse_duration("30s").expect("valid"),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_duration("2m").expect("valid"),
            Duration::from_secs(120)
        );
        assert_eq!(
            parse_duration("1h").expect("valid"),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn parses_compound_durations() {
        assert_eq!(
            parse_duration("1h30m").expect("valid"),
            Duration::from_secs(5400)
        );
    }

    #[test]
    fn bare_number_is_milliseconds() {
        assert_eq!(
            parse_duration("250").expect("valid"),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("10x").is_err());
        assert!(parse_duration("10s5").is_err());
    }

    #[test]
    fn formatting_is_compact() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_millis(1500)), "1500ms");
        assert_eq!(format_duration(Duration::from_millis(100)), "100ms");
    }

    #[test]
    fn byte_parsing_and_formatting() {
        assert_eq!(parse_bytes("512MiB").expect("valid"), 512 * 1024 * 1024);
        assert_eq!(parse_bytes("1GiB").expect("valid"), 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("1024").expect("valid"), 1024);
        assert!(parse_bytes("512MBX").is_err());
        assert_eq!(format_bytes(512 * 1024 * 1024), "512MiB");
        assert_eq!(format_bytes(1000), "1000B");
    }
}
