//! Resource limits enforced by the platform.
//!
//! Limits are expressed in the domain model so that a function can be validated without any
//! sandbox existing yet, and so that schedulers can reason about capacity before an instance
//! is created. Enforcement happens in the sandbox/process layer.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, ModelResult};

/// MiB in bytes.
pub const MIB: u64 = 1024 * 1024;

/// CPU limit, expressed either as a share or as a hard quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum CpuLimit {
    /// Relative share of a host CPU (cgroup `cpu.weight`).
    Share(u32),
    /// Hard quota in microseconds per period (cgroup `cpu.max`).
    Quota {
        /// Quota in microseconds per `period`.
        micros: u64,
        /// Period in microseconds.
        period: u64,
    },
}

impl CpuLimit {
    /// Build a quota from milliseconds per second.
    pub fn from_millis_per_second(millis: u64) -> ModelResult<Self> {
        if millis == 0 || millis > 1000 {
            return Err(ModelError::invalid_resource(
                "cpu quota must be between 1 and 1000 milliseconds per second",
            ));
        }
        Ok(CpuLimit::Quota {
            micros: millis * 1000,
            period: 1_000_000,
        })
    }

    /// Validate the limit.
    pub fn validate(&self) -> ModelResult<()> {
        match self {
            CpuLimit::Share(share) => {
                if !(1..=10_000).contains(share) {
                    return Err(ModelError::invalid_resource(
                        "cpu share must be between 1 and 10000",
                    ));
                }
                Ok(())
            }
            CpuLimit::Quota { micros, period } => {
                if *period == 0 || *micros == 0 {
                    return Err(ModelError::invalid_resource(
                        "cpu quota and period must be greater than zero",
                    ));
                }
                if *micros > *period {
                    return Err(ModelError::invalid_resource(
                        "cpu quota must not exceed the period",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Maximum number of processes/threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProcessLimit(pub u32);

impl ProcessLimit {
    /// Validate the limit.
    pub fn validate(&self) -> ModelResult<()> {
        if self.0 == 0 || self.0 > 1_000_000 {
            return Err(ModelError::invalid_resource(
                "process limit must be between 1 and 1000000",
            ));
        }
        Ok(())
    }
}

/// Maximum number of open file descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FileDescriptorLimit(pub u32);

impl FileDescriptorLimit {
    /// Validate the limit.
    pub fn validate(&self) -> ModelResult<()> {
        if self.0 < 16 {
            return Err(ModelError::invalid_resource(
                "file descriptor limit must be at least 16",
            ));
        }
        if self.0 > 4_194_304 {
            return Err(ModelError::invalid_resource(
                "file descriptor limit must not exceed 4194304",
            ));
        }
        Ok(())
    }
}

/// Writable disk quota for the instance scratch space, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DiskLimit(pub u64);

impl DiskLimit {
    /// Validate the limit.
    pub fn validate(&self) -> ModelResult<()> {
        if self.0 == 0 || self.0 > 1024 * 1024 * 1024 * 1024 {
            return Err(ModelError::invalid_resource(
                "disk quota must be between 1 byte and 1TiB",
            ));
        }
        Ok(())
    }
}

/// The complete resource contract for an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Memory ceiling in bytes.
    pub memory_bytes: u64,
    /// Optional CPU limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuLimit>,
    /// Wall-clock deadline for a single invocation.
    #[serde(with = "crate::time::serde_millis")]
    pub timeout: Duration,
    /// Optional process-count limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_processes: Option<ProcessLimit>,
    /// Optional open-file limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_open_files: Option<FileDescriptorLimit>,
    /// Optional scratch-disk quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_bytes: Option<DiskLimit>,
    /// Maximum request payload size in bytes.
    pub max_payload_bytes: usize,
    /// Maximum response payload size in bytes.
    pub max_response_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 512 * MIB,
            cpu: None,
            timeout: Duration::from_secs(30),
            max_processes: Some(ProcessLimit(64)),
            max_open_files: Some(FileDescriptorLimit(1024)),
            disk_bytes: None,
            max_payload_bytes: (4 * MIB) as usize,
            max_response_bytes: (8 * MIB) as usize,
        }
    }
}

impl ResourceLimits {
    /// Limits with no cgroup-enforceable restrictions, used by development host mode.
    pub fn development() -> Self {
        Self {
            cpu: None,
            max_processes: None,
            max_open_files: None,
            disk_bytes: None,
            ..Self::default()
        }
    }

    /// Set the memory ceiling.
    #[must_use]
    pub fn with_memory(mut self, bytes: u64) -> Self {
        self.memory_bytes = bytes;
        self
    }

    /// Set the invocation timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the CPU limit.
    #[must_use]
    pub fn with_cpu(mut self, cpu: CpuLimit) -> Self {
        self.cpu = Some(cpu);
        self
    }

    /// Set the maximum number of open files.
    #[must_use]
    pub fn with_max_open_files(mut self, files: u32) -> Self {
        self.max_open_files = Some(FileDescriptorLimit(files));
        self
    }

    /// Set the maximum number of processes.
    #[must_use]
    pub fn with_max_processes(mut self, processes: u32) -> Self {
        self.max_processes = Some(ProcessLimit(processes));
        self
    }

    /// Validate the limit set.
    pub fn validate(&self) -> ModelResult<()> {
        if self.memory_bytes < 16 * MIB {
            return Err(ModelError::invalid_resource(
                "memory limit must be at least 16MiB",
            ));
        }
        if self.memory_bytes > 64 * 1024 * MIB {
            return Err(ModelError::invalid_resource(
                "memory limit must not exceed 65536MiB",
            ));
        }
        if self.timeout.is_zero() {
            return Err(ModelError::invalid_resource(
                "timeout must be greater than zero",
            ));
        }
        if self.timeout > Duration::from_secs(3600) {
            return Err(ModelError::invalid_resource(
                "timeout must not exceed 3600 seconds",
            ));
        }
        if let Some(cpu) = self.cpu {
            cpu.validate()?;
        }
        if let Some(p) = self.max_processes {
            p.validate()?;
        }
        if let Some(f) = self.max_open_files {
            f.validate()?;
        }
        if let Some(d) = self.disk_bytes {
            d.validate()?;
        }
        if self.max_payload_bytes == 0 || self.max_payload_bytes > 256 * MIB as usize {
            return Err(ModelError::invalid_resource(
                "max_payload_bytes must be between 1 and 256MiB",
            ));
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > 256 * MIB as usize {
            return Err(ModelError::invalid_resource(
                "max_response_bytes must be between 1 and 256MiB",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        assert!(ResourceLimits::default().validate().is_ok());
        assert!(ResourceLimits::development().validate().is_ok());
    }

    #[test]
    fn rejects_tiny_memory() {
        let limits = ResourceLimits::default().with_memory(1024);
        assert!(limits.validate().is_err());
    }

    #[test]
    fn rejects_zero_and_huge_timeouts() {
        assert!(ResourceLimits::default()
            .with_timeout(Duration::ZERO)
            .validate()
            .is_err());
        assert!(ResourceLimits::default()
            .with_timeout(Duration::from_secs(7200))
            .validate()
            .is_err());
    }

    #[test]
    fn cpu_quota_validation() {
        assert!(CpuLimit::from_millis_per_second(500).is_ok());
        assert!(CpuLimit::from_millis_per_second(0).is_err());
        assert!(CpuLimit::from_millis_per_second(5000).is_err());
        assert!(CpuLimit::Share(0).validate().is_err());
        assert!(CpuLimit::Share(100).validate().is_ok());
    }

    #[test]
    fn serde_roundtrip_preserves_timeout() {
        let limits = ResourceLimits::default()
            .with_timeout(Duration::from_millis(1500))
            .with_memory(256 * MIB);
        let json = serde_json::to_string(&limits).expect("serializes");
        let back: ResourceLimits = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, limits);
        assert_eq!(back.timeout, Duration::from_millis(1500));
    }
}
