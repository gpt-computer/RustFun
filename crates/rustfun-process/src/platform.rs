//! Platform-specific process control.
//!
//! Isolation and lifecycle guarantees differ per OS, so they live here rather than being
//! sprinkled through the engine.

/// The platform family RustFun is running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
    /// Anything else (treated as a Unix-like development host).
    Other,
}

impl Platform {
    /// Detect the current platform.
    pub const fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            Platform::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Platform::MacOs
        }
        #[cfg(target_os = "windows")]
        {
            Platform::Windows
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Platform::Other
        }
    }

    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::MacOs => "macos",
            Platform::Windows => "windows",
            Platform::Other => "other",
        }
    }

    /// Whether the platform supports POSIX process groups and signals.
    pub const fn is_posix(self) -> bool {
        matches!(self, Platform::Linux | Platform::MacOs | Platform::Other)
    }

    /// Whether the platform supports Linux-style namespaces and cgroups v2.
    pub const fn supports_linux_isolation(self) -> bool {
        matches!(self, Platform::Linux)
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether the running kernel allows unprivileged user namespaces.
///
/// Linux distributions frequently disable this. `rustfun doctor` reports the answer rather
/// than letting a sandbox failure surface as a confusing runtime error.
pub fn unprivileged_user_namespaces_available() -> Option<bool> {
    if Platform::current() != Platform::Linux {
        return None;
    }
    // `/proc/sys/kernel/unprivileged_userns_clone` exists on Debian/Ubuntu; on other
    // kernels the sysctl is absent, which means user namespaces are permitted.
    match std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        Ok(value) => Some(value.trim() != "0"),
        Err(_) => Some(true),
    }
}

/// Whether a cgroup v2 hierarchy is mounted.
pub fn cgroup_v2_available() -> Option<bool> {
    if Platform::current() != Platform::Linux {
        return None;
    }
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    Some(cgroup.contains("0::"))
}

/// Whether seccomp can be installed for a child process.
///
/// Requires Linux and either `no_new_privs` (the supported path) or CAP_SYS_ADMIN.
pub fn seccomp_available() -> Option<bool> {
    if Platform::current() != Platform::Linux {
        return None;
    }
    // A kernel with CONFIG_SECCOMP exposes the /proc entry; modern kernels (>= 3.5) do.
    Some(std::path::Path::new("/proc/self/status").exists())
}

/// Read the peak resident set size of a process in kilobytes.
pub fn peak_rss_kb(pid: u32) -> Option<u64> {
    if Platform::current() == Platform::Linux {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                let kb: Vec<&str> = rest.split_whitespace().collect();
                return kb.first().and_then(|v| v.parse().ok());
            }
        }
        None
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_detection_is_consistent() {
        let platform = Platform::current();
        assert_eq!(platform.as_str(), std::env::consts::OS);
        if platform == Platform::Linux {
            assert!(platform.is_posix());
            assert!(platform.supports_linux_isolation());
        }
        if platform == Platform::Windows {
            assert!(!platform.is_posix());
            assert!(!platform.supports_linux_isolation());
        }
    }

    #[test]
    fn namespace_probes_return_none_off_linux() {
        if Platform::current() != Platform::Linux {
            assert!(unprivileged_user_namespaces_available().is_none());
            assert!(cgroup_v2_available().is_none());
            assert!(seccomp_available().is_none());
        }
    }

    #[test]
    fn linux_probes_return_booleans() {
        if Platform::current() == Platform::Linux {
            assert!(unprivileged_user_namespaces_available().is_some());
            assert!(cgroup_v2_available().is_some());
            assert!(seccomp_available().is_some());
        }
    }

    #[test]
    fn peak_rss_of_self_is_reported_on_linux() {
        if Platform::current() == Platform::Linux {
            let pid = std::process::id();
            assert!(peak_rss_kb(pid).is_some_and(|kb| kb > 0));
        }
    }
}
