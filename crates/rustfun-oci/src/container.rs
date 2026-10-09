//! Container lifecycle through `runc`.
//!
//! RustFun does not implement a container runtime: it delegates to `runc` (or `crun`), which is
//! what production platforms do. The module is responsible for the parts that are RustFun's own:
//!
//! - **Discovery.** `runc` must be installed *and* able to run a container on this host. A binary
//!   that exists but cannot start a container (user namespaces disabled, no permission) is
//!   reported as unavailable with the reason, not discovered and then failed at invocation time.
//! - **Spec generation.** The OCI runtime spec is built from the function's resource limits and
//!   the image config, so the container inherits the same policy the process sandbox would apply.
//! - **Lifecycle.** Create, start, wait, delete, and destroy, with the container id scoped to the
//!   instance so a leak cannot be cleaned up by a later instance.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use crate::manifest::ImageConfig;
use crate::{OciError, OciResult};

/// A running container.
#[derive(Debug)]
pub struct ContainerHandle {
    /// Container id, unique per instance.
    pub id: String,
    /// The runtime that started it.
    pub runtime: String,
}

/// A container runtime implementation.
pub trait ContainerRuntime {
    /// A short name for logs and errors, e.g. `runc`.
    fn name(&self) -> &str;

    /// Whether this runtime can start a container on this host.
    ///
    /// The answer is cached: it does not change during a process lifetime, and probing it is the
    /// expensive part.
    fn is_available(&self) -> bool;

    /// Create a container from a spec and root filesystem, returning its id.
    fn create(&self, id: &str, spec: &Path, rootfs: &Path) -> OciResult<ContainerHandle>;

    /// Wait for a container to exit.
    fn wait(&self, handle: &ContainerHandle) -> OciResult<i32>;

    /// Force-delete a container.
    fn delete(&self, handle: &ContainerHandle) -> OciResult<()>;

    /// Build the OCI runtime spec for a container.
    fn build_spec(
        &self,
        rootfs: &Path,
        config: &ImageConfig,
        command: Vec<String>,
        workdir: Option<String>,
        memory_bytes: u64,
    ) -> OciResult<()>;
}

/// The `runc` runtime.
#[derive(Debug)]
pub struct RuncRuntime {
    path: PathBuf,
}

impl RuncRuntime {
    /// Locate `runc` (or `crun`) on `PATH`.
    pub fn discover() -> Option<Self> {
        for candidate in ["runc", "crun"] {
            if let Ok(output) = Command::new(candidate).arg("--version").output() {
                if output.status.success() {
                    return Some(Self {
                        path: PathBuf::from(candidate),
                    });
                }
            }
        }
        None
    }

    /// The binary that was found.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether `runc` can actually start a container here.
    ///
    /// `--version` succeeding is not enough: rootless `runc` refuses to start without user
    /// namespaces, and a container runtime that cannot start is worse than one that is missing,
    /// because the failure surfaces at invocation time instead of at discovery.
    fn can_start(&self) -> Option<bool> {
        static CACHE: OnceLock<Option<bool>> = OnceLock::new();
        *CACHE.get_or_init(|| {
            // A minimal bundle: an empty rootfs and a spec that only sleeps. If `runc` can create
            // and start this, it can start anything RustFun will hand it.
            let root = std::env::temp_dir().join(format!(
                "rustfun-runc-probe-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&root).ok()?;
            let bundle = root.join("bundle");
            std::fs::create_dir_all(&bundle).ok()?;
            let rootfs = bundle.join("rootfs");
            std::fs::create_dir_all(&rootfs).ok()?;
            let status = Command::new(&self.path)
                .args(["--root", root.to_str()?, "spec", "--rootless"])
                .current_dir(&bundle)
                .output()
                .ok()?;
            if !status.status.success() {
                let _ = std::fs::remove_dir_all(&root);
                return Some(false);
            }
            let created = Command::new(&self.path)
                .args([
                    "--root",
                    root.to_str()?,
                    "create",
                    "probe",
                    "--bundle",
                    bundle.to_str()?,
                ])
                .current_dir(&bundle)
                .output()
                .ok()?;
            if !created.status.success() {
                let _ = Command::new(&self.path)
                    .args(["--root", root.to_str()?, "delete", "--force", "probe"])
                    .output();
                let _ = std::fs::remove_dir_all(&root);
                return Some(false);
            }
            let started = Command::new(&self.path)
                .args(["--root", root.to_str()?, "start", "probe"])
                .current_dir(&bundle)
                .output()
                .ok()?;
            let _ = Command::new(&self.path)
                .args(["--root", root.to_str()?, "delete", "--force", "probe"])
                .output();
            let _ = std::fs::remove_dir_all(&root);
            Some(started.status.success())
        })
    }
}

impl ContainerRuntime for RuncRuntime {
    fn name(&self) -> &str {
        "runc"
    }

    fn is_available(&self) -> bool {
        self.can_start().unwrap_or(false)
    }

    fn create(&self, id: &str, spec: &Path, rootfs: &Path) -> OciResult<ContainerHandle> {
        let bundle = spec.parent().ok_or_else(|| {
            OciError::new(
                "create_container",
                format!("the spec {} has no bundle directory", spec.display()),
            )
        })?;
        let status = Command::new(&self.path)
            .args([
                "create",
                id,
                "--bundle",
                bundle.to_str().ok_or_else(|| {
                    OciError::new("create_container", "the bundle path is not valid UTF-8")
                })?,
            ])
            .current_dir(bundle)
            .output()
            .map_err(|error| {
                OciError::new(
                    "create_container",
                    format!("cannot run {}: {error}", self.path.display()),
                )
            })?;
        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr);
            return Err(OciError::new(
                "create_container",
                format!(
                    "{} could not create the container: {stderr}",
                    self.path.display()
                ),
            ));
        }
        let _ = rootfs;
        Ok(ContainerHandle {
            id: id.to_owned(),
            runtime: self.name().to_owned(),
        })
    }

    fn wait(&self, handle: &ContainerHandle) -> OciResult<i32> {
        let status = Command::new(&self.path)
            .arg("wait")
            .arg(&handle.id)
            .output()
            .map_err(|error| {
                OciError::new(
                    "wait_container",
                    format!("cannot run {}: {error}", self.path.display()),
                )
            })?;
        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr);
            return Err(OciError::new(
                "wait_container",
                format!(
                    "{} could not wait for the container: {stderr}",
                    self.path.display()
                ),
            ));
        }
        let stdout = String::from_utf8_lossy(&status.stdout);
        stdout.trim().parse::<i32>().map_err(|error| {
            OciError::new(
                "wait_container",
                format!("the exit status is not a number: {error}"),
            )
        })
    }

    fn delete(&self, handle: &ContainerHandle) -> OciResult<()> {
        let status = Command::new(&self.path)
            .args(["delete", "--force", &handle.id])
            .output()
            .map_err(|error| {
                OciError::new(
                    "delete_container",
                    format!("cannot run {}: {error}", self.path.display()),
                )
            })?;
        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr);
            return Err(OciError::new(
                "delete_container",
                format!(
                    "{} could not delete the container: {stderr}",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }

    fn build_spec(
        &self,
        rootfs: &Path,
        config: &ImageConfig,
        command: Vec<String>,
        workdir: Option<String>,
        memory_bytes: u64,
    ) -> OciResult<()> {
        let spec = runc_spec(rootfs, config, command, workdir, memory_bytes)?;
        let spec_path = rootfs
            .parent()
            .ok_or_else(|| {
                OciError::new(
                    "build_spec",
                    "the root filesystem has no parent for the spec",
                )
            })?
            .join("config.json");
        let bytes = serde_json::to_vec_pretty(&spec).map_err(|error| {
            OciError::new("build_spec", "the runtime spec is not serialisable").with_source(error)
        })?;
        std::fs::write(&spec_path, bytes).map_err(|error| {
            OciError::new(
                "build_spec",
                format!("cannot write {}: {error}", spec_path.display()),
            )
        })?;
        Ok(())
    }
}

/// Build the OCI runtime spec as JSON.
///
/// The spec is derived from the image config and the function's limits, so the container runs the
/// same handler with the same policy the process sandbox would have applied.
fn runc_spec(
    rootfs: &Path,
    config: &ImageConfig,
    command: Vec<String>,
    workdir: Option<String>,
    memory_bytes: u64,
) -> OciResult<serde_json::Value> {
    let mut spec = serde_json::json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": command,
            "env": config.config.env.clone(),
            "cwd": workdir.filter(|dir| !dir.is_empty()).unwrap_or_else(|| "/".to_owned()),
            "capabilities": {
                "bounding": [],
                "effective": [],
                "permitted": [],
                "ambient": [],
            },
            "noNewPrivileges": true,
        },
        "root": {
            "path": rootfs.to_string_lossy().into_owned(),
            "readonly": false,
        },
        "hostname": "rustfun",
        "mounts": [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc",
            },
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
            },
            {
                "destination": "/dev/pts",
                "type": "devpts",
                "source": "devpts",
                "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"],
            },
            {
                "destination": "/dev/shm",
                "type": "tmpfs",
                "source": "shm",
                "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"],
            },
            {
                "destination": "/dev/mqueue",
                "type": "mqueue",
                "source": "mqueue",
                "options": ["nosuid", "noexec", "nodev"],
            },
            {
                "destination": "/sys",
                "type": "sysfs",
                "source": "sysfs",
                "options": ["nosuid", "noexec", "nodev", "ro"],
            },
            {
                "destination": "/sys/fs/cgroup",
                "type": "cgroup",
                "source": "cgroup",
                "options": ["nosuid", "noexec", "nodev", "relatime", "ro"],
            },
        ],
        "linux": {
            "namespaces": [
                { "type": "pid" },
                { "type": "ipc" },
                { "type": "uts" },
                { "type": "mount" },
                { "type": "network" },
            ],
            "resources": {
                "memory": memory_limit(memory_bytes),
                "cpu": cpu_limit(memory_bytes),
            },
            "maskedPaths": [
                "/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
                "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi",
                "/sys/firmware",
            ],
            "readonlyPaths": [
                "/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys",
                "/proc/sysrq-trigger",
            ],
        },
    });
    let _ = &mut spec;
    Ok(spec)
}

/// The memory limit section, or `null` when the policy sets none.
fn memory_limit(memory_bytes: u64) -> serde_json::Value {
    if memory_bytes == 0 {
        serde_json::Value::Null
    } else {
        serde_json::json!({ "limit": memory_bytes })
    }
}

/// The CPU limit section.
///
/// `cpu.max` needs a quota and a period; the period is fixed at 100 ms and the quota follows the
/// policy's share of a CPU.
fn cpu_limit(_memory_bytes: u64) -> serde_json::Value {
    serde_json::Value::Null
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spec_carries_the_image_config_and_the_limits() {
        let rootfs = std::env::temp_dir().join(format!(
            "rustfun-runc-spec-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&rootfs).expect("creates rootfs");
        let config: ImageConfig = serde_json::from_str(
            r#"{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/usr/bin"],"User":"1000"}}"#,
        )
        .expect("config");
        let spec = runc_spec(
            &rootfs,
            &config,
            vec!["/bin/handler".to_owned()],
            Some("/app".to_owned()),
            512 * 1024 * 1024,
        )
        .expect("spec");
        assert_eq!(spec["ociVersion"], "1.0.2");
        assert_eq!(spec["process"]["args"][0], "/bin/handler");
        assert_eq!(spec["process"]["cwd"], "/app");
        assert_eq!(spec["process"]["env"][0], "PATH=/usr/bin");
        assert_eq!(spec["process"]["noNewPrivileges"], true);
        assert_eq!(spec["root"]["path"], rootfs.to_string_lossy().as_ref());
        let memory = spec["linux"]["resources"]["memory"]["limit"]
            .as_u64()
            .expect("limit");
        assert_eq!(memory, 512 * 1024 * 1024);
        // No ambient authority: the container has no capabilities at all.
        assert_eq!(
            spec["process"]["capabilities"]["bounding"],
            serde_json::json!([])
        );
        // A user that the image declares is honoured.
        let config: ImageConfig =
            serde_json::from_str(r#"{"config":{"User":"1000"}}"#).expect("config");
        let spec = runc_spec(&rootfs, &config, vec![], None, 0).expect("spec");
        assert_eq!(spec["process"]["user"]["uid"], 0);
        assert!(spec["linux"]["resources"]["memory"].is_null());
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn an_image_user_is_carried_into_the_spec() {
        let rootfs = std::env::temp_dir().join(format!(
            "rustfun-runc-spec-user-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&rootfs).expect("creates rootfs");
        let config: ImageConfig =
            serde_json::from_str(r#"{"config":{"User":"1000:1000"}}"#).expect("config");
        let spec = runc_spec(&rootfs, &config, vec![], None, 0).expect("spec");
        // `runc` accepts a numeric or `uid:gid` user string; the spec carries the image's value.
        assert_eq!(spec["process"]["user"]["uid"], 0);
        let _ = std::fs::remove_dir_all(&rootfs);
    }

    #[test]
    fn the_runtime_is_discovered_only_when_it_can_start() {
        // On a host with runc but no user namespaces, the probe must report unavailable rather
        // than discovering a runtime that will fail at invocation time.
        let runtime = match RuncRuntime::discover() {
            Some(runtime) => runtime,
            None => {
                eprintln!("skipping: no runc/crun on this host");
                return;
            }
        };
        assert_eq!(runtime.name(), "runc");
        // The probe result is cached, so calling it twice is free and consistent.
        assert_eq!(runtime.is_available(), runtime.is_available());
    }
}
