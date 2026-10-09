//! The OCI runtime adapter.
//!
//! An OCI function is an **image**, not a directory of sources: the image contains a handler that
//! speaks the RustFun framed invocation protocol on stdin/stdout, exactly like the
//! [`executable`](crate::executable) runtime. The difference is where that handler runs — inside a
//! container created from the image's root filesystem.
//!
//! ```text
//! reference ──► pull + verify ──► extract layers ──► rootfs + OCI spec ──► runc ──► handler
//! ```
//!
//! # Isolation
//!
//! Isolation comes from the OCI runtime spec this crate generates, not from the process sandbox:
//! `runc` creates the pid, ipc, uts, mount, and network namespaces itself. The spec gives the
//! container **no capabilities**, `noNewPrivileges`, masked and read-only paths, and the memory
//! limit from the function policy — so the `runc` process itself is started on the host layer,
//! because wrapping a container runtime in the process sandbox would prevent it from creating the
//! namespaces it needs.
//!
//! # Honesty about capability
//!
//! A container runtime that is installed but cannot start a container (user namespaces disabled,
//! no privileges) is **not** reported as available. `discover` and `prepare` both fail with an
//! `Unavailable` error naming the reason, so a missing container runtime is a clear message
//! rather than a failed invocation.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use rustfun_core::runtime::{
    PrepareRequest, PreparedRuntime, RuntimeAdapter, RuntimeDiscovery, RuntimeInstance,
    StartRequest,
};
use rustfun_core::{ErrorContext, Result, RustFunError};
use rustfun_model::{
    Environment, RuntimeCapabilities, RuntimeFamily, RuntimeId, RuntimeVersion, SandboxPolicy,
};

use rustfun_oci::{
    ContainerRuntime, Digest, ImageReference, OciImageCache, RegistryClient, RootfsBuilder,
    RuncRuntime,
};

use crate::node::to_map;
use crate::process::{ProcessInstance, ProcessLaunch, ProcessRuntimeAdapter};

/// Environment variable that overrides the image reference (the handler normally carries it).
pub const ENV_IMAGE: &str = "RUSTFUN_OCI_IMAGE";

/// Environment variable that overrides the command run inside the container.
pub const ENV_COMMAND: &str = "RUSTFUN_OCI_COMMAND";

/// Directory name used for the extracted image inside the function root.
pub const OCI_DIR: &str = ".oci";

/// The OCI runtime adapter.
#[derive(Debug, Clone, Default)]
pub struct OciAdapter {
    base: ProcessRuntimeAdapter,
}

impl OciAdapter {
    /// Create the adapter.
    pub fn new() -> Self {
        Self {
            base: ProcessRuntimeAdapter::new("oci"),
        }
    }

    /// The container runtime on this host, when one can actually start a container.
    fn container_runtime() -> Option<RuncRuntime> {
        let runtime = RuncRuntime::discover()?;
        runtime.is_available().then_some(runtime)
    }

    /// The error every OCI path returns when no container can run here.
    fn unavailable(reason: &str) -> RustFunError {
        RustFunError::unavailable(format!("no usable OCI container runtime: {reason}"))
            .with_context(
                ErrorContext::new()
                    .operation("prepare_runtime")
                    .remediation(
                        "install runc (or crun) and make user namespaces available: \
                         sysctl kernel.unprivileged_userns_clone=1, or run rustfun with \
                         CAP_SYS_ADMIN to start containers as root",
                    ),
            )
    }
}

/// Pull an image, verify every blob, and assemble its root filesystem.
///
/// This is the whole image pipeline in one call, and it is deliberately all-or-nothing: a layer
/// that fails verification stops the pull rather than producing a partially trusted rootfs.
pub async fn materialise(
    reference: &ImageReference,
    workdir: &std::path::Path,
) -> Result<(PathBuf, rustfun_oci::ImageConfig, Digest)> {
    let client = RegistryClient::new(reference).map_err(oci_error)?;
    let cache = OciCacheHolder::open(workdir)?;
    let (manifest, manifest_bytes) = client.fetch_manifest().await.map_err(oci_error)?;

    // The manifest itself is content: recording its digest is what makes the pull reproducible.
    let manifest_digest = Digest::of(&manifest_bytes);
    if let Some(expected) = &reference.digest {
        if &manifest_digest != expected {
            return Err(RustFunError::artifact(format!(
                "the registry served a manifest with digest {manifest_digest}, but {} was requested",
                expected.as_str()
            ))
            .with_context(
                ErrorContext::new()
                    .operation("pull_image")
                    .remediation("a tag may have been re-pointed; pin the image by digest"),
            ));
        }
    }

    let config_digest = manifest.config.parsed_digest().map_err(oci_error)?;
    let config_bytes = cache
        .get(&client, &config_digest)
        .await
        .map_err(oci_error)?;
    let config: rustfun_oci::ImageConfig =
        serde_json::from_slice(&config_bytes).map_err(|error| {
            RustFunError::artifact(format!("the image config is not valid JSON: {error}"))
                .with_context(ErrorContext::new().operation("pull_image"))
        })?;

    let root = workdir.join(OCI_DIR).join("rootfs");
    // A stale rootfs would mix layers from a different image.
    let _ = std::fs::remove_dir_all(&root);
    let builder = RootfsBuilder::new(&root).map_err(oci_error)?;
    for layer in &manifest.layers {
        let digest = layer.parsed_digest().map_err(oci_error)?;
        // `get` verifies the digest before returning; a mismatched layer never reaches extraction.
        let bytes = cache.get(&client, &digest).await.map_err(oci_error)?;
        builder
            .extract_layer(&bytes, &layer.media_type)
            .map_err(oci_error)?;
    }
    Ok((root, config, manifest_digest))
}

/// Cache handle used by [`materialise`], kept in a wrapper so its error type stays local.
struct OciCacheHolder {
    cache: OciImageCache,
}

impl OciCacheHolder {
    fn open(workdir: &std::path::Path) -> Result<Self> {
        OciImageCache::open(workdir.join(OCI_DIR).join("blobs"))
            .map(|cache| Self { cache })
            .map_err(oci_error)
    }

    async fn get(
        &self,
        client: &RegistryClient,
        digest: &Digest,
    ) -> std::result::Result<Vec<u8>, rustfun_oci::OciError> {
        self.cache.get(client, digest).await
    }
}

/// Convert an OCI error into a platform error, keeping the operation name.
///
/// A digest mismatch is an artifact failure and a registry failure is an unavailability: the two
/// need different responses from an operator, so they are not collapsed into one category.
fn oci_error(error: rustfun_oci::OciError) -> RustFunError {
    let category = if error.operation.starts_with("fetch") || error.message.contains("cannot reach")
    {
        rustfun_core::ErrorCategory::Unavailable
    } else {
        rustfun_core::ErrorCategory::Artifact
    };
    let context = ErrorContext::new().operation(&error.operation);
    let text = format!("oci {}", error.message);
    match category {
        rustfun_core::ErrorCategory::Unavailable => RustFunError::unavailable(text)
            .with_context(context.remediation("check the image reference and network access")),
        _ => RustFunError::artifact(text).with_context(context),
    }
}

#[async_trait]
impl RuntimeAdapter for OciAdapter {
    fn family(&self) -> RuntimeFamily {
        RuntimeFamily::Oci
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        // A container is a single process speaking one protocol at a time, like any other
        // process-backed runtime; what changes is the isolation, not the calling convention.
        RuntimeCapabilities::PROCESS
    }

    async fn discover(&self) -> Result<Vec<RuntimeDiscovery>> {
        let executable = RuncRuntime::discover()
            .map(|runtime| runtime.path().display().to_string())
            .unwrap_or_else(|| "<not installed>".to_owned());
        let available = Self::container_runtime().is_some();
        Ok(vec![RuntimeDiscovery::new(
            RuntimeId::new(RuntimeFamily::Oci, RuntimeVersion::Any),
            executable,
        )
        .with_available(available)
        .with_reported_version(if available {
            "container runtime available"
        } else {
            "container runtime cannot start a container here"
        })])
    }

    async fn prepare(&self, request: PrepareRequest) -> Result<PreparedRuntime> {
        // The handler names the image: `handler = "ghcr.io/rustfun/hello:1"`.
        let image = request
            .environment
            .get(ENV_IMAGE)
            .map(str::to_owned)
            .unwrap_or_else(|| request.handler.as_str().to_owned());
        let reference = ImageReference::parse(&image).map_err(|error| {
            RustFunError::validation(format!(
                "the oci handler must be an image reference such as `ghcr.io/org/name:tag`: {error}"
            ))
            .with_context(
                ErrorContext::new()
                    .operation("prepare_runtime")
                    .function(request.function_name.as_str())
                    .remediation("set `handler` to an image reference, or set RUSTFUN_OCI_IMAGE"),
            )
        })?;

        let Some(runtime) = Self::container_runtime() else {
            return Err(Self::unavailable(&format!(
                "`{}` is installed but cannot start a container",
                runtime_name()
            )));
        };
        let _ = &runtime;

        let (root, config, digest) = materialise(&reference, &request.workdir).await?;
        let command = match request.environment.get(ENV_COMMAND) {
            Some(command) => command
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            None => config.config.command(),
        };
        if command.is_empty() {
            return Err(RustFunError::validation(format!(
                "the image {} has no entrypoint or command",
                reference.canonical()
            ))
            .with_context(
                ErrorContext::new()
                    .operation("prepare_runtime")
                    .function(request.function_name.as_str())
                    .remediation("give the image an ENTRYPOINT, or set RUSTFUN_OCI_COMMAND"),
            ));
        }

        let spec_path = root
            .parent()
            .map_or_else(|| request.workdir.clone(), PathBuf::from)
            .join("config.json");
        // The spec is regenerated per instance because the container id and limits belong to the
        // instance, not to the image.
        let _ = &spec_path;

        let mut environment: Environment = request.environment.clone();
        environment.insert(ENV_IMAGE, reference.canonical())?;
        environment.insert("RUSTFUN_OCI_DIGEST", digest.as_str())?;
        environment.insert("RUSTFUN_OCI_ROOTFS", root.to_string_lossy().as_ref())?;
        environment.insert("RUSTFUN_OCI_BUNDLE", spec_path.to_string_lossy().as_ref())?;
        environment.insert("RUSTFUN_OCI_COMMAND", command.join(" "))?;
        Ok(PreparedRuntime::new(
            request.runtime.clone(),
            vec![reference.canonical()],
            request.workdir,
            environment,
            self.capabilities(),
        ))
    }

    async fn start(&self, request: StartRequest) -> Result<Box<dyn RuntimeInstance>> {
        let Some(runtime) = Self::container_runtime() else {
            return Err(Self::unavailable(&format!(
                "`{}` is installed but cannot start a container",
                runtime_name()
            )));
        };
        let bundle = request
            .prepared
            .environment
            .get("RUSTFUN_OCI_BUNDLE")
            .ok_or_else(|| {
                RustFunError::validation("the prepared OCI runtime has no bundle path")
                    .with_context(ErrorContext::new().operation("start_instance"))
            })?;
        let rootfs = request
            .prepared
            .environment
            .get("RUSTFUN_OCI_ROOTFS")
            .ok_or_else(|| {
                RustFunError::validation("the prepared OCI runtime has no root filesystem")
                    .with_context(ErrorContext::new().operation("start_instance"))
            })?;
        let command: Vec<String> = request
            .prepared
            .environment
            .get("RUSTFUN_OCI_COMMAND")
            .map(|command| command.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        let memory_bytes = request.spec.resources.memory_bytes;

        let config_path = std::path::Path::new(&bundle).to_path_buf();
        let image_config = rustfun_oci::ImageConfig {
            architecture: String::new(),
            os: String::new(),
            config: rustfun_oci::manifest::ImageConfigContainer {
                env: Vec::new(),
                ..Default::default()
            },
            rootfs: Default::default(),
        };
        runtime
            .build_spec(
                std::path::Path::new(&rootfs),
                &image_config,
                command,
                None,
                memory_bytes,
            )
            .map_err(oci_error)?;
        let _ = config_path;

        let container_id = format!("rustfun-{}", request.instance_id);
        let runtime_binary = runtime.path().display().to_string();
        let environment = self.base.instance_environment(
            &request.spec,
            &request.instance_id,
            &to_map(&request.prepared.environment),
        )?;
        let launch = ProcessLaunch {
            // `runc run` blocks until the container exits and deletes it, so the protocol streams
            // stay attached to the pipes the process engine owns.
            command: vec![runtime_binary, "run".to_owned(), container_id.clone()],
            workdir: request.prepared.workdir.clone(),
            environment,
            resources: request.spec.resources,
            // The container's own namespaces come from the OCI spec; the sandbox would only stop
            // runc from creating them.
            sandbox: SandboxPolicy::host(),
            runtime: request.prepared.runtime.clone(),
            shutdown_grace: Duration::from_millis(500),
        };
        let instance =
            ProcessInstance::start(request.instance_id, request.spec.id.clone(), launch).await?;
        Ok(Box::new(OciInstance {
            inner: instance,
            container_id,
        }))
    }
}

/// The container id used for an instance, exposed for diagnostics and tests.
pub fn container_id_for(instance_id: &rustfun_model::InstanceId) -> String {
    format!("rustfun-{instance_id}")
}

/// Whether a container runtime is usable on this host.
pub fn container_runtime_available() -> bool {
    OciAdapter::container_runtime().is_some()
}

/// A human-readable name for the container runtime on this host.
fn runtime_name() -> String {
    RuncRuntime::discover()
        .map(|runtime| runtime.path().display().to_string())
        .unwrap_or_else(|| "runc".to_owned())
}

/// An OCI instance: the container's process, plus the id needed to delete it.
struct OciInstance {
    inner: ProcessInstance,
    container_id: String,
}

#[async_trait]
impl RuntimeInstance for OciInstance {
    fn instance_id(&self) -> &rustfun_model::InstanceId {
        self.inner.instance_id()
    }

    fn runtime(&self) -> &RuntimeId {
        self.inner.runtime()
    }

    async fn invoke(
        &self,
        request: rustfun_core::protocol::InvocationRequest,
    ) -> Result<rustfun_core::runtime::InvocationOutcome> {
        self.inner.invoke(request).await
    }

    async fn health(&self) -> rustfun_core::runtime::HealthStatus {
        self.inner.health().await
    }

    async fn shutdown(&mut self) -> Result<()> {
        // `runc run` removes the container when the process exits; forcing the id afterwards is
        // harmless and covers a container that outlived its `run` process.
        if let Some(runtime) = RuncRuntime::discover() {
            let _ = runtime.delete(&rustfun_oci::ContainerHandle {
                id: self.container_id.clone(),
                runtime: runtime.name().to_owned(),
            });
        }
        self.inner.shutdown().await
    }
}

/// The environment a container starts with, exposed for tests.
pub fn oci_environment(command: &[String]) -> BTreeMap<String, String> {
    command
        .iter()
        .enumerate()
        .map(|(index, part)| (format!("RUSTFUN_OCI_ARG{index}"), part.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfun_model::{FunctionName, FunctionSpec, HandlerSpec, ResourceLimits};

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rustfun-oci-adapter-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("creates dir");
        dir
    }

    fn request(dir: PathBuf, handler: &str) -> PrepareRequest {
        let spec = FunctionSpec::new(
            FunctionName::new("hello").expect("valid"),
            RuntimeId::parse("oci").expect("valid"),
            HandlerSpec::parse(handler).expect("valid handler"),
        );
        PrepareRequest {
            function_id: spec.id,
            function_name: spec.name.clone(),
            runtime: spec.runtime.clone(),
            handler: spec.handler.clone(),
            workdir: dir,
            environment: Environment::new(),
            resources: ResourceLimits::default(),
            sandbox: SandboxPolicy::oci(),
        }
    }

    #[tokio::test]
    async fn a_handler_that_is_not_an_image_reference_is_refused() {
        let dir = temp_dir("bad-handler");
        let error = match OciAdapter::new()
            .prepare(request(dir.clone(), "./bin/handler"))
            .await
        {
            Ok(_) => panic!("a filesystem path must not be accepted as an image reference"),
            Err(error) => error,
        };
        assert_eq!(error.category(), rustfun_core::ErrorCategory::Validation);
        assert!(
            error.context().remediation.is_some(),
            "the operator must be told what a valid handler looks like"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_valid_reference_without_a_container_runtime_is_unavailable() {
        let dir = temp_dir("no-runtime");
        let adapter = OciAdapter::new();
        // The image is never pulled: the container runtime is checked first, so a host that
        // cannot run containers fails fast with a clear reason instead of a network error.
        let result = adapter
            .prepare(request(dir.clone(), "ghcr.io/rustfun/hello:1"))
            .await;
        if container_runtime_available() {
            // On a host with a working runtime the failure must be about the network, not about
            // the sandbox.
            let error = match result {
                Ok(_) => panic!("a test must never reach a real registry"),
                Err(error) => error,
            };
            assert_ne!(error.category(), rustfun_core::ErrorCategory::Unavailable);
        } else {
            let error = match result {
                Ok(_) => panic!("a host without a container runtime must refuse"),
                Err(error) => error,
            };
            assert_eq!(error.category(), rustfun_core::ErrorCategory::Unavailable);
            assert!(
                error.context().remediation.is_some(),
                "an unavailable runtime must say how to fix it"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn discovery_reports_the_container_runtime_truthfully() {
        let discovered = OciAdapter::new().discover().await.expect("discovers");
        assert_eq!(discovered.len(), 1);
        let entry = &discovered[0];
        assert_eq!(entry.id.family(), RuntimeFamily::Oci);
        // Availability must mean "can start a container", not "binary exists".
        assert_eq!(entry.available, container_runtime_available());
        if !entry.available {
            assert!(
                entry
                    .reported_version
                    .as_deref()
                    .is_some_and(|v| v.contains("cannot start")),
                "an unusable runtime must say so: {entry:?}"
            );
        }
    }

    #[tokio::test]
    async fn starting_without_a_usable_runtime_is_unavailable() {
        if container_runtime_available() {
            return;
        }
        let dir = temp_dir("start");
        let adapter = OciAdapter::new();
        let prepared = PreparedRuntime::new(
            RuntimeId::parse("oci").expect("valid"),
            vec!["ghcr.io/rustfun/hello:1".to_owned()],
            dir.clone(),
            Environment::new(),
            RuntimeCapabilities::PROCESS,
        );
        let spec = std::sync::Arc::new(
            FunctionSpec::new(
                FunctionName::new("hello").expect("valid"),
                RuntimeId::parse("oci").expect("valid"),
                HandlerSpec::parse("ghcr.io/rustfun/hello:1").expect("valid handler"),
            )
            .with_sandbox(SandboxPolicy::oci()),
        );
        let error = match adapter
            .start(StartRequest {
                spec,
                instance_id: rustfun_model::InstanceId::new(),
                prepared,
                prewarm: false,
            })
            .await
        {
            Ok(_) => panic!("starting a container must fail without a usable runtime"),
            Err(error) => error,
        };
        assert_eq!(error.category(), rustfun_core::ErrorCategory::Unavailable);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn container_ids_are_namespaced_to_rustfun() {
        let id = rustfun_model::InstanceId::new();
        assert!(container_id_for(&id).starts_with("rustfun-"));
        assert_eq!(container_id_for(&id), container_id_for(&id));
    }

    #[test]
    fn capabilities_match_a_process_backed_runtime() {
        let capabilities = OciAdapter::new().capabilities();
        assert!(capabilities.warm_instances);
        assert!(capabilities.binary_payloads);
        assert!(!capabilities.concurrency);
    }
}
