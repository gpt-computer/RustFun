//! `rustfun` — the command line interface.
//!
//! Every command delegates to [`rustfun_invoke::InvocationService`]; the CLI owns argument
//! parsing, templates, and presentation only. That is why `rustfun function invoke` and
//! `POST /functions/:id/invoke` behave identically.
//!
//! ```text
//! rustfun init <name> --template node|python|rust|wasm|executable
//! rustfun doctor
//! rustfun dev [--port N]
//! rustfun build [<name>]
//! rustfun cache <list|clean|verify>
//! rustfun function <create|list|inspect|invoke|destroy>
//! rustfun runtime <list|inspect>
//! rustfun instance list
//! rustfun version
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use rustfun_core::artifact::ArtifactStore;
use rustfun_core::protocol::InvocationStatus;
use rustfun_core::{Result, RustFunError};
use rustfun_invoke::{InvocationService, ServiceConfig};
use serde_json::json;

/// RustFun: a serverless function execution kernel.
#[derive(Debug, Parser)]
#[command(name = "rustfun", version, about, long_about = None)]
pub struct Cli {
    /// Directory containing the function manifests.
    #[arg(long, global = true, env = "RUSTFUN_PROJECT_DIR")]
    pub project_dir: Option<PathBuf>,

    /// Directory for artifacts, extracted trees, and build output.
    #[arg(long, global = true, env = "RUSTFUN_HOME")]
    pub state_dir: Option<PathBuf>,

    /// Emit machine-readable JSON instead of human-readable output.
    #[arg(long, global = true)]
    pub json: bool,

    /// Increase log verbosity.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scaffold a new function from a template.
    Init(InitArgs),
    /// Check the host for everything RustFun needs.
    Doctor,
    /// Run the local development control plane.
    Dev(DevArgs),
    /// Build a function artifact.
    Build(BuildArgs),
    /// Inspect and manage the artifact cache.
    Cache(CacheArgs),
    /// Manage functions.
    #[command(subcommand)]
    Function(FunctionCommand),
    /// Discover and inspect runtimes.
    #[command(subcommand)]
    Runtime(RuntimeCommand),
    /// Inspect live instances.
    #[command(subcommand)]
    Instance(InstanceCommand),
    /// Print the platform version.
    Version,
}

/// Template for `rustfun init`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Template {
    /// Node.js (CommonJS or ES modules).
    Node,
    /// Python.
    Python,
    /// A Rust binary built with the RustFun SDK.
    Rust,
    /// A WebAssembly module.
    Wasm,
    /// Any executable that speaks the RustFun protocol.
    Executable,
    /// The in-process runtime, useful for trying RustFun without a toolchain.
    Echo,
}

impl Template {
    /// Runtime id written into the generated manifest.
    pub fn runtime(self) -> &'static str {
        match self {
            Template::Node => "node@*",
            Template::Python => "python@*",
            Template::Rust => "rust@*",
            Template::Wasm => "wasm@*",
            Template::Executable => "executable@*",
            Template::Echo => "echo@*",
        }
    }

    /// Sandbox layer the template's manifest selects.
    ///
    /// A Wasm module is confined by Wasmtime, so it declares the `wasm` layer; the process
    /// templates declare `host`, which the CLI reports as insecure rather than pretending.
    pub fn sandbox_kind(self) -> &'static str {
        match self {
            Template::Wasm => "wasm",
            _ => "host",
        }
    }
}

/// Arguments for `rustfun init`.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Function name.
    pub name: String,
    /// Template to scaffold from.
    #[arg(long, value_enum, default_value_t = Template::Node)]
    pub template: Template,
    /// Directory to create (defaults to `./<name>`).
    #[arg(long)]
    pub directory: Option<PathBuf>,
    /// Overwrite an existing directory.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `rustfun dev`.
#[derive(Debug, Args)]
pub struct DevArgs {
    /// Port to listen on.
    #[arg(long, default_value_t = 8787)]
    pub port: u16,
    /// Address to bind.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    /// Build every function at startup.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub build: bool,
}

/// Arguments for `rustfun build`.
#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Function to build (all functions when omitted).
    pub name: Option<String>,
    /// Ignore the artifact cache.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `rustfun cache`.
#[derive(Debug, Args)]
pub struct CacheArgs {
    /// Cache subcommand.
    #[command(subcommand)]
    pub command: CacheCommand,
}

/// Cache subcommands.
#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    /// Show cache statistics.
    List,
    /// Verify every artifact against its digest.
    Verify,
    /// Remove cached artifacts.
    Clean {
        /// Remove artifacts older than this many seconds.
        #[arg(long, default_value_t = 0)]
        max_age: u64,
    },
}

/// Function subcommands.
#[derive(Debug, Subcommand)]
pub enum FunctionCommand {
    /// Create a function from a manifest in the project.
    Create {
        /// Function name.
        name: String,
    },
    /// List functions.
    List,
    /// Show one function in detail.
    Inspect {
        /// Function name or id.
        name: String,
    },
    /// Invoke a function.
    Invoke(InvokeArgs),
    /// Destroy a function and its instances.
    Destroy {
        /// Function name.
        name: String,
    },
}

/// Arguments for `rustfun function invoke`.
#[derive(Debug, Args)]
pub struct InvokeArgs {
    /// Function name.
    pub name: String,
    /// JSON payload.
    #[arg(long, short)]
    pub payload: Option<String>,
    /// Read the payload from a file.
    #[arg(long, conflicts_with = "payload")]
    pub file: Option<PathBuf>,
    /// Invocation timeout in milliseconds.
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Print only the function result.
    #[arg(long)]
    pub raw: bool,
}

/// Runtime subcommands.
#[derive(Debug, Subcommand)]
pub enum RuntimeCommand {
    /// List discovered runtimes.
    List,
    /// Inspect one runtime.
    Inspect {
        /// Runtime id, e.g. `node`.
        name: String,
    },
}

/// Instance subcommands.
#[derive(Debug, Subcommand)]
pub enum InstanceCommand {
    /// List live instances.
    List,
}

impl Cli {
    /// Run the CLI.
    pub async fn run(mut cli: Cli) -> Result<()> {
        let command = std::mem::replace(&mut cli.command, Command::Version);
        match command {
            Command::Version => {
                println!("rustfun {}", rustfun_core::model::VERSION);
                Ok(())
            }
            Command::Init(args) => init(cli.json, args),
            Command::Doctor => doctor(cli.json).await,
            Command::Function(command) => function_command(&cli, command).await,
            Command::Runtime(command) => runtime_command(&cli, command).await,
            Command::Instance(command) => instance_command(&cli, command).await,
            Command::Cache(args) => cache_command(&cli, args).await,
            Command::Build(args) => build_command(&cli, args).await,
            Command::Dev(args) => dev_command(&cli, args).await,
        }
    }

    fn project_dir(&self) -> PathBuf {
        self.project_dir
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }

    fn service_config(&self) -> ServiceConfig {
        let mut config = ServiceConfig::new(self.project_dir());
        if let Some(state) = &self.state_dir {
            config = config.with_state_dir(state);
        }
        config
    }

    async fn service(&self) -> Result<Arc<InvocationService>> {
        let service = Arc::new(InvocationService::new(self.service_config()).await?);
        service.load_project().await?;
        Ok(service)
    }
}

fn print_or_json(json_mode: bool, value: serde_json::Value, human: impl FnOnce()) {
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
        );
    } else {
        human();
    }
}

/// Build the service configuration used by non-async commands.
fn scaffold(root: &Path, name: &str, template: Template, force: bool) -> std::io::Result<PathBuf> {
    let directory = root.join(name);
    if directory.exists() {
        if !force {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists", directory.display()),
            ));
        }
        std::fs::remove_dir_all(&directory)?;
    }
    std::fs::create_dir_all(&directory)?;
    write_template(&directory, name, template)?;
    Ok(directory)
}

fn write_template(directory: &Path, name: &str, template: Template) -> std::io::Result<()> {
    let manifest = format!(
        "name = \"{name}\"\nruntime = \"{}\"\nhandler = \"{}\"\n\n[build]\nsource = \".\"\n\n[resources]\nmemory = \"512MiB\"\ntimeout = \"30s\"\n\n[sandbox]\nkind = \"{}\"\n\n[environment]\n",
        template.runtime(),
        match template {
            Template::Node | Template::Echo => "index.handler",
            Template::Python => "main.handler",
            Template::Wasm => "main.wat.rustfun_handler",
            Template::Rust | Template::Executable => "./handler",
        },
        template.sandbox_kind(),
    );
    std::fs::write(directory.join("rustfun.toml"), manifest)?;

    match template {
        Template::Node => {
            std::fs::write(
                directory.join("index.js"),
                "// RustFun Node template. The handler receives (event, context).\nmodule.exports.handler = async (event, context) => {\n  return { message: `hello ${event.name ?? 'world'}`, function: context.functionName };\n};\n",
            )?;
            std::fs::write(
                directory.join("package.json"),
                "{\n  \"name\": \"rustfun-function\",\n  \"private\": true,\n  \"version\": \"0.0.0\"\n}\n",
            )?;
        }
        Template::Python => {
            std::fs::write(
                directory.join("main.py"),
                "\"\"\"RustFun Python template.\"\"\"\n\n\ndef handler(event, context=None):\n    name = (event or {}).get(\"name\", \"world\")\n    return {\"message\": f\"hello {name}\"}\n",
            )?;
        }
        Template::Rust => {
            std::fs::write(
                directory.join("Cargo.toml"),
                "[package]\nname = \"rustfun-function\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nrustfun-sdk = \"0.1\"\n\n[[bin]]\nname = \"handler\"\npath = \"src/main.rs\"\n",
            )?;
            std::fs::write(
                directory.join("src/main.rs"),
                "//! RustFun Rust template. Build with `cargo build --release` and point\n//! `[build] command` at the produced binary.\n\nfn main() {\n    println!(\"hello from rustfun\");\n}\n",
            )?;
        }
        Template::Wasm => {
            // The template is a WAT module so `rustfun init --template wasm` produces something
            // that runs immediately: wasmtime compiles text modules, and a real project swaps
            // this for the `.wasm` its toolchain emits.
            std::fs::write(
                directory.join("main.wat"),
                include_str!("templates/echo.wat"),
            )?;
            std::fs::write(
                directory.join("README.md"),
                "# RustFun Wasm function\n\n`main.wat` is the module RustFun runs. It is written in\nWebAssembly text format so it works without a toolchain; a real project would\npoint the handler at the `.wasm` its compiler emits.\n\nThe guest ABI is documented in\n`crates/rustfun-runtime/src/wasm/abi.rs`:\n\n- export `memory`,\n- export `rustfun_handler() -> i32` returning the length of a response frame,\n- optionally import `rustfun.payload` to learn where the request frame was written.\n\n```sh\nrustfun build hello-wasm\nrustfun function invoke hello-wasm --payload '{\"name\":\"world\"}'\n```\n",
            )?;
        }
        Template::Executable => {
            std::fs::write(
                directory.join("handler.sh"),
                "#!/usr/bin/env bash\n# A RustFun executable must speak the framed invocation protocol on stdio.\n# See crates/rustfun-test/src/fixtures/executable_handler.py for a reference.\necho \"this binary does not implement the invocation protocol yet\" >&2\nexit 70\n",
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let path = directory.join("handler.sh");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
            }
        }
        Template::Echo => {
            std::fs::write(
                directory.join("index.js"),
                "// The echo runtime answers with the payload it received.\nmodule.exports.handler = async (event) => event;\n",
            )?;
        }
    }
    Ok(())
}

fn init(json_mode: bool, args: InitArgs) -> Result<()> {
    let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let target = args.directory.clone().unwrap_or(root);
    let directory = scaffold(&target, &args.name, args.template, args.force).map_err(|error| {
        RustFunError::validation(format!("cannot scaffold '{}': {error}", args.name))
            .with_remediation("pass --force to overwrite an existing directory")
    })?;
    let value = json!({
        "created": directory.to_string_lossy(),
        "name": args.name,
        "template": format!("{:?}", args.template).to_lowercase(),
        "runtime": args.template.runtime(),
    });
    print_or_json(json_mode, value, || {
        println!(
            "created {} ({})",
            directory.display(),
            args.template.runtime()
        );
        println!(
            "next: cd {} && rustfun build {}",
            directory.display(),
            args.name
        );
    });
    Ok(())
}

async fn doctor(json_mode: bool) -> Result<()> {
    let registry = rustfun_runtime::default_registry();
    let sandbox = rustfun_sandbox::probe_sandbox();
    let discovered = registry.discover_all().await;

    let mut runtime_rows: Vec<serde_json::Value> = Vec::new();
    for (runtime, result) in discovered {
        match result {
            Ok(found) => {
                for installation in found {
                    runtime_rows.push(json!({
                        "runtime": runtime.to_string(),
                        "available": installation.available,
                        "executable": installation.executable,
                        "version": installation.reported_version,
                    }));
                }
            }
            Err(error) => runtime_rows.push(json!({
                "runtime": runtime.to_string(),
                "available": false,
                "error": error.to_string(),
            })),
        }
    }

    let state_dir = rustfun_invoke::default_state_dir();
    let cache_writable = {
        let probe = state_dir.join(".rustfun-doctor-probe");
        match std::fs::create_dir_all(&state_dir) {
            Ok(()) => match std::fs::write(&probe, b"probe") {
                Ok(()) => {
                    let _ = std::fs::remove_file(&probe);
                    true
                }
                Err(_) => false,
            },
            Err(_) => false,
        }
    };

    let value = json!({
        "version": rustfun_core::model::VERSION,
        "platform": sandbox.platform,
        "runtimes": runtime_rows,
        "sandbox": sandbox.probes,
        "state_dir": state_dir.to_string_lossy(),
        "cache_writable": cache_writable,
    });

    print_or_json(json_mode, value, || {
        println!("rustfun {}", rustfun_core::model::VERSION);
        println!("platform: {}", sandbox.summary());
        for probe in &sandbox.probes {
            println!(
                "  [{}] {} — {}{}",
                if probe.available { "ok" } else { "--" },
                probe.name,
                probe.detail,
                probe
                    .remediation
                    .as_ref()
                    .map(|hint| format!("\n      fix: {hint}"))
                    .unwrap_or_default()
            );
        }
        println!("state dir: {}", state_dir.display());
        println!(
            "cache: {}",
            if cache_writable {
                "writable"
            } else {
                "NOT writable"
            }
        );
        println!("runtimes:");
        for row in &runtime_rows {
            println!(
                "  [{}] {} {} ({})",
                if row["available"].as_bool().unwrap_or(false) {
                    "ok"
                } else {
                    "--"
                },
                row["runtime"].as_str().unwrap_or_default(),
                row["version"].as_str().unwrap_or("unknown"),
                row["executable"].as_str().unwrap_or_default()
            );
        }
    });
    Ok(())
}

async fn function_command(cli: &Cli, command: FunctionCommand) -> Result<()> {
    match command {
        FunctionCommand::Create { name } => {
            let service = cli.service().await?;
            let spec = service
                .function(&name)
                .map_err(|_| rustfun_invoke::function_not_found(&name))?;
            let built = service.build(&spec.id, false).await?;
            let value = json!({
                "name": spec.name.as_str(),
                "runtime": spec.runtime.to_string(),
                "digest": built.digest.to_string(),
                "file_count": built.file_count,
            });
            print_or_json(cli.json, value, || {
                println!("{} -> {}", spec.name, built.digest);
            });
            Ok(())
        }
        FunctionCommand::List => {
            let service = cli.service().await?;
            let functions: Vec<serde_json::Value> = service
                .manager()
                .list()
                .iter()
                .map(|spec| {
                    let artifact = service.manager().artifact_of(&spec.id);
                    json!({
                        "id": spec.id.to_string(),
                        "name": spec.name.as_str(),
                        "runtime": spec.runtime.to_string(),
                        "handler": spec.handler.as_str(),
                        "status": spec.status.as_str(),
                        "digest": artifact.map(|a| a.digest.to_string()),
                    })
                })
                .collect();
            print_or_json(cli.json, json!({ "functions": functions.clone() }), || {
                if functions.is_empty() {
                    println!("no functions found in {}", cli.project_dir().display());
                    return;
                }
                println!("{:<24} {:<14} {:<12} HANDLER", "NAME", "RUNTIME", "STATUS");
                for function in &functions {
                    println!(
                        "{:<24} {:<14} {:<12} {}",
                        function["name"].as_str().unwrap_or_default(),
                        function["runtime"].as_str().unwrap_or_default(),
                        function["status"].as_str().unwrap_or_default(),
                        function["handler"].as_str().unwrap_or_default(),
                    );
                }
            });
            Ok(())
        }
        FunctionCommand::Inspect { name } => {
            let service = cli.service().await?;
            let spec = service
                .function(&name)
                .map_err(|_| rustfun_invoke::function_not_found(&name))?;
            let artifact = service.manager().artifact_of(&spec.id);
            let value = json!({
                "id": spec.id.to_string(),
                "name": spec.name.as_str(),
                "runtime": spec.runtime.to_string(),
                "handler": spec.handler.as_str(),
                "status": spec.status.as_str(),
                "source": spec.source.describe(),
                "sandbox": spec.sandbox.kind.as_str(),
                "sandbox_is_security_boundary": spec.sandbox.is_secured(),
                "max_concurrency": spec.max_concurrency,
                "memory_bytes": spec.resources.memory_bytes,
                "timeout_ms": spec.resources.timeout.as_millis() as u64,
                "environment": spec.environment.redacted().iter().collect::<std::collections::BTreeMap<_, _>>(),
                "digest": artifact.as_ref().map(|a| a.digest.to_string()),
                "artifact_path": artifact.map(|a| a.path.to_string_lossy().into_owned()),
            });
            print_or_json(cli.json, value.clone(), || {
                println!("name:       {}", spec.name);
                println!("id:         {}", spec.id);
                println!("runtime:    {}", spec.runtime);
                println!("handler:    {}", spec.handler);
                println!("status:     {}", spec.status);
                println!("source:     {}", spec.source.describe());
                println!(
                    "sandbox:    {} ({})",
                    spec.sandbox.kind,
                    if spec.sandbox.is_secured() {
                        "security boundary"
                    } else {
                        "NOT a security boundary"
                    }
                );
                println!("memory:     {} bytes", spec.resources.memory_bytes);
                println!("timeout:    {} ms", spec.resources.timeout.as_millis());
                if let Some(digest) = value["digest"].as_str() {
                    println!("digest:     {digest}");
                }
            });
            Ok(())
        }
        FunctionCommand::Invoke(args) => invoke_function(cli, args).await,
        FunctionCommand::Destroy { name } => {
            let service = cli.service().await?;
            service.destroy(&name).await?;
            print_or_json(
                cli.json,
                json!({ "destroyed": name, "removed_manifest": false }),
                || {
                    println!(
                        "destroyed {name} (instances released; the manifest and sources are kept)"
                    );
                },
            );
            Ok(())
        }
    }
}

async fn invoke_function(cli: &Cli, args: InvokeArgs) -> Result<()> {
    let service = cli.service().await?;
    let payload = read_payload(&args)?;
    let timeout = args.timeout.map(Duration::from_millis);
    let response = service.invoke_by_name(&args.name, payload, timeout).await?;
    let result = decode_payload(&response.payload);
    let value = json!({
        "status": response.status.as_str(),
        "invocation_id": response.invocation_id.to_string(),
        "function_id": response.function_id.to_string(),
        "instance_id": response.instance_id.map(|id| id.to_string()),
        "duration_ms": response.duration_ms,
        "result": result,
        "error": response.error.as_ref().map(|error| json!({
            "code": error.code,
            "message": error.message,
            "detail": error.detail,
        })),
    });
    if args.raw {
        let rendered = serde_json::to_string_pretty(&result).unwrap_or_default();
        println!("{rendered}");
    } else {
        print_or_json(cli.json, value, || match response.status {
            InvocationStatus::Success => {
                println!(
                    "{} in {}ms",
                    serde_json::to_string_pretty(&result).unwrap_or_default(),
                    response.duration_ms
                );
            }
            _ => {
                if let Some(error) = &response.error {
                    eprintln!("[{}] {}", error.code, error.message);
                    if let Some(detail) = &error.detail {
                        eprintln!("{detail}");
                    }
                }
            }
        });
    }
    if response.status == InvocationStatus::Success {
        Ok(())
    } else {
        Err(RustFunError::function(format!(
            "invocation returned {}",
            response.status.as_str()
        )))
    }
}

fn read_payload(args: &InvokeArgs) -> Result<Vec<u8>> {
    if let Some(path) = &args.file {
        return std::fs::read(path).map_err(|error| {
            RustFunError::io(format!("cannot read {}: {error}", path.display()))
                .with_remediation("check the path passed to --file")
        });
    }
    match &args.payload {
        Some(text) => Ok(text.as_bytes().to_vec()),
        None => {
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                Ok(Vec::new())
            } else {
                use std::io::Read as _;
                let mut buffer = String::new();
                std::io::stdin()
                    .read_to_string(&mut buffer)
                    .map_err(RustFunError::from)?;
                Ok(buffer.into_bytes())
            }
        }
    }
}

fn decode_payload(payload: &[u8]) -> serde_json::Value {
    serde_json::from_slice(payload).unwrap_or_else(|_| {
        serde_json::Value::String(String::from_utf8_lossy(payload).into_owned())
    })
}

async fn runtime_command(cli: &Cli, command: RuntimeCommand) -> Result<()> {
    let registry = rustfun_runtime::default_registry();
    match command {
        RuntimeCommand::List => {
            let discovered = registry.discover_all().await;
            let mut rows = Vec::new();
            for (runtime, result) in discovered {
                match result {
                    Ok(found) => {
                        for installation in found {
                            rows.push(json!({
                                "runtime": runtime.to_string(),
                                "available": installation.available,
                                "version": installation.reported_version,
                                "executable": installation.executable,
                            }));
                        }
                    }
                    Err(error) => rows.push(json!({
                        "runtime": runtime.to_string(),
                        "available": false,
                        "error": error.to_string(),
                    })),
                }
            }
            print_or_json(cli.json, json!({ "runtimes": rows.clone() }), || {
                println!(
                    "{:<14} {:<10} {:<16} PATH",
                    "RUNTIME", "AVAILABLE", "VERSION"
                );
                for row in &rows {
                    println!(
                        "{:<14} {:<10} {:<16} {}",
                        row["runtime"].as_str().unwrap_or_default(),
                        if row["available"].as_bool().unwrap_or(false) {
                            "yes"
                        } else {
                            "no"
                        },
                        row["version"].as_str().unwrap_or("unknown"),
                        row["executable"].as_str().unwrap_or_default()
                    );
                }
            });
            Ok(())
        }
        RuntimeCommand::Inspect { name } => {
            let runtime = rustfun_core::RuntimeId::parse(&name)?;
            let found = registry.discover(&runtime).await?;
            let value = json!({
                "runtime": runtime.to_string(),
                "installations": found,
            });
            print_or_json(cli.json, value, || {
                println!("runtime: {runtime}");
                for installation in found {
                    println!(
                        "  {} ({})",
                        installation.executable,
                        installation
                            .reported_version
                            .unwrap_or_else(|| "unknown".into())
                    );
                }
            });
            Ok(())
        }
    }
}

async fn instance_command(cli: &Cli, command: InstanceCommand) -> Result<()> {
    match command {
        InstanceCommand::List => {
            let service = cli.service().await?;
            let instances = service.manager().instances().await;
            print_or_json(cli.json, json!({ "instances": instances.clone() }), || {
                if instances.is_empty() {
                    println!("no live instances");
                    return;
                }
                println!(
                    "{:<26} {:<14} {:<10} {:>6}",
                    "INSTANCE", "FUNCTION", "STATE", "CALLS"
                );
                for instance in &instances {
                    println!(
                        "{:<26} {:<14} {:<10} {:>6}",
                        instance.instance_id.to_string(),
                        instance.function_id.to_string(),
                        instance.state,
                        instance.invocation_count
                    );
                }
            });
            Ok(())
        }
    }
}

async fn cache_command(cli: &Cli, args: CacheArgs) -> Result<()> {
    let store =
        rustfun_artifact::FileArtifactStore::open(cli.service_config().state_dir.join("artifacts"))
            .await?;
    match args.command {
        CacheCommand::List => {
            let size = store.size_bytes().await?;
            let value = json!({ "root": store.root(), "size_bytes": size });
            print_or_json(cli.json, value, || {
                println!("cache: {}", store.root().display());
                println!("size:  {} bytes", size);
            });
            Ok(())
        }
        CacheCommand::Verify => {
            let mut verified = 0usize;
            let mut corrupted = 0usize;
            let mut pending = Vec::new();
            let Ok(buckets) = std::fs::read_dir(store.root().join("artifacts")) else {
                print_or_json(cli.json, json!({ "verified": 0, "corrupted": 0 }), || {
                    println!("the artifact cache is empty");
                });
                return Ok(());
            };
            for bucket in buckets.flatten() {
                let Ok(entries) = std::fs::read_dir(bucket.path()) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("json") {
                        continue;
                    }
                    let Ok(bytes) = std::fs::read(&path) else {
                        continue;
                    };
                    if let Ok(summary) =
                        serde_json::from_slice::<rustfun_core::ArtifactSummary>(&bytes)
                    {
                        pending.push(summary.digest);
                    }
                }
            }
            for digest in pending {
                match store.verify(&digest).await {
                    Ok(true) => verified += 1,
                    Ok(false) => corrupted += 1,
                    Err(error) => {
                        tracing::warn!(digest = %digest, error = %error, "verification failed")
                    }
                }
            }
            let value = json!({ "verified": verified, "corrupted": corrupted });
            print_or_json(cli.json, value, || {
                println!("verified:   {verified}");
                println!("corrupted:  {corrupted}");
            });
            Ok(())
        }
        CacheCommand::Clean { max_age } => {
            let removed = store.evict(Duration::from_secs(max_age)).await?;
            let value = json!({ "removed": removed });
            print_or_json(cli.json, value, || {
                println!("removed {removed} artifacts");
            });
            Ok(())
        }
    }
}

async fn build_command(cli: &Cli, args: BuildArgs) -> Result<()> {
    let service = cli.service().await?;
    let specs = match &args.name {
        Some(name) => vec![service.function(name)?],
        None => service.manager().list(),
    };
    let mut built = Vec::new();
    for spec in specs {
        match service.build(&spec.id, args.force).await {
            Ok(artifact) => built.push(json!({
                "name": spec.name.as_str(),
                "digest": artifact.digest.to_string(),
                "size_bytes": artifact.size_bytes,
                "file_count": artifact.file_count,
            })),
            Err(error) => {
                // One failing function must not hide the others.
                built.push(json!({
                    "name": spec.name.as_str(),
                    "error": error.to_string(),
                }));
            }
        }
    }
    let failed = built.iter().any(|entry| entry.get("error").is_some());
    print_or_json(cli.json, json!({ "artifacts": built.clone() }), || {
        for entry in &built {
            match entry.get("digest").and_then(|d| d.as_str()) {
                Some(digest) => println!(
                    "{:<24} {}",
                    entry["name"].as_str().unwrap_or_default(),
                    digest
                ),
                None => println!(
                    "{:<24} FAILED: {}",
                    entry["name"].as_str().unwrap_or_default(),
                    entry["error"].as_str().unwrap_or_default()
                ),
            }
        }
    });
    if failed {
        return Err(RustFunError::artifact(
            "one or more functions failed to build",
        ));
    }
    Ok(())
}

async fn dev_command(cli: &Cli, args: DevArgs) -> Result<()> {
    let service = cli.service().await?;
    if args.build {
        for spec in service.manager().list() {
            match service.build(&spec.id, false).await {
                Ok(artifact) => {
                    println!("built {} -> {}", spec.name, artifact.digest);
                }
                Err(error) => {
                    eprintln!("build failed for {}: {error}", spec.name);
                }
            }
        }
    }
    let address = format!("{}:{}", args.host, args.port)
        .parse()
        .map_err(|error| RustFunError::validation(format!("invalid listen address: {error}")))?;
    println!(
        "rustfun dev: {} function(s) registered",
        service.manager().len()
    );
    rustfun_http::serve(service, address).await
}

/// Entry point used by `main`.
pub async fn main() -> Result<()> {
    let cli = Cli::parse();
    // A CLI should be quiet unless the user asks for detail; `-v` raises the level.
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    rustfun_core::observability::init_tracing(level);
    Cli::run(cli).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn required_commands_exist() {
        let command = Cli::command();
        let names: Vec<String> = command
            .get_subcommands()
            .map(|s| s.get_name().to_owned())
            .collect();
        for expected in [
            "init", "doctor", "dev", "build", "cache", "function", "runtime", "instance", "version",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "missing {expected}"
            );
        }
    }

    #[test]
    fn function_subcommands_exist() {
        let command = Cli::command();
        let function = command
            .get_subcommands()
            .find(|sub| sub.get_name() == "function")
            .expect("function command");
        let names: Vec<String> = function
            .get_subcommands()
            .map(|s| s.get_name().to_owned())
            .collect();
        for expected in ["create", "list", "inspect", "invoke", "destroy"] {
            assert!(
                names.iter().any(|name| name == expected),
                "missing {expected}"
            );
        }
    }

    #[test]
    fn templates_map_to_runtimes() {
        assert_eq!(Template::Node.runtime(), "node@*");
        assert_eq!(Template::Python.runtime(), "python@*");
        assert_eq!(Template::Executable.runtime(), "executable@*");
    }

    #[test]
    fn init_scaffolds_a_working_function() {
        let root = std::env::temp_dir().join(format!(
            "rustfun-init-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).expect("creates");
        let directory = scaffold(&root, "hello", Template::Node, false).expect("scaffolds");
        assert!(directory.join("rustfun.toml").exists());
        assert!(directory.join("index.js").exists());

        let manifest =
            rustfun_config::Manifest::load(&directory.join("rustfun.toml")).expect("loads");
        assert_eq!(manifest.name, "hello");
        assert_eq!(manifest.runtime, "node@*");
        let spec = manifest.to_spec(&directory).expect("converts");
        assert!(spec.validate().is_ok());

        // Scaffolding twice without --force is refused.
        assert!(scaffold(&root, "hello", Template::Node, false).is_err());
        assert!(scaffold(&root, "hello", Template::Node, true).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn python_template_is_valid() {
        let root = std::env::temp_dir().join(format!("rustfun-init-py-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("creates");
        let directory = scaffold(&root, "pyfn", Template::Python, true).expect("scaffolds");
        let manifest =
            rustfun_config::Manifest::load(&directory.join("rustfun.toml")).expect("loads");
        let spec = manifest.to_spec(&directory).expect("converts");
        assert!(spec.validate().is_ok());
        assert_eq!(spec.handler.as_str(), "main.handler");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn payload_reading_prefers_explicit_input() {
        let args = InvokeArgs {
            name: "hello".to_owned(),
            payload: Some("{\"a\":1}".to_owned()),
            file: None,
            timeout: None,
            raw: false,
        };
        assert_eq!(read_payload(&args).expect("reads"), b"{\"a\":1}".to_vec());
    }

    #[test]
    fn payload_decoding_is_forgiving() {
        assert_eq!(decode_payload(b"{\"a\":1}")["a"], 1);
        assert!(decode_payload(b"not json").is_string());
    }
}
