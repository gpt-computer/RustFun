//! `rustfun` binary entry point.

fn main() -> std::process::ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("[RUSTFUN_INTERNAL_ERROR] cannot start the async runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(rustfun_cli::main()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error.to_human_string());
            std::process::ExitCode::FAILURE
        }
    }
}
