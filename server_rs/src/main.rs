//! The language server binary.
//!
//! Flag parsing, wiring and shutdown only — everything it composes lives in the
//! library, so the same pieces can be driven by the benchmarks and the tests.

use package_checker::{
    Backend, Database, Extractor, Requester, Scanner, WorkspaceScanner, default_root,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::Handle;
use tower_lsp_server::{LspService, Server};

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Options {
    /// Renames the server in its diagnostics, so two can run side by side and
    /// be told apart. Testing scaffolding, not a setting.
    label: Option<String>,
    log_file: Option<PathBuf>,
    debug: bool,
    db_root: Option<PathBuf>,
}

fn parse_args() -> Result<Options, String> {
    let mut options = Options {
        label: None,
        log_file: None,
        debug: false,
        db_root: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-version" | "--version" => {
                println!("package-checker-lsp {VERSION}");
                std::process::exit(0);
            }
            "-log" | "--log" => options.log_file = args.next().map(Into::into),
            "-debug" | "--debug" => options.debug = true,
            "-db-root" | "--db-root" => options.db_root = args.next().map(Into::into),
            "-label" | "--label" => options.label = args.next(),
            // Zed passes this; the server speaks stdio and nothing else.
            "-stdio" | "--stdio" => {}
            other => return Err(format!("unrecognised argument {other:?}")),
        }
    }
    Ok(options)
}

#[tokio::main]
async fn main() {
    let options = match parse_args() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("package-checker-lsp: {error}");
            std::process::exit(2);
        }
    };

    if let Some(label) = options.label {
        package_checker::set_label(label);
    }

    // Never stdout: that is the JSON-RPC stream.
    let level = if options.debug { "debug" } else { "info" };
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| level.into()),
        );
    match options.log_file.as_ref().and_then(|path| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
    }) {
        Some(file) => subscriber.with_writer(std::sync::Mutex::new(file)).init(),
        None => subscriber.init(),
    }

    let Some(root) = options.db_root.or_else(default_root) else {
        eprintln!("package-checker-lsp: no cache directory for this platform");
        std::process::exit(1);
    };
    let (service, socket) = LspService::new(move |client| {
        // Built here rather than above because progress needs the client, and
        // the client does not exist until this closure runs.
        let database = Arc::new(Database::new(root).with_progress(Box::new(
            package_checker::ClientProgress::new(client.clone(), Handle::current()),
        )));
        Backend::new(
            client,
            VERSION.to_owned(),
            move |_root, requester: Requester, config| {
                let database = Arc::clone(&database);
                let scanner = WorkspaceScanner::new(Extractor::new(), database, move || {
                    // The archives just landed; the scan that was refused can run.
                    requester.request(package_checker::Reason::DatabaseSync);
                })
                .with_config(config);
                Arc::new(scanner) as Arc<dyn Scanner>
            },
        )
    });

    Server::new(tokio::io::stdin(), tokio::io::stdout(), socket)
        .serve(service)
        .await;
}
