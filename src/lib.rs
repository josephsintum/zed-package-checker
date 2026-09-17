//! Zed extension shim for the package-checker language server.
//!
//! Zed extensions compile to WebAssembly and cannot publish diagnostics
//! themselves — only a language server can. So this shim does one job: work out
//! where the `package-checker-lsp` binary is and tell Zed how to launch it.
//!
//! At this stage the binary must already be present, either on `$PATH` or named
//! explicitly in settings. Downloading it from GitHub releases comes later; that
//! keeps the first working version free of any network dependency.

use zed_extension_api::{self as zed, settings::LspSettings, Command, LanguageServerId, Result};

/// Name of the language server executable, as found on `$PATH`.
const BINARY_NAME: &str = "package-checker-lsp";

/// Server id as declared in `extension.toml`. Zed keys LSP settings by this,
/// not by the executable name, so the two must not be conflated.
const SERVER_ID: &str = "package-checker";

struct PackageCheckerExtension;

impl zed::Extension for PackageCheckerExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<Command> {
        let path = resolve_binary(language_server_id, worktree)?;

        Ok(Command {
            command: path,
            args: vec!["--stdio".into()],
            // The server may shell out to language toolchains (`go` for
            // reachability analysis). A GUI-launched Zed has a minimal PATH, so
            // hand it the user's real shell environment.
            env: worktree.shell_env(),
        })
    }
}

/// Finds the language server binary.
///
/// Resolution order, most specific first:
///   1. `binary.path` in the user's LSP settings — the override used during
///      development, and the escape hatch for a non-standard install.
///   2. `$PATH`, via the worktree's shell environment.
fn resolve_binary(
    language_server_id: &LanguageServerId,
    worktree: &zed::Worktree,
) -> Result<String> {
    if let Ok(settings) = LspSettings::for_worktree(SERVER_ID, worktree) {
        if let Some(binary) = settings.binary {
            if let Some(path) = binary.path {
                return Ok(path);
            }
        }
    }

    if let Some(path) = worktree.which(BINARY_NAME) {
        return Ok(path);
    }

    zed::set_language_server_installation_status(
        language_server_id,
        &zed::LanguageServerInstallationStatus::Failed(format!("{BINARY_NAME} not found")),
    );

    Err(format!(
        "{BINARY_NAME} was not found on $PATH.\n\
         Build it with `make server` and either put it on your PATH, or point at it \
         directly in your Zed settings:\n\
         \n\
         \"lsp\": {{ \"{SERVER_ID}\": {{ \"binary\": {{ \"path\": \"/abs/path/to/{BINARY_NAME}\" }} }} }}"
    ))
}

zed::register_extension!(PackageCheckerExtension);
