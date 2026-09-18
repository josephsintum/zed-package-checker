//! The LSP surface.
//!
//! Zed extensions cannot publish diagnostics — only a language server can — so
//! this is the whole reason the server exists. It handles the six methods the
//! Go server handles and nothing else; `tower-lsp-server` answers anything else
//! with "method not found".

use crate::config::Config;
use crate::diagnostics;
use crate::engine::{Engine, Publisher, Reason, Requester};
use crate::model::Finding;
use crate::span::Encoding;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use tower_lsp_server::jsonrpc::Result;
use tower_lsp_server::ls_types::*;
use tower_lsp_server::{Client, LanguageServer};

/// The files worth watching. One list, so the watcher globs and the "is this a
/// manifest" test can never disagree — they did, in the Go server, while they
/// were maintained separately.
///
/// Deliberately wider than the set `extract` can parse: a `yarn.lock` or
/// `go.sum` changing means the project's dependencies changed, which is worth a
/// rescan even though the dependencies themselves are read from the manifest
/// beside it. The containment that *must* hold is the other direction — every
/// file a parser reads has to be watched, or editing it changes nothing — and
/// `every_parsed_manifest_is_watched` holds it.
const MANIFESTS: &[&str] = &[
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "go.mod",
    "go.sum",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "Cargo.toml",
    "Cargo.lock",
];

fn is_manifest(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    MANIFESTS.contains(&name) || (name.starts_with("requirements") && name.ends_with(".txt"))
}

fn watched_globs() -> Vec<FileSystemWatcher> {
    MANIFESTS
        .iter()
        .map(|name| format!("**/{name}"))
        .chain(std::iter::once("**/requirements*.txt".to_owned()))
        .map(|pattern| FileSystemWatcher {
            glob_pattern: GlobPattern::String(pattern),
            kind: None,
        })
        .collect()
}

/// Builds the scanner once the workspace root is known, which is not until
/// `initialize`.
/// Builds the scanner once the root is known, handed the live configuration so
/// a `didChangeConfiguration` reaches it without rebuilding anything.
type BuildScanner =
    dyn Fn(&Path, Requester, Arc<ArcSwap<Config>>) -> Arc<dyn crate::engine::Scanner> + Send + Sync;

/// Sends diagnostics to the client from whatever task produced them.
struct ClientPublisher {
    client: Client,
    utf16: Arc<AtomicBool>,
}

impl Publisher for ClientPublisher {
    fn publish(&self, path: PathBuf, findings: Vec<Finding>) {
        let Some(uri) = diagnostics::file_uri(&path) else {
            return;
        };
        let encoding = if self.utf16.load(Ordering::Relaxed) {
            Encoding::Utf16
        } else {
            Encoding::Utf8
        };
        // Rendering reads the manifest from disk, so it happens off the runtime.
        let client = self.client.clone();
        tokio::spawn(async move {
            let rendered = tokio::task::spawn_blocking(move || {
                diagnostics::for_file(&path, &findings, encoding)
            })
            .await
            .unwrap_or_default();
            client.publish_diagnostics(uri, rendered, None).await;
        });
    }

    fn notice(&self, message: String) {
        // Shown rather than logged: these are the two things a user cannot
        // work out from an empty diagnostics panel — that something left the
        // machine, and that nothing has been checked yet.
        let client = self.client.clone();
        tokio::spawn(async move {
            client.show_message(MessageType::INFO, message).await;
        });
    }
}

pub struct Backend {
    client: Client,
    version: String,
    root: OnceLock<PathBuf>,
    engine: OnceLock<Engine>,
    /// Written once during `initialize`, read from every publishing task. Since
    /// the extractors emit byte columns, this decides whether they are correct.
    utf16: Arc<AtomicBool>,
    /// Swapped wholesale on `didChangeConfiguration`; the scanner holds the
    /// same handle, so a change takes effect on the next scan with no restart.
    config: Arc<ArcSwap<Config>>,
    build: Box<BuildScanner>,
}

impl Backend {
    /// `build` makes the scanner once the workspace root is known, which is not
    /// until `initialize`.
    pub fn new(
        client: Client,
        version: String,
        build: impl Fn(&Path, Requester, Arc<ArcSwap<Config>>) -> Arc<dyn crate::engine::Scanner>
        + Send
        + Sync
        + 'static,
    ) -> Backend {
        Backend {
            client,
            version,
            root: OnceLock::new(),
            engine: OnceLock::new(),
            utf16: Arc::new(AtomicBool::new(false)),
            config: Arc::new(ArcSwap::from_pointee(Config::default())),
            build: Box::new(build),
        }
    }

    fn engine(&self) -> Option<&Engine> {
        self.engine.get()
    }
}

impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        let root = params
            .workspace_folders
            .as_ref()
            .and_then(|folders| folders.first())
            .map(|folder| folder.uri.clone())
            .or_else(|| {
                #[allow(deprecated)]
                params.root_uri.clone()
            })
            .as_ref()
            .and_then(uri_to_path);

        let Some(root) = root else {
            return Err(tower_lsp_server::jsonrpc::Error::invalid_params(
                "no workspace folder or rootUri",
            ));
        };

        // Prefer UTF-8: the extractors produce byte columns, so accepting it
        // removes a conversion rather than adding one.
        let encoding = params
            .capabilities
            .general
            .as_ref()
            .and_then(|g| g.position_encodings.as_ref())
            .filter(|encodings| encodings.contains(&PositionEncodingKind::UTF8))
            .map(|_| PositionEncodingKind::UTF8)
            .unwrap_or(PositionEncodingKind::UTF16);
        self.utf16
            .store(encoding == PositionEncodingKind::UTF16, Ordering::Relaxed);

        // Read before the scanner is built, so the first scan already has it.
        self.config.store(Arc::new(Config::from_options(
            params.initialization_options.as_ref(),
        )));

        let (requester, pending) = Engine::pending();
        let scanner = (self.build)(&root, requester, Arc::clone(&self.config));
        let publisher = Arc::new(ClientPublisher {
            client: self.client.clone(),
            utf16: Arc::clone(&self.utf16),
        });
        let _ = self.engine.set(pending.start(
            root.clone(),
            scanner,
            publisher,
            crate::engine::DEFAULT_DEBOUNCE,
        ));
        let _ = self.root.set(root);

        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: diagnostics::name().to_owned(),
                // Which implementation, not just which version: two servers can
                // run side by side and a stale binary on PATH is otherwise
                // indistinguishable from the one you meant to test.
                version: Some(format!("{} (rust)", self.version)),
            }),
            // A clangd extension this server does not implement; the
            // negotiated encoding is advertised in `capabilities` instead.
            offset_encoding: None,
            capabilities: ServerCapabilities {
                position_encoding: Some(encoding),
                // No document content is ever needed: manifests are read from
                // disk, never from the buffer.
                text_document_sync: Some(TextDocumentSyncCapability::Options(
                    TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(TextDocumentSyncKind::NONE),
                        save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                            include_text: Some(false),
                        })),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        let registration = Registration {
            id: "package-checker-watch-manifests".to_owned(),
            method: "workspace/didChangeWatchedFiles".to_owned(),
            register_options: serde_json::to_value(DidChangeWatchedFilesRegistrationOptions {
                watchers: watched_globs(),
            })
            .ok(),
        };
        // A failure here is not fatal: `didSave` is the documented fallback for
        // clients whose watchers are unreliable, such as over SSH.
        if let Err(error) = self.client.register_capability(vec![registration]).await {
            tracing::warn!(%error, "file watchers were not registered; falling back to didSave");
        }
        if let Some(engine) = self.engine() {
            engine.request(Reason::Startup);
        }
    }

    async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
        // Zed nests the server's settings under its own key; accept either
        // shape rather than guessing which client is talking.
        let settings = params
            .settings
            .get("package-checker")
            .unwrap_or(&params.settings);
        let config = Config::from_options(Some(settings));

        if *self.config.load_full() == config {
            return;
        }
        tracing::info!(
            online = config.online.enabled,
            offline = config.offline,
            "configuration changed"
        );
        self.config.store(Arc::new(config));

        // The previous answers were computed under the old configuration.
        if let Some(engine) = self.engine() {
            engine.request(Reason::Manual);
        }
    }

    async fn did_change_watched_files(&self, params: DidChangeWatchedFilesParams) {
        let Some(engine) = self.engine() else { return };
        for change in &params.changes {
            if change.typ == FileChangeType::DELETED
                && let Some(path) = uri_to_path(&change.uri)
            {
                // Clear immediately: a deleted manifest's diagnostics are wrong
                // the moment it goes, not a second later.
                engine.clear(path);
            }
        }
        engine.request(Reason::FileChanged);
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let Some(path) = uri_to_path(&params.text_document.uri) else {
            return;
        };
        if is_manifest(&path)
            && let Some(engine) = self.engine()
        {
            engine.request(Reason::FileSaved);
        }
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        // Re-publish what is already known, and never scan. Zed shows
        // diagnostics for files that were never opened, so this is insurance
        // rather than the mechanism.
        let Some(path) = uri_to_path(&params.text_document.uri) else {
            return;
        };
        let Some(engine) = self.engine() else { return };
        let findings = engine.findings(path.clone()).await;
        if findings.is_empty() {
            return;
        }
        let encoding = if self.utf16.load(Ordering::Relaxed) {
            Encoding::Utf16
        } else {
            Encoding::Utf8
        };
        if let Some(uri) = diagnostics::file_uri(&path) {
            let rendered = diagnostics::for_file(&path, &findings, encoding);
            self.client.publish_diagnostics(uri, rendered, None).await;
        }
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

/// A `file:` URI as a path.
///
/// Only percent-escapes are decoded; a URI naming anything but a local file is
/// not something this server can scan.
pub fn uri_to_path(uri: &Uri) -> Option<PathBuf> {
    let text = uri.as_str();
    let rest = text.strip_prefix("file://")?;
    // A Windows URI carries a leading slash before the drive letter.
    let rest = match rest.strip_prefix('/') {
        Some(tail) if cfg!(windows) && tail.as_bytes().get(1) == Some(&b':') => tail,
        _ => rest,
    };
    Some(PathBuf::from(percent_decode(rest)))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = s.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_parsed_manifest_is_watched() {
        // The direction that matters: a file some parser reads but nothing
        // watches would never trigger a rescan when the user edited it.
        for name in [
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "go.mod",
            "Cargo.toml",
            "Cargo.lock",
            "requirements.txt",
            "requirements-dev.txt",
        ] {
            assert!(
                crate::is_manifest_name(name),
                "{name:?} is in this list but no parser reads it"
            );
            assert!(
                is_manifest(Path::new(name)),
                "{name:?} is parsed but not watched, so editing it would change nothing"
            );
        }
    }

    #[test]
    fn manifests_and_watcher_globs_agree() {
        for watcher in watched_globs() {
            let GlobPattern::String(pattern) = watcher.glob_pattern else {
                panic!("globs are plain patterns")
            };
            let name = pattern.trim_start_matches("**/");
            // The wildcard pattern stands for the requirements files.
            let sample = name.replace('*', "-dev");
            assert!(
                is_manifest(Path::new(&sample)),
                "{sample:?} is watched but not recognised as a manifest"
            );
        }
    }

    #[test]
    fn uris_become_paths() {
        let uri: Uri = "file:///Users/me/my%20project/package.json"
            .parse()
            .unwrap();
        assert_eq!(
            uri_to_path(&uri).unwrap(),
            PathBuf::from("/Users/me/my project/package.json")
        );
        let http: Uri = "http://example.com/package.json".parse().unwrap();
        assert!(uri_to_path(&http).is_none());
    }

    #[test]
    fn only_manifests_trigger_a_scan_on_save() {
        assert!(is_manifest(Path::new("/p/package.json")));
        assert!(is_manifest(Path::new("/p/requirements-dev.txt")));
        assert!(!is_manifest(Path::new("/p/index.js")));
        assert!(!is_manifest(Path::new("/p/requirements.md")));
    }
}
