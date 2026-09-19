//! The LSP surface.
//!
//! Zed extensions cannot publish diagnostics — only a language server can — so
//! this is the whole reason the server exists. It handles the lifecycle and
//! synchronisation methods, plus `textDocument/codeAction` for the upgrade
//! quick fix; `tower-lsp-server` answers anything else with "method not found".

use crate::action;
use crate::config::Config;
use crate::diagnostics;
use crate::engine::{Engine, Publisher, Reason, Requester};
use crate::model::Finding;
use crate::span::Encoding;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use arc_swap::ArcSwap;
use tower_lsp_server::jsonrpc::Result;
use tower_lsp_server::ls_types::*;
use tower_lsp_server::{Client, LanguageServer};

/// The files worth watching. One list, so the watcher globs and the "is this a
/// manifest" test can never disagree, which two separately maintained lists
/// eventually do.
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
    /// Open manifests, by path, as the editor has them — text and the version
    /// the client last reported.
    ///
    /// Scanning still reads from disk; this exists only so a code action edits
    /// the buffer the user is looking at. A span computed from disk against a
    /// buffer with unsaved edits would rewrite the wrong bytes.
    open: Mutex<HashMap<PathBuf, (i32, String)>>,
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
            open: Mutex::new(HashMap::new()),
        }
    }

    fn engine(&self) -> Option<&Engine> {
        self.engine.get()
    }

    fn encoding(&self) -> Encoding {
        if self.utf16.load(Ordering::Relaxed) {
            Encoding::Utf16
        } else {
            Encoding::Utf8
        }
    }

    /// A manifest's text as the editor has it, falling back to disk.
    ///
    /// The version is `Some` only for a tracked buffer, and rides on the edit
    /// so a client that has moved on rejects it instead of applying it blind.
    fn source(&self, path: &Path) -> Option<(Option<i32>, String)> {
        if let Ok(open) = self.open.lock()
            && let Some((version, text)) = open.get(path)
        {
            return Some((Some(*version), text.clone()));
        }
        crate::read::manifest(path).map(|text| (None, text))
    }

    /// Records an open manifest's text, ignoring anything over the read cap.
    ///
    /// Narrower than `is_manifest`: a `yarn.lock` changing is worth a rescan,
    /// but no parser reads one, so holding its text would buy nothing.
    fn track(&self, path: &Path, version: i32, text: String) {
        let parseable = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(crate::extract::is_manifest_name);
        if !parseable {
            return;
        }
        let Ok(mut open) = self.open.lock() else {
            return;
        };
        if text.len() as u64 > crate::read::MAX_MANIFEST_BYTES {
            // Too large to index: `LineIndex` offsets are `u32`. Forgetting it
            // falls back to the disk read, which applies the same cap.
            open.remove(path);
            return;
        }
        open.insert(path.to_path_buf(), (version, text));
    }
}

/// The workspace to scan: the first workspace folder, or the deprecated
/// `rootUri` from a client that still sends only that.
fn workspace_root(params: &InitializeParams) -> Option<PathBuf> {
    params
        .workspace_folders
        .as_ref()
        .and_then(|folders| folders.first())
        .map(|folder| folder.uri.clone())
        .or_else(|| {
            #[allow(deprecated)]
            params.root_uri.clone()
        })
        .as_ref()
        .and_then(uri_to_path)
}

/// Prefers UTF-8: the extractors produce byte columns, so accepting it removes
/// a conversion rather than adding one. UTF-16 is the protocol's default and
/// the only encoding a client is obliged to support.
fn negotiate_encoding(params: &InitializeParams) -> PositionEncodingKind {
    params
        .capabilities
        .general
        .as_ref()
        .and_then(|g| g.position_encodings.as_ref())
        .filter(|encodings| encodings.contains(&PositionEncodingKind::UTF8))
        .map(|_| PositionEncodingKind::UTF8)
        .unwrap_or(PositionEncodingKind::UTF16)
}

impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        let Some(root) = workspace_root(&params) else {
            return Err(tower_lsp_server::jsonrpc::Error::invalid_params(
                "no workspace folder or rootUri",
            ));
        };

        let encoding = negotiate_encoding(&params);
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
                name: crate::config::NAME.to_owned(),
                version: Some(self.version.clone()),
            }),
            // A clangd extension this server does not implement; the
            // negotiated encoding is advertised in `capabilities` instead.
            offset_encoding: None,
            capabilities: ServerCapabilities {
                position_encoding: Some(encoding),
                // Scanning reads manifests from disk. The buffer is tracked
                // only so a quick fix edits what the user is looking at rather
                // than what was last saved; `track` keeps anything but a
                // manifest out of memory.
                text_document_sync: Some(TextDocumentSyncCapability::Options(
                    TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(TextDocumentSyncKind::FULL),
                        save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                            include_text: Some(false),
                        })),
                        ..Default::default()
                    },
                )),
                code_action_provider: Some(CodeActionProviderCapability::Options(
                    CodeActionOptions {
                        code_action_kinds: Some(vec![CodeActionKind::QUICKFIX]),
                        // The edit is one parse of one already-open file, so
                        // there is nothing worth deferring to a resolve.
                        resolve_provider: Some(false),
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
        self.track(
            &path,
            params.text_document.version,
            params.text_document.text,
        );
        let Some(engine) = self.engine() else { return };
        let findings = engine.findings(path.clone()).await;
        if findings.is_empty() {
            return;
        }
        if let Some(uri) = diagnostics::file_uri(&path) {
            let rendered = diagnostics::for_file(&path, &findings, self.encoding());
            self.client.publish_diagnostics(uri, rendered, None).await;
        }
    }

    /// Full sync: the last change carries the whole document.
    ///
    /// No scan is triggered — a manifest mid-edit is usually not valid, and
    /// `didSave` and the watcher already cover the real thing.
    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let Some(path) = uri_to_path(&params.text_document.uri) else {
            return;
        };
        let Some(change) = params.content_changes.into_iter().next_back() else {
            return;
        };
        self.track(&path, params.text_document.version, change.text);
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let Some(path) = uri_to_path(&params.text_document.uri) else {
            return;
        };
        if let Ok(mut open) = self.open.lock() {
            open.remove(&path);
        }
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let Some(path) = uri_to_path(&params.text_document.uri) else {
            return Ok(None);
        };
        let Some(engine) = self.engine() else {
            return Ok(None);
        };
        let findings = engine.findings(path.clone()).await;
        if findings.is_empty() {
            return Ok(None);
        }
        let Some((version, source)) = self.source(&path) else {
            return Ok(None);
        };
        let actions =
            action::upgrades(&path, &source, version, &findings, &params, self.encoding());
        Ok((!actions.is_empty()).then_some(actions))
    }

    async fn shutdown(&self) -> Result<()> {
        if let Some(engine) = self.engine() {
            engine.stop_background();
        }
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

    fn folder(path: &str) -> WorkspaceFolder {
        WorkspaceFolder {
            uri: format!("file://{path}").parse().unwrap(),
            name: String::new(),
        }
    }

    #[test]
    fn the_workspace_root_prefers_folders_over_root_uri() {
        #[allow(deprecated)]
        let params = InitializeParams {
            workspace_folders: Some(vec![folder("/from/folder")]),
            root_uri: Some("file:///from/rooturi".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(workspace_root(&params), Some(PathBuf::from("/from/folder")));

        #[allow(deprecated)]
        let only_root = InitializeParams {
            root_uri: Some("file:///from/rooturi".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(
            workspace_root(&only_root),
            Some(PathBuf::from("/from/rooturi"))
        );
        assert_eq!(workspace_root(&InitializeParams::default()), None);
    }

    #[test]
    fn utf8_is_taken_when_offered_and_utf16_otherwise() {
        let with = |encodings: Option<Vec<PositionEncodingKind>>| InitializeParams {
            capabilities: ClientCapabilities {
                general: encodings.map(|position_encodings| GeneralClientCapabilities {
                    position_encodings: Some(position_encodings),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            negotiate_encoding(&with(Some(vec![
                PositionEncodingKind::UTF16,
                PositionEncodingKind::UTF8
            ]))),
            PositionEncodingKind::UTF8
        );
        assert_eq!(
            negotiate_encoding(&with(Some(vec![]))),
            PositionEncodingKind::UTF16
        );
        // A minimal client may omit "general" entirely.
        assert_eq!(negotiate_encoding(&with(None)), PositionEncodingKind::UTF16);
    }

    /// A scanner that reports one finding on the root's package.json and
    /// counts how often it was asked.
    struct OneFinding(std::sync::atomic::AtomicUsize);

    impl crate::engine::Scanner for Arc<OneFinding> {
        fn scan(&self, root: &Path) -> anyhow::Result<crate::model::Report> {
            self.0.fetch_add(1, Ordering::SeqCst);
            let finding = Finding {
                package: crate::model::Package::new(
                    crate::model::Ecosystem::Npm,
                    "lodash",
                    "4.17.15",
                ),
                advisories: vec![Arc::new(crate::model::Advisory {
                    id: "GHSA-1".into(),
                    aliases: Box::default(),
                    summary: Box::default(),
                    cvss_score: 7.5,
                    cvss_vector: Box::default(),
                    affected: Box::default(),
                    references: Box::default(),
                })],
                evidence: crate::model::Site::new(
                    root.join("package.json"),
                    crate::model::Range::whole_line(1),
                ),
                declared: None,
                paths: Vec::new(),
                reachable: None,
                from_range: false,
                dep_groups: Vec::new(),
                fix: crate::model::Fix::None,
            };
            Ok(crate::model::Report::new(root, vec![finding]))
        }
    }

    /// An initialised server over a fake editor, with a startup scan pending.
    async fn initialised(
        root: &Path,
    ) -> (
        tower_lsp_server::LspService<Backend>,
        crate::testing::FakeClient,
        Arc<OneFinding>,
    ) {
        let scanner = Arc::new(OneFinding(std::sync::atomic::AtomicUsize::new(0)));
        let for_build = Arc::clone(&scanner);
        let (mut service, client) = crate::testing::FakeClient::serve(|client| {
            Backend::new(client, "test".into(), move |_, _, _| {
                Arc::new(Arc::clone(&for_build)) as Arc<dyn crate::engine::Scanner>
            })
        });
        let params = InitializeParams {
            workspace_folders: Some(vec![folder(root.to_str().unwrap())]),
            ..Default::default()
        };
        let response = crate::testing::FakeClient::call(&mut service, "initialize", 1, params)
            .await
            .expect("initialize answers");
        assert!(response.is_ok(), "{response:?}");
        crate::testing::FakeClient::notify(&mut service, "initialized", InitializedParams {}).await;
        (service, client, scanner)
    }

    #[tokio::test]
    async fn initialize_without_a_root_is_refused() {
        let (mut service, _client) = crate::testing::FakeClient::serve(|client| {
            Backend::new(client, "test".into(), |_, _, _| {
                unreachable!("no root, no scanner")
            })
        });
        let response = crate::testing::FakeClient::call(
            &mut service,
            "initialize",
            1,
            InitializeParams::default(),
        )
        .await
        .expect("initialize answers");
        assert!(response.is_error(), "{response:?}");
    }

    #[tokio::test]
    async fn initialized_registers_watchers_and_requests_a_scan() {
        let root = tempfile::tempdir().unwrap();
        let (_service, client, scanner) = initialised(root.path()).await;

        assert!(
            client
                .wait_until(|r| r.iter().any(|(m, _)| m == "client/registerCapability"))
                .await
        );
        let registration = client.params_of("client/registerCapability").remove(0);
        assert_eq!(
            registration["registrations"][0]["method"],
            "workspace/didChangeWatchedFiles"
        );
        // The startup scan follows the debounce, and publishes.
        assert!(
            client
                .wait_until(|r| r
                    .iter()
                    .any(|(m, _)| m == "textDocument/publishDiagnostics"))
                .await,
            "no diagnostics were published after initialized"
        );
        assert_eq!(scanner.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn did_open_republishes_without_scanning() {
        let root = tempfile::tempdir().unwrap();
        let (mut service, client, scanner) = initialised(root.path()).await;
        assert!(
            client
                .wait_until(|r| r
                    .iter()
                    .any(|(m, _)| m == "textDocument/publishDiagnostics"))
                .await
        );
        let before = client.count("textDocument/publishDiagnostics");

        let manifest = root.path().join("package.json");
        crate::testing::FakeClient::notify(
            &mut service,
            "textDocument/didOpen",
            DidOpenTextDocumentParams {
                text_document: TextDocumentItem {
                    uri: diagnostics::file_uri(&manifest).unwrap(),
                    language_id: "json".into(),
                    version: 1,
                    text: "{}".into(),
                },
            },
        )
        .await;

        assert!(
            client
                .wait_until(|r| {
                    r.iter()
                        .filter(|(m, _)| m == "textDocument/publishDiagnostics")
                        .count()
                        > before
                })
                .await,
            "didOpen did not republish"
        );
        let published = client
            .params_of("textDocument/publishDiagnostics")
            .pop()
            .unwrap();
        assert_eq!(published["diagnostics"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            scanner.0.load(Ordering::SeqCst),
            1,
            "didOpen must never scan"
        );
    }
}
