//! Telling the editor that a download is happening.
//!
//! The database reports its progress through [`crate::db::Progress`], which is
//! synchronous and called from the plain thread doing the downloading. LSP
//! progress is asynchronous and strictly ordered — create, begin, report…,
//! end — so each ecosystem gets a task fed by a channel rather than a spawn per
//! callback, which could deliver a report before its begin.

use crate::db::Progress;
use crate::model::Ecosystem;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::runtime::Handle;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{
    NumberOrString, ProgressParams, ProgressParamsValue, WorkDoneProgress, WorkDoneProgressBegin,
    WorkDoneProgressCreateParams, WorkDoneProgressEnd, WorkDoneProgressReport,
};

/// One step in an ecosystem's download.
enum Step {
    Advance { downloaded: u64, total: Option<u64> },
    Done(Option<String>),
}

pub struct ClientProgress {
    client: Client,
    /// Captured at construction: the callbacks arrive on a thread with no
    /// runtime of its own.
    handle: Handle,
    senders: Mutex<HashMap<Ecosystem, UnboundedSender<Step>>>,
}

impl ClientProgress {
    pub fn new(client: Client, handle: Handle) -> ClientProgress {
        ClientProgress {
            client,
            handle,
            senders: Mutex::new(HashMap::new()),
        }
    }

    fn send(&self, ecosystem: Ecosystem, step: Step) {
        if let Ok(senders) = self.senders.lock()
            && let Some(sender) = senders.get(&ecosystem)
        {
            let _ = sender.send(step);
        }
    }
}

impl Progress for ClientProgress {
    fn start(&self, ecosystem: Ecosystem, total: Option<u64>) {
        let (sender, mut steps) = unbounded_channel();
        if let Ok(mut senders) = self.senders.lock() {
            senders.insert(ecosystem, sender);
        }

        let client = self.client.clone();
        self.handle.spawn(async move {
            // One token per ecosystem, so four concurrent downloads do not
            // overwrite each other's bar.
            let token = NumberOrString::String(format!("package-checker/{ecosystem}"));
            if client
                .send_request::<tower_lsp_server::ls_types::request::WorkDoneProgressCreate>(
                    WorkDoneProgressCreateParams {
                        token: token.clone(),
                    },
                )
                .await
                .is_err()
            {
                // A client that does not do progress is not an error; it just
                // gets no bar. Draining keeps the sender from erroring.
                while steps.recv().await.is_some() {}
                return;
            }

            let report = |value| ProgressParams {
                token: token.clone(),
                value: ProgressParamsValue::WorkDone(value),
            };
            client
                .send_notification::<tower_lsp_server::ls_types::notification::Progress>(report(
                    WorkDoneProgress::Begin(WorkDoneProgressBegin {
                        title: format!("Downloading {ecosystem} advisories"),
                        percentage: total.map(|_| 0),
                        ..Default::default()
                    }),
                ))
                .await;

            while let Some(step) = steps.recv().await {
                match step {
                    Step::Advance { downloaded, total } => {
                        client
                            .send_notification::<tower_lsp_server::ls_types::notification::Progress>(
                                report(WorkDoneProgress::Report(WorkDoneProgressReport {
                                    percentage: percentage(downloaded, total),
                                    message: Some(describe(downloaded, total)),
                                    ..Default::default()
                                })),
                            )
                            .await;
                    }
                    Step::Done(error) => {
                        client
                            .send_notification::<tower_lsp_server::ls_types::notification::Progress>(
                                report(WorkDoneProgress::End(WorkDoneProgressEnd {
                                    message: Some(match error {
                                        Some(error) => format!("{ecosystem} failed: {error}"),
                                        None => format!("{ecosystem} advisories ready"),
                                    }),
                                })),
                            )
                            .await;
                        break;
                    }
                }
            }
        });
    }

    fn advance(&self, ecosystem: Ecosystem, downloaded: u64, total: Option<u64>) {
        self.send(ecosystem, Step::Advance { downloaded, total });
    }

    fn done(&self, ecosystem: Ecosystem, error: Option<&str>) {
        self.send(ecosystem, Step::Done(error.map(ToOwned::to_owned)));
        if let Ok(mut senders) = self.senders.lock() {
            senders.remove(&ecosystem);
        }
    }
}

/// Whole percent, or nothing when the server sent no `content-length`.
///
/// Computed in `u128`: `downloaded * 100` overflows a `u64` above ~1.8e17, and
/// saturating there yields a plausible-looking wrong number rather than an
/// obvious one.
fn percentage(downloaded: u64, total: Option<u64>) -> Option<u32> {
    let total = u128::from(total.filter(|t| *t > 0)?);
    let percent = u128::from(downloaded) * 100 / total;
    Some(u32::try_from(percent).unwrap_or(100).min(100))
}

/// "12.4 MB of 205.3 MB", or just the first half when the size is unknown.
fn describe(downloaded: u64, total: Option<u64>) -> String {
    match total.filter(|t| *t > 0) {
        Some(total) => format!("{} of {}", megabytes(downloaded), megabytes(total)),
        None => megabytes(downloaded),
    }
}

fn megabytes(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentage_is_whole_and_clamped() {
        assert_eq!(percentage(0, Some(200)), Some(0));
        assert_eq!(percentage(100, Some(200)), Some(50));
        assert_eq!(percentage(200, Some(200)), Some(100));
        // A server that under-reports its own length must not produce 140%.
        assert_eq!(percentage(280, Some(200)), Some(100));
        // No content-length means no bar, not a division by zero.
        assert_eq!(percentage(100, None), None);
        assert_eq!(percentage(100, Some(0)), None);
    }

    #[test]
    fn a_huge_download_does_not_overflow_the_percentage() {
        // downloaded * 100 overflows a u64 above ~1.8e17; saturating keeps it
        // a number rather than a panic, and this binary aborts on panic.
        assert_eq!(percentage(u64::MAX, Some(u64::MAX)), Some(100));
    }

    #[test]
    fn sizes_read_as_megabytes() {
        assert_eq!(describe(0, Some(215_232_640)), "0.0 MB of 205.3 MB");
        assert_eq!(describe(1_048_576, None), "1.0 MB");
    }

    /// Scans nothing: these tests are about the wire, not the workspace.
    struct Idle;

    impl crate::scan::Scanner for Idle {
        fn scan(
            &self,
            root: &std::path::Path,
        ) -> Result<crate::model::Report, crate::scan::ScanError> {
            Ok(crate::model::Report::new(root, Vec::new()))
        }
    }

    struct Wired {
        progress: ClientProgress,
        client: crate::testing::FakeClient,
        /// Held so the fake editor keeps answering.
        _service: tower_lsp_server::LspService<crate::lsp::Backend>,
        _root: tempfile::TempDir,
    }

    /// A reporter wired to an initialised server over a fake editor: the
    /// client sends nothing before the lifecycle says it may.
    async fn reporter() -> Wired {
        let slot: std::sync::Arc<Mutex<Option<Client>>> = Default::default();
        let captured = std::sync::Arc::clone(&slot);
        let (mut service, client) = crate::testing::FakeClient::serve(move |client| {
            *captured.lock().unwrap() = Some(client.clone());
            crate::lsp::Backend::new(client, "test".into(), |_, _, _| std::sync::Arc::new(Idle))
        });
        let root = tempfile::tempdir().unwrap();
        let params = tower_lsp_server::ls_types::InitializeParams {
            workspace_folders: Some(vec![tower_lsp_server::ls_types::WorkspaceFolder {
                uri: format!("file://{}", root.path().display()).parse().unwrap(),
                name: String::new(),
            }]),
            ..Default::default()
        };
        crate::testing::FakeClient::call(&mut service, "initialize", 1, params).await;
        crate::testing::FakeClient::notify(
            &mut service,
            "initialized",
            tower_lsp_server::ls_types::InitializedParams {},
        )
        .await;
        let lsp_client = slot.lock().unwrap().take().unwrap();
        Wired {
            progress: ClientProgress::new(lsp_client, Handle::current()),
            client,
            _service: service,
            _root: root,
        }
    }

    fn kinds(client: &crate::testing::FakeClient) -> Vec<String> {
        client
            .params_of("$/progress")
            .iter()
            .map(|p| p["value"]["kind"].as_str().unwrap_or("").to_owned())
            .collect()
    }

    #[tokio::test]
    async fn begin_report_end_arrive_in_order_on_one_token() {
        let Wired {
            progress, client, ..
        } = reporter().await;
        let total = Some(200u64 << 20);
        progress.start(Ecosystem::Npm, total);
        progress.advance(Ecosystem::Npm, 100 << 20, total);
        progress.done(Ecosystem::Npm, None);

        assert!(
            client
                .wait_until(|r| r.iter().filter(|(m, _)| m == "$/progress").count() == 3)
                .await
        );
        assert_eq!(kinds(&client), ["begin", "report", "end"]);

        let created = client.params_of("window/workDoneProgress/create");
        assert_eq!(created.len(), 1);
        for p in client.params_of("$/progress") {
            assert_eq!(p["token"], created[0]["token"]);
        }
        assert_eq!(client.params_of("$/progress")[1]["value"]["percentage"], 50);
    }

    #[tokio::test]
    async fn nothing_is_sent_when_the_client_refuses_the_token() {
        let Wired {
            progress, client, ..
        } = reporter().await;
        client
            .refuse_progress
            .store(true, std::sync::atomic::Ordering::SeqCst);
        progress.start(Ecosystem::Npm, Some(10));
        progress.advance(Ecosystem::Npm, 5, Some(10));
        progress.done(Ecosystem::Npm, None);

        assert!(
            client
                .wait_until(|r| r.iter().any(|(m, _)| m == "window/workDoneProgress/create"))
                .await
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            kinds(&client).is_empty(),
            "sent {:?} after the token was refused",
            kinds(&client)
        );
    }

    #[tokio::test]
    async fn the_end_names_the_failure() {
        let Wired {
            progress, client, ..
        } = reporter().await;
        progress.start(Ecosystem::Npm, Some(10));
        progress.done(Ecosystem::Npm, Some("connection reset"));

        assert!(
            client
                .wait_until(|r| r.iter().filter(|(m, _)| m == "$/progress").count() == 2)
                .await
        );
        assert_eq!(
            client.params_of("$/progress")[1]["value"]["message"],
            "npm failed: connection reset"
        );
    }

    #[tokio::test]
    async fn ecosystems_get_separate_tokens() {
        let Wired {
            progress, client, ..
        } = reporter().await;
        progress.start(Ecosystem::Npm, Some(10));
        progress.start(Ecosystem::PyPI, Some(20));

        assert!(
            client
                .wait_until(|r| r
                    .iter()
                    .filter(|(m, _)| m == "window/workDoneProgress/create")
                    .count()
                    == 2)
                .await
        );
        let created = client.params_of("window/workDoneProgress/create");
        assert_ne!(
            created[0]["token"], created[1]["token"],
            "npm and PyPI shared a token"
        );
    }

    #[tokio::test]
    async fn no_percentage_when_the_size_is_unknown() {
        // A mirror or proxy need not send Content-Length. An indeterminate bar
        // beats a fabricated number.
        let Wired {
            progress, client, ..
        } = reporter().await;
        progress.start(Ecosystem::Npm, None);
        progress.advance(Ecosystem::Npm, 5 << 20, None);

        assert!(
            client
                .wait_until(|r| r.iter().filter(|(m, _)| m == "$/progress").count() == 2)
                .await
        );
        let report = &client.params_of("$/progress")[1]["value"];
        assert!(report.get("percentage").is_none(), "{report}");
        assert_eq!(report["message"], "5.0 MB");
    }
}
