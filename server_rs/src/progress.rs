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
}
