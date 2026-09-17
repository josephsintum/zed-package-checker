//! Deciding *when* to scan, and what to publish.
//!
//! One task owns every piece of mutable state; everything else talks to it over
//! a channel. Same actor shape as the Go server's `internal/engine`, for the
//! same reason: it is race-free by construction rather than by discipline.
//!
//! Two things differ. Supersession here aborts the in-flight scan rather than
//! asking it to notice, so the `ctx.Err()` polls the Go loader needs every 256
//! packages and every 512 zip entries have no counterpart. And the compiler
//! enforces what `-race` and `goleak` are there to check for.

use crate::model::{Finding, Report};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Matches the JetBrains plugin, and is long enough that a `git checkout`
/// touching forty files causes one scan.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_secs(1);

/// Why a scan was asked for. Reported in logs; it never changes what is done.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    Startup,
    FileChanged,
    FileSaved,
    DatabaseSync,
    Manual,
}

impl Reason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::Startup => "startup",
            Reason::FileChanged => "file changed",
            Reason::FileSaved => "file saved",
            Reason::DatabaseSync => "database updated",
            Reason::Manual => "requested",
        }
    }
}

/// Produces a report for a workspace. Implemented by `crate::scan`.
pub trait Scanner: Send + Sync + 'static {
    fn scan(&self, root: &Path) -> anyhow::Result<Report>;
}

/// Sends diagnostics to the client. Implemented by the LSP layer.
pub trait Publisher: Send + Sync + 'static {
    fn publish(&self, path: PathBuf, findings: Vec<Finding>);
}

enum Message {
    Request(Reason),
    Clear(PathBuf),
    Query(PathBuf, oneshot::Sender<Vec<Finding>>),
}

/// Asks for a scan without holding the engine.
///
/// The scanner needs to request a rescan when a background download finishes,
/// and the engine needs the scanner — a cycle that Go breaks with a closure over
/// a variable assigned later. Here the channel exists before either end does,
/// which is the same trick without the window in which the variable is nil.
#[derive(Clone)]
pub struct Requester {
    tx: mpsc::Sender<Message>,
}

impl Requester {
    pub fn request(&self, reason: Reason) {
        let _ = self.tx.try_send(Message::Request(reason));
    }
}

/// The receiving half, before a scanner and publisher exist to serve it.
pub struct PendingEngine {
    tx: mpsc::Sender<Message>,
    rx: mpsc::Receiver<Message>,
}

impl PendingEngine {
    pub fn start(
        self,
        root: PathBuf,
        scanner: Arc<dyn Scanner>,
        publisher: Arc<dyn Publisher>,
        debounce: Duration,
    ) -> Engine {
        let task = tokio::spawn(run(root, scanner, publisher, debounce, self.rx));
        Engine { tx: self.tx, task }
    }
}

/// A handle to the scheduling task.
pub struct Engine {
    tx: mpsc::Sender<Message>,
    task: JoinHandle<()>,
}

impl Engine {
    /// Creates the request channel before the engine, so something that needs to
    /// ask for a scan can be built first.
    pub fn pending() -> (Requester, PendingEngine) {
        // Senders never block: a pending request already means "rescan", so
        // extra ones are dropped rather than queued and the channel can never
        // back up.
        let (tx, rx) = mpsc::channel(64);
        (Requester { tx: tx.clone() }, PendingEngine { tx, rx })
    }

    pub fn start(
        root: PathBuf,
        scanner: Arc<dyn Scanner>,
        publisher: Arc<dyn Publisher>,
        debounce: Duration,
    ) -> Engine {
        let (_, pending) = Engine::pending();
        pending.start(root, scanner, publisher, debounce)
    }

    /// Asks for a scan. Never blocks, and never fails: a full queue already
    /// holds the same instruction.
    pub fn request(&self, reason: Reason) {
        let _ = self.tx.try_send(Message::Request(reason));
    }

    /// Drops a file's diagnostics immediately, for a manifest that was deleted.
    pub fn clear(&self, path: PathBuf) {
        let _ = self.tx.try_send(Message::Clear(path));
    }

    /// The findings already known for a file, for re-publishing on `didOpen`.
    pub async fn findings(&self, path: PathBuf) -> Vec<Finding> {
        let (reply, answer) = oneshot::channel();
        if self.tx.send(Message::Query(path, reply)).await.is_err() {
            return Vec::new();
        }
        answer.await.unwrap_or_default()
    }

    /// Stops the scheduler and waits for it. Dropping the handle is enough to
    /// stop it; this exists so shutdown is deterministic.
    pub async fn shutdown(self) {
        drop(self.tx);
        let _ = self.task.await;
    }
}

async fn run(
    root: PathBuf,
    scanner: Arc<dyn Scanner>,
    publisher: Arc<dyn Publisher>,
    debounce: Duration,
    mut rx: mpsc::Receiver<Message>,
) {
    let mut report: HashMap<PathBuf, Vec<Finding>> = HashMap::new();
    let mut published: HashSet<PathBuf> = HashSet::new();
    let mut deadline: Option<tokio::time::Instant> = None;
    let mut in_flight: Option<JoinHandle<anyhow::Result<Report>>> = None;

    loop {
        // `sleep_until` on a deadline rather than a resettable timer: setting a
        // new deadline *is* the reset, so there is no timer to drain.
        let debounce_elapsed = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        let scan_finished = async {
            match in_flight.as_mut() {
                Some(handle) => handle.await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            message = rx.recv() => {
                let Some(message) = message else { break };
                match message {
                    Message::Request(reason) => {
                        tracing::debug!(reason = reason.as_str(), "scan requested");
                        // A newer request supersedes whatever is running: its
                        // results describe a tree that no longer exists.
                        if let Some(handle) = in_flight.take() {
                            handle.abort();
                        }
                        deadline = Some(tokio::time::Instant::now() + debounce);
                    }
                    Message::Clear(path) => {
                        report.remove(&path);
                        if published.remove(&path) {
                            publisher.publish(path, Vec::new());
                        }
                    }
                    Message::Query(path, reply) => {
                        let _ = reply.send(report.get(&path).cloned().unwrap_or_default());
                    }
                }
            }
            () = debounce_elapsed => {
                deadline = None;
                let scanner = Arc::clone(&scanner);
                let root = root.clone();
                // Scanning parses archives and walks a tree; it belongs on the
                // blocking pool, not on a runtime worker.
                in_flight = Some(tokio::task::spawn_blocking(move || scanner.scan(&root)));
            }
            finished = scan_finished => {
                in_flight = None;
                match finished {
                    Ok(Ok(fresh)) => {
                        publish(&fresh, &mut report, &mut published, publisher.as_ref());
                    }
                    Ok(Err(error)) => tracing::warn!(%error, "scan failed"),
                    // Cancelled by a newer request, which is the normal path.
                    Err(join) if join.is_cancelled() => {}
                    Err(join) => tracing::warn!(error = %join, "scan task failed"),
                }
            }
        }
    }

    if let Some(handle) = in_flight {
        handle.abort();
    }
}

/// Publishes a fresh report, including empty sets for files that were affected
/// last time and are not any more.
fn publish(
    fresh: &Report,
    report: &mut HashMap<PathBuf, Vec<Finding>>,
    published: &mut HashSet<PathBuf>,
    publisher: &dyn Publisher,
) {
    let grouped = fresh.by_file();
    let current: HashMap<PathBuf, Vec<Finding>> = grouped
        .into_iter()
        .map(|(path, findings)| (path.to_path_buf(), findings.into_iter().cloned().collect()))
        .collect();

    // Clearing comes first so a file that moved from "vulnerable" to "clean"
    // never keeps a stale squiggle, even briefly.
    for stale in published.difference(&current.keys().cloned().collect()) {
        publisher.publish(stale.clone(), Vec::new());
    }

    *published = current.keys().cloned().collect();
    for (path, findings) in &current {
        publisher.publish(path.clone(), findings.clone());
    }
    *report = current;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Ecosystem, Package, Range, Site};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Short enough to keep the tests quick, long enough that several requests
    /// land inside one window on a loaded machine.
    const DEBOUNCE: Duration = Duration::from_millis(60);

    fn finding(path: &str) -> Finding {
        Finding {
            package: Package::new(Ecosystem::Npm, "lodash", "4.17.15"),
            advisories: vec![Arc::new(crate::model::Advisory {
                id: "GHSA-1".into(),
                aliases: Box::default(),
                summary: Box::default(),
                cvss_score: 7.5,
                cvss_vector: Box::default(),
                affected: Box::default(),
                references: Box::default(),
            })],
            evidence: Site::new(path, Range::whole_line(1)),
            declared: None,
            paths: Vec::new(),
            reachable: None,
            from_range: false,
            dep_groups: Vec::new(),
        }
    }

    #[derive(Default)]
    struct FakeScanner {
        calls: AtomicUsize,
        findings: Mutex<Vec<Finding>>,
        /// Held while a scan is "running", so a test can supersede one.
        block: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl Scanner for Arc<FakeScanner> {
        fn scan(&self, root: &Path) -> anyhow::Result<Report> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = self.block.lock().unwrap().take() {
                let _ = gate.recv();
            }
            Ok(Report::new(root, self.findings.lock().unwrap().clone()))
        }
    }

    #[derive(Default)]
    struct Recorder {
        published: Mutex<Vec<(PathBuf, usize)>>,
    }

    impl Publisher for Arc<Recorder> {
        fn publish(&self, path: PathBuf, findings: Vec<Finding>) {
            self.published.lock().unwrap().push((path, findings.len()));
        }
    }

    fn harness(findings: Vec<Finding>) -> (Arc<FakeScanner>, Arc<Recorder>, Engine) {
        let scanner = Arc::new(FakeScanner::default());
        *scanner.findings.lock().unwrap() = findings;
        let recorder = Arc::new(Recorder::default());
        let engine = Engine::start(
            PathBuf::from("/project"),
            Arc::new(Arc::clone(&scanner)),
            Arc::new(Arc::clone(&recorder)),
            DEBOUNCE,
        );
        (scanner, recorder, engine)
    }

    async fn settle() {
        tokio::time::sleep(DEBOUNCE * 5).await;
    }

    #[tokio::test]
    async fn many_requests_inside_the_window_cause_one_scan() {
        let (scanner, _, engine) = harness(vec![finding("/project/package.json")]);
        for _ in 0..40 {
            engine.request(Reason::FileChanged);
        }
        settle().await;
        assert_eq!(scanner.calls.load(Ordering::SeqCst), 1);
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn a_report_is_published_per_file() {
        let (_, recorder, engine) = harness(vec![
            finding("/project/package.json"),
            finding("/project/go.mod"),
        ]);
        engine.request(Reason::Startup);
        settle().await;

        let published = recorder.published.lock().unwrap().clone();
        assert_eq!(published.len(), 2);
        assert!(published.iter().all(|(_, n)| *n == 1));
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn a_file_that_becomes_clean_is_published_empty() {
        let (scanner, recorder, engine) = harness(vec![finding("/project/package.json")]);
        engine.request(Reason::Startup);
        settle().await;

        // Nothing vulnerable this time: the previous squiggle has to go.
        scanner.findings.lock().unwrap().clear();
        engine.request(Reason::FileChanged);
        settle().await;

        let published = recorder.published.lock().unwrap().clone();
        assert_eq!(
            published.last(),
            Some(&(PathBuf::from("/project/package.json"), 0)),
            "the last publish must clear the file"
        );
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn a_deleted_manifest_is_cleared_without_waiting_for_a_scan() {
        let (_, recorder, engine) = harness(vec![finding("/project/package.json")]);
        engine.request(Reason::Startup);
        settle().await;
        recorder.published.lock().unwrap().clear();

        engine.clear(PathBuf::from("/project/package.json"));
        tokio::time::sleep(DEBOUNCE).await;
        assert_eq!(
            recorder.published.lock().unwrap().clone(),
            [(PathBuf::from("/project/package.json"), 0)]
        );
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn findings_are_readable_without_rescanning() {
        let (scanner, _, engine) = harness(vec![finding("/project/package.json")]);
        engine.request(Reason::Startup);
        settle().await;

        let found = engine.findings(PathBuf::from("/project/package.json")).await;
        assert_eq!(found.len(), 1);
        assert!(engine.findings(PathBuf::from("/project/go.mod")).await.is_empty());
        // A query must never trigger work.
        assert_eq!(scanner.calls.load(Ordering::SeqCst), 1);
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn a_superseded_scan_never_publishes() {
        let scanner = Arc::new(FakeScanner::default());
        *scanner.findings.lock().unwrap() = vec![finding("/project/package.json")];
        let (release, gate) = std::sync::mpsc::channel::<()>();
        *scanner.block.lock().unwrap() = Some(gate);

        let recorder = Arc::new(Recorder::default());
        let engine = Engine::start(
            PathBuf::from("/project"),
            Arc::new(Arc::clone(&scanner)),
            Arc::new(Arc::clone(&recorder)),
            DEBOUNCE,
        );

        engine.request(Reason::Startup);
        tokio::time::sleep(DEBOUNCE * 2).await; // the first scan is now stuck
        engine.request(Reason::FileChanged); // supersede it
        settle().await;
        drop(release); // let the abandoned scan finish

        settle().await;
        let published = recorder.published.lock().unwrap().clone();
        assert_eq!(
            published.len(),
            1,
            "only the winning scan publishes, got {published:?}"
        );
        engine.shutdown().await;
    }
}
