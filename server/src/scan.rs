//! Extraction, database and matching, composed into one scan.
//!
//! The advisory index is shared behind an `ArcSwap`, so scans read it with no
//! lock at all and a refresh is a pointer swap.

use crate::db::{Database, DbError};
use crate::extract::Extractor;
use crate::index::Index;
use crate::load::{Strategy, load};
use crate::matcher::Matcher;
use crate::model::{Ecosystem, Report, ecosystems_of};
use arc_swap::{ArcSwap, ArcSwapOption};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// How often a scan offers the database a chance to revalidate. Shorter than
/// the database's own freshness window, because this only asks — the database
/// decides whether anything is actually stale, and answers with one small
/// metadata read when it is not.
const REFRESH_CHECK_EVERY: Duration = Duration::from_secs(60 * 60);

/// How long shutdown waits for a download in flight. The process is exiting;
/// a partial download is discarded by the atomic publish either way.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(1);

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The archives are still downloading. Deliberately distinct from an empty
    /// report: "still downloading" and "nothing is vulnerable" must never look
    /// alike.
    #[error("advisory database not ready")]
    NotReady,
    #[error(transparent)]
    Extract(#[from] crate::extract::ExtractError),
    #[error(transparent)]
    Load(#[from] crate::load::LoadError),
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    Api(#[from] crate::api::ApiError),
}

/// Produces a report for a workspace.
///
/// A trait rather than the concrete [`WorkspaceScanner`] so the engine can be
/// tested against a fake; there is one real implementation.
pub trait Scanner: Send + Sync + 'static {
    /// Scans `root` and reports every vulnerable dependency under it.
    ///
    /// # Errors
    ///
    /// [`ScanError::NotReady`] while the advisory database is still
    /// downloading; the other variants wrap extraction, loading, cache and
    /// API failures.
    fn scan(&self, root: &Path) -> Result<Report, ScanError>;

    /// Stops background work. Called once, when the engine shuts down.
    fn shutdown(&self) {}
}

pub struct WorkspaceScanner {
    extractor: Extractor,
    api: crate::api::ApiSource,
    /// Shared with the LSP layer, which swaps it on `didChangeConfiguration`.
    config: Arc<ArcSwap<crate::config::Config>>,
    database: Arc<Database>,
    /// Shared rather than owned because the background download replaces it
    /// from another thread when new archives land.
    index: Arc<ArcSwapOption<Index>>,
    /// Whether a background download is running, and a way to wait for it.
    warming: Arc<(Mutex<bool>, Condvar)>,
    /// Set by `shutdown`: no download starts, and none that finishes asks for
    /// a rescan of an engine that is gone.
    stopped: Arc<AtomicBool>,
    /// When the database was last offered a chance to revalidate.
    refreshed_at: Mutex<Option<Instant>>,
    /// Called when a background download finishes, so the scan that was refused
    /// can be retried without waiting for the user to touch a file.
    on_ready: Arc<dyn Fn() + Send + Sync>,
    strategy: Strategy,
}

impl WorkspaceScanner {
    pub fn new(
        extractor: Extractor,
        database: Arc<Database>,
        on_ready: impl Fn() + Send + Sync + 'static,
    ) -> WorkspaceScanner {
        let config = Arc::new(ArcSwap::from_pointee(crate::config::Config::default()));
        WorkspaceScanner {
            extractor,
            api: crate::api::ApiSource::new(database.root(), Arc::clone(&config)),
            config,
            database,
            index: Arc::new(ArcSwapOption::empty()),
            warming: Arc::new((Mutex::new(false), Condvar::new())),
            stopped: Arc::new(AtomicBool::new(false)),
            refreshed_at: Mutex::new(None),
            on_ready: Arc::new(on_ready),
            strategy: Strategy::default(),
        }
    }

    /// Shares the live configuration with the LSP layer.
    #[must_use]
    pub fn with_config(mut self, config: Arc<ArcSwap<crate::config::Config>>) -> Self {
        self.api = crate::api::ApiSource::new(self.database.root(), Arc::clone(&config));
        self.config = config;
        self
    }

    /// Stops any background download from asking for a rescan, and waits
    /// briefly for one in flight.
    ///
    /// Safe to call more than once, and on a scanner that never downloaded
    /// anything.
    pub fn shutdown(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        let (warming, finished) = &*self.warming;
        if let Ok(guard) = warming.lock() {
            let _ = finished.wait_timeout_while(guard, SHUTDOWN_WAIT, |warming| *warming);
        }
    }

    /// Discards the cached index, so the next scan rebuilds it.
    pub fn invalidate(&self) {
        self.index.store(None);
    }

    fn index_for(&self, ecosystems: &[Ecosystem]) -> Result<Arc<Index>, ScanError> {
        if let Some(index) = self.index.load_full()
            && index.covers(ecosystems)
        {
            return Ok(index);
        }
        let archives = self.database.archives(ecosystems);
        let (index, stats) = load(&archives, self.strategy)?;
        for (ecosystem, s) in stats {
            tracing::info!(
                %ecosystem,
                entries = s.entries,
                indexed = s.indexed,
                "advisory archive loaded"
            );
            // A security tool that under-reports without saying so is worse
            // than one that fails, so a skipped advisory is never quiet.
            if s.skipped > 0 {
                tracing::warn!(%ecosystem, skipped = s.skipped, "advisories skipped as unreadable");
            }
        }
        let index = Arc::new(index);
        self.index.store(Some(Arc::clone(&index)));
        Ok(index)
    }

    /// Asks the database to revalidate, at most once an hour.
    ///
    /// `ready` reports only that an archive exists. Without this, once one was
    /// on disk the server never consulted its freshness window again, and an
    /// editor left open for a week matched against week-old advisories. The
    /// work is a cold start's — check staleness, revalidate with the ETag,
    /// download only when the bytes changed — so it reuses the same background
    /// path, which already runs one at a time and stops on shutdown.
    fn refresh_if_due(&self, ecosystems: Vec<Ecosystem>) {
        let Ok(mut refreshed_at) = self.refreshed_at.lock() else {
            return;
        };
        if refreshed_at.is_some_and(|at| at.elapsed() < REFRESH_CHECK_EVERY) {
            return;
        }
        *refreshed_at = Some(Instant::now());
        drop(refreshed_at);
        self.warm(ecosystems);
    }

    /// Downloads or revalidates the named archives, on its own thread.
    ///
    /// The scan that triggered this has already returned; the download outlives
    /// it deliberately, because cancelling a 205 MB transfer because the user
    /// saved a file would mean never finishing one. Only one runs at a time: a
    /// project with a missing database fails every scan it is asked for, and
    /// each of those must not start its own download.
    fn warm(&self, ecosystems: Vec<Ecosystem>) {
        if self.stopped.load(Ordering::SeqCst) {
            return;
        }
        {
            let Ok(mut warming) = self.warming.0.lock() else {
                return;
            };
            if *warming {
                return;
            }
            *warming = true;
        }

        let database = Arc::clone(&self.database);
        let warming = Arc::clone(&self.warming);
        let stopped = Arc::clone(&self.stopped);
        let index = Arc::clone(&self.index);
        let on_ready = Arc::clone(&self.on_ready);
        // What each archive looked like before, so a revalidation that
        // changed nothing does not reload an index and republish identical
        // diagnostics. An archive is only ever replaced by rename, so a new
        // modification time is the whole signal.
        let before: HashMap<Ecosystem, Option<SystemTime>> = ecosystems
            .iter()
            .map(|&e| (e, modified(&database, e)))
            .collect();

        std::thread::spawn(move || {
            let result = database.ensure_each(&ecosystems, |ecosystem| {
                if stopped.load(Ordering::SeqCst)
                    || modified(&database, ecosystem) == before[&ecosystem]
                {
                    return;
                }
                // Published the moment it lands, so a Rust project is not
                // waiting on npm's archive to see its own findings. The index
                // goes first, or the rescan would reuse the old one.
                tracing::info!(%ecosystem, "advisory archive ready");
                index.store(None);
                on_ready();
            });
            if let Err(error) = result {
                tracing::warn!(%error, "advisory download failed");
            }
            // Cleared last, so a failed download is retried on the next scan
            // rather than wedging the server, and shutdown can stop waiting.
            if let Ok(mut flag) = warming.0.lock() {
                *flag = false;
            }
            warming.1.notify_all();
        });
    }
}

/// When an archive was last replaced, or `None` when it is absent.
fn modified(database: &Database, ecosystem: Ecosystem) -> Option<SystemTime> {
    std::fs::metadata(database.archive_path(ecosystem))
        .and_then(|m| m.modified())
        .ok()
}

impl WorkspaceScanner {
    /// Matches against advisories fetched for these packages specifically.
    ///
    /// The index this builds is complete for every package that has a finding,
    /// which is what `Matcher::fix_for` needs to verify a candidate upgrade.
    /// Where `api` could not establish that for a package, the fix is withheld
    /// rather than guessed — see [`crate::api`]'s module documentation.
    fn online(
        &self,
        root: &Path,
        packages: &[crate::model::ExtractedPackage],
        ecosystems: &[Ecosystem],
    ) -> Result<Report, ScanError> {
        let started = std::time::Instant::now();
        let fetched = self.api.advisories(packages)?;

        tracing::info!(
            packages = packages.len(),
            advisories = fetched.advisories.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "matched against osv.dev; names and versions only left this machine"
        );

        let index = Index::build(fetched.advisories, ecosystems.to_vec(), started.elapsed());
        let mut findings = Matcher::new(&index).findings(packages);
        for finding in &mut findings {
            if fetched.partial.contains(&finding.package.key) {
                finding.fix = crate::model::Fix::None;
            }
        }
        Ok(Report::new(root, findings).from_api(packages.len()))
    }
}

impl Scanner for WorkspaceScanner {
    fn shutdown(&self) {
        WorkspaceScanner::shutdown(self);
    }

    fn scan(&self, root: &Path) -> Result<Report, ScanError> {
        let packages = self.extractor.extract(root)?;
        if packages.is_empty() {
            // Nothing to look up, so no database is needed and no download is
            // started. The server has to idle cheaply: it starts for nearly
            // every project.
            return Ok(Report::new(root, Vec::new()));
        }

        let ecosystems = ecosystems_of(&packages);

        // The archive is authoritative when it is here: it answers offline, it
        // covers packages the API was never asked about, and it costs nothing
        // per scan once loaded.
        if self.database.ready(&ecosystems) {
            self.refresh_if_due(ecosystems.clone());
            let index = self.index_for(&ecosystems)?;
            let findings = Matcher::new(&index).findings(&packages);
            return Ok(Report::new(root, findings));
        }

        // Some archives are here and the rest are still downloading. Each is
        // published by an atomic rename, so what is present is complete —
        // report it rather than showing nothing until npm's 205 MB lands.
        let ready = self.database.ready_ecosystems(&ecosystems);
        if !ready.is_empty() {
            let missing: Vec<Ecosystem> = ecosystems
                .iter()
                .copied()
                .filter(|e| !ready.contains(e))
                .collect();
            let index = self.index_for(&ready)?;
            let checkable: Vec<_> = packages
                .iter()
                .filter(|p| ready.contains(&p.package.ecosystem()))
                .cloned()
                .collect();
            let findings = Matcher::new(&index).findings(&checkable);

            self.warm(ecosystems);
            return Ok(Report::new(root, findings).missing(missing));
        }

        // Nothing on disk. Asking about the few hundred packages in hand beats
        // waiting for every advisory for every package that exists.
        let config = self.config.load_full();
        if config.online.enabled && !config.offline {
            match self.online(root, &packages, &ecosystems) {
                Ok(report) => return Ok(report),
                Err(error) => {
                    tracing::warn!(%error, "falling back to the advisory archive");
                }
            }
        }

        if !config.offline {
            self.warm(ecosystems);
        }
        Err(ScanError::NotReady)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{ArchiveServer, fake_archive};
    use std::sync::atomic::AtomicUsize;

    const LODASH: &str = r#"{"id":"GHSA-1","summary":"bad thing","affected":[{
        "package":{"ecosystem":"npm","name":"lodash"},
        "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#;

    fn lodash_archive() -> Vec<u8> {
        fake_archive(&[("GHSA-1.json", LODASH)])
    }

    /// A project depending on a vulnerable lodash, with no lockfile.
    fn project_with_lodash() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"fixture","version":"1.0.0","dependencies":{"lodash":"^4.17.15"}}"#,
        )
        .unwrap();
        dir
    }

    struct Harness {
        server: ArchiveServer,
        _cache: tempfile::TempDir,
        rescans: Arc<AtomicUsize>,
        scanner: WorkspaceScanner,
    }

    impl Harness {
        fn new(ttl: Duration) -> Harness {
            let server = ArchiveServer::new(lodash_archive());
            let cache = tempfile::tempdir().unwrap();
            let database = Arc::new(server.database(cache.path()).with_ttl(ttl));
            let rescans = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&rescans);
            let scanner = WorkspaceScanner::new(Extractor::new(), database, move || {
                counter.fetch_add(1, Ordering::SeqCst);
            });
            // The archive path, not the API: these tests are about the
            // database's lifecycle.
            let mut config = crate::config::Config::default();
            config.online.enabled = false;
            scanner.config.store(Arc::new(config));
            Harness {
                server,
                _cache: cache,
                rescans,
                scanner,
            }
        }

        fn rescans(&self) -> usize {
            self.rescans.load(Ordering::SeqCst)
        }

        fn scan(&self, root: &Path) -> Result<Report, ScanError> {
            self.scanner.scan(root)
        }

        /// Scans until the database has landed and the scan succeeds.
        fn scan_until_ready(&self, root: &Path) -> Report {
            let first = self.scan(root);
            assert!(is_not_ready(&first), "first scan: {first:?}");
            assert!(
                wait_for(|| self.rescans() >= 1),
                "no rescan requested after the download"
            );
            self.scan(root).expect("scan after the download landed")
        }
    }

    fn is_not_ready(result: &Result<Report, ScanError>) -> bool {
        matches!(result, Err(ScanError::NotReady))
    }

    fn wait_for(condition: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        condition()
    }

    #[test]
    fn a_workspace_without_dependencies_touches_no_database() {
        // The server attaches to nearly every language, so most workspaces it
        // starts in have nothing to scan. Those must not trigger a 205 MB
        // download.
        let h = Harness::new(Duration::from_secs(3600));
        let root = tempfile::tempdir().unwrap();

        let report = h.scan(root.path()).unwrap();
        assert!(report.findings.is_empty());
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(h.server.requests(), 0, "a download was started");
    }

    #[test]
    fn a_missing_database_reports_not_ready_rather_than_clean() {
        // "Still downloading" and "nothing is vulnerable" must never look
        // alike: the second is the one a user acts on.
        let h = Harness::new(Duration::from_secs(3600));
        h.scanner.config.store(Arc::new(crate::config::Config {
            offline: true,
            ..Default::default()
        }));
        let root = project_with_lodash();

        let result = h.scan(root.path());
        assert!(is_not_ready(&result), "{result:?}");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(h.server.requests(), 0, "offline must not download");
    }

    #[test]
    fn repeated_scans_start_only_one_download() {
        // A project with a missing database fails every scan it is asked for,
        // and each failure must not start its own download.
        let h = Harness::new(Duration::from_secs(3600));
        h.server.set(|s| s.delay = Duration::from_millis(300));
        let root = project_with_lodash();

        for _ in 0..5 {
            let result = h.scan(root.path());
            assert!(is_not_ready(&result), "{result:?}");
        }
        assert!(wait_for(|| h.rescans() >= 1));
        assert_eq!(h.server.requests(), 1, "want exactly one download");
    }

    #[test]
    fn a_finished_download_asks_for_a_rescan_that_then_finds_the_advisory() {
        let h = Harness::new(Duration::from_secs(3600));
        let root = project_with_lodash();

        let report = h.scan_until_ready(root.path());
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert_eq!(report.findings[0].package.name(), "lodash");
    }

    #[test]
    fn a_finished_download_asks_for_exactly_one_rescan() {
        let h = Harness::new(Duration::from_secs(3600));
        let root = project_with_lodash();

        h.scan_until_ready(root.path());
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(h.rescans(), 1, "one archive landed, one rescan");
    }

    #[test]
    fn a_ready_database_is_still_revalidated() {
        // Ready only reports that an archive exists. Before this, a server
        // whose archive was already on disk never reached the database's
        // freshness check again — an editor open for a week matched against
        // week-old advisories.
        let h = Harness::new(Duration::ZERO);
        let root = project_with_lodash();
        h.scan_until_ready(root.path());

        assert!(
            wait_for(|| h.server.not_modified() == 1),
            "a scan against a ready database never asked it to revalidate: {} requests",
            h.server.requests()
        );
    }

    #[test]
    fn revalidation_is_rate_limited() {
        // Revalidating on every keystroke-triggered rescan would put a network
        // round trip behind every scan for no benefit.
        let h = Harness::new(Duration::ZERO);
        let root = project_with_lodash();
        h.scan_until_ready(root.path());
        for _ in 0..5 {
            h.scan(root.path()).unwrap();
        }

        assert!(wait_for(|| h.server.not_modified() == 1));
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            h.server.requests(),
            2,
            "revalidated more than once across six scans"
        );
    }

    #[test]
    fn a_revalidation_that_changes_nothing_does_not_ask_for_a_rescan() {
        // A 304 leaves the archive as it was; reloading npm's index and
        // republishing identical diagnostics every hour would be pure cost.
        let h = Harness::new(Duration::ZERO);
        let root = project_with_lodash();
        h.scan_until_ready(root.path());
        assert!(wait_for(|| h.server.not_modified() == 1));

        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(h.rescans(), 1, "an unchanged archive asked for a rescan");
        assert!(
            h.scanner.index.load().is_some(),
            "an unchanged archive dropped the index"
        );
    }

    #[test]
    fn shutdown_returns_while_a_download_is_in_flight() {
        // Without this the server's exit waits out the whole download.
        let h = Harness::new(Duration::from_secs(3600));
        h.server.set(|s| s.delay = Duration::from_secs(3));
        let root = project_with_lodash();
        assert!(is_not_ready(&h.scan(root.path())));
        assert!(
            wait_for(|| h.server.requests() == 1),
            "the download never started"
        );

        let started = Instant::now();
        h.scanner.shutdown();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown waited {:?} for the download",
            started.elapsed()
        );
    }

    #[test]
    fn shutdown_is_idempotent_and_safe_without_a_download() {
        let h = Harness::new(Duration::from_secs(3600));
        h.scanner.shutdown();
        h.scanner.shutdown();
    }

    #[test]
    fn nothing_is_requested_after_shutdown() {
        let h = Harness::new(Duration::from_secs(3600));
        let root = project_with_lodash();
        h.scanner.shutdown();

        let result = h.scan(root.path());
        assert!(is_not_ready(&result), "{result:?}");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(h.server.requests(), 0, "a download started after shutdown");
        assert_eq!(h.rescans(), 0);
    }
}
