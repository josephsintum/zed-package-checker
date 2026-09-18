//! Extraction, database and matching, composed into one scan.
//!
//! The advisory index is shared behind an `ArcSwap`, so scans read it with no
//! lock at all and a refresh is a pointer swap. The Go server guards the same
//! immutable index with a mutex, because that is the only way to hand a
//! goroutine a new pointer safely.

use crate::db::{Database, DbError};
use crate::engine::Scanner;
use crate::extract::Extractor;
use crate::index::Index;
use crate::load::{Strategy, load};
use crate::matcher::Matcher;
use crate::model::{Ecosystem, Report, ecosystems_of};
use arc_swap::{ArcSwap, ArcSwapOption};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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

pub struct WorkspaceScanner {
    extractor: Extractor,
    api: crate::api::ApiSource,
    /// Shared with the LSP layer, which swaps it on `didChangeConfiguration`.
    config: Arc<ArcSwap<crate::config::Config>>,
    database: Arc<Database>,
    /// Shared rather than owned because the background download replaces it
    /// from another thread when new archives land.
    index: Arc<ArcSwapOption<Index>>,
    warming: Arc<AtomicBool>,
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
            warming: Arc::new(AtomicBool::new(false)),
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
                skipped = s.skipped,
                "advisory archive loaded"
            );
        }
        let index = Arc::new(index);
        self.index.store(Some(Arc::clone(&index)));
        Ok(index)
    }

    /// Downloads whatever is missing, on its own thread.
    ///
    /// The scan that triggered this has already returned; the download outlives
    /// it deliberately, because cancelling a 205 MB transfer because the user
    /// saved a file would mean never finishing one.
    fn warm(&self, ecosystems: Vec<Ecosystem>) {
        // One download at a time. `swap` rather than load-then-store so two
        // scans racing here cannot both start one.
        if self.warming.swap(true, Ordering::SeqCst) {
            return;
        }
        let database = Arc::clone(&self.database);
        let warming = Arc::clone(&self.warming);
        let index = Arc::clone(&self.index);
        let on_ready = Arc::clone(&self.on_ready);

        std::thread::spawn(move || {
            let result = database.ensure(&ecosystems);
            // Cleared before anything else, so a failed download is retried on
            // the next scan rather than wedging the server.
            warming.store(false, Ordering::SeqCst);
            match result {
                Ok(()) => {
                    index.store(None);
                    on_ready();
                }
                Err(error) => tracing::warn!(%error, "advisory download failed"),
            }
        });
    }
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
        Ok(Report::new(root, findings))
    }
}

impl Scanner for WorkspaceScanner {
    fn scan(&self, root: &Path) -> anyhow::Result<Report> {
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
            let index = self.index_for(&ecosystems)?;
            let findings = Matcher::new(&index).findings(&packages);
            return Ok(Report::new(root, findings));
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
        Err(ScanError::NotReady.into())
    }
}
