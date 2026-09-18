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
}

pub struct WorkspaceScanner {
    extractor: Extractor,
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
        WorkspaceScanner {
            extractor,
            config: Arc::new(ArcSwap::from_pointee(crate::config::Config::default())),
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
        if !self.database.ready(&ecosystems) {
            self.warm(ecosystems);
            return Err(ScanError::NotReady.into());
        }

        let index = self.index_for(&ecosystems)?;
        let findings = Matcher::new(&index).findings(&packages);
        Ok(Report::new(root, findings))
    }
}
