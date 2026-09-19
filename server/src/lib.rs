//! A language server that flags vulnerable and malicious dependencies.
//!
//! It walks a workspace, parses its manifests and lockfiles with spans, matches
//! every dependency it finds against the OSV database — a local archive, or
//! per-package answers from osv.dev kept on disk — and publishes the findings
//! as diagnostics anchored on the manifest line the user can act on.

mod action;
mod api;
mod config;
mod db;
mod diagnostics;
mod engine;
mod extract;
mod index;
mod load;
mod lsp;
mod manifest;
mod matcher;
mod osv;
mod progress;
mod read;
mod scan;
mod span;
#[cfg(test)]
mod testing;

pub mod model;
pub mod version;

// What the language server binary composes.
pub use config::{Config, NAME};
pub use db::{Database, DbError, Progress, default_root};
pub use engine::{DEFAULT_DEBOUNCE, Engine, Publisher, Reason, Requester};
pub use extract::{ExtractError, Extractor};
pub use lsp::Backend;
pub use progress::ClientProgress;
pub use scan::{ScanError, Scanner, WorkspaceScanner};

// What the measurement binaries (`dbcheck`, `scanbench`) need beyond that.
// Not a stable API: they live in this repository and move with the code.
pub use extract::{SKIP_DIRS, is_manifest_name};
pub use index::Index;
pub use load::{ArchiveStats, LoadError, Strategy, load};
pub use matcher::Matcher;
pub mod alloc;
