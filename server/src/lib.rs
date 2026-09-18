//! A language server that flags vulnerable and malicious dependencies.
//!
//! It walks a workspace, parses its manifests and lockfiles with spans, matches
//! every dependency it finds against the OSV database — a local archive, or
//! per-package answers from osv.dev kept on disk — and publishes the findings
//! as diagnostics anchored on the manifest line the user can act on.

mod action;
pub mod alloc;
mod api;
mod config;
mod db;
mod diagnostics;
mod digits;
mod engine;
mod extract;
mod index;
mod load;
mod lsp;
mod manifest;
mod matcher;
mod osv;
mod progress;
mod pypi;
mod read;
mod scan;
mod semver_like;
mod span;
#[cfg(test)]
mod testing;

pub mod model;
pub mod version;

pub use config::Config;
pub use db::{Database, DbError, Progress, default_root};
pub use engine::{DEFAULT_DEBOUNCE, Engine, Publisher, Reason, Requester, Scanner};
pub use extract::{ExtractError, Extractor, SKIP_DIRS, is_manifest_name};
pub use index::Index;
pub use load::{ArchiveStats, LoadError, Strategy, load};
pub use lsp::Backend;
pub use matcher::Matcher;
pub use progress::ClientProgress;
pub use scan::{ScanError, WorkspaceScanner};
pub use span::{Encoding, LineIndex, column};
