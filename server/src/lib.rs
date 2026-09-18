//! A language server that flags vulnerable and malicious dependencies.
//!
//! The Rust half of a controlled experiment against the Go server in `server/`:
//! same behaviour, same advisory archives, same fixtures, different language.
//! `docs/RUST-VS-GO.md` holds what the comparison found.

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

pub mod model;
pub mod version;

pub use config::Config;
pub use db::{Database, DbError, Progress, default_root};
pub use diagnostics::set_label;
pub use engine::{DEFAULT_DEBOUNCE, Engine, Publisher, Reason, Requester, Scanner};
pub use extract::{ExtractError, Extractor, SKIP_DIRS, is_manifest_name};
pub use index::Index;
pub use load::{ArchiveStats, LoadError, Strategy, load};
pub use lsp::Backend;
pub use matcher::Matcher;
pub use progress::ClientProgress;
pub use scan::{ScanError, WorkspaceScanner};
pub use span::{Encoding, LineIndex, column};
