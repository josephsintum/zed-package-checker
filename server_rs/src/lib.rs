//! A language server that flags vulnerable and malicious dependencies.
//!
//! The Rust half of a controlled experiment against the Go server in `server/`:
//! same behaviour, same advisory archives, same fixtures, different language.
//! `docs/RUST-VS-GO.md` holds what the comparison found.

pub mod alloc;
mod db;
mod diagnostics;
mod engine;
mod extract;
mod digits;
mod index;
mod load;
mod lsp;
mod manifest;
mod matcher;
mod scan;
mod osv;
mod pypi;
mod semver_like;
mod span;

pub mod model;
pub mod version;

pub use db::{default_root, Database, DbError, Progress};
pub use index::Index;
pub use matcher::Matcher;
pub use lsp::Backend;
pub use scan::{ScanError, WorkspaceScanner};
pub use engine::{DEFAULT_DEBOUNCE, Engine, Publisher, Reason, Requester, Scanner};
pub use extract::{ExtractError, Extractor};
pub use span::{Encoding, LineIndex, column};
pub use load::{load, ArchiveStats, LoadError, Strategy};
