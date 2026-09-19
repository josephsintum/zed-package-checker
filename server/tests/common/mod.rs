//! Shared by the integration tests; `cargo test` compiles it once per test binary.

use std::path::{Path, PathBuf};

/// A project under `testdata/fixtures/`.
pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/fixtures")
        .join(name)
}
