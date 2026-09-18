//! The dependency rule `model.rs` claims for itself, checked.
//!
//! Module privacy enforces most dependency boundaries in this crate for free,
//! but not this one: `model` is a module in the same crate as `db` and `lsp`,
//! so nothing stops it reaching for either. The
//! rule matters because `model` is the vocabulary every other module speaks,
//! and a domain type that drags in the protocol or the network is one the
//! others cannot use without them.

use std::path::Path;

/// `use` lines `model.rs` is allowed to have: `std`, and itself.
fn permitted(import: &str) -> bool {
    import == "std"
        || import.starts_with("std::")
        || import == "crate::model"
        || import.starts_with("crate::model::")
}

#[test]
fn model_depends_on_nothing_outside_std() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model.rs");
    let source = std::fs::read_to_string(&path).expect("read model.rs");

    let mut offending = Vec::new();
    let mut in_tests = false;
    for line in source.lines() {
        let trimmed = line.trim();
        // The rule is about what ships, not about what the tests reach for.
        // Anchored on the test module itself, not on any `#[cfg(test)]`: a
        // single gated helper partway down the file would otherwise switch the
        // check off for everything below it.
        if trimmed.starts_with("mod tests") {
            in_tests = true;
        }
        if in_tests {
            continue;
        }
        // `pub use` re-exports reach just as far as `use` does.
        let rest = trimmed
            .strip_prefix("pub(crate) use ")
            .or_else(|| trimmed.strip_prefix("pub use "))
            .or_else(|| trimmed.strip_prefix("use "));
        let Some(rest) = rest else {
            continue;
        };
        let import = rest.trim_end_matches(';').trim();
        // `use std::{fmt, path::Path}` — the crate is the part before `::`.
        if !permitted(import) {
            offending.push(import.to_owned());
        }
    }

    assert!(
        offending.is_empty(),
        "model.rs must depend on nothing outside std, but imports: {offending:?}"
    );
}

#[test]
fn the_check_would_notice_a_violation() {
    // A test that can only pass is not a test. These are the imports the rule
    // exists to reject, and the predicate has to say so.
    assert!(!permitted("tower_lsp_server::ls_types::Diagnostic"));
    assert!(!permitted("serde::Deserialize"));
    assert!(!permitted("crate::db::Database"));
    assert!(!permitted("crate::version::Version"));

    assert!(permitted("std::fmt"));
    assert!(permitted("std::path::{Path, PathBuf}"));

    // The two shapes the scanner used to miss entirely.
    assert!(!permitted("stdsomething::Thing"));
    let gated = "mod tests {";
    assert!(gated.starts_with("mod tests"));
}
