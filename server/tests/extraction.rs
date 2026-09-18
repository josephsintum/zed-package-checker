//! Extraction against the fixture projects under `testdata/`, asserting the
//! exact editor-visible span for every dependency.
//!
//! Positions are zero-based, as LSP wants them, and columns are byte offsets —
//! the encoding the server negotiates when the client allows it.

use package_checker::Extractor;
use package_checker::model::{Ecosystem, ExtractedPackage};
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/fixtures")
        .join(name)
}

/// One extracted package, flattened to what a reader can check by eye:
/// `ecosystem:name@version file line start-end [flags]`.
fn describe(root: &Path, p: &ExtractedPackage) -> String {
    let rel = |path: &Path| {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    };
    let r = p.evidence.range;
    let mut line = format!(
        "{} {} {} {}-{}",
        p.package,
        rel(&p.evidence.path),
        r.start.line,
        r.start.column,
        r.end.column
    );
    if let Some(declared) = &p.declared {
        line.push_str(&format!(
            " declared={} {} {}-{}",
            rel(&declared.path),
            declared.range.start.line,
            declared.range.start.column,
            declared.range.end.column
        ));
    }
    if p.from_range {
        line.push_str(" [from-range]");
    }
    if !p.dep_groups.is_empty() {
        line.push_str(&format!(" [{}]", p.dep_groups.join(",")));
    }
    line
}

fn extract(name: &str) -> Vec<String> {
    let root = fixture(name);
    Extractor::new()
        .extract(&root)
        .expect("fixture extracts")
        .iter()
        .map(|p| describe(&root, p))
        .collect()
}

#[test]
fn go_mod() {
    assert_eq!(
        extract("go-mod"),
        [
            "Go:github.com/gin-gonic/gin@1.6.0 go.mod 5 1-25",
            "Go:gopkg.in/yaml.v2@2.2.2 go.mod 6 1-17",
            // The toolchain is anchored on the version in the `go` directive:
            // that line names no package, so pointing at the keyword would
            // underline nothing useful.
            "Go:stdlib@1.21 go.mod 2 3-7",
        ]
    );
}

#[test]
fn npm_with_a_lockfile_reports_the_locked_version_and_keeps_the_declaration() {
    assert_eq!(
        extract("npm-direct"),
        ["npm:lodash@4.17.15 package-lock.json 13 18-24 \
          declared=package.json 4 5-11"]
    );
}

#[test]
fn npm_without_a_lockfile_infers_from_the_range() {
    assert_eq!(
        extract("npm-nolock"),
        ["npm:lodash@4.17.15 package.json 4 5-11 [from-range]"]
    );
}

#[test]
fn a_lockfile_supersedes_the_range_in_the_manifest() {
    // The manifest says ^4.17.0, the lockfile says 4.17.21. What is installed
    // wins, and the manifest stays as the place to act.
    assert_eq!(
        extract("npm-range-vs-lock"),
        ["npm:lodash@4.17.21 package-lock.json 10 18-24 \
          declared=package.json 4 5-11"]
    );
}

#[test]
fn cargo_reports_the_locked_version_and_keeps_the_declaration() {
    assert_eq!(
        extract("rust-cargo"),
        ["crates.io:time@0.1.44 Cargo.lock 8 8-12 declared=Cargo.toml 6 0-4"]
    );
}

#[test]
fn a_crate_is_not_a_dependency_of_itself() {
    // Cargo.lock lists every [[package]] including the local crate, and nothing
    // in the entry says which one is local; the name comes from Cargo.toml.
    assert!(
        !extract("rust-cargo")
            .iter()
            .any(|p| p.contains("rust-cargo-fixture")),
        "the project's own crate must not be reported"
    );
}

#[test]
fn requirements_get_exact_spans() {
    // The parser that finds the dependency is the one that knows where it is,
    // so even a free-form requirements line gets a name-width span rather than
    // the whole line.
    assert_eq!(
        extract("py-requirements"),
        [
            "PyPI:requests@2.19.1 requirements.txt 1 0-8",
            "PyPI:urllib3@1.24 requirements.txt 3 0-7 [from-range]",
        ]
    );
}

#[test]
fn a_project_is_not_a_dependency_of_itself() {
    let packages = Extractor::new().extract(&fixture("npm-direct")).unwrap();
    assert!(
        !packages
            .iter()
            .any(|p| p.package.name().contains("fixture")),
        "the manifest's own package must not be reported"
    );
}

#[test]
fn every_fixture_yields_only_supported_ecosystems() {
    for name in [
        "go-mod",
        "npm-direct",
        "npm-nolock",
        "npm-range-vs-lock",
        "py-requirements",
        "rust-cargo",
    ] {
        for p in Extractor::new().extract(&fixture(name)).unwrap() {
            assert!(
                matches!(
                    p.package.ecosystem(),
                    Ecosystem::Npm | Ecosystem::Go | Ecosystem::PyPI | Ecosystem::CratesIo
                ),
                "{name}: unexpected ecosystem for {}",
                p.package
            );
        }
    }
}
