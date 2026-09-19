//! Extraction against the fixture projects under `testdata/`, asserting the
//! exact editor-visible span for every dependency.
//!
//! Positions are zero-based, as LSP wants them, and columns are byte offsets —
//! the encoding the server negotiates when the client allows it.

// Test helpers may panic: a failed setup is a failed test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use package_checker::Extractor;
mod common;

use common::fixture;
use package_checker::model::{Ecosystem, ExtractedPackage};
use std::path::Path;

/// One extracted package, flattened to what a reader can check by eye:
/// `ecosystem:name@version file line start-end [via=a>b] [flags]`.
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
    if let Some(path) = p.paths.iter().min_by_key(|path| path.len()) {
        // The chain ends with the package itself, which the line already names.
        let hops: Vec<&str> = path
            .split_last()
            .map(|(_, hops)| hops.iter().map(|key| &*key.name).collect())
            .unwrap_or_default();
        line.push_str(&format!(" via={}", hops.join(">")));
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
fn a_transitive_dependency_is_anchored_on_what_pulled_it_in() {
    // Nothing in package.json names `minimist` or `mkdirp`; the project
    // depends on `tar`. Columns 5-8 are the `tar` line, which is the only one
    // of the three a reader of this project can edit.
    assert_eq!(
        extract("npm-transitive"),
        [
            "npm:minimist@1.2.0 package-lock.json 25 18-26 \
             declared=package.json 4 5-8 via=tar>mkdirp",
            "npm:mkdirp@0.5.1 package-lock.json 19 18-24 \
             declared=package.json 4 5-8 via=tar",
            "npm:tar@4.4.0 package-lock.json 13 18-21 declared=package.json 4 5-8",
        ]
    );
}

#[test]
fn a_workspace_member_owns_what_it_reaches_rather_than_the_root() {
    // One lockfile at the root, one manifest per member. `cookie` is hoisted to
    // the root's `node_modules` and named by nobody, but only `packages/api`
    // reaches it — so that is where it lands, not on the root package.json.
    assert_eq!(
        extract("npm-workspaces"),
        [
            "npm:cookie@0.4.0 package-lock.json 35 18-24 \
             declared=packages/api/package.json 4 5-12 via=express",
            "npm:express@4.17.1 package-lock.json 38 18-25 \
             declared=packages/api/package.json 4 5-12",
            "npm:lodash@4.17.15 package-lock.json 44 18-24 \
             declared=packages/web/package.json 4 5-11",
        ]
    );
}

#[test]
fn a_version_one_lockfile_attributes_from_its_requires_map() {
    // v1 nests rather than listing install paths, and writes no entry for the
    // project itself. Same attribution once it is normalised.
    assert_eq!(
        extract("npm-lock-v1"),
        [
            "npm:minimist@1.2.0 package-lock.json 12 5-13 \
             declared=package.json 4 5-11 via=mkdirp",
            "npm:mkdirp@0.5.1 package-lock.json 6 5-11 declared=package.json 4 5-11",
        ]
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

