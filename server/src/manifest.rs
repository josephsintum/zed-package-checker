//! The six manifest parsers, across five formats, each with its spans.
//!
//! Each function is pure: source text and a path in, sightings out, no
//! filesystem. A file that will not parse yields nothing rather than an error —
//! a manifest caught mid-save is a normal event in an editor, not a scan
//! failure.

use crate::model::{Ecosystem, ExtractedPackage, Package, Range, Site};
use std::path::Path;

mod cargo;
mod go;
pub(crate) mod npm;
mod python;

pub use cargo::{cargo_lock, cargo_self, cargo_toml};
pub use go::go_mod;
pub(crate) use npm::declarations;
pub use npm::{package_json, package_lock};
pub use python::{requirement_includes, requirements};

/// What every manifest parser is: source text and a path in, sightings out.
pub type Parser = fn(&str, &Path) -> Vec<ExtractedPackage>;

fn sighting(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    path: &Path,
    range: Range,
    dep_groups: Vec<String>,
    from_range: bool,
) -> ExtractedPackage {
    ExtractedPackage {
        package: Package::new(ecosystem, name, version),
        evidence: Site::new(path, range),
        declared: None,
        dep_groups,
        from_range,
        // Set by `with_version_span` where the version can be rewritten.
        version_span: None,
        // Set by `with_paths`, from the graph. A parser sees one file and
        // cannot know what reaches a package.
        paths: Vec::new(),
    }
}

/// Keeps the first sighting of each package, so a package declared in several
/// sections is attributed to the one that ships. Callers emit sections in
/// preference order.
fn first_per_name(found: Vec<ExtractedPackage>) -> Vec<ExtractedPackage> {
    let mut seen = std::collections::HashSet::new();
    found
        .into_iter()
        .filter(|f| seen.insert(f.package.key.clone()))
        .collect()
}

/// Byte offset of a subslice within the string it was sliced from.
///
/// Pointer arithmetic rather than a search: searching finds the wrong
/// occurrence whenever a package name contains its own version text.
fn offset_in(whole: &str, part: &str) -> usize {
    debug_assert!(part.as_ptr() as usize >= whole.as_ptr() as usize);
    part.as_ptr() as usize - whole.as_ptr() as usize
}

/// The lowest version a constraint admits, which is what is scanned when there
/// is no lockfile to say what is installed, and its byte span within the
/// constraint.
///
/// `^4.17.15` becomes `4.17.15`. Anything naming a protocol rather than a
/// version — `workspace:*`, `file:../x`, a git URL — is not a version at all and
/// yields nothing, because the digits inside a URL are not a version number.
///
/// The span covers the digits alone. Leaving the operator out is what lets
/// `>=1.0.0 <2.0.0` be bumped to `>=1.4.0 <2.0.0` rather than losing its upper
/// bound, and means no operator ever has to be reconstructed.
fn lowest_satisfying(constraint: &str) -> Option<(&str, usize, usize)> {
    let lead = constraint.len() - constraint.trim_start().len();
    let constraint = constraint.trim();
    if constraint.contains(':') || constraint.contains('/') {
        return None;
    }
    let start = constraint.find(|c: char| c.is_ascii_digit())?;
    // Only a leading operator may precede the version; `>=1.2.3` is a range,
    // `node16` is not a version.
    if !constraint[..start]
        .chars()
        .all(|c| matches!(c, '^' | '~' | '>' | '<' | '=' | 'v' | ' '))
    {
        return None;
    }
    let end = constraint[start..]
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+')))
        .map(|i| start + i)
        .unwrap_or(constraint.len());
    Some((&constraint[start..end], lead + start, lead + end))
}

/// Helpers the per-format tests share.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::model::ExtractedPackage;
    use std::path::PathBuf;

    pub(crate) fn at(name: &str) -> PathBuf {
        PathBuf::from("/p").join(name)
    }

    pub(crate) fn names_and_versions(found: &[ExtractedPackage]) -> Vec<(String, String)> {
        found
            .iter()
            .map(|f| (f.package.name().to_owned(), f.package.version.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod conformance {
    use super::*;

    const PACKAGE_JSON: &str =
        "{\n  \"name\": \"p\",\n  \"dependencies\": {\n    \"lodash\": \"4.17.15\"\n  }\n}\n";
    const PACKAGE_LOCK: &str = "{\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"node_modules/lodash\": {\n      \"version\": \"4.17.15\"\n    }\n  }\n}\n";
    const GO_MOD: &str = "module example.com/p\n\nrequire github.com/gin-gonic/gin v1.6.0\n";
    const CARGO_TOML: &str = "[package]\nname = \"p\"\n\n[dependencies]\ntime = \"0.1.44\"\n";
    const CARGO_LOCK: &str = "version = 3\n\n[[package]]\nname = \"time\"\nversion = \"0.1.44\"\n";
    const REQUIREMENTS: &str = "requests==2.19.1\n";

    /// Every parser, with the file it serves and a sample naming one package.
    const PARSERS: &[(&str, Parser, &str)] = &[
        ("package.json", package_json as Parser, PACKAGE_JSON),
        ("package-lock.json", package_lock, PACKAGE_LOCK),
        ("go.mod", go_mod, GO_MOD),
        ("Cargo.toml", cargo_toml, CARGO_TOML),
        ("Cargo.lock", cargo_lock, CARGO_LOCK),
        ("requirements.txt", requirements, REQUIREMENTS),
    ];

    fn path_for(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from("/p").join(name)
    }

    /// A position back to the byte offset it came from. Columns are byte
    /// offsets within the line at this stage — the UTF-16 conversion happens
    /// later, in `diagnostics` — so this is just the line start plus the column.
    fn offset_of(src: &str, position: crate::model::Position) -> usize {
        let line_start: usize = src
            .split_inclusive('\n')
            .take(position.line as usize)
            .map(str::len)
            .sum();
        line_start + position.column as usize
    }

    #[test]
    fn every_sample_names_exactly_one_package() {
        // Not a property of the parsers so much as of the table: a sample that
        // stopped parsing would make every test below vacuous.
        for (name, parse, sample) in PARSERS {
            let found = parse(sample, &path_for(name));
            assert_eq!(found.len(), 1, "{name} found {found:?}");
        }
    }

    #[test]
    fn empty_input_yields_nothing() {
        for (name, parse, _) in PARSERS {
            for src in ["", "\n", "\n\n\n", "   ", "\r\n"] {
                assert!(
                    parse(src, &path_for(name)).is_empty(),
                    "{name} found something in {src:?}"
                );
            }
        }
    }

    #[test]
    fn hostile_input_yields_nothing_rather_than_panicking() {
        // The parsers are the only part of this server reading attacker-chosen
        // bytes, and the binary aborts on panic — so a panic here is the whole
        // language server, not one bad file.
        let hostile: Vec<String> = vec![
            "\0".into(),
            "{".into(),
            "[".into(),
            "=".into(),
            "[[".into(),
            "\u{feff}".into(),
            "\"".repeat(10_000),
            "\\\n".repeat(1_000),
            "[".repeat(600),
            "{\"a\":".repeat(600),
            "x".repeat(1_000_000),
            "require (".into(),
            "[[package]]".into(),
        ];
        for (name, parse, _) in PARSERS {
            for src in &hostile {
                let found = parse(src, &path_for(name));
                assert!(
                    found.is_empty(),
                    "{name} found {} package(s) in hostile input",
                    found.len()
                );
            }
        }
    }

    #[test]
    fn crlf_reads_the_same_as_lf() {
        // Every parser trims line endings somewhere, and a branch that forgets
        // to would leave a version ending in \r or a span one column wide.
        for (name, parse, sample) in PARSERS {
            let unix = parse(sample, &path_for(name));
            let dos = parse(&sample.replace('\n', "\r\n"), &path_for(name));
            assert_eq!(unix.len(), dos.len(), "{name}: count differs under CRLF");
            for (a, b) in unix.iter().zip(&dos) {
                assert_eq!(a.package, b.package, "{name}: package differs under CRLF");
                assert_eq!(
                    a.evidence.range, b.evidence.range,
                    "{name}: span differs under CRLF"
                );
            }
        }
    }

    #[test]
    fn every_span_lies_within_the_source_and_covers_an_identifier() {
        // Weakened to "name or version" on purpose: go.mod anchors the
        // toolchain sighting on the version, because `go 1.21` names no
        // package. Still catches an off-by-one or an out-of-bounds span.
        for (name, parse, sample) in PARSERS {
            for found in parse(sample, &path_for(name)) {
                let range = found.evidence.range;
                let start = offset_of(sample, range.start);
                let end = offset_of(sample, range.end);
                assert!(start <= end, "{name}: inverted span {range:?}");
                assert!(end <= sample.len(), "{name}: span past the end of {name}");

                let covered = &sample[start..end];
                assert!(
                    covered == found.package.name() || covered == &*found.package.version,
                    "{name}: span covers {covered:?}, not {} or {}",
                    found.package.name(),
                    found.package.version
                );
            }
        }
    }

    #[test]
    fn a_deeply_nested_lockfile_does_not_overflow_the_stack() {
        // `lock_tree` recurses once per level of a v1 lockfile's nested
        // `dependencies`, with no depth limit of its own — it is safe only
        // because jsonc-parser refuses to build an AST past 512 levels. That is
        // a dependency's constant, so this pins it: a bump that removes it
        // turns this red rather than turning the server into an abort.
        let depth = 600;
        let mut src = String::from("{\"dependencies\":");
        for _ in 0..depth {
            src.push_str("{\"a\":{\"version\":\"1.0.0\",\"dependencies\":");
        }
        src.push_str("{}");
        for _ in 0..depth {
            src.push_str("}}");
        }
        src.push('}');

        let found = package_lock(&src, &path_for("package-lock.json"));
        assert!(
            found.is_empty(),
            "a lockfile nested past the parser's limit must yield nothing, got {}",
            found.len()
        );

        // And the same shape within the limit does parse, so the test above is
        // measuring the limit rather than a malformed string.
        let mut shallow = String::from("{\"dependencies\":");
        for _ in 0..8 {
            shallow.push_str("{\"a\":{\"version\":\"1.0.0\",\"dependencies\":");
        }
        shallow.push_str("{}");
        for _ in 0..8 {
            shallow.push_str("}}");
        }
        shallow.push('}');
        assert_eq!(
            package_lock(&shallow, &path_for("package-lock.json")).len(),
            8
        );
    }

    #[test]
    fn parsing_is_deterministic() {
        for (name, parse, sample) in PARSERS {
            assert_eq!(
                parse(sample, &path_for(name)),
                parse(sample, &path_for(name)),
                "{name} is not deterministic"
            );
        }
    }

    #[test]
    fn the_path_is_echoed_never_inspected() {
        // The module's stated contract: source text and a path in, no
        // filesystem. None of these paths exists.
        for (_, parse, sample) in PARSERS {
            let path = Path::new("/nonexistent/deeply/nested/file");
            for found in parse(sample, path) {
                assert_eq!(found.evidence.path, path);
            }
        }
    }
    /// The byte range a span covers, for slicing the source back out.
    fn slice(src: &str, range: crate::model::Range) -> &str {
        &src[offset_of(src, range.start)..offset_of(src, range.end)]
    }

    #[test]
    fn a_version_span_covers_exactly_the_version_it_reported() {
        // The invariant the upgrade quick fix rests on: replacing the span with
        // a new version must leave everything around it — quotes, operators,
        // go.mod's `v` — untouched.
        for (name, parse, sample) in PARSERS {
            for found in parse(sample, &path_for(name)) {
                let Some(span) = found.version_span else {
                    continue;
                };
                assert_eq!(
                    slice(sample, span),
                    found.package.version.as_ref(),
                    "{name} span covers the wrong text"
                );
            }
        }
    }

    #[test]
    fn lockfiles_offer_no_version_span() {
        // Rewriting a lockfile means rewriting integrity hashes and resolved
        // URLs, so no edit is ever offered against one.
        for (name, parse, sample) in PARSERS {
            if !name.contains("lock") {
                continue;
            }
            for found in parse(sample, &path_for(name)) {
                assert!(found.version_span.is_none(), "{name} offered a span");
            }
        }
    }

    #[test]
    fn a_span_excludes_the_operator_so_a_bound_survives_a_bump() {
        let src = "{\n  \"dependencies\": {\n    \"a\": \"^4.17.0\",\n    \"b\": \">=1.0.0 <2.0.0\"\n  }\n}\n";
        let found = package_json(src, &path_for("package.json"));
        let spans: Vec<&str> = found
            .iter()
            .map(|f| slice(src, f.version_span.unwrap()))
            .collect();
        assert_eq!(spans, vec!["4.17.0", "1.0.0"]);
    }

    #[test]
    fn a_cargo_span_excludes_the_operator_too() {
        let src = "[dependencies]\nserde = \"^1.0.1\"\ntime = { version = \">=0.1.44\", features = [] }\n";
        let found = cargo_toml(src, &path_for("Cargo.toml"));
        let spans: Vec<&str> = found
            .iter()
            .map(|f| slice(src, f.version_span.unwrap()))
            .collect();
        assert_eq!(spans, vec!["1.0.1", "0.1.44"]);
    }

    #[test]
    fn a_go_span_starts_after_the_v() {
        let src = "require (\n\tgithub.com/x/y v1.6.0 // indirect\n)\n";
        let found = go_mod(src, &path_for("go.mod"));
        assert_eq!(slice(src, found[0].version_span.unwrap()), "1.6.0");
    }

    #[test]
    fn a_continued_requirement_withholds_its_span() {
        // Joined lines are reassembled into a new string, so offsets past the
        // first physical line no longer refer to the file.
        let src = "requests==2.19.1\nflask\\\n==1.0.0\n";
        let found = requirements(src, &path_for("requirements.txt"));
        assert_eq!(found.len(), 2);
        assert_eq!(slice(src, found[0].version_span.unwrap()), "2.19.1");
        assert!(found[1].version_span.is_none());
    }
}
