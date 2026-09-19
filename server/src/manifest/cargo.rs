//! `Cargo.toml` and `Cargo.lock`.

use super::{first_per_name, lowest_satisfying, offset_in, sighting};
use crate::model::{DEV_GROUP, Ecosystem, ExtractedPackage};
use crate::span::LineIndex;
use std::path::Path;

/// Dependency tables, in the order a crate is attributed to them when it
/// appears in more than one.
///
/// Matched on the header's last dotted component, so a target-specific table
/// such as `[target.'cfg(unix)'.dependencies]` is recognised. A sub-table like
/// `[dependencies.serde]` is not.
const CARGO_SECTIONS: [(&str, Option<&str>); 3] = [
    ("dependencies", None),
    ("build-dependencies", Some("build")),
    ("dev-dependencies", Some(DEV_GROUP)),
];

/// Dependencies declared in a `Cargo.toml`.
///
/// Line-based rather than parsed: a TOML decoder hands back values without
/// telling you where they were written, and the position is the point. Only the
/// shapes that carry a version are read.
pub fn cargo_toml(src: &str, path: &Path) -> Vec<ExtractedPackage> {
    let lines = LineIndex::new(src);
    // Collected per section so the preference order can be applied afterwards,
    // rather than depending on how the file happens to be ordered.
    let mut found: Vec<Vec<ExtractedPackage>> = vec![Vec::new(); CARGO_SECTIONS.len()];

    let mut section: Option<usize> = None;
    let mut offset = 0usize;

    for raw in src.split_inclusive('\n') {
        let start = offset;
        offset += raw.len();
        let line = trim_toml_comment(raw);
        let trimmed = line.trim();

        if trimmed.starts_with('[') {
            section = cargo_section(trimmed);
            continue;
        }
        let Some(index) = section else { continue };
        let Some((name, name_span, version)) = cargo_dependency(line) else {
            continue;
        };
        // A Cargo version is a requirement string, so the span is narrowed to
        // the digits the same way npm's is: `">=1.0, <2.0"` keeps its upper
        // bound when the lower one is bumped.
        let version_at = start + offset_in(line, version);
        let version_span =
            lowest_satisfying(version).map(|(_, a, b)| lines.range(version_at + a, version_at + b));
        found[index].push(
            sighting(
                Ecosystem::CratesIo,
                name,
                version,
                path,
                lines.range(start + name_span.0, start + name_span.1),
                CARGO_SECTIONS[index]
                    .1
                    .map(str::to_owned)
                    .into_iter()
                    .collect(),
                // Cargo versions are constraints — `"0.1.44"` means `^0.1.44` — so
                // what is installed comes from the lockfile, never from here.
                true,
            )
            .with_version_span(version_span),
        );
    }
    first_per_name(found.into_iter().flatten().collect())
}

/// The crate a `Cargo.toml` declares as its own, so a project is not reported
/// as a dependency of itself.
///
/// A workspace root carries `[workspace]` and no `[package]`, and yields None.
pub fn cargo_self(src: &str) -> Option<String> {
    let mut in_package = false;
    for raw in src.lines() {
        let line = trim_toml_comment(raw);
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed.trim_matches(['[', ']']).trim() == "package";
            continue;
        }
        if in_package
            && let Some(rest) = trimmed.strip_prefix("name")
            && let Some(value) = rest.trim_start().strip_prefix('=')
            && let Some((start, end)) = first_quoted(value)
        {
            return Some(value[start..end].to_owned());
        }
    }
    None
}

/// Locked crate versions from a `Cargo.lock`. No version span, for the reason
/// [`lock_packages`] gives.
pub fn cargo_lock(src: &str, path: &Path) -> Vec<ExtractedPackage> {
    let lines = LineIndex::new(src);
    let mut out = Vec::new();

    let mut name: Option<(String, (usize, usize))> = None;
    let mut version: Option<String> = None;
    let mut offset = 0usize;

    // Each `[[package]]` opens a record; it is emitted when the next one opens
    // or the file ends, because name and version arrive on separate lines.
    let mut flush = |name: &mut Option<(String, (usize, usize))>, version: &mut Option<String>| {
        if let (Some((crate_name, span)), Some(v)) = (name.take(), version.take()) {
            out.push(sighting(
                Ecosystem::CratesIo,
                &crate_name,
                &v,
                path,
                lines.range(span.0, span.1),
                Vec::new(),
                false,
            ));
        }
    };

    for raw in src.split_inclusive('\n') {
        let start = offset;
        offset += raw.len();
        let line = trim_toml_comment(raw);
        let trimmed = line.trim();

        if trimmed.starts_with("[[") {
            flush(&mut name, &mut version);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("name")
            && let Some(value) = rest.trim_start().strip_prefix('=')
            && let Some((a, b)) = first_quoted(value)
        {
            let at = line.len() - value.len();
            name = Some((value[a..b].to_owned(), (start + at + a, start + at + b)));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("version")
            && let Some(value) = rest.trim_start().strip_prefix('=')
            && let Some((a, b)) = first_quoted(value)
        {
            version = Some(value[a..b].to_owned());
        }
    }
    flush(&mut name, &mut version);
    out
}

/// The dependency table a header names, as an index into `CARGO_SECTIONS`.
fn cargo_section(header: &str) -> Option<usize> {
    let name = header.trim_matches(['[', ']']);
    let name = name.rsplit('.').next().unwrap_or(name).trim();
    CARGO_SECTIONS
        .iter()
        .position(|(section, _)| *section == name)
}

/// One `crate = ...` line, as (name, span of the name, version).
///
/// Both spellings are handled: a bare `time = "0.1.44"` and an inline table
/// `serde = { version = "1.0", features = [...] }`. A renamed dependency —
/// `fast = { package = "real-crate" }` — is keyed by the crate actually
/// depended on, since that is what an advisory names.
fn cargo_dependency(line: &str) -> Option<(&str, (usize, usize), &str)> {
    let eq = line.find('=')?;
    let key = &line[..eq];
    let name_start = key.len() - key.trim_start().len();
    let name_end = key.trim_end().len();
    if name_end <= name_start {
        return None;
    }
    let name = line[name_start..name_end].trim_matches(['"', '\'']);
    if name.is_empty() || name.contains(['[', ']', '{', '}', ' ']) {
        return None;
    }

    let value = &line[eq + 1..];
    let version = match quoted_after(value, "version") {
        Some((a, b)) => &value[a..b],
        // A bare string is the version; a table without one declares a path or
        // git dependency, which has no version to look up.
        None if !value.contains('{') => {
            let (a, b) = first_quoted(value)?;
            &value[a..b]
        }
        None => return None,
    };
    if version.is_empty() {
        return None;
    }

    let name = match quoted_after(value, "package") {
        Some((a, b)) => &value[a..b],
        None => name,
    };
    Some((name, (name_start, name_end), version))
}

/// The quoted value of `key = "..."` inside an inline table.
fn quoted_after(s: &str, key: &str) -> Option<(usize, usize)> {
    let mut at = 0usize;
    while let Some(found) = s[at..].find(key) {
        let index = at + found;
        let rest = &s[index + key.len()..];
        let trimmed = rest.trim_start();
        if let Some(after_eq) = trimmed.strip_prefix('=') {
            let base = s.len() - after_eq.len();
            let (a, b) = first_quoted(after_eq)?;
            return Some((base + a, base + b));
        }
        at = index + 1;
    }
    None
}

/// The contents of the first quoted string in s, as byte offsets into it.
fn first_quoted(s: &str) -> Option<(usize, usize)> {
    let open = s.find(['"', '\''])?;
    let quote = s.as_bytes()[open];
    let close = s[open + 1..].bytes().position(|b| b == quote)?;
    Some((open + 1, open + 1 + close))
}

/// Drops a trailing TOML comment, leaving one inside a string alone.
fn trim_toml_comment(line: &str) -> &str {
    let mut quote: Option<u8> = None;
    for (i, b) in line.bytes().enumerate() {
        match quote {
            Some(open) if b == open => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'#' => return &line[..i],
            None => {}
        }
    }
    line.trim_end_matches(['\n', '\r'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::test_support::at;

    #[test]
    fn cargo_toml_ignores_the_package_table() {
        // [package] names the project, not something it depends on.
        let src = "[package]\nname = \"fixture\"\nversion = \"1.0.0\"\n";
        assert!(cargo_toml(src, &at("Cargo.toml")).is_empty());
    }

    #[test]
    fn cargo_toml_prefers_the_production_declaration() {
        let src = "[dev-dependencies]\ntime = \"0.2\"\n\n[dependencies]\ntime = \"0.1.44\"\n";
        let found = cargo_toml(src, &at("Cargo.toml"));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].evidence.range.start.line, 4);
        assert!(found[0].dep_groups.is_empty());
    }
}
