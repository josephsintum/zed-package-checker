//! `requirements.txt`: PEP 508 lines, continuations, `-r` includes.

use super::{offset_in, sighting};
use crate::model::{Ecosystem, ExtractedPackage};
use crate::span::LineIndex;
use std::path::Path;

/// PEP 508 requirement lines.
///
/// Only the shapes that name a version matter here: an unpinned requirement has
/// nothing to look up. Editable installs and `-r` includes are skipped, the
/// latter because the walker finds those files on its own.
pub fn requirements(src: &str, path: &Path) -> Vec<ExtractedPackage> {
    let lines = LineIndex::new(src);
    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut pending = String::new();
    let mut pending_start = 0usize;

    for line in src.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let text = line.trim_end_matches(['\n', '\r']);

        // A trailing backslash continues the requirement onto the next line.
        if let Some(head) = text.strip_suffix('\\') {
            if pending.is_empty() {
                pending_start = start;
            }
            pending.push_str(head);
            continue;
        }
        let (whole, whole_start) = if pending.is_empty() {
            (text.to_owned(), start)
        } else {
            pending.push_str(text);
            (std::mem::take(&mut pending), pending_start)
        };

        // `whole` is a fresh string when lines were joined, so its offsets no
        // longer refer to the file. The evidence span already drifts here; the
        // version span is simply withheld rather than pointing somewhere wrong.
        let contiguous = whole_start == start;
        if let Some(found) = requirement(&whole, whole_start, path, &lines, contiguous) {
            out.push(found);
        }
    }
    out
}

fn requirement(
    line: &str,
    start: usize,
    path: &Path,
    lines: &LineIndex,
    contiguous: bool,
) -> Option<ExtractedPackage> {
    // Comments, options and includes.
    let body = line.split('#').next()?.trim_end();
    let trimmed = body.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('-') {
        return None;
    }
    // Environment markers do not affect which package is named.
    let body = trimmed.split(';').next()?;

    let name_end = body
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(body.len());
    let name = &body[..name_end];
    if name.is_empty() {
        return None;
    }

    let rest = body[name_end..].trim_start();
    // Extras are part of the requirement, not of the package name.
    let rest = match rest.strip_prefix('[') {
        Some(after) => after.split_once(']').map(|(_, r)| r.trim_start())?,
        None => rest,
    };

    // A version guessed from an upper bound, an exclusion or a wildcard would
    // be a false positive; only a lower bound or a pin is worth a lookup.
    if unsupported_constraint(rest) {
        return None;
    }
    let (comparator, version) = specifier(rest)?;
    let column = line.find(name)?;

    let version_span = contiguous.then(|| {
        let at = start + offset_in(line, version);
        lines.range(at, at + version.len())
    });
    Some(
        sighting(
            Ecosystem::PyPI,
            name,
            version,
            path,
            lines.range(start + column, start + column + name.len()),
            Vec::new(),
            // Only `==` and `===` name an installed version; everything else is a
            // constraint whose lowest satisfying version is a guess.
            !matches!(comparator, "==" | "==="),
        )
        .with_version_span(version_span),
    )
}

/// Whether a specifier names no single lowest version: a wildcard, an
/// exclusion, an upper bound alone, or a list.
fn unsupported_constraint(spec: &str) -> bool {
    spec.contains('*')
        || spec.contains(',')
        || spec.contains("!=")
        || spec
            .match_indices('<')
            .any(|(i, _)| spec.as_bytes().get(i + 1) != Some(&b'='))
}

/// The files a requirements file pulls in with `-r`, as written.
///
/// Listed rather than read here, because the parsers touch no filesystem; the
/// extractor resolves and follows them.
pub fn requirement_includes(src: &str) -> Vec<String> {
    src.lines()
        .filter_map(|line| {
            let line = line.split('#').next()?.trim();
            line.strip_prefix("-r ")
                .or_else(|| line.strip_prefix("--requirement "))
                .or_else(|| line.strip_prefix("--requirement="))
        })
        .map(|target| target.trim().to_owned())
        .filter(|target| !target.is_empty())
        .collect()
}

/// The first version specifier in a requirement, as (comparator, version).
fn specifier(rest: &str) -> Option<(&str, &str)> {
    let comparator_len = rest
        .find(|c: char| !matches!(c, '=' | '<' | '>' | '!' | '~'))
        .filter(|&n| n > 0)?;
    let (comparator, tail) = rest.split_at(comparator_len);
    let tail = tail.trim_start();
    let end = tail
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '!' | '*')))
        .unwrap_or(tail.len());
    let version = &tail[..end];
    if version.is_empty() {
        return None;
    }
    Some((comparator, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::test_support::{at, names_and_versions};

    #[test]
    fn requirements_of_only_comments_yield_nothing() {
        assert!(requirements("# nothing here\n\n  \n", &at("requirements.txt")).is_empty());
    }

    #[test]
    fn requirements_with_unsupported_constraints_name_no_version() {
        // A version guessed from an upper bound, an exclusion or a wildcard is
        // a false positive; only a lower bound or a pin is worth a lookup.
        let src = "requests<2.0\nflask!=1.0\nnumpy==*\ndjango>=1,<2\nkept>=1.0\npinned==2.0\n";
        let found = requirements(src, &at("requirements.txt"));
        assert_eq!(
            names_and_versions(&found),
            [
                ("kept".into(), "1.0".into()),
                ("pinned".into(), "2.0".into())
            ]
        );
    }

    #[test]
    fn requirement_includes_are_listed() {
        let src =
            "-r base.txt\n--requirement ../shared/common.txt\n-c constraints.txt\nrequests==2.0\n";
        assert_eq!(
            requirement_includes(src),
            ["base.txt", "../shared/common.txt"]
        );
    }
}
