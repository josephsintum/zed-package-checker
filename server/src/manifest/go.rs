//! `go.mod`: `require`, `replace` and the `go`/`toolchain` directives.

use super::{offset_in, sighting};
use crate::model::{Ecosystem, ExtractedPackage};
use crate::span::LineIndex;
use std::path::Path;

/// A `replace` directive: which module it rewrites, and to what.
struct Replace<'a> {
    old: &'a str,
    /// `None` replaces every version of `old`.
    old_version: Option<&'a str>,
    /// `None` for a filesystem path, which has no version to look up.
    new: Option<(&'a str, &'a str)>,
}

/// `old [v] => new [v]`, the body of a replace directive.
fn replace_line(body: &str) -> Option<Replace<'_>> {
    let (old, new) = body.split_once("=>")?;
    let mut old = old.split_whitespace();
    let old_path = old.next()?;
    let old_version = old.next().map(|v| v.strip_prefix('v').unwrap_or(v));
    let mut new = new.split_whitespace();
    let new_path = new.next()?;
    let new = new
        .next()
        .map(|v| (new_path, v.strip_prefix('v').unwrap_or(v)));
    Some(Replace {
        old: old_path,
        old_version,
        new,
    })
}

/// Dependencies declared in a `go.mod`.
///
/// The toolchain is reported too, against the `toolchain` directive when there
/// is one and the `go` directive otherwise. The latter is a *minimum*, not the
/// toolchain in use, and the diagnostic says so.
///
/// `replace` directives are applied: the build uses the replacement, so
/// matching the original would report advisories against code that is not
/// there and miss the ones that are. A replacement by filesystem path has no
/// version to look up, and drops the module.
pub fn go_mod(src: &str, path: &Path) -> Vec<ExtractedPackage> {
    let lines = LineIndex::new(src);
    let mut out = Vec::new();
    let mut replaces = Vec::new();
    let mut go_directive = None;
    let mut toolchain = None;
    let mut block: Option<&str> = None;
    let mut offset = 0usize;

    for line in src.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let text = strip_comment(line);
        let trimmed = text.trim();

        if let Some(keyword) = block {
            if trimmed == ")" {
                block = None;
            } else if keyword == "require" {
                out.extend(require_line(text, start, path, &lines));
            } else {
                replaces.extend(replace_line(trimmed));
            }
            continue;
        }

        for keyword in ["require", "replace"] {
            if let Some(rest) = trimmed.strip_prefix(keyword)
                && rest.starts_with(|c: char| c.is_whitespace())
            {
                let rest = rest.trim_start();
                if rest == "(" {
                    block = Some(keyword);
                } else if keyword == "require" {
                    out.extend(require_line(text, start, path, &lines));
                } else {
                    replaces.extend(replace_line(rest));
                }
            }
        }

        // Declaration and version are the same token: `go 1.21` names no
        // package, so pointing at the keyword would underline nothing.
        if let Some(version) = trimmed.strip_prefix("go ")
            && let Some(column) = text.find(version.trim())
        {
            let version = version.trim();
            go_directive = Some((version, start + column));
        }
        if let Some(name) = trimmed.strip_prefix("toolchain ")
            && let Some(column) = text.find(name.trim())
        {
            // `go1.21.5`, or `go1.21.5-something` for a custom build.
            let name = name.trim();
            let version = name.split('-').next().unwrap_or(name);
            let version = version.strip_prefix("go").unwrap_or(version);
            let at = start + column + (name.len() - name.trim_start_matches("go").len());
            toolchain = Some((version, at));
        }
    }

    let mut out: Vec<ExtractedPackage> = out
        .into_iter()
        .filter_map(|found| {
            let applicable = replaces.iter().find(|r| {
                r.old == found.package.name()
                    && r.old_version
                        .is_none_or(|v| v == found.package.version.as_ref())
            });
            match applicable {
                None => Some(found),
                Some(Replace { new: None, .. }) => None,
                Some(Replace {
                    new: Some((name, version)),
                    ..
                }) => Some(sighting(
                    Ecosystem::Go,
                    name,
                    version,
                    path,
                    found.evidence.range,
                    Vec::new(),
                    false,
                )),
            }
        })
        .collect();

    if let Some((version, at)) = toolchain.or(go_directive) {
        let span = lines.range(at, at + version.len());
        out.push(
            sighting(
                Ecosystem::Go,
                crate::model::GO_TOOLCHAIN,
                version,
                path,
                span,
                Vec::new(),
                false,
            )
            .with_version_span(Some(span)),
        );
    }
    out
}

/// One `require` entry, whether standalone or inside a block.
///
/// The module path is located within the line rather than assumed to start it:
/// a require inside a block starts at the module path, a standalone one starts
/// at the `require` keyword.
fn require_line(
    full_line: &str,
    start: usize,
    path: &Path,
    lines: &LineIndex,
) -> Option<ExtractedPackage> {
    let body = full_line.trim_start_matches(|c: char| c.is_whitespace());
    let body = body
        .strip_prefix("require")
        .map(str::trim_start)
        .unwrap_or(body);
    let mut parts = body.split_whitespace();
    let module = parts.next()?;
    let version = parts.next()?;
    if module.is_empty() || module == "(" || !version.starts_with('v') {
        return None;
    }
    let column = full_line.find(module)?;
    // The span starts after the `v`, so a rewrite replaces `v1.2.3` with
    // `v1.4.0` rather than dropping the prefix go.mod requires.
    let version_at = offset_in(full_line, version) + 1;
    let version_span = lines.range(start + version_at, start + version_at + version.len() - 1);
    Some(
        sighting(
            Ecosystem::Go,
            module,
            // OSV records Go versions without the `v` the module file writes.
            &version[1..],
            path,
            lines.range(start + column, start + column + module.len()),
            // `// indirect` is a graph fact, not a dependency group.
            Vec::new(),
            false,
        )
        .with_version_span(Some(version_span)),
    )
}

fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line.trim_end_matches(['\n', '\r']),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::test_support::{at, names_and_versions};

    #[test]
    fn go_mod_replace_substitutes_name_and_version() {
        // The build uses the replacement, so matching the original would
        // report advisories against code that is not there and miss the ones
        // that are.
        let src = "module m\n\nrequire example.com/old v1.0.0\n\nreplace example.com/old => example.com/fork v1.2.0\n";
        let found = go_mod(src, &at("go.mod"));
        assert_eq!(
            names_and_versions(&found),
            [("example.com/fork".into(), "1.2.0".into())]
        );
        // The require line is still where the user acts.
        assert_eq!(found[0].evidence.range.start.line, 2);
        // Rewriting the require's version would not change what is built.
        assert!(found[0].version_span.is_none());
    }

    #[test]
    fn go_mod_replace_with_a_version_applies_only_to_that_version() {
        let src = "module m\n\nrequire example.com/a v1.0.0\n\nreplace example.com/a v2.0.0 => example.com/b v2.1.0\n";
        let found = go_mod(src, &at("go.mod"));
        assert_eq!(
            names_and_versions(&found),
            [("example.com/a".into(), "1.0.0".into())]
        );
    }

    #[test]
    fn go_mod_replace_to_a_local_path_drops_the_module() {
        // A directory has no version to look up, and the advisory for the
        // published module says nothing about a local copy.
        let src = "module m\n\nrequire (\n\texample.com/old v1.0.0\n\texample.com/kept v2.0.0\n)\n\nreplace example.com/old => ../old\n";
        let found = go_mod(src, &at("go.mod"));
        assert_eq!(
            names_and_versions(&found),
            [("example.com/kept".into(), "2.0.0".into())]
        );
    }

    #[test]
    fn go_mod_replace_block_is_read() {
        let src = "module m\n\nrequire example.com/a v1.0.0\n\nreplace (\n\texample.com/a => example.com/b v1.5.0\n)\n";
        let found = go_mod(src, &at("go.mod"));
        assert_eq!(
            names_and_versions(&found),
            [("example.com/b".into(), "1.5.0".into())]
        );
    }

    #[test]
    fn go_mod_toolchain_wins_over_the_go_directive() {
        // `go` is a minimum; `toolchain` is what actually builds the module,
        // and the stdlib advisories apply to that.
        let src = "module m\n\ngo 1.21\n\ntoolchain go1.21.5\n";
        let found = go_mod(src, &at("go.mod"));
        assert_eq!(
            names_and_versions(&found),
            [("stdlib".into(), "1.21.5".into())]
        );
        assert_eq!(
            found[0].evidence.range.start.line, 4,
            "anchored on the toolchain line"
        );
    }

    #[test]
    fn go_mod_module_itself_is_not_a_dependency() {
        let found = go_mod("module example.com/fixture\n\ngo 1.21\n", &at("go.mod"));
        assert!(
            found
                .iter()
                .all(|f| f.package.name() != "example.com/fixture")
        );
    }
}
