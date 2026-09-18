//! The six manifest parsers, across five formats, each with its spans.
//!
//! Each function is pure: source text and a path in, sightings out, no
//! filesystem. A file that will not parse yields nothing rather than an error —
//! a manifest caught mid-save is a normal event in an editor, not a scan
//! failure.

use crate::model::{DEV_GROUP, Ecosystem, ExtractedPackage, Package, Range, Site};
use crate::span::LineIndex;
use jsonc_parser::ast::{Object, ObjectPropName, Value};
use jsonc_parser::{CollectOptions, ParseOptions, parse_to_ast};
use std::path::Path;

/// npm dependency sections, in the order a dependency should be attributed to
/// them: a package in both `dependencies` and `devDependencies` ships.
const NPM_SECTIONS: [(&str, Option<&str>); 4] = [
    ("dependencies", None),
    ("optionalDependencies", Some("optional")),
    ("peerDependencies", Some("peer")),
    ("devDependencies", Some(DEV_GROUP)),
];

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

// ---------------------------------------------------------------- package.json

pub fn package_json(src: &str, path: &Path) -> Vec<ExtractedPackage> {
    let Ok(parsed) = parse_to_ast(src, &CollectOptions::default(), &ParseOptions::default()) else {
        return Vec::new();
    };
    let Some(Value::Object(root)) = parsed.value else {
        return Vec::new();
    };
    let lines = LineIndex::new(src);
    let mut out = Vec::new();

    for (section, group) in NPM_SECTIONS {
        let Some(Value::Object(deps)) = property(&root, section) else {
            continue;
        };
        for prop in &deps.properties {
            let Some((name, range)) = prop_name(&prop.name) else {
                continue;
            };
            let Value::StringLit(constraint) = &prop.value else {
                continue;
            };
            let Some((version, at, to)) = lowest_satisfying(&constraint.value) else {
                continue;
            };
            // The literal's range includes the quotes; the value inside starts
            // one byte in. `value` is the *decoded* string, so an escape would
            // put the span somewhere else in the file — checked, not assumed,
            // since a wrong span here rewrites the wrong bytes.
            let (at, to) = (
                constraint.range.start + 1 + at,
                constraint.range.start + 1 + to,
            );
            let version_span = (src.get(at..to) == Some(version)).then(|| lines.range(at, to));
            out.push(
                sighting(
                    Ecosystem::Npm,
                    name,
                    version,
                    path,
                    lines.range(range.0, range.1),
                    group.map(str::to_owned).into_iter().collect(),
                    // A manifest states a constraint, never an installed version,
                    // so everything here is inferred until a lockfile says otherwise.
                    true,
                )
                .with_version_span(version_span),
            );
        }
    }
    first_per_name(out)
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

// ----------------------------------------------------------- package-lock.json

pub fn package_lock(src: &str, path: &Path) -> Vec<ExtractedPackage> {
    let Ok(parsed) = parse_to_ast(src, &CollectOptions::default(), &ParseOptions::default()) else {
        return Vec::new();
    };
    let Some(Value::Object(root)) = parsed.value else {
        return Vec::new();
    };
    let lines = LineIndex::new(src);

    // lockfileVersion 2 and 3 carry `packages`, keyed by install path. Version 2
    // carries `dependencies` as well, for older npm, so `packages` is preferred
    // and the tree is only read when it is the only thing there.
    if let Some(Value::Object(packages)) = property(&root, "packages") {
        return lock_packages(packages, path, &lines);
    }
    if let Some(Value::Object(deps)) = property(&root, "dependencies") {
        let mut out = Vec::new();
        lock_tree(deps, path, &lines, &mut out);
        return out;
    }
    Vec::new()
}

/// The flat `packages` map of lockfile versions 2 and 3.
///
/// No version span: rewriting a lockfile means rewriting integrity hashes and
/// resolved URLs, so no edit is ever offered against one.
fn lock_packages(packages: &Object<'_>, path: &Path, lines: &LineIndex) -> Vec<ExtractedPackage> {
    let mut out = Vec::new();
    for prop in &packages.properties {
        let Some((key, range)) = prop_name(&prop.name) else {
            continue;
        };
        // The empty key is the project itself, which is not its own dependency.
        let Some(offset) = key.rfind("node_modules/") else {
            continue;
        };
        let name_start = offset + "node_modules/".len();
        let name = &key[name_start..];
        if name.is_empty() {
            continue;
        }
        let Value::Object(entry) = &prop.value else {
            continue;
        };
        let Some(Value::StringLit(version)) = property(entry, "version") else {
            continue;
        };

        // The span covers the package name inside the install path, not the
        // whole `node_modules/...` key.
        let span = lines.range(range.0 + name_start, range.1);
        out.push(sighting(
            Ecosystem::Npm,
            name,
            &version.value,
            path,
            span,
            lock_groups(entry),
            false,
        ));
    }
    out
}

/// The nested `dependencies` tree of lockfile version 1. No version span, for
/// the reason [`lock_packages`] gives.
fn lock_tree(deps: &Object<'_>, path: &Path, lines: &LineIndex, out: &mut Vec<ExtractedPackage>) {
    for prop in &deps.properties {
        let Some((name, range)) = prop_name(&prop.name) else {
            continue;
        };
        let Value::Object(entry) = &prop.value else {
            continue;
        };
        if let Some(Value::StringLit(version)) = property(entry, "version") {
            out.push(sighting(
                Ecosystem::Npm,
                name,
                &version.value,
                path,
                lines.range(range.0, range.1),
                lock_groups(entry),
                false,
            ));
        }
        if let Some(Value::Object(nested)) = property(entry, "dependencies") {
            lock_tree(nested, path, lines, out);
        }
    }
}

fn lock_groups(entry: &Object<'_>) -> Vec<String> {
    let mut groups = Vec::new();
    if matches!(property(entry, "dev"), Some(Value::BooleanLit(b)) if b.value) {
        groups.push(DEV_GROUP.to_owned());
    }
    if matches!(property(entry, "optional"), Some(Value::BooleanLit(b)) if b.value) {
        groups.push("optional".to_owned());
    }
    groups
}

// --------------------------------------------------------------------- go.mod

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

// --------------------------------------------------------------- Cargo.toml

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

// --------------------------------------------------------- requirements.txt

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

// --------------------------------------------------------------------- shared

fn property<'a>(object: &'a Object<'a>, name: &str) -> Option<&'a Value<'a>> {
    object
        .properties
        .iter()
        .find(|p| prop_name(&p.name).is_some_and(|(n, _)| n == name))
        .map(|p| &p.value)
}

/// A property's name and the byte span of the name itself, inside its quotes.
fn prop_name<'a>(name: &'a ObjectPropName<'a>) -> Option<(&'a str, (usize, usize))> {
    match name {
        ObjectPropName::String(s) => {
            // The literal's range includes the quotes; the span should not.
            Some((s.value.as_ref(), (s.range.start + 1, s.range.end - 1)))
        }
        ObjectPropName::Word(w) => Some((w.value, (w.range.start, w.range.end))),
    }
}

/// What every parser must do regardless of the format it reads.
///
/// A table rather than six copies: an edge case found in one format is almost
/// always an edge case in the others, and a per-parser test is a fix that
/// reaches one of them.
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

#[cfg(test)]
mod behaviour {
    use super::*;

    fn at(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from("/p").join(name)
    }

    fn names_and_versions(found: &[ExtractedPackage]) -> Vec<(String, String)> {
        found
            .iter()
            .map(|f| (f.package.name().to_owned(), f.package.version.to_string()))
            .collect()
    }

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

    #[test]
    fn package_json_production_wins_over_dev() {
        // A package migrating between sections appears in both. The diagnostic
        // has to land on one, and the production declaration is the one that
        // ships.
        let src = "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.0\"\n  },\n  \"devDependencies\": {\n    \"lodash\": \"^3.0.0\"\n  }\n}\n";
        let found = package_json(src, &at("package.json"));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].evidence.range.start.line, 2);
        assert!(
            found[0].dep_groups.is_empty(),
            "the production declaration has no group"
        );
    }

    #[test]
    fn package_json_non_dependency_sections_are_ignored() {
        let src = "{\n  \"scripts\": {\n    \"lodash\": \"echo not a dependency\"\n  },\n  \"engines\": {\n    \"node\": \">=18\"\n  }\n}\n";
        assert!(package_json(src, &at("package.json")).is_empty());
    }

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
