//! The four manifest formats, parsed with their spans.
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
    }
}

// ---------------------------------------------------------------- package.json

pub fn package_json(src: &str, path: &Path) -> Vec<ExtractedPackage> {
    let Ok(parsed) = parse_to_ast(src, &CollectOptions::default(), &ParseOptions::default())
    else {
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
            let Some((name, range)) = prop_name(&prop.name) else { continue };
            let Value::StringLit(constraint) = &prop.value else { continue };
            let Some(version) = lowest_satisfying(&constraint.value) else { continue };
            out.push(sighting(
                Ecosystem::Npm,
                name,
                version,
                path,
                lines.range(range.0, range.1),
                group.map(str::to_owned).into_iter().collect(),
                // A manifest states a constraint, never an installed version,
                // so everything here is inferred until a lockfile says otherwise.
                true,
            ));
        }
    }
    out
}


/// The lowest version a constraint admits, which is what is scanned when there
/// is no lockfile to say what is installed.
///
/// `^4.17.15` becomes `4.17.15`. Anything naming a protocol rather than a
/// version — `workspace:*`, `file:../x`, a git URL — is not a version at all and
/// yields nothing, because the digits inside a URL are not a version number.
fn lowest_satisfying(constraint: &str) -> Option<&str> {
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
    Some(&constraint[start..end])
}

// ----------------------------------------------------------- package-lock.json

pub fn package_lock(src: &str, path: &Path) -> Vec<ExtractedPackage> {
    let Ok(parsed) = parse_to_ast(src, &CollectOptions::default(), &ParseOptions::default())
    else {
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
fn lock_packages(packages: &Object<'_>, path: &Path, lines: &LineIndex) -> Vec<ExtractedPackage> {
    let mut out = Vec::new();
    for prop in &packages.properties {
        let Some((key, range)) = prop_name(&prop.name) else { continue };
        // The empty key is the project itself, which is not its own dependency.
        let Some(offset) = key.rfind("node_modules/") else { continue };
        let name_start = offset + "node_modules/".len();
        let name = &key[name_start..];
        if name.is_empty() {
            continue;
        }
        let Value::Object(entry) = &prop.value else { continue };
        let Some(Value::StringLit(version)) = property(entry, "version") else { continue };

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

/// The nested `dependencies` tree of lockfile version 1.
fn lock_tree(
    deps: &Object<'_>,
    path: &Path,
    lines: &LineIndex,
    out: &mut Vec<ExtractedPackage>,
) {
    for prop in &deps.properties {
        let Some((name, range)) = prop_name(&prop.name) else { continue };
        let Value::Object(entry) = &prop.value else { continue };
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

/// The Go toolchain, reported against the `go` directive.
///
/// That directive is a *minimum*, not the toolchain in use, and the diagnostic
/// says so.
pub fn go_mod(src: &str, path: &Path) -> Vec<ExtractedPackage> {
    let lines = LineIndex::new(src);
    let mut out = Vec::new();
    let mut in_require_block = false;
    let mut offset = 0usize;

    for line in src.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let text = strip_comment(line);
        let trimmed = text.trim();

        if in_require_block {
            if trimmed == ")" {
                in_require_block = false;
                continue;
            }
            if let Some(found) = require_line(text, start, path, &lines) {
                out.push(found);
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("require") {
            let rest = rest.trim_start();
            if rest == "(" {
                in_require_block = true;
            } else if let Some(found) = require_line(text, start, path, &lines) {
                out.push(found);
            }
            continue;
        }

        if let Some(version) = trimmed.strip_prefix("go ")
            && let Some(column) = text.find(version.trim())
        {
            let version = version.trim();
            // Declaration and version are the same token: `go 1.21` names no
            // package, so pointing at the keyword would underline nothing.
            out.push(sighting(
                Ecosystem::Go,
                crate::model::GO_TOOLCHAIN,
                version,
                path,
                lines.range(start + column, start + column + version.len()),
                Vec::new(),
                false,
            ));
        }
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
    let body = body.strip_prefix("require").map(str::trim_start).unwrap_or(body);
    let mut parts = body.split_whitespace();
    let module = parts.next()?;
    let version = parts.next()?;
    if module.is_empty() || module == "(" || !version.starts_with('v') {
        return None;
    }
    let column = full_line.find(module)?;
    Some(sighting(
        Ecosystem::Go,
        module,
        // OSV records Go versions without the `v` the module file writes.
        version.trim_start_matches('v'),
        path,
        lines.range(start + column, start + column + module.len()),
        // `// indirect` is a graph fact, not a dependency group; the Go server
        // does not treat it as one either.
        Vec::new(),
        false,
    ))
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
/// `[dependencies.serde]` is not, which matches the Go server.
const CARGO_SECTIONS: [(&str, Option<&str>); 3] = [
    ("dependencies", None),
    ("build-dependencies", Some("build")),
    ("dev-dependencies", Some(DEV_GROUP)),
];

/// Dependencies declared in a `Cargo.toml`.
///
/// Line-based rather than parsed, for the same reason the Go locator is: a TOML
/// decoder hands back values without telling you where they were written, and
/// the position is the point. Only the shapes that carry a version are read.
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
        found[index].push(sighting(
            Ecosystem::CratesIo,
            name,
            version,
            path,
            lines.range(start + name_span.0, start + name_span.1),
            CARGO_SECTIONS[index].1.map(str::to_owned).into_iter().collect(),
            // Cargo versions are constraints — `"0.1.44"` means `^0.1.44` — so
            // what is installed comes from the lockfile, never from here.
            true,
        ));
    }
    found.into_iter().flatten().collect()
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

/// Locked crate versions from a `Cargo.lock`.
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
    CARGO_SECTIONS.iter().position(|(section, _)| *section == name)
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

        if let Some(found) = requirement(&whole, whole_start, path, &lines) {
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

    let (comparator, version) = specifier(rest)?;
    let column = line.find(name)?;

    Some(sighting(
        Ecosystem::PyPI,
        name,
        version,
        path,
        lines.range(start + column, start + column + name.len()),
        Vec::new(),
        // Only `==` and `===` name an installed version; everything else is a
        // constraint whose lowest satisfying version is a guess.
        !matches!(comparator, "==" | "==="),
    ))
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

