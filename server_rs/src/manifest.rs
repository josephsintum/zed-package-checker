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

