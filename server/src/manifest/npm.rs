//! `package.json` and `package-lock.json`.

use super::{first_per_name, lowest_satisfying, sighting};
use crate::model::{DEV_GROUP, Ecosystem, ExtractedPackage};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::test_support::at;

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
}
