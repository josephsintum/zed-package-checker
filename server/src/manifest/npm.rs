//! `package.json` and `package-lock.json`.

use super::{first_per_name, lowest_satisfying, sighting};
use crate::model::{DEV_GROUP, Declaration, Ecosystem, ExtractedPackage, Range, Site};
use crate::span::LineIndex;
use std::collections::HashMap;
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

/// One dependency as `package.json` writes it.
struct Declared<'a> {
    name: &'a str,
    /// Byte span of the name, inside its quotes.
    name_at: (usize, usize),
    /// The raw spec, and where its first byte sits in the source.
    spec: &'a str,
    spec_at: usize,
    group: Option<&'static str>,
}

/// The root object of a JSON document, or `None` if it is not one.
fn object(src: &str) -> Option<Object<'_>> {
    let parsed = parse_to_ast(src, &CollectOptions::default(), &ParseOptions::default()).ok()?;
    match parsed.value {
        Some(Value::Object(root)) => Some(root),
        _ => None,
    }
}

/// Every dependency the four sections name, in attribution order.
///
/// Shared by [`package_json`] and [`declarations`], so a section added to one
/// is added to both. Deliberately not deduplicated: the two callers disagree
/// about what a duplicate is, since only one of them drops a spec it cannot
/// read a version from.
fn declared<'a>(root: &'a Object<'a>) -> Vec<Declared<'a>> {
    let mut out = Vec::new();
    for (section, group) in NPM_SECTIONS {
        let Some(Value::Object(deps)) = property(root, section) else {
            continue;
        };
        for prop in &deps.properties {
            let (Some((name, name_at)), Value::StringLit(spec)) =
                (prop_name(&prop.name), &prop.value)
            else {
                continue;
            };
            out.push(Declared {
                name,
                name_at,
                spec: spec.value.as_ref(),
                // The literal's range includes the quotes; the value is one byte in.
                spec_at: spec.range.start + 1,
                group,
            });
        }
    }
    out
}

pub fn package_json(src: &str, path: &Path) -> Vec<ExtractedPackage> {
    let Some(root) = object(src) else {
        return Vec::new();
    };
    let lines = LineIndex::new(src);
    let mut out = Vec::new();

    for dep in declared(&root) {
        let Some((version, at, to)) = lowest_satisfying(dep.spec) else {
            continue;
        };
        // `spec` is the *decoded* string, so an escape would put the span
        // somewhere else in the file — checked, not assumed, since a wrong span
        // here rewrites the wrong bytes.
        let (at, to) = (dep.spec_at + at, dep.spec_at + to);
        let version_span = (src.get(at..to) == Some(version)).then(|| lines.range(at, to));
        out.push(
            sighting(
                Ecosystem::Npm,
                dep.name,
                version,
                path,
                lines.range(dep.name_at.0, dep.name_at.1),
                dep.group.map(str::to_owned).into_iter().collect(),
                // A manifest states a constraint, never an installed version,
                // so everything here is inferred until a lockfile says otherwise.
                true,
            )
            .with_version_span(version_span),
        );
    }
    first_per_name(out)
}

/// Every dependency `package.json` names, one per name.
///
/// Unlike [`package_json`], a spec no version can be read from — `workspace:*`,
/// `file:../shared`, a git URL — still yields a declaration. The graph needs
/// the edge, and somewhere to anchor what it reaches, even where there is no
/// version to report; dropping those names would sever the tree at exactly the
/// dependencies a workspace is held together by.
pub(crate) fn declarations(src: &str, path: &Path) -> Vec<Declaration> {
    let Some(root) = object(src) else {
        return Vec::new();
    };
    let lines = LineIndex::new(src);
    let mut out: Vec<Declaration> = Vec::new();
    for dep in declared(&root) {
        if dep.name.is_empty() || out.iter().any(|seen| &*seen.name == dep.name) {
            continue;
        }
        out.push(Declaration {
            name: dep.name.into(),
            site: Site {
                path: path.to_path_buf(),
                range: lines.range(dep.name_at.0, dep.name_at.1),
            },
            groups: dep.group.map(str::to_owned).into_iter().collect(),
        });
    }
    out
}

/// Every dependency a lockfile records.
///
/// A thin view over [`lock`], which parses the file once: `crate::graph` needs
/// the same parse for its edges, and a lockfile is the largest file this server
/// reads.
pub fn package_lock(src: &str, path: &Path) -> Vec<ExtractedPackage> {
    let Some(tree) = lock(src) else {
        return Vec::new();
    };
    tree.sightings(path)
        .into_iter()
        .map(|(_, sighting)| sighting)
        .collect()
}

/// How many `link` hops are followed before giving up.
///
/// Arborist does not chain links, but nothing in the format forbids it and this
/// parser reads attacker-chosen bytes from any folder the user opens.
const MAX_LINK_HOPS: usize = 8;

/// Which section declared an edge, which decides when it is followed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DepKind {
    /// `dependencies` and `optionalDependencies`: installed under this node.
    Runtime,
    /// `devDependencies`. npm installs these for the project's own packages
    /// and strips them from everything under `node_modules`, so they are
    /// followed only out of the node a walk started from.
    Dev,
    /// `peerDependencies`. npm 7+ installs them, so they are real edges, but a
    /// peer edge is a shorter route than the real install reason — followed
    /// only where nothing else reaches the node.
    Peer,
}

/// One name an entry depends on, and the section that named it.
#[derive(Clone, Debug)]
pub(crate) struct Dep {
    /// The name as the requirer writes it — an alias, where one is used.
    pub(crate) name: Box<str>,
    /// Which section declared it.
    pub(crate) kind: DepKind,
}

/// One entry of a lockfile: a package at an install path.
#[derive(Clone, Debug)]
pub(crate) struct LockNode {
    /// The install path, verbatim: `""`, `"packages/api"`,
    /// `"node_modules/a/node_modules/b"`. Kept as text, never as a path —
    /// lockfiles use `/` on every platform and a key may contain `..`, both of
    /// which `PathBuf` would quietly rewrite.
    pub(crate) path: Box<str>,
    /// The name the registry published it under, which an alias hides. This is
    /// the one advisories are keyed by.
    pub(crate) registry_name: Box<str>,
    /// Absent on a link entry, which records only where its target lives.
    pub(crate) version: Option<Box<str>>,
    /// What it depends on, in file order.
    pub(crate) deps: Vec<Dep>,
    /// The `resolved` path of a `"link": true` entry.
    pub(crate) link: Option<Box<str>>,
    /// Where the name is written, for a sighting's evidence.
    pub(crate) span: Range,
    /// Groups the lockfile records, such as [`DEV_GROUP`].
    pub(crate) groups: Vec<String>,
}

impl LockNode {
    /// Whether this entry is a dependency rather than one of the project's own
    /// packages. The root and each workspace member are keyed by directory.
    fn is_dependency(&self) -> bool {
        self.path.contains("node_modules/")
    }
}

/// The install tree a `package-lock.json` describes.
///
/// Built once per lockfile and read by `crate::graph`, which is the only thing
/// that needs the edges; [`package_lock`] takes only the sightings.
#[derive(Clone, Debug)]
pub(crate) struct Lock {
    /// Every entry, in lockfile key order. Order is load-bearing: a scan of an
    /// unchanged tree has to publish an unchanged report, and `HashMap`
    /// iteration order is randomised per process.
    pub(crate) nodes: Vec<LockNode>,
    /// Lookup only. Never iterated, for the reason above.
    by_path: HashMap<Box<str>, usize>,
    /// Whether the file recorded any edges at all. npm 5.0–5.1 wrote v1
    /// lockfiles without `requires`, and an edgeless graph is indistinguishable
    /// from one where everything is a direct dependency.
    pub(crate) has_edges: bool,
}

impl Lock {
    /// The entry at an exact install path.
    ///
    /// Only tests ask this: production goes through [`Lock::resolve`], which
    /// is the question npm itself asks.
    #[cfg(test)]
    pub(crate) fn at(&self, path: &str) -> Option<usize> {
        self.by_path.get(path).copied()
    }

    fn new(nodes: Vec<LockNode>, has_edges: bool) -> Lock {
        // A duplicate key is not something npm writes; keeping the first match
        // the order `nodes` is already in.
        let mut by_path = HashMap::with_capacity(nodes.len());
        for (i, node) in nodes.iter().enumerate() {
            by_path.entry(node.path.clone()).or_insert(i);
        }
        Lock {
            nodes,
            by_path,
            has_edges,
        }
    }

    /// The node npm would resolve `name` to, for an entry installed at `from`.
    ///
    /// Node consults `<dir>/node_modules/<name>` for `from` and every ancestor
    /// directory, **nearest first, stopping at the first hit** — the nearest
    /// placement is the one that satisfies the requirer's range, and a farther
    /// one may be a different major.
    ///
    /// Every path segment is enumerated, not only `node_modules` boundaries: a
    /// workspace member at `packages/api` genuinely resolves through
    /// `packages/node_modules/` before the root's. The candidates that cannot
    /// exist — `…/node_modules/node_modules/x`, `node_modules/@scope/node_modules/x`
    /// — simply miss, because `node_modules` is a name npm refuses to publish,
    /// so no real key can ever spell them.
    pub(crate) fn resolve(&self, from: &str, name: &str) -> Option<usize> {
        let mut candidate = String::with_capacity(from.len() + name.len() + 16);
        let mut dir = Some(from);
        while let Some(at) = dir {
            candidate.clear();
            if !at.is_empty() {
                candidate.push_str(at);
                candidate.push('/');
            }
            candidate.push_str("node_modules/");
            candidate.push_str(name);
            if let Some(&found) = self.by_path.get(candidate.as_str()) {
                return self.follow(found);
            }
            dir = (!at.is_empty()).then(|| at.rsplit_once('/').map_or("", |(parent, _)| parent));
        }
        None
    }

    /// Walks a link entry to the package it stands for.
    ///
    /// A link records only where its target lives, so an edge that lands on one
    /// has not arrived yet. A dangling target dead-ends rather than failing the
    /// parse: a half-written lockfile is a normal event in an editor.
    fn follow(&self, mut at: usize) -> Option<usize> {
        for _ in 0..MAX_LINK_HOPS {
            let Some(target) = &self.nodes[at].link else {
                return Some(at);
            };
            at = *self.by_path.get(&**target)?;
        }
        None
    }

    /// One sighting per entry that is a dependency and records a version,
    /// paired with the node it came from so attribution can find its way back.
    ///
    /// No version span: rewriting a lockfile means rewriting integrity hashes
    /// and resolved URLs, so no edit is ever offered against one.
    pub(crate) fn sightings(&self, path: &Path) -> Vec<(usize, ExtractedPackage)> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.is_dependency())
            .filter_map(|(i, node)| {
                let version = node.version.as_deref()?;
                Some((
                    i,
                    sighting(
                        Ecosystem::Npm,
                        &node.registry_name,
                        version,
                        path,
                        node.span,
                        node.groups.clone(),
                        false,
                    ),
                ))
            })
            .collect()
    }
}

/// npm's dependency sections inside a lockfile entry, in file order.
const LOCK_SECTIONS: [(&str, DepKind); 4] = [
    ("dependencies", DepKind::Runtime),
    ("optionalDependencies", DepKind::Runtime),
    ("devDependencies", DepKind::Dev),
    ("peerDependencies", DepKind::Peer),
];

/// The install tree, or `None` where the file describes none.
///
/// `packages` takes precedence over `dependencies`: a v2 lockfile carries both,
/// for older npm, and building from each would produce every node twice.
pub(crate) fn lock(src: &str) -> Option<Lock> {
    let parsed = parse_to_ast(src, &CollectOptions::default(), &ParseOptions::default()).ok()?;
    let Some(Value::Object(root)) = parsed.value else {
        return None;
    };
    let lines = LineIndex::new(src);

    if let Some(Value::Object(packages)) = property(&root, "packages") {
        return Some(from_packages(packages, &lines));
    }
    if let Some(Value::Object(deps)) = property(&root, "dependencies") {
        // v1 writes no entry for the project itself, but a walk has to start
        // somewhere: this is where the manifest's own names resolve from.
        // Workspaces arrived with npm 7, which writes v2 or v3, so a v1
        // lockfile has exactly this one root and never any members.
        let mut nodes = vec![LockNode {
            path: "".into(),
            registry_name: "".into(),
            version: None,
            deps: Vec::new(),
            link: None,
            span: lines.range(0, 0),
            groups: Vec::new(),
        }];
        let mut has_edges = false;
        from_tree(deps, "", &lines, &mut nodes, &mut has_edges);
        return Some(Lock::new(nodes, has_edges));
    }
    None
}

/// The flat `packages` map of lockfile versions 2 and 3.
fn from_packages(packages: &Object<'_>, lines: &LineIndex) -> Lock {
    let mut nodes = Vec::with_capacity(packages.properties.len());
    let mut has_edges = false;
    for prop in &packages.properties {
        let (Some((key, range)), Value::Object(entry)) = (prop_name(&prop.name), &prop.value)
        else {
            continue;
        };
        let published = match property(entry, "name") {
            Some(Value::StringLit(name)) => Some(name.value.as_ref()),
            _ => None,
        };
        // The root and each workspace member are keyed by directory and named
        // by the manifest there; everything else is named by its install path.
        let (install_name, name_at) = match key.rfind("node_modules/") {
            Some(at) => {
                let at = at + "node_modules/".len();
                (&key[at..], at)
            }
            None => (published.unwrap_or(key), 0),
        };
        if install_name.is_empty() && !key.is_empty() {
            continue;
        }
        let deps = edges(entry);
        has_edges |= !deps.is_empty();
        nodes.push(LockNode {
            path: key.into(),
            // An alias installs under a name the registry never published, and
            // advisories are keyed by the published one.
            registry_name: published.unwrap_or(install_name).into(),
            version: match property(entry, "version") {
                Some(Value::StringLit(version)) => Some(version.value.as_ref().into()),
                _ => None,
            },
            deps,
            link: matches!(property(entry, "link"), Some(Value::BooleanLit(b)) if b.value)
                .then(|| match property(entry, "resolved") {
                    Some(Value::StringLit(target)) => Some(target.value.as_ref().into()),
                    _ => None,
                })
                .flatten(),
            // The span covers the package name inside the install path, not
            // the whole `node_modules/...` key.
            span: lines.range(range.0 + name_at, range.1),
            groups: lock_groups(entry),
        });
    }
    Lock::new(nodes, has_edges)
}

/// The nested tree of lockfile version 1, flattened into install paths.
///
/// The nesting is a *placement* — the versions that had to be un-hoisted under
/// a node — and is used only to synthesise those paths. The edges come from
/// `requires` and nowhere else: the nested map is a subset of what a node
/// depends on, never a superset, so reading it as edges would lose the hoisted
/// majority and misreport the rest.
fn from_tree(
    deps: &Object<'_>,
    prefix: &str,
    lines: &LineIndex,
    nodes: &mut Vec<LockNode>,
    has_edges: &mut bool,
) {
    for prop in &deps.properties {
        let (Some((name, range)), Value::Object(entry)) = (prop_name(&prop.name), &prop.value)
        else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let path = if prefix.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{prefix}/node_modules/{name}")
        };
        let raw = match property(entry, "version") {
            Some(Value::StringLit(version)) => Some(version.value.as_ref()),
            _ => None,
        };
        // v1 has no `name` on an entry; it folds an alias into the version.
        let (registry_name, version) = match raw.and_then(alias_target) {
            Some((aliased, version)) => (aliased, Some(version)),
            None => (name, raw),
        };
        // `requires` is a map on an entry but the boolean `true` at the root of
        // the file, and 125 of 209 entries in one real lockfile have none at
        // all — an entry with no `requires` is a leaf, not a fallback case.
        let requires = match property(entry, "requires") {
            Some(Value::Object(map)) => {
                *has_edges = true;
                map.properties
                    .iter()
                    .filter_map(|p| prop_name(&p.name))
                    .map(|(name, _)| Dep {
                        name: name.into(),
                        kind: DepKind::Runtime,
                    })
                    .collect()
            }
            _ => Vec::new(),
        };
        nodes.push(LockNode {
            path: path.as_str().into(),
            registry_name: registry_name.into(),
            version: version.map(Into::into),
            deps: requires,
            link: None,
            span: lines.range(range.0, range.1),
            groups: lock_groups(entry),
        });
        if let Some(Value::Object(nested)) = property(entry, "dependencies") {
            from_tree(nested, &path, lines, nodes, has_edges);
        }
    }
}

/// The names one entry depends on, deduplicated, in section then file order.
fn edges(entry: &Object<'_>) -> Vec<Dep> {
    let mut deps: Vec<Dep> = Vec::new();
    for (section, kind) in LOCK_SECTIONS {
        let Some(Value::Object(map)) = property(entry, section) else {
            continue;
        };
        for prop in &map.properties {
            let Some((name, _)) = prop_name(&prop.name) else {
                continue;
            };
            if !name.is_empty() && !deps.iter().any(|dep| &*dep.name == name) {
                deps.push(Dep {
                    name: name.into(),
                    kind,
                });
            }
        }
    }
    deps
}

fn lock_groups(entry: &Object<'_>) -> Vec<String> {
    let flag = |name: &str| matches!(property(entry, name), Some(Value::BooleanLit(b)) if b.value);
    // npm writes `devOptional` *instead of* the other two for a package
    // reachable only through dev and optional paths, so reading `dev` alone
    // leaves it looking like something that ships.
    let dev_optional = flag("devOptional");
    let mut groups = Vec::new();
    if flag("dev") || dev_optional {
        groups.push(DEV_GROUP.to_owned());
    }
    if flag("optional") || dev_optional {
        groups.push("optional".to_owned());
    }
    groups
}

/// The published name and version hidden behind an alias, if this is one.
///
/// `"h3-v2": "npm:h3@^2"` installs under `h3-v2` but is published as `h3`.
/// Lockfile v1 folds that into the version field as `npm:<name>@<version>`;
/// v2 and v3 record the published name on the entry instead.
fn alias_target(version: &str) -> Option<(&str, &str)> {
    // Split on the last `@`, so a scoped target keeps its own leading one.
    let (name, version) = version.strip_prefix("npm:")?.rsplit_once('@')?;
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
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
    use crate::manifest::test_support::{at, names_and_versions};

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
    fn an_aliased_entry_is_reported_under_its_published_name() {
        // `"h3-v2": "npm:h3@^2"` installs under the alias, but every advisory
        // is filed against `h3`, so the alias would match nothing at all.
        let src = "{\n  \"packages\": {\n    \"node_modules/h3-v2\": {\n      \"name\": \"h3\",\n      \"version\": \"2.0.0\"\n    }\n  }\n}\n";
        let found = package_lock(src, &at("package-lock.json"));
        assert_eq!(names_and_versions(&found), [("h3".into(), "2.0.0".into())]);
    }

    #[test]
    fn an_aliased_entry_keeps_its_span_on_the_alias() {
        // The published name is not in the file; the alias is what the reader
        // sees on that line, so that is what the span has to cover.
        let src = "{\n  \"packages\": {\n    \"node_modules/h3-v2\": {\n      \"name\": \"h3\",\n      \"version\": \"2.0.0\"\n    }\n  }\n}\n";
        let found = package_lock(src, &at("package-lock.json"));
        let span = found[0].evidence.range;
        assert_eq!(
            &src.lines().nth(2).unwrap()[span.start.column as usize..span.end.column as usize],
            "h3-v2"
        );
    }

    #[test]
    fn an_unaliased_entry_is_unaffected_by_its_own_name_field() {
        // Every `name` seen across 12,000 real entries was an alias, but the
        // degenerate case must still behave.
        let src = "{\n  \"packages\": {\n    \"node_modules/lodash\": {\n      \"name\": \"lodash\",\n      \"version\": \"4.17.15\"\n    }\n  }\n}\n";
        let found = package_lock(src, &at("package-lock.json"));
        assert_eq!(
            names_and_versions(&found),
            [("lodash".into(), "4.17.15".into())]
        );
    }

    #[test]
    fn a_v1_alias_is_read_out_of_the_version_field() {
        // v1 has no `name` on an entry; it folds the target into the version.
        let src = "{\n  \"dependencies\": {\n    \"h3-v2\": {\n      \"version\": \"npm:h3@2.0.0\"\n    }\n  }\n}\n";
        let found = package_lock(src, &at("package-lock.json"));
        assert_eq!(names_and_versions(&found), [("h3".into(), "2.0.0".into())]);
    }

    #[test]
    fn a_scoped_alias_target_keeps_its_leading_at() {
        let src = "{\n  \"dependencies\": {\n    \"api\": {\n      \"version\": \"npm:@acme/api@1.2.3\"\n    }\n  }\n}\n";
        let found = package_lock(src, &at("package-lock.json"));
        assert_eq!(
            names_and_versions(&found),
            [("@acme/api".into(), "1.2.3".into())]
        );
    }

    #[test]
    fn a_plain_v1_version_is_not_mistaken_for_an_alias() {
        let src = "{\n  \"dependencies\": {\n    \"lodash\": {\n      \"version\": \"4.17.15\"\n    }\n  }\n}\n";
        let found = package_lock(src, &at("package-lock.json"));
        assert_eq!(
            names_and_versions(&found),
            [("lodash".into(), "4.17.15".into())]
        );
    }

    #[test]
    fn dev_optional_demotes_like_both_groups_it_stands_for() {
        // npm writes `devOptional` instead of `dev` and `optional`, so reading
        // `dev` alone leaves the package looking like something that ships.
        let src = "{\n  \"packages\": {\n    \"node_modules/lodash\": {\n      \"version\": \"4.17.15\",\n      \"devOptional\": true\n    }\n  }\n}\n";
        let found = package_lock(src, &at("package-lock.json"));
        assert_eq!(found[0].dep_groups, ["dev", "optional"]);
    }

    /// A v3 lockfile with the given `(install path, entry body)` pairs.
    fn v3(entries: &[(&str, &str)]) -> String {
        let body: Vec<String> = entries
            .iter()
            .map(|(key, entry)| format!("    {key:?}: {entry}"))
            .collect();
        format!(
            "{{\n  \"lockfileVersion\": 3,\n  \"packages\": {{\n{}\n  }}\n}}\n",
            body.join(",\n")
        )
    }

    fn version_at(tree: &Lock, index: usize) -> String {
        tree.nodes[index].version.clone().unwrap().into_string()
    }

    mod resolve {
        use super::*;

        #[test]
        fn the_nearest_placement_wins_over_a_hoisted_one() {
            // Both satisfy the name; only the nested one satisfies `a`'s range,
            // which is why npm un-hoisted it in the first place.
            let src = v3(&[
                ("node_modules/lodash", r#"{"version": "4.0.0"}"#),
                (
                    "node_modules/a",
                    r#"{"version": "1.0.0", "dependencies": {"lodash": "^3"}}"#,
                ),
                ("node_modules/a/node_modules/lodash", r#"{"version": "3.0.0"}"#),
            ]);
            let tree = lock(&src).unwrap();
            let found = tree.resolve("node_modules/a", "lodash").unwrap();
            assert_eq!(version_at(&tree, found), "3.0.0");
        }

        #[test]
        fn the_walk_reaches_the_root_when_nothing_is_nested() {
            let src = v3(&[
                ("node_modules/lodash", r#"{"version": "4.0.0"}"#),
                ("node_modules/a", r#"{"version": "1.0.0"}"#),
            ]);
            let tree = lock(&src).unwrap();
            let found = tree.resolve("node_modules/a", "lodash").unwrap();
            assert_eq!(version_at(&tree, found), "4.0.0");
        }

        #[test]
        fn a_scoped_name_resolves_like_any_other() {
            let src = v3(&[
                ("node_modules/@acme/api", r#"{"version": "1.0.0"}"#),
                ("node_modules/a", r#"{"version": "1.0.0"}"#),
            ]);
            let tree = lock(&src).unwrap();
            assert!(tree.resolve("node_modules/a", "@acme/api").is_some());
        }

        #[test]
        fn a_scoped_package_nested_under_another_resolves() {
            let src = v3(&[
                ("node_modules/a/node_modules/@acme/api", r#"{"version": "2.0.0"}"#),
                ("node_modules/@acme/api", r#"{"version": "1.0.0"}"#),
            ]);
            let tree = lock(&src).unwrap();
            let found = tree.resolve("node_modules/a", "@acme/api").unwrap();
            assert_eq!(version_at(&tree, found), "2.0.0");
        }

        #[test]
        fn a_package_named_node_modules_cannot_be_reached_by_a_bogus_candidate() {
            // npm refuses to publish the name, so no real key spells the
            // candidates the upward walk generates and misses. If that ever
            // changed, this is the collision it would cause.
            let src = v3(&[
                ("node_modules/@scope/node_modules", r#"{"version": "1.0.0"}"#),
                ("node_modules/a", r#"{"version": "1.0.0"}"#),
            ]);
            let tree = lock(&src).unwrap();
            assert!(tree.resolve("node_modules/@scope/a", "x").is_none());
        }

        #[test]
        fn a_link_resolves_to_what_it_points_at() {
            let src = v3(&[
                ("", r#"{"name": "root"}"#),
                ("packages/api", r#"{"version": "9.9.9"}"#),
                (
                    "node_modules/api",
                    r#"{"link": true, "resolved": "packages/api"}"#,
                ),
            ]);
            let tree = lock(&src).unwrap();
            let found = tree.resolve("", "api").unwrap();
            assert_eq!(&*tree.nodes[found].path, "packages/api");
        }

        #[test]
        fn a_dangling_link_dead_ends_rather_than_failing() {
            // A half-written lockfile is a normal event in an editor.
            let src = v3(&[(
                "node_modules/api",
                r#"{"link": true, "resolved": "packages/gone"}"#,
            )]);
            let tree = lock(&src).unwrap();
            assert!(tree.resolve("", "api").is_none());
        }

        #[test]
        fn a_name_nothing_installed_resolves_to_nothing() {
            let src = v3(&[("node_modules/a", r#"{"version": "1.0.0"}"#)]);
            let tree = lock(&src).unwrap();
            assert!(tree.resolve("node_modules/a", "missing").is_none());
        }
    }

    mod install_tree {
        use super::*;

        #[test]
        fn every_section_becomes_an_edge_of_its_own_kind() {
            let src = v3(&[(
                "node_modules/a",
                r#"{"version": "1.0.0", "dependencies": {"r": "1"}, "optionalDependencies": {"o": "1"}, "devDependencies": {"d": "1"}, "peerDependencies": {"p": "1"}}"#,
            )]);
            let tree = lock(&src).unwrap();
            let kinds: Vec<_> = tree.nodes[0]
                .deps
                .iter()
                .map(|dep| (dep.name.to_string(), dep.kind))
                .collect();
            assert_eq!(
                kinds,
                [
                    ("r".to_owned(), DepKind::Runtime),
                    ("o".to_owned(), DepKind::Runtime),
                    ("d".to_owned(), DepKind::Dev),
                    ("p".to_owned(), DepKind::Peer),
                ]
            );
        }

        #[test]
        fn a_v1_tree_becomes_install_paths() {
            let src = r#"{
  "dependencies": {
    "a": {
      "version": "1.0.0",
      "requires": {"b": "^2"},
      "dependencies": {
        "b": {"version": "2.0.0"}
      }
    },
    "b": {"version": "3.0.0"}
  }
}
"#;
            let tree = lock(src).unwrap();
            let paths: Vec<&str> = tree.nodes.iter().map(|node| &*node.path).collect();
            assert_eq!(
                paths,
                [
                    // The project itself, which v1 writes no entry for.
                    "",
                    "node_modules/a",
                    "node_modules/a/node_modules/b",
                    "node_modules/b"
                ]
            );
            // The nested placement is what `a` resolves to, not the hoisted one.
            let found = tree.resolve("node_modules/a", "b").unwrap();
            assert_eq!(version_at(&tree, found), "2.0.0");
        }

        #[test]
        fn a_v1_tree_has_a_root_to_walk_from() {
            // v1 writes no entry for the project itself, so without a
            // synthesised one nothing has anywhere to start, and every
            // transitive dependency silently loses its attribution.
            let src = r#"{"dependencies": {"a": {"version": "1.0.0"}}}"#;
            let tree = lock(src).unwrap();
            assert_eq!(&*tree.nodes[0].path, "");
            assert!(tree.resolve("", "a").is_some());
        }

        #[test]
        fn the_root_requires_boolean_is_not_read_as_edges() {
            // Real v1 lockfiles carry `"requires": true` at the top level.
            let src = r#"{"requires": true, "dependencies": {"a": {"version": "1.0.0"}}}"#;
            let tree = lock(src).unwrap();
            let a = tree.at("node_modules/a").unwrap();
            assert!(tree.nodes[a].deps.is_empty());
            assert!(!tree.has_edges);
        }

        #[test]
        fn a_nested_dependencies_map_is_a_placement_not_an_edge() {
            // 125 of 209 entries in one real v1 lockfile have no `requires`;
            // reading the nested map as edges would lose the hoisted majority.
            let src = r#"{"dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}"#;
            let tree = lock(src).unwrap();
            let a = tree.at("node_modules/a").unwrap();
            assert!(tree.nodes[a].deps.is_empty(), "{:?}", tree.nodes[a].deps);
            assert!(
                tree.at("node_modules/a/node_modules/b").is_some(),
                "the placement is still a node"
            );
        }

        #[test]
        fn a_v1_lockfile_recording_no_requires_anywhere_reports_no_edges() {
            // npm 5.0-5.1 wrote these. An edgeless graph is indistinguishable
            // from one where everything is direct, so the caller must be told.
            let src = r#"{"dependencies": {"a": {"version": "1.0.0"}}}"#;
            assert!(!lock(src).unwrap().has_edges);
        }

        #[test]
        fn packages_takes_precedence_over_the_v2_compatibility_tree() {
            // A v2 lockfile carries both; building from each doubles every node.
            let src = r#"{
  "lockfileVersion": 2,
  "packages": {"node_modules/a": {"version": "1.0.0"}},
  "dependencies": {"a": {"version": "1.0.0"}}
}
"#;
            assert_eq!(lock(src).unwrap().nodes.len(), 1);
        }

        #[test]
        fn a_workspace_member_is_a_node_but_not_a_sighting() {
            // It is the project's own package, not something it depends on.
            let src = v3(&[
                ("", r#"{"name": "root", "version": "1.0.0"}"#),
                ("packages/api", r#"{"version": "9.9.9"}"#),
                ("node_modules/lodash", r#"{"version": "4.17.15"}"#),
            ]);
            let tree = lock(&src).unwrap();
            assert_eq!(tree.nodes.len(), 3);
            let found = tree.sightings(&at("package-lock.json"));
            assert_eq!(found.len(), 1);
            assert_eq!(&*found[0].1.package.name(), "lodash");
        }
    }

    mod declarations {
        use super::*;

        #[test]
        fn a_spec_no_version_can_be_read_from_still_declares_the_name() {
            // `package_json` drops these for want of a version; the graph needs
            // the edge and somewhere to anchor what it reaches.
            let src = "{\n  \"dependencies\": {\n    \"api\": \"workspace:*\",\n    \"shared\": \"file:../shared\"\n  }\n}\n";
            assert!(package_json(src, &at("package.json")).is_empty());
            let found = super::super::declarations(src, &at("package.json"));
            let names: Vec<&str> = found.iter().map(|d| &*d.name).collect();
            assert_eq!(names, ["api", "shared"]);
        }

        #[test]
        fn the_site_covers_the_name_alone() {
            let src = "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.0\"\n  }\n}\n";
            let found = super::super::declarations(src, &at("package.json"));
            let span = found[0].site.range;
            assert_eq!(
                &src.lines().nth(2).unwrap()
                    [span.start.column as usize..span.end.column as usize],
                "lodash"
            );
        }

        #[test]
        fn a_name_in_two_sections_is_declared_once_where_it_ships() {
            let src = "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.0\"\n  },\n  \"devDependencies\": {\n    \"lodash\": \"^3.0.0\"\n  }\n}\n";
            let found = super::super::declarations(src, &at("package.json"));
            assert_eq!(found.len(), 1);
            assert!(found[0].groups.is_empty());
        }
    }

    #[test]
    fn package_json_non_dependency_sections_are_ignored() {
        let src = "{\n  \"scripts\": {\n    \"lodash\": \"echo not a dependency\"\n  },\n  \"engines\": {\n    \"node\": \">=18\"\n  }\n}\n";
        assert!(package_json(src, &at("package.json")).is_empty());
    }
}
