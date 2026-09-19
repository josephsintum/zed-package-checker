//! Finding what a project depends on, and where it says so.
//!
//! Each parser keeps the spans of what it finds, so discovery and anchoring are
//! one pass over one file: no second read to narrow a whole-line anchor down to
//! the dependency's name.

use crate::graph;
use crate::manifest;
use crate::manifest::npm::Lock;
use crate::model::{Declaration, ExtractedPackage, Finding, Package, PackageKey, Range, Site};
use ignore::WalkBuilder;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Directories never worth walking into.
///
/// In code rather than in user-visible defaults: a manifest under
/// `node_modules` describes someone else's package, which is a correctness
/// property and not a preference.
pub const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "vendor",
    "target",
    "dist",
];

/// Stops a pathological tree from being walked forever.
const DEFAULT_MAX_FILES: usize = 100_000;

#[derive(Debug, thiserror::Error)]
/// Why a workspace could not be walked at all.
pub enum ExtractError {
    #[error("walk {root}: {source}")]
    /// The root itself could not be walked.
    Walk {
        /// The workspace that was asked for.
        root: PathBuf,
        /// What the walker reported.
        source: ignore::Error,
    },
}

/// Finds every dependency declared under a directory.
pub struct Extractor {
    /// Added to `SKIP_DIRS`, never replacing it: replacing is a footgun, and
    /// nobody wants to re-specify `node_modules` to exclude one fixture tree.
    exclude: Vec<String>,
    max_files: usize,
}

impl Default for Extractor {
    fn default() -> Self {
        Extractor {
            exclude: Vec::new(),
            max_files: DEFAULT_MAX_FILES,
        }
    }
}

impl Extractor {
    /// An extractor with the built-in skip list and walk cap.
    pub fn new() -> Extractor {
        Extractor::default()
    }

    /// Directory names to skip, in addition to the built-in list.
    pub fn with_exclude(mut self, dirs: impl IntoIterator<Item = String>) -> Self {
        self.exclude.extend(dirs);
        self
    }

    /// Overridable so the truncation path can be exercised without building a
    /// hundred thousand files. Not a setting: nothing reads it from the client.
    pub fn with_max_files(mut self, max: usize) -> Self {
        self.max_files = max;
        self
    }

    /// Every dependency declared anywhere under `root`.
    ///
    /// # Errors
    ///
    /// [`ExtractError::Walk`] when `root` is not a directory. Anything less than
    /// that — an unreadable subdirectory, an unparseable file — is skipped and logged.
    pub fn extract(&self, root: &Path) -> Result<Vec<ExtractedPackage>, ExtractError> {
        // Owned, because the walker's filter outlives this borrow of `self`.
        let skip: Vec<String> = SKIP_DIRS
            .iter()
            .map(|s| (*s).to_owned())
            .chain(self.exclude.iter().cloned())
            .collect();

        let mut sightings = Vec::new();
        // The crate each Cargo project calls itself, so its lockfile's own
        // [[package]] entry can be dropped. npm needs no equivalent: the
        // manifest parser only reads dependency tables, so a project never
        // names itself there. Cargo.lock lists every crate including the local
        // one, and nothing in the entry marks it as local.
        let mut cargo_self: HashMap<PathBuf, String> = HashMap::new();
        let mut files = 0usize;
        // Files named by `-r` that no parser would pick up by name.
        let mut includes: Vec<PathBuf> = Vec::new();
        // What the npm graph is allowed to see. Held from the walk rather than
        // re-read afterwards, so the graph can never attribute a finding to a
        // manifest the report says does not exist — one excluded by the skip
        // list, or lost past the file cap.
        let mut manifests: HashMap<PathBuf, Vec<Declaration>> = HashMap::new();
        let mut lock_dirs: HashSet<PathBuf> = HashSet::new();
        // Ordered, because a `HashMap` is walked in a different order every
        // process and the order sightings arrive in decides which of two
        // answers for one package survives.
        let mut locks: BTreeMap<PathBuf, (PathBuf, Lock)> = BTreeMap::new();

        if !root.is_dir() {
            return Err(ExtractError::Walk {
                root: root.into(),
                source: ignore::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "not a directory",
                )),
            });
        }

        let walker = WalkBuilder::new(root)
            .hidden(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .filter_entry(move |entry| {
                if entry.file_type().is_some_and(|t| t.is_dir()) {
                    let name = entry.file_name().to_string_lossy();
                    // Matched by name, not by suffix: `dist` must not also
                    // exclude `district`.
                    return !skip.iter().any(|s| *s == name);
                }
                true
            })
            .build();

        for entry in walker {
            // One directory that cannot be read is not a scan failure: the
            // rest of the tree is still worth reporting, and saying nothing
            // about a whole workspace over one EACCES would hide everything.
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    tracing::warn!(%error, "skipping part of the tree");
                    continue;
                }
            };
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            files += 1;
            if files > self.max_files {
                // Said out loud, because the partial report is published as
                // authoritative: findings past this point are not merely
                // missing, they are actively cleared.
                tracing::warn!(
                    root = %root.display(),
                    max_files = self.max_files,
                    "tree too large to walk in full; scanned only part of it"
                );
                break;
            }
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let Some(parse) = parser_for(path) else {
                continue;
            };
            let Some(source) = crate::read::manifest(path) else {
                // A manifest we cannot read is not a scan failure: it may be
                // binary, being written right now, or larger than anything
                // worth scanning.
                continue;
            };
            if path.file_name().is_some_and(|n| n == "Cargo.toml")
                && let Some(name) = manifest::cargo_self(&source)
            {
                cargo_self.insert(path.parent().unwrap_or(Path::new("")).to_path_buf(), name);
            }
            if is_requirements_name(path) {
                includes.extend(unwalked_includes(path, &source));
            }
            let dir = path.parent().unwrap_or(Path::new("")).to_path_buf();
            if name == "package.json" {
                manifests.insert(path.to_path_buf(), manifest::declarations(&source, path));
            }
            // An npm lockfile is held rather than turned straight into
            // sightings: the install tree it describes is what attributes a
            // transitive dependency to a manifest, and reading a ten-megabyte
            // file twice to recover it would cost more than keeping it.
            if is_npm_lock_name(name) {
                if let Some(tree) = manifest::npm::lock(&source) {
                    lock_dirs.insert(dir.clone());
                    let entry = (path.to_path_buf(), tree);
                    // npm's own precedence, where both sit in one directory.
                    match locks.entry(dir) {
                        std::collections::btree_map::Entry::Vacant(slot) => {
                            slot.insert(entry);
                        }
                        std::collections::btree_map::Entry::Occupied(mut slot) => {
                            if name == "npm-shrinkwrap.json" {
                                slot.insert(entry);
                            }
                        }
                    }
                }
                continue;
            }
            sightings.extend(parse(&source, path));
        }

        // Followed after the walk, so an included file the walk would reach on
        // its own is not parsed twice. Bounded by a visited set: includes can
        // form a cycle.
        let mut visited: std::collections::HashSet<PathBuf> = HashSet::new();
        while let Some(path) = includes.pop() {
            if !visited.insert(path.clone()) {
                continue;
            }
            let Some(source) = crate::read::manifest(&path) else {
                continue;
            };
            includes.extend(unwalked_includes(&path, &source));
            sightings.extend(manifest::requirements(&source, &path));
        }

        let mut attributed = Attributed::default();
        for (dir, (path, tree)) in &locks {
            let seen = graph::Workspace {
                manifests: &manifests,
                lock_dirs: &lock_dirs,
            };
            for found in graph::attribute(tree, dir, &seen) {
                attributed.add(&tree.nodes[found.node].span, path, found);
            }
            sightings.extend(tree.sightings(path).into_iter().map(|(_, s)| s));
        }

        sightings.retain(|s| !is_own_crate(s, &cargo_self));
        Ok(reconcile(sightings, &attributed))
    }
}

/// Whether a filename is one npm writes its resolved tree to.
///
/// Both formats are identical; `npm-shrinkwrap.json` is the one npm ships in a
/// published package, and it outranks a `package-lock.json` beside it.
fn is_npm_lock_name(name: &str) -> bool {
    matches!(name, "package-lock.json" | "npm-shrinkwrap.json")
}

fn is_requirements_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("requirements") && n.ends_with(".txt"))
}

/// The files a requirements file includes that no parser would find by name.
fn unwalked_includes(path: &Path, source: &str) -> Vec<PathBuf> {
    let dir = path.parent().unwrap_or(Path::new(""));
    manifest::requirement_includes(source)
        .into_iter()
        .map(|target| dir.join(target))
        .filter(|target| parser_for(target).is_none())
        .collect()
}

/// Where this finding's version is written in the text just parsed.
///
/// The finding's anchor was produced by the same parser over the file on disk,
/// so an untouched buffer matches it exactly. Once the buffer has been edited
/// the positions no longer line up, and the package name is all that is left to
/// go on — accepted only when it names one declaration, since picking between
/// `dependencies` and `devDependencies` by guesswork would edit the wrong one.
pub(crate) fn version_span(sightings: &[ExtractedPackage], finding: &Finding) -> Option<Range> {
    // A transitive dependency has no version in the file its diagnostic sits
    // on: the anchor is the direct dependency that reaches it, whose version is
    // not the one at fault. The name lookup below would already miss, but only
    // by accident — and its single-declaration fallback could still match the
    // wrong line, which would offer an edit that rewrites another package.
    if !finding.direct() {
        return None;
    }
    let named = || {
        sightings.iter().filter(|s| {
            s.package.ecosystem() == finding.package.ecosystem()
                && s.package.name() == finding.package.name()
        })
    };
    let anchor = finding.anchor_site().range;
    if let Some(exact) = named().find(|s| s.evidence.range == anchor) {
        return exact.version_span;
    }
    let mut candidates = named();
    let only = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    only.version_span
}

/// Whether a filename is one some parser reads.
///
/// Exported so nothing has to keep a second copy of the list: `lsp` watches
/// these and `scanbench` counts them.
pub fn is_manifest_name(name: &str) -> bool {
    parser_for_name(name).is_some()
}

pub(crate) fn parser_for(path: &Path) -> Option<manifest::Parser> {
    parser_for_name(path.file_name()?.to_str()?)
}

fn parser_for_name(name: &str) -> Option<manifest::Parser> {
    match name {
        "package.json" => Some(manifest::package_json),
        "package-lock.json" | "npm-shrinkwrap.json" => Some(manifest::package_lock),
        "go.mod" => Some(manifest::go_mod),
        "Cargo.toml" => Some(manifest::cargo_toml),
        "Cargo.lock" => Some(manifest::cargo_lock),
        _ if name.starts_with("requirements") && name.ends_with(".txt") => {
            Some(manifest::requirements)
        }
        _ => None,
    }
}

/// Whether a sighting is the Cargo project's own crate.
///
/// A workspace root declares `[workspace]` and no `[package]`, so it records no
/// name and nothing is dropped there.
fn is_own_crate(sighting: &ExtractedPackage, cargo_self: &HashMap<PathBuf, String>) -> bool {
    if sighting.package.ecosystem() != crate::model::Ecosystem::CratesIo {
        return false;
    }
    let dir = sighting.evidence.path.parent().unwrap_or(Path::new(""));
    cargo_self
        .get(dir)
        .is_some_and(|own| *own == *sighting.package.name())
}

/// A package within one project directory.
///
/// Scoped to a directory so a sibling's lockfile cannot suppress a dependency
/// that is genuinely present here.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct Scope {
    dir: PathBuf,
    package: PackageKey,
}

fn scope_of(sighting: &ExtractedPackage) -> Scope {
    Scope {
        dir: sighting
            .evidence
            .path
            .parent()
            .unwrap_or(Path::new(""))
            .to_path_buf(),
        package: sighting.package.key.clone(),
    }
}

/// What the npm graph found, keyed by the lockfile line an entry sits on.
///
/// A lockfile holds one entry per install path, so its own site identifies it
/// uniquely — and it is the one thing that survives the trip from
/// [`Lock::sightings`] into a flat list of sightings.
#[derive(Default)]
struct Attributed(HashMap<(PathBuf, u32, u32), Vec<(Site, Vec<Vec<PackageKey>>)>>);

impl Attributed {
    fn key(path: &Path, span: &Range) -> (PathBuf, u32, u32) {
        (path.to_path_buf(), span.start.line, span.start.column)
    }

    fn add(&mut self, span: &Range, path: &Path, found: graph::Attribution) {
        self.0
            .entry(Self::key(path, span))
            .or_default()
            .push((found.declared, found.paths));
    }

    fn of(&self, sighting: &ExtractedPackage) -> &[(Site, Vec<Vec<PackageKey>>)] {
        self.0
            .get(&Self::key(
                &sighting.evidence.path,
                &sighting.evidence.range,
            ))
            .map_or(&[], Vec::as_slice)
    }
}

/// Whether one answer for a package outranks another already recorded.
///
/// Explicit rather than left to the order the walk reached files in: a
/// dependency the manifest declares itself outranks one reached through
/// something else, because telling users their own declaration is transitive is
/// worse than saying nothing, and a shorter chain outranks a longer one.
fn supersedes(candidate: &ExtractedPackage, current: &ExtractedPackage) -> bool {
    let depth = |p: &ExtractedPackage| p.paths.iter().map(Vec::len).min().unwrap_or(0);
    match (candidate.paths.is_empty(), current.paths.is_empty()) {
        (true, false) => true,
        (false, true) => false,
        _ => depth(candidate) < depth(current),
    }
}

/// The groups that survive when two sightings of one package are collapsed.
///
/// Empty means it ships, so a package reached by any shipping route ships —
/// previously the first non-empty set won, which let the order the walk reached
/// files in decide whether a finding was demoted.
fn merged_groups(current: &[String], candidate: &[String]) -> Vec<String> {
    if current.is_empty() || candidate.is_empty() {
        return Vec::new();
    }
    let mut groups = current.to_vec();
    for group in candidate {
        if !groups.contains(group) {
            groups.push(group.clone());
        }
    }
    groups.sort();
    groups
}

/// Resolves the same package seen in more than one file.
///
/// A dependency appears twice — once as a range in `package.json`, once pinned
/// in `package-lock.json`. The lockfile wins, because it says what is actually
/// installed, but the manifest's location is carried forward as `declared`,
/// because that is where the user can act.
///
/// A lockfile governs every manifest at or below its directory that has no
/// nearer lockfile of its own, which is how a workspace works: one lockfile at
/// the root, one manifest per member. A hoisted entry declared by several
/// members is reported once per member, so each lands where its own author
/// edits.
fn reconcile(sightings: Vec<ExtractedPackage>, attributed: &Attributed) -> Vec<ExtractedPackage> {
    // Keyed by name within a project: a lockfile legitimately holds several
    // versions of one package, and all of those are kept.
    let mut locked: std::collections::HashSet<Scope> = Default::default();
    for sighting in &sightings {
        if !sighting.from_range {
            locked.insert(scope_of(sighting));
        }
    }
    // Every declaration, filed under the lockfile that governs it.
    let mut declared: HashMap<Scope, Vec<Site>> = HashMap::new();
    for sighting in &sightings {
        if !sighting.from_range {
            continue;
        }
        let scope = scope_of(sighting);
        if let Some(dir) = nearest_lock(&locked, &scope) {
            let sites = declared
                .entry(Scope {
                    dir,
                    package: scope.package,
                })
                .or_default();
            if !sites.contains(&sighting.evidence) {
                sites.push(sighting.evidence.clone());
            }
        }
    }

    let mut seen: HashMap<(PathBuf, Package), usize> = HashMap::new();
    let mut out: Vec<ExtractedPackage> = Vec::with_capacity(sightings.len());
    let mut push = |sighting: ExtractedPackage, out: &mut Vec<ExtractedPackage>| {
        let anchor_dir = sighting
            .declared
            .as_ref()
            .map_or(&sighting.evidence.path, |d| &d.path)
            .parent()
            .unwrap_or(Path::new(""))
            .to_path_buf();
        let dedupe = (anchor_dir, sighting.package.clone());
        if let Some(&i) = seen.get(&dedupe) {
            let groups = merged_groups(&out[i].dep_groups, &sighting.dep_groups);
            if supersedes(&sighting, &out[i]) {
                out[i] = sighting;
            }
            out[i].dep_groups = groups;
            return;
        }
        seen.insert(dedupe, out.len());
        out.push(sighting);
    };

    for sighting in sightings {
        let scope = scope_of(&sighting);
        if sighting.from_range {
            if nearest_lock(&locked, &scope).is_some() {
                // Superseded by a lockfile governing this manifest. Its
                // location survives through `declared`.
                continue;
            }
            push(sighting, &mut out);
            continue;
        }
        let sites = declared.get(&scope).map_or(&[][..], Vec::as_slice);
        let chains = attributed.of(&sighting);
        if sites.is_empty() && chains.is_empty() {
            push(sighting, &mut out);
            continue;
        }
        for site in sites {
            push(
                ExtractedPackage {
                    declared: Some(site.clone()),
                    ..sighting.clone()
                },
                &mut out,
            );
        }
        // Only where no manifest names the package itself: the graph answers
        // "which declaration reaches this", which is a different question from
        // "who declares this", and the second one wins where both apply.
        for (site, paths) in chains {
            push(
                ExtractedPackage {
                    declared: Some(site.clone()),
                    ..sighting.clone()
                }
                .with_paths(paths.clone()),
                &mut out,
            );
        }
    }

    // Sorted so a scan of an unchanged tree publishes an unchanged report.
    out.sort_by(|a, b| {
        a.package
            .key
            .cmp(&b.package.key)
            .then_with(|| a.package.version.cmp(&b.package.version))
            .then_with(|| a.evidence.path.cmp(&b.evidence.path))
            .then_with(|| {
                let site = |p: &ExtractedPackage| p.declared.as_ref().map(|d| d.path.clone());
                site(a).cmp(&site(b))
            })
    });
    out
}

/// The directory of the nearest lockfile pinning this package, here or in any
/// ancestor.
///
/// Walking upwards is what makes npm workspaces work: one lockfile at the
/// repository root governs `packages/app/package.json` below it.
fn nearest_lock(locked: &std::collections::HashSet<Scope>, scope: &Scope) -> Option<PathBuf> {
    let mut dir = scope.dir.as_path();
    loop {
        if locked.contains(&Scope {
            dir: dir.to_path_buf(),
            package: scope.package.clone(),
        }) {
            return Some(dir.to_path_buf());
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent,
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three manifests in one directory, each naming one dependency.
    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        for name in ["a", "b", "c"] {
            let sub = dir.path().join(name);
            std::fs::create_dir(&sub).expect("mkdir");
            std::fs::write(
                sub.join("go.mod"),
                format!("module example.com/{name}\n\nrequire example.com/dep-{name} v1.0.0\n"),
            )
            .expect("write");
        }
        dir
    }

    #[test]
    fn every_manifest_is_found_when_the_walk_is_not_capped() {
        let dir = tree();
        let found = Extractor::new().extract(dir.path()).expect("extract");
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn the_walk_stops_at_max_files() {
        // The cap counts every file the walk visits, not every manifest, so two
        // files is two manifests here — one directory each.
        let dir = tree();
        let found = Extractor::new()
            .with_max_files(2)
            .extract(dir.path())
            .expect("extract");
        assert!(
            found.len() < 3,
            "the cap must actually truncate, got {} packages",
            found.len()
        );
    }

    #[test]
    fn a_manifest_over_the_read_cap_is_skipped_rather_than_truncated() {
        // A `go.mod` whose declared size exceeds the read cap. Truncating it
        // would report the dependencies in the prefix and silently drop the
        // rest, which reads as "the others are clean".
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("go.mod");
        std::fs::write(
            &path,
            "module example.com/x\n\nrequire example.com/dep v1.0.0\n",
        )
        .expect("write");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open")
            .set_len(crate::read::MAX_MANIFEST_BYTES + 1)
            .expect("grow");

        let found = Extractor::new().extract(dir.path()).expect("extract");
        assert!(found.is_empty(), "an oversized manifest must yield nothing");
    }

    fn write_project(dir: &Path, files: &[(&str, &str)]) {
        std::fs::create_dir_all(dir).expect("mkdir");
        for (name, body) in files {
            std::fs::write(dir.join(name), body).expect("write");
        }
    }

    fn versions_of(found: &[ExtractedPackage], name: &str) -> Vec<String> {
        found
            .iter()
            .filter(|p| p.package.name() == name)
            .map(|p| p.package.version.to_string())
            .collect()
    }

    mod precedence {
        use super::*;

        fn npm(name: &str, version: &str, declared_in: &str, line: u32) -> ExtractedPackage {
            ExtractedPackage {
                package: Package::new(crate::model::Ecosystem::Npm, name, version),
                evidence: Site::new("/p/package-lock.json", Range::on_line(9, 0, 1)),
                declared: Some(Site::new(declared_in, Range::on_line(line, 0, 1))),
                dep_groups: Vec::new(),
                from_range: false,
                version_span: None,
                paths: Vec::new(),
            }
        }

        fn via(hops: &[&str], sighting: ExtractedPackage) -> ExtractedPackage {
            sighting.with_paths(vec![
                hops.iter()
                    .map(|name| PackageKey::new(crate::model::Ecosystem::Npm, *name))
                    .collect(),
            ])
        }

        /// What survives for one package, as `version [via a>b]`.
        fn survivor(sightings: Vec<ExtractedPackage>) -> String {
            let out = reconcile(sightings, &Attributed::default());
            assert_eq!(out.len(), 1, "one anchor, one package: {out:?}");
            let hops: Vec<&str> = out[0]
                .paths
                .first()
                .and_then(|path| path.split_last())
                .map(|(_, hops)| hops.iter().map(|key| &*key.name).collect())
                .unwrap_or_default();
            format!("{} via {}", out[0].package.version, hops.join(">"))
        }

        #[test]
        fn a_declared_dependency_outranks_one_reached_through_something_else() {
            // Telling users their own declaration is transitive is worse than
            // saying nothing, so this must not depend on which the walk saw
            // first — which is the order `WalkBuilder` happened to return.
            let direct = npm("lodash", "4.17.15", "/p/package.json", 3);
            let reached = via(&["express", "lodash"], direct.clone());
            assert_eq!(survivor(vec![direct.clone(), reached.clone()]), "4.17.15 via ");
            assert_eq!(survivor(vec![reached, direct]), "4.17.15 via ");
        }

        #[test]
        fn the_shorter_chain_wins_between_two_transitive_answers() {
            let at = npm("cookie", "0.4.0", "/p/package.json", 3);
            let near = via(&["express", "cookie"], at.clone());
            let far = via(&["a", "b", "cookie"], at);
            assert_eq!(survivor(vec![far.clone(), near.clone()]), "0.4.0 via express");
            assert_eq!(survivor(vec![near, far]), "0.4.0 via express");
        }
    }

    mod groups {
        use super::*;

        #[test]
        fn a_package_reached_by_any_shipping_route_is_not_demoted() {
            // Empty means it ships. Previously the first non-empty set won, so
            // whether a finding was demoted depended on directory order — and
            // `dev()` feeds the severity that gets published.
            let ships: Vec<String> = Vec::new();
            let dev = vec![crate::model::DEV_GROUP.to_owned()];
            assert!(merged_groups(&ships, &dev).is_empty());
            assert!(merged_groups(&dev, &ships).is_empty());
        }

        #[test]
        fn groups_that_both_agree_on_survive_together() {
            let dev = vec![crate::model::DEV_GROUP.to_owned()];
            let optional = vec!["optional".to_owned()];
            assert_eq!(merged_groups(&dev, &optional), ["dev", "optional"]);
            // Order of arrival must not change the answer.
            assert_eq!(merged_groups(&optional, &dev), ["dev", "optional"]);
        }

        #[test]
        fn a_repeated_group_is_not_listed_twice() {
            let dev = vec![crate::model::DEV_GROUP.to_owned()];
            assert_eq!(merged_groups(&dev, &dev), ["dev"]);
        }
    }

    #[test]
    fn an_empty_directory_yields_nothing() {
        // The server starts for nearly every project, so most workspaces have
        // nothing to extract. That is not an error.
        let dir = tempfile::tempdir().expect("temp dir");
        assert!(
            Extractor::new()
                .extract(dir.path())
                .expect("extract")
                .is_empty()
        );
    }

    #[test]
    fn exclude_removes_exactly_that_directory() {
        let dir = tree();
        let found = Extractor::new()
            .with_exclude(["b".to_owned()])
            .extract(dir.path())
            .expect("extract");
        let names: Vec<&str> = found.iter().map(|p| p.package.name()).collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(!names.contains(&"example.com/dep-b"), "{names:?}");
    }

    #[test]
    fn exclusion_matches_whole_names_not_substrings() {
        // `dist` is skipped by default; `district` must not be.
        let dir = tempfile::tempdir().expect("temp dir");
        for name in ["dist", "district"] {
            write_project(
                &dir.path().join(name),
                &[(
                    "go.mod",
                    &format!("module m\n\nrequire example.com/{name} v1.0.0\n"),
                )],
            );
        }
        let found = Extractor::new().extract(dir.path()).expect("extract");
        let names: Vec<&str> = found.iter().map(|p| p.package.name()).collect();
        assert_eq!(names, ["example.com/district"]);
    }

    #[test]
    fn several_locked_versions_of_one_package_are_all_kept() {
        // npm legitimately installs several copies of one package at different
        // versions, and reconciling by name must not collapse them.
        let dir = tempfile::tempdir().expect("temp dir");
        write_project(
            dir.path(),
            &[(
                "package-lock.json",
                r#"{"lockfileVersion":3,"packages":{
                    "node_modules/lodash":{"version":"4.17.21"},
                    "node_modules/x/node_modules/lodash":{"version":"3.10.1"}}}"#,
            )],
        );
        let found = Extractor::new().extract(dir.path()).expect("extract");
        let mut versions = versions_of(&found, "lodash");
        versions.sort();
        assert_eq!(versions, ["3.10.1", "4.17.21"]);
    }

    #[test]
    fn reconciliation_is_scoped_to_one_project() {
        // Two projects in one tree, both depending on lodash: one pins it in a
        // lockfile, the other has no lockfile at all. Reconciling them together
        // would drop the lockfile-free project entirely — a silent false
        // negative — and anchor the locked version on the wrong manifest.
        let root = tempfile::tempdir().expect("temp dir");
        write_project(
            &root.path().join("locked"),
            &[
                (
                    "package.json",
                    r#"{"name":"locked","version":"1.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
                ),
                (
                    "package-lock.json",
                    r#"{"name":"locked","lockfileVersion":3,"packages":{
                    "":{"name":"locked","version":"1.0.0"},
                    "node_modules/lodash":{"version":"4.17.21"}}}"#,
                ),
            ],
        );
        write_project(
            &root.path().join("unlocked"),
            &[(
                "package.json",
                r#"{"name":"unlocked","version":"1.0.0","dependencies":{"lodash":"^3.0.0"}}"#,
            )],
        );

        let found = Extractor::new().extract(root.path()).expect("extract");
        let in_dir = |name: &str| {
            found
                .iter()
                .find(|p| p.evidence.path.parent().unwrap().ends_with(name))
                .unwrap_or_else(|| panic!("the {name} project produced no package: {found:?}"))
        };
        assert_eq!(in_dir("locked").package.version.as_ref(), "4.17.21");
        let unlocked = in_dir("unlocked");
        assert!(
            unlocked.from_range,
            "the lockfile-free version is inferred from its range"
        );
        assert_ne!(
            unlocked.package.version.as_ref(),
            "4.17.21",
            "took another project's lockfile"
        );

        for p in &found {
            let declared = p.declared.as_ref().map_or(&p.evidence.path, |d| &d.path);
            assert_eq!(
                declared.parent(),
                p.evidence.path.parent(),
                "reconciliation crossed projects"
            );
        }
    }

    #[test]
    fn a_workspace_lockfile_supersedes_its_members() {
        // A workspace keeps one lockfile at the root and a manifest per member,
        // so the pin that supersedes a member's range sits several directories
        // up.
        let root = tempfile::tempdir().expect("temp dir");
        write_project(
            root.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"ws","version":"1.0.0","workspaces":["packages/*"]}"#,
                ),
                (
                    "package-lock.json",
                    r#"{"name":"ws","lockfileVersion":3,"packages":{
                    "":{"name":"ws","version":"1.0.0"},
                    "node_modules/lodash":{"version":"4.17.21"}}}"#,
                ),
            ],
        );
        write_project(
            &root.path().join("packages/app"),
            &[(
                "package.json",
                r#"{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
            )],
        );

        let found = Extractor::new().extract(root.path()).expect("extract");
        assert_eq!(
            versions_of(&found, "lodash"),
            ["4.17.21"],
            "the root lockfile governs the member"
        );
    }

    fn declared_paths(found: &[ExtractedPackage], name: &str) -> Vec<String> {
        let mut paths: Vec<String> = found
            .iter()
            .filter(|p| p.package.name() == name)
            .map(|p| {
                let site = p.declared.as_ref().map_or(&p.evidence, |d| d);
                site.path
                    .to_string_lossy()
                    .rsplit('/')
                    .take(2)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn a_workspace_member_keeps_its_manifest_anchor() {
        // The root lockfile supersedes the member's range, but the member's
        // manifest is still where the user acts, so the finding must point
        // there — not at a lockfile line nobody opens.
        let root = tempfile::tempdir().expect("temp dir");
        write_project(
            root.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"ws","version":"1.0.0","workspaces":["packages/*"]}"#,
                ),
                (
                    "package-lock.json",
                    r#"{"name":"ws","lockfileVersion":3,"packages":{
                    "":{"name":"ws","version":"1.0.0"},
                    "node_modules/lodash":{"version":"4.17.21"}}}"#,
                ),
            ],
        );
        write_project(
            &root.path().join("packages/app"),
            &[(
                "package.json",
                r#"{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
            )],
        );

        let found = Extractor::new().extract(root.path()).expect("extract");
        assert_eq!(declared_paths(&found, "lodash"), ["app/package.json"]);
        let lodash = found.iter().find(|p| p.package.name() == "lodash").unwrap();
        assert!(
            lodash.evidence.path.ends_with("package-lock.json"),
            "{lodash:?}"
        );
    }

    #[test]
    fn every_member_declaring_a_hoisted_package_gets_its_own_finding() {
        // One hoisted lockfile entry, two members that declare it: each member
        // manifest is where its own author acts.
        let root = tempfile::tempdir().expect("temp dir");
        write_project(
            root.path(),
            &[(
                "package-lock.json",
                r#"{"name":"ws","lockfileVersion":3,"packages":{
                "":{"name":"ws","version":"1.0.0"},
                "node_modules/lodash":{"version":"4.17.21"}}}"#,
            )],
        );
        for member in ["app", "api"] {
            write_project(
                &root.path().join("packages").join(member),
                &[(
                    "package.json",
                    r#"{"name":"m","version":"1.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
                )],
            );
        }

        let found = Extractor::new().extract(root.path()).expect("extract");
        assert_eq!(
            declared_paths(&found, "lodash"),
            ["api/package.json", "app/package.json"]
        );
        assert_eq!(versions_of(&found, "lodash"), ["4.17.21", "4.17.21"]);
    }

    #[test]
    fn a_member_with_its_own_lockfile_is_not_claimed_by_the_root() {
        // The nearest lockfile governs a manifest. A member that pins its own
        // copy is anchored by its own lock, and the root lock's entry belongs
        // to the root manifest alone.
        let root = tempfile::tempdir().expect("temp dir");
        write_project(
            root.path(),
            &[
                (
                    "package.json",
                    r#"{"name":"ws","version":"1.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
                ),
                (
                    "package-lock.json",
                    r#"{"name":"ws","lockfileVersion":3,"packages":{
                    "":{"name":"ws","version":"1.0.0"},
                    "node_modules/lodash":{"version":"4.17.21"}}}"#,
                ),
            ],
        );
        write_project(
            &root.path().join("packages/app"),
            &[
                (
                    "package.json",
                    r#"{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.0"}}"#,
                ),
                (
                    "package-lock.json",
                    r#"{"name":"app","lockfileVersion":3,"packages":{
                    "":{"name":"app","version":"1.0.0"},
                    "node_modules/lodash":{"version":"4.17.20"}}}"#,
                ),
            ],
        );

        let found = Extractor::new().extract(root.path()).expect("extract");
        let mut pairs: Vec<(String, String)> = found
            .iter()
            .filter(|p| p.package.name() == "lodash")
            .map(|p| {
                (
                    declared_paths(std::slice::from_ref(p), "lodash").remove(0),
                    p.package.version.to_string(),
                )
            })
            .collect();
        pairs.sort();
        let root_name = root
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let mut want = vec![
            ("app/package.json".to_owned(), "4.17.20".to_owned()),
            (format!("{root_name}/package.json"), "4.17.21".to_owned()),
        ];
        want.sort();
        assert_eq!(pairs, want);
    }

    #[test]
    fn a_workspace_root_keeps_its_members() {
        // A virtual manifest has [workspace] and no [package], so there is no
        // crate of its own to drop and nothing may be filtered by accident.
        let root = tempfile::tempdir().expect("temp dir");
        write_project(
            root.path(),
            &[
                ("Cargo.toml", "[workspace]\nmembers = [\"app\"]\n"),
                (
                    "Cargo.lock",
                    "version = 3\n\n[[package]]\nname = \"time\"\nversion = \"0.1.44\"\n",
                ),
            ],
        );
        let found = Extractor::new().extract(root.path()).expect("extract");
        let names: Vec<&str> = found.iter().map(|p| p.package.name()).collect();
        assert_eq!(names, ["time"]);
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_directory_does_not_fail_the_scan() {
        // One EACCES in a cloned repository must not turn into "dependencies
        // not checked" for the whole workspace: publish what was found.
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().expect("temp dir");
        write_project(
            root.path(),
            &[("go.mod", "module m\n\nrequire example.com/dep v1.0.0\n")],
        );
        let sealed = root.path().join("sealed");
        std::fs::create_dir(&sealed).expect("mkdir");
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).expect("chmod");

        let found = Extractor::new().extract(root.path());
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let found = found.expect("an unreadable directory failed the scan");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn a_requirements_include_is_followed() {
        // `-r base.txt` names a file the walker would never pick up on its own.
        let root = tempfile::tempdir().expect("temp dir");
        write_project(
            root.path(),
            &[
                ("requirements.txt", "-r base.txt\nflask==1.0\n"),
                ("base.txt", "requests==2.19.1\n"),
            ],
        );
        let found = Extractor::new().extract(root.path()).expect("extract");
        let mut names: Vec<&str> = found.iter().map(|p| p.package.name()).collect();
        names.sort_unstable();
        assert_eq!(names, ["flask", "requests"]);
    }

    #[test]
    fn a_requirements_include_cycle_terminates() {
        let root = tempfile::tempdir().expect("temp dir");
        write_project(
            root.path(),
            &[
                ("requirements.txt", "-r other.txt\n"),
                ("other.txt", "-r requirements.txt\nrequests==2.0\n"),
            ],
        );
        let found = Extractor::new().extract(root.path()).expect("extract");
        assert_eq!(versions_of(&found, "requests"), ["2.0"]);
    }
}
