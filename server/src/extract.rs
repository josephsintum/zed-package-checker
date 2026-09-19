//! Finding what a project depends on, and where it says so.
//!
//! Each parser keeps the spans of what it finds, so discovery and anchoring are
//! one pass over one file: no second read to narrow a whole-line anchor down to
//! the dependency's name.

use crate::manifest;
use crate::model::{ExtractedPackage, Finding, Package, PackageKey, Range, Site};
use ignore::WalkBuilder;
use std::collections::{HashMap, HashSet};
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
pub enum ExtractError {
    #[error("walk {root}: {source}")]
    Walk {
        root: PathBuf,
        source: ignore::Error,
    },
}

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
    pub fn new() -> Extractor {
        Extractor::default()
    }

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

        sightings.retain(|s| !is_own_crate(s, &cargo_self));
        Ok(reconcile(sightings))
    }
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

/// Resolves the same package seen in more than one file.
///
/// A dependency appears twice — once as a range in `package.json`, once pinned
/// in `package-lock.json`. The lockfile wins, because it says what is actually
/// installed, but the manifest's location is carried forward as `declared`,
/// because that is where the user can act.
fn reconcile(sightings: Vec<ExtractedPackage>) -> Vec<ExtractedPackage> {
    // Keyed by name within a project: a lockfile legitimately holds several
    // versions of one package, and all of those are kept.
    let mut locked: std::collections::HashSet<Scope> = Default::default();
    let mut declared: HashMap<Scope, Site> = HashMap::new();
    for sighting in &sightings {
        let scope = scope_of(sighting);
        if sighting.from_range {
            declared
                .entry(scope)
                .or_insert_with(|| sighting.evidence.clone());
        } else {
            locked.insert(scope);
        }
    }

    let mut seen: HashMap<(PathBuf, Package), usize> = HashMap::new();
    let mut out: Vec<ExtractedPackage> = Vec::with_capacity(sightings.len());

    for mut sighting in sightings {
        let scope = scope_of(&sighting);
        if sighting.from_range && locked_at_or_above(&locked, &scope) {
            // Superseded by a lockfile governing this project. Its location is
            // still used, through `declared`.
            continue;
        }
        let dedupe = (scope.dir.clone(), sighting.package.clone());
        if let Some(&i) = seen.get(&dedupe) {
            if out[i].dep_groups.is_empty() {
                out[i].dep_groups = sighting.dep_groups;
            }
            continue;
        }
        if let Some(site) = declared.get(&scope)
            && *site != sighting.evidence
        {
            sighting.declared = Some(site.clone());
        }
        seen.insert(dedupe, out.len());
        out.push(sighting);
    }

    // Sorted so a scan of an unchanged tree publishes an unchanged report.
    out.sort_by(|a, b| {
        a.package
            .key
            .cmp(&b.package.key)
            .then_with(|| a.package.version.cmp(&b.package.version))
            .then_with(|| a.evidence.path.cmp(&b.evidence.path))
    });
    out
}

/// Whether a lockfile in this directory or any ancestor pins this package.
///
/// Walking upwards is what makes npm workspaces work: one lockfile at the
/// repository root governs `packages/app/package.json` below it.
fn locked_at_or_above(locked: &std::collections::HashSet<Scope>, scope: &Scope) -> bool {
    let mut dir = scope.dir.as_path();
    loop {
        if locked.contains(&Scope {
            dir: dir.to_path_buf(),
            package: scope.package.clone(),
        }) {
            return true;
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent,
            _ => return false,
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
