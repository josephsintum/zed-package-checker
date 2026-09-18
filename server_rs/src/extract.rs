//! Finding what a project depends on, and where it says so.
//!
//! The Go server delegates this to osv-scalibr and then re-reads each manifest
//! in a second pass to narrow the whole-line anchor scalibr gives it down to the
//! dependency's name. Here the parser that finds a dependency is the one that
//! knows where it is, so there is one pass and `internal/locate` has no
//! counterpart — including for `requirements.txt`, which the Go server still
//! anchors on the whole line.

use crate::manifest;
use crate::model::{ExtractedPackage, Package, PackageKey, Site};
use ignore::WalkBuilder;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Directories never worth walking into.
///
/// In code rather than in user-visible defaults: a manifest under
/// `node_modules` describes someone else's package, which is a correctness
/// property and not a preference.
const SKIP_DIRS: &[&str] = &[
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
            let entry = entry.map_err(|source| ExtractError::Walk {
                root: root.into(),
                source,
            })?;
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            files += 1;
            if files > self.max_files {
                break;
            }
            let path = entry.path();
            let Some(parse) = parser_for(path) else {
                continue;
            };
            let Ok(source) = std::fs::read_to_string(path) else {
                // A manifest we cannot read is not a scan failure: it may be
                // binary, or being written right now.
                continue;
            };
            if path.file_name().is_some_and(|n| n == "Cargo.toml")
                && let Some(name) = manifest::cargo_self(&source)
            {
                cargo_self.insert(path.parent().unwrap_or(Path::new("")).to_path_buf(), name);
            }
            sightings.extend(parse(&source, path));
        }

        sightings.retain(|s| !is_own_crate(s, &cargo_self));
        Ok(reconcile(sightings))
    }
}

type Parser = fn(&str, &Path) -> Vec<ExtractedPackage>;

fn parser_for(path: &Path) -> Option<Parser> {
    let name = path.file_name()?.to_str()?;
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
