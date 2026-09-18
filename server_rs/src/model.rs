//! The vocabulary the rest of the server speaks: packages, positions,
//! advisories, findings.
//!
//! Pure data and pure functions, depending on nothing outside `std`. In the Go
//! server this is its own package with an import-boundary test enforcing that;
//! here it is one module, and `tests/boundaries.rs` checks the same property
//! over the module's `use` statements.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

/// An OSV ecosystem.
///
/// A closed enum rather than the wrapped string the Go server uses. The set is
/// fixed by what the extractors can parse, so making it closed turns "did you
/// handle crates.io?" from a code review question into a compile error.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Ecosystem {
    Npm,
    Go,
    PyPI,
    CratesIo,
}

impl Ecosystem {
    /// Every ecosystem, in the order reports and downloads present them.
    pub const ALL: [Ecosystem; 4] = [
        Ecosystem::Npm,
        Ecosystem::Go,
        Ecosystem::PyPI,
        Ecosystem::CratesIo,
    ];

    /// The OSV name, used verbatim in archive URLs and cache paths.
    ///
    /// Capitalisation and the dot in `crates.io` are load-bearing: normalising
    /// them produces 404s against the advisory bucket.
    pub const fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Go => "Go",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::CratesIo => "crates.io",
        }
    }

    /// The ecosystem a Package URL type names, if it is one we support.
    pub fn from_purl_type(purl_type: &str) -> Option<Ecosystem> {
        match purl_type {
            "npm" => Some(Ecosystem::Npm),
            "golang" => Some(Ecosystem::Go),
            "pypi" => Some(Ecosystem::PyPI),
            "cargo" => Some(Ecosystem::CratesIo),
            _ => None,
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Ecosystem {
    type Err = UnknownEcosystem;

    /// Parses an OSV ecosystem name.
    ///
    /// An OSV ecosystem may carry a suffix after a colon (`Debian:12`); only
    /// the part before it names the ecosystem.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let base = s.split(':').next().unwrap_or(s);
        Ecosystem::ALL
            .into_iter()
            .find(|e| e.as_str() == base)
            .ok_or_else(|| UnknownEcosystem(s.to_owned()))
    }
}

/// An ecosystem name none of the extractors can produce packages for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnknownEcosystem(pub String);

impl fmt::Display for UnknownEcosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported ecosystem {:?}", self.0)
    }
}

impl std::error::Error for UnknownEcosystem {}

/// The Go toolchain, which the `go.mod` extractor reports as a dependency.
///
/// It is not one: the `go` directive is a minimum version, not the toolchain in
/// use, and diagnostics about it say so.
pub const GO_TOOLCHAIN: &str = "stdlib";

/// A package, independent of version. The key advisories are indexed by.
/// `Box<str>` rather than `String` throughout the advisory types: none of this
/// is ever mutated after parsing, and a `String` carries a capacity word that a
/// Go `string` does not. Across npm's 228,368 advisories that word alone is tens
/// of megabytes held for the life of the editor session.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PackageKey {
    pub ecosystem: Ecosystem,
    pub name: Box<str>,
}

impl PackageKey {
    pub fn new(ecosystem: Ecosystem, name: impl Into<Box<str>>) -> Self {
        PackageKey {
            ecosystem,
            name: name.into(),
        }
    }

    pub fn is_go_toolchain(&self) -> bool {
        self.ecosystem == Ecosystem::Go && &*self.name == GO_TOOLCHAIN
    }
}

impl fmt::Display for PackageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ecosystem, self.name)
    }
}

/// A package at a specific version.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Package {
    pub key: PackageKey,
    pub version: Box<str>,
}

impl Package {
    pub fn new(
        ecosystem: Ecosystem,
        name: impl Into<Box<str>>,
        version: impl Into<Box<str>>,
    ) -> Self {
        Package {
            key: PackageKey::new(ecosystem, name),
            version: version.into(),
        }
    }

    pub fn ecosystem(&self) -> Ecosystem {
        self.key.ecosystem
    }

    pub fn name(&self) -> &str {
        &self.key.name
    }
}

impl fmt::Display for Package {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.key, self.version)
    }
}

/// A point in a file. Both fields are **zero-based**, as LSP requires.
///
/// Column units follow the negotiated `positionEncoding`: byte offsets when the
/// client accepted utf-8, which is what the extractors produce natively.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Position {
    pub line: u32,
    pub column: u32,
}

impl Position {
    pub const fn new(line: u32, column: u32) -> Self {
        Position { line, column }
    }

    /// Converts the one-based line numbers manifests and parsers report.
    pub const fn from_one_based_line(line: u32) -> Self {
        Position {
            line: line.saturating_sub(1),
            column: 0,
        }
    }
}

/// A half-open span: `start` is included, `end` is not.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

impl Range {
    pub const fn new(start: Position, end: Position) -> Self {
        Range { start, end }
    }

    /// The whole of a one-based line, used when nothing narrower is known.
    pub const fn whole_line(one_based_line: u32) -> Self {
        let start = Position::from_one_based_line(one_based_line);
        Range {
            start,
            end: Position::new(start.line + 1, 0),
        }
    }

    /// A span within a single line, from byte columns.
    pub const fn on_line(line: u32, start_column: u32, end_column: u32) -> Self {
        Range {
            start: Position::new(line, start_column),
            end: Position::new(line, end_column),
        }
    }
}

/// A range in a named file. The path is always absolute.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Site {
    pub path: PathBuf,
    pub range: Range,
}

impl Site {
    pub fn new(path: impl Into<PathBuf>, range: Range) -> Self {
        Site {
            path: path.into(),
            range,
        }
    }
}

/// Where a dependency is declared, and where its version is written.
///
/// Two separate sites because they can genuinely live in different files — a
/// range in `package.json`, the resolved version in `package-lock.json`.
/// Conflating them is the bug JetBrains shipped.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Anchor {
    pub declaration: Site,
    pub version: Option<Site>,
}

impl Anchor {
    pub fn new(declaration: Site) -> Self {
        Anchor {
            declaration,
            version: None,
        }
    }

    pub fn with_version(mut self, version: Site) -> Self {
        self.version = Some(version);
        self
    }
}

/// Marks advisories from the OpenSSF malicious-packages feed.
const MALICIOUS_ID_PREFIX: &str = "MAL-";

/// Qualitative severity, ascending.
///
/// `Unknown` sorts lowest so an unscored advisory never outranks an assessed
/// one — roughly a third of OSV advisories carry no severity at all, and the Go
/// vulnerability database carries none whatsoever.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub enum Severity {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Maps a CVSS base score to its v3.1 band.
    ///
    /// Zero maps to `Unknown` rather than "None": the distinction buys nothing
    /// here. Out-of-range scores clamp rather than discard a valid advisory.
    pub fn from_cvss(score: f64) -> Severity {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Unknown
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Unknown => "Unknown",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A half-open interval of affected versions.
///
/// At most one of `fixed` and `last_affected` is set.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct AffectedRange {
    /// The first affected version. `"0"` means "since the first release" and is
    /// a sentinel, not a version to compare against.
    pub introduced: Box<str>,
    /// The first *unaffected* version; empty when no fix exists.
    pub fixed: Box<str>,
    /// The final bad version, instead of the first good one.
    pub last_affected: Box<str>,
}

/// One package an advisory affects, with the versions it affects.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Affected {
    pub package: PackageKey,
    /// Version intervals. Empty when `versions` enumerates instead.
    pub ranges: Box<[AffectedRange]>,
    /// An explicit list. A version here is affected regardless of `ranges`.
    pub versions: Box<[Box<str>]>,
}

/// An OSV advisory, reduced to what a diagnostic needs.
///
/// There is deliberately no `details` field. It is full Markdown prose
/// averaging 662 bytes, and across npm's 229k advisories it accounted for 151 MB
/// of a 257 MB index — more than half, to render hover text for the two or three
/// advisories a project actually matches. The Go server carries the field and
/// leaves it empty by convention; omitting it makes that a property of the type
/// instead, so it cannot be populated by accident. `Database::details` reads it
/// back from the archive on demand.
#[derive(Clone, PartialEq, Debug)]
pub struct Advisory {
    /// The primary OSV identifier, e.g. `GHSA-p6mc-m468-83gw`.
    pub id: Box<str>,
    /// Other identifiers, typically CVEs. EPSS and KEV are CVE-keyed, so
    /// enrichment looks up through these.
    pub aliases: Box<[Box<str>]>,
    pub summary: Box<str>,
    /// The base score, zero when the advisory carries none.
    pub cvss_score: f64,
    pub cvss_vector: Box<str>,
    pub affected: Box<[Affected]>,
    pub references: Box<[Box<str>]>,
}

impl Advisory {
    /// Whether the package is malicious rather than vulnerable.
    ///
    /// Reads the aliases as well as the id: OSV files some confirmed-malicious
    /// events under a `GHSA-` id, naming the canonical `MAL-` one only as an
    /// alias. Not `related`, which means "see also".
    pub fn malicious(&self) -> bool {
        self.id.starts_with(MALICIOUS_ID_PREFIX)
            || self
                .aliases
                .iter()
                .any(|alias| alias.starts_with(MALICIOUS_ID_PREFIX))
    }

    /// The qualitative severity.
    ///
    /// Malicious packages are always critical: "remove this now" does not scale
    /// with CVSS.
    pub fn severity(&self) -> Severity {
        if self.malicious() {
            Severity::Critical
        } else {
            Severity::from_cvss(self.cvss_score)
        }
    }

    pub fn url(&self) -> String {
        format!("https://osv.dev/vulnerability/{}", self.id)
    }

    /// Every version this advisory names as fixing the given package.
    ///
    /// Deduplicated: an advisory often carries the same fix on several ranges —
    /// one per affected release line that was patched together — and "Fixed in
    /// 0.2.23 or 0.2.23" reads as a bug in the tool rather than a detail of the
    /// data.
    ///
    /// Advisory-local: picking one version that clears every advisory on a
    /// package needs ecosystem-aware ordering and belongs to the matcher.
    pub fn fixed_versions_for(&self, key: &PackageKey) -> Vec<&str> {
        let mut fixed: Vec<&str> = Vec::new();
        for affected in self.affected.iter().filter(|a| &a.package == key) {
            for range in &affected.ranges {
                if !range.fixed.is_empty() && !fixed.contains(&&*range.fixed) {
                    fixed.push(&range.fixed);
                }
            }
        }
        fixed
    }
}

/// The dependency group a development-only dependency belongs to.
pub const DEV_GROUP: &str = "dev";

/// A dependency an extractor found, before any advisory has been consulted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtractedPackage {
    pub package: Package,
    /// Where the package was actually found — a lockfile line, usually.
    pub evidence: Site,
    /// Where the user can act on it, when that is a different file.
    pub declared: Option<Site>,
    pub dep_groups: Vec<String>,
    /// The version came from resolving a range, not from reading a pin, so the
    /// installed version may differ.
    pub from_range: bool,
}

/// Every distinct ecosystem among the extracted packages, sorted.
pub fn ecosystems_of(packages: &[ExtractedPackage]) -> Vec<Ecosystem> {
    let mut seen: Vec<_> = packages.iter().map(|p| p.package.ecosystem()).collect();
    seen.sort_unstable();
    seen.dedup();
    seen
}

/// A vulnerable dependency and the advisories that apply to it.
///
/// Advisories are shared rather than copied: one `Arc` bump per finding instead
/// of the struct copy the Go server makes for every affected package.
#[derive(Clone, Debug)]
pub struct Finding {
    pub package: Package,
    pub advisories: Vec<Arc<Advisory>>,
    pub evidence: Site,
    pub declared: Option<Anchor>,
    /// root -> ... -> package. Empty means the dependency is direct.
    pub paths: Vec<Vec<PackageKey>>,
    /// `None` means no reachability analysis ran.
    pub reachable: Option<bool>,
    pub from_range: bool,
    pub dep_groups: Vec<String>,
    /// Decided by the matcher, where the index is borrowed. Nothing downstream
    /// of it holds one.
    pub fix: Fix,
}

/// What to upgrade to.
///
/// Three cases rather than an `Option`, because "nothing is published" and
/// "things are published but none of them is enough" are different answers and
/// a user acts differently on each.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum Fix {
    /// The lowest published version no advisory on this package still affects.
    Clears(Box<str>),
    /// Fixes are published, but no single one clears every advisory.
    Partial,
    /// No advisory on this package names a fixed version.
    #[default]
    None,
}

impl Finding {
    pub fn direct(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn dev(&self) -> bool {
        self.dep_groups.iter().any(|g| g == DEV_GROUP)
    }

    pub fn malicious(&self) -> bool {
        self.advisories.iter().any(|a| a.malicious())
    }

    pub fn severity(&self) -> Severity {
        self.advisories
            .iter()
            .map(|a| a.severity())
            .max()
            .unwrap_or(Severity::Unknown)
    }

    /// The highest-severity advisory. Ties keep the earlier one, which is
    /// already sorted, so output stays stable between runs.
    ///
    /// Not `max_by_key`: it returns the *last* maximum, which would make the
    /// reported advisory depend on the order two equally-scored entries came
    /// out of the archive.
    pub fn worst(&self) -> &Advisory {
        self.advisories
            .iter()
            .map(Arc::as_ref)
            .reduce(|best, a| {
                if a.severity() > best.severity() {
                    a
                } else {
                    best
                }
            })
            .expect("a finding always carries at least one advisory")
    }

    pub fn shortest_path(&self) -> Option<&[PackageKey]> {
        self.paths.iter().min_by_key(|p| p.len()).map(Vec::as_slice)
    }

    /// The site a diagnostic is anchored on: where the user can act, falling
    /// back to where the dependency was found.
    pub fn anchor_site(&self) -> &Site {
        match &self.declared {
            Some(anchor) => &anchor.declaration,
            None => &self.evidence,
        }
    }
}

/// Everything one scan of one workspace found.
#[derive(Clone, Debug)]
pub struct Report {
    pub root: PathBuf,
    pub findings: Vec<Finding>,
    pub scanned_at: SystemTime,
}

impl Report {
    pub fn new(root: impl Into<PathBuf>, findings: Vec<Finding>) -> Self {
        Report {
            root: root.into(),
            findings,
            scanned_at: SystemTime::now(),
        }
    }

    /// Findings grouped by the file their diagnostic is anchored on.
    ///
    /// Ordered, so the set of files published does not churn between scans.
    pub fn by_file(&self) -> BTreeMap<&Path, Vec<&Finding>> {
        let mut out: BTreeMap<&Path, Vec<&Finding>> = BTreeMap::new();
        for finding in &self.findings {
            out.entry(finding.anchor_site().path.as_path())
                .or_default()
                .push(finding);
        }
        out
    }
}
