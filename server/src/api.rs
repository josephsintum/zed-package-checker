//! Advisories for the packages a project actually depends on, over the network.
//!
//! The archive path downloads every advisory for every package — 253 MB across
//! four ecosystems, 97% of npm's being malicious-package reports for packages
//! nobody here depends on. This asks osv.dev about the few hundred packages in
//! hand instead, keeps the answers on disk, and refreshes them on a TTL.
//!
//! Only a package's name, ecosystem and version ever leave the machine, and
//! only for packages `Config::may_send` allows.
//!
//! # The invariant this module exists to hold
//!
//! For every package that ends up with a finding, the index must hold that
//! package's **complete** advisory set — not just the advisories matching the
//! installed version. `Matcher::fix_for` verifies a candidate upgrade by asking
//! the index what else affects that package; an index filtered to the installed
//! version is missing exactly the advisories whose window starts above it, and
//! would recommend upgrading to a version already known to be vulnerable.
//!
//! That is why a hit is followed by a second, *unversioned* query. Where even
//! that comes back truncated, the package is reported in [`Advisories::partial`]
//! and the caller withholds the fix rather than guessing.

use crate::config::Config;
use crate::model::{Advisory, Ecosystem, ExtractedPackage, PackageKey};
use crate::osv::OsvAdvisory;
use arc_swap::ArcSwap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// OSV's documented ceiling on one batch request.
const BATCH_LIMIT: usize = 1000;

/// Simultaneous record fetches. The records come from a static bucket rather
/// than the API, so this is bounded by politeness rather than by a quota.
const RECORD_CONCURRENCY: usize = 16;

const API_HOST: &str = "https://api.osv.dev";

/// Records are served from the same bucket the archives come from, one file per
/// advisory, in the identical format — so the archive decoder reads them
/// unchanged and no API quota is spent on the bulk of the traffic.
const RECORD_HOST: &str = "https://osv-vulnerabilities.storage.googleapis.com";

/// Long enough for a slow link, short enough that a wedged scan does not sit in
/// the editor forever.
const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("query osv.dev: {0}")]
    Query(String),
    #[error("osv.dev returned {status} for {url}")]
    Status { status: u16, url: String },
    #[error("osv.dev sent {0}")]
    Malformed(String),
}

/// What one scan learned.
#[derive(Debug, Default)]
pub struct Advisories {
    pub advisories: Vec<Advisory>,

    /// Packages whose advisory set could not be retrieved in full.
    ///
    /// A finding on one of these is still reported — missing a vulnerability is
    /// the worse failure — but no fix may be claimed for it, because verifying
    /// a candidate needs the complete set.
    pub partial: HashSet<PackageKey>,
}

pub struct ApiSource {
    agent: ureq::Agent,
    root: PathBuf,
    config: Arc<ArcSwap<Config>>,
}

impl ApiSource {
    pub fn new(root: impl Into<PathBuf>, config: Arc<ArcSwap<Config>>) -> ApiSource {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .build();
        ApiSource {
            agent: agent.into(),
            root: root.into(),
            config,
        }
    }

    /// Advisories for exactly these packages.
    pub fn advisories(&self, packages: &[ExtractedPackage]) -> Result<Advisories, ApiError> {
        let config = self.config.load_full();
        let ttl = Duration::from_secs(config.online.ttl_hours.saturating_mul(3600));

        let mut out = Advisories::default();
        let mut wanted: HashMap<Ecosystem, Vec<PackageKey>> = HashMap::new();

        for (ecosystem, packages) in group_by_ecosystem(packages, &config) {
            let mut cache = Cache::read(&self.root, ecosystem);
            let keys = self.resolve(ecosystem, &packages, &mut cache, ttl, &mut out)?;
            cache.write(&self.root, ecosystem);
            wanted.insert(ecosystem, keys);
        }

        // Decoded per ecosystem, because `into_model` keeps only the affected
        // entries for one and an advisory can name several.
        for (ecosystem, keys) in wanted {
            for id in self.ids_for(&keys, ecosystem) {
                let Some(raw) = self.read_record(&id) else {
                    continue;
                };
                if let Ok(parsed) = serde_json::from_slice::<OsvAdvisory<'_>>(&raw)
                    && let Some(advisory) = parsed.into_model(ecosystem)
                {
                    out.advisories.push(advisory);
                }
            }
        }
        Ok(out)
    }

    /// Brings `cache` up to date for these packages, fetching what is missing.
    ///
    /// Returns the packages that have at least one advisory, which is the set
    /// whose records are needed.
    fn resolve(
        &self,
        ecosystem: Ecosystem,
        packages: &[(String, String)],
        cache: &mut Cache,
        ttl: Duration,
        out: &mut Advisories,
    ) -> Result<Vec<PackageKey>, ApiError> {
        let now = unix_now();

        // A package is already answered when we hold its complete set, or when
        // we confirmed this exact version clean. "Clean at 1.0.0" says nothing
        // about 2.0.0, which is why the negative entry carries the version.
        let mut ask = Vec::new();
        for (name, version) in packages {
            if cache.fresh_affected(name, now, ttl) || cache.fresh_clean(name, version, now, ttl) {
                continue;
            }
            ask.push((name.clone(), version.clone()));
        }

        if !ask.is_empty() {
            // Versioned: the cheap filter that says which packages are worth a
            // second look. Most projects come back almost entirely clean.
            let hits = self.query(ecosystem, &ask, true)?;
            let mut affected = Vec::new();
            for ((name, version), result) in ask.iter().zip(hits) {
                if result.ids.is_empty() && !result.truncated {
                    cache.mark_clean(name, version, now);
                } else {
                    affected.push(name.clone());
                }
            }

            if !affected.is_empty() {
                // Unversioned: the complete set per package, which is what
                // makes a verified fix possible. Only the few that matched.
                let unversioned: Vec<(String, String)> = affected
                    .iter()
                    .map(|n| (n.clone(), String::new()))
                    .collect();
                for (name, result) in
                    affected
                        .iter()
                        .zip(self.query(ecosystem, &unversioned, false)?)
                {
                    if result.truncated {
                        tracing::warn!(
                            %ecosystem, package = %name,
                            "osv.dev truncated this package's advisory list; no fix will be claimed"
                        );
                        out.partial
                            .insert(PackageKey::new(ecosystem, name.as_str()));
                    }
                    cache.mark_affected(name, result.ids, now);
                }
            }
            self.fetch_records(ecosystem, cache, &affected);
        }

        Ok(packages
            .iter()
            .filter(|(name, _)| cache.affected.contains_key(name))
            .map(|(name, _)| PackageKey::new(ecosystem, name.as_str()))
            .collect())
    }

    /// One `POST /v1/querybatch`, chunked at OSV's documented limit.
    fn query(
        &self,
        ecosystem: Ecosystem,
        packages: &[(String, String)],
        versioned: bool,
    ) -> Result<Vec<QueryResult>, ApiError> {
        let mut out = Vec::with_capacity(packages.len());
        for chunk in packages.chunks(BATCH_LIMIT) {
            let queries: Vec<Query> = chunk
                .iter()
                .map(|(name, version)| Query {
                    package: QueryPackage {
                        name: name.clone(),
                        ecosystem: ecosystem.as_str().to_owned(),
                    },
                    version: versioned.then(|| version.clone()),
                })
                .collect();

            let url = format!("{API_HOST}/v1/querybatch");
            let body = serde_json::to_vec(&BatchRequest { queries })
                .map_err(|e| ApiError::Malformed(e.to_string()))?;

            let mut response = self
                .agent
                .post(&url)
                .header("content-type", "application/json")
                .send(&body[..])
                .map_err(|e| ApiError::Query(e.to_string()))?;

            let status = response.status().as_u16();
            if status != 200 {
                return Err(ApiError::Status { status, url });
            }
            let raw = response
                .body_mut()
                .read_to_vec()
                .map_err(|e| ApiError::Query(e.to_string()))?;
            let parsed: BatchResponse =
                serde_json::from_slice(&raw).map_err(|e| ApiError::Malformed(e.to_string()))?;

            // Results are positional. A length mismatch means we cannot tell
            // which answer belongs to which package, and guessing would
            // misattribute a vulnerability.
            if parsed.results.len() != chunk.len() {
                return Err(ApiError::Malformed(format!(
                    "{} results for {} queries",
                    parsed.results.len(),
                    chunk.len()
                )));
            }
            out.extend(parsed.results.into_iter().map(|r| {
                QueryResult {
                    truncated: r.next_page_token.is_some(),
                    ids: r
                        .vulns
                        .into_iter()
                        .map(|v| v.id)
                        .filter(|id| is_valid_osv_id(id))
                        .collect(),
                }
            }));
        }
        Ok(out)
    }

    /// Downloads every record named by these packages that is not already on
    /// disk, in parallel.
    fn fetch_records(&self, ecosystem: Ecosystem, cache: &Cache, packages: &[String]) {
        let missing: Vec<String> = packages
            .iter()
            .filter_map(|name| cache.affected.get(name))
            .flat_map(|entry| entry.ids.iter().cloned())
            .filter(|id| !self.record_path(id).exists())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        if missing.is_empty() {
            return;
        }

        let Ok(pool) = rayon::ThreadPoolBuilder::new()
            .num_threads(RECORD_CONCURRENCY)
            .build()
        else {
            return;
        };
        pool.install(|| {
            missing.par_iter().for_each(|id| {
                if let Some(raw) = self.download_record(ecosystem, id) {
                    self.write_record(id, &raw);
                }
            });
        });
    }

    /// One advisory record, preferring the bucket over the API.
    fn download_record(&self, ecosystem: Ecosystem, id: &str) -> Option<Vec<u8>> {
        let bucket = format!("{RECORD_HOST}/{}/{id}.json", ecosystem.as_str());
        // An advisory filed under a different ecosystem's folder is a 404 here
        // rather than an error; the API knows it by id alone.
        self.get(&bucket)
            .or_else(|| self.get(&format!("{API_HOST}/v1/vulns/{id}")))
    }

    fn get(&self, url: &str) -> Option<Vec<u8>> {
        let mut response = self.agent.get(url).call().ok()?;
        if response.status().as_u16() != 200 {
            return None;
        }
        response.body_mut().read_to_vec().ok()
    }

    fn ids_for(&self, keys: &[PackageKey], ecosystem: Ecosystem) -> Vec<String> {
        let cache = Cache::read(&self.root, ecosystem);
        keys.iter()
            .filter_map(|key| cache.affected.get(&*key.name))
            .flat_map(|entry| entry.ids.iter().cloned())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }

    fn record_path(&self, id: &str) -> PathBuf {
        self.root
            .join("api")
            .join("records")
            .join(format!("{id}.json"))
    }

    fn read_record(&self, id: &str) -> Option<Vec<u8>> {
        std::fs::read(self.record_path(id)).ok()
    }

    fn write_record(&self, id: &str, raw: &[u8]) {
        let path = self.record_path(id);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        write_atomic(&path, raw);
    }
}

/// Packages worth asking about, grouped by ecosystem and deduplicated.
fn group_by_ecosystem(
    packages: &[ExtractedPackage],
    config: &Config,
) -> BTreeMap<Ecosystem, Vec<(String, String)>> {
    let mut out: BTreeMap<Ecosystem, Vec<(String, String)>> = BTreeMap::new();
    let mut seen = HashSet::new();
    for extracted in packages {
        let ecosystem = extracted.package.ecosystem();
        let name = extracted.package.name();
        if !config.may_send(ecosystem, name) {
            continue;
        }
        let version = &*extracted.package.version;
        if !seen.insert((ecosystem, name.to_owned(), version.to_owned())) {
            continue;
        }
        out.entry(ecosystem)
            .or_default()
            .push((name.to_owned(), version.to_owned()));
    }
    out
}

/// Whether an identifier is safe to use as a file name and a URL segment.
///
/// OSV ids are alphanumerics, dots, dashes and underscores. Anything else is
/// refused rather than sanitised: `..` would walk out of the cache directory,
/// and an id we do not recognise is one we have no business fetching.
fn is_valid_osv_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Writes through a temporary file so a crash cannot leave a half-written cache
/// entry that parses as truth.
fn write_atomic(path: &Path, bytes: &[u8]) {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    if std::fs::write(&tmp, bytes).is_ok() && std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

// ------------------------------------------------------------------- the cache

#[derive(Debug, Default, Serialize, Deserialize)]
struct Cache {
    /// Package name to its complete advisory set. Keyed by name alone, because
    /// the set is version-independent.
    #[serde(default)]
    affected: BTreeMap<String, Affected>,

    /// `name@version` to when it was last confirmed clean. Keyed by version as
    /// well, because a bump has to be asked about again.
    #[serde(default)]
    clean: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Affected {
    ids: Vec<String>,
    fetched_at: u64,
}

impl Cache {
    fn path(root: &Path, ecosystem: Ecosystem) -> PathBuf {
        // The ecosystem name contains a dot (`crates.io`) but no separator, so
        // it is a safe file name as published.
        root.join("api")
            .join(format!("{}.json", ecosystem.as_str()))
    }

    fn read(root: &Path, ecosystem: Ecosystem) -> Cache {
        std::fs::read(Self::path(root, ecosystem))
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default()
    }

    fn write(&self, root: &Path, ecosystem: Ecosystem) {
        let path = Self::path(root, ecosystem);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec(self) {
            write_atomic(&path, &bytes);
        }
    }

    fn fresh_affected(&self, name: &str, now: u64, ttl: Duration) -> bool {
        self.affected
            .get(name)
            .is_some_and(|e| fresh(e.fetched_at, now, ttl))
    }

    fn fresh_clean(&self, name: &str, version: &str, now: u64, ttl: Duration) -> bool {
        self.clean
            .get(&clean_key(name, version))
            .is_some_and(|at| fresh(*at, now, ttl))
    }

    fn mark_clean(&mut self, name: &str, version: &str, now: u64) {
        self.affected.remove(name);
        self.clean.insert(clean_key(name, version), now);
    }

    fn mark_affected(&mut self, name: &str, ids: Vec<String>, now: u64) {
        self.affected.insert(
            name.to_owned(),
            Affected {
                ids,
                fetched_at: now,
            },
        );
    }
}

fn clean_key(name: &str, version: &str) -> String {
    format!("{name}@{version}")
}

fn fresh(fetched_at: u64, now: u64, ttl: Duration) -> bool {
    now.saturating_sub(fetched_at) < ttl.as_secs()
}

// --------------------------------------------------------------------- the wire

#[derive(Serialize)]
struct BatchRequest {
    queries: Vec<Query>,
}

#[derive(Serialize)]
struct Query {
    package: QueryPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Serialize)]
struct QueryPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<VulnStub>,
    /// Present when OSV truncated this result, in which case the list is
    /// incomplete and cannot support a verified fix.
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct VulnStub {
    id: String,
}

struct QueryResult {
    ids: Vec<String>,
    truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Package, Range, Site};

    fn extracted(ecosystem: Ecosystem, name: &str, version: &str) -> ExtractedPackage {
        ExtractedPackage {
            package: Package::new(ecosystem, name, version),
            evidence: Site::new("/p/package.json", Range::whole_line(1)),
            declared: None,
            dep_groups: Vec::new(),
            from_range: false,
            version_span: None,
            paths: Vec::new(),
        }
    }

    fn config(json: &serde_json::Value) -> Config {
        Config::from_options(Some(json))
    }

    #[test]
    fn an_id_that_would_escape_the_cache_directory_is_refused() {
        // The id becomes a file name and a URL segment. `..` walks out of the
        // records directory; a slash picks a different one.
        assert!(!is_valid_osv_id(".."));
        assert!(!is_valid_osv_id("."));
        assert!(!is_valid_osv_id("../../etc/passwd"));
        assert!(!is_valid_osv_id("a/b"));
        assert!(!is_valid_osv_id("a\\b"));
        assert!(!is_valid_osv_id(""));
        assert!(!is_valid_osv_id(&"A".repeat(129)));
        assert!(!is_valid_osv_id("GHSA-abc?query=1"));

        assert!(is_valid_osv_id("GHSA-35jh-r3h4-6jhm"));
        assert!(is_valid_osv_id("MAL-2026-1380"));
        assert!(is_valid_osv_id("PYSEC-2018-28"));
        assert!(is_valid_osv_id("RUSTSEC-2020-0071"));
        assert!(is_valid_osv_id("GO-2023-2041"));
    }

    #[test]
    fn excluded_packages_are_never_sent() {
        let packages = [
            extracted(Ecosystem::Npm, "@acme/internal", "1.0.0"),
            extracted(Ecosystem::Npm, "lodash", "4.17.15"),
            extracted(Ecosystem::Go, "github.com/acme/tool", "1.0.0"),
        ];
        let config = config(&serde_json::json!({
            "online": { "exclude": ["@acme/", "Go:github.com/acme/"] }
        }));

        let grouped = group_by_ecosystem(&packages, &config);
        let npm: Vec<&str> = grouped[&Ecosystem::Npm]
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(npm, ["lodash"], "an excluded name must not be queried");
        assert!(
            !grouped.contains_key(&Ecosystem::Go),
            "excluding every package of an ecosystem must not query it at all"
        );
    }

    #[test]
    fn the_same_package_is_asked_about_once() {
        // A dependency found in both a manifest and a lockfile is one query.
        let packages = [
            extracted(Ecosystem::Npm, "lodash", "4.17.15"),
            extracted(Ecosystem::Npm, "lodash", "4.17.15"),
            extracted(Ecosystem::Npm, "lodash", "4.17.21"),
        ];
        let grouped = group_by_ecosystem(&packages, &Config::default());
        assert_eq!(
            grouped[&Ecosystem::Npm].len(),
            2,
            "distinct versions, not rows"
        );
    }

    #[test]
    fn a_clean_answer_does_not_carry_over_to_another_version() {
        // The soundness property of the negative cache: "clean at 4.17.21" says
        // nothing about 4.17.15, and treating it as if it did would report a
        // downgraded dependency clean without ever asking.
        let mut cache = Cache::default();
        let now = 1_000_000;
        let ttl = Duration::from_secs(3600);
        cache.mark_clean("lodash", "4.17.21", now);

        assert!(cache.fresh_clean("lodash", "4.17.21", now, ttl));
        assert!(!cache.fresh_clean("lodash", "4.17.15", now, ttl));
    }

    #[test]
    fn an_entry_past_its_ttl_is_asked_about_again() {
        let mut cache = Cache::default();
        let ttl = Duration::from_secs(3600);
        cache.mark_clean("lodash", "4.17.21", 0);
        cache.mark_affected("evil", vec!["GHSA-1".into()], 0);

        assert!(cache.fresh_clean("lodash", "4.17.21", 3599, ttl));
        assert!(!cache.fresh_clean("lodash", "4.17.21", 3600, ttl));
        assert!(cache.fresh_affected("evil", 3599, ttl));
        assert!(!cache.fresh_affected("evil", 3600, ttl));
    }

    #[test]
    fn a_package_that_becomes_clean_loses_its_advisories() {
        // An advisory can be withdrawn. The positive entry has to go, or the
        // package keeps reporting a finding nothing supports any more.
        let mut cache = Cache::default();
        cache.mark_affected("lodash", vec!["GHSA-1".into()], 0);
        cache.mark_clean("lodash", "5.0.0", 10);
        assert!(!cache.affected.contains_key("lodash"));
    }

    #[test]
    fn the_cache_round_trips_through_disk() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut cache = Cache::default();
        cache.mark_affected("lodash", vec!["GHSA-1".into(), "GHSA-2".into()], 42);
        cache.mark_clean("left-pad", "1.0.0", 42);
        cache.write(dir.path(), Ecosystem::Npm);

        let read = Cache::read(dir.path(), Ecosystem::Npm);
        assert_eq!(read.affected["lodash"].ids, ["GHSA-1", "GHSA-2"]);
        assert_eq!(read.affected["lodash"].fetched_at, 42);
        assert_eq!(read.clean["left-pad@1.0.0"], 42);
    }

    #[test]
    fn a_missing_or_corrupt_cache_reads_as_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert!(Cache::read(dir.path(), Ecosystem::Npm).affected.is_empty());

        // A truncated write must not take the server down with it.
        let path = Cache::path(dir.path(), Ecosystem::Npm);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"{\"affected\": {").expect("write");
        assert!(Cache::read(dir.path(), Ecosystem::Npm).affected.is_empty());
    }

    #[test]
    fn every_ecosystem_name_is_a_safe_file_name() {
        // `crates.io` has a dot in it; none may contain a separator.
        for ecosystem in Ecosystem::ALL {
            let path = Cache::path(Path::new("/cache"), ecosystem);
            assert_eq!(
                path.parent(),
                Some(Path::new("/cache/api")),
                "{ecosystem} escaped the cache directory"
            );
        }
    }
}
