//! Deciding which advisories apply to a project's dependencies.
//!
//! Only the range arithmetic is ours; version *ordering* lives in
//! `crate::version`. osv-scanner's own matcher is not reused by either server:
//! its database cache is filtered to the package names present when it first
//! loaded, and later calls receive that stale set regardless of what the project
//! now depends on.

use crate::index::Index;
use crate::model::{Advisory, Anchor, ExtractedPackage, Finding, Package};
use crate::version::Version;
use std::sync::Arc;

/// OSV's sentinel for "affected since the first release". It is not a version
/// string and must not be compared as one.
const INTRODUCED_FROM_THE_BEGINNING: &str = "0";

pub struct Matcher<'a> {
    index: &'a Index,
}

impl<'a> Matcher<'a> {
    pub fn new(index: &'a Index) -> Matcher<'a> {
        Matcher { index }
    }

    /// Every dependency that at least one advisory applies to.
    pub fn findings(&self, packages: &[ExtractedPackage]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for extracted in packages {
            let advisories = self.applicable(&extracted.package);
            if advisories.is_empty() {
                continue;
            }
            findings.push(Finding {
                package: extracted.package.clone(),
                advisories,
                evidence: extracted.evidence.clone(),
                declared: extracted.declared.clone().map(Anchor::new),
                paths: Vec::new(),
                reachable: None,
                from_range: extracted.from_range,
                dep_groups: extracted.dep_groups.clone(),
            });
        }
        findings
    }

    fn applicable(&self, package: &Package) -> Vec<Arc<Advisory>> {
        let candidates = self.index.lookup(&package.key);

        // Parsed once for the whole candidate set. The Go matcher re-parses the
        // installed version inside every single bound comparison.
        let Ok(version) = Version::parse(&package.version, package.ecosystem()) else {
            return Vec::new();
        };

        let mut hits: Vec<Arc<Advisory>> = candidates
            .filter(|advisory| affects(advisory, package, &version))
            .map(|advisory| Arc::new(advisory.clone()))
            .collect();

        // Stable order: severity first, then id, so output does not churn
        // between runs for advisories that score the same.
        hits.sort_by(|a, b| {
            b.severity()
                .cmp(&a.severity())
                .then_with(|| a.id.cmp(&b.id))
        });
        hits
    }
}

fn affects(advisory: &Advisory, package: &Package, version: &Version<'_>) -> bool {
    for entry in &advisory.affected {
        if entry.package != package.key {
            continue;
        }
        // An explicit version list is authoritative for the versions it names,
        // and OSV uses it for ecosystems with no reliable ordering.
        if entry.versions.iter().any(|v| **v == *package.version) {
            return true;
        }
        if entry.ranges.iter().any(|range| in_range(range, version)) {
            return true;
        }
    }
    false
}

/// Whether a version falls within one affected range.
///
/// Ranges are half-open: affected at or after `introduced`, and before `fixed`.
/// A version exactly equal to `fixed` is **not** affected — that is the whole
/// point of publishing a fix — while a version exactly equal to `introduced` is.
fn in_range(range: &crate::model::AffectedRange, version: &Version<'_>) -> bool {
    if !range.introduced.is_empty()
        && &*range.introduced != INTRODUCED_FROM_THE_BEGINNING
        && matches!(version.compare_str(&range.introduced), Ok(std::cmp::Ordering::Less))
    {
        return false;
    }

    if !range.fixed.is_empty() {
        return matches!(version.compare_str(&range.fixed), Ok(std::cmp::Ordering::Less));
    }
    if !range.last_affected.is_empty() {
        // `last_affected` names the final bad version rather than the first good
        // one, so the comparison is inclusive.
        return !matches!(
            version.compare_str(&range.last_affected),
            Ok(std::cmp::Ordering::Greater)
        );
    }
    // Introduced with no upper bound: affected, and no fix exists yet.
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Affected, AffectedRange, Ecosystem, Range, Severity, Site};

    fn advisory(id: &str, score: f64, affected: Vec<Affected>) -> Advisory {
        Advisory {
            id: id.into(),
            aliases: Box::default(),
            summary: Box::default(),
            cvss_score: score,
            cvss_vector: Box::default(),
            affected: affected.into(),
            references: Box::default(),
        }
    }

    fn npm(name: &str, ranges: Vec<AffectedRange>, versions: Vec<&str>) -> Affected {
        Affected {
            package: crate::model::PackageKey::new(Ecosystem::Npm, name),
            ranges: ranges.into(),
            versions: versions.into_iter().map(Box::<str>::from).collect(),
        }
    }

    fn range(introduced: &str, fixed: &str) -> AffectedRange {
        AffectedRange {
            introduced: introduced.into(),
            fixed: fixed.into(),
            last_affected: Box::default(),
        }
    }

    fn index_of(advisories: Vec<Advisory>) -> Index {
        Index::build(advisories, vec![Ecosystem::Npm], std::time::Duration::ZERO)
    }

    fn extracted(name: &str, version: &str) -> ExtractedPackage {
        ExtractedPackage {
            package: Package::new(Ecosystem::Npm, name, version),
            evidence: Site::new("/p/package.json", Range::whole_line(1)),
            declared: None,
            dep_groups: Vec::new(),
            from_range: false,
        }
    }

    fn matches(index: &Index, name: &str, version: &str) -> Vec<String> {
        Matcher::new(index)
            .findings(&[extracted(name, version)])
            .into_iter()
            .flat_map(|f| f.advisories)
            .map(|a| a.id.to_string())
            .collect()
    }

    #[test]
    fn ranges_are_half_open() {
        let index = index_of(vec![advisory(
            "GHSA-1",
            5.0,
            vec![npm("lodash", vec![range("4.0.0", "4.17.21")], vec![])],
        )]);

        // Below the introduction: unaffected.
        assert!(matches(&index, "lodash", "3.9.9").is_empty());
        // Exactly the introduced version: affected.
        assert_eq!(matches(&index, "lodash", "4.0.0"), ["GHSA-1"]);
        assert_eq!(matches(&index, "lodash", "4.17.20"), ["GHSA-1"]);
        // Exactly the fixed version: not affected. That is the point of a fix.
        assert!(matches(&index, "lodash", "4.17.21").is_empty());
        assert!(matches(&index, "lodash", "5.0.0").is_empty());
    }

    #[test]
    fn introduced_zero_is_a_sentinel_not_a_version() {
        let index = index_of(vec![advisory(
            "GHSA-1",
            5.0,
            vec![npm("lodash", vec![range("0", "4.17.21")], vec![])],
        )]);
        assert_eq!(matches(&index, "lodash", "0.0.1"), ["GHSA-1"]);
    }

    #[test]
    fn an_open_range_has_no_fix_yet() {
        let index = index_of(vec![advisory(
            "GHSA-1",
            5.0,
            vec![npm("lodash", vec![range("4.0.0", "")], vec![])],
        )]);
        assert_eq!(matches(&index, "lodash", "99.0.0"), ["GHSA-1"]);
    }

    #[test]
    fn last_affected_is_inclusive() {
        let index = index_of(vec![advisory(
            "GHSA-1",
            5.0,
            vec![npm(
                "lodash",
                vec![AffectedRange {
                    introduced: "4.0.0".into(),
                    fixed: Box::default(),
                    last_affected: "4.17.20".into(),
                }],
                vec![],
            )],
        )]);
        assert_eq!(matches(&index, "lodash", "4.17.20"), ["GHSA-1"]);
        assert!(matches(&index, "lodash", "4.17.21").is_empty());
    }

    #[test]
    fn backported_fixes_are_disjoint_windows() {
        // Fixed in 1.2.3 and again in 2.0.1; 1.2.3 through 2.0.0 is clean.
        let index = index_of(vec![advisory(
            "GHSA-1",
            5.0,
            vec![npm(
                "lodash",
                vec![range("1.0.0", "1.2.3"), range("2.0.0", "2.0.1")],
                vec![],
            )],
        )]);
        assert_eq!(matches(&index, "lodash", "1.2.2"), ["GHSA-1"]);
        assert!(matches(&index, "lodash", "1.5.0").is_empty());
        assert_eq!(matches(&index, "lodash", "2.0.0"), ["GHSA-1"]);
        assert!(matches(&index, "lodash", "2.0.1").is_empty());
    }

    #[test]
    fn prereleases_sort_below_their_release() {
        let index = index_of(vec![advisory(
            "GHSA-1",
            5.0,
            vec![npm("lodash", vec![range("1.0.0", "2.0.0")], vec![])],
        )]);
        // 2.0.0-rc1 is below 2.0.0, so it is still affected.
        assert_eq!(matches(&index, "lodash", "2.0.0-rc1"), ["GHSA-1"]);
        assert!(matches(&index, "lodash", "2.0.0").is_empty());
    }

    #[test]
    fn an_explicit_version_list_is_authoritative() {
        let index = index_of(vec![advisory(
            "GHSA-1",
            5.0,
            vec![npm("lodash", vec![], vec!["1.0.0", "1.0.2"])],
        )]);
        assert_eq!(matches(&index, "lodash", "1.0.0"), ["GHSA-1"]);
        assert!(matches(&index, "lodash", "1.0.1").is_empty());
        assert_eq!(matches(&index, "lodash", "1.0.2"), ["GHSA-1"]);
    }

    #[test]
    fn advisories_are_sorted_by_severity_then_id() {
        let index = index_of(vec![
            advisory("GHSA-low", 2.0, vec![npm("lodash", vec![range("0", "")], vec![])]),
            advisory("GHSA-crit", 9.5, vec![npm("lodash", vec![range("0", "")], vec![])]),
            advisory("GHSA-b-high", 7.5, vec![npm("lodash", vec![range("0", "")], vec![])]),
            advisory("GHSA-a-high", 7.5, vec![npm("lodash", vec![range("0", "")], vec![])]),
        ]);
        assert_eq!(
            matches(&index, "lodash", "1.0.0"),
            ["GHSA-crit", "GHSA-a-high", "GHSA-b-high", "GHSA-low"]
        );
    }

    #[test]
    fn a_malicious_advisory_outranks_a_scored_one() {
        let index = index_of(vec![
            advisory("GHSA-crit", 9.8, vec![npm("evil", vec![range("0", "")], vec![])]),
            advisory("MAL-2024-1", 0.0, vec![npm("evil", vec![range("0", "")], vec![])]),
        ]);
        let findings = Matcher::new(&index).findings(&[extracted("evil", "1.0.0")]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].malicious());
        assert_eq!(findings[0].severity(), Severity::Critical);
        // Ties on Critical fall back to the id, so the MAL- entry sorts second.
        assert_eq!(&*findings[0].worst().id, "GHSA-crit");
    }

    #[test]
    fn an_advisory_for_another_package_never_matches() {
        let index = index_of(vec![advisory(
            "GHSA-1",
            5.0,
            vec![npm("other", vec![range("0", "")], vec![])],
        )]);
        assert!(matches(&index, "lodash", "1.0.0").is_empty());
    }

    #[test]
    fn a_package_with_no_advisories_produces_no_finding() {
        let index = index_of(vec![advisory(
            "GHSA-1",
            5.0,
            vec![npm("lodash", vec![range("4.0.0", "4.17.21")], vec![])],
        )]);
        assert!(Matcher::new(&index).findings(&[extracted("lodash", "4.17.21")]).is_empty());
    }
}
