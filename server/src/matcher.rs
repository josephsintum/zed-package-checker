//! Deciding which advisories apply to a project's dependencies.
//!
//! Only the range arithmetic is ours; version *ordering* lives in
//! `crate::version`. osv-scanner's own matcher is not reused: its database cache is filtered to the package names present when it first
//! loaded, and later calls receive that stale set regardless of what the project
//! now depends on.

use crate::index::Index;
use crate::model::{Advisory, Anchor, ExtractedPackage, Finding, Fix, Package, PackageKey};
use crate::version::Version;
use std::sync::Arc;

/// OSV's sentinel for "affected since the first release". It is not a version
/// string and must not be compared as one.
const INTRODUCED_FROM_THE_BEGINNING: &str = "0";

/// Matches extracted packages against an index.
pub struct Matcher<'a> {
    index: &'a Index,
}

impl<'a> Matcher<'a> {
    /// A matcher over `index`.
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
            let fix = self.fix_for(&extracted.package, &advisories);
            findings.push(Finding {
                package: extracted.package.clone(),
                advisories,
                evidence: extracted.evidence.clone(),
                declared: extracted.declared.clone().map(Anchor::new),
                paths: extracted.paths.clone(),
                reachable: None,
                from_range: extracted.from_range,
                dep_groups: extracted.dep_groups.clone(),
                fix,
            });
        }
        findings
    }

    /// Whether any advisory in the index still affects this package at
    /// `version`.
    ///
    /// Shares `affects` with `applicable`, so a version this clears is one that
    /// would produce no finding. Clones nothing, unlike `applicable`.
    pub fn affected_at(&self, key: &PackageKey, version: &str) -> bool {
        let Ok(parsed) = Version::parse(version, key.ecosystem) else {
            // A version we cannot order is one we cannot recommend.
            return true;
        };
        self.index
            .lookup(key)
            .any(|advisory| affects(advisory, key, version, &parsed))
    }

    /// The lowest published version above the installed one that no advisory on
    /// this package still affects.
    ///
    /// Each candidate is checked against the whole index, not just the
    /// advisories that produced this finding, because a fix for one can be
    /// affected by another. "Above the installed one" keeps a fix backported to
    /// an older release line from being offered as a downgrade.
    pub fn fix_for(&self, package: &Package, advisories: &[Arc<Advisory>]) -> Fix {
        let Ok(installed) = Version::parse(&package.version, package.ecosystem()) else {
            return Fix::None;
        };

        let mut candidates: Vec<(Version<'_>, &str)> = advisories
            .iter()
            .flat_map(|advisory| advisory.fixed_versions_for(&package.key))
            .filter_map(|fixed| {
                Version::parse(fixed, package.ecosystem())
                    .ok()
                    .map(|parsed| (parsed, fixed))
            })
            .filter(|(parsed, _)| installed.compare(parsed) == std::cmp::Ordering::Less)
            .collect();
        if candidates.is_empty() {
            return Fix::None;
        }

        // Ascending, so the first that clears is the lowest that does.
        candidates.sort_by(|(a, _), (b, _)| a.compare(b));
        // Backported fixes repeat the same version across advisories, and a
        // Go toolchain finding carries seventy-six of them; each duplicate is
        // an entire pass over the package's posting list.
        candidates.dedup_by(|(a, _), (b, _)| a.compare(b) == std::cmp::Ordering::Equal);

        candidates
            .into_iter()
            .find(|(_, fixed)| !self.affected_at(&package.key, fixed))
            .map_or(Fix::Partial, |(_, fixed)| Fix::Clears(fixed.into()))
    }

    fn applicable(&self, package: &Package) -> Vec<Arc<Advisory>> {
        let candidates = self.index.lookup(&package.key);

        // Parsed once for the whole candidate set, not inside every bound
        // comparison.
        let Ok(version) = Version::parse(&package.version, package.ecosystem()) else {
            return Vec::new();
        };

        let mut hits: Vec<Arc<Advisory>> = candidates
            .filter(|advisory| affects(advisory, &package.key, &package.version, &version))
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

/// Takes the key and the version separately rather than a `Package`, so
/// checking a candidate fix does not have to build one per candidate.
fn affects(advisory: &Advisory, key: &PackageKey, raw: &str, version: &Version<'_>) -> bool {
    for entry in &advisory.affected {
        if entry.package != *key {
            continue;
        }
        // An explicit version list is authoritative for the versions it names,
        // and OSV uses it for ecosystems with no reliable ordering.
        if entry.versions.iter().any(|v| **v == *raw) {
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
        && matches!(
            version.compare_str(&range.introduced),
            Ok(std::cmp::Ordering::Less)
        )
    {
        return false;
    }

    if !range.fixed.is_empty() {
        return matches!(
            version.compare_str(&range.fixed),
            Ok(std::cmp::Ordering::Less)
        );
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
            version_span: None,
            paths: Vec::new(),
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

    /// The `Fix` the matcher decides for one package against one index.
    fn fix_of(index: &Index, name: &str, version: &str) -> Fix {
        Matcher::new(index)
            .findings(&[extracted(name, version)])
            .into_iter()
            .next()
            .map_or(Fix::None, |f| f.fix)
    }

    mod ranges {
        use super::*;

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
    }

    mod severity {
        use super::*;

        #[test]
        fn advisories_are_sorted_by_severity_then_id() {
            let index = index_of(vec![
                advisory(
                    "GHSA-low",
                    2.0,
                    vec![npm("lodash", vec![range("0", "")], vec![])],
                ),
                advisory(
                    "GHSA-crit",
                    9.5,
                    vec![npm("lodash", vec![range("0", "")], vec![])],
                ),
                advisory(
                    "GHSA-b-high",
                    7.5,
                    vec![npm("lodash", vec![range("0", "")], vec![])],
                ),
                advisory(
                    "GHSA-a-high",
                    7.5,
                    vec![npm("lodash", vec![range("0", "")], vec![])],
                ),
            ]);
            assert_eq!(
                matches(&index, "lodash", "1.0.0"),
                ["GHSA-crit", "GHSA-a-high", "GHSA-b-high", "GHSA-low"]
            );
        }

        #[test]
        fn a_malicious_advisory_outranks_a_scored_one() {
            let index = index_of(vec![
                advisory(
                    "GHSA-crit",
                    9.8,
                    vec![npm("evil", vec![range("0", "")], vec![])],
                ),
                advisory(
                    "MAL-2024-1",
                    0.0,
                    vec![npm("evil", vec![range("0", "")], vec![])],
                ),
            ]);
            let findings = Matcher::new(&index).findings(&[extracted("evil", "1.0.0")]);
            assert_eq!(findings.len(), 1);
            assert!(findings[0].malicious());
            assert_eq!(findings[0].severity(), Severity::Critical);
            // Ties on Critical fall back to the id, so the MAL- entry sorts second.
            assert_eq!(&*findings[0].worst().unwrap().id, "GHSA-crit");
        }

        #[test]
        fn an_advisory_aliased_to_a_mal_id_is_malicious() {
            // `Finding::malicious()` is an `any`, so a sibling MAL- record usually
            // rescues this. Here there is none, which is the case the per-advisory
            // predicate has to get right on its own.
            let index = index_of(vec![Advisory {
                aliases: Box::from([Box::<str>::from("MAL-2026-1380")]),
                ..advisory(
                    "GHSA-9ppg-jx86-fqw7",
                    0.0,
                    vec![npm("cline", vec![range("0", "")], vec![])],
                )
            }]);
            let findings = Matcher::new(&index).findings(&[extracted("cline", "1.0.0")]);
            assert_eq!(findings.len(), 1);
            assert!(findings[0].malicious());
            assert_eq!(findings[0].severity(), Severity::Critical);
        }
    }

    mod fixes {
        use super::*;

        #[test]
        fn the_fix_is_the_lowest_version_clearing_every_advisory() {
            // Shaped on lodash@4.17.15: the worst advisory is fixed in 4.17.21,
            // but another is still open until 4.18.0.
            let index = index_of(vec![
                advisory(
                    "GHSA-worst",
                    7.2,
                    vec![npm("lodash", vec![range("0", "4.17.21")], vec![])],
                ),
                advisory(
                    "GHSA-later",
                    5.0,
                    vec![npm("lodash", vec![range("0", "4.18.0")], vec![])],
                ),
            ]);
            assert_eq!(
                fix_of(&index, "lodash", "4.17.15"),
                Fix::Clears("4.18.0".into())
            );
        }

        #[test]
        fn a_fix_another_advisory_still_affects_is_rejected() {
            // The reason the verification step exists. A is fixed in 1.5.0, but B
            // covers everything below 2.0.0 — so 1.5.0 is no fix at all, and the
            // answer has to be the next candidate up.
            let index = index_of(vec![
                advisory(
                    "GHSA-a",
                    9.0,
                    vec![npm("evil", vec![range("1.0.0", "1.5.0")], vec![])],
                ),
                advisory(
                    "GHSA-b",
                    5.0,
                    vec![npm("evil", vec![range("0", "2.0.0")], vec![])],
                ),
            ]);
            assert_eq!(
                fix_of(&index, "evil", "1.2.0"),
                Fix::Clears("2.0.0".into()),
                "1.5.0 is itself affected by GHSA-b"
            );
        }

        #[test]
        fn disjoint_release_lines_have_no_single_fix() {
            // One advisory is fixed in 2.0.0; another opened at 1.0.0 and never
            // closed, so nothing published clears both.
            let index = index_of(vec![
                advisory(
                    "GHSA-fixed",
                    7.0,
                    vec![npm("pkg", vec![range("0", "2.0.0")], vec![])],
                ),
                advisory(
                    "GHSA-open",
                    7.0,
                    vec![npm("pkg", vec![range("1.0.0", "")], vec![])],
                ),
            ]);
            assert_eq!(fix_of(&index, "pkg", "1.5.0"), Fix::Partial);
        }

        #[test]
        fn an_advisory_with_only_last_affected_names_no_fix() {
            let index = index_of(vec![advisory(
                "GHSA-1",
                7.0,
                vec![npm(
                    "pkg",
                    vec![AffectedRange {
                        introduced: "0".into(),
                        fixed: Box::default(),
                        last_affected: "2.0.0".into(),
                    }],
                    vec![],
                )],
            )]);
            assert_eq!(fix_of(&index, "pkg", "1.0.0"), Fix::None);
        }

        #[test]
        fn candidates_are_ordered_by_the_ecosystem_not_the_archive() {
            // Lexicographically "10.0.0" sorts below "9.0.0", so a string sort
            // would answer 9.0.0 here and leave the other advisory unresolved.
            let index = index_of(vec![
                advisory(
                    "GHSA-a",
                    7.0,
                    vec![npm("pkg", vec![range("0", "9.0.0")], vec![])],
                ),
                advisory(
                    "GHSA-b",
                    7.0,
                    vec![npm("pkg", vec![range("0", "10.0.0")], vec![])],
                ),
            ]);
            assert_eq!(fix_of(&index, "pkg", "1.0.0"), Fix::Clears("10.0.0".into()));
        }

        #[test]
        fn a_fix_named_in_an_explicit_versions_list_is_rejected() {
            // OSV uses `versions` where ordering is unreliable, and `affects`
            // already honours it — so the verification has to as well.
            let index = index_of(vec![
                advisory(
                    "GHSA-a",
                    7.0,
                    vec![npm("pkg", vec![range("0", "2.0.0")], vec![])],
                ),
                advisory("GHSA-b", 7.0, vec![npm("pkg", vec![], vec!["2.0.0"])]),
            ]);
            assert_eq!(fix_of(&index, "pkg", "1.0.0"), Fix::Partial);
        }

        #[test]
        fn affected_at_agrees_with_findings() {
            let index = index_of(vec![advisory(
                "GHSA-1",
                7.0,
                vec![npm("pkg", vec![range("1.0.0", "2.0.0")], vec![])],
            )]);
            let matcher = Matcher::new(&index);
            let key = crate::model::PackageKey::new(Ecosystem::Npm, "pkg");
            for version in ["0.9.0", "1.0.0", "1.9.9", "2.0.0", "3.0.0"] {
                assert_eq!(
                    matcher.affected_at(&key, version),
                    !matches(&index, "pkg", version).is_empty(),
                    "the two must share one definition of affected, at {version}"
                );
            }
        }

        #[test]
        fn a_backported_fix_is_never_offered_as_a_downgrade() {
            // One advisory patched on two release lines at once. 1.2.3 is
            // genuinely unaffected, and genuinely useless to a project on 2.0.0.
            let index = index_of(vec![advisory(
                "GHSA-1",
                7.0,
                vec![npm(
                    "pkg",
                    vec![range("1.0.0", "1.2.3"), range("2.0.0", "2.0.1")],
                    vec![],
                )],
            )]);
            assert_eq!(fix_of(&index, "pkg", "2.0.0"), Fix::Clears("2.0.1".into()));
            // The lower line still gets the lower fix, which is right for it.
            assert_eq!(fix_of(&index, "pkg", "1.1.0"), Fix::Clears("1.2.3".into()));
        }

        #[test]
        fn a_fix_at_or_below_the_installed_version_is_not_a_fix() {
            // Everything published is behind us and something is still open, so
            // there is nothing to upgrade to.
            let index = index_of(vec![
                advisory(
                    "GHSA-old",
                    7.0,
                    vec![npm("pkg", vec![range("0", "1.0.0")], vec![])],
                ),
                advisory(
                    "GHSA-open",
                    7.0,
                    vec![npm("pkg", vec![range("2.0.0", "")], vec![])],
                ),
            ]);
            assert_eq!(fix_of(&index, "pkg", "3.0.0"), Fix::None);
        }
    }

    mod findings {
        use super::*;

        #[test]
        fn the_chain_that_reaches_a_package_survives_into_the_finding() {
            // Without this the graph's work stops at the extractor and every
            // finding claims to be direct, which is what `direct()` reports.
            let index = index_of(vec![advisory(
                "GHSA-1",
                5.0,
                vec![npm("minimist", vec![range("1.0.0", "1.2.6")], vec![])],
            )]);
            let chain = vec![
                PackageKey::new(Ecosystem::Npm, "tar"),
                PackageKey::new(Ecosystem::Npm, "minimist"),
            ];
            let reached = extracted("minimist", "1.2.0").with_paths(vec![chain.clone()]);
            let found = Matcher::new(&index).findings(&[reached]);
            assert_eq!(found[0].paths, vec![chain]);
            assert!(!found[0].direct());
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
            assert!(
                Matcher::new(&index)
                    .findings(&[extracted("lodash", "4.17.21")])
                    .is_empty()
            );
        }

        #[test]
        fn findings_carry_evidence_and_declaration() {
            // The manifest line is what the diagnostic anchors on, so it must
            // survive matching rather than being rediscovered later.
            let index = index_of(vec![advisory(
                "GHSA-1",
                5.0,
                vec![npm("lodash", vec![range("0", "")], vec![])],
            )]);
            let declared = Site::new("/proj/package.json", Range::whole_line(5));
            let evidence = Site::new("/proj/package-lock.json", Range::whole_line(14));
            let extracted = ExtractedPackage {
                evidence: evidence.clone(),
                declared: Some(declared.clone()),
                from_range: true,
                dep_groups: vec![crate::model::DEV_GROUP.to_owned()],
                ..extracted("lodash", "4.17.15")
            };

            let findings = Matcher::new(&index).findings(&[extracted]);
            let f = &findings[0];
            assert_eq!(f.evidence, evidence);
            assert_eq!(
                f.anchor_site(),
                &declared,
                "the manifest declaration is the anchor"
            );
            assert!(f.from_range, "from_range was lost");
            assert!(f.dev(), "dependency groups were lost");
        }

        #[test]
        fn an_unparsable_bound_skips_one_advisory_not_the_scan() {
            // A bound the ecosystem's rules cannot read must not cost the user
            // every other finding in the project.
            let index = index_of(vec![
                advisory(
                    "GHSA-bad",
                    5.0,
                    vec![npm("p", vec![range("0", "not a version")], vec![])],
                ),
                advisory(
                    "GHSA-good",
                    5.0,
                    vec![npm("q", vec![range("0", "")], vec![])],
                ),
            ]);
            let findings =
                Matcher::new(&index).findings(&[extracted("p", "1.0.0"), extracted("q", "1.0.0")]);
            let names: Vec<&str> = findings.iter().map(|f| f.package.name()).collect();
            assert_eq!(names, ["q"], "{findings:?}");
        }
    }
}
