//! Ported from `server/internal/model/model_test.go`, case for case, so a
//! divergence between the two servers shows up as a failing test rather than as
//! a difference in a benchmark table.

use package_checker::model::*;
use std::sync::Arc;

fn advisory(id: &str, score: f64) -> Advisory {
    Advisory {
        id: id.into(),
        aliases: Box::default(),
        summary: Box::default(),
        cvss_score: score,
        cvss_vector: Box::default(),
        affected: Box::default(),
        references: Box::default(),
    }
}

fn site(path: &str, line: u32) -> Site {
    Site::new(path, Range::whole_line(line))
}

fn finding(pkg: Package, advisories: Vec<Advisory>) -> Finding {
    Finding {
        package: pkg,
        advisories: advisories.into_iter().map(Arc::new).collect(),
        evidence: site("/p/package.json", 1),
        declared: None,
        paths: Vec::new(),
        reachable: None,
        from_range: false,
        dep_groups: Vec::new(),
    }
}

#[test]
fn severity_from_cvss_bands() {
    for (score, want) in [
        (0.0, Severity::Unknown),
        (0.1, Severity::Low),
        (3.9, Severity::Low),
        (4.0, Severity::Medium),
        (6.9, Severity::Medium),
        (7.0, Severity::High),
        (8.9, Severity::High),
        (9.0, Severity::Critical),
        (10.0, Severity::Critical),
        // Out of range clamps rather than discarding a valid advisory.
        (11.0, Severity::Critical),
        (-1.0, Severity::Unknown),
    ] {
        assert_eq!(Severity::from_cvss(score), want, "score {score}");
    }
}

#[test]
fn severity_orders_unknown_lowest() {
    let ascending = [
        Severity::Unknown,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    for pair in ascending.windows(2) {
        assert!(
            pair[0] < pair[1],
            "{:?} should sort below {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn position_from_one_based_line() {
    for (one_based, want) in [(1u32, 0u32), (2, 1), (42, 41)] {
        let got = Position::from_one_based_line(one_based);
        assert_eq!(got.line, want);
        assert_eq!(got.column, 0);
    }
    // A zero line would underflow; it saturates rather than wrapping to u32::MAX.
    assert_eq!(Position::from_one_based_line(0).line, 0);
}

#[test]
fn whole_line_is_half_open() {
    let r = Range::whole_line(3);
    assert_eq!(r.start, Position::new(2, 0));
    assert_eq!(r.end, Position::new(3, 0));
}

#[test]
fn ecosystem_from_purl_type() {
    for (purl, want) in [
        ("npm", Some(Ecosystem::Npm)),
        ("golang", Some(Ecosystem::Go)),
        ("pypi", Some(Ecosystem::PyPI)),
        ("cargo", Some(Ecosystem::CratesIo)),
        ("maven", None),
        ("", None),
    ] {
        assert_eq!(Ecosystem::from_purl_type(purl), want, "purl type {purl:?}");
    }
}

#[test]
fn ecosystem_names_are_verbatim() {
    // Capitalisation and the dot are load-bearing: they go straight into the
    // advisory bucket URL.
    assert_eq!(Ecosystem::Npm.as_str(), "npm");
    assert_eq!(Ecosystem::Go.as_str(), "Go");
    assert_eq!(Ecosystem::PyPI.as_str(), "PyPI");
    assert_eq!(Ecosystem::CratesIo.as_str(), "crates.io");
}

#[test]
fn ecosystem_parses_and_strips_suffixes() {
    assert_eq!("npm".parse(), Ok(Ecosystem::Npm));
    assert_eq!("crates.io".parse(), Ok(Ecosystem::CratesIo));
    // OSV suffixes an ecosystem after a colon; only the base names it.
    assert_eq!("PyPI:something".parse(), Ok(Ecosystem::PyPI));
    assert!("Debian:12".parse::<Ecosystem>().is_err());
}

#[test]
fn advisory_malicious_is_an_exact_prefix() {
    assert!(advisory("MAL-2024-1", 0.0).malicious());
    // Not a prefix match on "MAL" alone.
    assert!(!advisory("MALFORMED-1", 0.0).malicious());
    assert!(!advisory("GHSA-xxxx", 0.0).malicious());
    assert!(!advisory("CVE-2024-1", 0.0).malicious());
}

#[test]
fn malicious_outranks_its_score() {
    // No CVSS at all, still critical: "remove this now" does not scale.
    assert_eq!(advisory("MAL-2024-1", 0.0).severity(), Severity::Critical);
    assert_eq!(advisory("MAL-2024-1", 1.0).severity(), Severity::Critical);
}

#[test]
fn advisory_url() {
    assert_eq!(
        advisory("GHSA-p6mc-m468-83gw", 0.0).url(),
        "https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw"
    );
}

#[test]
fn fixed_versions_only_for_the_asked_package() {
    let lodash = PackageKey::new(Ecosystem::Npm, "lodash");
    let other = PackageKey::new(Ecosystem::Npm, "other");
    let repeated = PackageKey::new(Ecosystem::Npm, "repeated");
    let mut a = advisory("GHSA-1", 5.0);
    a.affected = Box::new([
        Affected {
            package: lodash.clone(),
            ranges: [
                AffectedRange {
                    introduced: "0".into(),
                    fixed: "4.17.21".into(),
                    last_affected: Box::default(),
                },
                // No fix: contributes nothing.
                AffectedRange {
                    introduced: "5.0.0".into(),
                    fixed: Box::default(),
                    last_affected: Box::default(),
                },
            ]
            .into(),
            versions: Box::default(),
        },
        Affected {
            package: other.clone(),
            ranges: Box::new([AffectedRange {
                introduced: "0".into(),
                fixed: "9.9.9".into(),
                last_affected: Box::default(),
            }]),
            versions: Box::default(),
        },
        Affected {
            package: repeated.clone(),
            ranges: Box::new([
                AffectedRange {
                    introduced: "0".into(),
                    fixed: "1.2.3".into(),
                    last_affected: Box::default(),
                },
                // A second release line, patched in the same release.
                AffectedRange {
                    introduced: "1.0.0".into(),
                    fixed: "1.2.3".into(),
                    last_affected: Box::default(),
                },
            ]),
            versions: Box::default(),
        },
    ]);

    assert_eq!(a.fixed_versions_for(&lodash), vec!["4.17.21"]);
    // The same fix on several ranges is reported once, not once per range.
    assert_eq!(a.fixed_versions_for(&repeated), vec!["1.2.3"]);
    assert_eq!(a.fixed_versions_for(&other), vec!["9.9.9"]);
    assert!(
        a.fixed_versions_for(&PackageKey::new(Ecosystem::Go, "lodash"))
            .is_empty()
    );
}

#[test]
fn finding_severity_is_the_worst_advisory() {
    let f = finding(
        Package::new(Ecosystem::Npm, "lodash", "4.17.15"),
        vec![
            advisory("GHSA-low", 2.0),
            advisory("GHSA-high", 7.5),
            advisory("GHSA-med", 5.0),
        ],
    );
    assert_eq!(f.severity(), Severity::High);
    assert_eq!(&*f.worst().id, "GHSA-high");
}

#[test]
fn worst_prefers_the_earlier_advisory_on_a_tie() {
    let f = finding(
        Package::new(Ecosystem::Npm, "lodash", "4.17.15"),
        vec![advisory("GHSA-first", 7.5), advisory("GHSA-second", 7.5)],
    );
    assert_eq!(&*f.worst().id, "GHSA-first");
}

#[test]
fn direct_means_no_path() {
    let mut f = finding(
        Package::new(Ecosystem::Npm, "lodash", "4.17.15"),
        vec![advisory("GHSA-1", 1.0)],
    );
    assert!(f.direct());
    assert!(f.shortest_path().is_none());

    f.paths = vec![
        vec![
            PackageKey::new(Ecosystem::Npm, "a"),
            PackageKey::new(Ecosystem::Npm, "b"),
            PackageKey::new(Ecosystem::Npm, "lodash"),
        ],
        vec![
            PackageKey::new(Ecosystem::Npm, "c"),
            PackageKey::new(Ecosystem::Npm, "lodash"),
        ],
    ];
    assert!(!f.direct());
    assert_eq!(f.shortest_path().map(<[_]>::len), Some(2));
}

#[test]
fn dev_reads_the_dep_groups() {
    let mut f = finding(
        Package::new(Ecosystem::Npm, "lodash", "4.17.15"),
        vec![advisory("GHSA-1", 1.0)],
    );
    assert!(!f.dev());
    f.dep_groups = vec!["optional".into()];
    assert!(!f.dev());
    f.dep_groups = vec!["dev".into()];
    assert!(f.dev());
}

#[test]
fn anchor_site_falls_back_to_evidence() {
    let mut f = finding(
        Package::new(Ecosystem::Npm, "lodash", "4.17.15"),
        vec![advisory("GHSA-1", 1.0)],
    );
    f.evidence = site("/p/package-lock.json", 12);
    assert_eq!(
        f.anchor_site().path.to_str().unwrap(),
        "/p/package-lock.json"
    );

    f.declared = Some(Anchor::new(site("/p/package.json", 4)));
    assert_eq!(f.anchor_site().path.to_str().unwrap(), "/p/package.json");
    assert_eq!(f.anchor_site().range, Range::whole_line(4));
}

#[test]
fn report_groups_by_anchor_file() {
    let mut a = finding(
        Package::new(Ecosystem::Npm, "a", "1.0.0"),
        vec![advisory("GHSA-1", 1.0)],
    );
    a.declared = Some(Anchor::new(site("/p/package.json", 2)));
    let mut b = finding(
        Package::new(Ecosystem::Npm, "b", "1.0.0"),
        vec![advisory("GHSA-2", 1.0)],
    );
    b.declared = Some(Anchor::new(site("/p/package.json", 3)));
    let mut c = finding(
        Package::new(Ecosystem::Go, "c", "1.0.0"),
        vec![advisory("GHSA-3", 1.0)],
    );
    c.evidence = site("/p/go.mod", 5);

    let report = Report::new("/p", vec![a, b, c]);
    let grouped = report.by_file();
    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped[std::path::Path::new("/p/package.json")].len(), 2);
    assert_eq!(grouped[std::path::Path::new("/p/go.mod")].len(), 1);
}

#[test]
fn report_with_no_findings_groups_nothing() {
    assert!(Report::new("/p", Vec::new()).by_file().is_empty());
}

#[test]
fn stringers() {
    let key = PackageKey::new(Ecosystem::Npm, "lodash");
    assert_eq!(key.to_string(), "npm:lodash");
    assert_eq!(
        Package::new(Ecosystem::Npm, "lodash", "4.17.15").to_string(),
        "npm:lodash@4.17.15"
    );
    assert!(
        Package::new(Ecosystem::Go, "stdlib", "1.21")
            .key
            .is_go_toolchain()
    );
    assert!(!key.is_go_toolchain());
}

#[test]
fn ecosystems_of_is_sorted_and_deduplicated() {
    let pkgs = [
        Ecosystem::PyPI,
        Ecosystem::Npm,
        Ecosystem::Npm,
        Ecosystem::Go,
    ]
    .into_iter()
    .map(|e| ExtractedPackage {
        package: Package::new(e, "x", "1"),
        evidence: site("/p/f", 1),
        declared: None,
        dep_groups: Vec::new(),
        from_range: false,
    })
    .collect::<Vec<_>>();
    assert_eq!(
        ecosystems_of(&pkgs),
        vec![Ecosystem::Npm, Ecosystem::Go, Ecosystem::PyPI]
    );
}
