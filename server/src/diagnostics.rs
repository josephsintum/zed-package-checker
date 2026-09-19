//! Rendering findings as diagnostics.
//!
//! Kept apart from the protocol glue in `crate::lsp` because this is where the
//! wording lives, and the wording is the product: it is the only part of the
//! server most users will ever read.

use crate::model::{Finding, Fix, Severity};
use crate::span::{Encoding, column};
use std::path::Path;
use tower_lsp_server::ls_types::{
    CodeDescription, Diagnostic, DiagnosticRelatedInformation, DiagnosticSeverity, Location,
    NumberOrString, Position, Range, Uri,
};

/// One file's diagnostics: one per finding, plus a summary when there is more
/// than one thing wrong.
pub fn for_file(path: &Path, findings: &[Finding], encoding: Encoding) -> Vec<Diagnostic> {
    if findings.is_empty() {
        return Vec::new();
    }
    // Read once, for the summary anchor and for re-encoding columns. A manifest
    // that cannot be read still produces diagnostics, just with byte columns.
    let source = crate::read::manifest(path);

    // Which findings a quick fix can actually act on, so the message only
    // promises one where `action` would offer it. The same parse it does, over
    // the same text — microseconds, and the alternative is telling the user to
    // press a key that does nothing.
    let sightings = match (crate::extract::parser_for(path), source.as_deref()) {
        (Some(parse), Some(src)) => parse(src, path),
        _ => Vec::new(),
    };

    let mut out = Vec::with_capacity(findings.len() + 1);
    if let Some(summary) = summary(path, findings, source.as_deref()) {
        out.push(summary);
    }
    out.extend(findings.iter().filter_map(|finding| {
        let fixable = crate::extract::version_span(&sightings, finding).is_some();
        finding_diagnostic(finding, fixable)
    }));

    if encoding == Encoding::Utf16
        && let Some(source) = source.as_deref()
    {
        let lines: Vec<&str> = source.lines().collect();
        for diagnostic in &mut out {
            reencode(&mut diagnostic.range, &lines);
        }
    }
    out
}

fn finding_diagnostic(finding: &Finding, fixable: bool) -> Option<Diagnostic> {
    let worst = finding.worst()?;
    let anchor = finding.anchor_site();

    let mut diagnostic = Diagnostic {
        range: to_range(anchor.range),
        severity: Some(severity_for(finding)),
        code: Some(NumberOrString::String(worst.id.to_string())),
        code_description: worst
            .url()
            .parse::<Uri>()
            .ok()
            .map(|href| CodeDescription { href }),
        source: Some(crate::config::NAME.to_owned()),
        message: message_for(finding, fixable),
        ..Default::default()
    };

    if resolved_elsewhere(finding)
        && let Some(uri) = file_uri(&finding.evidence.path)
    {
        // Point at where the version was actually resolved, since the
        // diagnostic itself sits on the manifest line the user can edit.
        diagnostic.related_information = Some(vec![DiagnosticRelatedInformation {
            location: Location {
                uri,
                range: to_range(finding.evidence.range),
            },
            message: format!("{} resolved here", finding.package),
        }]);
    }

    // Round-trips back on a code action, so a fix can be offered without
    // rescanning to work out what the diagnostic referred to.
    let mut data = serde_json::json!({
        "ecosystem": finding.package.ecosystem().as_str(),
        "name": finding.package.name(),
        "version": finding.package.version,
        "advisories": finding.advisories.iter().map(|a| a.id.to_string()).collect::<Vec<_>>(),
        "direct": finding.direct(),
    });
    // Omitted rather than null when there is nothing to name, which is what a
    // consumer testing for the key expects.
    if let Fix::Clears(version) = &finding.fix
        && let Some(object) = data.as_object_mut()
    {
        object.insert("fixedVersion".into(), (**version).into());
    }
    diagnostic.data = Some(data);
    Some(diagnostic)
}

/// Whether the version was resolved in a file other than the one the diagnostic
/// sits on — a lockfile pinning what a manifest left as a range.
///
/// Shared by the `relatedInformation` link and the message clause. The link
/// additionally needs the evidence path to survive `file_uri`, so it can be
/// absent where the sentence is present; the sentence is the one that must not
/// go missing, since it is the only part a client is obliged to show.
fn resolved_elsewhere(finding: &Finding) -> bool {
    finding.evidence.path != finding.anchor_site().path
}

/// One line saying how much is wrong with a file.
///
/// Per-package diagnostics scatter across files the user may not have open, so
/// nothing otherwise says "this project has a problem" in one place.
fn summary(path: &Path, findings: &[Finding], source: Option<&str>) -> Option<Diagnostic> {
    if findings.len() < 2 {
        // One finding is its own summary.
        return None;
    }

    let mut counts = [0usize; 5];
    let mut worst = Severity::Unknown;
    let mut malicious = 0usize;
    for finding in findings {
        let severity = finding.severity();
        counts[severity as usize] += 1;
        worst = worst.max(severity);
        if finding.malicious() {
            malicious += 1;
        }
    }

    let parts: Vec<String> = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ]
    .into_iter()
    .filter(|s| counts[*s as usize] > 0)
    .map(|s| format!("{} {}", counts[s as usize], s.as_str().to_lowercase()))
    .collect();

    let mut message = format!("{} vulnerable dependencies", findings.len());
    if !parts.is_empty() {
        message.push_str(&format!(" ({})", parts.join(", ")));
    }
    if malicious > 0 {
        message.push_str(&format!(" — {malicious} MALICIOUS"));
    }

    let line = summary_anchor_line(path, source);
    Some(Diagnostic {
        range: to_range(crate::model::Range::whole_line(line)),
        severity: Some(severity_level(worst, false, None)),
        code: Some(NumberOrString::String("summary".to_owned())),
        source: Some(crate::config::NAME.to_owned()),
        message,
        data: Some(serde_json::json!({ "summary": true, "path": path.to_string_lossy() })),
        ..Default::default()
    })
}

/// The one-line description a diagnostic leads with.
/// The key that runs a quick fix, as the editor most likely binds it.
///
/// Named rather than described because "a quick fix is available" tells someone
/// who does not already know the phrase nothing at all. Read from the machine
/// the server runs on, which is the editor's machine except over a remote
/// connection.
const FIX_KEY: &str = if cfg!(target_os = "macos") {
    "Cmd+."
} else {
    "Ctrl+."
};

fn message_for(finding: &Finding, fixable: bool) -> String {
    let mut message = String::new();

    if finding.malicious() {
        message.push_str("MALICIOUS: ");
    }
    let toolchain = finding.package.key.is_go_toolchain();
    if toolchain {
        message.push_str(&format!("Go toolchain {}", finding.package.version));
    } else {
        message.push_str(&finding.package.to_string());
    }
    message.push_str(&format!(" — {}", count_and_severity(finding)));

    // The version named here is one the matcher checked back against the index,
    // so it clears every advisory rather than only the worst one's. Where none
    // does, saying so beats naming a version that does not finish the job.
    match &finding.fix {
        Fix::Clears(version) => message.push_str(&format!(". Fixed in {version}")),
        Fix::Partial if finding.advisories.len() == 1 => {
            message.push_str(". No published version clears it")
        }
        Fix::Partial => message.push_str(". No single version clears all of them"),
        Fix::None => {}
    }
    if toolchain {
        message.push_str(
            ". The go directive is a minimum, so the toolchain building this may already be newer",
        );
    }
    if finding.from_range {
        message.push_str(". Version inferred from a range, so the installed one may differ");
    }
    if resolved_elsewhere(finding) {
        message.push_str(
            ". Version comes from the lockfile, so editing this file alone will not clear it",
        );
    }
    if finding.dev() {
        message.push_str(". Development dependency");
    }
    // Last, because it is the one clause that is an instruction rather than a
    // fact, and only where the fix exists and can be written somewhere.
    if fixable && let Fix::Clears(version) = &finding.fix {
        message.push_str(&format!(". Press {FIX_KEY} to update to {version}"));
    }
    message
}

/// How much is wrong and how bad, omitting a severity nobody published rather
/// than printing "Unknown".
///
/// The Go vulnerability database carries no CVSS on any of its stdlib
/// advisories, so a toolchain finding would otherwise read "76 advisories,
/// worst Unknown", where the only word doing any work is the number.
fn count_and_severity(finding: &Finding) -> String {
    let Some(worst) = finding.worst() else {
        return format!("{} advisories", finding.advisories.len());
    };
    let n = finding.advisories.len();
    let rated = worst.severity() != Severity::Unknown;
    match (n, rated) {
        (1, true) => describe(worst.severity(), worst.cvss_score),
        (1, false) => "1 known vulnerability".to_owned(),
        (n, true) => format!(
            "{n} advisories, worst {}",
            describe(worst.severity(), worst.cvss_score)
        ),
        (n, false) => format!("{n} known vulnerabilities"),
    }
}

fn describe(severity: Severity, score: f64) -> String {
    if score > 0.0 {
        format!("{severity} (CVSS {score:.1})")
    } else {
        severity.to_string()
    }
}

fn severity_for(finding: &Finding) -> DiagnosticSeverity {
    if finding.malicious() {
        // Never demoted: "remove this now" does not become less true because
        // the package is a development dependency or its code is unreachable.
        return DiagnosticSeverity::ERROR;
    }
    severity_level(finding.severity(), finding.dev(), finding.reachable)
}

/// Lowers a severity for findings that are less likely to matter.
///
/// Development dependencies do not ship, and code proven unreachable cannot be
/// exploited through this project. Neither makes a finding false, so they are
/// demoted rather than hidden.
fn severity_level(severity: Severity, dev: bool, reachable: Option<bool>) -> DiagnosticSeverity {
    // Listed rather than tested with `>=`, so adding a severity means deciding
    // where it belongs.
    let base = match severity {
        Severity::Critical | Severity::High => DiagnosticSeverity::ERROR,
        _ => DiagnosticSeverity::WARNING,
    };
    if !dev && reachable.unwrap_or(true) {
        return base;
    }
    // Demoted by exactly one step. `base` is only ever ERROR or WARNING.
    if base == DiagnosticSeverity::ERROR {
        DiagnosticSeverity::WARNING
    } else {
        DiagnosticSeverity::INFORMATION
    }
}

/// The line a file's summary is anchored on.
///
/// The declaration every file of its kind must contain, so it survives
/// reformatting, rather than line 1.
fn summary_anchor_line(path: &Path, source: Option<&str>) -> u32 {
    let Some(source) = source else { return 1 };
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let matches: fn(&str, i32) -> bool = match name {
        "go.mod" => |line, _| line.starts_with("module "),
        "package.json" => |line, depth| depth == 1 && line.starts_with("\"name\""),
        "Cargo.toml" | "pyproject.toml" => |line, _| line.starts_with("name ="),
        _ => return 1,
    };

    let mut depth = 0i32;
    for (i, text) in source.lines().enumerate() {
        let trimmed = text.trim();
        // Depth before the line, so a key on the same line as the brace that
        // opens its object is not counted as being inside it.
        if matches(trimmed, depth + opens_before(trimmed)) {
            return i as u32 + 1;
        }
        depth += brace_delta(trimmed);
    }
    1
}

/// Objects a line opens before its first key, which is what puts
/// `{"name": ...}` on a minified first line at depth 1.
fn opens_before(line: &str) -> i32 {
    line.chars()
        .take_while(|&c| c != '"')
        .filter(|&c| c == '{')
        .count() as i32
}

fn brace_delta(line: &str) -> i32 {
    line.chars().filter(|&c| c == '{').count() as i32
        - line.chars().filter(|&c| c == '}').count() as i32
}

fn to_range(range: crate::model::Range) -> Range {
    Range {
        start: Position::new(range.start.line, range.start.column),
        end: Position::new(range.end.line, range.end.column),
    }
}

/// Rewrites byte columns as UTF-16 code units, for a client that declined UTF-8.
fn reencode(range: &mut Range, lines: &[&str]) {
    let convert = |position: &mut Position| {
        if let Some(line) = lines.get(position.line as usize) {
            position.character = column(line, position.character as usize, Encoding::Utf16);
        }
    };
    convert(&mut range.start);
    convert(&mut range.end);
}

pub fn file_uri(path: &Path) -> Option<Uri> {
    format!("file://{}", path.to_str()?).parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Advisory, Anchor, DEV_GROUP, Ecosystem, Package, Site};
    use std::sync::Arc;

    fn advisory(id: &str, score: f64) -> Arc<Advisory> {
        Arc::new(Advisory {
            id: id.into(),
            aliases: Box::default(),
            summary: Box::default(),
            cvss_score: score,
            cvss_vector: Box::default(),
            affected: Box::default(),
            references: Box::default(),
        })
    }

    /// One npm finding on `lodash`, with everything optional left off.
    fn finding() -> Finding {
        Finding {
            package: Package::new(Ecosystem::Npm, "lodash", "4.17.15"),
            advisories: vec![advisory("GHSA-1", 7.2)],
            evidence: Site::new("/p/package.json", crate::model::Range::whole_line(1)),
            declared: None,
            paths: Vec::new(),
            reachable: None,
            from_range: false,
            dep_groups: Vec::new(),
            fix: Fix::None,
        }
    }

    /// The same, resolved in a lockfile and anchored on the manifest.
    fn lockfile_resolved() -> Finding {
        Finding {
            evidence: Site::new("/p/package-lock.json", crate::model::Range::whole_line(9)),
            declared: Some(Anchor::new(Site::new(
                "/p/package.json",
                crate::model::Range::whole_line(1),
            ))),
            ..finding()
        }
    }

    fn with(name: &str, score: f64, line: u32) -> Finding {
        Finding {
            package: Package::new(Ecosystem::Npm, name, "1.0.0"),
            advisories: vec![advisory("GHSA-1", score)],
            evidence: Site::new("/p/package.json", crate::model::Range::whole_line(line)),
            ..finding()
        }
    }

    mod message {
        use super::*;

        #[test]
        fn a_verified_fix_is_named() {
            let f = Finding {
                fix: Fix::Clears("4.18.0".into()),
                ..finding()
            };
            assert!(
                message_for(&f, false).ends_with(". Fixed in 4.18.0"),
                "{}",
                message_for(&f, false)
            );
        }

        #[test]
        fn no_clearing_version_is_said_rather_than_guessed() {
            // "all of them" needs something to be plural about.
            let one = Finding {
                fix: Fix::Partial,
                ..finding()
            };
            let message = message_for(&one, false);
            assert!(
                message.contains(". No published version clears it"),
                "{message}"
            );
            // Naming any one version here is the defect this replaces.
            assert!(!message.contains("Fixed in"), "{message}");

            let several = Finding {
                fix: Fix::Partial,
                advisories: vec![advisory("GHSA-1", 7.2), advisory("GHSA-2", 5.0)],
                ..finding()
            };
            let message = message_for(&several, false);
            assert!(
                message.contains(". No single version clears all of them"),
                "{message}"
            );
        }

        #[test]
        fn an_unfixed_finding_says_nothing_about_a_fix() {
            let message = message_for(&finding(), false);
            assert!(!message.contains("Fixed in"), "{message}");
            assert!(!message.contains("clears"), "{message}");
        }

        #[test]
        fn the_go_toolchain_names_a_verified_fix() {
            // Suppressed before, because the worst advisory's fix cleared almost
            // none of the other seventy-five. A verified one has no such problem.
            let f = Finding {
                package: Package::new(Ecosystem::Go, "stdlib", "1.21"),
                advisories: vec![advisory("GO-1", 0.0), advisory("GO-2", 0.0)],
                fix: Fix::Clears("1.25.13".into()),
                ..finding()
            };
            assert!(message_for(&f, false).contains(". Fixed in 1.25.13"));
        }

        #[test]
        fn a_lockfile_resolved_finding_says_the_manifest_is_not_enough() {
            let message = message_for(&lockfile_resolved(), false);
            assert!(
                message.contains(
                    ". Version comes from the lockfile, so editing this file alone will not clear it"
                ),
                "{message}"
            );
        }

        #[test]
        fn a_manifest_only_finding_does_not() {
            assert!(!message_for(&finding(), false).contains("lockfile"));
            // Nor does a range-inferred one, which is the other provenance case.
            let ranged = Finding {
                from_range: true,
                ..finding()
            };
            assert!(!message_for(&ranged, false).contains("lockfile"));
        }

        #[test]
        fn the_lockfile_clause_and_the_related_link_agree() {
            // Both derive from `resolved_elsewhere`, so a diagnostic can never
            // carry the link without the sentence or the other way round.
            for f in [finding(), lockfile_resolved()] {
                let says = message_for(&f, false).contains("lockfile");
                let links = finding_diagnostic(&f, false)
                    .expect("a finding with advisories renders")
                    .related_information
                    .is_some();
                assert_eq!(says, links, "{}", message_for(&f, false));
            }
        }

        #[test]
        fn a_fixable_finding_says_which_key_applies_it() {
            let f = Finding {
                fix: Fix::Clears("4.18.0".into()),
                ..finding()
            };
            let message = message_for(&f, true);
            assert!(
                message.ends_with(&format!(". Press {FIX_KEY} to update to 4.18.0")),
                "{message}"
            );
            // The instruction goes last, after every fact about the finding.
            assert!(message.contains(". Fixed in 4.18.0"), "{message}");
        }

        #[test]
        fn a_finding_with_nowhere_to_write_the_version_promises_nothing() {
            // A transitive dependency anchored in a lockfile has a verified fix and
            // no editable span. Naming a key that does nothing is worse than silence.
            let f = Finding {
                fix: Fix::Clears("4.18.0".into()),
                ..finding()
            };
            let message = message_for(&f, false);
            assert!(!message.contains("Press"), "{message}");
            assert!(message.contains(". Fixed in 4.18.0"), "{message}");
        }

        #[test]
        fn no_verified_fix_means_no_instruction_even_where_the_version_is_writable() {
            for fix in [Fix::Partial, Fix::None] {
                let f = Finding { fix, ..finding() };
                let message = message_for(&f, true);
                assert!(!message.contains("Press"), "{message}");
            }
        }
    }

    mod severity {
        use super::*;

        #[test]
        fn a_malicious_finding_is_never_demoted() {
            let f = Finding {
                advisories: vec![advisory("MAL-2024-1", 0.0)],
                dep_groups: vec![DEV_GROUP.to_owned()],
                reachable: Some(false),
                ..finding()
            };
            assert!(message_for(&f, false).starts_with("MALICIOUS: "));
            assert_eq!(severity_for(&f), DiagnosticSeverity::ERROR);
        }

        #[test]
        fn a_development_dependency_is_demoted_and_labelled() {
            let f = Finding {
                dep_groups: vec![DEV_GROUP.to_owned()],
                ..finding()
            };
            assert!(message_for(&f, false).ends_with(". Development dependency"));
            assert_ne!(severity_for(&f), severity_for(&finding()));
        }

        #[test]
        fn severity_follows_the_score_and_dev_demotes_one_step() {
            let cases: &[(&str, f64, bool, DiagnosticSeverity)] = &[
                (
                    "critical is an error",
                    9.8,
                    false,
                    DiagnosticSeverity::ERROR,
                ),
                ("high is an error", 7.5, false, DiagnosticSeverity::ERROR),
                (
                    "medium is a warning",
                    5.0,
                    false,
                    DiagnosticSeverity::WARNING,
                ),
                ("low is a warning", 2.0, false, DiagnosticSeverity::WARNING),
                (
                    "unscored is a warning",
                    0.0,
                    false,
                    DiagnosticSeverity::WARNING,
                ),
                // Development dependencies do not ship, so they are demoted
                // rather than hidden.
                (
                    "a dev dependency is demoted",
                    9.8,
                    true,
                    DiagnosticSeverity::WARNING,
                ),
                (
                    "a low dev dependency is demoted further",
                    2.0,
                    true,
                    DiagnosticSeverity::INFORMATION,
                ),
            ];
            for (name, score, dev, want) in cases {
                let f = Finding {
                    advisories: vec![advisory("GHSA-1", *score)],
                    dep_groups: if *dev {
                        vec![DEV_GROUP.to_owned()]
                    } else {
                        Vec::new()
                    },
                    ..finding()
                };
                assert_eq!(severity_for(&f), *want, "{name}");
            }
        }
    }

    mod summary {
        use super::*;

        #[test]
        fn the_summary_anchors_on_a_line_the_manifest_must_have() {
            // Line 1 would not survive reformatting, so each format has a
            // declaration the anchor hunts for instead.
            let source = "{\n  \"name\": \"x\",\n  \"dependencies\": {}\n}\n";
            assert_eq!(
                summary_anchor_line(Path::new("/p/package.json"), Some(source)),
                2
            );
            // With nothing to read, line 1 is the honest fallback.
            assert_eq!(summary_anchor_line(Path::new("/p/package.json"), None), 1);
        }

        #[test]
        fn a_summary_leads_when_more_than_one_thing_is_wrong() {
            // Per-package diagnostics scatter; the summary is the one line that
            // says the file has a problem.
            let findings = [with("a", 9.8, 3), with("b", 7.5, 4), with("c", 5.0, 5)];
            let diagnostics = for_file(Path::new("/p/package.json"), &findings, Encoding::Utf8);
            assert_eq!(diagnostics.len(), 4, "three findings plus a summary");

            let summary = &diagnostics[0];
            assert_eq!(summary.code, Some(NumberOrString::String("summary".into())));
            for want in [
                "3 vulnerable dependencies",
                "1 critical",
                "1 high",
                "1 medium",
            ] {
                assert!(
                    summary.message.contains(want),
                    "{:?} lacks {want}",
                    summary.message
                );
            }
            // Nothing to read at that path, so the first line is the anchor.
            assert_eq!(summary.range.start.line, 0);
            assert_eq!(summary.data.as_ref().unwrap()["summary"], true);
        }

        #[test]
        fn one_finding_is_its_own_summary() {
            let diagnostics = for_file(
                Path::new("/p/package.json"),
                &[with("a", 9.8, 3)],
                Encoding::Utf8,
            );
            assert_eq!(diagnostics.len(), 1);
            assert_ne!(
                diagnostics[0].code,
                Some(NumberOrString::String("summary".into()))
            );
        }
    }

    mod data {
        use super::*;

        #[test]
        fn fixed_version_is_omitted_rather_than_null() {
            // A consumer testing for the key must not be handed `null`, which is
            // what `Option` serialised to before.
            for fix in [Fix::None, Fix::Partial] {
                let data = finding_diagnostic(&Finding { fix, ..finding() }, false)
                    .expect("a finding with advisories renders")
                    .data
                    .expect("data");
                assert!(data.get("fixedVersion").is_none(), "{data}");
            }

            let data = finding_diagnostic(
                &Finding {
                    fix: Fix::Clears("4.18.0".into()),
                    ..finding()
                },
                false,
            )
            .expect("a finding with advisories renders")
            .data
            .expect("data");
            assert_eq!(data["fixedVersion"], "4.18.0");
        }

        #[test]
        fn a_lockfile_resolved_finding_sits_on_the_manifest_line() {
            // The diagnostic goes where the user can edit; related information
            // says where the version was actually resolved.
            let f = Finding {
                declared: Some(Anchor::new(Site::new(
                    "/p/package.json",
                    crate::model::Range::whole_line(5),
                ))),
                ..lockfile_resolved()
            };
            let d = finding_diagnostic(&f, false).expect("a finding with advisories renders");
            assert_eq!(d.range.start.line, 4, "want the manifest line");
            let related = d.related_information.expect("a link to the lockfile");
            assert_eq!(related.len(), 1);
            assert!(
                related[0]
                    .location
                    .uri
                    .path()
                    .as_str()
                    .ends_with("/p/package-lock.json")
            );
        }

        #[test]
        fn finding_data_round_trips_what_a_code_action_needs() {
            let fixed = Finding {
                fix: Fix::Clears("9.9.9".into()),
                ..finding()
            };
            let data = finding_diagnostic(&fixed, true)
                .expect("a finding with advisories renders")
                .data
                .unwrap();
            assert_eq!(data["ecosystem"], "npm");
            assert_eq!(data["name"], "lodash");
            assert_eq!(data["version"], "4.17.15");
            assert_eq!(data["fixedVersion"], "9.9.9");
            assert_eq!(data["direct"], true);
            assert_eq!(data["advisories"], serde_json::json!(["GHSA-1"]));

            let data = finding_diagnostic(&finding(), false)
                .expect("a finding with advisories renders")
                .data
                .unwrap();
            assert!(
                data.get("fixedVersion").is_none(),
                "omitted, not null: {data}"
            );
        }
    }
}
