//! Rendering findings as diagnostics.
//!
//! Kept apart from the protocol glue in `crate::lsp` because this is where the
//! wording lives, and the wording is the product: it is the only part of the
//! server most users will ever read.

use crate::model::{Finding, Severity};
use crate::span::{Encoding, column};
use std::path::Path;
use tower_lsp_server::ls_types::{
    CodeDescription, Diagnostic, DiagnosticRelatedInformation, DiagnosticSeverity, Location,
    NumberOrString, Position, Range, Uri,
};

/// The `source` field on every diagnostic, and the server's name.
pub const NAME: &str = "package-checker";

/// One file's diagnostics: one per finding, plus a summary when there is more
/// than one thing wrong.
pub fn for_file(path: &Path, findings: &[Finding], encoding: Encoding) -> Vec<Diagnostic> {
    if findings.is_empty() {
        return Vec::new();
    }
    // Read once, for the summary anchor and for re-encoding columns. A manifest
    // that cannot be read still produces diagnostics, just with byte columns.
    let source = std::fs::read_to_string(path).ok();

    let mut out = Vec::with_capacity(findings.len() + 1);
    if let Some(summary) = summary(path, findings, source.as_deref()) {
        out.push(summary);
    }
    out.extend(findings.iter().map(finding_diagnostic));

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

fn finding_diagnostic(finding: &Finding) -> Diagnostic {
    let worst = finding.worst();
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
        source: Some(NAME.to_owned()),
        message: message_for(finding),
        ..Default::default()
    };

    if finding.evidence.path != anchor.path
        && let Some(uri) = file_uri(&finding.evidence.path)
    {
        // Point at where the version was actually resolved, since the
        // diagnostic itself sits on the manifest line the user can edit.
        diagnostic.related_information = Some(vec![DiagnosticRelatedInformation {
            location: Location { uri, range: to_range(finding.evidence.range) },
            message: format!("{} resolved here", finding.package),
        }]);
    }

    // Round-trips back on a code action, so a fix can be offered without
    // rescanning to work out what the diagnostic referred to.
    diagnostic.data = Some(serde_json::json!({
        "ecosystem": finding.package.ecosystem().as_str(),
        "name": finding.package.name(),
        "version": finding.package.version,
        "advisories": finding.advisories.iter().map(|a| a.id.to_string()).collect::<Vec<_>>(),
        "direct": finding.direct(),
        "fixedVersion": worst.fixed_versions_for(&finding.package.key).first(),
    }));
    diagnostic
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

    let parts: Vec<String> = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low]
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
        source: Some(NAME.to_owned()),
        message,
        data: Some(serde_json::json!({ "summary": true, "path": path.to_string_lossy() })),
        ..Default::default()
    })
}

/// The one-line description a diagnostic leads with.
fn message_for(finding: &Finding) -> String {
    let worst = finding.worst();
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

    // One fixed version is the answer for one advisory. Across seventy-six it
    // is merely the worst one's fix and clears almost none of the others, so
    // naming it reads as a remedy when it is not one.
    if !toolchain || finding.advisories.len() == 1 {
        let fixed = worst.fixed_versions_for(&finding.package.key);
        if !fixed.is_empty() {
            message.push_str(&format!(". Fixed in {}", fixed.join(" or ")));
        }
    }
    if toolchain {
        message.push_str(
            ". The go directive is a minimum, so the toolchain building this may already be newer",
        );
    }
    if finding.from_range {
        message.push_str(". Version inferred from a range, so the installed one may differ");
    }
    if finding.dev() {
        message.push_str(". Development dependency");
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
    let worst = finding.worst();
    let n = finding.advisories.len();
    let rated = worst.severity() != Severity::Unknown;
    match (n, rated) {
        (1, true) => describe(worst.severity(), worst.cvss_score),
        (1, false) => "1 known vulnerability".to_owned(),
        (n, true) => format!("{n} advisories, worst {}", describe(worst.severity(), worst.cvss_score)),
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
