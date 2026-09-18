//! The subset of the OSV schema a diagnostic needs.
//!
//! Deliberately partial, and deliberately *borrowed*. An advisory's JSON
//! averages several kilobytes, most of it prose, credits and provenance that
//! never reaches a diagnostic. Fields not declared here are skipped by the
//! parser rather than decoded and discarded — which is the whole difference for
//! `details`, 662 bytes on average across 229,049 npm advisories that the Go
//! loader allocates a `string` for and then throws away.

use crate::model::{Advisory, Affected, AffectedRange, Ecosystem, PackageKey};
use serde::Deserialize;
use std::borrow::Cow;
use std::str::FromStr;

#[derive(Deserialize)]
pub struct OsvAdvisory<'a> {
    #[serde(borrow, default)]
    pub id: Cow<'a, str>,
    #[serde(borrow, default)]
    withdrawn: Cow<'a, str>,
    #[serde(borrow, default)]
    aliases: Vec<Cow<'a, str>>,
    #[serde(borrow, default)]
    summary: Cow<'a, str>,
    #[serde(borrow, default)]
    severity: Vec<OsvSeverity<'a>>,
    #[serde(borrow, default)]
    affected: Vec<OsvAffected<'a>>,
    #[serde(borrow, default)]
    references: Vec<OsvReference<'a>>,
}

#[derive(Deserialize)]
struct OsvSeverity<'a> {
    #[serde(rename = "type", borrow, default)]
    kind: Cow<'a, str>,
    #[serde(borrow, default)]
    score: Cow<'a, str>,
}

#[derive(Deserialize)]
struct OsvAffected<'a> {
    #[serde(borrow, default)]
    package: OsvPackage<'a>,
    #[serde(borrow, default)]
    ranges: Vec<OsvRange<'a>>,
    #[serde(borrow, default)]
    versions: Vec<Cow<'a, str>>,
}

#[derive(Deserialize, Default)]
struct OsvPackage<'a> {
    #[serde(borrow, default)]
    ecosystem: Cow<'a, str>,
    #[serde(borrow, default)]
    name: Cow<'a, str>,
}

#[derive(Deserialize)]
struct OsvRange<'a> {
    #[serde(rename = "type", borrow, default)]
    kind: Cow<'a, str>,
    #[serde(borrow, default)]
    events: Vec<OsvEvent<'a>>,
}

#[derive(Deserialize)]
struct OsvEvent<'a> {
    #[serde(borrow, default)]
    introduced: Cow<'a, str>,
    #[serde(borrow, default)]
    fixed: Cow<'a, str>,
    #[serde(rename = "last_affected", borrow, default)]
    last_affected: Cow<'a, str>,
}

#[derive(Deserialize)]
struct OsvReference<'a> {
    #[serde(borrow, default)]
    url: Cow<'a, str>,
}

impl<'a> OsvAdvisory<'a> {
    /// Converts to the domain type, keeping only one ecosystem.
    ///
    /// Returns `None` for an advisory that is withdrawn — roughly 4% of a
    /// typical archive — or that touches nothing in the wanted ecosystem.
    pub fn into_model(self, want: Ecosystem) -> Option<Advisory> {
        if !self.withdrawn.is_empty() {
            return None;
        }

        let affected: Box<[Affected]> = self
            .affected
            .into_iter()
            .filter(|entry| {
                !entry.package.name.is_empty()
                    && entry.package.ecosystem.parse::<Ecosystem>() == Ok(want)
            })
            .map(|entry| Affected {
                package: PackageKey::new(want, entry.package.name.as_ref()),
                ranges: flatten_ranges(&entry.ranges),
                versions: entry.versions.iter().map(|s| boxed(s)).collect(),
            })
            .collect();
        if affected.is_empty() {
            return None;
        }

        let (cvss_score, cvss_vector) = cvss(&self.severity);
        Some(Advisory {
            id: boxed(&self.id),
            aliases: self.aliases.iter().map(|s| boxed(s)).collect(),
            summary: boxed(&self.summary),
            cvss_score,
            cvss_vector,
            affected,
            references: self.references.iter().map(|r| boxed(&r.url)).collect(),
        })
    }
}

fn boxed(s: &str) -> Box<str> {
    // Exactly sized: no spare capacity is retained for the life of the index.
    Box::from(s)
}

/// A range whose bounds are commit hashes rather than versions.
const GIT_RANGE: &str = "GIT";

/// Turns OSV's event timelines into explicit ranges.
///
/// A range is a sequence of events along one version timeline rather than a pair
/// of bounds: an `introduced` opens a window, and the next `fixed` or
/// `last_affected` closes it. An introduction that is never closed means still
/// affected, and stays open-ended.
///
/// This is the subtlest transformation in the program and the one most able to
/// be confidently wrong — pairing an event with the wrong introduction makes an
/// advisory match versions it does not affect.
///
/// `GIT` ranges are dropped, because their bounds are forty hex characters and
/// both comparators accept every input rather than rejecting one — a commit
/// hash would be silently ordered as a version, and offered as a fix. Only that
/// type is dropped, so a range whose type is absent or unrecognised is still
/// indexed: this can lose a hash, never an advisory.
fn flatten_ranges(ranges: &[OsvRange<'_>]) -> Box<[AffectedRange]> {
    let mut out = Vec::new();
    for range in ranges.iter().filter(|r| r.kind != GIT_RANGE) {
        let mut current = AffectedRange::default();
        let mut open = false;

        for event in &range.events {
            if !event.introduced.is_empty() {
                if open {
                    out.push(std::mem::take(&mut current));
                }
                current = AffectedRange {
                    introduced: boxed(&event.introduced),
                    ..Default::default()
                };
                open = true;
            } else if !event.fixed.is_empty() {
                current.fixed = boxed(&event.fixed);
                out.push(std::mem::take(&mut current));
                open = false;
            } else if !event.last_affected.is_empty() {
                current.last_affected = boxed(&event.last_affected);
                out.push(std::mem::take(&mut current));
                open = false;
            }
        }
        if open {
            out.push(current);
        }
    }
    out.into()
}

/// Returns a base score and the vector it came from.
///
/// OSV carries the vector string, not a number, so the score is computed. Both
/// CVSS v3 and v4 appear, often on the same advisory; v3.1 is preferred because
/// it is what almost every other tool displays, and showing a different number
/// than the GitHub advisory page for the same issue invites mistrust. Around a
/// third of advisories carry no severity at all, which is not an error.
fn cvss(severities: &[OsvSeverity<'_>]) -> (f64, Box<str>) {
    let mut v4: Option<&str> = None;
    for severity in severities {
        if severity.kind.eq_ignore_ascii_case("CVSS_V3") {
            if let Ok(parsed) = cvss::v3::Base::from_str(&severity.score) {
                return (parsed.score().value(), boxed(&severity.score));
            }
        } else if severity.kind.eq_ignore_ascii_case("CVSS_V4") && v4.is_none() {
            v4 = Some(&severity.score);
        }
    }
    if let Some(vector) = v4
        && let Ok(parsed) = cvss::v4::Vector::from_str(vector)
    {
        return (parsed.score().value(), Box::from(vector));
    }
    (0.0, Box::from(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(json: &str, want: Ecosystem) -> Option<Advisory> {
        serde_json::from_str::<OsvAdvisory<'_>>(json)
            .expect("well-formed OSV")
            .into_model(want)
    }

    /// Shaped on PYSEC-2018-28, which carries both kinds of range for the same
    /// package: a commit hash and a version.
    const BOTH_RANGE_KINDS: &str = r#"{
        "id": "PYSEC-2018-28",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [
                {"type": "GIT", "events": [
                    {"introduced": "0"},
                    {"fixed": "c45d7c49ea75133e52ab22a8e9e13173938e36ff"}
                ]},
                {"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"},
                    {"fixed": "2.20.0"}
                ]}
            ]
        }]
    }"#;

    #[test]
    fn a_git_range_is_dropped_and_the_version_range_kept() {
        let advisory = decode(BOTH_RANGE_KINDS, Ecosystem::PyPI).expect("indexed");
        let ranges = &advisory.affected[0].ranges;
        assert_eq!(ranges.len(), 1, "the GIT range must not be indexed");
        assert_eq!(&*ranges[0].fixed, "2.20.0");

        // The consequence that matters: a commit hash can never be offered as
        // a fixed version.
        let key = crate::model::PackageKey::new(Ecosystem::PyPI, "requests");
        assert_eq!(advisory.fixed_versions_for(&key), ["2.20.0"]);
    }

    #[test]
    fn a_range_with_no_type_is_still_indexed() {
        // Only GIT is dropped, so an absent or unrecognised type can never
        // cost us an advisory.
        let advisory = decode(
            r#"{
                "id": "GHSA-x",
                "affected": [{
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
                }]
            }"#,
            Ecosystem::Npm,
        )
        .expect("indexed");
        assert_eq!(advisory.affected[0].ranges.len(), 1);
    }

    #[test]
    fn an_affected_entry_with_only_a_git_range_keeps_no_ranges() {
        // OSV-2021-449 and OSV-2025-500 are the two PyPI advisories shaped this
        // way. With no version bound left they match nothing, which is right —
        // a commit range cannot be evaluated against a PyPI version.
        let advisory = decode(
            r#"{
                "id": "OSV-2021-449",
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": "tensorflow"},
                    "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}]
                }]
            }"#,
            Ecosystem::PyPI,
        )
        .expect("indexed");
        assert!(advisory.affected[0].ranges.is_empty());
        assert!(advisory.affected[0].versions.is_empty());
    }
}
