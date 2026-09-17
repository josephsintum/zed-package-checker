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
fn boxed(s: &str) -> Box<str> {
    // Exactly sized: no spare capacity is retained for the life of the index.
    Box::from(s)
}

fn flatten_ranges(ranges: &[OsvRange<'_>]) -> Box<[AffectedRange]> {
    let mut out = Vec::new();
    for range in ranges {
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
