use super::digits::{cmp_digits, components_cmp};
use std::cmp::Ordering;
use std::sync::LazyLock;

use regex::Regex;

/// PEP 440, Appendix B. Copied from the specification, as osv-scalibr does.
#[expect(
    clippy::expect_used,
    reason = "the pattern is a constant; a typo fails the first test that touches it"
)]
static PEP440: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*v?(?:(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)(?P<pre>[-_\.]?(?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))[-_\.]?(?P<pre_n>[0-9]+)?)?(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?(?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?)(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?\s*$",
    )
    .expect("the PEP 440 pattern is a compile-time constant")
});

#[expect(
    clippy::expect_used,
    reason = "the pattern is a constant; a typo fails the first test that touches it"
)]
static LOCAL_SPLIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[._-]").expect("constant pattern"));

#[expect(
    clippy::expect_used,
    reason = "the pattern is a constant; a typo fails the first test that touches it"
)]
static LEGACY_PARTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d+|[a-z]+|\.|-").expect("constant pattern"));

/// A release-phase marker and its number, e.g. the `rc` and `2` of `1.0rc2`.
#[derive(Clone, Debug, Default)]
struct LetterAndNumber {
    letter: String,
    /// `None` means the segment is absent, which is distinct from zero.
    number: Option<String>,
}

/// A `PyPI` version.
///
/// A port of osv-scalibr's `PyPIVersion`, not of PEP 440. The difference
/// matters: `pep440_rs` rejects 3,185 of the version strings the `PyPI` advisory
/// archive actually contains — setuptools-era spellings like `0.3m1`,
/// `0.1-charmander` and `0.1.0.dev-120828c` — and scalibr accepts every one of
/// them through a legacy fallback. Using a strict PEP 440 crate would silently
/// skip those advisories, which is a false negative in a security tool.
#[derive(Clone, Debug, Default)]
pub struct PyPiVersion {
    epoch: String,
    release: Vec<String>,
    pre: LetterAndNumber,
    post: LetterAndNumber,
    dev: LetterAndNumber,
    local: Vec<String>,
    /// Non-empty only for versions that predate PEP 440 entirely.
    legacy: Vec<String>,
}

impl PyPiVersion {
    /// Parses a version. Like scalibr's, this never fails: anything PEP 440
    /// rejects falls through to the legacy interpretation.
    pub fn parse(src: &str) -> PyPiVersion {
        let lowered = src.to_lowercase();
        let Some(m) = PEP440.captures(&lowered) else {
            return PyPiVersion {
                legacy: legacy_parts(&lowered),
                ..Default::default()
            };
        };

        let group = |name: &str| m.name(name).map(|g| g.as_str()).unwrap_or("");

        let mut v = PyPiVersion {
            epoch: match group("epoch") {
                "" => "0".to_owned(),
                e => e.to_owned(),
            },
            release: group("release").split('.').map(str::to_owned).collect(),
            ..Default::default()
        };

        v.pre = letter_version(group("pre_l"), group("pre_n"));
        let post_number = match group("post_n1") {
            "" => group("post_n2"),
            n => n,
        };
        v.post = letter_version(group("post_l"), post_number);
        v.dev = letter_version(group("dev_l"), group("dev_n"));
        v.local = match group("local") {
            "" => Vec::new(),
            local => LOCAL_SPLIT.split(local).map(str::to_lowercase).collect(),
        };
        v
    }

    pub fn compare(&self, other: &PyPiVersion) -> Ordering {
        self.compare_legacy(other)
            .then_with(|| cmp_digits(&self.epoch, &other.epoch))
            .then_with(|| components_cmp(&self.release, &other.release))
            .then_with(|| self.compare_pre(other))
            .then_with(|| self.compare_post(other))
            .then_with(|| self.compare_dev(other))
            .then_with(|| self.compare_local(other))
    }

    /// Legacy versions always sort below PEP 440 ones, matching current tooling.
    fn compare_legacy(&self, other: &PyPiVersion) -> Ordering {
        match (self.legacy.is_empty(), other.legacy.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => self.legacy.concat().cmp(&other.legacy.concat()),
        }
    }

    /// Whether the sort trick that puts `1.0.dev0` before `1.0a0` applies.
    fn should_apply_pre_trick(&self) -> bool {
        self.pre.number.is_none() && self.post.number.is_none() && self.dev.number.is_some()
    }

    fn compare_pre(&self, other: &PyPiVersion) -> Ordering {
        match (
            self.should_apply_pre_trick(),
            other.should_apply_pre_trick(),
        ) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            (false, false) => {}
        }
        match (&self.pre.number, &other.pre.number) {
            // A version without a prerelease sorts after one with it.
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => self
                .pre
                .letter
                .as_bytes()
                .first()
                .cmp(&other.pre.letter.as_bytes().first())
                .then_with(|| cmp_digits(a, b)),
        }
    }

    fn compare_post(&self, other: &PyPiVersion) -> Ordering {
        match (&self.post.number, &other.post.number) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(a), Some(b)) => cmp_digits(a, b),
        }
    }

    fn compare_dev(&self, other: &PyPiVersion) -> Ordering {
        match (&self.dev.number, &other.dev.number) {
            (None, None) => Ordering::Equal,
            // A development release sorts before the release it leads to.
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => cmp_digits(a, b),
        }
    }

    fn compare_local(&self, other: &PyPiVersion) -> Ordering {
        for (a, b) in self.local.iter().zip(&other.local) {
            let ord = match (all_digits(a), all_digits(b)) {
                (true, true) => cmp_digits(a, b),
                (false, false) => a.cmp(b),
                // A numeric segment outranks an alphabetic one.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        // More segments wins, when the shorter is a prefix of the longer.
        self.local.len().cmp(&other.local.len())
    }
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn letter_version(letter: &str, number: &str) -> LetterAndNumber {
    if !letter.is_empty() {
        // A prerelease with no number carries an implicit zero.
        let number = if number.is_empty() { "0" } else { number };
        let letter = match letter {
            "alpha" => "a",
            "beta" => "b",
            "c" | "pre" | "preview" => "rc",
            "rev" | "r" => "post",
            other => other,
        };
        return LetterAndNumber {
            letter: letter.to_owned(),
            number: Some(number.to_owned()),
        };
    }
    if !number.is_empty() {
        // A number with no letter is the implicit post-release form, `1.0-1`.
        return LetterAndNumber {
            letter: "post".to_owned(),
            number: Some(number.to_owned()),
        };
    }
    LetterAndNumber::default()
}

/// Splits a pre-PEP-440 version the way setuptools did.
fn legacy_parts(src: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let splits = LEGACY_PARTS
        .find_iter(src)
        .map(|m| m.as_str())
        .chain(std::iter::once("final"));

    for raw in splits {
        if raw.is_empty() || raw == "." {
            continue;
        }
        let part = normalise_legacy_part(raw);

        if part.starts_with('*') {
            if part.as_str() < "*final" {
                while parts.last().is_some_and(|p| p == "*final-") {
                    parts.pop();
                }
            }
            while parts.last().is_some_and(|p| p == "00000000") {
                parts.pop();
            }
        }
        parts.push(part);
    }
    parts
}

fn normalise_legacy_part(part: &str) -> String {
    let part = match part {
        "pre" | "preview" | "rc" => "c",
        "-" => "final-",
        "dev" => "@",
        other => other,
    };
    if part.as_bytes()[0].is_ascii_digit() {
        // Zero-padded so that a string comparison orders numbers numerically.
        format!("{part:0>8}")
    } else {
        format!("*{part}")
    }
}
