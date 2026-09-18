use crate::digits::cmp_digits;
use std::borrow::Cow;
use std::cmp::Ordering;

/// Semver's cap on numeric components. Anything past the third is folded into
/// the build string, which is what makes `1.2.3.4` sort *below* `1.2.3`.
const MAX_COMPONENTS: usize = 3;

/// A version that is *like* a Semantic Version: potentially unlimited numeric
/// components, an optional leading `v`, and a parser that never fails.
///
/// Borrows its input. Nothing is allocated for the common case — the components
/// are byte ranges into the original string, and `build` only owns storage when
/// a fourth numeric component had to be folded into it.
#[derive(Clone, Debug)]
pub struct SemverLike<'a> {
    src: &'a str,
    /// Byte ranges into `src`, already parsed out; at most three.
    components: [(u32, u32); MAX_COMPONENTS],
    count: u8,
    build: Cow<'a, str>,
}

impl<'a> SemverLike<'a> {
    /// Parses a version. This cannot fail: every string is *some* version, and
    /// refusing one would drop an advisory rather than report it.
    pub fn parse(src: &'a str) -> SemverLike<'a> {
        let body = src.strip_prefix('v').unwrap_or(src);
        let offset = (src.len() - body.len()) as u32;

        // Scan into components and a trailing build string. The loop mirrors
        // osv-scalibr's parseSemverLike byte for byte, including the quirk that
        // a component terminator and the start of the build string are decided
        // by the same branch.
        let bytes = body.as_bytes();
        let mut all: Vec<(u32, u32)> = Vec::new();
        let mut current_start: Option<u32> = None;
        let mut build_start: Option<u32> = None;

        for (i, &b) in bytes.iter().enumerate() {
            let i = i as u32;
            if build_start.is_some() {
                continue;
            }
            if b.is_ascii_digit() {
                current_start.get_or_insert(i);
                continue;
            }
            if let Some(start) = current_start.take() {
                all.push((start + offset, i + offset));
            }
            if b == b'.' {
                continue;
            }
            build_start = Some(i);
        }
        if build_start.is_none()
            && let Some(start) = current_start.take()
        {
            all.push((start + offset, bytes.len() as u32 + offset));
        }

        let tail = build_start.map(|s| &body[s as usize..]).unwrap_or("");

        let mut components = [(0u32, 0u32); MAX_COMPONENTS];
        let kept = all.len().min(MAX_COMPONENTS);
        components[..kept].copy_from_slice(&all[..kept]);

        // Extras past the third become part of the build string, written back
        // in decimal so "1.2.3.04" and "1.2.3.4" fold identically.
        let build = if all.len() > MAX_COMPONENTS {
            let mut s = String::from(tail);
            for &(lo, hi) in &all[MAX_COMPONENTS..] {
                s.push('.');
                s.push_str(normalise_digits(&src[lo as usize..hi as usize]));
            }
            Cow::Owned(s)
        } else {
            Cow::Borrowed(tail)
        };

        SemverLike {
            src,
            components,
            count: kept as u8,
            build,
        }
    }

    /// The nth numeric component, as its digits. Absent components read as `"0"`.
    fn component(&self, n: usize) -> &str {
        if n >= self.count as usize {
            return "0";
        }
        let (lo, hi) = self.components[n];
        &self.src[lo as usize..hi as usize]
    }

    pub fn compare(&self, other: &SemverLike<'_>) -> Ordering {
        for n in 0..MAX_COMPONENTS {
            match cmp_digits(self.component(n), other.component(n)) {
                Ordering::Equal => {}
                ord => return ord,
            }
        }
        compare_build(&self.build, &other.build)
    }
}

fn normalise_digits(s: &str) -> &str {
    let t = s.trim_start_matches('0');
    if t.is_empty() { "0" } else { t }
}

/// Strips semver build metadata: everything from the first `+`.
fn without_build_metadata(s: &str) -> &str {
    s.split('+').next().unwrap_or(s)
}

fn compare_build(a: &str, b: &str) -> Ordering {
    let a = without_build_metadata(a);
    let b = without_build_metadata(b);

    // The spec does not say to drop the hyphen before comparing, but node-semver
    // does, and matching node-semver is what matters for npm.
    let a = a.strip_prefix('-').unwrap_or(a);
    let b = b.strip_prefix('-').unwrap_or(b);

    // A version with a prerelease is lower than one without.
    match (a.is_empty(), b.is_empty()) {
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        _ => {}
    }

    let (mut ai, mut bi) = (a.split('.'), b.split('.'));
    let (mut alen, mut blen) = (0usize, 0usize);
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) => {
                alen += 1;
                blen += 1;
                match compare_identifier(x, y) {
                    Ordering::Equal => {}
                    ord => return ord,
                }
            }
            (Some(_), None) => {
                // A larger set of prerelease fields wins, all else equal.
                return Ordering::Greater;
            }
            (None, Some(_)) => return Ordering::Less,
            (None, None) => {
                let _ = (alen, blen);
                return Ordering::Equal;
            }
        }
    }
}

/// One dot-separated prerelease identifier.
fn compare_identifier(a: &str, b: &str) -> Ordering {
    match (signed_digits(a), signed_digits(b)) {
        // Digits compare numerically.
        (Some((an, ad)), Some((bn, bd))) => match (an, bn) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => cmp_digits(ad, bd),
            (true, true) => cmp_digits(bd, ad),
        },
        // Letters and hyphens compare lexically, in ASCII order.
        (None, None) => a.cmp(b),
        // Numeric identifiers rank below non-numeric ones.
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
    }
}

/// Splits an optionally-signed decimal integer, matching what Go's
/// `big.Int.SetString(s, 10)` accepts — a leading `+` or `-` and then digits.
fn signed_digits(s: &str) -> Option<(bool, &str)> {
    let (negative, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((negative, digits))
}
