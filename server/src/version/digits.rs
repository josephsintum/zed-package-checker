use std::cmp::Ordering;

/// Compares two runs of decimal digits exactly, at any length.
///
/// Arbitrary precision without a big-integer type: stripping leading zeros
/// makes length the primary key and the digits themselves the tiebreak, which
/// is the same ordering with no allocation.
pub fn cmp_digits(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Compares two lists of numeric components, padding the shorter with zeros.
pub fn components_cmp(a: &[String], b: &[String]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).map(String::as_str).unwrap_or("0");
        let y = b.get(i).map(String::as_str).unwrap_or("0");
        match cmp_digits(x, y) {
            Ordering::Equal => {}
            ord => return ord,
        }
    }
    Ordering::Equal
}
