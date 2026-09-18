//! The R2 gate: our comparator must order real version strings exactly as
//! osv-scalibr's does.
//!
//! The corpus records what scalibr's `semantic.Parse(...).CompareStr(...)`
//! answered over every distinct version string in the Go, PyPI and npm advisory
//! archives — 116,142 comparisons, generated once from the real data and
//! checked in gzipped. Checking against the reference implementation's recorded
//! output, rather than against a reading of its source, is the whole point.

use package_checker::model::Ecosystem;
use package_checker::version::Version;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;

fn corpus() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/ordering.tsv.gz");
    let file = std::fs::File::open(&path)
        .unwrap_or_else(|e| panic!("ordering corpus {}: {e}", path.display()));
    let mut text = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut text)
        .expect("corpus is gzipped UTF-8");
    text
}

#[test]
fn agrees_with_scalibr_over_the_real_archives() {
    let text = corpus();

    let mut checked = 0usize;
    // Divergences are counted per ecosystem and reported together: one summary
    // is worth more than the first failure, because the question is whether the
    // port is wrong in general or wrong about one grammar.
    let mut diverged: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut unparsable: BTreeMap<&str, usize> = BTreeMap::new();

    for line in text.lines() {
        let mut fields = line.split('\t');
        let (Some(eco), Some(a), Some(b), Some(want)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let ecosystem = Ecosystem::from_str(eco).expect("corpus names a supported ecosystem");
        let want = match want {
            "-1" => Ordering::Less,
            "0" => Ordering::Equal,
            "1" => Ordering::Greater,
            other => panic!("corpus ordering {other:?}"),
        };

        let Ok(parsed) = Version::parse(a, ecosystem) else {
            *unparsable.entry(eco).or_default() += 1;
            continue;
        };
        let Ok(got) = parsed.compare_str(b) else {
            *unparsable.entry(eco).or_default() += 1;
            continue;
        };

        checked += 1;
        if got != want {
            let entry = diverged.entry(eco).or_default();
            if entry.len() < 10 {
                entry.push(format!(
                    "{a:?} vs {b:?}: got {got:?}, scalibr said {want:?}"
                ));
            } else {
                entry.push(String::new());
            }
        }
    }

    for (eco, count) in &unparsable {
        eprintln!("{eco}: {count} comparisons skipped, version rejected by our parser");
    }

    if !diverged.is_empty() {
        let mut report = String::new();
        for (eco, cases) in &diverged {
            let shown: Vec<_> = cases.iter().filter(|c| !c.is_empty()).collect();
            report.push_str(&format!("\n{eco}: {} divergences, e.g.\n", cases.len()));
            for case in shown {
                report.push_str(&format!("    {case}\n"));
            }
        }
        panic!("checked {checked} comparisons against osv-scalibr:{report}");
    }

    assert!(
        checked > 100_000,
        "corpus too small to prove anything: {checked}"
    );
    eprintln!("{checked} comparisons agree with osv-scalibr");
}
