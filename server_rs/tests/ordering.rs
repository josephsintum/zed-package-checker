//! The quirks worth naming, so a future simplification of the comparator has to
//! argue with a test rather than with a 116k-row corpus.

use package_checker::model::Ecosystem::{Go, Npm, PyPI};
use package_checker::version::Version;
use std::cmp::Ordering::{Equal, Greater, Less};

fn cmp(a: &str, b: &str, eco: package_checker::model::Ecosystem) -> std::cmp::Ordering {
    Version::parse(a, eco).unwrap().compare_str(b).unwrap()
}

#[test]
fn semver_basics() {
    assert_eq!(cmp("1.0.0", "1.0.1", Npm), Less);
    assert_eq!(cmp("1.0.0", "1.0.0", Npm), Equal);
    assert_eq!(cmp("2.0.0", "10.0.0", Npm), Less);
    // A leading v is accepted and ignored, which is how Go module versions arrive.
    assert_eq!(cmp("v1.2.3", "1.2.3", Go), Equal);
    // Missing components read as zero.
    assert_eq!(cmp("1.2", "1.2.0", Npm), Equal);
}

#[test]
fn prereleases_sort_below_their_release() {
    assert_eq!(cmp("1.0.0-alpha", "1.0.0", Npm), Less);
    assert_eq!(cmp("1.0.0-alpha", "1.0.0-beta", Npm), Less);
    assert_eq!(cmp("1.0.0-alpha.1", "1.0.0-alpha.2", Npm), Less);
    // Numeric identifiers rank below non-numeric ones.
    assert_eq!(cmp("1.0.0-1", "1.0.0-alpha", Npm), Less);
    // A larger set of prerelease fields wins.
    assert_eq!(cmp("1.0.0-alpha", "1.0.0-alpha.1", Npm), Less);
    // Build metadata is ignored entirely.
    assert_eq!(cmp("1.0.0+build1", "1.0.0+build2", Npm), Equal);
}

#[test]
fn a_fourth_component_is_treated_as_a_prerelease() {
    // Surprising, and scalibr's actual behaviour: only three components are
    // numeric, so the fourth folds into the build string and drags the version
    // below the three-component one.
    assert_eq!(cmp("1.2.3.4", "1.2.3", Npm), Less);
    // And it is normalised on the way, so leading zeros do not change the order.
    assert_eq!(cmp("1.2.3.04", "1.2.3.4", Npm), Equal);
}

#[test]
fn arbitrary_precision_components() {
    // Longer than u64. A big.Int in Go; a digit-string comparison here.
    assert_eq!(
        cmp(
            "1.0.99999999999999999999999999",
            "1.0.99999999999999999999999998",
            Npm
        ),
        Greater
    );
}

#[test]
fn pypi_pep440() {
    assert_eq!(cmp("1.0", "1.0.post1", PyPI), Less);
    assert_eq!(cmp("1.0.dev1", "1.0", PyPI), Less);
    assert_eq!(cmp("1.0a1", "1.0b1", PyPI), Less);
    assert_eq!(cmp("1!1.0", "2.0", PyPI), Greater);
    // Alternative spellings normalise to the same phase.
    assert_eq!(cmp("1.0alpha1", "1.0a1", PyPI), Equal);
    assert_eq!(cmp("1.0preview1", "1.0rc1", PyPI), Equal);
    // The trick that keeps a dev release below the first alpha.
    assert_eq!(cmp("1.0.dev0", "1.0a0", PyPI), Less);
    // A bare trailing number is the implicit post-release form.
    assert_eq!(cmp("1.0-1", "1.0", PyPI), Greater);
}

#[test]
fn pypi_legacy_versions_are_accepted_and_sort_lowest() {
    // Real strings from the PyPI advisory archive. A strict PEP 440 parser
    // rejects every one of these, which would silently drop the advisory.
    for legacy in [
        "0.3m1",
        "0.1-charmander",
        "0.1.0.dev-120828c",
        "0.12.10-NA",
        "0.3.2d",
    ] {
        assert!(
            Version::parse(legacy, PyPI).is_ok(),
            "{legacy:?} must parse"
        );
        assert_eq!(
            cmp(legacy, "1.0", PyPI),
            Less,
            "{legacy:?} vs a PEP 440 version"
        );
    }
    assert_eq!(cmp("0.3m1", "0.3m2", PyPI), Less);
}
