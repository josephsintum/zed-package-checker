//! Per-ecosystem version ordering.
//!
//! The reference is osv-scalibr's `semantic` package, the comparator the OSV
//! ecosystem's own tooling uses. No Rust crate implements it, and the obvious
//! candidates are not substitutes: the `semver` crate rejects `1.2`, a leading
//! `v`, and `1.2.3.4`, all of which appear in real advisories; and `pep440_rs`
//! rejects 3,185 of the version strings the PyPI archive actually contains,
//! because scalibr implements PEP 440 *plus* a setuptools-era legacy fallback.
//! Both comparators are therefore ported here, and checked against scalibr's
//! recorded answers over 116,142 real comparisons by `tests/differential.rs`.
//!
//! Versions borrow their input and are parsed once, then compared many times,
//! with no allocation per comparison.

use crate::model::Ecosystem;
use crate::pypi::PyPiVersion;
use crate::semver_like::SemverLike;
use std::cmp::Ordering;
use std::fmt;

/// A parsed version, ready to be compared against others in its ecosystem.
#[derive(Clone, Debug)]
pub enum Version<'a> {
    /// npm, Go and crates.io all order versions the same way.
    Semver(SemverLike<'a>),
    PyPI(PyPiVersion),
}

/// A version string no ecosystem grammar here can interpret.
///
/// Nothing produces one today — both comparators accept every input, as
/// scalibr's do — but keeping the case in the signature means adding an
/// ecosystem with a fallible grammar is not an API change.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ParseError {
    pub version: String,
    pub ecosystem: Ecosystem,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parse {} version {:?}", self.ecosystem, self.version)
    }
}

impl std::error::Error for ParseError {}

impl<'a> Version<'a> {
    pub fn parse(version: &'a str, ecosystem: Ecosystem) -> Result<Version<'a>, ParseError> {
        match ecosystem {
            Ecosystem::Npm | Ecosystem::Go | Ecosystem::CratesIo => {
                Ok(Version::Semver(SemverLike::parse(version)))
            }
            Ecosystem::PyPI => Ok(Version::PyPI(PyPiVersion::parse(version))),
        }
    }

    /// Compares against another version string in the same ecosystem.
    pub fn compare_str(&self, other: &str) -> Result<Ordering, ParseError> {
        match self {
            Version::Semver(v) => Ok(v.compare(&SemverLike::parse(other))),
            Version::PyPI(v) => Ok(v.compare(&PyPiVersion::parse(other))),
        }
    }

    /// Compares against another already-parsed version.
    ///
    /// Infallible where `compare_str` is not, which is what makes it usable as
    /// a sort comparator: swallowing a `Result` into `Equal` gives an
    /// intransitive relation, and `sort_by` panics on one.
    ///
    /// A cross-ecosystem pair orders `Equal` rather than panicking — nothing in
    /// an advisory should be able to abort the server.
    pub fn compare(&self, other: &Version<'_>) -> Ordering {
        match (self, other) {
            (Version::Semver(a), Version::Semver(b)) => a.compare(b),
            (Version::PyPI(a), Version::PyPI(b)) => a.compare(b),
            _ => Ordering::Equal,
        }
    }
}
