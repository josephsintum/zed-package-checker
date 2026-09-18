//! Turning advisory archives on disk into an in-memory index.
//!
//! This is the heaviest work the server does. npm's archive holds 229,049
//! separately-compressed JSON documents totalling 379 MB uncompressed, 97% of
//! them `MAL-` malicious-package reports rather than CVEs.
//!
//! Two strategies are implemented and both are measured: the sequential one
//! attributes the cost to inflating versus parsing, and the parallel one is what
//! the server runs.

use crate::index::Index;
use crate::model::{Advisory, Ecosystem};
use crate::osv::OsvAdvisory;
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// How an archive's entries are decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Strategy {
    /// One entry at a time, streamed from disk.
    Sequential,
    /// Memory-mapped and decoded across every core. `ZipArchive` is `Clone`, so
    /// each worker gets its own cursor over the same mapping and no entry is
    /// read twice.
    #[default]
    Parallel,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("advisory database not ready: {0}")]
    NotReady(String),
    #[error("open {path}: {source}")]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("read {path}: {source}")]
    Zip {
        path: PathBuf,
        source: zip::result::ZipError,
    },
}

/// What one archive contributed, for logging and for the benchmarks.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArchiveStats {
    pub entries: usize,
    pub indexed: usize,
    pub skipped: usize,
    /// Time spent inflating entries, and time spent parsing them. Split because
    /// "Rust is faster" is not an explanation, and these two answer different
    /// questions: one is about the DEFLATE implementation, the other about the
    /// JSON one. Only filled in by the sequential strategy, where the phases do
    /// not overlap.
    pub inflate: std::time::Duration,
    pub parse: std::time::Duration,
}

/// Parses the named archives into one index.
///
/// Only the ecosystems a project actually uses are passed in, which is the
/// single largest saving available: a Go project reads 12 MB rather than npm's
/// 215 MB, and most projects never touch npm's at all.
pub fn load(
    archives: &[(Ecosystem, PathBuf)],
    strategy: Strategy,
) -> Result<(Index, Vec<(Ecosystem, ArchiveStats)>), LoadError> {
    let start = Instant::now();
    let mut all = Vec::new();
    let mut ecosystems = Vec::new();
    let mut stats = Vec::new();

    for (ecosystem, path) in archives {
        let (advisories, archive_stats) = match strategy {
            Strategy::Sequential => load_sequential(path, *ecosystem)?,
            Strategy::Parallel => load_parallel(path, *ecosystem)?,
        };

        // Every entry failing is corruption, not content: an archive that
        // decodes but indexes nothing is a legitimate answer, an archive where
        // nothing decodes is a truncated download.
        if archive_stats.entries > 0 && archive_stats.skipped == archive_stats.entries {
            return Err(LoadError::NotReady(format!(
                "all {} advisories in {} failed to decode",
                archive_stats.entries,
                path.display()
            )));
        }

        all.extend(advisories);
        ecosystems.push(*ecosystem);
        stats.push((*ecosystem, archive_stats));
    }

    Ok((Index::build(all, ecosystems, start.elapsed()), stats))
}

fn load_sequential(
    path: &Path,
    ecosystem: Ecosystem,
) -> Result<(Vec<Advisory>, ArchiveStats), LoadError> {
    let file = File::open(path).map_err(|source| LoadError::Open {
        path: path.into(),
        source,
    })?;
    let mut archive =
        zip::ZipArchive::new(BufReader::new(file)).map_err(|source| LoadError::Zip {
            path: path.into(),
            source,
        })?;

    let mut out = Vec::new();
    let mut stats = ArchiveStats::default();
    // One buffer for the whole archive rather than one allocation per entry.
    let mut buffer = Vec::with_capacity(8 * 1024);

    for i in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(i) else {
            continue;
        };
        if !entry.name().ends_with(".json") {
            continue;
        }
        stats.entries += 1;
        buffer.clear();
        let inflate_start = Instant::now();
        let read = entry.read_to_end(&mut buffer);
        stats.inflate += inflate_start.elapsed();
        if read.is_err() {
            stats.skipped += 1;
            continue;
        }
        let parse_start = Instant::now();
        let decoded = decode(&buffer, ecosystem);
        stats.parse += parse_start.elapsed();
        match decoded {
            Decoded::Indexed(advisory) => {
                stats.indexed += 1;
                out.push(advisory);
            }
            Decoded::Filtered => {}
            Decoded::Failed => stats.skipped += 1,
        }
    }
    Ok((out, stats))
}

fn load_parallel(
    path: &Path,
    ecosystem: Ecosystem,
) -> Result<(Vec<Advisory>, ArchiveStats), LoadError> {
    let file = File::open(path).map_err(|source| LoadError::Open {
        path: path.into(),
        source,
    })?;
    // Safety: the archive is published by an atomic rename and never written in
    // place, so the mapping cannot be truncated underneath us. A concurrent
    // refresh creates a new file and renames over the name, leaving this
    // mapping pointing at the old inode.
    let mmap = unsafe { Mmap::map(&file) }.map_err(|source| LoadError::Open {
        path: path.into(),
        source,
    })?;

    let archive =
        zip::ZipArchive::new(Cursor::new(&mmap[..])).map_err(|source| LoadError::Zip {
            path: path.into(),
            source,
        })?;

    let names: Vec<usize> = (0..archive.len()).collect();
    let results: Vec<(Option<Advisory>, ArchiveStats)> = names
        .into_par_iter()
        .map_init(
            || (archive.clone(), Vec::<u8>::with_capacity(8 * 1024)),
            |(archive, buffer), i| {
                let mut stats = ArchiveStats::default();
                let Ok(mut entry) = archive.by_index(i) else {
                    return (None, stats);
                };
                if !entry.name().ends_with(".json") {
                    return (None, stats);
                }
                stats.entries = 1;
                buffer.clear();
                if entry.read_to_end(buffer).is_err() {
                    stats.skipped = 1;
                    return (None, stats);
                }
                match decode(buffer, ecosystem) {
                    Decoded::Indexed(advisory) => {
                        stats.indexed = 1;
                        (Some(advisory), stats)
                    }
                    Decoded::Filtered => (None, stats),
                    Decoded::Failed => {
                        stats.skipped = 1;
                        (None, stats)
                    }
                }
            },
        )
        .collect();

    let mut out = Vec::with_capacity(results.len());
    let mut stats = ArchiveStats::default();
    for (advisory, entry_stats) in results {
        stats.entries += entry_stats.entries;
        stats.indexed += entry_stats.indexed;
        stats.skipped += entry_stats.skipped;
        if let Some(advisory) = advisory {
            out.push(advisory);
        }
    }
    Ok((out, stats))
}

enum Decoded {
    Indexed(Advisory),
    /// Withdrawn, or covering only other ecosystems. Not an error.
    Filtered,
    Failed,
}

fn decode(bytes: &[u8], ecosystem: Ecosystem) -> Decoded {
    match serde_json::from_slice::<OsvAdvisory<'_>>(bytes) {
        Ok(raw) => match raw.into_model(ecosystem) {
            Some(advisory) => Decoded::Indexed(advisory),
            None => Decoded::Filtered,
        },
        Err(_) => Decoded::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageKey;
    use crate::testing::fake_archive;

    const LODASH: &str = r#"{"id":"GHSA-1","summary":"bad thing","affected":[{
        "package":{"ecosystem":"npm","name":"lodash"},
        "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#;
    const EXPRESS: &str =
        r#"{"id":"GHSA-2","affected":[{"package":{"ecosystem":"npm","name":"express"}}]}"#;
    const WITHDRAWN: &str = r#"{"id":"GHSA-gone","withdrawn":"2023-01-01T00:00:00Z",
        "affected":[{"package":{"ecosystem":"npm","name":"lodash"}}]}"#;

    /// Downloads nothing: writes an archive straight to disk, so these tests
    /// stay hermetic.
    fn seeded(entries: &[(&str, &str)]) -> (tempfile::TempDir, Vec<(Ecosystem, PathBuf)>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("all.zip");
        std::fs::write(&path, fake_archive(entries)).unwrap();
        (dir, vec![(Ecosystem::Npm, path)])
    }

    const BOTH: [Strategy; 2] = [Strategy::Sequential, Strategy::Parallel];

    #[test]
    fn an_archive_becomes_an_index() {
        let (_dir, archives) = seeded(&[
            ("GHSA-1.json", LODASH),
            ("GHSA-2.json", EXPRESS),
            ("GHSA-gone.json", WITHDRAWN),
            ("not-json.txt", "ignored"),
        ]);
        for strategy in BOTH {
            let (index, stats) = load(&archives, strategy).unwrap();
            assert_eq!(
                index.advisories(),
                2,
                "{strategy:?}: the withdrawn one is excluded"
            );
            assert_eq!(index.packages(), 2, "{strategy:?}");

            let lodash: Vec<_> = index
                .lookup(&PackageKey::new(Ecosystem::Npm, "lodash"))
                .collect();
            assert_eq!(lodash.len(), 1, "{strategy:?}");
            assert_eq!(&*lodash[0].id, "GHSA-1");
            assert_eq!(
                index
                    .lookup(&PackageKey::new(Ecosystem::Npm, "absent"))
                    .count(),
                0
            );

            assert!(index.covers(&[Ecosystem::Npm]));
            assert!(
                !index.covers(&[Ecosystem::Go]),
                "claims to cover Go, never loaded"
            );

            let (_, s) = stats[0];
            assert_eq!((s.entries, s.indexed, s.skipped), (3, 2, 0), "{strategy:?}");
        }
    }

    #[test]
    fn a_missing_archive_is_an_error_not_an_empty_index() {
        // "Not downloaded yet" must never be indistinguishable from "nothing
        // is vulnerable", which would be a silent false negative.
        let dir = tempfile::tempdir().unwrap();
        let archives = vec![(Ecosystem::Npm, dir.path().join("all.zip"))];
        for strategy in BOTH {
            assert!(matches!(
                load(&archives, strategy),
                Err(LoadError::Open { .. })
            ));
        }
    }

    #[test]
    fn an_archive_nothing_decodes_from_is_rejected() {
        // A zip that opens but whose entries are all garbage passes the zip
        // validation the database does, so nothing upstream catches it.
        // Loading it as a successful empty index would report every project
        // clean.
        let (_dir, archives) = seeded(&[
            ("GHSA-1.json", "{ this is not json"),
            ("GHSA-2.json", "]]]"),
        ]);
        for strategy in BOTH {
            assert!(matches!(
                load(&archives, strategy),
                Err(LoadError::NotReady(_))
            ));
        }
    }

    #[test]
    fn one_unreadable_advisory_does_not_lose_the_rest() {
        // The opposite of the above: some entries decode, so the archive is
        // intact and the readable advisories are still worth having.
        let (_dir, archives) =
            seeded(&[("GHSA-broken.json", "{ not json"), ("GHSA-2.json", EXPRESS)]);
        for strategy in BOTH {
            let (index, stats) = load(&archives, strategy).unwrap();
            assert_eq!(index.advisories(), 1, "{strategy:?}");
            assert_eq!(
                stats[0].1.skipped, 1,
                "{strategy:?}: the skip must be counted"
            );
        }
    }

    #[test]
    fn an_archive_of_only_withdrawn_advisories_is_an_empty_index() {
        // An archive of nothing but withdrawn entries decodes cleanly and
        // indexes nothing, and that is not corruption.
        let (_dir, archives) = seeded(&[("GHSA-gone.json", WITHDRAWN)]);
        for strategy in BOTH {
            let (index, _) = load(&archives, strategy).unwrap();
            assert_eq!(index.advisories(), 0, "{strategy:?}");
        }
    }
}
