use crate::model::{Advisory, Ecosystem, PackageKey};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// A parsed advisory database, held in memory and keyed by package.
///
/// Built once per process and rebuilt only when the archives change, never per
/// scan. Immutable once built, which is what lets it be shared across tasks
/// behind an `Arc` with no lock on the read path.
///
/// Advisories are stored once, contiguously. The Go index is
/// `map[PackageKey][]Advisory`, which copies a 144-byte header into a separately
/// allocated slice for every package an advisory affects; here an advisory lives
/// in one `Vec` and the per-package lists are index ranges into a second one.
#[derive(Debug, Default)]
pub struct Index {
    advisories: Vec<Advisory>,
    /// Indices into `advisories`, grouped so each package's are contiguous.
    postings: Vec<u32>,
    by_package: HashMap<PackageKey, (u32, u32)>,
    ecosystems: Vec<Ecosystem>,
    load_time: Duration,
    built_at: Option<SystemTime>,
}

impl Index {
    /// Builds an index from advisories already parsed out of the archives.
    ///
    /// Takes ownership of the whole set at once rather than accumulating, so
    /// the posting lists can be laid out contiguously in one pass.
    pub(crate) fn build(
        advisories: Vec<Advisory>,
        ecosystems: Vec<Ecosystem>,
        load_time: Duration,
    ) -> Index {
        // One pass to count, one to place: no per-key Vec is ever allocated.
        let mut counts: HashMap<PackageKey, u32> = HashMap::with_capacity(advisories.len());
        for advisory in &advisories {
            for affected in &advisory.affected {
                *counts.entry(affected.package.clone()).or_default() += 1;
            }
        }

        let total: u32 = counts.values().sum();
        let mut by_package = HashMap::with_capacity(counts.len());
        let mut cursor = 0u32;
        for (key, count) in counts {
            by_package.insert(key, (cursor, 0));
            cursor += count;
        }

        let mut postings = vec![0u32; total as usize];
        for (i, advisory) in advisories.iter().enumerate() {
            for affected in &advisory.affected {
                let slot = by_package
                    .get_mut(&affected.package)
                    .expect("every affected package was counted");
                postings[(slot.0 + slot.1) as usize] = i as u32;
                slot.1 += 1;
            }
        }

        Index {
            advisories,
            postings,
            by_package,
            ecosystems,
            load_time,
            built_at: Some(SystemTime::now()),
        }
    }

    /// Every advisory that names this package, in archive order.
    ///
    /// Borrowed from the arena: no copy, no per-key allocation. The Go index
    /// returns a slice that was built by appending a struct copy per affected
    /// package while loading.
    pub fn lookup(&self, key: &PackageKey) -> impl Iterator<Item = &Advisory> {
        let postings = match self.by_package.get(key) {
            Some(&(start, len)) => &self.postings[start as usize..(start + len) as usize],
            None => &[][..],
        };
        postings.iter().map(|&i| &self.advisories[i as usize])
    }

    pub fn ecosystems(&self) -> &[Ecosystem] {
        &self.ecosystems
    }

    /// Whether this index already covers everything a scan needs.
    pub fn covers(&self, ecosystems: &[Ecosystem]) -> bool {
        ecosystems.iter().all(|e| self.ecosystems.contains(e))
    }

    /// Every advisory in the index, for analysis and benchmarking.
    pub fn iter(&self) -> impl Iterator<Item = &Advisory> {
        self.advisories.iter()
    }

    /// Bytes the posting lists and the package map occupy, excluding the
    /// advisories themselves.
    pub fn overhead_bytes(&self) -> usize {
        let postings = self.postings.capacity() * size_of::<u32>();
        let map = self.by_package.capacity() * (size_of::<PackageKey>() + size_of::<(u32, u32)>());
        let names: usize = self.by_package.keys().map(|k| k.name.len()).sum();
        postings + map + names
    }

    pub fn advisories(&self) -> usize {
        self.advisories.len()
    }

    pub fn packages(&self) -> usize {
        self.by_package.len()
    }

    /// How long the archives took to parse. Reported by the benchmarks.
    pub fn load_time(&self) -> Duration {
        self.load_time
    }

    pub fn built_at(&self) -> Option<SystemTime> {
        self.built_at
    }
}
