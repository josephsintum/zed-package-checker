//! Times the advisory database against the archives already on disk.
//!
//! The Go server's `cmd/dbcheck` equivalent, deliberately reporting the same
//! things so the two can be put side by side. Peak memory is left to
//! `/usr/bin/time -l` rather than measured from inside: a cross-language memory
//! claim has to come from the kernel, not from two different allocators' own
//! accounting.

#[cfg(feature = "count-alloc")]
use package_checker::alloc::{Counting, live_bytes};
use package_checker::model::Ecosystem;
use package_checker::{Database, Strategy, default_root, load};
use std::str::FromStr;
use std::time::Instant;

#[cfg(feature = "count-alloc")]
#[global_allocator]
static ALLOC: Counting = Counting;

/// Zero without the `count-alloc` feature, which is how the timing runs are
/// built: an accurate clock and an accurate allocator counter cannot be had
/// from the same process.
#[cfg(not(feature = "count-alloc"))]
fn live_bytes() -> usize {
    0
}

fn main() -> std::process::ExitCode {
    let mut root = None;
    let mut strategy = Strategy::Parallel;
    let mut fetch = false;
    let mut breakdown = false;
    let mut ecosystems = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-root" | "--root" => root = args.next().map(Into::into),
            "-sequential" | "--sequential" => strategy = Strategy::Sequential,
            "-fetch" | "--fetch" => fetch = true,
            "-breakdown" | "--breakdown" => breakdown = true,
            other => match Ecosystem::from_str(other) {
                Ok(e) => ecosystems.push(e),
                Err(e) => {
                    eprintln!("error: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            },
        }
    }
    if ecosystems.is_empty() {
        eprintln!("usage: dbcheck [--root DIR] [--sequential] [--fetch] ECOSYSTEM...");
        return std::process::ExitCode::FAILURE;
    }

    let Some(root) = root.or_else(default_root) else {
        eprintln!("error: no cache directory for this platform");
        return std::process::ExitCode::FAILURE;
    };
    let database = Database::new(root);
    println!("cache   {}", database.root().display());

    if fetch {
        let start = Instant::now();
        if let Err(e) = database.ensure(&ecosystems) {
            eprintln!("error: {e}");
            return std::process::ExitCode::FAILURE;
        }
        println!("ensure  {:.2?}", start.elapsed());
    }
    if !database.ready(&ecosystems) {
        eprintln!("error: archives missing; rerun with --fetch");
        return std::process::ExitCode::FAILURE;
    }

    let archives = database.archives(&ecosystems);
    let before = live_bytes();
    let start = Instant::now();
    let (index, stats) = match load(&archives, strategy) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("error: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let elapsed = start.elapsed();

    println!("strategy {strategy:?}");
    for (ecosystem, s) in &stats {
        println!(
            "  {:<10} entries {:>7}  indexed {:>7}  skipped {:>5}",
            ecosystem.to_string(),
            s.entries,
            s.indexed,
            s.skipped
        );
        if !s.inflate.is_zero() || !s.parse.is_zero() {
            println!("    inflate {:>8.0?}   parse {:>8.0?}", s.inflate, s.parse);
        }
    }
    let retained = live_bytes().saturating_sub(before);
    let _ = retained;
    println!(
        "load    {elapsed:.2?}  advisories {}  packages {}",
        index.advisories(),
        index.packages()
    );
    if cfg!(feature = "count-alloc") {
        println!("retained {:.1} MiB", retained as f64 / (1 << 20) as f64);
    }

    if breakdown {
        let mb = |n: usize| n as f64 / (1 << 20) as f64;
        let structs = index.advisories() * size_of::<package_checker::model::Advisory>();
        let (mut text, mut aliases, mut refs, mut affected, mut ranges, mut versions) =
            (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        for a in index.iter() {
            text += a.id.len() + a.summary.len() + a.cvss_vector.len();
            aliases += a.aliases.len() * size_of::<Box<str>>()
                + a.aliases.iter().map(|s| s.len()).sum::<usize>();
            refs += a.references.len() * size_of::<Box<str>>()
                + a.references.iter().map(|s| s.len()).sum::<usize>();
            affected += a.affected.len() * size_of::<package_checker::model::Affected>();
            for f in &a.affected {
                affected += f.package.name.len();
                ranges += f.ranges.len() * size_of::<package_checker::model::AffectedRange>()
                    + f.ranges
                        .iter()
                        .map(|r| {
                            r.introduced.len() + r.fixed.len() + r.last_affected.len()
                        })
                        .sum::<usize>();
                versions += f.versions.len() * size_of::<Box<str>>()
                    + f.versions.iter().map(|s| s.len()).sum::<usize>();
            }
        }
        println!("  advisory structs {:>7.1} MiB", mb(structs));
        println!("  id/summary/vector{:>7.1} MiB", mb(text));
        println!("  aliases          {:>7.1} MiB", mb(aliases));
        println!("  references       {:>7.1} MiB", mb(refs));
        println!("  affected entries {:>7.1} MiB", mb(affected));
        println!("  ranges           {:>7.1} MiB", mb(ranges));
        println!("  explicit versions{:>7.1} MiB", mb(versions));
        println!("  index overhead   {:>7.1} MiB", mb(index.overhead_bytes()));
    }

    // Keep the index alive past the measurement so nothing is freed early.
    std::hint::black_box(&index);
    std::process::ExitCode::SUCCESS
}
