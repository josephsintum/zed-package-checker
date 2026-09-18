//! Times a scan against a real tree, phase by phase.
//!
//! The Go server's `cmd/scanharness` equivalent, and `dbcheck`'s sibling: the
//! database is what `dbcheck` measures, and this is everything the editor pays
//! on *every* debounce rather than once per refresh.
//!
//! The walk is re-implemented here rather than instrumented in `extract`,
//! because measurement scaffolding does not belong in the server. That means
//! read and parse are reported together, by subtraction — stated in the output
//! rather than quietly folded in.

use ignore::WalkBuilder;
use package_checker::model::{Ecosystem, ecosystems_of};
use package_checker::{
    Database, Extractor, Matcher, SKIP_DIRS, Strategy, default_root, is_manifest_name, load,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

struct Walk {
    elapsed: Duration,
    files: usize,
    manifests: usize,
    bytes: u64,
}

fn walk(root: &Path) -> Walk {
    let skip: Vec<String> = SKIP_DIRS.iter().map(|s| (*s).to_owned()).collect();
    let start = Instant::now();
    let (mut files, mut manifests, mut bytes) = (0usize, 0usize, 0u64);

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .filter_entry(move |entry| {
            if entry.file_type().is_some_and(|t| t.is_dir()) {
                let name = entry.file_name().to_string_lossy();
                return !skip.iter().any(|s| *s == name);
            }
            true
        })
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        files += 1;
        if entry.file_name().to_str().is_some_and(is_manifest_name) {
            manifests += 1;
            bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }

    Walk {
        elapsed: start.elapsed(),
        files,
        manifests,
        bytes,
    }
}

fn ms(d: Duration) -> String {
    format!("{:>8.2}ms", d.as_secs_f64() * 1000.0)
}

fn best(runs: usize, mut f: impl FnMut() -> Duration) -> Duration {
    // Fastest of N, for the reason bench.sh gives: the slow runs are other
    // things happening on the machine, not the program.
    (0..runs).map(|_| f()).min().unwrap_or_default()
}

fn main() -> std::process::ExitCode {
    let mut runs = 3usize;
    let mut root: Option<PathBuf> = None;
    let mut db_root: Option<PathBuf> = None;
    let mut skip_match = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-runs" | "--runs" => runs = args.next().and_then(|n| n.parse().ok()).unwrap_or(3),
            "-db-root" | "--db-root" => db_root = args.next().map(Into::into),
            "-no-match" | "--no-match" => skip_match = true,
            other => root = Some(other.into()),
        }
    }
    let Some(root) = root else {
        eprintln!("usage: scanbench [--runs N] [--db-root DIR] [--no-match] DIR");
        return std::process::ExitCode::FAILURE;
    };
    if !root.is_dir() {
        eprintln!("error: {} is not a directory", root.display());
        return std::process::ExitCode::FAILURE;
    }

    println!("tree    {}", root.display());
    println!("runs    {runs}, fastest reported except where a row says otherwise");

    // The counts come from the same runs as the timing, rather than an extra
    // walk on top of them.
    let mut counted = walk(&root);
    let walk_time = best(runs, || {
        counted = walk(&root);
        counted.elapsed
    });

    let extractor = Extractor::new();
    let mut packages = Vec::new();
    let extract_time = best(runs, || {
        let start = Instant::now();
        packages = extractor.extract(&root).unwrap_or_default();
        start.elapsed()
    });

    println!(
        "\n  walk       {}  files {:>7}  manifests {:>4}  {:>8.1} KiB",
        ms(walk_time),
        counted.files,
        counted.manifests,
        counted.bytes as f64 / 1024.0
    );
    println!(
        "  read+parse {}  (extract minus walk; reconcile is inside it)",
        ms(extract_time.saturating_sub(walk_time))
    );
    println!(
        "  extract    {}  packages {}",
        ms(extract_time),
        packages.len()
    );

    if skip_match || packages.is_empty() {
        println!("\n  no advisory database consulted");
        return std::process::ExitCode::SUCCESS;
    }

    let ecosystems: Vec<Ecosystem> = ecosystems_of(&packages);
    let Some(db_root) = db_root.or_else(default_root) else {
        eprintln!("error: no cache directory for this platform");
        return std::process::ExitCode::FAILURE;
    };
    let database = Database::new(db_root);
    if !database.ready(&ecosystems) {
        println!("\n  advisory archives not on disk; run dbcheck --fetch first");
        return std::process::ExitCode::SUCCESS;
    }

    let start = Instant::now();
    let Ok((index, _)) = load(&database.archives(&ecosystems), Strategy::Parallel) else {
        eprintln!("error: could not load the archives");
        return std::process::ExitCode::FAILURE;
    };
    let load_time = start.elapsed();

    let mut findings = Vec::new();
    let match_time = best(runs, || {
        let start = Instant::now();
        findings = Matcher::new(&index).findings(&packages);
        start.elapsed()
    });

    println!(
        "  load       {}  one sample, not repeated; once per refresh anyway",
        ms(load_time)
    );
    println!(
        "  match      {}  findings {}",
        ms(match_time),
        findings.len()
    );

    // What the publish path re-reads: `diagnostics::for_file` reads every
    // manifest that carries a finding, a second time, after extraction already
    // read it. Measured from the findings the timed run produced, rather than
    // by matching all over again.
    let republished: u64 = findings
        .iter()
        .map(|f| f.anchor_site().path.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
        .sum();
    println!(
        "\n  re-read on publish {:>6.1} KiB across the files carrying a finding",
        republished as f64 / 1024.0
    );

    std::hint::black_box(&index);
    std::process::ExitCode::SUCCESS
}
