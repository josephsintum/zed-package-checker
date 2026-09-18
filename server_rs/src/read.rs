//! Reading a project's files, bounded.
//!
//! A manifest comes from whatever repository the user opened, so its size is
//! not ours to assume. The cap is a correctness bound rather than a
//! preference: `LineIndex` stores offsets as `u32`, so a file at 4 GiB would
//! produce silently wrong positions rather than an error.

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// The most of one file that is ever read.
///
/// The largest monorepo lockfiles reach about ten megabytes, so this leaves
/// real headroom without coming close to the four gigabytes at which `u32`
/// offsets would start lying.
pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// A file's text, or `None` if it cannot be read, is not UTF-8, or is larger
/// than [`MAX_MANIFEST_BYTES`].
pub fn manifest(path: &Path) -> Option<String> {
    bounded(path, MAX_MANIFEST_BYTES)
}

/// Split out from [`manifest`] so the cap can be exercised with a nine-byte
/// file rather than a sixteen-megabyte one.
///
/// Skips an oversized file rather than truncating it: `Cargo.lock` and
/// `requirements.txt` are line-based, so a prefix parses cleanly and "too big
/// to scan" would read as "half your dependencies are fine".
fn bounded(path: &Path, cap: u64) -> Option<String> {
    let file = File::open(path).ok()?;

    // Measured through the open handle rather than the path, so the file
    // checked is the file read.
    let size = file.metadata().ok()?.len();
    if size > cap {
        // Warned rather than logged quietly, for the reason `extract` warns
        // when it hits the file cap: a skipped manifest is not merely absent
        // from the report, it is published as having nothing wrong with it.
        tracing::warn!(path = %path.display(), size, cap, "manifest too large to scan");
        return None;
    }

    // The stat above is a hint, not a guarantee: a file being written can grow
    // between the two calls. Reading one byte past the cap is what turns it
    // into a bound.
    let mut source = String::new();
    file.take(cap + 1).read_to_string(&mut source).ok()?;
    if source.len() as u64 > cap {
        tracing::warn!(path = %path.display(), cap, "manifest grew past the cap while being read");
        return None;
    }

    Some(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn file(name: &str, contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("write");
        (dir, path)
    }

    #[test]
    fn a_file_under_the_cap_reads_whole() {
        let (_dir, path) = file("go.mod", b"module example.com/x\n");
        assert_eq!(
            bounded(&path, 64).as_deref(),
            Some("module example.com/x\n")
        );
    }

    #[test]
    fn a_file_over_the_cap_is_skipped() {
        let (_dir, path) = file("go.mod", b"123456789");
        assert_eq!(bounded(&path, 8), None);
        // One byte under is the boundary that must still succeed.
        assert!(bounded(&path, 9).is_some());
    }

    #[test]
    fn the_shipped_cap_rejects_an_oversized_file() {
        // set_len writes nothing and costs one syscall on APFS and ext4, so the
        // real constant is exercised without a sixteen-megabyte fixture.
        let (_dir, path) = file("package-lock.json", b"");
        File::options()
            .write(true)
            .open(&path)
            .expect("open")
            .set_len(MAX_MANIFEST_BYTES + 1)
            .expect("grow");
        assert_eq!(manifest(&path), None);
    }

    #[test]
    fn a_file_that_grows_past_the_cap_after_the_stat_is_rejected() {
        // What the second check exists for. The stat sees nine bytes; by the
        // time the read runs there are more.
        let (_dir, path) = file("requirements.txt", b"123456789");
        let mut growing = File::options().append(true).open(&path).expect("open");
        let size = growing.metadata().expect("stat").len();
        growing.write_all(b"0123456789").expect("grow");
        drop(growing);

        // Standing in for the race: the cap is the size the stat would have
        // seen, and the file on disk is now larger than it.
        assert_eq!(bounded(&path, size), None);
    }

    #[test]
    fn a_file_that_is_not_utf8_is_skipped() {
        let (_dir, path) = file("go.mod", &[0xff, 0xfe, 0x00]);
        assert_eq!(manifest(&path), None);
    }

    #[test]
    fn a_missing_file_is_skipped() {
        assert_eq!(manifest(Path::new("/nonexistent/go.mod")), None);
    }
}
