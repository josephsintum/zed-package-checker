//! The on-disk copy of the OSV database: where it lives, how it is refreshed,
//! and how two editor windows share it without corrupting it.
//!
//! Archives are read by `crate::load`; this module is only responsible for
//! there being a correct archive to read.

use crate::model::Ecosystem;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// Serves the OSV database, one zip per ecosystem.
const ARCHIVE_HOST: &str = "https://osv-vulnerabilities.storage.googleapis.com";
const ARCHIVE_NAME: &str = "all.zip";

/// Matches the layout osv-scanner uses, so the same cache can be pointed at
/// osv-scanner when differential-testing.
const VENDOR_DIR: &str = "osv-scalibr";

/// How long a downloaded archive is trusted before it is checked again.
/// Advisories are published continuously, but a day-old database is a
/// reasonable trade against waking the network on every editor start.
/// Smallest archive first, so the quick wins land while npm is still streaming.
/// Sizes as published: crates.io 3 MB, Go 11 MB, `PyPI` 32 MB, npm 205 MB.
const ARCHIVE_ORDER: [Ecosystem; 4] = [
    Ecosystem::CratesIo,
    Ecosystem::Go,
    Ecosystem::PyPI,
    Ecosystem::Npm,
];

const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Bounds how long we wait for another process already refreshing an ecosystem.
/// Generous enough for npm's 215 MB on a slow link, short enough that a dead
/// peer does not hang a scan forever.
const PEER_WAIT: Duration = Duration::from_secs(15 * 60);

const PROGRESS_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, thiserror::Error)]
/// Why the advisory cache could not be brought up to date.
pub enum DbError {
    #[error("advisory database not ready: {0}")]
    /// No usable archive, with what is known about why.
    NotReady(String),
    #[error("{context}: {source}")]
    /// A filesystem operation failed.
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        source: io::Error,
    },
    #[error("fetch {url}: {message}")]
    /// The bucket answered, but not with an archive.
    Fetch {
        /// What was requested.
        url: String,
        /// What went wrong, as the transport or the status reported it.
        message: String,
    },
}

fn io_err(context: impl Into<String>) -> impl FnOnce(io::Error) -> DbError {
    let context = context.into();
    move |source| DbError::Io { context, source }
}

/// Reports download progress to whatever is watching — the LSP client, or a
/// benchmark harness.
pub trait Progress: Send + Sync {
    /// `total` is `None` when the server sent no Content-Length.
    fn start(&self, ecosystem: Ecosystem, total: Option<u64>);
    /// Bytes received so far.
    fn advance(&self, ecosystem: Ecosystem, downloaded: u64, total: Option<u64>);
    /// The download finished, with the failure if it failed.
    fn done(&self, ecosystem: Ecosystem, error: Option<&str>);
}

/// The advisory cache.
pub struct Database {
    root: PathBuf,
    host: String,
    agent: ureq::Agent,
    ttl: Duration,
    progress: Option<Box<dyn Progress>>,
    /// Overridable so staleness can be tested without sleeping.
    now: Box<dyn Fn() -> SystemTime + Send + Sync>,
    /// The modification time each archive had when it last passed validation.
    validated: Mutex<HashMap<Ecosystem, SystemTime>>,
}

impl Database {
    /// A cache rooted at `root`, reading the public bucket with a 24-hour
    /// freshness window.
    pub fn new(root: impl Into<PathBuf>) -> Database {
        let config = ureq::Agent::config_builder()
            // npm's archive is 215 MB.
            .timeout_global(Some(Duration::from_secs(600)))
            // A 304 is the good case, not an error.
            .http_status_as_error(false)
            .build();
        Database {
            root: root.into(),
            host: ARCHIVE_HOST.to_owned(),
            agent: config.into(),
            ttl: DEFAULT_TTL,
            progress: None,
            now: Box::new(SystemTime::now),
            validated: Mutex::new(HashMap::new()),
        }
    }

    /// Where the archives are fetched from. A mirror, or a test server.
    pub fn with_archive_host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    /// How long an archive is trusted before it is checked again.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Reports downloads as they happen.
    pub fn with_progress(mut self, progress: Box<dyn Progress>) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Overrides the clock, so staleness can be exercised without sleeping.
    pub fn with_clock(mut self, now: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.now = Box::new(now);
        self
    }

    /// The cache directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory holding one ecosystem's archive.
    pub fn dir_for(&self, ecosystem: Ecosystem) -> PathBuf {
        self.root.join(VENDOR_DIR).join(ecosystem.as_str())
    }

    /// Where one ecosystem's `all.zip` lives.
    pub fn archive_path(&self, ecosystem: Ecosystem) -> PathBuf {
        self.dir_for(ecosystem).join(ARCHIVE_NAME)
    }

    /// The freshness sidecar.
    ///
    /// Named for this server rather than reusing the `.meta` other tools keep
    /// beside the same archive. The archive itself is worth sharing — it is the
    /// 215 MB — but sharing the metadata would mean each tool invalidating the
    /// other's record of when it last checked, and both re-downloading.
    /// Separate sidecars, one shared archive.
    fn meta_path(&self, ecosystem: Ecosystem) -> PathBuf {
        self.dir_for(ecosystem)
            .join(format!("{ARCHIVE_NAME}.rsmeta"))
    }

    fn lock_path(&self, ecosystem: Ecosystem) -> PathBuf {
        self.dir_for(ecosystem).join(format!("{ARCHIVE_NAME}.lock"))
    }

    /// Whether every named ecosystem has an archive on disk.
    ///
    /// A stat, deliberately: this is on the scan path, and "is there something
    /// to read" is a different question from "is it current".
    pub fn ready(&self, ecosystems: &[Ecosystem]) -> bool {
        ecosystems.iter().all(|&e| self.archive_path(e).exists())
    }

    /// Which of the named ecosystems have an archive on disk.
    ///
    /// Each archive is published by an atomic rename, so one that is present is
    /// complete and verified even while its siblings are still downloading.
    pub fn ready_ecosystems(&self, ecosystems: &[Ecosystem]) -> Vec<Ecosystem> {
        ecosystems
            .iter()
            .copied()
            .filter(|&e| self.archive_path(e).exists())
            .collect()
    }

    /// The archives for the named ecosystems, ready to be handed to `load`.
    pub fn archives(&self, ecosystems: &[Ecosystem]) -> Vec<(Ecosystem, PathBuf)> {
        ecosystems
            .iter()
            .map(|&e| (e, self.archive_path(e)))
            .collect()
    }

    /// Downloads or revalidates every named ecosystem, concurrently.
    ///
    /// `landed` is called with each ecosystem as its archive becomes readable,
    /// so a scan can start on what is present rather than waiting for all of
    /// them. Ordered smallest first: crates.io is 3 MB and npm is 205, and a
    /// Rust project waiting on npm's archive before seeing its own findings was
    /// the whole of the first-run problem.
    ///
    /// # Errors
    ///
    /// [`DbError::NotReady`] naming every ecosystem that could not be brought up
    /// to date; the ones that could are still usable.
    pub fn ensure_each(
        &self,
        ecosystems: &[Ecosystem],
        landed: impl Fn(Ecosystem) + Send + Sync,
    ) -> Result<(), DbError> {
        let mut ordered = ecosystems.to_vec();
        ordered.sort_by_key(|e| {
            ARCHIVE_ORDER
                .iter()
                .position(|o| o == e)
                .unwrap_or(usize::MAX)
        });

        let failures = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for ecosystem in ordered {
                let failures = &failures;
                let landed = &landed;
                scope.spawn(move || match self.ensure_one(ecosystem) {
                    Ok(()) => landed(ecosystem),
                    Err(err) => {
                        if let Ok(mut failures) = failures.lock() {
                            failures.push(format!("{ecosystem}: {err}"));
                        }
                    }
                });
            }
        });

        let failures = failures.into_inner().unwrap_or_default();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(DbError::NotReady(failures.join("; ")))
        }
    }

    /// Downloads or revalidates every named ecosystem.
    ///
    /// # Errors
    ///
    /// As [`Database::ensure_each`].
    pub fn ensure(&self, ecosystems: &[Ecosystem]) -> Result<(), DbError> {
        self.ensure_each(ecosystems, |_| {})
    }

    fn ensure_one(&self, ecosystem: Ecosystem) -> Result<(), DbError> {
        let dir = self.dir_for(ecosystem);
        fs::create_dir_all(&dir).map_err(io_err(format!("create {}", dir.display())))?;

        // Repair before deciding freshness: a corrupt archive is stale
        // regardless of what its metadata claims.
        self.heal(ecosystem);

        if !self.stale(ecosystem) {
            return Ok(());
        }

        let lock_path = self.lock_path(ecosystem);
        let lock =
            File::create(&lock_path).map_err(io_err(format!("open {}", lock_path.display())))?;

        // std gained advisory file locking in 1.89, so no locking crate is
        // needed for the one place the failure mode is a corrupt 205 MB file.
        if !try_lock(&lock) {
            // Another process is already downloading this ecosystem.
            return self.await_peer(ecosystem, &lock);
        }
        let result = (|| {
            // Re-check under the lock: a peer may have finished between the
            // staleness check and acquiring it.
            if !self.stale(ecosystem) {
                return Ok(());
            }
            self.fetch(ecosystem)
        })();
        let _ = lock.unlock();
        result
    }

    /// Waits for whichever process holds the lock, then uses what it left.
    ///
    /// Without this, a second editor window would sit at "not ready" until the
    /// next file event, which could be never.
    fn await_peer(&self, ecosystem: Ecosystem, lock: &File) -> Result<(), DbError> {
        let deadline = Instant::now() + PEER_WAIT;
        while Instant::now() < deadline {
            if try_lock(lock) {
                let _ = lock.unlock();
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        if self.archive_path(ecosystem).exists() {
            Ok(())
        } else {
            Err(DbError::NotReady(format!(
                "{ecosystem}: waited for another process and it produced nothing"
            )))
        }
    }

    fn stale(&self, ecosystem: Ecosystem) -> bool {
        if !self.archive_path(ecosystem).exists() {
            return true;
        }
        match self.read_meta(ecosystem) {
            // Archive present but unaccounted for: re-check rather than trust it.
            None => true,
            Some(meta) => (self.now)()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs().saturating_sub(meta.fetched_at) >= self.ttl.as_secs())
                .unwrap_or(true),
        }
    }

    /// Deletes an archive that no longer opens as a zip.
    ///
    /// osv-scanner has no equivalent: its offline mode skips checksum
    /// validation, so a download interrupted mid-write leaves a corrupt archive
    /// that never self-heals.
    fn heal(&self, ecosystem: Ecosystem) {
        let archive = self.archive_path(ecosystem);
        let Ok(info) = fs::metadata(&archive) else {
            return;
        };
        if !info.is_file() {
            return;
        }

        // Validation reads the central directory of a file that is 205 MB for
        // npm, and this runs on every revalidation, not just once. An archive
        // is only ever replaced by an atomic rename, so an unchanged
        // modification time means unchanged bytes, and bytes that were
        // readable an hour ago still are.
        let modified = info.modified().ok();
        if let Some(modified) = modified
            && self
                .validated
                .lock()
                .is_ok_and(|v| v.get(&ecosystem) == Some(&modified))
        {
            return;
        }

        if validate_zip(&archive).is_ok() {
            if let (Some(modified), Ok(mut validated)) = (modified, self.validated.lock()) {
                validated.insert(ecosystem, modified);
            }
            return;
        }
        tracing::warn!(%ecosystem, path = %archive.display(), "discarding unreadable advisory archive");
        let _ = fs::remove_file(&archive);
        let _ = fs::remove_file(self.meta_path(ecosystem));
    }

    fn fetch(&self, ecosystem: Ecosystem) -> Result<(), DbError> {
        let url = self.archive_url(ecosystem);
        let archive = self.archive_path(ecosystem);

        let mut request = self.agent.get(&url);
        // Only offer a validator when the archive it describes is actually
        // present; otherwise a 304 would leave us with metadata and no data.
        if let Some(meta) = self.read_meta(ecosystem)
            && !meta.etag.is_empty()
            && archive.exists()
        {
            request = request.header("If-None-Match", &meta.etag);
        }

        let mut response = request.call().map_err(|e| DbError::Fetch {
            url: url.clone(),
            message: e.to_string(),
        })?;

        match response.status().as_u16() {
            304 => {
                // Still current. Record the check so staleness is measured from
                // now rather than from the last time the bytes changed.
                let mut meta = self.read_meta(ecosystem).unwrap_or_default();
                meta.fetched_at = self.unix_now();
                return self.write_meta(ecosystem, &meta);
            }
            200 => {}
            other => {
                return Err(DbError::Fetch {
                    url,
                    message: format!("unexpected status {other}"),
                });
            }
        }

        let want_crc = crc32c_from_header(response.headers());
        let total = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();

        if let Some(progress) = &self.progress {
            progress.start(ecosystem, total);
        }

        let mut reader = response.body_mut().as_reader();
        let result = write_atomic(
            &archive,
            |out| {
                let mut downloaded = 0u64;
                let mut last = Instant::now();
                let mut buffer = vec![0u8; 256 * 1024];
                loop {
                    let n = reader.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    out.write_all(&buffer[..n])?;
                    downloaded += n as u64;
                    if let Some(progress) = &self.progress
                        && last.elapsed() >= PROGRESS_INTERVAL
                    {
                        last = Instant::now();
                        progress.advance(ecosystem, downloaded, total);
                    }
                }
                // The timer above skips the last stretch, so without this a
                // download can end with the bar short of its total.
                if let Some(progress) = &self.progress {
                    progress.advance(ecosystem, downloaded, total);
                }
                Ok(())
            },
            |tmp| verify_archive(tmp, want_crc),
        );

        if let Some(progress) = &self.progress {
            progress.done(
                ecosystem,
                result.as_ref().err().map(|e| e.to_string()).as_deref(),
            );
        }
        result?;

        // Verified as part of the publish, so the next heal need not read it.
        if let Ok(modified) = fs::metadata(&archive).and_then(|m| m.modified())
            && let Ok(mut validated) = self.validated.lock()
        {
            validated.insert(ecosystem, modified);
        }

        // Written only once the archive has landed and been verified. Without
        // the metadata the archive reads as stale and the whole download repeats
        // on the next start, so announcing "ready" before this would be a lie.
        self.write_meta(
            ecosystem,
            &Meta {
                etag,
                fetched_at: self.unix_now(),
                crc32c: want_crc.unwrap_or(0),
            },
        )
    }

    /// An advisory's full description, read back from the archive.
    ///
    /// Kept out of the index because it dominates its size while being needed
    /// only for the few advisories a project actually matches. One seek into the
    /// central directory, while a user is hovering rather than during a scan.
    ///
    /// # Errors
    ///
    /// [`DbError::NotReady`] when the archive or the advisory is not there, and
    /// [`DbError::Io`] when it cannot be read.
    pub fn details(&self, ecosystem: Ecosystem, advisory_id: &str) -> Result<String, DbError> {
        let path = self.archive_path(ecosystem);
        let file = File::open(&path).map_err(io_err(format!("open {}", path.display())))?;
        let mut archive = zip::ZipArchive::new(io::BufReader::new(file))
            .map_err(|e| DbError::NotReady(format!("{}: {e}", path.display())))?;

        // Archives name each entry after its advisory id.
        let mut entry = archive
            .by_name(&format!("{advisory_id}.json"))
            .map_err(|e| DbError::NotReady(format!("{advisory_id} in {ecosystem}: {e}")))?;
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(io_err("read advisory"))?;

        #[derive(Deserialize)]
        struct Details {
            #[serde(default)]
            details: String,
        }
        serde_json::from_slice::<Details>(&bytes)
            .map(|d| d.details)
            .map_err(|e| DbError::NotReady(format!("decode {advisory_id}: {e}")))
    }

    fn archive_url(&self, ecosystem: Ecosystem) -> String {
        // Ecosystem names are used verbatim, including case and the dot in
        // "crates.io"; normalising them produces 404s.
        format!("{}/{}/{ARCHIVE_NAME}", self.host, ecosystem.as_str())
    }

    fn unix_now(&self) -> u64 {
        (self.now)()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn read_meta(&self, ecosystem: Ecosystem) -> Option<Meta> {
        let bytes = fs::read(self.meta_path(ecosystem)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    #[expect(
        clippy::expect_used,
        reason = "Meta is plain data with no map keys; serialisation cannot fail"
    )]
    fn write_meta(&self, ecosystem: Ecosystem, meta: &Meta) -> Result<(), DbError> {
        let path = self.meta_path(ecosystem);
        let encoded = serde_json::to_vec(meta).expect("meta is plain data");
        write_atomic(&path, |out| out.write_all(&encoded), |_| Ok(()))
    }
}

/// What is known about an archive without opening it.
#[derive(Serialize, Deserialize, Default, Debug)]
struct Meta {
    /// Sent back as `If-None-Match`.
    #[serde(default)]
    etag: String,
    /// When the archive was last confirmed current, updated on a 304 as well as
    /// on a download. Unix seconds.
    #[serde(default, rename = "fetchedAt")]
    fetched_at: u64,
    /// The checksum the server reported, retained so corruption can be detected
    /// without asking the network.
    #[serde(default)]
    crc32c: u32,
}

/// Takes the lock if it is free. A lock another process holds is an answer,
/// not an error: the caller waits for it rather than failing.
fn try_lock(file: &File) -> bool {
    match file.try_lock() {
        Ok(()) => true,
        Err(std::fs::TryLockError::WouldBlock) => false,
        Err(std::fs::TryLockError::Error(e)) => {
            tracing::debug!(error = %e, "advisory lock unavailable");
            false
        }
    }
}

/// Reads Google Cloud Storage's `x-goog-hash: crc32c=<base64 big-endian u32>`.
fn crc32c_from_header(headers: &ureq::http::HeaderMap) -> Option<u32> {
    for value in headers.get_all("x-goog-hash") {
        let Ok(value) = value.to_str() else { continue };
        for part in value.split(',') {
            if let Some(encoded) = part.trim().strip_prefix("crc32c=") {
                let raw = base64_decode(encoded)?;
                if raw.len() == 4 {
                    return Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]));
                }
            }
        }
    }
    None
}

/// Standard base64, for the one four-byte value this program ever decodes.
/// A dependency would be more code than the decoder.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in s.bytes() {
        if byte == b'=' {
            break;
        }
        let value = TABLE.iter().position(|&c| c == byte)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

fn verify_archive(path: &Path, want_crc: Option<u32>) -> Result<(), DbError> {
    if let Some(want) = want_crc {
        let got = checksum(path).map_err(io_err("read downloaded archive"))?;
        if got != want {
            return Err(DbError::Fetch {
                url: path.display().to_string(),
                message: format!("checksum mismatch: got {got:08x}, want {want:08x}"),
            });
        }
    }
    validate_zip(path)
}

/// The CRC32C of a file, streamed: the archive was just written and is 215 MB
/// for npm, so reading it back whole would double the peak memory of the
/// download it just finished.
fn checksum(path: &Path) -> io::Result<u32> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; 256 * 1024];
    let mut crc = 0;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            return Ok(crc);
        }
        crc = crc32c::crc32c_append(crc, &buffer[..n]);
    }
}

fn validate_zip(path: &Path) -> Result<(), DbError> {
    let file = File::open(path).map_err(io_err(format!("open {}", path.display())))?;
    let archive = zip::ZipArchive::new(io::BufReader::new(file))
        .map_err(|e| DbError::NotReady(format!("{}: not a readable zip: {e}", path.display())))?;
    if archive.is_empty() {
        return Err(DbError::NotReady(format!(
            "{}: zip archive is empty",
            path.display()
        )));
    }
    Ok(())
}

/// Writes a file so that a concurrent reader sees either the whole old content
/// or the whole new one, never a partial.
///
/// The temp file is created in the same directory as the target, so the rename
/// stays within one filesystem and is therefore atomic. Nothing is published
/// until `verify` has accepted it.
fn write_atomic(
    path: &Path,
    write: impl FnOnce(&mut File) -> io::Result<()>,
    verify: impl FnOnce(&Path) -> Result<(), DbError>,
) -> Result<(), DbError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir).map_err(io_err(format!("create {}", dir.display())))?;

    let tmp = dir.join(format!(
        "{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("out"),
        std::process::id()
    ));

    let result = (|| {
        let mut file = File::create(&tmp).map_err(io_err(format!("create {}", tmp.display())))?;
        write(&mut file).map_err(io_err(format!("write {}", tmp.display())))?;
        // Flush before publishing: a rename can otherwise be visible after a
        // crash while the contents are not.
        file.sync_all()
            .map_err(io_err(format!("sync {}", tmp.display())))?;
        drop(file);
        verify(&tmp)?;
        rename_with_retry(&tmp, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn rename_with_retry(from: &Path, to: &Path) -> Result<(), DbError> {
    let mut delay = Duration::from_millis(20);
    for attempt in 0..5 {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            // Windows refuses to rename over a file another process has open.
            // The read window is short, so back off and try again.
            Err(e) if attempt < 4 && cfg!(windows) => {
                tracing::debug!(error = %e, "rename refused, retrying");
                std::thread::sleep(delay);
                delay *= 2;
            }
            Err(e) => {
                return Err(DbError::Io {
                    context: format!("rename to {}", to.display()),
                    source: e,
                });
            }
        }
    }
    unreachable!("the loop returns on the final attempt")
}

/// The advisory cache directory for this platform.
///
/// A cache rather than a config directory: this is derived data a user should
/// be able to reclaim by deleting it.
pub fn default_root() -> Option<PathBuf> {
    let base = if cfg!(target_os = "macos") {
        PathBuf::from(std::env::var_os("HOME")?).join("Library/Caches")
    } else if cfg!(windows) {
        PathBuf::from(std::env::var_os("LOCALAPPDATA")?)
    } else {
        match std::env::var_os("XDG_CACHE_HOME") {
            Some(dir) => PathBuf::from(dir),
            None => PathBuf::from(std::env::var_os("HOME")?).join(".cache"),
        }
    };
    Some(base.join("zed-package-checker").join("db"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{ArchiveServer, Serve, fake_archive, one_entry_archive};
    use std::sync::{Arc, Mutex};

    const NPM: &[Ecosystem] = &[Ecosystem::Npm];

    #[derive(Default)]
    struct Recorded {
        starts: usize,
        advances: usize,
        dones: usize,
        total: Option<u64>,
        downloaded: u64,
        error: Option<String>,
    }

    /// Captures the `Progress` calls a fetch makes.
    #[derive(Default)]
    struct RecordingProgress(Arc<Mutex<Recorded>>);

    impl Progress for RecordingProgress {
        fn start(&self, _: Ecosystem, total: Option<u64>) {
            let mut r = self.0.lock().unwrap();
            r.starts += 1;
            r.total = total;
        }
        fn advance(&self, _: Ecosystem, downloaded: u64, _: Option<u64>) {
            let mut r = self.0.lock().unwrap();
            r.advances += 1;
            r.downloaded = downloaded;
        }
        fn done(&self, _: Ecosystem, error: Option<&str>) {
            let mut r = self.0.lock().unwrap();
            r.dones += 1;
            r.error = error.map(str::to_owned);
        }
    }

    /// A body large enough that the download loop reports progress at least
    /// once between start and done.
    fn large_archive() -> Vec<u8> {
        let body = "x".repeat(4 * 1024 * 1024);
        fake_archive(&[("GHSA-1.json", &body)])
    }

    mod ensure {
        use super::*;

        #[test]
        fn ensure_downloads_then_reuses_cache() {
            let server = ArchiveServer::new(one_entry_archive());
            let root = tempfile::tempdir().unwrap();
            let db = server.database(root.path());

            assert!(!db.ready(NPM), "ready before any download");
            db.ensure(NPM).unwrap();
            assert!(db.ready(NPM), "not ready after a successful download");
            assert_eq!(server.requests(), 1);

            // Within the TTL nothing should touch the network at all.
            db.ensure(NPM).unwrap();
            assert_eq!(server.requests(), 1, "a warm start made a request");
        }

        #[test]
        fn ensure_revalidates_when_stale() {
            let server = ArchiveServer::new(one_entry_archive());
            let root = tempfile::tempdir().unwrap();
            let now = Arc::new(Mutex::new(SystemTime::now()));
            let clock = now.clone();
            let db = server
                .database(root.path())
                .with_ttl(Duration::from_secs(3600))
                .with_clock(move || *clock.lock().unwrap());

            db.ensure(NPM).unwrap();

            // Past the TTL the server is asked, but an unchanged ETag means a 304
            // and no re-download.
            *now.lock().unwrap() += Duration::from_secs(2 * 3600);
            db.ensure(NPM).unwrap();
            assert_eq!(server.requests(), 2);
            assert_eq!(server.not_modified(), 1);

            // And the freshness check must be recorded, or every scan would re-ask.
            *now.lock().unwrap() += Duration::from_secs(30 * 60);
            db.ensure(NPM).unwrap();
            assert_eq!(server.requests(), 2, "a 304 did not refresh the timestamp");
        }

        #[test]
        fn ensure_fetches_only_requested_ecosystems() {
            // A Go project must never pay for npm's 205 MB.
            let server = ArchiveServer::new(fake_archive(&[("GO-1.json", "{}")]));
            let root = tempfile::tempdir().unwrap();
            let db = server.database(root.path());

            db.ensure(&[Ecosystem::Go]).unwrap();

            assert!(db.archive_path(Ecosystem::Go).exists());
            for e in [Ecosystem::Npm, Ecosystem::PyPI, Ecosystem::CratesIo] {
                assert!(
                    !db.archive_path(e).exists(),
                    "{e} was downloaded but not requested"
                );
            }
        }

        #[test]
        fn concurrent_ensure_downloads_once() {
            // Zed runs one server per worktree, so several processes routinely race
            // on this cache. Exactly one should download; the rest wait and then
            // succeed.
            let server = ArchiveServer::new(one_entry_archive());
            server.set(|s| s.delay = Duration::from_millis(100));
            let root = tempfile::tempdir().unwrap();

            std::thread::scope(|scope| {
                let workers: Vec<_> = (0..5)
                    .map(|_| scope.spawn(|| server.database(root.path()).ensure(NPM)))
                    .collect();
                for (i, worker) in workers.into_iter().enumerate() {
                    worker
                        .join()
                        .unwrap()
                        .unwrap_or_else(|e| panic!("worker {i}: {e}"));
                }
            });

            assert_eq!(server.requests(), 1, "want exactly one download");
            assert!(server.database(root.path()).ready(NPM));
        }

        #[test]
        fn ensure_reports_every_ecosystem_that_failed() {
            let server = ArchiveServer::new(one_entry_archive());
            server.set(|s| s.mode = Serve::NotFound);
            let root = tempfile::tempdir().unwrap();
            let db = server.database(root.path());

            let err = db
                .ensure(&[Ecosystem::Npm, Ecosystem::Go])
                .expect_err("a 404 was accepted");
            // Both failures should be reported, not just the first.
            let message = err.to_string();
            assert!(message.contains("npm"), "{message}");
            assert!(message.contains("Go"), "{message}");
        }
    }

    mod verify {
        use super::*;

        #[test]
        fn ensure_rejects_corrupt_download() {
            // A body that is not a zip must never be published, however cleanly it
            // transferred: an error page served with a 200 looks like success.
            let server = ArchiveServer::new(b"<html>502 Bad Gateway</html>".to_vec());
            let root = tempfile::tempdir().unwrap();
            let db = server.database(root.path());

            assert!(db.ensure(NPM).is_err(), "a non-zip body was accepted");
            assert!(
                !db.archive_path(Ecosystem::Npm).exists(),
                "a corrupt archive was published"
            );
            // The temporary file must be cleaned up too.
            for entry in fs::read_dir(db.dir_for(Ecosystem::Npm)).unwrap().flatten() {
                let name = entry.file_name();
                assert!(
                    name.to_string_lossy().ends_with(".lock"),
                    "left behind {}",
                    name.to_string_lossy()
                );
            }
        }

        #[test]
        fn ensure_rejects_checksum_mismatch() {
            let server = ArchiveServer::new(one_entry_archive());
            server.set(|s| s.mode = Serve::WrongChecksum);
            let root = tempfile::tempdir().unwrap();
            let db = server.database(root.path());

            let err = db
                .ensure(NPM)
                .expect_err("a checksum mismatch was accepted");
            assert!(err.to_string().contains("checksum mismatch"), "{err}");
            assert!(
                !db.archive_path(Ecosystem::Npm).exists(),
                "published despite a bad checksum"
            );
        }

        #[test]
        fn reads_never_see_a_partial_archive() {
            // Publishing is a rename, so a concurrent reader sees either the old
            // complete archive or the new one, never a half-written file.
            let server = ArchiveServer::new(one_entry_archive());
            // Every request is answered with a full body, so every ensure republishes.
            server.set(|s| s.conditional = false);
            let root = tempfile::tempdir().unwrap();
            let writer = server.database(root.path()).with_ttl(Duration::ZERO);
            writer.ensure(NPM).unwrap();
            let archive = writer.archive_path(Ecosystem::Npm);

            let deadline = Instant::now() + Duration::from_secs(1);
            let (reads, failures) = std::thread::scope(|scope| {
                scope.spawn(|| {
                    while Instant::now() < deadline {
                        let _ = writer.ensure(NPM);
                    }
                });
                let (mut reads, mut failures) = (0, 0);
                while Instant::now() < deadline {
                    if validate_zip(&archive).is_err() {
                        failures += 1;
                    }
                    reads += 1;
                }
                (reads, failures)
            });

            assert_eq!(
                failures, 0,
                "{failures} of {reads} reads saw an invalid archive"
            );
            assert!(
                reads >= 10,
                "only {reads} reads; the test barely exercised anything"
            );
            assert!(server.requests() >= 2, "the writer never republished");
        }

        #[test]
        fn crc32c_is_read_from_the_header() {
            let cases: &[(&str, &[&str], Option<u32>)] = &[
                ("absent", &[], None),
                ("md5 only", &["md5=6bBQJ2rnE5o/rJZDYqgAew=="], None),
                ("crc32c alone", &["crc32c=W3hLNw=="], Some(0x5b78_4b37)),
                (
                    "repeated headers",
                    &["md5=6bBQJ2rnE5o/rJZDYqgAew==", "crc32c=W3hLNw=="],
                    Some(0x5b78_4b37),
                ),
                (
                    "comma separated",
                    &["md5=6bBQJ2rnE5o/rJZDYqgAew==, crc32c=W3hLNw=="],
                    Some(0x5b78_4b37),
                ),
                ("malformed base64", &["crc32c=!!!"], None),
                ("wrong length", &["crc32c=AAA="], None),
            ];
            for (name, values, want) in cases {
                let mut headers = ureq::http::HeaderMap::new();
                for value in *values {
                    headers.append("x-goog-hash", value.parse().unwrap());
                }
                assert_eq!(crc32c_from_header(&headers), *want, "{name}");
            }
        }
    }

    mod heal {
        use super::*;

        #[test]
        fn heal_recovers_from_truncated_archive() {
            // The failure osv-scanner's own cache can leave behind: a half-written
            // zip that offline matching never revalidates.
            let server = ArchiveServer::new(one_entry_archive());
            let root = tempfile::tempdir().unwrap();
            let db = server.database(root.path());
            db.ensure(NPM).unwrap();

            let archive = db.archive_path(Ecosystem::Npm);
            let original = fs::read(&archive).unwrap();
            fs::write(&archive, &original[..original.len() / 2]).unwrap();
            assert!(
                validate_zip(&archive).is_err(),
                "truncation left a valid zip; nothing exercised"
            );

            db.ensure(NPM).unwrap();
            validate_zip(&archive).expect("archive still unreadable after recovery");
            assert_eq!(server.requests(), 2, "the corrupt copy must be re-fetched");
        }

        #[test]
        fn heal_does_not_reread_an_unchanged_archive() {
            // Validation reads the central directory of a file that is 205 MB for
            // npm, and ensure is reached hourly now that the database revalidates.
            // An archive is only ever replaced by an atomic rename, so an unchanged
            // modification time means unchanged bytes.
            //
            // The trade-off is deliberate and this test states it: corruption that
            // leaves the modification time alone is not noticed. Nothing writes
            // these files in place, so the only way to produce that is to do what
            // this test does on purpose.
            let server = ArchiveServer::new(one_entry_archive());
            let root = tempfile::tempdir().unwrap();
            let db = server.database(root.path()).with_ttl(Duration::ZERO);
            db.ensure(NPM).unwrap();

            let archive = db.archive_path(Ecosystem::Npm);
            let before = fs::metadata(&archive).unwrap().modified().unwrap();
            fs::write(&archive, b"not a zip").unwrap();
            File::options()
                .write(true)
                .open(&archive)
                .unwrap()
                .set_modified(before)
                .unwrap();

            db.ensure(NPM).unwrap();
            assert_eq!(
                fs::read(&archive).unwrap(),
                b"not a zip",
                "an archive whose modification time did not change was re-read and discarded"
            );
        }

        #[test]
        fn heal_still_catches_corruption_that_changes_the_file() {
            let server = ArchiveServer::new(one_entry_archive());
            let root = tempfile::tempdir().unwrap();
            let db = server.database(root.path()).with_ttl(Duration::ZERO);
            db.ensure(NPM).unwrap();

            // Corrupt it the way a crash mid-write would: new bytes, new mtime.
            let archive = db.archive_path(Ecosystem::Npm);
            std::thread::sleep(Duration::from_millis(20));
            fs::write(&archive, b"not a zip").unwrap();

            db.ensure(NPM).unwrap();
            validate_zip(&archive).expect("a corrupted archive was left in place");
        }

        #[test]
        fn heal_ignores_a_directory_where_the_archive_should_be() {
            let root = tempfile::tempdir().unwrap();
            let db = Database::new(root.path());
            let archive = db.archive_path(Ecosystem::Npm);
            fs::create_dir_all(&archive).unwrap();

            db.heal(Ecosystem::Npm);
            assert!(
                archive.is_dir(),
                "heal removed something that was not an archive"
            );
        }
    }

    mod progress {
        use super::*;

        #[test]
        fn download_reports_progress() {
            // The link between the download and the editor: without this the 205 MB
            // first run looks like a hang.
            let server = ArchiveServer::new(large_archive());
            server.set(|s| s.delay = Duration::from_millis(250));
            let root = tempfile::tempdir().unwrap();
            let recorded = Arc::new(Mutex::new(Recorded::default()));
            let db = server
                .database(root.path())
                .with_progress(Box::new(RecordingProgress(recorded.clone())));

            db.ensure(NPM).unwrap();

            let r = recorded.lock().unwrap();
            assert_eq!((r.starts, r.dones), (1, 1), "one start and one done");
            assert_eq!(r.error, None);
            assert!(
                r.downloaded > 0,
                "final downloaded count is the archive size"
            );
            if let Some(total) = r.total {
                assert_eq!(r.downloaded, total, "the counts must agree at the end");
            }
        }

        #[test]
        fn a_cached_archive_reports_no_progress() {
            // A 304 moves no bytes, so opening a progress entry for it would flash
            // an empty download at the user on every startup.
            let server = ArchiveServer::new(one_entry_archive());
            let root = tempfile::tempdir().unwrap();
            let recorded = Arc::new(Mutex::new(Recorded::default()));
            let db = server
                .database(root.path())
                .with_ttl(Duration::ZERO)
                .with_progress(Box::new(RecordingProgress(recorded.clone())));

            db.ensure(NPM).unwrap();
            let after_first = recorded.lock().unwrap().starts;
            db.ensure(NPM).unwrap();

            assert_eq!(server.not_modified(), 1, "the second call revalidated");
            assert_eq!(recorded.lock().unwrap().starts, after_first);
        }
    }

    mod paths {
        use super::*;

        #[test]
        fn archive_url_uses_the_ecosystem_name_verbatim() {
            // Normalising case or punctuation produces 404s.
            let db = Database::new("unused");
            for (ecosystem, suffix) in [
                (Ecosystem::Npm, "/npm/all.zip"),
                (Ecosystem::Go, "/Go/all.zip"),
                (Ecosystem::PyPI, "/PyPI/all.zip"),
                (Ecosystem::CratesIo, "/crates.io/all.zip"),
            ] {
                assert_eq!(db.archive_url(ecosystem), format!("{ARCHIVE_HOST}{suffix}"));
            }
        }

        #[test]
        fn default_root_is_under_the_user_cache() {
            let Some(root) = default_root() else {
                eprintln!("no user cache directory available");
                return;
            };
            assert!(root.is_absolute(), "{}", root.display());
            assert!(
                root.ends_with("zed-package-checker/db"),
                "{}",
                root.display()
            );
        }

        #[test]
        fn details_are_read_back_from_the_archive() {
            let root = tempfile::tempdir().unwrap();
            let db = Database::new(root.path());
            let archive = db.archive_path(Ecosystem::Npm);
            fs::create_dir_all(archive.parent().unwrap()).unwrap();
            fs::write(
                &archive,
                fake_archive(&[(
                    "GHSA-1.json",
                    r#"{"id":"GHSA-1","details":"the full prose description","affected":[]}"#,
                )]),
            )
            .unwrap();

            assert_eq!(
                db.details(Ecosystem::Npm, "GHSA-1").unwrap(),
                "the full prose description"
            );
            assert!(db.details(Ecosystem::Npm, "GHSA-absent").is_err());
        }
    }
}
