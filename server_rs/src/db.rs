//! The on-disk copy of the OSV database: where it lives, how it is refreshed,
//! and how two editor windows share it without corrupting it.
//!
//! Archives are read by `crate::load`; this module is only responsible for
//! there being a correct archive to read.

use crate::model::Ecosystem;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// Serves the OSV database, one zip per ecosystem.
const ARCHIVE_HOST: &str = "https://osv-vulnerabilities.storage.googleapis.com";
const ARCHIVE_NAME: &str = "all.zip";

/// Matches the layout osv-scanner uses, so the same cache can be pointed at
/// osv-scanner — or at the Go server — when differential-testing.
const VENDOR_DIR: &str = "osv-scalibr";

/// How long a downloaded archive is trusted before it is checked again.
/// Advisories are published continuously, but a day-old database is a
/// reasonable trade against waking the network on every editor start.
const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Bounds how long we wait for another process already refreshing an ecosystem.
/// Generous enough for npm's 215 MB on a slow link, short enough that a dead
/// peer does not hang a scan forever.
const PEER_WAIT: Duration = Duration::from_secs(15 * 60);

const PROGRESS_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("advisory database not ready: {0}")]
    NotReady(String),
    #[error("{context}: {source}")]
    Io { context: String, source: io::Error },
    #[error("fetch {url}: {message}")]
    Fetch { url: String, message: String },
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
    fn advance(&self, ecosystem: Ecosystem, downloaded: u64, total: Option<u64>);
    fn done(&self, ecosystem: Ecosystem, error: Option<&str>);
}

/// The advisory cache.
pub struct Database {
    root: PathBuf,
    agent: ureq::Agent,
    ttl: Duration,
    progress: Option<Box<dyn Progress>>,
    /// Overridable so staleness can be tested without sleeping.
    now: Box<dyn Fn() -> SystemTime + Send + Sync>,
}

impl Database {
    pub fn new(root: impl Into<PathBuf>) -> Database {
        let config = ureq::Agent::config_builder()
            // npm's archive is 215 MB.
            .timeout_global(Some(Duration::from_secs(600)))
            // A 304 is the good case, not an error.
            .http_status_as_error(false)
            .build();
        Database {
            root: root.into(),
            agent: config.into(),
            ttl: DEFAULT_TTL,
            progress: None,
            now: Box::new(SystemTime::now),
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_progress(mut self, progress: Box<dyn Progress>) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Overrides the clock, so staleness can be exercised without sleeping.
    pub fn with_clock(mut self, now: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.now = Box::new(now);
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn dir_for(&self, ecosystem: Ecosystem) -> PathBuf {
        self.root.join(VENDOR_DIR).join(ecosystem.as_str())
    }

    pub fn archive_path(&self, ecosystem: Ecosystem) -> PathBuf {
        self.dir_for(ecosystem).join(ARCHIVE_NAME)
    }

    /// The freshness sidecar.
    ///
    /// Deliberately *not* the name the Go server uses. The archive itself is
    /// worth sharing — it is the 215 MB — but sharing the metadata would mean
    /// each server invalidating the other's record of when it last checked, and
    /// both re-downloading. Separate sidecars, one shared archive.
    fn meta_path(&self, ecosystem: Ecosystem) -> PathBuf {
        self.dir_for(ecosystem).join(format!("{ARCHIVE_NAME}.rsmeta"))
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

    /// The archives for the named ecosystems, ready to be handed to `load`.
    pub fn archives(&self, ecosystems: &[Ecosystem]) -> Vec<(Ecosystem, PathBuf)> {
        ecosystems.iter().map(|&e| (e, self.archive_path(e))).collect()
    }

    /// Downloads or revalidates every named ecosystem.
    pub fn ensure(&self, ecosystems: &[Ecosystem]) -> Result<(), DbError> {
        let mut failures = Vec::new();
        for &ecosystem in ecosystems {
            if let Err(err) = self.ensure_one(ecosystem) {
                failures.push(format!("{ecosystem}: {err}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(DbError::NotReady(failures.join("; ")))
        }
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
        let lock = File::create(&lock_path)
            .map_err(io_err(format!("open {}", lock_path.display())))?;

        // std gained advisory file locking in 1.89, so the `gofrs/flock`
        // equivalent the Go server needs is simply not a dependency here.
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
        if !archive.exists() || validate_zip(&archive).is_ok() {
            return;
        }
        tracing::warn!(%ecosystem, path = %archive.display(), "discarding unreadable advisory archive");
        let _ = fs::remove_file(&archive);
        let _ = fs::remove_file(self.meta_path(ecosystem));
    }

    fn fetch(&self, ecosystem: Ecosystem) -> Result<(), DbError> {
        let url = archive_url(ecosystem);
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
                Ok(())
            },
            |tmp| verify_archive(tmp, want_crc),
        );

        if let Some(progress) = &self.progress {
            progress.done(ecosystem, result.as_ref().err().map(|e| e.to_string()).as_deref());
        }
        result?;

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
        entry.read_to_end(&mut bytes).map_err(io_err("read advisory"))?;

        #[derive(Deserialize)]
        struct Details {
            #[serde(default)]
            details: String,
        }
        serde_json::from_slice::<Details>(&bytes)
            .map(|d| d.details)
            .map_err(|e| DbError::NotReady(format!("decode {advisory_id}: {e}")))
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

fn archive_url(ecosystem: Ecosystem) -> String {
    // Ecosystem names are used verbatim, including case and the dot in
    // "crates.io"; normalising them produces 404s.
    format!("{ARCHIVE_HOST}/{}/{ARCHIVE_NAME}", ecosystem.as_str())
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
        let bytes = fs::read(path).map_err(io_err("read downloaded archive"))?;
        let got = crc32c::crc32c(&bytes);
        if got != want {
            return Err(DbError::Fetch {
                url: path.display().to_string(),
                message: format!("checksum mismatch: got {got:08x}, want {want:08x}"),
            });
        }
    }
    validate_zip(path)
}

fn validate_zip(path: &Path) -> Result<(), DbError> {
    let file = File::open(path).map_err(io_err(format!("open {}", path.display())))?;
    let archive = zip::ZipArchive::new(io::BufReader::new(file))
        .map_err(|e| DbError::NotReady(format!("{}: not a readable zip: {e}", path.display())))?;
    if archive.is_empty() {
        return Err(DbError::NotReady(format!("{}: zip archive is empty", path.display())));
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
        file.sync_all().map_err(io_err(format!("sync {}", tmp.display())))?;
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
            Err(e) => return Err(DbError::Io { context: format!("rename to {}", to.display()), source: e }),
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
