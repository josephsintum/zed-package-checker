//! Zed extension shim for the package-checker language server.
//!
//! Zed extensions compile to WebAssembly and cannot publish diagnostics
//! themselves — only a language server can. So this shim does one job: make sure
//! the `package-checker-lsp` binary is present, and tell Zed how to launch it.

use std::fs;
use std::io::Read;

use sha2::{Digest, Sha256};
use zed_extension_api::{
    self as zed, settings::LspSettings, Architecture, Command, DownloadedFileType,
    LanguageServerId, LanguageServerInstallationStatus, Os, Result,
};

/// Name of the language server executable.
const BINARY_NAME: &str = "package-checker-lsp";

/// Server id as declared in `extension.toml`. Zed keys LSP settings by this,
/// not by the executable name, so the two must not be conflated.
const SERVER_ID: &str = "package-checker";

/// The comparison server, declared alongside the first so both can run at once.
///
/// It installs nothing: pointing it at a binary is the only way to start it,
/// which keeps it inert for anyone who has not asked for it.
const COMPARISON_SERVER_ID: &str = "package-checker-go";

/// Where releases are published.
const REPO: &str = "josephsintum/zed-package-checker";

/// The server release this extension installs.
///
/// Pinned rather than "latest": an extension and the server it drives are
/// released together, and a shim that silently picks up a newer server is a
/// shim that can be broken by a release nobody tested it against.
const SERVER_VERSION: &str = "v0.0.1";

/// The checksum file published alongside the binaries.
const SUMS_NAME: &str = "SHA256SUMS";

struct PackageCheckerExtension;

impl zed::Extension for PackageCheckerExtension {
    fn new() -> Self {
        Self
    }

    /// Hands the server whatever the user put under
    /// `lsp.package-checker.initialization_options`.
    ///
    /// Without this the server's settings are unreachable from Zed: it reads
    /// them from `initializationOptions` and nothing else forwards them.
    fn language_server_initialization_options(
        &mut self,
        _language_server_id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<Option<serde_json::Value>> {
        Ok(LspSettings::for_worktree(SERVER_ID, worktree)
            .ok()
            .and_then(|settings| settings.initialization_options))
    }

    fn language_server_command(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<Command> {
        let id = language_server_id.as_ref();

        // Two servers can run side by side, and the diagnostics panel tells
        // them apart by the `source` field rather than by the server's name —
        // so each is told what to call itself.
        let mut args = vec!["--stdio".to_owned()];
        let path = if id == COMPARISON_SERVER_ID {
            args.push("--label".to_owned());
            args.push(COMPARISON_SERVER_ID.to_owned());
            // Never downloaded, and never resolved from PATH: an older copy
            // installed there would produce differences that look like a real
            // disagreement between the two servers and are not.
            configured_binary(COMPARISON_SERVER_ID, worktree)
                .or_else(|| worktree.which("package-checker-go"))
                .ok_or_else(|| {
                    format!(
                        "The comparison server has no binary. It is development \
                     scaffolding: build it with `make server` and either put \
                     `package-checker-go` on your PATH or name it here:\n\n  \
                     \"lsp\": {{ \"{COMPARISON_SERVER_ID}\": {{ \"binary\": \
                     {{ \"path\": \"/abs/path/to/{GO_BUILD}\" }} }} }}\n\n\
                     Deleting that settings block silences this."
                    )
                })?
        } else {
            resolve_binary(language_server_id, worktree)?
        };

        Ok(Command {
            command: path,
            args,
            // The server may shell out to language toolchains (`go` for
            // reachability analysis). A GUI-launched Zed has a minimal PATH, so
            // hand it the user's real shell environment.
            env: worktree.shell_env(),
        })
    }
}

/// Finds the language server binary, downloading a release if needed.
///
/// Resolution order, most specific first:
///   1. `binary.path` in the user's LSP settings — the development override.
///   2. `$PATH`, for anyone who installed it deliberately.
///   3. A verified download from this repository's releases.
fn resolve_binary(
    language_server_id: &LanguageServerId,
    worktree: &zed::Worktree,
) -> Result<String> {
    if let Some(path) = configured_binary(SERVER_ID, worktree) {
        return Ok(path);
    }

    if let Some(path) = worktree.which(BINARY_NAME) {
        return Ok(path);
    }

    install(language_server_id).inspect_err(|err| {
        zed::set_language_server_installation_status(
            language_server_id,
            &LanguageServerInstallationStatus::Failed(err.clone()),
        );
    })
}

/// The binary a user pointed this server at, if any.
fn configured_binary(server_id: &str, worktree: &zed::Worktree) -> Option<String> {
    LspSettings::for_worktree(server_id, worktree)
        .ok()?
        .binary?
        .path
}

/// Where the Go server lands when built from source, for the error message.
///
/// Deliberately *not* resolved by looking inside the worktree: a language
/// server runs whatever folder the user opens, so executing a file found at a
/// fixed path within it would let any cloned repository ship a binary and have
/// it run on open. The path has to come from the user's own settings or their
/// PATH, never from the project being inspected.
const GO_BUILD: &str = "server/dist/package-checker-lsp";

/// Downloads the pinned release for this platform, unless it is already here.
fn install(language_server_id: &LanguageServerId) -> Result<String> {
    let binary = asset_stem();
    let directory = SERVER_VERSION;
    let binary_path = format!("{directory}/{binary}");

    // An existing download is trusted: it was verified when it was installed,
    // and re-hashing 46 MB on every editor start would be paid by everyone to
    // catch something that does not happen.
    if fs::metadata(&binary_path).is_ok_and(|meta| meta.is_file()) {
        return Ok(binary_path);
    }

    zed::set_language_server_installation_status(
        language_server_id,
        &LanguageServerInstallationStatus::CheckingForUpdate,
    );

    let release = zed::github_release_by_tag_name(REPO, SERVER_VERSION).map_err(|err| {
        format!(
            "could not reach GitHub to download {BINARY_NAME} {SERVER_VERSION}: {err}\n\
             Build it yourself with `make server` and point at it in your settings:\n\
             \"lsp\": {{ \"{SERVER_ID}\": {{ \"binary\": {{ \"path\": \"/abs/path/to/{BINARY_NAME}\" }} }} }}"
        )
    })?;

    let archive = asset_url(&release, &format!("{binary}.gz"))?;
    let sums = asset_url(&release, SUMS_NAME)?;

    zed::set_language_server_installation_status(
        language_server_id,
        &LanguageServerInstallationStatus::Downloading,
    );

    let sums_path = format!("{directory}/{SUMS_NAME}");
    zed::download_file(&sums, &sums_path, DownloadedFileType::Uncompressed)?;
    zed::download_file(&archive, &binary_path, DownloadedFileType::Gzip)?;

    verify(&binary_path, &sums_path, &binary)?;
    zed::make_file_executable(&binary_path)?;
    remove_other_versions(directory);

    Ok(binary_path)
}

/// Checks the downloaded binary against the published checksum, deleting it if
/// they disagree.
///
/// The binary is removed on mismatch rather than left in place, because a file
/// that stays becomes the "already installed" answer on the next launch and
/// would never be checked again.
fn verify(binary_path: &str, sums_path: &str, name: &str) -> Result<()> {
    let published = published_sum(sums_path, name)?;
    let actual = sha256(binary_path)?;

    if actual != published {
        let _ = fs::remove_file(binary_path);
        return Err(format!(
            "{name} does not match its published checksum and was discarded\n\
             expected {published}\n\
             got      {actual}"
        ));
    }
    Ok(())
}

/// Reads one entry out of a `shasum`-format file.
///
/// Each line is `<hex>  <name>`. The names are of the uncompressed binaries,
/// which is what there is to hash once download_file has decompressed.
fn published_sum(sums_path: &str, name: &str) -> Result<String> {
    let contents = fs::read_to_string(sums_path)
        .map_err(|err| format!("could not read {SUMS_NAME}: {err}"))?;

    contents
        .lines()
        .find_map(|line| {
            let (sum, entry) = line.split_once("  ")?;
            (entry.trim() == name).then(|| sum.trim().to_string())
        })
        .ok_or_else(|| format!("{SUMS_NAME} has no entry for {name}"))
}

/// Hashes a file in chunks, so a 46 MB binary is never held in memory at once.
fn sha256(path: &str) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|err| format!("could not open {path}: {err}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| format!("could not read {path}: {err}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
            out
        }))
}

/// Finds an asset's download URL by exact name.
fn asset_url(release: &zed::GithubRelease, name: &str) -> Result<String> {
    release
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .map(|asset| asset.download_url.clone())
        .ok_or_else(|| format!("release {SERVER_VERSION} has no asset named {name}"))
}

/// The binary's name for this platform, matching what the release publishes.
fn asset_stem() -> String {
    let (os, arch) = zed::current_platform();
    let os_name = match os {
        Os::Mac => "darwin",
        Os::Linux => "linux",
        Os::Windows => "windows",
    };
    let arch_name = match arch {
        Architecture::Aarch64 => "arm64",
        Architecture::X8664 => "amd64",
        Architecture::X86 => "386",
    };
    let suffix = if matches!(os, Os::Windows) {
        ".exe"
    } else {
        ""
    };
    format!("{BINARY_NAME}-{os_name}-{arch_name}{suffix}")
}

/// Deletes downloads for every version but the current one.
///
/// Best-effort: leaving an old binary behind wastes disk, which is not worth
/// failing a working install over.
fn remove_other_versions(keep: &str) {
    let Ok(entries) = fs::read_dir(".") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name != keep && name.to_string_lossy().starts_with('v') {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

zed::register_extension!(PackageCheckerExtension);

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(name: &str, contents: &[u8]) -> String {
        let path = std::env::temp_dir().join(format!("pkgchk-{name}"));
        let mut file = fs::File::create(&path).expect("create temp file");
        file.write_all(contents).expect("write temp file");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn sha256_matches_the_known_digest_of_empty_input() {
        let path = write_temp("empty", b"");
        assert_eq!(
            sha256(&path).expect("hash"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_spans_more_than_one_read_buffer() {
        // The hash is computed in 64 KiB chunks; a payload larger than one
        // chunk is what proves the loop accumulates rather than overwrites.
        let payload = vec![b'x'; 200 * 1024];
        let path = write_temp("large", &payload);

        let mut expected = Sha256::new();
        expected.update(&payload);
        let expected = expected
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        assert_eq!(sha256(&path).expect("hash"), expected);
    }

    #[test]
    fn published_sum_reads_the_named_entry() {
        let path = write_temp(
            "sums",
            b"aaaa  package-checker-lsp-linux-amd64\nbbbb  package-checker-lsp-darwin-arm64\n",
        );
        assert_eq!(
            published_sum(&path, "package-checker-lsp-darwin-arm64").expect("entry"),
            "bbbb"
        );
    }

    #[test]
    fn published_sum_rejects_a_name_it_does_not_list() {
        let path = write_temp("sums-missing", b"aaaa  package-checker-lsp-linux-amd64\n");
        assert!(published_sum(&path, "package-checker-lsp-darwin-arm64").is_err());
    }

    #[test]
    fn verify_accepts_a_binary_that_matches() {
        let binary = write_temp("good-binary", b"pretend this is a language server");
        let digest = sha256(&binary).expect("hash");
        let sums = write_temp("good-sums", format!("{digest}  thebinary\n").as_bytes());

        assert!(verify(&binary, &sums, "thebinary").is_ok());
        assert!(fs::metadata(&binary).is_ok(), "a good binary must survive");
    }

    #[test]
    fn verify_rejects_a_tampered_binary_and_deletes_it() {
        // One byte changed: the gate this whole mechanism exists for.
        let original = b"pretend this is a language server";
        let digest = sha256(&write_temp("tamper-src", original)).expect("hash");

        let mut tampered = original.to_vec();
        tampered[0] = b'P';
        let binary = write_temp("tampered-binary", &tampered);
        let sums = write_temp("tamper-sums", format!("{digest}  thebinary\n").as_bytes());

        assert!(verify(&binary, &sums, "thebinary").is_err());
        assert!(
            fs::metadata(&binary).is_err(),
            "a binary that fails verification must not be left behind to be trusted next launch"
        );
    }
}
