// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use cpoe::config::CpopConfig;
use cpoe::vdf::params::Parameters as VdfParameters;
use cpoe::{derive_hmac_key, SecureStore};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// 500 MB — maximum allowed file size.
pub(crate) const MAX_FILE_SIZE: u64 = 500_000_000;

/// 50 MB — warning threshold for large files.
pub(crate) const LARGE_FILE_WARNING_THRESHOLD: u64 = 50_000_000;

/// File extensions excluded from tracking.
pub(crate) const BLOCKED_EXTENSIONS: &[&str] = &[
    "exe", "dll", "so", "dylib", "o", "a", "obj", "lib", "class", "pyc", "pyo", "wasm", "zip",
    "tar", "gz", "tgz", "bz2", "xz", "zst", "rar", "7z", "dmg", "iso", "jpg", "jpeg", "png", "gif",
    "bmp", "ico", "tiff", "tif", "webp", "heic", "heif", "raw", "svg", "mp3", "mp4", "avi", "mov",
    "wav", "webm", "flac", "aac", "ogg", "mkv", "wmv", "pdf", "db", "sqlite", "sqlite3", "mdb",
    "lock", "tmp", "bak", "swp", "swo", "DS_Store",
];

pub fn writersproof_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("CPOE_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home.join(".writersproof"))
}

pub fn ensure_dirs() -> Result<CpopConfig> {
    let dir = writersproof_dir()?;
    let config = CpopConfig::load_or_default(&dir)?;

    let dirs = [
        config.data_dir.clone(),
        config.data_dir.join("chains"),
        config.data_dir.join("sessions"),
        config.data_dir.join("tracking"),
        config.data_dir.join("sentinel"),
        config.data_dir.join("sentinel").join("wal"),
    ];

    for d in &dirs {
        fs::create_dir_all(d).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                anyhow!("Permission denied creating directory: {}", d.display())
            } else {
                anyhow!("mkdir {}: {}", d.display(), e)
            }
        })?;

        cpoe::restrict_permissions(d, 0o700)
            .map_err(|e| anyhow!("chmod {}: {}", d.display(), e))?;
    }

    Ok(config)
}

pub fn load_vdf_params(config: &CpopConfig) -> VdfParameters {
    VdfParameters {
        iterations_per_second: config.vdf.iterations_per_second,
        min_iterations: config.vdf.min_iterations,
        max_iterations: config.vdf.max_iterations,
    }
}

pub fn load_signing_key(dir: &Path) -> Result<SigningKey> {
    let key_path = dir.join("signing_key");
    let mut key_data = fs::read(&key_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => anyhow!("CPoE not initialized. Run 'cpoe init'."),
        std::io::ErrorKind::PermissionDenied => {
            anyhow!("Permission denied: {}", key_path.display())
        }
        _ => anyhow!("read signing key: {}", e),
    })?;
    let mut seed: [u8; 32] = if key_data.len() == 32 {
        let arr: [u8; 32] = key_data[..32]
            .try_into()
            .map_err(|_| anyhow!("Invalid signing key"))?;
        key_data.zeroize();
        arr
    } else if key_data.len() == 64 {
        let s: [u8; 32] = key_data[..32]
            .try_into()
            .map_err(|_| anyhow!("Invalid signing key"))?;
        key_data.zeroize();
        s
    } else {
        let actual_len = key_data.len();
        key_data.zeroize();
        return Err(anyhow!(
            "Invalid signing key: expected 32 or 64 bytes, got {}",
            actual_len
        ));
    };
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

pub fn open_secure_store() -> Result<SecureStore> {
    let config = ensure_dirs()?;
    let dir = config.data_dir;
    let db_path = dir.join("events.db");

    if let Ok(Some(hmac_key)) = cpoe::identity::SecureStorage::load_hmac_key() {
        return SecureStore::open(&db_path, hmac_key).map_err(|e| anyhow!("Database error: {}", e));
    }

    let signing_key = load_signing_key(&dir)?;
    let hmac_key = derive_hmac_key(&signing_key.to_bytes());

    if let Err(e) = cpoe::identity::SecureStorage::save_hmac_key(&hmac_key) {
        eprintln!("Warning: HMAC key migration: {}", e);
    }

    SecureStore::open(&db_path, hmac_key).map_err(|e| anyhow!("Database error: {}", e))
}

pub fn get_device_id() -> Result<[u8; 16]> {
    let dir = writersproof_dir()?;
    let key_path = dir.join("signing_key.pub");
    let pub_key = fs::read(&key_path)
        .map_err(|e| anyhow::anyhow!("Cannot read signing_key.pub (run `cpoe init` first): {e}"))?;
    let h = Sha256::digest(&pub_key);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    Ok(id)
}

pub fn validate_session_id(id: &str) -> Result<&str> {
    if id.is_empty() {
        anyhow::bail!("Session ID cannot be empty");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!(
            "Session ID contains invalid characters \
             (only alphanumeric, hyphens, and underscores allowed)"
        );
    }
    Ok(id)
}

pub fn get_machine_id() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn load_did(dir: &Path) -> Result<String> {
    let identity_path = dir.join("identity.json");
    let data = fs::read_to_string(&identity_path)
        .map_err(|_| anyhow!("No identity found. Run 'cpoe identity' to create one."))?;
    let identity: serde_json::Value = serde_json::from_str(&data)?;
    identity
        .get("did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Identity file missing 'did' field"))
}

/// Encode an Ed25519 public key as a `did:key` identifier per the
/// [did:key Method Specification](https://w3c-ccg.github.io/did-key-spec/).
pub fn ed25519_pubkey_to_did_key(pubkey: &[u8]) -> String {
    cpoe::identity::did_key_from_public(pubkey)
        .unwrap_or_else(|| format!("did:key:invalid-{}", hex::encode(pubkey)))
}

pub fn write_restrictive(path: &Path, data: &[u8]) -> Result<()> {
    // Use engine's atomic_write (unpredictable temp name + fsync + rename),
    // then restrict permissions to owner-only.
    cpoe::crypto::atomic_write(path, data)
        .map_err(|e| anyhow!("write {}: {}", path.display(), e))?;
    cpoe::restrict_permissions(path, 0o600)
        .map_err(|e| anyhow!("chmod {}: {}", path.display(), e))?;
    Ok(())
}

/// WARNING: Does not resolve `..` for non-existent paths beyond lexical
/// cleaning. Callers must validate against directory traversal attacks.
pub fn normalize_path(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    let expanded = if path_str.starts_with("~/") || path_str == "~" {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
        if path_str == "~" {
            home
        } else {
            home.join(&path_str[2..])
        }
    } else {
        path.to_path_buf()
    };

    let cleaned = clean_path(&expanded);

    match fs::canonicalize(&cleaned) {
        Ok(canonical) => {
            #[cfg(target_os = "windows")]
            {
                let s = canonical.to_string_lossy();
                if let Some(stripped) = s.strip_prefix(r"\\?\") {
                    return Ok(PathBuf::from(stripped));
                }
            }
            Ok(canonical)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(cleaned),
        Err(e) => Err(anyhow!("Cannot access path {}: {}", cleaned.display(), e)),
    }
}

fn clean_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                if !cleaned.pop() {
                    cleaned.push(component);
                }
            }
            Component::CurDir => {}
            _ => cleaned.push(component),
        }
    }
    cleaned
}

/// Maximum retries for SQLite BUSY errors.
const SQLITE_BUSY_MAX_RETRIES: u32 = 5;

/// Base delay in milliseconds for SQLite BUSY retry backoff.
const SQLITE_BUSY_BASE_DELAY_MS: u64 = 100;

/// Retry a fallible operation with exponential backoff when SQLite is busy.
///
/// Retries up to [`SQLITE_BUSY_MAX_RETRIES`] times with exponential backoff
/// starting at [`SQLITE_BUSY_BASE_DELAY_MS`] when the error message indicates
/// a locked database.
pub(crate) fn retry_on_busy<T, F: FnMut() -> Result<T>>(mut op: F) -> Result<T> {
    let mut last_err = None;
    for attempt in 0..SQLITE_BUSY_MAX_RETRIES {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let msg = e.to_string();
                if (msg.contains("database is locked") || msg.contains("SQLITE_BUSY"))
                    && attempt < SQLITE_BUSY_MAX_RETRIES - 1
                {
                    let delay_ms = SQLITE_BUSY_BASE_DELAY_MS * (1 << attempt);
                    if delay_ms > 500 {
                        eprintln!(
                            "Warning: SQLite busy, backing off for {}ms before retry {}/{}",
                            delay_ms,
                            attempt + 1,
                            SQLITE_BUSY_MAX_RETRIES
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    last_err = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last_err
        .unwrap_or_else(|| anyhow::anyhow!("retry_on_busy: no attempts made (MAX_RETRIES=0)")))
}

pub fn load_api_key(dir: &Path) -> Result<String> {
    let key_path = dir.join("api_key");
    fs::read_to_string(&key_path)
        .map(|s| s.trim().to_string())
        .map_err(|_| anyhow!("No WritersProof API key found at: {}", key_path.display()))
}

/// Parse user input as a yes/no response.
///
/// Trims whitespace and converts to lowercase, then matches against yes/no words.
/// Returns `Some(true)` for "y" or "yes", `Some(false)` for "n" or "no",
/// and `None` for anything else.
pub fn parse_yes_no(input: &str) -> Option<bool> {
    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => Some(true),
        "n" | "no" => Some(false),
        _ => None,
    }
}

/// Convert a path to a String for FFI calls.
pub(crate) fn path_str(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

/// Check an FFI result with `success` and `error_message` fields.
pub(crate) fn check_ffi_result(success: bool, error_message: &Option<String>) -> Result<()> {
    if success {
        Ok(())
    } else {
        Err(anyhow!(
            "{}",
            error_message.as_deref().unwrap_or("Unknown error")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // --- validate_session_id ---

    #[test]
    fn test_validate_session_id_alphanumeric_accepted() {
        let result = validate_session_id("abc123");
        assert!(result.is_ok(), "alphanumeric session ID should be valid");
        assert_eq!(
            result.unwrap(),
            "abc123",
            "validated ID should be returned unchanged"
        );
    }

    #[test]
    fn test_validate_session_id_with_hyphens_and_underscores() {
        assert!(
            validate_session_id("my-session_01").is_ok(),
            "hyphens and underscores should be allowed in session IDs"
        );
    }

    #[test]
    fn test_validate_session_id_empty_rejected() {
        let result = validate_session_id("");
        assert!(result.is_err(), "empty session ID should be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("empty"),
            "error should mention 'empty', got: {err_msg}"
        );
    }

    #[test]
    fn test_validate_session_id_special_chars_rejected() {
        let result = validate_session_id("session@#!");
        assert!(
            result.is_err(),
            "special characters should be rejected in session IDs"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid characters"),
            "error should mention invalid characters, got: {err_msg}"
        );
    }

    #[test]
    fn test_validate_session_id_spaces_rejected() {
        assert!(
            validate_session_id("my session").is_err(),
            "spaces should be rejected in session IDs"
        );
    }

    #[test]
    fn test_validate_session_id_unicode_rejected() {
        assert!(
            validate_session_id("会话id").is_err(),
            "Unicode characters should be rejected in session IDs"
        );
    }

    #[test]
    fn test_validate_session_id_path_traversal_rejected() {
        assert!(
            validate_session_id("../etc/passwd").is_err(),
            "path traversal characters (dots, slashes) should be rejected"
        );
    }

    // --- ed25519_pubkey_to_did_key ---

    #[test]
    fn test_ed25519_pubkey_to_did_key_format() {
        let pubkey = [0u8; 32]; // zero key (valid format, not secure)
        let did = ed25519_pubkey_to_did_key(&pubkey);
        assert!(
            did.starts_with("did:key:z"),
            "DID should start with 'did:key:z', got: {did}"
        );
    }

    #[test]
    fn test_ed25519_pubkey_to_did_key_deterministic() {
        let pubkey = [42u8; 32];
        let did1 = ed25519_pubkey_to_did_key(&pubkey);
        let did2 = ed25519_pubkey_to_did_key(&pubkey);
        assert_eq!(did1, did2, "same public key should produce same DID");
    }

    #[test]
    fn test_ed25519_pubkey_to_did_key_different_keys_produce_different_dids() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let did_a = ed25519_pubkey_to_did_key(&key_a);
        let did_b = ed25519_pubkey_to_did_key(&key_b);
        assert_ne!(
            did_a, did_b,
            "different public keys must produce different DIDs"
        );
    }

    #[test]
    fn test_ed25519_pubkey_to_did_key_contains_multicodec_prefix() {
        let pubkey = [0xABu8; 32];
        let did = ed25519_pubkey_to_did_key(&pubkey);
        // Decode the base58btc part (after "did:key:z")
        let encoded = &did["did:key:z".len()..];
        let decoded = bs58::decode(encoded).into_vec().expect("valid base58btc");
        assert_eq!(
            decoded[0], 0xed,
            "first byte of decoded DID should be 0xed (Ed25519 multicodec)"
        );
        assert_eq!(
            decoded[1], 0x01,
            "second byte of decoded DID should be 0x01 (multicodec varint)"
        );
        assert_eq!(
            &decoded[2..],
            &pubkey,
            "remaining bytes should be the raw public key"
        );
    }

    // --- normalize_path ---

    #[test]
    fn test_normalize_path_absolute_existing_path_resolved() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();
        let result =
            normalize_path(&file_path).expect("normalize should succeed for existing file");
        // canonicalize resolves symlinks, so compare canonical forms
        let expected = fs::canonicalize(&file_path).unwrap();
        assert_eq!(result, expected, "existing path should be canonicalized");
    }

    #[test]
    fn test_normalize_path_nonexistent_path_cleaned() {
        let result = normalize_path(Path::new("/tmp/nonexistent_cpop_test_dir/foo.txt"))
            .expect("normalize should succeed for nonexistent path");
        assert_eq!(
            result,
            PathBuf::from("/tmp/nonexistent_cpop_test_dir/foo.txt"),
            "nonexistent path should be returned cleaned but not canonicalized"
        );
    }

    #[test]
    fn test_normalize_path_dotdot_on_existing_path_resolved() {
        // .. is only resolved when the path exists (via canonicalize)
        let tmp = tempfile::tempdir().unwrap();
        let subdir = tmp.path().join("a").join("b");
        fs::create_dir_all(&subdir).unwrap();
        let file = subdir.join("test.txt");
        fs::write(&file, "x").unwrap();

        // Access via ../b/test.txt from inside a/
        let dotdot_path = tmp
            .path()
            .join("a")
            .join("b")
            .join("..")
            .join("b")
            .join("test.txt");
        let result =
            normalize_path(&dotdot_path).expect("normalize should resolve .. on existing paths");
        assert!(
            !result.to_string_lossy().contains(".."),
            "dotdot should be resolved for existing paths, got: {}",
            result.display()
        );
    }

    #[test]
    fn test_normalize_path_dotdot_on_nonexistent_resolved() {
        // clean_path now resolves .. lexically even for nonexistent paths (L-003)
        let result = normalize_path(Path::new("/tmp/nonexistent_xyz/a/../b"))
            .expect("normalize should handle nonexistent paths with ..");
        assert_eq!(
            result,
            PathBuf::from("/tmp/nonexistent_xyz/b"),
            "nonexistent paths should resolve .. lexically"
        );
    }

    #[test]
    fn test_normalize_path_unicode_in_path_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let unicode_path = tmp.path().join("写作_2026.txt");
        fs::write(&unicode_path, "content").unwrap();
        let result =
            normalize_path(&unicode_path).expect("normalize should handle Unicode filenames");
        // Verify the filename is preserved
        let filename = result
            .file_name()
            .unwrap()
            .to_str()
            .expect("filename should be valid UTF-8");
        assert_eq!(
            filename, "写作_2026.txt",
            "Unicode filename should round-trip without byte loss"
        );
    }

    #[test]
    fn test_normalize_path_spaces_in_path_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        let spaced_path = tmp.path().join("my novel chapter 01.txt");
        fs::write(&spaced_path, "content").unwrap();
        let result = normalize_path(&spaced_path).expect("normalize should handle spaces in paths");
        let filename = result.file_name().unwrap().to_str().unwrap();
        assert_eq!(
            filename, "my novel chapter 01.txt",
            "spaces in filename should be preserved"
        );
    }

    #[test]
    fn test_normalize_path_emoji_in_filename() {
        let tmp = tempfile::tempdir().unwrap();
        let emoji_path = tmp.path().join("📝draft.txt");
        fs::write(&emoji_path, "content").unwrap();
        let result = normalize_path(&emoji_path).expect("normalize should handle emoji filenames");
        let filename = result.file_name().unwrap().to_str().unwrap();
        assert_eq!(
            filename, "📝draft.txt",
            "emoji in filename should be preserved"
        );
    }

    // --- write_restrictive ---

    #[test]
    fn test_write_restrictive_creates_file_with_correct_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secret.key");
        write_restrictive(&path, b"secret data").expect("write_restrictive should succeed");

        let metadata = fs::metadata(&path).expect("file should exist");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file should have mode 0o600, got: {mode:o}");

        let content = fs::read(&path).unwrap();
        assert_eq!(
            content, b"secret data",
            "file content should match written data"
        );
    }

    #[test]
    fn test_write_restrictive_not_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("private.key");
        write_restrictive(&path, b"data").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o044,
            0,
            "file should not be world-readable or group-readable, mode: {mode:o}"
        );
        assert_eq!(
            mode & 0o022,
            0,
            "file should not be world-writable or group-writable, mode: {mode:o}"
        );
    }

    #[test]
    fn test_write_restrictive_overwrites_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("overwrite.key");
        write_restrictive(&path, b"original").unwrap();
        write_restrictive(&path, b"replaced").unwrap();

        let content = fs::read(&path).unwrap();
        assert_eq!(
            content, b"replaced",
            "overwrite should replace content, not append"
        );
    }

    #[test]
    fn test_write_restrictive_fails_if_parent_missing() {
        let path = Path::new("/tmp/nonexistent_cpop_parent_dir_xyz/file.key");
        let result = write_restrictive(path, b"data");
        assert!(result.is_err(), "write to nonexistent parent should fail");
    }

    #[test]
    fn test_write_restrictive_no_temp_file_on_failure() {
        let path = Path::new("/tmp/nonexistent_cpop_parent_dir_xyz/file.key");
        let _ = write_restrictive(path, b"data");
        let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));
        assert!(
            !tmp_path.exists(),
            "temp file should be cleaned up on failure"
        );
    }

    #[test]
    fn test_write_restrictive_atomic_no_partial_visible() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("atomic.key");
        // Write initial content
        write_restrictive(&path, b"complete").unwrap();
        // The file should always contain complete data, never partial
        let content = fs::read(&path).unwrap();
        assert_eq!(content, b"complete", "file should contain complete data");
    }

    // --- retry_on_busy ---

    #[test]
    fn test_retry_on_busy_succeeds_on_first_attempt() {
        let mut call_count = 0u32;
        let result = retry_on_busy(|| {
            call_count += 1;
            Ok(42)
        });
        assert_eq!(result.unwrap(), 42, "should return the closure's value");
        assert_eq!(
            call_count, 1,
            "closure should be called exactly once on success"
        );
    }

    #[test]
    fn test_retry_on_busy_non_busy_error_not_retried() {
        let mut call_count = 0u32;
        let result: Result<()> = retry_on_busy(|| {
            call_count += 1;
            Err(anyhow!("permission denied"))
        });
        assert!(result.is_err(), "non-busy error should propagate");
        assert_eq!(call_count, 1, "non-busy errors should not trigger retries");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("permission denied"),
            "original error message should be preserved"
        );
    }

    #[test]
    fn test_retry_on_busy_retries_on_locked_database() {
        let mut call_count = 0u32;
        let result = retry_on_busy(|| {
            call_count += 1;
            if call_count < 3 {
                Err(anyhow!("database is locked"))
            } else {
                Ok("success")
            }
        });
        assert_eq!(result.unwrap(), "success", "should succeed after retries");
        assert_eq!(call_count, 3, "should retry until success (3 attempts)");
    }

    #[test]
    fn test_retry_on_busy_retries_on_sqlite_busy() {
        let mut call_count = 0u32;
        let result = retry_on_busy(|| {
            call_count += 1;
            if call_count < 2 {
                Err(anyhow!("SQLITE_BUSY"))
            } else {
                Ok(99)
            }
        });
        assert_eq!(
            result.unwrap(),
            99,
            "should succeed after SQLITE_BUSY retry"
        );
        assert_eq!(call_count, 2, "should retry once on SQLITE_BUSY");
    }

    #[test]
    fn test_retry_on_busy_exhausts_retries_returns_last_error() {
        let mut call_count = 0u32;
        let result: Result<()> = retry_on_busy(|| {
            call_count += 1;
            Err(anyhow!("database is locked (attempt {})", call_count))
        });
        assert!(result.is_err(), "should fail after exhausting retries");
        assert_eq!(
            call_count, SQLITE_BUSY_MAX_RETRIES,
            "should attempt exactly MAX_RETRIES times"
        );
    }

    // --- load_signing_key ---

    #[test]
    fn test_load_signing_key_32_byte_seed() {
        let tmp = tempfile::tempdir().unwrap();
        let seed: [u8; 32] = [7u8; 32];
        fs::write(tmp.path().join("signing_key"), &seed).unwrap();
        let key = load_signing_key(tmp.path()).expect("32-byte key should load");
        assert_eq!(
            key.to_bytes(),
            seed,
            "loaded key bytes should match original seed"
        );
    }

    #[test]
    fn test_load_signing_key_64_byte_keypair() {
        let tmp = tempfile::tempdir().unwrap();
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(&[9u8; 32]);
        keypair[32..].copy_from_slice(&[0xAA; 32]); // public key half
        fs::write(tmp.path().join("signing_key"), &keypair).unwrap();
        let key = load_signing_key(tmp.path()).expect("64-byte keypair should load");
        assert_eq!(
            key.to_bytes(),
            [9u8; 32],
            "should extract first 32 bytes as seed"
        );
    }

    #[test]
    fn test_load_signing_key_wrong_size_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("signing_key"), &[1u8; 16]).unwrap();
        let result = load_signing_key(tmp.path());
        assert!(result.is_err(), "16-byte key should be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("expected 32 or 64 bytes"),
            "error should name expected sizes, got: {err_msg}"
        );
        assert!(
            err_msg.contains("16"),
            "error should name actual size, got: {err_msg}"
        );
    }

    #[test]
    fn test_load_signing_key_missing_file_mentions_init() {
        let tmp = tempfile::tempdir().unwrap();
        let result = load_signing_key(tmp.path());
        assert!(result.is_err(), "missing key should fail");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cpoe init"),
            "error should suggest running 'cpoe init', got: {err_msg}"
        );
    }

    // --- load_did ---

    #[test]
    fn test_load_did_valid_identity_json() {
        let tmp = tempfile::tempdir().unwrap();
        let identity = serde_json::json!({
            "did": "did:key:z6Mk...",
            "public_key": "abc123"
        });
        fs::write(
            tmp.path().join("identity.json"),
            serde_json::to_string(&identity).unwrap(),
        )
        .unwrap();
        let did = load_did(tmp.path()).expect("valid identity.json should load");
        assert_eq!(did, "did:key:z6Mk...", "should extract the 'did' field");
    }

    #[test]
    fn test_load_did_missing_did_field() {
        let tmp = tempfile::tempdir().unwrap();
        let identity = serde_json::json!({"public_key": "abc"});
        fs::write(
            tmp.path().join("identity.json"),
            serde_json::to_string(&identity).unwrap(),
        )
        .unwrap();
        let result = load_did(tmp.path());
        assert!(result.is_err(), "missing 'did' field should fail");
        assert!(
            result.unwrap_err().to_string().contains("did"),
            "error should mention the missing field"
        );
    }

    #[test]
    fn test_load_did_missing_file_mentions_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let result = load_did(tmp.path());
        assert!(result.is_err(), "missing identity.json should fail");
        assert!(
            result.unwrap_err().to_string().contains("cpoe identity"),
            "error should suggest running 'cpoe identity'"
        );
    }

    // --- load_api_key ---

    #[test]
    fn test_load_api_key_valid() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("api_key"), "  sk-test-12345  \n").unwrap();
        let key = load_api_key(tmp.path()).expect("valid api_key file should load");
        assert_eq!(key, "sk-test-12345", "api key should be trimmed");
    }

    #[test]
    fn test_load_api_key_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let result = load_api_key(tmp.path());
        assert!(result.is_err(), "missing api_key file should fail");
        assert!(
            result.unwrap_err().to_string().contains("api_key"),
            "error should mention the file path"
        );
    }

    // --- get_machine_id ---

    #[test]
    fn test_get_machine_id_returns_nonempty_string() {
        let id = get_machine_id();
        assert!(
            !id.is_empty(),
            "machine ID should not be empty (either hostname or 'unknown')"
        );
    }

    // --- writersproof_dir ---

    #[test]
    fn test_writersproof_dir_uses_cpop_data_dir_env() {
        // This test reads CPOE_DATA_DIR which other tests also set, but
        // each test runs in its own process for e2e; for unit tests this is
        // safe because we're reading, not writing.
        let original = std::env::var("CPOE_DATA_DIR").ok();
        std::env::set_var("CPOE_DATA_DIR", "/tmp/cpop_test_dir");
        let result = writersproof_dir();
        // Restore
        match original {
            Some(v) => std::env::set_var("CPOE_DATA_DIR", v),
            None => std::env::remove_var("CPOE_DATA_DIR"),
        }
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/tmp/cpop_test_dir"),
            "should use CPOE_DATA_DIR env var when set"
        );
    }

    // --- constants ---

    #[test]
    fn test_max_file_size_is_500mb() {
        assert_eq!(MAX_FILE_SIZE, 500_000_000, "MAX_FILE_SIZE should be 500 MB");
    }

    #[test]
    fn test_large_file_warning_below_max() {
        assert!(
            LARGE_FILE_WARNING_THRESHOLD < MAX_FILE_SIZE,
            "warning threshold should be below max file size"
        );
    }

    #[test]
    fn test_blocked_extensions_contains_common_binaries() {
        let must_block = ["exe", "dll", "zip", "jpg", "mp4", "pdf", "db"];
        for ext in must_block {
            assert!(
                BLOCKED_EXTENSIONS.contains(&ext),
                "BLOCKED_EXTENSIONS should contain '{ext}'"
            );
        }
    }

    #[test]
    fn test_blocked_extensions_no_text_formats() {
        let must_allow = ["txt", "md", "rs", "py", "js", "html", "css", "json", "toml"];
        for ext in must_allow {
            assert!(
                !BLOCKED_EXTENSIONS.contains(&ext),
                "BLOCKED_EXTENSIONS should not contain text format '{ext}'"
            );
        }
    }
}
