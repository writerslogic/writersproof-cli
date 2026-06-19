// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Signed remote app registry fetched from `updates.writerslogic.com`.
//!
//! On first launch and every 24 hours, fetches a JSON registry signed with
//! Ed25519. Verified entries are merged into the `AppRegistry` with priority:
//! user > remote > builtin. If the fetch fails, the cached local copy is used.

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::app_registry::{StoragePattern, WitnessingMode};

const REMOTE_URL: &str = "https://updates.writerslogic.com/app-registry.json";
const CACHE_FILENAME: &str = "remote_app_registry.json";
const REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Ed25519 public key for verifying the remote registry signature.
///
/// **PLACEHOLDER** -- replace with the real production update-signing key
/// before deployment. Generate with `wld keygen --purpose update-signing`
/// and store the private half in the CI signing HSM.
const SIGNING_PUBKEY: [u8; 32] = [
    0x8a, 0x3b, 0x5c, 0x7d, 0x9e, 0x1f, 0x2a, 0x4b,
    0x6c, 0x8d, 0xae, 0xcf, 0xe0, 0x11, 0x32, 0x53,
    0x74, 0x95, 0xb6, 0xd7, 0xf8, 0x19, 0x3a, 0x5b,
    0x7c, 0x9d, 0xbe, 0xdf, 0x00, 0x21, 0x42, 0x63,
];

#[derive(Deserialize)]
struct RemoteRegistryFile {
    version: u32,
    signature: String,
    apps: Vec<RemoteApp>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RemoteApp {
    pub bundle_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub storage: StoragePattern,
    #[serde(default)]
    pub container_paths: Vec<String>,
    #[serde(default)]
    pub needs_title_inference: bool,
    #[serde(default)]
    pub witnessing_mode: WitnessingMode,
}

/// Load the remote registry from cache, spawning a background refresh if stale.
///
/// Always returns the cached copy immediately (may be empty on first run).
/// If the cache is stale, a background thread fetches and writes the updated
/// cache to disk; the next call to `load_remote_apps` (e.g. on sentinel
/// restart) will pick up the refreshed data.
pub fn load_remote_apps(data_dir: &Path) -> Vec<RemoteApp> {
    let cache_path = data_dir.join(CACHE_FILENAME);
    let cached = load_from_cache(&cache_path);

    if should_refresh(&cache_path) {
        let bg_cache_path = cache_path.clone();
        std::thread::spawn(move || {
            match fetch_and_verify() {
                Ok(apps) => {
                    let count = apps.len();
                    if let Ok(json) = serde_json::to_string_pretty(&serde_json::json!({
                        "fetched_at": SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        "apps": apps,
                    })) {
                        match crate::crypto::atomic_write(&bg_cache_path, json.as_bytes()) {
                            Ok(()) => log::info!(
                                "Remote app registry refreshed: {count} entries"
                            ),
                            Err(e) => log::warn!(
                                "Remote registry fetched but cache write failed: {e}"
                            ),
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Remote registry background fetch failed: {e}");
                }
            }
        });
    }

    cached
}

fn should_refresh(cache_path: &Path) -> bool {
    match std::fs::metadata(cache_path) {
        Ok(meta) => {
            let age = meta
                .modified()
                .ok()
                .and_then(|m| m.elapsed().ok())
                .unwrap_or(Duration::MAX);
            age >= REFRESH_INTERVAL
        }
        Err(_) => true,
    }
}

fn fetch_and_verify() -> Result<Vec<RemoteApp>, String> {
    let response = reqwest::blocking::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?
        .get(REMOTE_URL)
        .send()
        .map_err(|e| format!("fetch: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }

    const MAX_BODY_SIZE: u64 = 1024 * 1024; // 1 MiB
    if let Some(len) = response.content_length() {
        if len > MAX_BODY_SIZE {
            return Err(format!("response too large: {len} bytes"));
        }
    }

    let body = response.bytes().map_err(|e| format!("read body: {e}"))?;
    if body.len() as u64 > MAX_BODY_SIZE {
        return Err(format!("response too large: {} bytes", body.len()));
    }

    let file: RemoteRegistryFile =
        serde_json::from_slice(&body).map_err(|e| format!("parse: {e}"))?;

    if file.version < 1 {
        return Err("unsupported schema version".into());
    }

    // Signature is computed over the canonical JSON of the apps array, not the
    // full response (which includes the signature field itself).
    let apps_json = serde_json::to_vec(&file.apps)
        .map_err(|e| format!("re-serialize apps: {e}"))?;
    verify_signature(&apps_json, &file.signature)?;

    Ok(file.apps)
}

fn verify_signature(payload: &[u8], hex_sig: &str) -> Result<(), String> {
    let sig_bytes =
        hex::decode(hex_sig).map_err(|e| format!("decode signature hex: {e}"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("parse signature: {e}"))?;

    let pubkey = VerifyingKey::from_bytes(&SIGNING_PUBKEY)
        .map_err(|e| format!("parse public key: {e}"))?;

    pubkey
        .verify(payload, &sig)
        .map_err(|_| "signature verification failed".to_string())
}

fn load_from_cache(cache_path: &Path) -> Vec<RemoteApp> {
    let contents = match std::fs::read_to_string(cache_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    #[derive(Deserialize)]
    struct CacheFile {
        #[allow(dead_code)]
        fetched_at: Option<u64>,
        apps: Vec<RemoteApp>,
    }

    match serde_json::from_str::<CacheFile>(&contents) {
        Ok(file) => file.apps,
        Err(e) => {
            log::warn!("Malformed remote registry cache: {e}");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_refresh_missing_file() {
        assert!(should_refresh(Path::new("/nonexistent/path/file.json")));
    }

    #[test]
    fn test_load_from_cache_missing() {
        let apps = load_from_cache(Path::new("/nonexistent/cache.json"));
        assert!(apps.is_empty());
    }

    #[test]
    fn test_load_from_cache_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cache.json");
        std::fs::write(
            &path,
            r#"{"fetched_at": 1700000000, "apps": [
                {"bundle_id": "com.example.Test", "display_name": "Test"}
            ]}"#,
        )
        .unwrap();
        let apps = load_from_cache(&path);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].bundle_id, "com.example.Test");
    }

    #[test]
    fn test_load_from_cache_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cache.json");
        std::fs::write(&path, "not json").unwrap();
        let apps = load_from_cache(&path);
        assert!(apps.is_empty());
    }

    #[test]
    fn test_load_remote_apps_returns_cache_immediately() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_path = tmp.path().join(CACHE_FILENAME);
        std::fs::write(
            &cache_path,
            r#"{"fetched_at": 1700000000, "apps": [
                {"bundle_id": "com.example.Cached", "display_name": "Cached"}
            ]}"#,
        )
        .unwrap();
        // Even with a stale cache, load_remote_apps returns instantly from cache.
        let apps = load_remote_apps(tmp.path());
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].bundle_id, "com.example.Cached");
    }

    #[test]
    fn test_load_remote_apps_empty_on_first_run() {
        let tmp = tempfile::tempdir().unwrap();
        let apps = load_remote_apps(tmp.path());
        assert!(apps.is_empty());
    }

    #[test]
    fn test_remote_app_deserialize_defaults() {
        let json = r#"{"bundle_id": "com.example.Minimal"}"#;
        let app: RemoteApp = serde_json::from_str(json).unwrap();
        assert_eq!(app.bundle_id, "com.example.Minimal");
        assert_eq!(app.storage, StoragePattern::FileBased);
        assert_eq!(app.witnessing_mode, WitnessingMode::Auto);
        assert!(!app.needs_title_inference);
        assert!(app.container_paths.is_empty());
    }
}
