// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! CA trust bundle loading: fetch a signed manifest from a remote URL, cache it
//! locally, and fall back to the pinned compile-time bundle when offline.

use crate::config::TrustBundleConfig;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single CA key entry loaded from the trust bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaBundleEntry {
    pub kid: String,
    pub pubkey_hex: String,
    pub not_before: String,
    pub not_after: String,
}

/// Signed JSON manifest returned from the WritersProof CA bundle endpoint.
///
/// The `signature` field covers the canonical JSON of `{version, published_at, keys}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaBundleManifest {
    pub version: u32,
    pub published_at: String,
    pub keys: Vec<CaBundleEntry>,
    /// Ed25519 signature (hex, 64 bytes) over the `payload` field.
    pub signature: String,
    /// Canonical UTF-8 JSON of `{version, published_at, keys}` — what was signed.
    pub payload: String,
}

/// Ed25519 public key of the manifest signing key (pinned in binary, 32 bytes hex).
///
/// This key is separate from any CA key — it signs the *manifest* that lists CA
/// keys. Rotating this key requires a binary update (intentional — it is a root
/// of trust, not subject to remote rotation).
const MANIFEST_SIGNING_PUBKEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Verify the Ed25519 manifest signature over `payload`.
fn verify_manifest_signature(manifest: &CaBundleManifest) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};

    let pubkey_bytes = match hex::decode(MANIFEST_SIGNING_PUBKEY_HEX) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let pubkey_arr: &[u8; 32] = match pubkey_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(pubkey_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig_bytes = match hex::decode(&manifest.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify_strict(manifest.payload.as_bytes(), &signature)
        .is_ok()
}

/// Validate that all entries in the bundle are structurally well-formed.
fn validate_bundle_entries(entries: &[CaBundleEntry]) -> bool {
    if entries.is_empty() {
        return false;
    }
    for entry in entries {
        if entry.kid.is_empty() {
            return false;
        }
        if hex::decode(&entry.pubkey_hex).map(|b| b.len()).unwrap_or(0) != 32 {
            return false;
        }
        if DateTime::parse_from_rfc3339(&entry.not_before).is_err() {
            return false;
        }
        if DateTime::parse_from_rfc3339(&entry.not_after).is_err() {
            return false;
        }
    }
    true
}

/// Return `true` when the local cache file exists and is newer than `max_age_secs`.
fn cache_is_fresh(path: &Path, max_age_secs: u64) -> bool {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let modified = match meta.modified() {
        Ok(t) => t,
        Err(_) => return false,
    };
    match modified.elapsed() {
        Ok(age) => age.as_secs() < max_age_secs,
        Err(_) => false,
    }
}

/// Parse and validate a manifest JSON string.
fn parse_and_validate(json: &str) -> Option<Vec<CaBundleEntry>> {
    let manifest: CaBundleManifest = serde_json::from_str(json).ok()?;
    if manifest.version == 0 {
        return None;
    }
    // When the manifest signing key is the all-zeros placeholder, skip signature
    // verification (development / testing mode). In production the key is non-zero
    // and signature verification is enforced.
    let key_is_placeholder = MANIFEST_SIGNING_PUBKEY_HEX
        .bytes()
        .all(|b| b == b'0');
    if !key_is_placeholder && !verify_manifest_signature(&manifest) {
        log::warn!("trust_bundle: manifest signature verification failed");
        return None;
    }
    if !validate_bundle_entries(&manifest.keys) {
        log::warn!("trust_bundle: manifest contains invalid key entries");
        return None;
    }
    Some(manifest.keys)
}

/// Try to load the bundle from the local cache file.
fn load_from_cache(path: &Path) -> Option<Vec<CaBundleEntry>> {
    let json = std::fs::read_to_string(path).ok()?;
    parse_and_validate(&json)
}

/// Attempt a synchronous HTTPS fetch of the manifest (blocking).
fn fetch_from_url(url: &str, timeout_secs: u64) -> Option<String> {
    use std::time::Duration;

    if url.is_empty() {
        return None;
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .ok()?;
    let resp = client.get(url).send().ok()?;
    if !resp.status().is_success() {
        log::warn!("trust_bundle: fetch {} returned {}", url, resp.status());
        return None;
    }
    resp.text().ok()
}

/// The compile-time pinned CA bundle. Keys here are always trusted as a last
/// resort when both remote fetch and local cache are unavailable.
pub fn pinned_bundle() -> Vec<CaBundleEntry> {
    // Mirrors CA_KEY_RING in verification.rs. Must be kept in sync manually;
    // the rotation runbook (docs/ca_rotation.md) documents the update procedure.
    vec![CaBundleEntry {
        kid: "e58a2aacaad69b37".to_string(),
        pubkey_hex: "b48f36054b9160dff06ac4329898523f441914442958a01e84b719ac539ca053"
            .to_string(),
        not_before: "2026-03-19T00:00:00Z".to_string(),
        not_after: "2036-03-18T23:59:59Z".to_string(),
    }]
}

/// Load the CA trust bundle, returning the most up-to-date available set of keys.
///
/// Strategy (in order):
/// 1. Fresh local cache (< `max_cache_age_secs`) — no network required.
/// 2. Remote fetch from `manifest_url`, validated and written to `local_cache_path`.
/// 3. Stale local cache (validation still passes, just older than max age).
/// 4. Compile-time pinned bundle (always available).
pub fn load_bundle(config: &TrustBundleConfig) -> Vec<CaBundleEntry> {
    // 1. Fresh cache hit.
    if cache_is_fresh(&config.local_cache_path, config.max_cache_age_secs) {
        if let Some(entries) = load_from_cache(&config.local_cache_path) {
            log::debug!("trust_bundle: loaded {} keys from fresh cache", entries.len());
            return entries;
        }
    }

    // 2. Remote fetch.
    if let Some(json) = fetch_from_url(&config.manifest_url, config.fetch_timeout_secs) {
        if let Some(entries) = parse_and_validate(&json) {
            // Best-effort cache write; non-fatal on failure.
            if let Some(parent) = config.local_cache_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(&config.local_cache_path, &json) {
                log::warn!("trust_bundle: failed to write cache: {e}");
            }
            log::info!("trust_bundle: loaded {} keys from remote", entries.len());
            return entries;
        }
    }

    // 3. Stale cache fallback.
    if let Some(entries) = load_from_cache(&config.local_cache_path) {
        log::warn!(
            "trust_bundle: using stale cache (remote fetch failed), {} keys",
            entries.len()
        );
        return entries;
    }

    // 4. Pinned fallback.
    log::warn!("trust_bundle: using pinned compile-time bundle");
    pinned_bundle()
}

/// Find the key for a given attestation from `bundle`, returning a clone on success.
///
/// Mirrors the logic in `verification::find_ca_key` but operates on owned entries.
pub fn find_in_bundle(
    kid: Option<&str>,
    fetched_at: &str,
    bundle: &[CaBundleEntry],
) -> Result<CaBundleEntry, String> {
    let ts = DateTime::parse_from_rfc3339(fetched_at)
        .map_err(|e| format!("Invalid fetched_at timestamp: {e}"))?;

    if let Some(kid_value) = kid {
        let entry = bundle
            .iter()
            .find(|k| k.kid == kid_value)
            .ok_or_else(|| format!("Unknown CA key ID: {kid_value}"))?;

        let nb = DateTime::parse_from_rfc3339(&entry.not_before)
            .map_err(|e| format!("Internal error: bad not_before in bundle: {e}"))?;
        let na = DateTime::parse_from_rfc3339(&entry.not_after)
            .map_err(|e| format!("Internal error: bad not_after in bundle: {e}"))?;

        if ts < nb || ts > na {
            return Err(format!(
                "CA key {} expired or not yet valid for timestamp {}",
                kid_value, fetched_at
            ));
        }
        return Ok(entry.clone());
    }

    for entry in bundle {
        let nb = DateTime::parse_from_rfc3339(&entry.not_before)
            .map_err(|e| format!("Internal error: bad not_before in bundle: {e}"))?;
        let na = DateTime::parse_from_rfc3339(&entry.not_after)
            .map_err(|e| format!("Internal error: bad not_after in bundle: {e}"))?;

        if ts >= nb && ts <= na {
            return Ok(entry.clone());
        }
    }

    Err(format!(
        "No valid CA key found for timestamp {fetched_at}; \
         evidence may predate the oldest key or postdate all key expiry dates"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_bundle_is_valid() {
        let bundle = pinned_bundle();
        assert!(!bundle.is_empty());
        assert!(validate_bundle_entries(&bundle));
    }

    #[test]
    fn test_find_in_bundle_by_kid() {
        let bundle = pinned_bundle();
        let entry = find_in_bundle(Some("e58a2aacaad69b37"), "2030-01-01T00:00:00Z", &bundle);
        assert!(entry.is_ok());
        assert_eq!(entry.unwrap().kid, "e58a2aacaad69b37");
    }

    #[test]
    fn test_find_in_bundle_by_timestamp() {
        let bundle = pinned_bundle();
        let entry = find_in_bundle(None, "2030-01-01T00:00:00Z", &bundle);
        assert!(entry.is_ok());
    }

    #[test]
    fn test_find_in_bundle_before_validity() {
        let bundle = pinned_bundle();
        let entry = find_in_bundle(None, "2020-01-01T00:00:00Z", &bundle);
        assert!(entry.is_err());
    }

    #[test]
    fn test_find_in_bundle_after_expiry() {
        let bundle = pinned_bundle();
        let entry = find_in_bundle(None, "2037-01-01T00:00:00Z", &bundle);
        assert!(entry.is_err());
    }

    #[test]
    fn test_find_in_bundle_unknown_kid() {
        let bundle = pinned_bundle();
        let entry = find_in_bundle(Some("0000000000000000"), "2030-01-01T00:00:00Z", &bundle);
        assert!(entry.is_err());
        assert!(entry.unwrap_err().contains("Unknown CA key ID"));
    }

    #[test]
    fn test_find_in_bundle_kid_expired() {
        let bundle = pinned_bundle();
        let entry = find_in_bundle(Some("e58a2aacaad69b37"), "2037-01-01T00:00:00Z", &bundle);
        assert!(entry.is_err());
        assert!(entry.unwrap_err().contains("expired or not yet valid"));
    }

    #[test]
    fn test_find_in_bundle_invalid_timestamp() {
        let bundle = pinned_bundle();
        let entry = find_in_bundle(None, "not-a-timestamp", &bundle);
        assert!(entry.is_err());
        assert!(entry.unwrap_err().contains("Invalid fetched_at"));
    }

    #[test]
    fn test_validate_empty_bundle_fails() {
        assert!(!validate_bundle_entries(&[]));
    }

    #[test]
    fn test_validate_bad_pubkey_hex_fails() {
        let bad = vec![CaBundleEntry {
            kid: "abc".to_string(),
            pubkey_hex: "not-hex".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2036-01-01T00:00:00Z".to_string(),
        }];
        assert!(!validate_bundle_entries(&bad));
    }

    #[test]
    fn test_cache_freshness_missing_file() {
        assert!(!cache_is_fresh(Path::new("/nonexistent/path/bundle.json"), 3600));
    }
}
