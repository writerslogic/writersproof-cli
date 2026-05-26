// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::forensics::EventData;
use crate::store::SecureStore;
use authorproof_protocol::rfc::wire_types::AttestationTier;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Cached device identity for populating evidence events.
/// Uses Mutex so we can retry if the first attempt returned an ephemeral fallback
/// (e.g., keychain was locked at startup but unlocked later).
static DEVICE_IDENTITY: std::sync::Mutex<Option<(bool, [u8; 16], String)>> =
    std::sync::Mutex::new(None);

pub fn device_identity() -> ([u8; 16], String) {
    let mut guard = DEVICE_IDENTITY.lock().unwrap_or_else(|e| {
        log::warn!("DEVICE_IDENTITY mutex poisoned; recovering cached value");
        e.into_inner()
    });
    // If we have a persistent (non-ephemeral) identity, return it.
    if let Some((true, id, machine)) = guard.as_ref() {
        return (*id, machine.clone());
    }
    // Try loading from secure storage (retries if previously ephemeral).
    match crate::identity::secure_storage::SecureStorage::load_device_identity() {
        Ok(Some(identity)) => {
            *guard = Some((true, identity.0, identity.1.clone()));
            identity
        }
        Ok(None) | Err(_) => {
            // Return cached ephemeral if we already generated one.
            if let Some((false, id, machine)) = guard.as_ref() {
                return (*id, machine.clone());
            }
            log::error!(
                "SecureStorage device identity unavailable; using random ephemeral device ID"
            );
            let mut fallback_id = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut fallback_id);
            let machine_id = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
            *guard = Some((false, fallback_id, machine_id.clone()));
            (fallback_id, machine_id)
        }
    }
}

pub use crate::evidence::unwrap_cose_or_raw;

/// Maximum Shannon entropy for the edit-position histogram (log2(20 bins)).
pub const ENTROPY_NORMALIZATION_FACTOR: f64 = 4.321928;

/// Shared lock for tests that modify `CPOE_DATA_DIR`.
/// All FFI test modules must use this to avoid env var races.
/// Uses a helper that recovers from poisoned state (previous test panics).
#[cfg(test)]
pub static FFI_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub fn lock_ffi_env() -> std::sync::MutexGuard<'static, ()> {
    FFI_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn get_data_dir() -> Option<PathBuf> {
    crate::utils::get_data_dir()
}

pub(crate) fn get_db_path() -> Option<PathBuf> {
    get_data_dir().map(|d| d.join("events.db"))
}

pub(crate) fn load_hmac_key() -> Option<Zeroizing<Vec<u8>>> {
    if let Ok(Some(key)) = crate::identity::SecureStorage::load_hmac_key() {
        return Some(key);
    }

    let key = derive_hmac_from_signing_key()?;

    if let Err(e) = crate::identity::SecureStorage::save_hmac_key(&key) {
        log::warn!("Failed to migrate signing key to secure storage: {}", e);
    }

    Some(key)
}

/// Load the Ed25519 signing key from the data directory, zeroizing intermediates.
pub(crate) fn load_signing_key() -> Result<ed25519_dalek::SigningKey, String> {
    use std::io::Read;
    use zeroize::Zeroize;

    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let key_path = data_dir.join("signing_key");
    // Open first, then fstat the handle to avoid TOCTOU between stat and open.
    let key_file = std::fs::File::open(&key_path)
        .map_err(|e| format!("Failed to open signing key: {e}"))?;
    let meta = key_file
        .metadata()
        .map_err(|e| format!("Failed to stat signing key: {e}"))?;
    if !meta.is_file() {
        return Err("Signing key path is not a regular file".to_string());
    }
    if meta.len() > 1024 {
        return Err(format!("Signing key file too large: {} bytes", meta.len()));
    }
    let mut key_data = Zeroizing::new(Vec::new());
    {
        let mut f = key_file;
        f.read_to_end(&mut key_data)
            .map_err(|e| format!("Failed to read signing key: {e}"))?;
    }
    if key_data.len() < 32 {
        return Err("Signing key is too short".to_string());
    }
    let mut secret: Zeroizing<[u8; 32]> = Zeroizing::new(
        key_data[..32]
            .try_into()
            .map_err(|_| "Invalid signing key length".to_string())?,
    );
    drop(key_data);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(signing_key)
}

/// Load a cached CA-signed X.509 certificate, or fall back to self-signed.
///
/// Checks for `{DATA_DIR}/ca_cert.der`. If present, returns the cached DER bytes.
/// If absent, generates a self-signed cert with C2PA-compliant extensions.
/// The CA-provisioned cert is populated asynchronously by `provision_ca_cert()`
/// after successful enrollment with the WritersProof CA.
pub(crate) fn load_or_generate_cert(
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, String> {
    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let cert_path = data_dir.join("ca_cert.der");

    // Prefer CA-signed cert if cached.
    if cert_path.is_file() {
        match std::fs::read(&cert_path) {
            Ok(der) if der.len() > 100 => return Ok(der),
            Ok(_) => log::warn!("Cached CA cert too small; regenerating self-signed"),
            Err(e) => log::warn!("Failed to read cached CA cert: {e}; using self-signed"),
        }
    }

    // Fall back to self-signed with C2PA extensions.
    authorproof_protocol::c2pa::cert::generate_self_signed_cert(signing_key)
        .map_err(|e| format!("Failed to generate self-signed cert: {e}"))
}

/// Cache a CA-signed certificate from WritersProof CA.
///
/// Called after successful enrollment. Writes the DER-encoded cert to
/// `{DATA_DIR}/ca_cert.der` via atomic rename.
pub(crate) fn cache_ca_cert(cert_der: &[u8]) -> Result<(), String> {
    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let cert_path = data_dir.join("ca_cert.der");

    let parent = cert_path.parent().unwrap_or(std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("Failed to create temp file for cert: {e}"))?;
    std::io::Write::write_all(&mut tmp, cert_der)
        .map_err(|e| format!("Failed to write cert: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("Failed to sync cert: {e}"))?;
    tmp.persist(&cert_path)
        .map_err(|e| format!("Failed to persist cert: {e}"))?;
    Ok(())
}

/// Load the DID string from identity.json.
pub(crate) fn load_did() -> Result<String, String> {
    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let identity_path = data_dir.join("identity.json");
    let data = std::fs::read_to_string(&identity_path)
        .map_err(|e| format!("Failed to read identity.json: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&data).map_err(|e| format!("Invalid identity.json: {e}"))?;
    v.get("did")
        .and_then(|d| d.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "DID not found in identity.json".to_string())
}

/// Load the WritersProof API key, if available. Wrapped in Zeroizing for cleanup.
pub(crate) fn load_api_key() -> Result<Zeroizing<String>, String> {
    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let key_path = data_dir.join("writersproof_api_key");
    let key = std::fs::read_to_string(&key_path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("Failed to read API key: {e}"))?;
    Ok(Zeroizing::new(key))
}

/// Validate a document path and return its canonical string form.
pub(crate) fn validate_path_str(path: &str) -> Result<String, String> {
    let validated = crate::sentinel::helpers::validate_path(path).map_err(|e| e.to_string())?;
    validated
        .to_str()
        .ok_or_else(|| "Path contains non-UTF-8 characters".to_string())
        .map(|s| s.to_string())
}

/// Validate a document path, open the store, and load events in one call.
/// Eliminates the repeated validate+open+get_events boilerplate across FFI functions.
pub(crate) fn load_events_for_path(
    path: &str,
) -> Result<(String, SecureStore, Vec<crate::store::SecureEvent>), String> {
    let canonical = validate_path_str(path)?;
    let store = open_store()?;
    let events = store
        .get_events_for_file(&canonical)
        .map_err(|e| format!("Failed to load events: {e}"))?;
    Ok((canonical, store, events))
}

pub(crate) fn open_store() -> Result<SecureStore, String> {
    let db_path = get_db_path()
        .filter(|p| p.exists())
        .ok_or_else(|| "Database not found".to_string())?;
    open_store_at(&db_path)
}

/// Open or recover a SecureStore at the given path.
///
/// Recovery strategy on HMAC mismatch:
/// 1. Try the signing-key-derived HMAC (handles keychain key transitions)
/// 2. Verify a fresh key is available, THEN delete the stale DB and recreate
pub(crate) fn open_store_at(db_path: &std::path::Path) -> Result<SecureStore, String> {
    let hmac_key = load_hmac_key().ok_or_else(|| "Failed to load signing key".to_string())?;
    match SecureStore::open(db_path, hmac_key) {
        Ok(store) => Ok(store),
        Err(primary_err) => {
            let err_msg = primary_err.to_string();
            let is_hmac_mismatch =
                err_msg.contains("HMAC mismatch") || err_msg.contains("hmac mismatch");

            // Strategy 1: try signing-key-derived HMAC
            if let Some(key) = derive_hmac_from_signing_key() {
                if let Ok(store) = SecureStore::open(db_path, key) {
                    log::info!("Opened database with signing-key-derived HMAC");
                    if let Some(k) = derive_hmac_from_signing_key() {
                        if let Err(e) = crate::identity::SecureStorage::save_hmac_key(&k) {
                            log::warn!("Failed to persist migrated HMAC key: {e}");
                        }
                    }
                    return Ok(store);
                }
            }

            // Strategy 2: verify key available BEFORE backing up, then recreate
            if is_hmac_mismatch {
                // Reset the cache so load_hmac_key re-derives from signing_key
                crate::identity::SecureStorage::reset_hmac_cache();
                let fresh_key = load_hmac_key();
                if let Some(k) = fresh_key {
                    let timestamp = crate::utils::now_secs();
                    let backup_path = db_path.with_extension(format!("backup-{timestamp}"));
                    log::error!(
                        "CRITICAL: HMAC mismatch unrecoverable; renaming stale database to {}",
                        backup_path.display()
                    );
                    if let Err(e) = std::fs::rename(db_path, &backup_path) {
                        return Err(format!("HMAC mismatch; database backup failed: {e}"));
                    }
                    match SecureStore::open(db_path, k) {
                        Ok(store) => {
                            // Persist the migrated HMAC key so future opens succeed
                            if let Some(migrated) = load_hmac_key() {
                                if let Err(e) =
                                    crate::identity::SecureStorage::save_hmac_key(&migrated)
                                {
                                    // Recreated DB is valid but key not persisted;
                                    // roll back to avoid an inconsistent state where
                                    // the new DB exists but the old key is gone.
                                    log::error!(
                                        "Failed to persist HMAC key after recreate: {e}; \
                                         restoring backup"
                                    );
                                    if let Err(e2) = std::fs::remove_file(db_path) {
                                        log::warn!("rollback: remove new DB failed: {e2}");
                                    }
                                    if let Err(e2) = std::fs::rename(&backup_path, db_path) {
                                        log::warn!("rollback: restore backup failed: {e2}");
                                    }
                                    return Err(format!(
                                        "DB recreated but HMAC key persist failed: {e}"
                                    ));
                                }
                            }
                            return Ok(store);
                        }
                        Err(e) => {
                            log::error!("Recreate failed; restoring backup: {e}");
                            if let Err(e2) = std::fs::rename(&backup_path, db_path) {
                                log::warn!("rollback: restore backup after recreate failed: {e2}");
                            }
                            return Err(format!("Failed to recreate database: {e}"));
                        }
                    }
                }
                // Key unavailable; do NOT touch the DB (preserve data)
                log::error!("HMAC key unavailable; cannot recover database");
            }

            Err(format!("Failed to open database: {}", primary_err))
        }
    }
}

/// Derive HMAC key directly from the signing_key file, bypassing keychain.
///
/// Opens the file, stats the handle (not the path), bounds the size, and
/// derives an HMAC key from the first 32 bytes.
pub(crate) fn derive_hmac_from_signing_key() -> Option<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let data_dir = get_data_dir()?;
    let key_path = data_dir.join("signing_key");
    let key_file = match std::fs::File::open(&key_path) {
        Ok(f) => f,
        Err(e) => {
            log::warn!("failed to open signing key file: {e}");
            return None;
        }
    };
    if let Ok(meta) = key_file.metadata() {
        if meta.len() > 1024 {
            log::error!("Signing key file too large: {} bytes", meta.len());
            return None;
        }
    }
    let mut raw = Zeroizing::new(Vec::new());
    {
        let mut f = key_file;
        if let Err(e) = f.read_to_end(&mut raw) {
            log::warn!("failed to read signing key file: {e}");
            return None;
        }
    }
    if raw.len() >= 32 {
        Some(crate::crypto::derive_hmac_key(&raw[..32]))
    } else {
        None
    }
}

pub(crate) fn detect_attestation_tier() -> AttestationTier {
    let (tier, _, _) = detect_attestation_tier_info();
    tier
}

pub(crate) fn detect_attestation_tier_info() -> (AttestationTier, u8, String) {
    let provider = crate::tpm::detect_provider();
    let caps = provider.capabilities();
    if caps.hardware_backed && caps.supports_sealing {
        (
            AttestationTier::HardwareBound,
            3,
            "hardware-bound".to_string(),
        )
    } else if caps.hardware_backed && caps.supports_attestation {
        (
            AttestationTier::AttestedSoftware,
            2,
            "attested-software".to_string(),
        )
    } else {
        (
            AttestationTier::SoftwareOnly,
            1,
            "software-only".to_string(),
        )
    }
}

/// Streak statistics computed from a set of active days.
pub(crate) struct StreakStats {
    pub current_streak_days: u32,
    pub longest_streak_days: u32,
    pub active_days_in_window: u32,
}

/// Compute streak and activity stats from nanosecond timestamps.
///
/// `timestamps_ns`: event timestamps in nanoseconds.
/// `today_day`: the current day as Unix epoch / 86400.
/// `window_days`: how many days back to count active days (e.g. 30).
pub(crate) fn compute_streak_stats(
    timestamps_ns: &[i64],
    today_day: i64,
    window_days: i64,
) -> StreakStats {
    let mut active_days: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
    for ts in timestamps_ns {
        let day = ts / (86400 * 1_000_000_000);
        active_days.insert(day);
    }

    let active_days_in_window = active_days
        .iter()
        .filter(|d| **d >= today_day - window_days)
        .count() as u32;

    let mut longest_streak: u32 = 0;
    let mut streak: u32 = 0;
    let mut prev_day: Option<i64> = None;

    for &day in active_days.iter().rev() {
        if let Some(prev) = prev_day {
            if prev - day == 1 {
                streak += 1;
            } else {
                longest_streak = longest_streak.max(streak);
                streak = 1;
            }
        } else {
            streak = 1;
        }
        prev_day = Some(day);
    }
    longest_streak = longest_streak.max(streak);

    let mut current_streak: u32 = 0;
    let mut check_day = today_day;
    while active_days.contains(&check_day) {
        current_streak += 1;
        check_day -= 1;
    }
    if current_streak == 0 {
        check_day = today_day - 1;
        while active_days.contains(&check_day) {
            current_streak += 1;
            check_day -= 1;
        }
    }

    StreakStats {
        current_streak_days: current_streak,
        longest_streak_days: longest_streak,
        active_days_in_window,
    }
}

pub(crate) fn events_to_forensic_data(events: &[crate::store::SecureEvent]) -> Vec<EventData> {
    EventData::from_secure_events(events)
}

/// Build per-event edit region maps from secure events.
///
/// Delegates to `forensics::build_edit_regions` (single source of truth).
pub(crate) fn build_edit_regions(
    events: &[crate::store::SecureEvent],
) -> std::collections::HashMap<i64, Vec<crate::forensics::RegionData>> {
    crate::forensics::build_edit_regions(events)
}

/// Run the full forensics pipeline on stored events: convert to EventData,
/// build edit regions, and call `analyze_forensics`.
pub(crate) fn run_full_forensics(
    events: &[crate::store::SecureEvent],
) -> (
    crate::forensics::ForensicMetrics,
    std::collections::HashMap<i64, Vec<crate::forensics::RegionData>>,
) {
    let event_data = events_to_forensic_data(events);
    let regions = build_edit_regions(events);
    let metrics = crate::forensics::analyze_forensics(&event_data, &regions, None, None, None);
    (metrics, regions)
}
