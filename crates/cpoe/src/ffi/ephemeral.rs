// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Ephemeral session FFI — in-memory text witnessing without file paths.
//!
//! Used by browser extensions and macOS Services where content lives in
//! a text field, not on disk. Sessions use `ephemeral://<id>` as synthetic
//! paths and hash content bytes in-memory.
//!
//! Security invariants:
//! - All string inputs are bounded (context_label ≤256, content ≤10MB, statement ≤1000)
//! - Sessions auto-expire after `SESSION_TIMEOUT` (30 min)
//! - Signing key bytes are zeroized after use
//! - Crash-recovery files use atomic write-then-rename
//! - Content snapshots are bounded to `MAX_SNAPSHOTS` per session

use crate::ffi::helpers::{get_data_dir, open_store};
use crate::ffi::types::{
    catch_ffi_panic, FfiEphemeralFinalizeResult, FfiEphemeralSessionResult,
    FfiEphemeralStatusResult, FfiResult,
};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::helpers::device_identity;

// FFI boundary constants: these values MUST match the corresponding constants
// in the Swift side (EphemeralSessionManager.swift / EphemeralConstants.swift).
// Changing any value here requires updating the Swift counterpart.

/// Max context label length (chars). Swift: `kMaxContextLabelLen`.
const MAX_CONTEXT_LABEL_LEN: usize = 256;
/// Max content size for checkpoint/finalize (bytes). Swift: `kMaxContentSize`.
const MAX_CONTENT_SIZE: usize = 10 * 1024 * 1024; // 10 MB
/// Max declaration statement length (chars). Swift: `kMaxStatementLen`.
const MAX_STATEMENT_LEN: usize = 1000;
/// Max content snapshots per session (30s interval x ~8.3 hours). Swift: `kMaxSnapshots`.
const MAX_SNAPSHOTS: usize = 1000;
/// Max jitter intervals per session (protocol limit). Swift: `kMaxJitterIntervals`.
const MAX_JITTER_INTERVALS: usize = 1000;
/// Maximum number of concurrent ephemeral sessions. Prevents unbounded memory growth
/// from callers that start sessions without finalizing them.
/// Swift: `kMaxConcurrentSessions`.
const MAX_CONCURRENT_SESSIONS: usize = 100;
/// Sessions expire after 30 minutes of inactivity. Swift: `kSessionTimeoutSecs`.
const SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Minimum interval between checkpoints per session (rate limiting).
/// Swift: `kMinCheckpointIntervalSecs`.
const MIN_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(1);

/// In-memory ephemeral session state.
struct EphemeralSession {
    context_label: String,
    started_at: Instant,
    started_at_ns: i64,
    last_activity: Instant,
    jitter_intervals: Vec<u64>,
    checkpoint_count: u64,
    keystroke_count: u64,
    /// Content hashes from each checkpoint (for chain building).
    content_snapshots: Vec<ContentSnapshot>,
    /// Canary seed from NMH handshake (hex-encoded).
    canary_seed: Option<String>,
    /// When the last checkpoint was accepted (for rate limiting).
    last_checkpoint_at: Option<Instant>,
}

/// A checkpoint snapshot of the content at a point in time.
struct ContentSnapshot {
    timestamp_ns: i64,
    content_hash: [u8; 32],
    byte_count: u64,
    #[allow(dead_code)]
    size_delta: i32,
    message: Option<String>,
}

static EPHEMERAL_SESSIONS: OnceLock<DashMap<String, EphemeralSession>> = OnceLock::new();
static LAST_EVICTION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Minimum interval between eviction sweeps (seconds).
const EVICTION_INTERVAL_SECS: u64 = 60;

fn sessions() -> &'static DashMap<String, EphemeralSession> {
    EPHEMERAL_SESSIONS.get_or_init(DashMap::new)
}

/// Clear all ephemeral sessions. Call on app exit to release memory.
pub fn shutdown_ephemeral_sessions() {
    if let Some(map) = EPHEMERAL_SESSIONS.get() {
        let count = map.len();
        map.clear();
        if count > 0 {
            log::info!("Cleared {count} ephemeral sessions on shutdown");
        }
    }
}

fn generate_session_id(label: &str) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(crate::utils::now_ns().to_le_bytes());
    let mut random_bytes = [0u8; 16];
    getrandom::getrandom(&mut random_bytes).map_err(|e| format!("CSPRNG failure: {e}"))?;
    hasher.update(random_bytes);
    let hash = hasher.finalize();
    Ok(hex::encode(&hash[..16]))
}

/// Evict sessions that have been idle longer than `SESSION_TIMEOUT`.
/// Throttled to run at most once per `EVICTION_INTERVAL_SECS`.
fn evict_stale_sessions() {
    let now_secs = crate::utils::now_secs();
    let last = LAST_EVICTION.load(std::sync::atomic::Ordering::Relaxed);
    if now_secs.saturating_sub(last) < EVICTION_INTERVAL_SECS {
        return;
    }
    LAST_EVICTION.store(now_secs, std::sync::atomic::Ordering::Relaxed);

    let now = Instant::now();
    sessions().retain(|id, session| {
        let stale = now.duration_since(session.last_activity) > SESSION_TIMEOUT;
        if stale {
            log::info!("Evicting stale ephemeral session {id} (idle > 30min)");
            cleanup_session_state(id);
        }
        !stale
    });
}

/// Start a new ephemeral witnessing session.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_start_ephemeral_session(context_label: String) -> FfiEphemeralSessionResult {
    catch_ffi_panic!(FfiEphemeralSessionResult {
        success: false,
        session_id: String::new(),
        error_message: Some("engine internal error".to_string()),
    }, {
    if context_label.len() > MAX_CONTEXT_LABEL_LEN {
        return FfiEphemeralSessionResult {
            success: false,
            session_id: String::new(),
            error_message: Some(format!(
                "Context label too long ({} bytes, max {MAX_CONTEXT_LABEL_LEN})",
                context_label.len()
            )),
        };
    }

    evict_stale_sessions();

    if sessions().len() >= MAX_CONCURRENT_SESSIONS {
        return FfiEphemeralSessionResult {
            success: false,
            session_id: String::new(),
            error_message: Some(format!(
                "Too many concurrent ephemeral sessions (max {MAX_CONCURRENT_SESSIONS})"
            )),
        };
    }

    let now = Instant::now();
    let session_id = match generate_session_id(&context_label) {
        Ok(id) => id,
        Err(e) => {
            return FfiEphemeralSessionResult {
                success: false,
                session_id: String::new(),
                error_message: Some(e),
            };
        }
    };

    sessions().insert(
        session_id.clone(),
        EphemeralSession {
            context_label,
            started_at: now,
            started_at_ns: crate::utils::now_ns(),
            last_activity: now,
            jitter_intervals: Vec::new(),
            checkpoint_count: 0,
            keystroke_count: 0,

            content_snapshots: Vec::new(),
            canary_seed: None,
            last_checkpoint_at: None,
        },
    );

    FfiEphemeralSessionResult {
        success: true,
        session_id,
        error_message: None,
    }
    })
}

/// Create an in-memory checkpoint of the current content.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_ephemeral_checkpoint(session_id: String, content: String, message: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    evict_stale_sessions();

    let mut entry = match sessions().get_mut(&session_id) {
        Some(e) => e,
        None => return FfiResult::err(format!("No ephemeral session: {session_id}")),
    };

    if content.len() > MAX_CONTENT_SIZE {
        return FfiResult::err(format!(
            "Content too large: {} bytes (max {})",
            content.len(),
            MAX_CONTENT_SIZE
        ));
    }

    if entry.content_snapshots.len() >= MAX_SNAPSHOTS {
        return FfiResult::err(format!("Max snapshots reached ({})", MAX_SNAPSHOTS));
    }

    let now = Instant::now();
    if let Some(last) = entry.last_checkpoint_at {
        if now.duration_since(last) < MIN_CHECKPOINT_INTERVAL {
            return FfiResult::err("Checkpoint rate limited (min 1s interval)".to_string());
        }
    }

    let content_hash: [u8; 32] = Sha256::digest(content.as_bytes()).into();
    let byte_count = content.len() as u64;
    let prev_bytes = entry
        .content_snapshots
        .last()
        .map(|s| s.byte_count)
        .unwrap_or(0);
    let size_delta =
        (byte_count as i64 - prev_bytes as i64).clamp(i32::MIN as i64, i32::MAX as i64) as i32;

    let context_note = if message.is_empty() {
        None
    } else {
        Some(message)
    };

    let snapshot_msg = context_note.clone();
    entry.content_snapshots.push(ContentSnapshot {
        timestamp_ns: crate::utils::now_ns(),
        content_hash,
        byte_count,
        size_delta,
        message: context_note,
    });
    entry.checkpoint_count += 1;
    entry.last_checkpoint_at = Some(Instant::now());
    let checkpoint_num = entry.checkpoint_count;

    // Perform disk I/O while holding the guard to prevent concurrent flushes
    // for the same session_id from racing. The guard is per-entry (DashMap
    // shard-level), so other sessions are not blocked.
    let ephemeral_path = format!("ephemeral://{session_id}");
    let persist_error = match open_store() {
        Ok(mut store) => {
            let mut event = crate::store::SecureEvent::new(
                ephemeral_path,
                content_hash,
                byte_count as i64,
                snapshot_msg,
            );
            let (dev_id, mach_id) = device_identity();
            event.device_id = dev_id;
            event.machine_id = mach_id;
            event.size_delta = size_delta;
            event.context_type = Some("ephemeral".to_string());
            if let Err(e) = store.add_secure_event(&mut event) {
                log::error!("Failed to persist checkpoint: {e}");
                Some(format!("persist failed: {e}"))
            } else {
                None
            }
        }
        Err(e) => {
            log::error!("Failed to open store for ephemeral checkpoint: {e}");
            Some(format!("store unavailable: {e}"))
        }
    };

    entry.last_activity = Instant::now();
    flush_session_state(&session_id, &entry);
    drop(entry);

    let msg = format!(
        "Ephemeral checkpoint #{}: {}",
        checkpoint_num,
        crate::utils::short_hex_id(&content_hash)
    );
    FfiResult {
        success: true,
        message: Some(msg),
        error_message: persist_error,
        error_code: None,
    }
    })
}

/// Accumulate keystroke timing intervals for jitter analysis.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_ephemeral_inject_jitter(session_id: String, intervals: Vec<u64>) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    if intervals.len() > MAX_JITTER_INTERVALS * 10 {
        return FfiResult::err(format!(
            "intervals length {} exceeds maximum ({})",
            intervals.len(),
            MAX_JITTER_INTERVALS * 10
        ));
    }
    let mut entry = match sessions().get_mut(&session_id) {
        Some(e) => e,
        None => return FfiResult::err(format!("No ephemeral session: {session_id}")),
    };

    let total = intervals.len();
    let valid: Vec<u64> = intervals
        .into_iter()
        .filter(|i| (10_000..=10_000_000).contains(i))
        .collect();

    let accepted = valid.len();
    let rejected = total - accepted;
    let remaining_cap = MAX_JITTER_INTERVALS.saturating_sub(entry.jitter_intervals.len());
    entry
        .jitter_intervals
        .extend_from_slice(&valid[..accepted.min(remaining_cap)]);

    entry.keystroke_count += accepted as u64;
    entry.last_activity = Instant::now();

    FfiResult::ok(format!(
        "Accepted {accepted} intervals, rejected {rejected}"
    ))
    })
}

/// Finalize an ephemeral session: build evidence packet → WAR block + compact ref.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_ephemeral_finalize(
    session_id: String,
    content: String,
    statement: String,
) -> FfiEphemeralFinalizeResult {
    catch_ffi_panic!(FfiEphemeralFinalizeResult {
        success: false,
        war_block: String::new(),
        compact_ref: String::new(),
        error_message: Some("engine internal error".to_string()),
    }, {
    if content.len() > MAX_CONTENT_SIZE {
        return FfiEphemeralFinalizeResult {
            success: false,
            war_block: String::new(),
            compact_ref: String::new(),
            error_message: Some(format!(
                "Content too large: {} bytes (max {})",
                content.len(),
                MAX_CONTENT_SIZE
            )),
        };
    }

    let statement = if statement.len() > MAX_STATEMENT_LEN {
        let truncated = match statement
            .char_indices()
            .take_while(|(i, _)| *i < MAX_STATEMENT_LEN)
            .last()
        {
            Some((i, c)) => &statement[..i + c.len_utf8()],
            None => "",
        };
        truncated.to_string()
    } else {
        statement
    };

    // Keep the session in the map during WAR construction so it survives
    // failures and the user can retry. Only remove on success.
    {
        let session_ref = match sessions().get(&session_id) {
            Some(r) => r,
            None => {
                return FfiEphemeralFinalizeResult {
                    success: false,
                    war_block: String::new(),
                    compact_ref: String::new(),
                    error_message: Some(format!("No ephemeral session: {session_id}")),
                };
            }
        };
        if session_ref.content_snapshots.is_empty() {
            return FfiEphemeralFinalizeResult {
                success: false,
                war_block: String::new(),
                compact_ref: String::new(),
                error_message: Some("No checkpoints recorded in session".to_string()),
            };
        }

        let final_hash: [u8; 32] = Sha256::digest(content.as_bytes()).into();
        let final_hash_hex = hex::encode(final_hash);

        let checkpoint_count = session_ref.content_snapshots.len();

        let war_block_str = match build_war_block(&final_hash_hex, &statement, &session_ref) {
            Ok(s) => s,
            Err(e) => {
                // Session stays in the map; user can retry.
                return FfiEphemeralFinalizeResult {
                    success: false,
                    war_block: String::new(),
                    compact_ref: String::new(),
                    error_message: Some(format!("Failed to create WAR block: {e}")),
                };
            }
        };

        let compact_ref = format!(
            "cpoe-ref:writerslogic:{}:{}",
            &final_hash_hex[..final_hash_hex.len().min(12)],
            checkpoint_count
        );

        // WAR block built successfully; drop the read guard before removing.
        drop(session_ref);
        sessions().remove(&session_id);
        cleanup_session_state(&session_id);

        FfiEphemeralFinalizeResult {
            success: true,
            war_block: war_block_str,
            compact_ref,
            error_message: None,
        }
    }
    })
}

/// Get current ephemeral session stats (for the floating indicator).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_ephemeral_status(session_id: String) -> FfiEphemeralStatusResult {
    catch_ffi_panic!(FfiEphemeralStatusResult {
        success: false,
        checkpoint_count: 0,
        keystroke_count: 0,
        elapsed_secs: 0.0,
        error_message: Some("engine internal error".to_string()),
    }, {
    evict_stale_sessions();

    match sessions().get(&session_id) {
        Some(entry) => FfiEphemeralStatusResult {
            success: true,
            checkpoint_count: entry.checkpoint_count,
            keystroke_count: entry.keystroke_count,
            elapsed_secs: entry.started_at.elapsed().as_secs_f64(),
            error_message: None,
        },
        None => FfiEphemeralStatusResult {
            success: false,
            checkpoint_count: 0,
            keystroke_count: 0,
            elapsed_secs: 0.0,
            error_message: Some(format!("No ephemeral session: {session_id}")),
        },
    }
    })
}

/// Return `true` if an ephemeral session with the given ID currently exists.
/// Use this before calling `ffi_ephemeral_finalize` to distinguish "session
/// already evicted by timeout" from a genuine finalize failure.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_ephemeral_session_exists(session_id: String) -> bool {
    catch_ffi_panic!(false, {
    sessions().contains_key(&session_id)
    })
}

/// Create a checkpoint from a pre-computed content hash (avoids sending full content).
/// Used by the NMH where Chrome's 1MB native messaging limit prevents sending full documents.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_ephemeral_checkpoint_hash(
    session_id: String,
    content_hash_hex: String,
    byte_count: u64,
    size_delta: i32,
    message: String,
    commitment: Option<String>,
) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    let mut entry = match sessions().get_mut(&session_id) {
        Some(e) => e,
        None => return FfiResult::err(format!("No ephemeral session: {session_id}")),
    };

    if content_hash_hex.len() != 64 {
        return FfiResult::err(format!(
            "Invalid hash length: {} chars (expected 64 hex chars)",
            content_hash_hex.len()
        ));
    }

    let content_hash: [u8; 32] = match hex::decode(&content_hash_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return FfiResult::err("Invalid hex in content hash".to_string()),
    };

    if entry.content_snapshots.len() >= MAX_SNAPSHOTS {
        return FfiResult::err(format!("Max snapshots reached ({})", MAX_SNAPSHOTS));
    }

    let now = Instant::now();
    if let Some(last) = entry.last_checkpoint_at {
        if now.duration_since(last) < MIN_CHECKPOINT_INTERVAL {
            return FfiResult::err("Checkpoint rate limited (min 1s interval)".to_string());
        }
    }

    let context_note = if message.is_empty() {
        commitment
    } else if let Some(c) = commitment {
        Some(format!("{message} [{c}]"))
    } else {
        Some(message)
    };

    entry.content_snapshots.push(ContentSnapshot {
        timestamp_ns: crate::utils::now_ns(),
        content_hash,
        byte_count,
        size_delta,
        message: context_note,
    });
    entry.checkpoint_count += 1;
    entry.last_checkpoint_at = Some(Instant::now());

    let checkpoint_count = entry.checkpoint_count;
    let last_message = entry
        .content_snapshots
        .last()
        .and_then(|s| s.message.clone());

    // Hold the guard through disk I/O and flush to prevent concurrent threads
    // from racing on the same session's state file. The guard is per-entry
    // (DashMap shard-level), so other sessions are not blocked.
    let ephemeral_path = format!("ephemeral://{session_id}");
    let persist_error = match open_store() {
        Ok(mut store) => {
            let mut event = crate::store::SecureEvent::new(
                ephemeral_path,
                content_hash,
                byte_count as i64,
                last_message,
            );
            let (dev_id, mach_id) = device_identity();
            event.device_id = dev_id;
            event.machine_id = mach_id;
            event.size_delta = size_delta;
            event.context_type = Some("ephemeral".to_string());
            if let Err(e) = store.add_secure_event(&mut event) {
                log::error!("Failed to persist checkpoint_hash: {e}");
                Some(format!("persist failed: {e}"))
            } else {
                None
            }
        }
        Err(e) => {
            log::error!("Failed to open store for ephemeral checkpoint_hash: {e}");
            Some(format!("store unavailable: {e}"))
        }
    };

    flush_session_state(&session_id, &entry);
    drop(entry);

    if let Some(err) = persist_error {
        return FfiResult::err(err);
    }

    let msg = format!(
        "Ephemeral checkpoint #{}: {}",
        checkpoint_count,
        &content_hash_hex[..16]
    );
    FfiResult {
        success: true,
        message: Some(msg),
        error_message: None,
        error_code: None,
    }
    })
}

/// Set the canary seed for an ephemeral session (derived during NMH handshake).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_ephemeral_set_canary_seed(session_id: String, canary_seed_hex: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    let mut entry = match sessions().get_mut(&session_id) {
        Some(e) => e,
        None => return FfiResult::err(format!("No ephemeral session: {session_id}")),
    };

    if canary_seed_hex.len() != 64 {
        return FfiResult::err(format!(
            "Invalid canary seed length: {} chars (expected 64 hex chars)",
            canary_seed_hex.len()
        ));
    }

    if hex::decode(&canary_seed_hex).is_err() {
        return FfiResult::err("Invalid hex in canary seed".to_string());
    }

    entry.canary_seed = Some(canary_seed_hex);
    entry.last_activity = Instant::now();

    FfiResult::ok("Canary seed set".to_string())
    })
}

/// Build a signed WAR block from ephemeral session data.
fn build_war_block(
    final_hash_hex: &str,
    statement: &str,
    session: &EphemeralSession,
) -> Result<String, String> {
    let data_dir = crate::ffi::helpers::get_data_dir()
        .ok_or_else(|| "Cannot determine data directory".to_string())?;
    let key_path = data_dir.join("signing_key");
    // Verify file permissions before reading key material
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&key_path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "signing key file has unsafe permissions {:o}",
                    mode
                ));
            }
        }
    }
    const MAX_SIGNING_KEY_FILE: u64 = 1024;
    let key_meta =
        std::fs::metadata(&key_path).map_err(|e| format!("Cannot stat signing key: {e}"))?;
    if key_meta.len() > MAX_SIGNING_KEY_FILE {
        return Err(format!(
            "Signing key file too large ({} bytes, max {MAX_SIGNING_KEY_FILE})",
            key_meta.len()
        ));
    }
    let key_data = zeroize::Zeroizing::new(
        std::fs::read(&key_path).map_err(|e| format!("Cannot read signing key: {e}"))?,
    );
    if key_data.len() < 32 {
        return Err("Signing key too short".to_string());
    }
    let key_bytes = zeroize::Zeroizing::new(
        <[u8; 32]>::try_from(&key_data[..32]).map_err(|_| "invalid key length")?,
    );
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

    let snapshots: Vec<crate::evidence::EphemeralSnapshot> = session
        .content_snapshots
        .iter()
        .map(|s| crate::evidence::EphemeralSnapshot {
            timestamp_ns: s.timestamp_ns,
            content_hash: s.content_hash,
            char_count: s.byte_count,
            message: s.message.clone(),
        })
        .collect();

    crate::war::build_signed_ephemeral_block(
        final_hash_hex,
        statement,
        &session.context_label,
        &snapshots,
        &session.jitter_intervals,
        session.keystroke_count,
        &signing_key,
    )
}

/// Flush ephemeral session state to disk for crash recovery.
fn flush_session_state_fields(
    session_id: &str,
    context_label: &str,
    started_at_ns: i64,
    checkpoint_count: u64,
    keystroke_count: u64,
    jitter_count: usize,
) {
    let Some(data_dir) = get_data_dir() else {
        return;
    };
    let recovery_dir = data_dir.join("ephemeral-sessions");
    if std::fs::create_dir_all(&recovery_dir).is_err() {
        return;
    }

    let state = serde_json::json!({
        "session_id": session_id,
        "context_label": context_label,
        "started_at_ns": started_at_ns,
        "checkpoint_count": checkpoint_count,
        "keystroke_count": keystroke_count,
        "jitter_count": jitter_count,
    });

    let path = recovery_dir.join(format!("{session_id}.json"));
    // Use a per-invocation unique suffix to prevent concurrent writes for the
    // same session_id from corrupting each other's temp file.
    let tmp_suffix = {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    };
    let tmp_path = recovery_dir.join(format!("{session_id}.{tmp_suffix}.json.tmp"));
    if let Ok(bytes) = serde_json::to_vec_pretty(&state) {
        if let Err(e) =
            std::fs::write(&tmp_path, &bytes).and_then(|_| std::fs::rename(&tmp_path, &path))
        {
            log::warn!("Failed to persist ephemeral session {session_id}: {e}");
        }
    }
}

fn flush_session_state(session_id: &str, session: &EphemeralSession) {
    flush_session_state_fields(
        session_id,
        &session.context_label,
        session.started_at_ns,
        session.checkpoint_count,
        session.keystroke_count,
        session.jitter_intervals.len(),
    );
}

/// Remove crash-recovery state after successful finalization.
fn cleanup_session_state(session_id: &str) {
    let Some(data_dir) = get_data_dir() else {
        return;
    };
    let path = data_dir
        .join("ephemeral-sessions")
        .join(format!("{session_id}.json"));
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_ephemeral_session() {
        let result = ffi_start_ephemeral_session("test email".to_string());
        assert!(result.success);
        assert!(!result.session_id.is_empty());
        assert!(result.error_message.is_none());

        sessions().remove(&result.session_id);
    }

    #[test]
    fn test_ephemeral_checkpoint() {
        let start = ffi_start_ephemeral_session("test checkpoint".to_string());
        let sid = start.session_id.clone();

        let cp = ffi_ephemeral_checkpoint(sid.clone(), "Hello world".to_string(), "draft".into());
        assert!(cp.success);

        let status = ffi_ephemeral_status(sid.clone());
        assert!(status.success);
        assert_eq!(status.checkpoint_count, 1);

        sessions().remove(&sid);
    }

    #[test]
    fn test_ephemeral_inject_jitter() {
        let start = ffi_start_ephemeral_session("test jitter".to_string());
        let sid = start.session_id.clone();

        let intervals = vec![50_000, 80_000, 120_000, 5, 15_000_000]; // 3 valid, 2 out of range
        let result = ffi_ephemeral_inject_jitter(sid.clone(), intervals);
        assert!(result.success);

        let status = ffi_ephemeral_status(sid.clone());
        assert_eq!(status.keystroke_count, 3);

        sessions().remove(&sid);
    }

    #[test]
    fn test_ephemeral_status_no_session() {
        let status = ffi_ephemeral_status("nonexistent".to_string());
        assert!(!status.success);
        assert!(status.error_message.is_some());
    }

    #[test]
    fn test_finalize_no_checkpoints() {
        let start = ffi_start_ephemeral_session("test finalize empty".to_string());
        let result = ffi_ephemeral_finalize(
            start.session_id,
            "content".to_string(),
            "statement".to_string(),
        );
        assert!(!result.success);
        assert!(result
            .error_message
            .unwrap_or_default()
            .contains("No checkpoints"));
    }
}
