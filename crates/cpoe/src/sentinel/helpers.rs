// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::shadow::ShadowManager;
use super::types::*;
use crate::config::SentinelConfig;
use crate::wal::{EntryType, Wal};

use crate::RwLockRecover;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

// Synchronous event handlers — avoids Send issues with RwLock guards across .await
#[allow(clippy::too_many_arguments)]
pub fn handle_focus_event_sync(
    event: FocusEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    config: &SentinelConfig,
    shadow: &Arc<ShadowManager>,
    signing_key: &Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    current_focus: &Arc<RwLock<Option<String>>>,
    targeted_path: &Arc<RwLock<Option<String>>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    // Targeted mode: only process focus events for the pinned document.
    // Empty-path events (FocusLost from apps that don't report paths) are
    // allowed through so the targeted document's focus state updates correctly.
    if let Some(ref target) = *targeted_path.read_recover() {
        if !event.path.is_empty() && event.path != *target {
            super::trace!(
                "[FOCUS] targeted mode: ignoring {:?} (target={:?})",
                event.path,
                target
            );
            return;
        }
    }
    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        if let Ok(d) = std::env::var("CPOE_DATA_DIR") {
            let debug_path = format!("{}/event_debug.txt", d);
            if let Ok(mut f) = open_nofollow_append(&debug_path) {
                let _ = writeln!(
                    f,
                    "HANDLE_FOCUS: type={:?} bundle={} path={:?} shadow={}",
                    event.event_type, event.app_bundle_id, event.path, event.shadow_id
                );
            }
        }
    }

    super::trace!(
        "[FOCUS] type={:?} bundle={} path={:?} app={}",
        event.event_type,
        event.app_bundle_id,
        event.path,
        event.app_name
    );

    if !config.is_app_allowed(&event.app_bundle_id, &event.app_name) {
        super::trace!(
            "[FOCUS] BLOCKED app={} bundle={}",
            event.app_name,
            event.app_bundle_id
        );
        let path_to_unfocus = {
            let focus = current_focus.read_recover();
            focus.clone()
        };
        if let Some(path) = path_to_unfocus {
            super::trace!("[FOCUS] unfocusing {:?} due to blocked app", path);
            unfocus_document_sync(&path, sessions, session_events_tx);
            *current_focus.write_recover() = None;
        }
        return;
    }

    // Opt-out filtering: exclude paths and non-allowed extensions.
    // Virtual paths (title://, shadow://) and empty paths always pass.
    if !event.path.is_empty()
        && !event.path.starts_with("title://")
        && !event.path.starts_with("shadow://")
    {
        let p = Path::new(&event.path);
        if config.is_path_excluded(p) {
            super::trace!("[FOCUS] EXCLUDED path={:?}", event.path);
            return;
        }
        if !config.is_extension_allowed(p) {
            super::trace!("[FOCUS] EXTENSION NOT ALLOWED path={:?}", event.path);
            return;
        }
    }

    match event.event_type {
        FocusEventType::FocusGained => {
            let doc_path = if event.path.is_empty() {
                if !event.shadow_id.is_empty() {
                    super::trace!("[FOCUS] using shadow://{}", event.shadow_id);
                    format!("shadow://{}", event.shadow_id)
                } else {
                    let fallback = { current_focus.read_recover().clone() };
                    if let Some(path) = fallback {
                        super::trace!("[FOCUS] empty path, fallback to {:?}", path);
                        if let Some(session) = sessions.write_recover().get_mut(path.as_str()) {
                            session.focus_gained();
                        }
                        return;
                    }
                    super::trace!("[FOCUS] empty path, no fallback, dropping");
                    return;
                }
            } else {
                event.path.clone()
            };

            super::trace!("[FOCUS] doc_path={:?}", doc_path);

            let path_to_unfocus = {
                let focus = current_focus.read_recover();
                if let Some(ref current) = *focus {
                    if *current != doc_path {
                        Some(current.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            // Single write lock for the entire unfocus + regained_at stamp
            // to prevent TOCTOU races between lock acquisitions.
            {
                let mut sessions_map = sessions.write_recover();

                // Record focus switch and unfocus the previous document.
                if let Some(ref path) = path_to_unfocus {
                    if let Some(session) = sessions_map.get_mut(path.as_str()) {
                        if session.focus_switches.len() >= super::types::MAX_FOCUS_SWITCHES {
                            session.focus_switches.pop_front();
                        }
                        session.focus_switches.push_back(FocusSwitchRecord {
                            lost_at: SystemTime::now(),
                            regained_at: None,
                            target_app: event.app_name.clone(),
                            target_bundle_id: event.app_bundle_id.clone(),
                        });
                        session.focus_lost();
                        let _ = session_events_tx.send(SessionEvent {
                            event_type: SessionEventType::Unfocused,
                            session_id: session.session_id.clone(),
                            document_path: path.to_string(),
                            timestamp: SystemTime::now(),
                            hash: None,
                        });
                    }
                }

                // If this document is regaining focus, stamp regained_at on its
                // most recent open switch record.
                if let Some(session) = sessions_map.get_mut(doc_path.as_str()) {
                    if let Some(last) = session.focus_switches.back_mut() {
                        if last.regained_at.is_none() {
                            last.regained_at = Some(SystemTime::now());
                        }
                    }
                }
            }

            if path_to_unfocus.is_some() {
                *current_focus.write_recover() = None;
            }

            focus_document_sync(
                &doc_path,
                &event,
                sessions,
                config,
                shadow,
                signing_key,
                wal_dir,
                session_events_tx,
            );
            super::trace!("[FOCUS] set current_focus={:?}", doc_path);
            *current_focus.write_recover() = Some(doc_path);
        }
        FocusEventType::FocusLost | FocusEventType::FocusUnknown => {
            let prev_path = {
                let focus = current_focus.read_recover();
                focus.clone()
            };
            super::trace!(
                "[FOCUS] FocusLost, clearing current_focus (was {:?})",
                prev_path
            );
            if let Some(path) = prev_path {
                unfocus_document_sync(&path, sessions, session_events_tx);
                *current_focus.write_recover() = None;
            }
        }
    }
}

/// Maximum file size (10 MB) for initial hash computation during focus tracking.
/// Files larger than this are skipped to avoid blocking the sessions write lock.
const MAX_HASH_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// File extensions that should never be tracked as authored documents.
const NON_DOCUMENT_EXTENSIONS: &[&str] = &[
    "mov", "mp4", "avi", "mkv", "webm", // video
    "mp3", "wav", "aac", "flac", "ogg", // audio
    "dmg", "iso", "img", "pkg", // disk images
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", // archives
    "app", "exe", "dll", "dylib", "so", // binaries
    "o", "a", "lib", // object files
];

#[allow(clippy::too_many_arguments)]
pub fn focus_document_sync(
    path: &str,
    event: &FocusEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    _config: &SentinelConfig,
    _shadow: &Arc<ShadowManager>,
    signing_key: &Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    // Skip directories and paths that don't look like documents.
    // Virtual keys (shadow://, title://) bypass filesystem checks.
    if !path.starts_with("shadow://") {
        let p = std::path::Path::new(path);
        if p.is_dir() {
            return;
        }
        // Block known non-document extensions (media, archives, binaries).
        // Files without extensions are allowed through; many legitimate
        // documents (README, Makefile, cloud app exports) have no extension.
        if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            if NON_DOCUMENT_EXTENSIONS.contains(&ext.to_lowercase().as_str()) {
                return;
            }
        }
    }

    // Fast path: if the session already exists, skip expensive I/O (file
    // hashing, SQLite open) and just update focus state under the write lock.
    let already_tracked = sessions.read_recover().contains_key(path);

    let (pre_hash, pre_stats, key) = if already_tracked {
        (None, None, signing_key.read_recover().key())
    } else {
        // Compute file hash and load cumulative stats before acquiring the
        // sessions write lock to avoid blocking keystroke counting during I/O.
        // We also record the mtime so we can detect staleness inside the lock.
        let (hash, _pre_mtime) = if !path.starts_with("shadow://") {
            match open_nofollow(path) {
                Ok(file) => match file.metadata() {
                    Ok(meta) if meta.len() <= MAX_HASH_FILE_SIZE => {
                        let mtime = meta.modified().ok();
                        let h = crate::crypto::hash_file_handle(file)
                            .ok()
                            .map(|(h, _)| hex::encode(h));
                        (h, mtime)
                    }
                    _ => (None, None),
                },
                Err(_) => (None, None),
            }
        } else {
            (None, None)
        };
        let k = signing_key.read_recover().key();
        // If the key just became available, drain any WAL entries that were
        // buffered while the BehavioralKey was locked.
        if let Some(ref sk) = k {
            drain_pending_wal(sk);
        }
        let stats = {
            let db_path = wal_dir.parent().unwrap_or(wal_dir).join("events.db");
            k.as_ref().and_then(|sk| {
                crate::store::open_store_with_signing_key(sk, &db_path)
                    .ok()
                    .and_then(|store| store.load_document_stats(path).ok().flatten())
            })
        };
        (hash, stats, k)
    };

    let new_session_info = {
        let mut sessions_map = sessions.write_recover();
        let was_new = !sessions_map.contains_key(path);

        let session = sessions_map.entry(path.to_string()).or_insert_with(|| {
            let mut session = DocumentSession::new(
                path.to_string(),
                event.app_bundle_id.clone(),
                event.app_name.clone(),
                event.window_title.clone(),
            );

            if is_temporary_path(&session.path) {
                session.origin_temp_path = Some(session.path.clone());
            }

            if let Some(ref hash) = pre_hash {
                session.initial_hash = Some(hash.clone());
                session.current_hash = Some(hash.clone());
            }

            if let Some(ref stats) = pre_stats {
                session.cumulative_keystrokes_base =
                    u64::try_from(stats.total_keystrokes).unwrap_or(0);
                session.cumulative_focus_ms_base = stats.total_focus_ms;
                session.session_number = u32::try_from(stats.session_count).unwrap_or(0);
            }

            session
        });

        session.focus_gained();
        session.window_title = event.window_title.clone();

        if was_new {
            Some((
                session.session_id.clone(),
                create_session_start_payload(session),
            ))
        } else {
            None
        }
    }; // write lock released here

    // WAL append and event broadcast happen outside the lock
    if let Some((session_id, payload)) = new_session_info {
        wal_append_session_event(&session_id, wal_dir, key, EntryType::SessionStart, payload);

        // Intentionally ignored: broadcast send fails only when no receivers are subscribed
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Started,
            session_id: session_id.clone(),
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
            hash: pre_hash,
        });
    }

    #[cfg(debug_assertions)]
    let focus_count = sessions
        .read_recover()
        .get(path)
        .map(|s| s.focus_count)
        .unwrap_or(0);

    #[cfg(debug_assertions)]
    {
        use std::io::Write;
        if let Ok(d) = std::env::var("CPOE_DATA_DIR") {
            let debug_path = format!("{}/event_debug.txt", d);
            if let Ok(mut f) = open_nofollow_append(&debug_path) {
                let _ = writeln!(
                    f,
                    "SESSION_FOCUSED: path={} focus_count={}",
                    path, focus_count
                );
            }
        }
    }

    // Read back session_id for the Focused event
    if let Some(session_id) = sessions
        .read_recover()
        .get(path)
        .map(|s| s.session_id.clone())
    {
        // Intentionally ignored: broadcast send fails only when no receivers are subscribed
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Focused,
            session_id,
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
            hash: None,
        });
    }
}

pub fn unfocus_document_sync(
    path: &str,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let mut sessions_map = sessions.write_recover();

    if let Some(session) = sessions_map.get_mut(path) {
        session.focus_lost();

        // Intentionally ignored: broadcast send fails only when no receivers are subscribed
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Unfocused,
            session_id: session.session_id.clone(),
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
            hash: None,
        });
    }
}

pub fn handle_change_event_sync(
    event: &ChangeEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    config: &SentinelConfig,
    signing_key: &Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
    current_focus_opt: Option<&Arc<RwLock<Option<String>>>>,
) {
    // SQLite WAL/SHM/journal files from container-based apps (Bear, Day One) signal
    // a database write. They bypass the extension filter and are handled separately.
    let is_wal_event = is_sqlite_auxiliary_file(&event.path);

    // Bundle documents (.scriv, .pages, .rtfd): extract the package root so
    // internal file changes contribute to the same session checkpoint.
    let normalized_path = if !is_wal_event {
        extract_bundle_package_root(&event.path).unwrap_or_else(|| event.path.clone())
    } else {
        event.path.clone()
    };

    // Opt-out filtering: exclude paths and non-allowed extensions.
    // WAL auxiliary files bypass this block; they have no trackable document path.
    if !is_wal_event
        && !normalized_path.is_empty()
        && !normalized_path.starts_with("title://")
        && !normalized_path.starts_with("shadow://")
    {
        let p = Path::new(&normalized_path);
        if config.is_path_excluded(p) {
            return;
        }
        if !config.is_extension_allowed(p) {
            return;
        }
    }

    // WAL pseudo-save: treat a SQLite auxiliary write as a Saved event on the
    // currently focused session. Read current_focus before acquiring sessions to
    // maintain lock order (current_focus → sessions).
    if is_wal_event {
        let focused_path_opt = current_focus_opt.and_then(|cf| cf.read_recover().clone());
        if let Some(ref focused_path) = focused_path_opt {
            let mut sessions_map = sessions.write_recover();
            if let Some(session) = sessions_map.get_mut(focused_path.as_str()) {
                session.save_count += 1;
                let _ = session_events_tx.send(SessionEvent {
                    event_type: SessionEventType::Saved,
                    session_id: session.session_id.clone(),
                    document_path: focused_path.clone(),
                    timestamp: SystemTime::now(),
                    hash: session.current_hash.clone(),
                });
            }
        }
        return;
    }

    // Acquire signing_key before sessions to match lock order in focus_document_sync
    let key = signing_key.read_recover().key();
    let mut sessions_map = sessions.write_recover();

    // Handle Renamed and Deleted first: they remove the entry from the map
    // and don't need a mutable reference through get_mut.
    match event.event_type {
        ChangeEventType::Deleted => {
            let removed = sessions_map.remove(&normalized_path);
            drop(sessions_map);
            if let Some(session) = removed {
                let _ = session_events_tx.send(SessionEvent {
                    event_type: SessionEventType::Ended,
                    session_id: session.session_id,
                    document_path: normalized_path.clone(),
                    timestamp: SystemTime::now(),
                    hash: session.current_hash,
                });
            }
            return;
        }
        ChangeEventType::Renamed { ref new_path } => {
            let new_path = new_path.clone();
            if sessions_map.contains_key(&new_path) {
                log::warn!(
                    "Rename target already tracked, ignoring: {} -> {}",
                    normalized_path,
                    new_path
                );
                return;
            }
            let mut session = match sessions_map.remove(&normalized_path) {
                Some(s) => s,
                None => return,
            };
            let old_path = session.path.clone();
            // Preserve origin when a file migrates from a temporary location
            // (email attachment, download) to a permanent save path.
            if is_temporary_path(&old_path) && !is_temporary_path(&new_path) {
                if session.origin_temp_path.is_none() {
                    session.origin_temp_path = Some(old_path.clone());
                }
                log::info!(
                    "File migrated from temp to permanent: {} -> {}",
                    old_path,
                    new_path
                );
            }
            session.path = new_path.clone();
            let session_id = session.session_id.clone();
            sessions_map.insert(new_path.clone(), session);
            drop(sessions_map);

            let old_bytes = old_path.as_bytes();
            let new_bytes = new_path.as_bytes();
            let mut payload = Vec::with_capacity(4 + old_bytes.len() + 4 + new_bytes.len());
            payload.extend_from_slice(
                &u32::try_from(old_bytes.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            payload.extend_from_slice(old_bytes);
            payload.extend_from_slice(
                &u32::try_from(new_bytes.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            payload.extend_from_slice(new_bytes);
            wal_append_session_event(
                &session_id,
                wal_dir,
                key.clone(),
                EntryType::PathChange,
                payload,
            );

            if let Some(current_focus) = current_focus_opt {
                let mut focus = current_focus.write_recover();
                if focus.as_deref() == Some(old_path.as_str()) {
                    *focus = Some(new_path.clone());
                }
            }

            let _ = session_events_tx.send(SessionEvent {
                event_type: SessionEventType::Renamed,
                session_id,
                document_path: new_path,
                timestamp: SystemTime::now(),
                hash: None,
            });
            return;
        }
        _ => {}
    }

    if let Some(session) = sessions_map.get_mut(&normalized_path) {
        match event.event_type {
            ChangeEventType::Saved => {
                session.save_count += 1;

                let current_hash = event
                    .hash
                    .clone()
                    .or_else(|| compute_file_hash(&normalized_path).ok());
                session.current_hash = current_hash.clone();

                if let Some(hash) = current_hash {
                    match create_document_hash_payload(&hash, event.size.unwrap_or(0)) {
                        Ok(payload) => wal_append_session_event(
                            &session.session_id,
                            wal_dir,
                            key.clone(),
                            EntryType::DocumentHash,
                            payload,
                        ),
                        Err(e) => log::error!("Failed to build document hash payload: {e}"),
                    }
                }

                let _ = session_events_tx.send(SessionEvent {
                    event_type: SessionEventType::Saved,
                    session_id: session.session_id.clone(),
                    document_path: normalized_path.clone(),
                    timestamp: SystemTime::now(),
                    hash: session.current_hash.clone(),
                });
            }
            ChangeEventType::Modified => {
                session.change_count += 1;
                if let Some(hash) = &event.hash {
                    session.current_hash = Some(hash.clone());
                }
            }
            ChangeEventType::Created => {
                // Picked up on next focus event
            }
            ChangeEventType::Deleted | ChangeEventType::Renamed { .. } => {
                unreachable!("handled above")
            }
        }
    }
}

pub fn check_idle_sessions_sync(
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    idle_timeout: std::time::Duration,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let sessions_to_end: Vec<String> = {
        let sessions_map = sessions.read_recover();
        sessions_map
            .iter()
            .filter(|(_, session)| {
                !session.is_focused()
                    && session
                        .last_focus_time
                        .elapsed()
                        .map(|d| d > idle_timeout)
                        .unwrap_or(false)
            })
            .map(|(path, _)| path.clone())
            .collect()
    };

    for path in sessions_to_end {
        end_session_sync(&path, sessions, session_events_tx);
    }
}

pub fn end_session_sync(
    path: &str,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let session = sessions.write_recover().remove(path);

    if let Some(session) = session {
        // Intentionally ignored: broadcast send fails only when no receivers are subscribed
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Ended,
            session_id: session.session_id,
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
            hash: session.current_hash,
        });
    }
}

pub fn end_all_sessions_sync(
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    shadow: &Arc<ShadowManager>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let all_sessions: Vec<_> = sessions.write_recover().drain().collect();

    for (path, session) in all_sessions {
        // Intentionally ignored: broadcast send fails only when no receivers are subscribed
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Ended,
            session_id: session.session_id,
            document_path: path,
            timestamp: SystemTime::now(),
            hash: session.current_hash,
        });

        if let Some(shadow_id) = session.shadow_id {
            if let Err(e) = shadow.delete(&shadow_id) {
                log::warn!("shadow buffer cleanup failed for {shadow_id}: {e}");
            }
        }
    }
}

/// Pending WAL entry buffered while the signing key was unavailable.
struct PendingWalEntry {
    session_id: String,
    session_id_bytes: [u8; 32],
    wal_dir: PathBuf,
    entry_type: EntryType,
    payload: Vec<u8>,
}

/// Maximum buffered WAL entries before oldest are dropped.
const MAX_PENDING_WAL_ENTRIES: usize = 256;

static PENDING_WAL: std::sync::Mutex<Vec<PendingWalEntry>> = std::sync::Mutex::new(Vec::new());

/// Drain any buffered WAL entries now that a signing key is available.
/// Called from `focus_document_sync` and checkpoint paths when a key is obtained.
pub(super) fn drain_pending_wal(key: &SigningKey) {
    use crate::MutexRecover;
    let entries: Vec<PendingWalEntry> = {
        let mut pending = PENDING_WAL.lock_recover();
        std::mem::take(&mut *pending)
    };
    if entries.is_empty() {
        return;
    }
    log::info!("Draining {} buffered WAL entries", entries.len());
    for entry in entries {
        let wal_path = entry.wal_dir.join(format!("{}.wal", entry.session_id));
        match Wal::open(&wal_path, entry.session_id_bytes, key.clone()) {
            Ok(wal) => {
                if let Err(e) = wal.append(entry.entry_type, entry.payload) {
                    log::error!(
                        "WAL append (deferred) failed for session {}: {}",
                        entry.session_id,
                        e
                    );
                }
            }
            Err(e) => {
                log::error!(
                    "WAL open (deferred) failed for session {}: {}",
                    entry.session_id,
                    e
                );
            }
        }
    }
}

/// Append an entry to the session's WAL file, handling hex decode, key check, and errors.
/// If the signing key is unavailable, the entry is buffered for later draining.
fn wal_append_session_event(
    session_id: &str,
    wal_dir: &Path,
    key: Option<SigningKey>,
    entry_type: EntryType,
    payload: Vec<u8>,
) {
    let mut session_id_bytes = [0u8; 32];
    let hex_str = session_id
        .get(..64.min(session_id.len()))
        .unwrap_or(session_id);
    if hex::decode_to_slice(hex_str, &mut session_id_bytes).is_err() {
        log::error!("Invalid session ID hex: {}", session_id);
        return;
    }

    if let Some(key) = key {
        let wal_path = wal_dir.join(format!("{}.wal", session_id));
        match Wal::open(&wal_path, session_id_bytes, key) {
            Ok(wal) => {
                if let Err(e) = wal.append(entry_type, payload) {
                    log::error!("WAL append failed for session {}: {}", session_id, e);
                }
            }
            Err(e) => {
                log::error!("WAL open failed for session {}: {}", session_id, e);
            }
        }
    } else {
        use crate::MutexRecover;
        let mut pending = PENDING_WAL.lock_recover();
        if pending.len() >= MAX_PENDING_WAL_ENTRIES {
            log::warn!(
                "Pending WAL buffer full ({MAX_PENDING_WAL_ENTRIES}); dropping oldest entry"
            );
            pending.remove(0);
        }
        log::warn!(
            "Signing key unavailable; buffering WAL entry for session {} ({} pending)",
            session_id,
            pending.len() + 1
        );
        pending.push(PendingWalEntry {
            session_id: session_id.to_string(),
            session_id_bytes,
            wal_dir: wal_dir.to_path_buf(),
            entry_type,
            payload,
        });
    }
}

/// Check whether a path is in a macOS temporary directory.
///
/// Detects paths from email attachments, downloads-in-progress, and other
/// transient locations that may be saved permanently later. Used to tag
/// sessions with their origin so evidence shows the file started as an
/// attachment/download.
pub fn is_temporary_path(path: &str) -> bool {
    // Common macOS temp prefixes. /private/tmp and /private/var/folders are
    // the canonical forms; /tmp and /var/folders are symlinks to them.
    const TEMP_PREFIXES: &[&str] = &[
        "/tmp/",
        "/private/tmp/",
        "/var/folders/",
        "/private/var/folders/",
    ];
    for prefix in TEMP_PREFIXES {
        if path.starts_with(prefix) {
            return true;
        }
    }
    // ~/Library/Caches/ — apps stage downloads and attachments here.
    if let Some(home) = dirs::home_dir() {
        let caches = format!("{}/Library/Caches/", home.display());
        if path.starts_with(&caches) {
            return true;
        }
    }
    false
}

/// Detect SQLite auxiliary files (WAL, SHM, journal) that signal a database write.
/// These files bypass the extension filter and trigger pseudo-save events on the
/// currently focused document when they arrive from known database-backed apps
/// (Bear, Day One, etc.).
fn is_sqlite_auxiliary_file(path: &str) -> bool {
    let p = Path::new(path);
    let file_name = match p.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };

    // Match SQLite auxiliary file patterns: db-wal, db-shm, db-journal
    file_name.ends_with("-wal")
        || file_name.ends_with("-shm")
        || file_name.ends_with("-journal")
        || file_name.ends_with(".sqlite-wal")
        || file_name.ends_with(".sqlite-shm")
        || file_name.ends_with(".sqlite-journal")
        || file_name.ends_with(".db-wal")
        || file_name.ends_with(".db-shm")
        || file_name.ends_with(".db-journal")
}

/// Bundle document extensions whose internal file changes should be
/// attributed to the package root rather than individual files inside.
const BUNDLE_DOC_EXTENSIONS: &[&str] = &[".scriv", ".pages", ".rtfd"];

/// Extract the bundle document root from a nested internal path.
///
/// macOS "package" documents store content inside a directory that looks
/// like a single file in Finder:
///   - Scrivener: Project.scriv/Files/Data/<UUID>/content.rtf
///   - Pages:     Document.pages/Index/Tables/DataList-…
///   - RTFD:      Note.rtfd/TXT.rtf  (rich text with attachments)
///
/// This function walks up the path looking for a directory whose name
/// ends with one of the known bundle extensions and returns it, so
/// checkpoint events are associated with the package rather than
/// individual internal files.
fn extract_bundle_package_root(path: &str) -> Option<String> {
    let p = Path::new(path);

    for ancestor in p.ancestors() {
        if let Some(file_name) = ancestor.file_name().and_then(|n| n.to_str()) {
            for ext in BUNDLE_DOC_EXTENSIONS {
                if file_name.ends_with(ext) {
                    return ancestor.to_str().map(|s| s.to_string());
                }
            }
        }
    }

    None
}

pub fn compute_file_hash(path: &str) -> std::io::Result<String> {
    let file = open_nofollow(path)?;
    let meta = file.metadata()?;
    if meta.len() > MAX_HASH_FILE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "file too large to hash ({} bytes, limit {})",
                meta.len(),
                MAX_HASH_FILE_SIZE
            ),
        ));
    }
    let (hash, _) = crate::crypto::hash_file_handle(file)?;
    Ok(hex::encode(hash))
}

/// Open a file with O_NOFOLLOW to prevent symlink-following TOCTOU attacks.
#[cfg(unix)]
fn open_nofollow(path: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_nofollow(path: &str) -> std::io::Result<std::fs::File> {
    // H-010: Reject symlinks on non-Unix platforms before opening.
    // symlink_metadata does not follow symlinks, so is_symlink() is reliable here.
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "symlinks are not accepted for file hashing",
        ));
    }
    std::fs::File::open(path)
}

#[cfg(all(debug_assertions, unix))]
fn open_nofollow_append(path: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(all(debug_assertions, not(unix)))]
fn open_nofollow_append(path: &str) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

pub fn create_session_start_payload(session: &DocumentSession) -> Vec<u8> {
    // Binary format: path_len(4) | path | hash(32) | timestamp(8)
    let path_bytes = session.path.as_bytes();
    let mut payload = Vec::with_capacity(4 + path_bytes.len() + 32 + 8);

    payload.extend_from_slice(
        &u32::try_from(path_bytes.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    payload.extend_from_slice(path_bytes);

    let hash_bytes = session
        .initial_hash
        .as_ref()
        .and_then(|h| match hex::decode(h) {
            Ok(bytes) if bytes.len() == 32 => Some(bytes),
            Ok(bytes) => {
                log::warn!(
                    "Initial hash '{}' decoded to {} bytes, expected 32",
                    h,
                    bytes.len()
                );
                None
            }
            Err(e) => {
                log::warn!("Failed to decode initial hash '{}': {}", h, e);
                None
            }
        })
        .unwrap_or_else(|| {
            log::debug!("No initial hash available for session, using zero hash");
            vec![0u8; 32]
        });
    let hash_fixed: [u8; 32] = hash_bytes.as_slice().try_into().unwrap_or_default();
    payload.extend_from_slice(&hash_fixed);

    let timestamp = session
        .start_time
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    payload.extend_from_slice(&timestamp.to_be_bytes());

    payload
}

pub fn create_document_hash_payload(hash: &str, size: i64) -> Result<Vec<u8>, String> {
    let hash_bytes =
        hex::decode(hash).map_err(|e| format!("Failed to decode hash '{}': {}", hash, e))?;
    if hash_bytes.len() != 32 {
        return Err(format!(
            "Hash '{}' decoded to {} bytes, expected 32",
            hash,
            hash_bytes.len()
        ));
    }
    let mut payload = Vec::with_capacity(32 + 8 + 8);

    let mut hash_fixed = [0u8; 32];
    hash_fixed.copy_from_slice(&hash_bytes);
    payload.extend_from_slice(&hash_fixed);
    if size < 0 {
        return Err(format!("Negative file size: {}", size));
    }
    payload.extend_from_slice(&(size as u64).to_be_bytes());

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    payload.extend_from_slice(&timestamp.to_be_bytes());

    Ok(payload)
}

/// Canonicalize and validate a user-provided path against traversal attacks.
pub fn validate_path(path: impl AsRef<Path>) -> Result<PathBuf, String> {
    let path = path.as_ref();

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!("Symlinks not accepted: {}", path.display()));
        }
    }

    if path.exists() {
        let canonical = path
            .canonicalize()
            .map_err(|e| format!("Invalid path '{}': {}", path.display(), e))?;
        validate_canonical_path(&canonical)?;
        return Ok(canonical);
    }

    let parent = path
        .parent()
        .ok_or_else(|| "Invalid path: no parent".to_string())?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|e| format!("Invalid parent directory for '{}': {}", path.display(), e))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| "Invalid path: no file name".to_string())?;
    let canonical = canonical_parent.join(file_name);

    validate_canonical_path(&canonical)?;
    Ok(canonical)
}

/// Key material file names that must never be overwritten via export paths.
const KEY_MATERIAL_NAMES: &[&str] = &[
    "signing_key",
    ".storage_key",
    "puf_seed",
    "sealed_identity",
    "identity.key",
    "session.key",
];

fn validate_canonical_path(path: &Path) -> Result<(), String> {
    if crate::ipc::messages::is_blocked_system_path(path)? {
        return Err("Access to system directory denied".to_string());
    }
    // EH-046: Reject paths that would overwrite key material files.
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        for &key_name in KEY_MATERIAL_NAMES {
            if name == key_name {
                return Err(format!("Refusing to overwrite key material file: {}", name));
            }
        }
    }
    Ok(())
}

/// Try to perform an entangled hardware co-signature on a document session.
///
/// Checks the scheduler threshold, computes the entangled hash (binding document
/// content, device time, device identity, and the previous HW signature), signs
/// with the TPM/Secure Enclave, and persists the result to the event store.
/// Returns `true` if a co-signature was performed.
/// Try to perform an entangled hardware co-signature on a document session.
///
/// The entangled hash binds: content_hash + event_hash (HMAC chain) +
/// clock + monotonic_counter + device_id + previous HW signature.
/// This mirrors `Packet::compute_hw_cosign_hash` but uses the event HMAC
/// as the software binding (the Ed25519 packet signature doesn't exist yet
/// at checkpoint time).
pub(crate) fn try_hw_cosign(
    session: &mut DocumentSession,
    tpm: &dyn crate::tpm::Provider,
    content_hash: &[u8; 32],
    event_hash: Option<&[u8; 32]>,
    store: Option<(&crate::store::SecureStore, &str)>,
) -> bool {
    let sched = match session.hw_cosign_scheduler.as_mut() {
        Some(s) => s,
        None => return false,
    };
    if !sched.record_checkpoint() {
        return false;
    }

    let clock_info = tpm.clock_info().ok();
    let clock_ms = clock_info.as_ref().map(|c| c.clock).unwrap_or(0);
    let caps = tpm.capabilities();
    let counter = if caps.monotonic_counter {
        clock_info
            .as_ref()
            .map(|c| u64::from(c.reset_count))
            .unwrap_or(0)
    } else {
        clock_ms
    };
    let device_id = tpm.device_id();
    let public_key = tpm.public_key();
    let prev_sig = session.last_hw_cosign_signature.as_deref().unwrap_or(&[]);
    let empty_hash = [0u8; 32];
    let sw_binding: &[u8] = event_hash.map(|h| h.as_slice()).unwrap_or(&empty_hash);

    let entangled_hash = crate::evidence::compute_hw_entangled_hash(
        content_hash,
        sw_binding,
        clock_ms,
        counter,
        &device_id,
        &public_key,
        prev_sig,
    );

    let sig = match tpm.sign(&entangled_hash) {
        Ok(s) => s,
        Err(_) => {
            sched.reset_after_cosign();
            return false;
        }
    };

    let chain_idx = session.hw_cosign_chain_index;
    session.hw_cosign_chain_index += 1;
    let salt_commit = sched.salt_commitment();
    let (ent_digest, ent_bytes) = sched.flush_entropy();

    if let Some((store, path)) = store {
        if let Err(e) = store.update_hw_cosign(
            path,
            &sig,
            &tpm.public_key(),
            &salt_commit,
            chain_idx,
            &entangled_hash,
            Some(&ent_digest),
            Some(ent_bytes as u64),
        ) {
            log::error!("HW co-sign persistence failed for {}: {e}", path);
        }
    }

    session.last_hw_cosign_signature = Some(sig);
    sched.reset_after_cosign();
    true
}

/// Detect if current keystroke follows a paste event.
///
/// Returns: (KeystrokeContext, confidence: 0.0-1.0)
///
/// Decision logic (2/3 signals required):
/// - Signal 1: Keystroke silence >500ms after last keystroke
/// - Signal 2: Text hash discontinuity from previous keystroke
/// - Signal 3: App/window transition detected
///
/// Confidence calculation:
/// - 3/3 signals: 0.99 (extremely confident)
/// - 2/3 signals: 0.85-0.92 (confident)
/// - 1/3 signals: 0.60-0.70 (uncertain)
/// - 0/3 signals: 0.20 (likely original composition)
pub fn detect_paste_boundary(
    last_keystroke_timestamp: i64,
    current_timestamp: i64,
    accumulated_text_hash: &[u8; 32],
    new_text_hash: &[u8; 32],
    app_focused_at_time: &str,
    previous_focused_app: &str,
) -> (super::types::KeystrokeContext, f64) {
    if last_keystroke_timestamp == 0 {
        return (super::types::KeystrokeContext::OriginalComposition, 0.20);
    }
    if current_timestamp < last_keystroke_timestamp {
        log::warn!(
            "Timestamp regression in paste detection: current={} < last={}",
            current_timestamp,
            last_keystroke_timestamp
        );
        return (super::types::KeystrokeContext::PastedContent, 0.80);
    }

    let mut signals = 0;
    let time_delta_ms = (current_timestamp - last_keystroke_timestamp) / 1_000_000;

    // Signal 1: Keystroke silence >500ms
    if time_delta_ms > 500 {
        signals += 1;
    }

    // Signal 2: Hash discontinuity
    if accumulated_text_hash != new_text_hash {
        signals += 1;
    }

    // Signal 3: App transition
    if app_focused_at_time != previous_focused_app {
        signals += 1;
    }

    match signals {
        3 => (super::types::KeystrokeContext::PastedContent, 0.99),
        2 => {
            let confidence = if time_delta_ms > 2000 { 0.92 } else { 0.85 };
            (super::types::KeystrokeContext::PastedContent, confidence)
        }
        1 => {
            if app_focused_at_time != previous_focused_app {
                (super::types::KeystrokeContext::PastedContent, 0.70)
            } else {
                (super::types::KeystrokeContext::OriginalComposition, 0.60)
            }
        }
        _ => (super::types::KeystrokeContext::OriginalComposition, 0.20),
    }
}

/// Update keystroke context for a session after paste detection.
///
/// Sets a time window during which subsequent keystrokes are marked as PastedContent.
/// Window duration: typically 30 seconds after paste.
///
/// `source` classifies where the pasted content originated. Use
/// [`classify_paste_source`] to derive this from a store lookup before calling.
pub fn update_keystroke_context_window(
    session: &mut super::types::DocumentSession,
    paste_time: i64,
    context_window_ms: u64,
    source: super::types::PasteSource,
) {
    let window_nanos = context_window_ms
        .checked_mul(1_000_000)
        .and_then(|w| i64::try_from(w).ok())
        .unwrap_or(i64::MAX);
    session.paste_context = Some(super::types::PasteContext {
        paste_time,
        context_window_end: paste_time.saturating_add(window_nanos),
        keystroke_count_after_paste: 0,
        source,
    });
}

/// Classify the origin of pasted content by looking up its hash in the store.
///
/// - If the hash matches a fragment from `current_session_id` -> `SameDocument`
/// - If it matches a fragment from a different session -> `OtherDocument`
/// - If no match is found (content came from outside) -> `External`
/// - If the store is unavailable or the lookup fails -> `Unknown`
pub fn classify_paste_source(
    store: Option<&crate::store::SecureStore>,
    text_hash: &[u8; 32],
    current_session_id: &str,
) -> super::types::PasteSource {
    let store = match store {
        Some(s) => s,
        None => return super::types::PasteSource::Unknown,
    };

    match store.lookup_fragment_by_hash(text_hash) {
        Ok(Some(fragment)) => {
            if fragment.session_id == current_session_id {
                super::types::PasteSource::SameDocument
            } else {
                super::types::PasteSource::OtherDocument
            }
        }
        Ok(None) => super::types::PasteSource::External,
        Err(e) => {
            log::warn!("Paste source classification failed: {e}");
            super::types::PasteSource::Unknown
        }
    }
}

/// Check if current keystroke is within paste context window.
pub fn is_within_paste_window(session: &super::types::DocumentSession, current_time: i64) -> bool {
    match &session.paste_context {
        Some(ctx) => current_time < ctx.context_window_end,
        None => false,
    }
}

/// Maximum time allowed for git context capture before abandoning.
const GIT_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Run a git command, returning its stdout on success.
///
/// Returns `None` if the command fails or produces non-UTF-8 output.
fn run_git_command(args: &[&str], cwd: &Path) -> Option<String> {
    use std::process::Command;

    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?
        .wait_with_output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Find the git repository root by walking up from the given path.
///
/// Returns the directory containing `.git` if found, or `None`.
fn find_git_root(file_path: &Path) -> Option<PathBuf> {
    let dir = if file_path.is_file() {
        file_path.parent()?
    } else {
        file_path
    };

    let mut current = dir;
    loop {
        if current.join(".git").exists() {
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }
}

/// Capture git repository context for a tracked file at checkpoint time.
///
/// Checks whether the file lives inside a git repository and, if so,
/// collects branch name, last commit hash, diff statistics, and staging
/// state. All git subprocesses are bounded by a 5-second wall-clock
/// deadline to avoid blocking the checkpoint path.
///
/// Returns `None` if git is not installed, the file is not in a repo,
/// or any git command fails or times out.
pub(super) fn capture_git_context(
    file_path: &Path,
) -> Option<super::types::GitContext> {
    let git_root = find_git_root(file_path)?;

    let file_path_owned = file_path.to_path_buf();
    let git_root_owned = git_root;

    // Run on a dedicated thread with a wall-clock deadline so slow git
    // operations cannot block the checkpoint path indefinitely.
    let handle = std::thread::spawn(move || {
        capture_git_context_inner(&file_path_owned, &git_root_owned)
    });

    match handle.join() {
        Ok(result) => result,
        Err(_) => {
            log::warn!("Git context capture thread panicked");
            None
        }
    }
}

/// Inner implementation of git context capture (runs on a dedicated thread).
fn capture_git_context_inner(
    file_path: &Path,
    git_root: &Path,
) -> Option<super::types::GitContext> {
    let start = std::time::Instant::now();

    let branch = run_git_command(
        &["rev-parse", "--abbrev-ref", "HEAD"],
        git_root,
    )?;
    if start.elapsed() > GIT_COMMAND_TIMEOUT {
        log::warn!("Git context capture timed out after branch query");
        return None;
    }

    let last_commit = run_git_command(
        &["log", "-1", "--format=%H", "--", file_path.to_str()?],
        git_root,
    )
    .unwrap_or_default();
    if start.elapsed() > GIT_COMMAND_TIMEOUT {
        log::warn!("Git context capture timed out after log query");
        return None;
    }

    let diff_stat = run_git_command(
        &["diff", "--numstat", "--", file_path.to_str()?],
        git_root,
    )
    .unwrap_or_default();
    if start.elapsed() > GIT_COMMAND_TIMEOUT {
        log::warn!("Git context capture timed out after diff query");
        return None;
    }

    let (insertions, deletions) = parse_numstat(&diff_stat);

    let staged_stat = run_git_command(
        &["diff", "--cached", "--numstat", "--", file_path.to_str()?],
        git_root,
    )
    .unwrap_or_default();
    let is_staged = !staged_stat.is_empty();

    let (staged_ins, staged_del) = parse_numstat(&staged_stat);
    let insertions = insertions.saturating_add(staged_ins);
    let deletions = deletions.saturating_add(staged_del);

    Some(super::types::GitContext {
        branch,
        last_commit,
        insertions,
        deletions,
        is_staged,
    })
}

/// Parse a single-line `git diff --numstat` output into (insertions, deletions).
///
/// Format: `<insertions>\t<deletions>\t<filename>`
/// Binary files show `-\t-\t<filename>`; those return (0, 0).
fn parse_numstat(line: &str) -> (u32, u32) {
    if line.is_empty() {
        return (0, 0);
    }
    let parts: Vec<&str> = line.split('\t').collect();
    if parts.len() < 2 {
        return (0, 0);
    }
    let ins = parts[0].parse::<u32>().unwrap_or(0);
    let del = parts[1].parse::<u32>().unwrap_or(0);
    (ins, del)
}

/// Hash a file, open the secure store, and write a checkpoint event.
///
/// Returns the committed event hash on success, or `None` on any failure.
/// Extracted from the event loop to eliminate duplicate checkpoint logic
/// between the idle-timeout and periodic-checkpoint timer arms.
pub(super) fn commit_checkpoint_for_path(
    path: &str,
    reason: &str,
    signing_key: &Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    writersproof_dir: &Path,
    challenge_nonce: &Option<String>,
    stopping: &AtomicBool,
) -> Option<[u8; 32]> {
    commit_checkpoint_for_path_with_semantics(
        path,
        reason,
        signing_key,
        writersproof_dir,
        challenge_nonce,
        stopping,
        None,
    )
}

/// Like `commit_checkpoint_for_path` but attaches a semantic keystroke summary.
pub(super) fn commit_checkpoint_for_path_with_semantics(
    path: &str,
    reason: &str,
    signing_key: &Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    writersproof_dir: &Path,
    challenge_nonce: &Option<String>,
    stopping: &AtomicBool,
    semantic_summary: Option<String>,
) -> Option<[u8; 32]> {
    if stopping.load(Ordering::SeqCst) {
        log::debug!("Skipping checkpoint for {path}: sentinel stopping");
        return None;
    }
    if challenge_nonce.is_none() {
        log::warn!(
            "Checkpoint for {path} has no server nonce — temporal binding absent; \
             WP unreachable or nonce not fetched before checkpoint window"
        );
    }
    let file = match open_nofollow(path) {
        Ok(f) => f,
        Err(e) => {
            log::debug!("Auto-checkpoint open failed for {path}: {e}");
            return None;
        }
    };
    let raw_size = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            log::debug!("Auto-checkpoint metadata failed for {path}: {e}");
            return None;
        }
    };
    let (content_hash, _) = match crate::crypto::hash_file_handle(file) {
        Ok(pair) => pair,
        Err(e) => {
            log::debug!("Auto-checkpoint hash failed for {path}: {e}");
            return None;
        }
    };
    let file_size = i64::try_from(raw_size).unwrap_or(i64::MAX);

    let mut store = {
        let guard = signing_key.read_recover();
        let sk = guard.key()?;
        let db_path = writersproof_dir.join("events.db");
        match crate::store::open_store_with_signing_key(&sk, &db_path) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("Auto-checkpoint store open failed for {path}: {e}");
                return None;
            }
        }
    };

    // Capture git context for version-controlled files (non-blocking).
    let context_note = if !path.starts_with("shadow://") && !path.starts_with("title://") {
        let git_ctx = capture_git_context(Path::new(path));
        match git_ctx {
            Some(ref ctx) => {
                match serde_json::to_string(ctx) {
                    Ok(json) => Some(format!("{reason}|git:{json}")),
                    Err(_) => Some(reason.to_string()),
                }
            }
            None => Some(reason.to_string()),
        }
    } else {
        Some(reason.to_string())
    };

    let mut event = crate::store::SecureEvent::new(
        path.to_string(),
        content_hash,
        file_size,
        context_note,
    );
    event.challenge_nonce = challenge_nonce.clone();
    event.semantic_summary = semantic_summary;
    let sk_guard = signing_key.read_recover();
    let sk_opt = sk_guard.key();
    match store.add_secure_event_with_signer(&mut event, sk_opt.as_ref()) {
        Ok(_) => {
            log::info!("Auto-checkpoint committed for {path} ({reason})");
            Some(event.event_hash)
        }
        Err(e) => {
            log::warn!("Auto-checkpoint store write failed for {path}: {e}");
            None
        }
    }
}

/// Maximum age (in seconds) of the last session activity for a "Save As" match.
/// If the new file's content hash matches an active session whose last activity
/// was more than this many seconds ago, we do not consider it a "Save As".
const SAVE_AS_TIME_WINDOW_SECS: u64 = 5;

/// Detect if a newly created file is a "Save As" copy of an active session.
///
/// Checks all active sessions for a matching `current_hash`. If found within
/// the time window, returns the original session's path and ID.
pub fn detect_save_as(
    new_file_hash: &str,
    new_file_path: &str,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
) -> Option<super::types::SaveAsDetection> {
    let sessions_map = sessions.read_recover();
    let now = SystemTime::now();

    for (path, session) in sessions_map.iter() {
        if path == new_file_path {
            continue;
        }
        if let Some(ref hash) = session.current_hash {
            if hash == new_file_hash {
                let elapsed = now
                    .duration_since(session.last_focus_time)
                    .unwrap_or(std::time::Duration::from_secs(u64::MAX));
                if elapsed.as_secs() <= SAVE_AS_TIME_WINDOW_SECS {
                    return Some(super::types::SaveAsDetection {
                        original_path: path.clone(),
                        original_session_id: session.session_id.clone(),
                        content_hash: hash.clone(),
                    });
                }
            }
        }
    }
    None
}

/// Detect file encoding by reading the first 4 bytes for BOM markers.
///
/// Returns `FileEncoding::Unknown` for empty files or I/O errors.
/// Uses `open_nofollow` to prevent symlink-following TOCTOU attacks.
pub fn detect_file_encoding(path: &Path) -> super::types::FileEncoding {
    use super::types::FileEncoding;

    let file = match open_nofollow(path.to_str().unwrap_or("")) {
        Ok(f) => f,
        Err(_) => return FileEncoding::Unknown,
    };

    let mut buf = [0u8; 4];
    let n = {
        use std::io::Read;
        let mut reader = std::io::BufReader::new(file);
        match reader.read(&mut buf) {
            Ok(n) => n,
            Err(_) => return FileEncoding::Unknown,
        }
    };

    if n == 0 {
        return FileEncoding::Unknown;
    }

    // Check BOMs in order of specificity (longer BOMs first).
    // UTF-32 LE BOM: FF FE 00 00 (must check before UTF-16 LE which shares FF FE prefix).
    if n >= 4 && buf[..4] == [0xFF, 0xFE, 0x00, 0x00] {
        return FileEncoding::Utf32Le;
    }
    // UTF-32 BE BOM: 00 00 FE FF
    if n >= 4 && buf[..4] == [0x00, 0x00, 0xFE, 0xFF] {
        return FileEncoding::Utf32Be;
    }
    // UTF-8 BOM: EF BB BF
    if n >= 3 && buf[..3] == [0xEF, 0xBB, 0xBF] {
        return FileEncoding::Utf8Bom;
    }
    // UTF-16 LE BOM: FF FE
    if n >= 2 && buf[..2] == [0xFF, 0xFE] {
        return FileEncoding::Utf16Le;
    }
    // UTF-16 BE BOM: FE FF
    if n >= 2 && buf[..2] == [0xFE, 0xFF] {
        return FileEncoding::Utf16Be;
    }

    // No BOM: check if content is pure ASCII.
    let file2 = match open_nofollow(path.to_str().unwrap_or("")) {
        Ok(f) => f,
        Err(_) => return FileEncoding::Utf8,
    };
    let mut sample = [0u8; 512];
    let sample_n = {
        use std::io::Read;
        let mut reader = std::io::BufReader::new(file2);
        reader.read(&mut sample).unwrap_or(0)
    };
    if sample_n > 0 && sample[..sample_n].iter().all(|&b| b < 128) {
        return FileEncoding::Ascii;
    }

    FileEncoding::Utf8
}

/// Check if the file encoding changed since the last checkpoint and log if so.
///
/// Updates `session.file_encoding` with the new encoding. Returns `true` if
/// a transition was detected (previous encoding was set and differs from current).
pub fn check_encoding_transition(
    session: &mut DocumentSession,
    path: &Path,
) -> bool {
    let new_encoding = detect_file_encoding(path);
    let changed = match session.file_encoding {
        Some(prev) if prev != new_encoding => {
            log::info!(
                "File encoding changed for {}: {} -> {}",
                path.display(),
                prev,
                new_encoding
            );
            true
        }
        _ => false,
    };
    session.file_encoding = Some(new_encoding);
    changed
}

// ---------------------------------------------------------------------------
// Third-party app integration: Scrivener, word count, Track Changes
// ---------------------------------------------------------------------------

/// Extract the chapter title for a binder item inside a Scrivener `.scriv` package.
///
/// Scrivener stores its binder structure in a `.scrivx` XML file at the package
/// root. Each `<BinderItem>` has an `ID` attribute matching a UUID subdirectory
/// under `Files/Data/`. This function finds the `.scrivx` file, locates the
/// binder item whose ID matches the UUID in the file path, and returns its
/// `<Title>` text.
///
/// Returns `None` if the path is not inside a `.scriv` package, the `.scrivx`
/// file cannot be read, or the binder item is not found.
pub fn extract_scrivener_chapter_title(path: &Path) -> Option<String> {
    let path_str = path.to_str()?;
    let scriv_root = extract_bundle_package_root(path_str)?;

    // Only process .scriv bundles
    if !scriv_root.ends_with(".scriv") {
        return None;
    }

    // Extract the UUID from the path: .scriv/Files/Data/<UUID>/content.rtf
    let after_root = path_str.get(scriv_root.len()..)?;
    let after_root = after_root.strip_prefix('/')?;

    // Expected: Files/Data/<UUID>/...
    let parts: Vec<&str> = after_root.splitn(4, '/').collect();
    if parts.len() < 3 || parts[0] != "Files" || parts[1] != "Data" {
        return None;
    }
    let uuid = parts[2];

    // Find the .scrivx file inside the .scriv package root
    let scriv_dir = Path::new(&scriv_root);
    let scrivx_path = find_scrivx_file(scriv_dir)?;

    // Read and parse the .scrivx XML to find the binder item title
    let contents = std::fs::read_to_string(&scrivx_path).ok()?;
    find_binder_item_title(&contents, uuid)
}

/// Locate the `.scrivx` file inside a `.scriv` package directory.
fn find_scrivx_file(scriv_dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(scriv_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if let Some(name_str) = name.to_str() {
            if name_str.ends_with(".scrivx") {
                return Some(entry.path());
            }
        }
    }
    None
}

/// Parse `.scrivx` XML to find the `<Title>` of a `<BinderItem>` with the given ID.
///
/// Uses simple string scanning rather than an XML parser to avoid adding
/// dependencies. The `.scrivx` format uses `<BinderItem ID="..." ...>` with
/// nested `<Title>text</Title>`.
fn find_binder_item_title(xml: &str, target_id: &str) -> Option<String> {
    let search_patterns = [
        format!("ID=\"{}\"", target_id),
        format!("ID='{}'", target_id),
    ];

    let mut search_from = 0;
    while let Some(binder_pos) = xml[search_from..].find("<BinderItem") {
        let abs_pos = search_from + binder_pos;
        let tag_end = match xml[abs_pos..].find('>') {
            Some(e) => abs_pos + e,
            None => break,
        };
        let tag = &xml[abs_pos..=tag_end];

        let id_matches = search_patterns.iter().any(|pat| tag.contains(pat.as_str()));
        if id_matches {
            let after_tag = &xml[tag_end..];
            if let Some(title_start) = after_tag.find("<Title>") {
                let content_start = title_start + "<Title>".len();
                if let Some(title_end) = after_tag[content_start..].find("</Title>") {
                    let title = after_tag[content_start..content_start + title_end].trim();
                    if !title.is_empty() {
                        return Some(title.to_string());
                    }
                }
            }
        }
        search_from = tag_end + 1;
    }
    None
}

/// Extract the word count from a document file.
///
/// Supports:
/// - `.txt` / `.md`: whitespace-separated token count
/// - `.rtf`: strips RTF control words, then counts whitespace-separated tokens
/// - `.docx`: reads `word/document.xml` from the zip archive, strips XML tags,
///   counts whitespace-separated tokens
///
/// Returns `None` for unsupported formats or on any I/O / parse error.
pub fn extract_word_count(path: &Path) -> Option<u64> {
    let ext = path.extension().and_then(|e| e.to_str())?.to_lowercase();
    match ext.as_str() {
        "txt" | "md" => extract_word_count_plaintext(path),
        "rtf" => extract_word_count_rtf(path),
        "docx" => extract_word_count_docx(path),
        _ => None,
    }
}

/// Count whitespace-separated tokens in a plain text file.
fn extract_word_count_plaintext(path: &Path) -> Option<u64> {
    let contents = std::fs::read_to_string(path).ok()?;
    let count = contents.split_whitespace().count();
    Some(count as u64)
}

/// Strip RTF control words and count remaining whitespace-separated tokens.
fn extract_word_count_rtf(path: &Path) -> Option<u64> {
    let contents = std::fs::read_to_string(path).ok()?;
    let text = strip_rtf(&contents);
    let count = text.split_whitespace().count();
    Some(count as u64)
}

/// Minimal RTF stripping: remove control words, groups, and special characters.
fn strip_rtf(rtf: &str) -> String {
    let mut result = String::with_capacity(rtf.len());
    let mut chars = rtf.chars().peekable();
    let mut brace_depth: i32 = 0;
    let mut skip_depth: Option<i32> = None;

    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                brace_depth += 1;
            }
            '}' => {
                if let Some(sd) = skip_depth {
                    if brace_depth <= sd {
                        skip_depth = None;
                    }
                }
                brace_depth = brace_depth.saturating_sub(1);
            }
            '\\' => {
                if let Some(&next) = chars.peek() {
                    if next == '\'' {
                        // Hex-encoded character: \'XX
                        chars.next();
                        let mut hex = String::with_capacity(2);
                        for _ in 0..2 {
                            if let Some(&h) = chars.peek() {
                                if h.is_ascii_hexdigit() {
                                    hex.push(h);
                                    chars.next();
                                }
                            }
                        }
                        if skip_depth.is_none() {
                            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                                if byte.is_ascii_graphic() || byte == b' ' {
                                    result.push(byte as char);
                                }
                            }
                        }
                    } else if next == '\\' || next == '{' || next == '}' {
                        chars.next();
                        if skip_depth.is_none() {
                            result.push(next);
                        }
                    } else if next.is_ascii_alphabetic() {
                        let mut word = String::new();
                        while let Some(&c) = chars.peek() {
                            if c.is_ascii_alphabetic() {
                                word.push(c);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        // Skip optional numeric parameter
                        while let Some(&c) = chars.peek() {
                            if c.is_ascii_digit() || c == '-' {
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        // Consume delimiter space
                        if let Some(&' ') = chars.peek() {
                            chars.next();
                        }
                        const SKIP_GROUPS: &[&str] = &[
                            "fonttbl", "colortbl", "stylesheet", "info", "header",
                            "footer", "headerl", "headerr", "footerl", "footerr",
                            "pict", "object", "fldinst",
                        ];
                        if SKIP_GROUPS.contains(&word.as_str()) {
                            skip_depth = Some(brace_depth);
                        }
                        if skip_depth.is_none()
                            && (word == "par" || word == "line" || word == "tab")
                        {
                            result.push(' ');
                        }
                    } else {
                        chars.next();
                    }
                }
            }
            '\r' | '\n' => {}
            _ => {
                if skip_depth.is_none() {
                    result.push(ch);
                }
            }
        }
    }
    result
}

/// Extract word count from a `.docx` file by reading `word/document.xml` from
/// the zip archive.
fn extract_word_count_docx(path: &Path) -> Option<u64> {
    let xml = read_docx_entry(path, "word/document.xml")?;
    let text = strip_xml_tags(&xml);
    let count = text.split_whitespace().count();
    Some(count as u64)
}

/// Strip all XML tags from a string, inserting spaces between elements.
fn strip_xml_tags(xml: &str) -> String {
    let mut result = String::with_capacity(xml.len() / 2);
    let mut in_tag = false;
    for ch in xml.chars() {
        match ch {
            '<' => {
                in_tag = true;
                if !result.ends_with(' ') && !result.is_empty() {
                    result.push(' ');
                }
            }
            '>' => {
                in_tag = false;
            }
            _ if !in_tag => {
                result.push(ch);
            }
            _ => {}
        }
    }
    result
}

/// Read a single entry from a `.docx` (ZIP) file without external zip dependencies.
///
/// Parses ZIP local file headers to find the named entry, decompresses
/// DEFLATE data using `flate2`, or reads STORED data directly.
fn read_docx_entry(path: &Path, entry_name: &str) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path).ok()?;

    const LOCAL_HEADER_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
    const MAX_ENTRIES: usize = 500;

    let file_len = file.metadata().ok()?.len();
    if file_len > 100 * 1024 * 1024 {
        return None;
    }

    for _ in 0..MAX_ENTRIES {
        let pos = file.stream_position().ok()?;
        if pos >= file_len {
            break;
        }

        let mut sig = [0u8; 4];
        if file.read_exact(&mut sig).is_err() {
            break;
        }
        if sig != LOCAL_HEADER_SIG {
            break;
        }

        // Read local file header fields (26 bytes after signature)
        let mut header = [0u8; 26];
        file.read_exact(&mut header).ok()?;

        let compression = u16::from_le_bytes([header[4], header[5]]);
        let compressed_size =
            u32::from_le_bytes([header[14], header[15], header[16], header[17]]);
        let name_len = u16::from_le_bytes([header[22], header[23]]) as usize;
        let extra_len = u16::from_le_bytes([header[24], header[25]]) as usize;

        let mut name_buf = vec![0u8; name_len];
        file.read_exact(&mut name_buf).ok()?;
        let name = String::from_utf8_lossy(&name_buf);

        if extra_len > 0 {
            file.seek(SeekFrom::Current(extra_len as i64)).ok()?;
        }

        if name == entry_name {
            const MAX_DECOMPRESSED: u64 = 16 * 1024 * 1024;
            if compressed_size as u64 > MAX_DECOMPRESSED {
                return None;
            }

            let mut compressed = vec![0u8; compressed_size as usize];
            file.read_exact(&mut compressed).ok()?;

            let data = match compression {
                0 => compressed,
                8 => {
                    use flate2::read::DeflateDecoder;
                    let decoder = DeflateDecoder::new(&compressed[..]);
                    let mut decompressed = Vec::new();
                    decoder
                        .take(MAX_DECOMPRESSED)
                        .read_to_end(&mut decompressed)
                        .ok()?;
                    decompressed
                }
                _ => return None,
            };

            return String::from_utf8(data).ok();
        }

        if compressed_size > 0 {
            file.seek(SeekFrom::Current(compressed_size as i64)).ok()?;
        }
    }

    None
}

/// Detect whether a `.docx` file contains Track Changes (revisions).
///
/// Checks `word/document.xml` for `<w:ins` or `<w:del` elements, which
/// indicate inserted or deleted text tracked by Word's revision system.
///
/// Returns `false` for non-`.docx` files, unreadable files, or on any error.
pub fn has_track_changes(path: &Path) -> bool {
    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(e) => e.to_lowercase(),
        None => return false,
    };
    if ext != "docx" {
        return false;
    }
    match read_docx_entry(path, "word/document.xml") {
        Some(xml) => xml.contains("<w:ins") || xml.contains("<w:del"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ObfuscatedString;

    const MS_TO_NS: i64 = 1_000_000;

    #[test]
    fn test_paste_detection_3_signals() {
        let last_ts = 1000 * MS_TO_NS;
        let current_ts = last_ts + 1000 * MS_TO_NS;
        let hash1 = [0u8; 32];
        let hash2 = [1u8; 32];

        let (context, confidence) = detect_paste_boundary(
            last_ts,
            current_ts,
            &hash1,
            &hash2,
            "com.app.new",
            "com.app.old",
        );

        assert_eq!(context, KeystrokeContext::PastedContent);
        assert!(confidence > 0.98);
    }

    #[test]
    fn test_paste_detection_2_signals_long_silence() {
        let last_ts = 2000 * MS_TO_NS;
        let current_ts = last_ts + 2500 * MS_TO_NS;
        let hash1 = [0u8; 32];
        let hash2 = [1u8; 32];

        let (context, confidence) = detect_paste_boundary(
            last_ts,
            current_ts,
            &hash1,
            &hash2,
            "com.app.same",
            "com.app.same",
        );

        assert_eq!(context, KeystrokeContext::PastedContent);
        assert_eq!(confidence, 0.92);
    }

    #[test]
    fn test_paste_detection_1_signal_app_transition() {
        let last_ts = 3000 * MS_TO_NS;
        let current_ts = last_ts + 50 * MS_TO_NS;
        let hash = [0u8; 32];

        let (context, confidence) = detect_paste_boundary(
            last_ts,
            current_ts,
            &hash,
            &hash,
            "com.app.new",
            "com.app.old",
        );

        assert_eq!(context, KeystrokeContext::PastedContent);
        assert_eq!(confidence, 0.70);
    }

    #[test]
    fn test_no_paste_signals_original() {
        let last_ts = 4000 * MS_TO_NS;
        let current_ts = last_ts + 100 * MS_TO_NS;
        let hash = [0u8; 32];

        let (context, confidence) = detect_paste_boundary(
            last_ts,
            current_ts,
            &hash,
            &hash,
            "com.app.same",
            "com.app.same",
        );

        assert_eq!(context, KeystrokeContext::OriginalComposition);
        assert_eq!(confidence, 0.20);
    }

    #[test]
    fn test_context_window_expiry() {
        let mut session = DocumentSession::new(
            "/test/doc.txt".to_string(),
            "com.test.app".to_string(),
            "TestApp".to_string(),
            ObfuscatedString::new("Test Doc"),
        );

        let paste_time = 5000 * MS_TO_NS;
        update_keystroke_context_window(
            &mut session,
            paste_time,
            30_000,
            PasteSource::Unknown,
        );

        assert!(session.paste_context.is_some());
        let ctx = session.paste_context.as_ref().unwrap();
        assert_eq!(ctx.paste_time, paste_time);

        let within_window = paste_time + 15_000 * MS_TO_NS;
        assert!(is_within_paste_window(&session, within_window));

        let past_window = paste_time + 31_000 * MS_TO_NS;
        assert!(!is_within_paste_window(&session, past_window));
    }

    #[test]
    fn test_bundle_package_root_scriv() {
        assert_eq!(
            extract_bundle_package_root("/Users/me/Novel.scriv/Files/Data/ABC/content.rtf"),
            Some("/Users/me/Novel.scriv".to_string())
        );
    }

    #[test]
    fn test_bundle_package_root_pages() {
        assert_eq!(
            extract_bundle_package_root("/Users/me/Report.pages/Index/Tables/DataList"),
            Some("/Users/me/Report.pages".to_string())
        );
    }

    #[test]
    fn test_bundle_package_root_rtfd() {
        assert_eq!(
            extract_bundle_package_root("/Users/me/Note.rtfd/TXT.rtf"),
            Some("/Users/me/Note.rtfd".to_string())
        );
    }

    #[test]
    fn test_bundle_package_root_none_for_plain_file() {
        assert_eq!(extract_bundle_package_root("/Users/me/essay.md"), None);
    }

    #[test]
    fn test_bundle_package_root_bare_bundle_returns_self() {
        // If the path IS the bundle root, ancestors() includes self,
        // so it returns the bundle path directly — functionally a no-op
        // at the call site since the caller falls back to event.path.
        assert_eq!(
            extract_bundle_package_root("/Users/me/Novel.scriv"),
            Some("/Users/me/Novel.scriv".to_string())
        );
    }

    #[test]
    fn test_classify_paste_source_no_store() {
        let hash = [0u8; 32];
        assert_eq!(
            classify_paste_source(None, &hash, "session1"),
            PasteSource::Unknown
        );
    }

    #[test]
    fn test_is_temporary_path_tmp() {
        assert!(is_temporary_path("/tmp/com.apple.mail/attachment.docx"));
        assert!(is_temporary_path("/private/tmp/download.pdf"));
    }

    #[test]
    fn test_is_temporary_path_var_folders() {
        assert!(is_temporary_path(
            "/var/folders/zz/abc123/T/com.apple.Preview/file.pdf"
        ));
        assert!(is_temporary_path(
            "/private/var/folders/xy/def456/T/temp.txt"
        ));
    }

    #[test]
    fn test_is_temporary_path_permanent() {
        assert!(!is_temporary_path("/Users/me/Documents/essay.md"));
        assert!(!is_temporary_path("/Users/me/Desktop/report.docx"));
        assert!(!is_temporary_path("/Users/me/Downloads/paper.pdf"));
    }

    #[test]
    fn test_update_context_window_preserves_source() {
        let mut session = DocumentSession::new(
            "/test/doc.txt".to_string(),
            "com.test.app".to_string(),
            "TestApp".to_string(),
            ObfuscatedString::new("Test Doc"),
        );

        let paste_time = 1000 * MS_TO_NS;
        update_keystroke_context_window(
            &mut session,
            paste_time,
            30_000,
            PasteSource::SameDocument,
        );
        assert_eq!(
            session.paste_context.as_ref().unwrap().source,
            PasteSource::SameDocument,
        );

        update_keystroke_context_window(
            &mut session,
            paste_time,
            30_000,
            PasteSource::External,
        );
        assert_eq!(
            session.paste_context.as_ref().unwrap().source,
            PasteSource::External,
        );
    }

    #[test]
    fn test_detect_save_as_match() {
        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let mut session = DocumentSession::new(
            "/original/doc.txt".to_string(),
            "com.test.app".to_string(),
            "TestApp".to_string(),
            ObfuscatedString::new("doc.txt"),
        );
        session.current_hash = Some("abc123".to_string());
        session.last_focus_time = SystemTime::now();
        sessions
            .write()
            .unwrap()
            .insert("/original/doc.txt".to_string(), session);

        let result = detect_save_as("abc123", "/new/doc_copy.txt", &sessions);
        assert!(result.is_some());
        let detection = result.unwrap();
        assert_eq!(detection.original_path, "/original/doc.txt");
        assert_eq!(detection.content_hash, "abc123");
    }

    #[test]
    fn test_detect_save_as_no_match_different_hash() {
        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let mut session = DocumentSession::new(
            "/original/doc.txt".to_string(),
            "com.test.app".to_string(),
            "TestApp".to_string(),
            ObfuscatedString::new("doc.txt"),
        );
        session.current_hash = Some("abc123".to_string());
        session.last_focus_time = SystemTime::now();
        sessions
            .write()
            .unwrap()
            .insert("/original/doc.txt".to_string(), session);

        let result = detect_save_as("different_hash", "/new/doc_copy.txt", &sessions);
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_save_as_no_match_stale_session() {
        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let mut session = DocumentSession::new(
            "/original/doc.txt".to_string(),
            "com.test.app".to_string(),
            "TestApp".to_string(),
            ObfuscatedString::new("doc.txt"),
        );
        session.current_hash = Some("abc123".to_string());
        // Set last_focus_time to 10 seconds ago (beyond the 5-second window).
        session.last_focus_time =
            SystemTime::now() - std::time::Duration::from_secs(10);
        sessions
            .write()
            .unwrap()
            .insert("/original/doc.txt".to_string(), session);

        let result = detect_save_as("abc123", "/new/doc_copy.txt", &sessions);
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_save_as_skips_same_path() {
        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let mut session = DocumentSession::new(
            "/same/doc.txt".to_string(),
            "com.test.app".to_string(),
            "TestApp".to_string(),
            ObfuscatedString::new("doc.txt"),
        );
        session.current_hash = Some("abc123".to_string());
        session.last_focus_time = SystemTime::now();
        sessions
            .write()
            .unwrap()
            .insert("/same/doc.txt".to_string(), session);

        let result = detect_save_as("abc123", "/same/doc.txt", &sessions);
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_file_encoding_utf8_bom() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("utf8bom.txt");
        std::fs::write(&path, b"\xEF\xBB\xBFHello").unwrap();
        assert_eq!(
            detect_file_encoding(&path),
            super::super::types::FileEncoding::Utf8Bom
        );
    }

    #[test]
    fn test_detect_file_encoding_utf16le() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("utf16le.txt");
        std::fs::write(&path, b"\xFF\xFEH\x00i\x00").unwrap();
        assert_eq!(
            detect_file_encoding(&path),
            super::super::types::FileEncoding::Utf16Le
        );
    }

    #[test]
    fn test_detect_file_encoding_utf16be() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("utf16be.txt");
        std::fs::write(&path, b"\xFE\xFF\x00H\x00i").unwrap();
        assert_eq!(
            detect_file_encoding(&path),
            super::super::types::FileEncoding::Utf16Be
        );
    }

    #[test]
    fn test_detect_file_encoding_utf32le() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("utf32le.txt");
        std::fs::write(&path, b"\xFF\xFE\x00\x00Hi").unwrap();
        assert_eq!(
            detect_file_encoding(&path),
            super::super::types::FileEncoding::Utf32Le
        );
    }

    #[test]
    fn test_detect_file_encoding_utf32be() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("utf32be.txt");
        std::fs::write(&path, b"\x00\x00\xFE\xFFHi").unwrap();
        assert_eq!(
            detect_file_encoding(&path),
            super::super::types::FileEncoding::Utf32Be
        );
    }

    #[test]
    fn test_detect_file_encoding_ascii() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ascii.txt");
        std::fs::write(&path, b"Hello, world!").unwrap();
        assert_eq!(
            detect_file_encoding(&path),
            super::super::types::FileEncoding::Ascii
        );
    }

    #[test]
    fn test_detect_file_encoding_utf8_no_bom() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("utf8.txt");
        // UTF-8 multi-byte: e2 80 99 = right single quotation mark
        std::fs::write(&path, "Hello\u{2019}world").unwrap();
        assert_eq!(
            detect_file_encoding(&path),
            super::super::types::FileEncoding::Utf8
        );
    }

    #[test]
    fn test_detect_file_encoding_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            detect_file_encoding(&path),
            super::super::types::FileEncoding::Unknown
        );
    }

    #[test]
    fn test_detect_file_encoding_nonexistent() {
        let path = std::path::Path::new("/nonexistent/file.txt");
        assert_eq!(
            detect_file_encoding(path),
            super::super::types::FileEncoding::Unknown
        );
    }

    #[test]
    fn test_check_encoding_transition_first_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.txt");
        std::fs::write(&path, b"Hello").unwrap();

        let mut session = DocumentSession::new(
            path.to_str().unwrap().to_string(),
            "com.test.app".to_string(),
            "TestApp".to_string(),
            ObfuscatedString::new("doc.txt"),
        );

        // First check: no previous encoding, so no transition.
        let changed = check_encoding_transition(&mut session, &path);
        assert!(!changed);
        assert_eq!(
            session.file_encoding,
            Some(super::super::types::FileEncoding::Ascii)
        );
    }

    #[test]
    fn test_check_encoding_transition_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.txt");

        let mut session = DocumentSession::new(
            path.to_str().unwrap().to_string(),
            "com.test.app".to_string(),
            "TestApp".to_string(),
            ObfuscatedString::new("doc.txt"),
        );

        // Set initial encoding to ASCII.
        std::fs::write(&path, b"Hello").unwrap();
        check_encoding_transition(&mut session, &path);
        assert_eq!(
            session.file_encoding,
            Some(super::super::types::FileEncoding::Ascii)
        );

        // Change file to UTF-8 BOM.
        std::fs::write(&path, b"\xEF\xBB\xBFHello").unwrap();
        let changed = check_encoding_transition(&mut session, &path);
        assert!(changed);
        assert_eq!(
            session.file_encoding,
            Some(super::super::types::FileEncoding::Utf8Bom)
        );
    }

    #[test]
    fn test_check_encoding_transition_no_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.txt");
        std::fs::write(&path, b"Hello").unwrap();

        let mut session = DocumentSession::new(
            path.to_str().unwrap().to_string(),
            "com.test.app".to_string(),
            "TestApp".to_string(),
            ObfuscatedString::new("doc.txt"),
        );

        check_encoding_transition(&mut session, &path);
        let changed = check_encoding_transition(&mut session, &path);
        assert!(!changed);
    }

    #[test]
    fn test_find_git_root_in_repo() {
        // This test file lives inside the writerslogic git repo.
        let this_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sentinel/helpers.rs");
        let root = find_git_root(&this_file);
        assert!(root.is_some(), "should find git root for a file in the repo");
        assert!(
            root.as_ref().unwrap().join(".git").exists(),
            "git root should contain .git"
        );
    }

    #[test]
    fn test_find_git_root_outside_repo() {
        let root = find_git_root(Path::new("/tmp"));
        assert!(root.is_none(), "should not find git root for /tmp");
    }

    #[test]
    fn test_parse_numstat_normal() {
        assert_eq!(parse_numstat("10\t5\tfile.rs"), (10, 5));
    }

    #[test]
    fn test_parse_numstat_empty() {
        assert_eq!(parse_numstat(""), (0, 0));
    }

    #[test]
    fn test_parse_numstat_binary() {
        assert_eq!(parse_numstat("-\t-\timage.png"), (0, 0));
    }

    #[test]
    fn test_parse_numstat_single_field() {
        assert_eq!(parse_numstat("10"), (0, 0));
    }

    #[test]
    fn test_capture_git_context_in_repo() {
        // Use a known file inside this repo.
        let this_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sentinel/helpers.rs");
        let ctx = capture_git_context(&this_file);
        // The file is in a git repo, so we should get a context.
        // However, git must be installed; skip assertion if None
        // (CI environments without git).
        if let Some(ctx) = ctx {
            assert!(!ctx.branch.is_empty(), "branch should not be empty");
        }
    }

    #[test]
    fn test_capture_git_context_outside_repo() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not_in_git.txt");
        std::fs::write(&file, b"hello").unwrap();
        let ctx = capture_git_context(&file);
        assert!(ctx.is_none(), "file outside git repo should return None");
    }

    #[test]
    fn test_git_context_json_roundtrip() {
        let ctx = super::super::types::GitContext {
            branch: "main".to_string(),
            last_commit: "abc123".to_string(),
            insertions: 10,
            deletions: 3,
            is_staged: true,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: super::super::types::GitContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, parsed);
    }

    // -----------------------------------------------------------------------
    // Scrivener chapter title extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_binder_item_title_found() {
        let xml = r#"
        <ScrivenerProject>
          <Binder>
            <BinderItem ID="ABC-123" Type="Text">
              <Title>Chapter One</Title>
              <MetaData><IncludeInCompile>Yes</IncludeInCompile></MetaData>
            </BinderItem>
            <BinderItem ID="DEF-456" Type="Text">
              <Title>Chapter Two</Title>
            </BinderItem>
          </Binder>
        </ScrivenerProject>"#;

        assert_eq!(
            find_binder_item_title(xml, "ABC-123"),
            Some("Chapter One".to_string())
        );
        assert_eq!(
            find_binder_item_title(xml, "DEF-456"),
            Some("Chapter Two".to_string())
        );
    }

    #[test]
    fn test_find_binder_item_title_not_found() {
        let xml = r#"<BinderItem ID="ABC" Type="Text"><Title>Ch1</Title></BinderItem>"#;
        assert_eq!(find_binder_item_title(xml, "MISSING"), None);
    }

    #[test]
    fn test_find_binder_item_title_empty_xml() {
        assert_eq!(find_binder_item_title("", "ABC"), None);
    }

    #[test]
    fn test_find_binder_item_title_single_quotes() {
        let xml = r#"<BinderItem ID='XYZ' Type="Text"><Title>Epilogue</Title></BinderItem>"#;
        assert_eq!(
            find_binder_item_title(xml, "XYZ"),
            Some("Epilogue".to_string())
        );
    }

    #[test]
    fn test_scrivener_chapter_title_non_scriv_path() {
        let path = Path::new("/Users/me/essay.md");
        assert_eq!(extract_scrivener_chapter_title(path), None);
    }

    #[test]
    fn test_scrivener_chapter_title_bare_scriv_root() {
        // Just the .scriv root, no Files/Data/<UUID> component
        let path = Path::new("/Users/me/Novel.scriv");
        assert_eq!(extract_scrivener_chapter_title(path), None);
    }

    #[test]
    fn test_scrivener_chapter_title_pages_bundle() {
        // .pages bundle should return None (not .scriv)
        let path = Path::new("/Users/me/Doc.pages/Index/foo");
        assert_eq!(extract_scrivener_chapter_title(path), None);
    }

    // -----------------------------------------------------------------------
    // Word count extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_word_count_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "Hello world this is a test").unwrap();
        assert_eq!(extract_word_count(&file), Some(6));
    }

    #[test]
    fn test_word_count_plaintext_empty() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("empty.txt");
        std::fs::write(&file, "").unwrap();
        assert_eq!(extract_word_count(&file), Some(0));
    }

    #[test]
    fn test_word_count_markdown() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("doc.md");
        std::fs::write(&file, "# Title\n\nSome **bold** text here.").unwrap();
        // Tokens: #, Title, Some, **bold**, text, here.
        assert_eq!(extract_word_count(&file), Some(6));
    }

    #[test]
    fn test_word_count_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("image.png");
        std::fs::write(&file, "not really a png").unwrap();
        assert_eq!(extract_word_count(&file), None);
    }

    #[test]
    fn test_word_count_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("noext");
        std::fs::write(&file, "hello world").unwrap();
        assert_eq!(extract_word_count(&file), None);
    }

    #[test]
    fn test_word_count_nonexistent_file() {
        let path = Path::new("/nonexistent/file.txt");
        assert_eq!(extract_word_count(path), None);
    }

    // -----------------------------------------------------------------------
    // RTF stripping
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_rtf_basic() {
        let rtf = r"{\rtf1\ansi{\fonttbl\f0 Times New Roman;}\f0 Hello world}";
        let text = strip_rtf(rtf);
        assert!(
            text.contains("Hello") && text.contains("world"),
            "stripped RTF should contain visible text, got: {:?}",
            text
        );
        assert!(
            !text.contains("\\rtf") && !text.contains("\\ansi"),
            "stripped RTF should not contain control words"
        );
    }

    #[test]
    fn test_strip_rtf_with_par() {
        let rtf = r"{\rtf1 First paragraph.\par Second paragraph.}";
        let text = strip_rtf(rtf);
        assert!(text.contains("First paragraph."));
        assert!(text.contains("Second paragraph."));
    }

    #[test]
    fn test_strip_rtf_empty() {
        assert_eq!(strip_rtf(""), "");
    }

    #[test]
    fn test_word_count_rtf_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.rtf");
        let rtf = r"{\rtf1\ansi\deff0{\fonttbl{\f0 Helvetica;}}Hello world from RTF}";
        std::fs::write(&file, rtf).unwrap();
        let count = extract_word_count(&file);
        assert!(count.is_some());
        // "Hello", "world", "from", "RTF" = 4
        assert_eq!(count.unwrap(), 4);
    }

    // -----------------------------------------------------------------------
    // XML tag stripping
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_xml_tags() {
        let xml = "<w:body><w:p><w:r><w:t>Hello</w:t></w:r> <w:r><w:t>world</w:t></w:r></w:p></w:body>";
        let text = strip_xml_tags(xml);
        let words: Vec<&str> = text.split_whitespace().collect();
        assert_eq!(words, vec!["Hello", "world"]);
    }

    #[test]
    fn test_strip_xml_tags_empty() {
        assert_eq!(strip_xml_tags(""), "");
    }

    #[test]
    fn test_strip_xml_tags_no_tags() {
        assert_eq!(strip_xml_tags("plain text"), "plain text");
    }

    // -----------------------------------------------------------------------
    // Track Changes detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_has_track_changes_non_docx() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "hello").unwrap();
        assert!(!has_track_changes(&file));
    }

    #[test]
    fn test_has_track_changes_nonexistent() {
        assert!(!has_track_changes(Path::new("/nonexistent/file.docx")));
    }

    #[test]
    fn test_has_track_changes_no_extension() {
        assert!(!has_track_changes(Path::new("/some/file")));
    }

    // -----------------------------------------------------------------------
    // DOCX integration: word count + track changes with real zip files
    // -----------------------------------------------------------------------

    /// Build a minimal valid .docx (ZIP) file in memory with the given
    /// `word/document.xml` content, using STORED compression (method 0).
    fn build_minimal_docx(document_xml: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let entry_name = b"word/document.xml";

        // Local file header
        buf.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // signature
        buf.extend_from_slice(&[0x14, 0x00]); // version needed (2.0)
        buf.extend_from_slice(&[0x00, 0x00]); // flags
        buf.extend_from_slice(&[0x00, 0x00]); // compression: STORED
        buf.extend_from_slice(&[0x00, 0x00]); // mod time
        buf.extend_from_slice(&[0x00, 0x00]); // mod date
        // CRC-32 (compute it)
        let crc = crc32_simple(document_xml);
        buf.extend_from_slice(&crc.to_le_bytes());
        let size = document_xml.len() as u32;
        buf.extend_from_slice(&size.to_le_bytes()); // compressed size
        buf.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        buf.extend_from_slice(&(entry_name.len() as u16).to_le_bytes()); // name len
        buf.extend_from_slice(&[0x00, 0x00]); // extra len
        buf.extend_from_slice(entry_name);
        buf.extend_from_slice(document_xml);

        let cd_offset = buf.len() as u32;

        // Central directory header
        buf.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]); // signature
        buf.extend_from_slice(&[0x14, 0x00]); // version made by
        buf.extend_from_slice(&[0x14, 0x00]); // version needed
        buf.extend_from_slice(&[0x00, 0x00]); // flags
        buf.extend_from_slice(&[0x00, 0x00]); // compression: STORED
        buf.extend_from_slice(&[0x00, 0x00]); // mod time
        buf.extend_from_slice(&[0x00, 0x00]); // mod date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&(entry_name.len() as u16).to_le_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // extra len
        buf.extend_from_slice(&[0x00, 0x00]); // comment len
        buf.extend_from_slice(&[0x00, 0x00]); // disk number
        buf.extend_from_slice(&[0x00, 0x00]); // internal attrs
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // external attrs
        buf.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        buf.extend_from_slice(entry_name);

        let cd_size = (buf.len() as u32) - cd_offset;

        // End of central directory
        buf.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // signature
        buf.extend_from_slice(&[0x00, 0x00]); // disk number
        buf.extend_from_slice(&[0x00, 0x00]); // cd disk
        buf.extend_from_slice(&[0x01, 0x00]); // entries on disk
        buf.extend_from_slice(&[0x01, 0x00]); // total entries
        buf.extend_from_slice(&cd_size.to_le_bytes());
        buf.extend_from_slice(&cd_offset.to_le_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // comment len

        buf
    }

    /// Simple CRC-32 (IEEE/ZIP) for test use.
    fn crc32_simple(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    #[test]
    fn test_word_count_docx_stored() {
        let xml = br#"<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>Hello world from docx</w:t></w:r></w:p></w:body></w:document>"#;
        let docx = build_minimal_docx(xml);

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.docx");
        std::fs::write(&file, &docx).unwrap();

        let count = extract_word_count(&file);
        assert_eq!(count, Some(4)); // Hello, world, from, docx
    }

    #[test]
    fn test_has_track_changes_with_ins() {
        let xml = br#"<?xml version="1.0"?><w:document><w:body><w:p><w:ins w:author="A"><w:r><w:t>added</w:t></w:r></w:ins></w:p></w:body></w:document>"#;
        let docx = build_minimal_docx(xml);

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tracked.docx");
        std::fs::write(&file, &docx).unwrap();

        assert!(has_track_changes(&file));
    }

    #[test]
    fn test_has_track_changes_with_del() {
        let xml = br#"<?xml version="1.0"?><w:document><w:body><w:p><w:del w:author="A"><w:r><w:t>removed</w:t></w:r></w:del></w:p></w:body></w:document>"#;
        let docx = build_minimal_docx(xml);

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tracked_del.docx");
        std::fs::write(&file, &docx).unwrap();

        assert!(has_track_changes(&file));
    }

    #[test]
    fn test_has_track_changes_clean_docx() {
        let xml = br#"<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>clean</w:t></w:r></w:p></w:body></w:document>"#;
        let docx = build_minimal_docx(xml);

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("clean.docx");
        std::fs::write(&file, &docx).unwrap();

        assert!(!has_track_changes(&file));
    }
}
