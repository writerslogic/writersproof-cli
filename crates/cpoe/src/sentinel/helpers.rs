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

    // Scrivener chapter content: extract the .scriv package root so all chapters
    // in a project contribute to the same session checkpoint.
    let normalized_path = if !is_wal_event {
        extract_scrivener_package_root(&event.path).unwrap_or_else(|| event.path.clone())
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

/// Append an entry to the session's WAL file, handling hex decode, key check, and errors.
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
    if hex::decode_to_slice(hex_str, &mut session_id_bytes).is_ok() {
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
            log::error!(
                "Signing key not initialized, skipping WAL for session {}",
                session_id
            );
        }
    } else {
        log::error!("Invalid session ID hex: {}", session_id);
    }
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

/// Extract the .scriv package root from a nested chapter content path.
///
/// Scrivener stores chapter content in:
///   /path/to/Project.scriv/Files/Data/<UUID>/content.rtf
///
/// This function strips back to the .scriv package root so checkpoint
/// events are associated with the project rather than individual chapters.
fn extract_scrivener_package_root(path: &str) -> Option<String> {
    let p = Path::new(path);

    // Walk up the path looking for *.scriv directory
    for ancestor in p.ancestors() {
        if let Some(file_name) = ancestor.file_name().and_then(|n| n.to_str()) {
            if file_name.ends_with(".scriv") {
                if let Some(s) = ancestor.to_str() {
                    return Some(s.to_string());
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
pub fn update_keystroke_context_window(
    session: &mut super::types::DocumentSession,
    paste_time: i64,
    context_window_ms: u64,
) {
    let window_nanos = context_window_ms
        .checked_mul(1_000_000)
        .and_then(|w| i64::try_from(w).ok())
        .unwrap_or(i64::MAX);
    session.paste_context = Some(super::types::PasteContext {
        paste_time,
        context_window_end: paste_time.saturating_add(window_nanos),
        keystroke_count_after_paste: 0,
    });
}

/// Check if current keystroke is within paste context window.
pub fn is_within_paste_window(session: &super::types::DocumentSession, current_time: i64) -> bool {
    match &session.paste_context {
        Some(ctx) => current_time < ctx.context_window_end,
        None => false,
    }
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

    let mut event = crate::store::SecureEvent::new(
        path.to_string(),
        content_hash,
        file_size,
        Some(reason.to_string()),
    );
    event.challenge_nonce = challenge_nonce.clone();
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
        update_keystroke_context_window(&mut session, paste_time, 30_000);

        assert!(session.paste_context.is_some());
        let ctx = session.paste_context.as_ref().unwrap();
        assert_eq!(ctx.paste_time, paste_time);

        let within_window = paste_time + 15_000 * MS_TO_NS;
        assert!(is_within_paste_window(&session, within_window));

        let past_window = paste_time + 31_000 * MS_TO_NS;
        assert!(!is_within_paste_window(&session, past_window));
    }
}
