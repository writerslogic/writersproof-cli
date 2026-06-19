// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::shadow::ShadowManager;
use super::types::*;
use crate::config::SentinelConfig;
use crate::wal::{EntryType, Wal};

use crate::RwLockRecover;
use ed25519_dalek::{Signer, SigningKey};
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
    // Targeted mode: only maintain the pin while the user stays on the pinned
    // document.  Empty-path events (FocusLost from apps that don't expose
    // paths) are always passed through so the session's focus state updates.
    // When a non-empty path *different* from the target arrives the user has
    // switched documents or apps; exit targeted mode so focus follows naturally
    // and the new document's session (or app-allowed check) takes over.
    let exit_targeted = {
        let guard = targeted_path.read_recover();
        matches!(guard.as_deref(), Some(t) if !event.path.is_empty() && event.path != t)
    };
    if exit_targeted {
        log::debug!(
            "[FOCUS] targeted mode: auto-following focus to {:?}",
            event.path
        );
        *targeted_path.write_recover() = None;
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
        log::debug!(
            "[FOCUS] BLOCKED app={} bundle={}",
            event.app_name,
            event.app_bundle_id
        );
        // Only unfocus if the currently focused session belongs to the blocked
        // app. The HybridFocusTracker can deliver stale polling FocusLost events
        // for the previous app AFTER the AXObserver already set focus to the new
        // (allowed) app. Unconditionally clearing current_focus here would destroy
        // the correct AXObserver focus.
        let path_to_unfocus = {
            let focused_path = current_focus.read_recover().clone();
            if let Some(ref path) = focused_path {
                let belongs_to_blocked = sessions.read_recover()
                    .get(path.as_str())
                    .map(|s| {
                        s.app_bundle_id.eq_ignore_ascii_case(&event.app_bundle_id)
                    })
                    .unwrap_or(false);
                if belongs_to_blocked {
                    Some(path.clone())
                } else {
                    log::debug!(
                        "[FOCUS] skipping unfocus: current session {:?} does not belong to blocked app {}",
                        path, event.app_bundle_id
                    );
                    None
                }
            } else {
                None
            }
        };
        if let Some(path) = path_to_unfocus {
            log::debug!("[FOCUS] unfocusing {:?} due to blocked app", path);
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
        let excluded = config.is_path_excluded(p);
        let ext_blocked = !excluded && !config.is_extension_allowed(p);
        if excluded || ext_blocked {
            log::debug!(
                "[FOCUS] FILTERED path={:?} excluded={} ext_blocked={}",
                event.path, excluded, ext_blocked
            );
            // Unfocus the previous session so keystrokes aren't attributed
            // to the old document while the user is in a filtered app/path.
            let path_to_unfocus = { current_focus.read_recover().clone() };
            if let Some(path) = path_to_unfocus {
                unfocus_document_sync(&path, sessions, session_events_tx);
                *current_focus.write_recover() = None;
            }
            return;
        }
    }

    match event.event_type {
        FocusEventType::FocusGained => {
            let doc_path = if event.path.is_empty() {
                if !event.shadow_id.is_empty() {
                    log::debug!("[FOCUS] using shadow://{}", event.shadow_id);
                    format!("shadow://{}", event.shadow_id)
                } else {
                    let fallback = { current_focus.read_recover().clone() };
                    if let Some(path) = fallback {
                        log::debug!("[FOCUS] empty path, fallback to {:?}", path);
                        if let Some(session) = sessions.write_recover().get_mut(path.as_str()) {
                            session.focus_gained();
                        }
                        return;
                    }
                    log::debug!("[FOCUS] empty path, no fallback, dropping");
                    return;
                }
            } else {
                // S16: For title-inferred paths shared by multiple windows of the same
                // app (e.g. two Obsidian windows), append the CGWindowID so each window
                // gets a distinct session key. File-based paths (starting with '/') are
                // never modified — only virtual title:// keys are affected.
                let raw_path = event.path.clone();
                let needs_title_inf =
                    super::app_registry::needs_title_inference(&event.app_bundle_id);
                if let Some(wid) = event.window_id {
                    if needs_title_inf && raw_path.starts_with("title://") {
                        format!("{}#w{}", raw_path, wid)
                    } else {
                        raw_path
                    }
                } else {
                    raw_path
                }
            };

            log::debug!("[FOCUS] doc_path={:?}", doc_path);

            // When a title:// session's window title changes (e.g. VS Code
            // shows first-line-of-content for unsaved files), re-key the
            // existing session to the new title rather than creating a new
            // session. The #w{window_id} suffix is the stable identifier.
            if doc_path.starts_with("title://") {
                if let Some(wid_pos) = doc_path.rfind("#w") {
                    let wid_suffix = &doc_path[wid_pos..];
                    let mut sessions_map = sessions.write_recover();
                    let old_key = sessions_map
                        .keys()
                        .find(|k| k.ends_with(wid_suffix) && **k != doc_path)
                        .cloned();
                    if let Some(old_key) = old_key {
                        if let Some(mut session) = sessions_map.remove(&old_key) {
                            log::debug!(
                                "[FOCUS] re-keying title session: {:?} -> {:?}",
                                old_key, doc_path
                            );
                            session.path = doc_path.clone();
                            session.window_title = event.window_title.clone();
                            sessions_map.insert(doc_path.clone(), session);
                            // Also upgrade to real path if AXDocument resolved
                        }
                    }
                    drop(sessions_map);
                }
            }

            // When a title:// session gets a real AXDocument path (user saved
            // the file), upgrade the session to the real path so keystroke
            // attribution uses the filesystem path going forward.
            if !doc_path.starts_with("title://") && !doc_path.starts_with("shadow://") {
                let mut sessions_map = sessions.write_recover();
                if !sessions_map.contains_key(&doc_path) {
                    // Try window_id match first, then fall back to app bundle match.
                    let old_key = event.window_id
                        .map(|wid| format!("#w{}", wid))
                        .and_then(|wid_suffix| {
                            sessions_map.keys()
                                .find(|k| k.starts_with("title://") && k.ends_with(&wid_suffix))
                                .cloned()
                        })
                        .or_else(|| {
                            // Fallback: if there's exactly one title:// session for this
                            // app, upgrade it (covers apps that report window_id=None).
                            let app_prefix = format!("title://{}/", event.app_bundle_id);
                            let mut it = sessions_map.keys()
                                .filter(|k| k.starts_with(&app_prefix));
                            match (it.next(), it.next()) {
                                (Some(only), None) => Some(only.clone()),
                                _ => None,
                            }
                        });
                    if let Some(old_key) = old_key {
                        if let Some(mut session) = sessions_map.remove(&old_key) {
                            log::info!(
                                "[FOCUS] upgrading title session to real path: {:?} -> {:?}",
                                old_key, doc_path
                            );
                            session.origin_temp_path = Some(old_key);
                            session.path = doc_path.clone();
                            session.evidence_confidence =
                                super::types::EvidenceConfidence::Full;
                            session.confidence_reason = None;
                            sessions_map.insert(doc_path.clone(), session);
                        }
                    }
                }
                drop(sessions_map);
            }

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

            // Set current_focus to the new path immediately so keystrokes
            // arriving during focus_document_sync I/O are attributed to the
            // incoming document rather than dropped (the session will be
            // created momentarily by focus_document_sync).
            log::debug!("[FOCUS] set current_focus={:?}", doc_path);
            *current_focus.write_recover() = Some(doc_path.clone());

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
        }
        FocusEventType::ValueChanged => {
            // Handled in handle_focus_branch before delegation; should not reach here.
        }
        FocusEventType::FocusLost | FocusEventType::FocusUnknown => {
            let prev_path = {
                let focus = current_focus.read_recover();
                focus.clone()
            };
            // Only clear current_focus if the FocusLost event matches what is
            // currently focused. The HybridFocusTracker's polling watchdog can
            // deliver a stale FocusLost for the OLD document after the AXObserver
            // already set current_focus to the NEW document. Clearing
            // unconditionally would destroy the correct AXObserver focus.
            let should_clear = if event.path.is_empty() {
                // Generic app-level FocusLost — only clear if the currently
                // focused session belongs to the same app that lost focus.
                if let Some(ref current) = prev_path {
                    sessions.read_recover()
                        .get(current.as_str())
                        .map(|s| s.app_bundle_id.eq_ignore_ascii_case(&event.app_bundle_id))
                        .unwrap_or(true)
                } else {
                    false
                }
            } else if let Some(ref current) = prev_path {
                *current == event.path
            } else {
                false
            };
            log::debug!(
                "[FOCUS] FocusLost: event_path={:?} current={:?} should_clear={}",
                event.path, prev_path, should_clear
            );
            if should_clear {
                if let Some(path) = prev_path {
                    unfocus_document_sync(&path, sessions, session_events_tx);
                    *current_focus.write_recover() = None;
                }
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
    // macOS packages (.scriv, .pages, .rtfd, etc.) are directories that
    // act as single-file documents — allow them through.
    const PACKAGE_EXTENSIONS: &[&str] = &[
        "scriv", "scrivx", "pages", "key", "numbers", "rtfd",
        "band", "graffle", "mindnode", "oo3",
    ];
    if !path.starts_with("shadow://") {
        let p = std::path::Path::new(path);
        let is_package = p.extension()
            .and_then(|e| e.to_str())
            .map(|e| PACKAGE_EXTENSIONS.contains(&e.to_lowercase().as_str()))
            .unwrap_or(false);
        if p.is_dir() && !is_package {
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
                        let h = crate::crypto::hash_file_handle(&file)
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
                    .and_then(|store| {
                        store.load_document_stats(path).ok().flatten().or_else(|| {
                            if path.starts_with("title://") {
                                store.load_title_session_stats(path).ok().flatten()
                            } else {
                                None
                            }
                        })
                    })
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

            if path.starts_with("title://") {
                session.evidence_confidence = super::types::EvidenceConfidence::Partial;
                session.confidence_reason =
                    Some("document path inferred from window title".into());
            } else if path.starts_with("shadow://") {
                session.evidence_confidence = super::types::EvidenceConfidence::Partial;
                session.confidence_reason =
                    Some("document identified via CGWindowList, not AX".into());
            } else if !super::app_registry::is_known(&event.app_bundle_id) {
                session.evidence_confidence = super::types::EvidenceConfidence::Heuristic;
                session.confidence_reason =
                    Some("unknown app, no storage metadata available".into());
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
        if event.window_id.is_some() {
            session.window_id = event.window_id;
        }

        if was_new {
            log::debug!("focus_document_sync: new session created for {}", path);
            if !super::app_registry::is_known(&event.app_bundle_id) {
                super::app_registry::probe_and_cache(
                    &event.app_bundle_id,
                    &event.app_name,
                );
                super::app_registry::enrich_discovered_app(
                    &event.app_bundle_id,
                    path,
                );
            }
            Some((
                session.session_id.clone(),
                create_session_start_payload(session),
            ))
        } else {
            log::debug!("focus_document_sync: resumed existing session for {}", path);
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

    // Pre-compute file hash outside the write lock to avoid blocking other
    // threads on potentially slow file I/O (NFS, FUSE).
    let precomputed_hash = if event.hash.is_none() {
        compute_file_hash(&normalized_path).ok()
    } else {
        None
    };

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
                    .or(precomputed_hash.clone());
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
                    // Paste boundary detection: compare previous and current
                    // content hashes plus timing to classify large changes.
                    let prev_hash = {
                        use sha2::{Sha256, Digest};
                        let prev = session.current_hash.as_deref().unwrap_or("");
                        let result: [u8; 32] = Sha256::digest(prev.as_bytes()).into();
                        result
                    };
                    let new_hash = {
                        use sha2::{Sha256, Digest};
                        let result: [u8; 32] = Sha256::digest(hash.as_bytes()).into();
                        result
                    };
                    let last_ts = session
                        .jitter_ring
                        .last()
                        .map(|s| s.timestamp_ns)
                        .unwrap_or(0);
                    let current_ts = event
                        .timestamp
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_nanos() as i64)
                        .unwrap_or(0);
                    let (context, confidence) = detect_paste_boundary(
                        last_ts,
                        current_ts,
                        &prev_hash,
                        &new_hash,
                        &session.app_bundle_id,
                        &session.app_bundle_id,
                    );
                    if matches!(context, super::types::KeystrokeContext::PastedContent)
                        && confidence >= 0.92
                    {
                        log::info!(
                            "Paste boundary detected for {}: confidence={:.2}",
                            normalized_path,
                            confidence
                        );
                        update_keystroke_context_window(
                            session,
                            current_ts,
                            5000,
                            super::types::PasteSource::Unknown,
                            super::types::PasteContentKind::default(),
                            0,
                        );
                    }
                    session.current_hash = Some(hash.clone());
                }
                // Detect encoding transitions (e.g. ASCII -> UTF-8 BOM).
                if !normalized_path.starts_with("shadow://")
                    && !normalized_path.starts_with("title://")
                {
                    check_encoding_transition(session, Path::new(&normalized_path));
                }
                // Attribute intra-bundle file changes (e.g. Scrivener chapter .rtf)
                // to the bundle-relative segment so per-chapter velocity is tracked.
                if event.path != normalized_path {
                    let rel = event
                        .path
                        .strip_prefix(normalized_path.as_str())
                        .map(|s| s.trim_start_matches('/'))
                        .unwrap_or(event.path.as_str());
                    attribute_change_to_segment(session, rel, event.hash.as_deref());
                }
            }
            ChangeEventType::Created => {
                // Picked up on next focus event; attribute bundle-relative creation.
                if event.path != normalized_path {
                    let rel = event
                        .path
                        .strip_prefix(normalized_path.as_str())
                        .map(|s| s.trim_start_matches('/'))
                        .unwrap_or(event.path.as_str());
                    attribute_change_to_segment(session, rel, event.hash.as_deref());
                }
            }
            ChangeEventType::Deleted | ChangeEventType::Renamed { .. } => {
                unreachable!("handled above")
            }
        }
    } else if matches!(
        event.event_type,
        ChangeEventType::Created | ChangeEventType::Saved
    ) {
        // New file without an active session: check if it's a Save As copy.
        if let Some(hash) = &event.hash {
            drop(sessions_map);
            if let Some(detection) = detect_save_as(hash, &normalized_path, sessions) {
                log::info!(
                    "Save As detected: {} -> {} (session {})",
                    detection.original_path,
                    normalized_path,
                    &detection.original_session_id[..8],
                );
                // Record a WAL PathChange entry on the original session so the
                // checkpoint chain links the original document to the new copy.
                let key = signing_key.read_recover().key();
                let mut payload = Vec::with_capacity(
                    4 + detection.original_path.len() + 4 + normalized_path.len(),
                );
                payload.extend_from_slice(
                    &u32::try_from(detection.original_path.len())
                        .unwrap_or(u32::MAX)
                        .to_be_bytes(),
                );
                payload.extend_from_slice(detection.original_path.as_bytes());
                payload.extend_from_slice(
                    &u32::try_from(normalized_path.len())
                        .unwrap_or(u32::MAX)
                        .to_be_bytes(),
                );
                payload.extend_from_slice(normalized_path.as_bytes());
                wal_append_session_event(
                    &detection.original_session_id,
                    wal_dir,
                    key,
                    EntryType::PathChange,
                    payload,
                );
            }
        }
    }
}

pub fn end_session_sync(
    path: &str,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let session = sessions.write_recover().remove(path);

    if let Some(mut session) = session {
        session.transcription_detector.clear_buffer();
        session.transcription_detector.clear_matches();
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
            pending.drain(..1);
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

pub fn is_icloud_placeholder(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    name.starts_with('.') && name.ends_with(".icloud")
}

pub fn is_icloud_conflict_copy(path: &Path) -> bool {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if let Some(paren_start) = stem.rfind(" (") {
        let inside = &stem[paren_start + 2..];
        if let Some(close) = inside.rfind(')') {
            let content = &inside[..close];
            if let Some(dash_pos) = content.rfind(" - ") {
                let date_part = &content[dash_pos + 3..];
                return date_part.len() == 10
                    && date_part.as_bytes().get(4) == Some(&b'-')
                    && date_part.as_bytes().get(7) == Some(&b'-')
                    && date_part.bytes().filter(|b| b.is_ascii_digit()).count() == 8;
            }
        }
    }
    false
}

/// SHA-256 hash of a file, returned as a hex string.
///
/// Uses `O_NOFOLLOW` to prevent symlink-following TOCTOU attacks.
/// For general-purpose hashing (follows symlinks), use [`crate::crypto::hash_file`].
pub fn compute_file_hash(path: &str) -> std::io::Result<String> {
    if is_icloud_placeholder(Path::new(path)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "iCloud placeholder file, not real document content",
        ));
    }
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
    let (hash, _) = crate::crypto::hash_file_handle(&file)?;
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
///
/// For existing files, uses [`crate::utils::fs::canonicalize_validated`] which
/// atomically resolves and rejects symlinks. For not-yet-existing files,
/// canonicalizes the parent directory and appends the file name.
pub fn validate_path(path: impl AsRef<Path>) -> Result<PathBuf, String> {
    let path = path.as_ref();

    // Virtual paths (title://, shadow://) are sentinel-internal and not
    // filesystem paths — return as-is without canonicalization.
    let path_str = path.to_string_lossy();
    if path_str.starts_with("title://") || path_str.starts_with("shadow://") {
        return Ok(path.to_path_buf());
    }

    if path.exists() {
        let canonical = crate::utils::fs::canonicalize_validated(path)
            .map_err(|e| format!("Invalid path '{}': {}", path.display(), e))?;
        validate_canonical_path(&canonical)?;
        return Ok(canonical);
    }

    // File does not exist yet — validate the parent directory
    let parent = path
        .parent()
        .ok_or_else(|| "Invalid path: no parent".to_string())?;
    let canonical_parent = crate::utils::fs::canonicalize_validated(parent)
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
    content_kind: super::types::PasteContentKind,
    paste_char_count: usize,
) {
    let window_nanos = context_window_ms
        .checked_mul(1_000_000)
        .and_then(|w| i64::try_from(w).ok())
        .unwrap_or(i64::MAX);
    let window_end = paste_time.saturating_add(window_nanos);

    // Merge with the most recent paste if within 2 seconds (dedup Rust + FFI paths).
    if let Some(existing) = session.paste_context.last_mut() {
        let delta_ns = paste_time
            .saturating_sub(existing.paste_time)
            .unsigned_abs();
        if delta_ns < 2_000_000_000 {
            if source != super::types::PasteSource::Unknown {
                existing.source = source;
            }
            if content_kind != super::types::PasteContentKind::Prose
                || existing.content_kind == super::types::PasteContentKind::Prose
            {
                existing.content_kind = content_kind;
            }
            existing.context_window_end = existing.context_window_end.max(window_end);
            if paste_char_count > 0 {
                existing.paste_char_count = paste_char_count;
            }
            return;
        }
    }

    if session.paste_context.len() >= 100 {
        session.paste_context.remove(0);
    }
    session.paste_context.push(super::types::PasteContext {
        paste_time,
        context_window_end: window_end,
        keystroke_count_after_paste: 0,
        source,
        content_kind,
        paste_char_count,
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
    session
        .paste_context
        .last()
        .map(|ctx| current_time < ctx.context_window_end)
        .unwrap_or(false)
}

/// Maximum time allowed for git context capture before abandoning.
const GIT_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Run a git command, returning its stdout on success.
///
/// Returns `None` if the command fails or produces non-UTF-8 output.
fn run_git_command(args: &[&str], cwd: &Path) -> Option<String> {
    use std::process::Command;

    let mut child = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    // 5-second timeout to prevent hangs on NFS, credential prompts, etc.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let output = child.wait_with_output().ok()?;
                return String::from_utf8(output.stdout)
                    .ok()
                    .map(|s| s.trim().to_string());
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    log::warn!("git command timed out after 5s: {:?}", args);
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
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
    let handle = std::thread::Builder::new()
        .name("cpoe-git-ctx".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            capture_git_context_inner(&file_path_owned, &git_root_owned)
        });

    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            log::error!("cpoe-git-ctx thread spawn failed: {e}");
            return None;
        }
    };

    // Bounded wait: abandon the thread after GIT_COMMAND_TIMEOUT if it hasn't
    // returned. The orphaned thread will eventually finish or be reclaimed on
    // process exit; we just stop waiting for it.
    let deadline = std::time::Instant::now() + GIT_COMMAND_TIMEOUT;
    loop {
        if handle.is_finished() {
            return match handle.join() {
                Ok(result) => result,
                Err(_) => {
                    log::warn!("Git context capture thread panicked");
                    None
                }
            };
        }
        if std::time::Instant::now() >= deadline {
            log::warn!("Git context capture timed out, abandoning thread");
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
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
    anchor_manager: &Option<Arc<crate::anchors::AnchorManager>>,
) -> Option<[u8; 32]> {
    commit_checkpoint_for_path_with_semantics(
        path,
        reason,
        signing_key,
        writersproof_dir,
        challenge_nonce,
        stopping,
        None,
        anchor_manager,
        None,
    )
}

/// Like `commit_checkpoint_for_path` but attaches a semantic keystroke summary.
#[allow(clippy::too_many_arguments)]
pub(super) fn commit_checkpoint_for_path_with_semantics(
    path: &str,
    reason: &str,
    signing_key: &Arc<RwLock<super::behavioral_key::BehavioralKey>>,
    writersproof_dir: &Path,
    challenge_nonce: &Option<String>,
    stopping: &AtomicBool,
    semantic_summary: Option<String>,
    anchor_manager: &Option<Arc<crate::anchors::AnchorManager>>,
    captured_text: Option<String>,
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
    // Virtual title:// paths have no file to hash. When captured text is
    // available, hash it directly (analogous to hashing file contents for
    // real files) so the evidence is bound to the actual composed content.
    let (raw_size, content_hash_override) = if path.starts_with("title://") {
        if let Some(ref text) = captured_text {
            if !text.is_empty() {
                let h: [u8; 32] = blake3::hash(text.as_bytes()).into();
                // Also witness into content MMR for derivation proofs.
                witness_virtual_text(path, text);
                (text.len() as u64, Some(h))
            } else {
                (0u64, Some(blake3::hash(path.as_bytes()).into()))
            }
        } else {
            (0u64, Some(blake3::hash(path.as_bytes()).into()))
        }
    } else {
        (0u64, None)
    };
    let (raw_size, file) = if content_hash_override.is_some() {
        (raw_size, None)
    } else {
        match open_nofollow(path) {
            Ok(f) => match f.metadata() {
                Ok(m) => (m.len(), Some(f)),
                Err(e) => {
                    log::debug!("Auto-checkpoint metadata failed for {path}: {e}");
                    return None;
                }
            },
            Err(e) => {
                log::debug!("Auto-checkpoint open failed for {path}: {e}");
                return None;
            }
        }
    };
    // Hash the file while holding the handle open. The handle stays alive
    // through the SQLite transaction to prevent another process from modifying
    // the file between hash and store (TOCTOU closure).
    let content_hash = if let Some(h) = content_hash_override {
        h
    } else {
        match crate::crypto::hash_file_handle(file.as_ref().expect("file must be Some when no override")) {
            Ok((h, _)) => h,
            Err(e) => {
                log::debug!("Auto-checkpoint hash failed for {path}: {e}");
                return None;
            }
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

    // Enrich context_note with word count and track changes for real files.
    let context_note = if !path.starts_with("shadow://") && !path.starts_with("title://") {
        let file_path = Path::new(path);
        let mut extra = Vec::new();
        if !is_icloud_placeholder(file_path) {
            if let Some(wc) = extract_word_count(file_path) {
                extra.push(format!("wc:{wc}"));
            }
            if has_track_changes(file_path) {
                extra.push("track_changes:true".to_string());
            }
            if let Some((key, fp)) = structural_fingerprint(file_path) {
                extra.push(format!("{key}:{fp}"));
            }
        }
        if is_icloud_conflict_copy(file_path) {
            extra.push("icloud_conflict:true".to_string());
        }
        if extra.is_empty() {
            context_note
        } else {
            context_note.map(|cn| format!("{cn}|{}", extra.join("|")))
        }
    } else {
        context_note
    };

    let (dev_id, mach_id) = crate::ffi::helpers::device_identity();
    let mut event = crate::store::SecureEvent::new(
        path.to_string(),
        content_hash,
        file_size,
        context_note,
    );
    event.device_id = dev_id;
    event.machine_id = mach_id;
    event.challenge_nonce = challenge_nonce.clone();
    event.semantic_summary = semantic_summary;
    let sk_opt = signing_key.read_recover().key();
    let result = store.add_secure_event_with_signer(&mut event, sk_opt.as_ref());

    // File handle drops here — after the SQLite transaction has committed.
    // This closes the TOCTOU window: the file content that was hashed is
    // guaranteed to be the same content that was on disk during the entire
    // hash→sign→write sequence.
    drop(file);

    match result {
        Ok(_) => {
            log::info!("Auto-checkpoint committed for {path} ({reason})");
            let db_path = writersproof_dir.join("events.db");
            if let Err(e) = store.auto_archive_if_needed(&db_path) {
                log::debug!("Auto-archive check failed: {e}");
            }
            if let Some(ref am) = *anchor_manager {
                let am = Arc::clone(am);
                let hash = event.event_hash;
                let wp_dir = writersproof_dir.to_path_buf();
                drop(tokio::task::spawn(async move {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        am.anchor(&hash),
                    )
                    .await
                    {
                        Ok(Ok(anchor)) => {
                            log::info!(
                                "Anchor submitted: {} proof(s) for {}",
                                anchor.proofs.len(),
                                hex::encode(&hash[..8])
                            );
                            let anchor_dir = wp_dir.join("anchors");
                            let _ = std::fs::create_dir_all(&anchor_dir);
                            let file_path =
                                anchor_dir.join(format!("{}.json", hex::encode(hash)));
                            if let Ok(json) = serde_json::to_vec_pretty(&anchor) {
                                let _ = std::fs::write(&file_path, json);
                            }
                            // Submit to WritersProof transparency log if configured.
                            let anchor_sk = crate::ffi::helpers::load_signing_key().ok();
                            submit_to_writersproof_anchor(&wp_dir, &hash, anchor_sk.as_ref()).await;
                        }
                        Ok(Err(e)) => {
                            log::warn!(
                                "Anchoring failed for {}: {e}",
                                hex::encode(&hash[..8])
                            );
                        }
                        Err(_) => {
                            log::warn!(
                                "Anchoring timed out for {}",
                                hex::encode(&hash[..8])
                            );
                        }
                    }
                }));
            }
            Some(event.event_hash)
        }
        Err(e) => {
            log::warn!("Auto-checkpoint store write failed for {path}: {e}");
            None
        }
    }
}

/// Submit an evidence hash to the WritersProof /v1/anchor transparency log.
///
/// Reads config from `wp_dir`, signs the hash with the device key, and POSTs.
/// On failure, queues the request for later retry if offline_queue is enabled.
async fn submit_to_writersproof_anchor(
    wp_dir: &std::path::Path,
    hash: &[u8; 32],
    signing_key: Option<&ed25519_dalek::SigningKey>,
) {
    let config = match crate::config::CpopConfig::load_or_default(wp_dir) {
        Ok(c) => c.writersproof,
        Err(_) => return,
    };
    if !config.enabled || !config.auto_attest {
        return;
    }
    let hash_hex = hex::encode(hash);
    let client = match crate::writersproof::WritersProofClient::new(&config.base_url) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Failed to create WritersProof client: {e}");
            return;
        }
    };
    let (author_did, signature) = match signing_key {
        Some(sk) => {
            let vk = sk.verifying_key();
            let did = format!("did:key:z6Mk{}", bs58::encode(vk.as_bytes()).into_string());
            let sig = hex::encode(sk.sign(hash).to_bytes());
            (did, sig)
        }
        None => {
            log::warn!("No signing key available for anchor authentication");
            (String::new(), String::new())
        }
    };
    let req = crate::writersproof::types::AnchorRequest {
        evidence_hash: hash_hex.clone(),
        author_did,
        signature,
        metadata: None,
    };
    match client.anchor(req).await {
        Ok(resp) => {
            log::info!(
                "WritersProof anchor submitted: id={}, log_index={}",
                resp.anchor_id,
                resp.log_index
            );
        }
        Err(e) => {
            log::warn!("WritersProof anchor submission failed: {e}");
            if config.offline_queue {
                let queue_dir = wp_dir.join("queue");
                if let Ok(queue) = crate::writersproof::OfflineQueue::new(&queue_dir) {
                    if let Err(qe) = queue.enqueue_anchor(hash_hex, String::new(), None) {
                        log::warn!("Failed to queue anchor request: {qe}");
                    }
                }
            }
        }
    }
}

/// Maximum age (in seconds) of the last session activity for a "Save As" match.
/// If the new file's content hash matches an active session whose last activity
/// was more than this many seconds ago, we do not consider it a "Save As".
/// Witness captured text into a content MMR for a virtual session.
/// Appends paragraph-level segment hashes to a file-backed MMR so that
/// derivation proofs can later verify that exported text was composed
/// during the witnessed session.
fn witness_virtual_text(path: &str, text: &str) {
    use crate::content::mmr::ContentMmr;
    use crate::sentinel::app_registry::ContentGranularity;

    let mmr_dir = match ContentMmr::default_mmr_dir() {
        Ok(d) => d,
        Err(e) => {
            log::warn!("Content MMR dir error for {path}: {e}");
            return;
        }
    };
    // Derive a stable session ID from the virtual path for MMR file naming.
    let session_id = hex::encode(&blake3::hash(path.as_bytes()).as_bytes()[..16]);
    let mmr = match ContentMmr::open(&mmr_dir, &session_id, ContentGranularity::Paragraph) {
        Ok(m) => m,
        Err(e) => {
            log::warn!("Content MMR open failed for {path}: {e}");
            return;
        }
    };
    match mmr.witness_text_if_changed(text, &mmr_dir) {
        Ok(0) => {
            log::debug!(
                "Content MMR: text unchanged, skipped for virtual session {}",
                &session_id[..8],
            );
        }
        Ok(n) => {
            log::debug!(
                "Content MMR: appended {n} new segments for virtual session {}",
                &session_id[..8],
            );
        }
        Err(e) => {
            log::warn!("Content MMR witness failed for {path}: {e}");
        }
    }
}

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
    use std::io::{Read, Seek};

    let mut file = match open_nofollow(path.to_str().unwrap_or("")) {
        Ok(f) => f,
        Err(_) => return FileEncoding::Unknown,
    };

    let mut buf = [0u8; 4];
    let n = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return FileEncoding::Unknown,
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

    // No BOM: seek back to start and check if content is pure ASCII.
    let mut sample = [0u8; 512];
    let sample_n = {
        let _ = file.seek(std::io::SeekFrom::Start(0));
        file.read(&mut sample).unwrap_or(0)
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
#[allow(dead_code)] // Available for Scrivener binder title resolution
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
        "fdx" => extract_word_count_fdx(path),
        "odt" => extract_word_count_odt(path),
        "fountain" => extract_word_count_fountain(path),
        "tex" | "latex" => extract_word_count_tex(path),
        "opml" => extract_word_count_opml(path),
        "org" => extract_word_count_org(path),
        "rst" => extract_word_count_rst(path),
        "adoc" | "asciidoc" => extract_word_count_asciidoc(path),
        _ => None,
    }
}

/// Count whitespace-separated tokens in a plain text file.
fn extract_word_count_plaintext(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_FILE_SIZE {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;
    let count = contents.split_whitespace().count();
    Some(count as u64)
}

/// Strip RTF control words and count remaining whitespace-separated tokens.
fn extract_word_count_rtf(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_FILE_SIZE {
        return None;
    }
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
    let xml = read_zip_entry_as_str(path, "word/document.xml")?;
    let text = strip_xml_tags(&xml);
    let count = text.split_whitespace().count();
    Some(count as u64)
}

/// Count words in a Final Draft `.fdx` file (ZIP-wrapped or plain XML).
///
/// Extracts text content from `<Text>` elements inside `<Paragraph>` blocks,
/// which covers dialogue, action, and scene headings.
fn extract_word_count_fdx(path: &Path) -> Option<u64> {
    let xml = read_xml_content(path, ".fdx")?;
    let text = strip_xml_tags(&xml);
    let count = text.split_whitespace().count();
    Some(count as u64)
}

fn extract_word_count_odt(path: &Path) -> Option<u64> {
    let xml = read_zip_entry_as_str(path, "content.xml")?;
    let text = strip_xml_tags(&xml);
    let count = text.split_whitespace().count();
    Some(count as u64)
}

fn extract_word_count_fountain(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_FILE_SIZE {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;

    // Title page: key-value lines (e.g. "Title: My Script") before the first
    // blank line. If the first line isn't key-value format, there's no title page.
    let has_title_page = contents
        .lines()
        .next()
        .map(|l| l.contains(':') && !l.trim().is_empty())
        .unwrap_or(false);
    let mut counting = !has_title_page;
    let mut word_count: u64 = 0;
    let mut in_boneyard = false;
    let mut in_notes = false;

    for line in contents.lines() {
        if !counting {
            if line.trim().is_empty() {
                counting = true;
            }
            continue;
        }

        // Boneyard blocks: /* ... */
        if in_boneyard {
            if line.contains("*/") {
                in_boneyard = false;
            }
            continue;
        }
        if line.contains("/*") {
            in_boneyard = true;
            continue;
        }

        // Notes: [[ ... ]]
        if in_notes {
            if line.contains("]]") {
                in_notes = false;
            }
            continue;
        }
        if line.contains("[[") {
            in_notes = true;
            continue;
        }

        let trimmed = line.trim();
        // Skip synopsis lines, section headers, centering markers.
        if trimmed.starts_with('=')
            || trimmed.starts_with('#')
            || (trimmed.starts_with('>') && trimmed.ends_with('<'))
        {
            continue;
        }

        word_count += trimmed.split_whitespace().count() as u64;
    }
    Some(word_count)
}

fn extract_word_count_tex(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_FILE_SIZE {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;

    let body = if let Some(pos) = contents.find("\\begin{document}") {
        &contents[pos + "\\begin{document}".len()..]
    } else {
        &contents
    };

    let mut word_count: u64 = 0;
    let mut in_math = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('%') {
            continue;
        }
        if trimmed.contains("\\end{document}") {
            break;
        }
        let mut cleaned = String::with_capacity(trimmed.len());
        let mut chars = trimmed.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '$' => in_math = !in_math,
                '\\' if chars.peek() == Some(&'[') => {
                    in_math = true;
                    chars.next();
                }
                '\\' if chars.peek() == Some(&']') => {
                    in_math = false;
                    chars.next();
                }
                '\\' if !in_math => {
                    let mut cmd = String::new();
                    while let Some(&c) = chars.peek() {
                        if c.is_ascii_alphabetic() {
                            cmd.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if matches!(
                        cmd.as_str(),
                        "textbf" | "textit" | "emph" | "underline" | "text"
                    ) {
                        if chars.peek() == Some(&'{') {
                            chars.next();
                        }
                    }
                }
                '{' | '}' if !in_math => {}
                _ if !in_math => cleaned.push(ch),
                _ => {}
            }
        }
        word_count += cleaned.split_whitespace().count() as u64;
    }
    Some(word_count)
}

fn extract_word_count_opml(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_FILE_SIZE {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;
    let mut word_count: u64 = 0;
    let mut search_from = 0;
    while let Some(pos) = contents[search_from..].find("text=\"") {
        let abs = search_from + pos + "text=\"".len();
        if let Some(end) = contents[abs..].find('"') {
            let value = &contents[abs..abs + end];
            let text = strip_xml_tags(value);
            word_count += text.split_whitespace().count() as u64;
            search_from = abs + end + 1;
        } else {
            break;
        }
    }
    Some(word_count)
}

fn extract_word_count_org(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_FILE_SIZE {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;
    let mut word_count: u64 = 0;
    let mut in_drawer = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#+") || trimmed.starts_with('#') && trimmed.len() > 1 && trimmed.as_bytes()[1] == b'+' {
            continue;
        }
        if trimmed == ":PROPERTIES:" {
            in_drawer = true;
            continue;
        }
        if trimmed == ":END:" {
            in_drawer = false;
            continue;
        }
        if in_drawer {
            continue;
        }
        if trimmed.starts_with("# ") {
            continue;
        }
        // Strip link syntax: [[url][text]] → text
        let mut cleaned = String::with_capacity(trimmed.len());
        let mut chars = trimmed.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '[' && chars.peek() == Some(&'[') {
                chars.next();
                let mut link = String::new();
                for c in chars.by_ref() {
                    if c == ']' {
                        break;
                    }
                    link.push(c);
                }
                if chars.peek() == Some(&']') {
                    chars.next();
                }
                if let Some(text_start) = link.find("][") {
                    cleaned.push_str(&link[text_start + 2..]);
                } else {
                    cleaned.push_str(&link);
                }
            } else {
                cleaned.push(ch);
            }
        }
        word_count += cleaned.split_whitespace().count() as u64;
    }
    Some(word_count)
}

fn extract_word_count_rst(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_FILE_SIZE {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;
    let mut word_count: u64 = 0;
    let mut in_block = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(".. ") && trimmed.ends_with("::") {
            in_block = true;
            continue;
        }
        if in_block {
            if trimmed.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
                continue;
            }
            in_block = false;
        }
        if trimmed.starts_with(':') && trimmed.contains(": ") {
            continue;
        }
        word_count += trimmed.split_whitespace().count() as u64;
    }
    Some(word_count)
}

fn extract_word_count_asciidoc(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_FILE_SIZE {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;
    let mut word_count: u64 = 0;
    let mut in_comment = false;
    let mut in_block = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "////" {
            in_comment = !in_comment;
            continue;
        }
        if in_comment {
            continue;
        }
        if trimmed == "----" || trimmed == "====" || trimmed == "...." {
            in_block = !in_block;
            continue;
        }
        if in_block {
            continue;
        }
        if trimmed.starts_with(':') && trimmed.contains(": ") {
            continue;
        }
        word_count += trimmed.split_whitespace().count() as u64;
    }
    Some(word_count)
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
    match ext.as_str() {
        "docx" => match read_zip_entry_as_str(path, "word/document.xml") {
            Some(xml) => xml.contains("<w:ins") || xml.contains("<w:del"),
            None => false,
        },
        "fdx" => has_fdx_revisions(path),
        "odt" => match read_zip_entry_as_str(path, "content.xml") {
            Some(xml) => {
                xml.contains("<text:tracked-changes") || xml.contains("<text:change")
            }
            None => false,
        },
        "fountain" => {
            let contents = std::fs::read_to_string(path).unwrap_or_default();
            contents.contains("[[") || contents.contains("/*")
        }
        "tex" | "latex" => {
            let contents = std::fs::read_to_string(path).unwrap_or_default();
            contents.contains("\\todo{")
                || contents.contains("\\fixme{")
                || contents.contains("\\added{")
                || contents.contains("\\deleted{")
                || contents.contains("\\replaced{")
                || contents.contains("\\hl{")
        }
        _ => false,
    }
}

/// Detect Final Draft revision marks in an `.fdx` file.
///
/// FDX uses `Revision` attributes on `<Paragraph>` and `<Text>` elements and
/// `<ScriptNote>` elements to track changes across revision drafts.
fn has_fdx_revisions(path: &Path) -> bool {
    match read_xml_content(path, ".fdx") {
        Some(xml) => xml.contains("Revision=\"") || xml.contains("<ScriptNote"),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Bundle document helpers (Scrivener, Final Draft, Vellum)
// ---------------------------------------------------------------------------

/// Maximum number of segment entries tracked per bundle session.
const MAX_SEGMENT_ENTRIES: usize = 10_000;

/// Window (nanoseconds) within which a new output file creation is considered
/// a direct compile/export of the associated session's bundle.
const EXPORT_CORRELATION_WINDOW_NS: i64 = 30 * 1_000_000_000;

/// Formats almost exclusively created by deliberate export.
/// Guard: 30s window + keystrokes > 0 (no process match needed).
const EXPORT_TIER1: &[&str] = &["docx", "epub", "mobi", "odt", "pages", "rtf"];

/// Formats commonly created by many processes.
/// Guard: 30s window + keystrokes > 0 + signing_id must match session app.
const EXPORT_TIER2: &[&str] = &[
    "doc", "dvi", "fdx", "fountain", "html", "md", "mmd", "opml", "pdf", "ps",
    "tex", "txt",
];

/// Image formats — only attested when the writing app itself wrote the file.
/// Guard: 30s window + keystrokes > 0 + signing_id must match session app.
const EXPORT_TIER3_IMAGE: &[&str] = &["jpeg", "jpg", "png", "tiff"];

/// Parse all `<BinderItem>` entries from a Scrivener `.scriv` package into a
/// [`ScrivenerProjectMap`].
///
/// Reuses the private `find_scrivx_file` helper already in this module.  The
/// `.scrivx` XML is scanned with the same string-based technique as
/// `find_binder_item_title` to avoid new dependencies.
///
/// Returns `None` if the bundle is not a `.scriv` directory, the `.scrivx`
/// file is unreadable, or no binder items are found.
pub fn parse_scrivener_project_map(scriv_root: &Path) -> Option<ScrivenerProjectMap> {
    let scrivx_path = find_scrivx_file(scriv_root)?;
    let contents = std::fs::read_to_string(&scrivx_path).ok()?;

    let scrivx_hash = hex::encode(blake3::hash(contents.as_bytes()).as_bytes());

    let mut uuid_to_title = std::collections::HashMap::new();
    let mut search_from = 0usize;

    while let Some(rel_pos) = contents[search_from..].find("<BinderItem") {
        let abs_pos = search_from + rel_pos;
        let tag_end = match contents[abs_pos..].find('>') {
            Some(e) => abs_pos + e,
            None => break,
        };
        let tag = &contents[abs_pos..=tag_end];

        // Extract the ID attribute from the tag.
        let id = ['\"', '\''].iter().find_map(|q| {
            let needle = format!("ID={q}");
            let after = tag.find(needle.as_str()).map(|p| &tag[p + needle.len()..])?;
            after.find(*q).map(|end| after[..end].to_string())
        });

        if let Some(id) = id {
            let after_tag = &contents[tag_end..];
            if let Some(title_start) = after_tag.find("<Title>") {
                let content_start = title_start + "<Title>".len();
                if let Some(title_end) = after_tag[content_start..].find("</Title>") {
                    let title = after_tag[content_start..content_start + title_end].trim();
                    if !title.is_empty() {
                        uuid_to_title.insert(id, title.to_string());
                    }
                }
            }
        }

        search_from = tag_end + 1;
    }

    if uuid_to_title.is_empty() {
        return None;
    }

    let captured_at_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64;

    Some(ScrivenerProjectMap {
        uuid_to_title,
        scrivx_hash,
        captured_at_ns,
    })
}

pub fn parse_scrivener_binder_snapshot(
    scriv_root: &Path,
) -> Option<crate::evidence::DocumentStructureSnapshot> {
    let scrivx_path = find_scrivx_file(scriv_root)?;
    let contents = std::fs::read_to_string(&scrivx_path).ok()?;
    let source_hash = hex::encode(blake3::hash(contents.as_bytes()).as_bytes());

    let mut entries = Vec::new();
    let mut depth: u32 = 0;
    let mut search_from = 0usize;

    while search_from < contents.len() {
        // Find next tag
        let next_open = contents[search_from..].find('<');
        let next_open = match next_open {
            Some(p) => search_from + p,
            None => break,
        };
        let tag_end = match contents[next_open..].find('>') {
            Some(e) => next_open + e,
            None => break,
        };
        let tag = &contents[next_open..=tag_end];

        if tag.starts_with("<BinderItem") {
            let item_type = tag
                .find("Type=\"")
                .and_then(|p| {
                    let start = p + "Type=\"".len();
                    tag[start..].find('"').map(|end| tag[start..start + end].to_string())
                })
                .unwrap_or_default();
            let uuid = ['\"', '\''].iter().find_map(|q| {
                let needle = format!("ID={q}");
                let after = tag.find(needle.as_str()).map(|p| &tag[p + needle.len()..])?;
                after.find(*q).map(|end| after[..end].to_string())
            });
            let after_tag = &contents[tag_end + 1..];
            let title = after_tag.find("<Title>").and_then(|ts| {
                let start = ts + "<Title>".len();
                after_tag[start..]
                    .find("</Title>")
                    .map(|end| after_tag[start..start + end].trim().to_string())
            });
            entries.push(crate::evidence::DocumentStructureEntry {
                uuid: uuid.unwrap_or_default(),
                title: title.unwrap_or_default(),
                depth,
                item_type,
            });
            if !tag.ends_with("/>") {
                depth += 1;
            }
        } else if tag.starts_with("</BinderItem") {
            depth = depth.saturating_sub(1);
        }

        search_from = tag_end + 1;
    }

    if entries.is_empty() {
        return None;
    }

    let path_hash = hex::encode(blake3::hash(scriv_root.to_string_lossy().as_bytes()).as_bytes());
    Some(crate::evidence::DocumentStructureSnapshot {
        document_path_hash: path_hash,
        entries,
        source_hash,
        captured_at: chrono::Utc::now(),
    })
}

/// Record a file-change event for a path inside a bundle document session.
///
/// `rel_path` is the path component after the bundle root (e.g.
/// `"Files/Data/3F2C1A/content.rtf"`).  Increments the segment's
/// `change_count` and updates its `last_modified_ns` and `content_hash`.
/// New segment entries are created on first observation; the total number of
/// tracked segments is capped at [`MAX_SEGMENT_ENTRIES`].
pub fn attribute_change_to_segment(
    session: &mut DocumentSession,
    rel_path: &str,
    content_hash: Option<&str>,
) {
    if rel_path.is_empty() {
        return;
    }
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64;

    if let Some(seg) = session.segment_counts.get_mut(rel_path) {
        seg.change_count = seg.change_count.saturating_add(1);
        seg.last_modified_ns = now_ns;
        if let Some(h) = content_hash {
            seg.content_hash = Some(h.to_string());
        }
    } else if session.segment_counts.len() < MAX_SEGMENT_ENTRIES {
        session.segment_counts.insert(
            rel_path.to_string(),
            SessionSegment {
                rel_path: rel_path.to_string(),
                keystroke_count: 0,
                change_count: 1,
                last_modified_ns: now_ns,
                content_hash: content_hash.map(|h| h.to_string()),
            },
        );
    }
}

/// Check whether `new_file_path` looks like a manuscript export derived from
/// the given session.
///
/// Uses tiered extension matching:
/// - Tier 1 (docx, epub, etc.): time window + keystrokes only.
/// - Tier 2/3 (pdf, txt, html, images): additionally requires `signing_id` to
///   match the session's bundle ID (prevents false positives from other apps).
///
/// `signing_id` is the ES process signing identity (format "teamID:bundleID"
/// or bare process name). Pass an empty string to skip process matching
/// (only tier 1 extensions will match).
///
/// Returns a [`ManuscriptExportAttestation`] on match, `None` otherwise.
pub fn detect_export_event(
    session: &DocumentSession,
    new_file_path: &str,
    new_file_hash: &str,
    bundle_hash: &str,
    now_ns: i64,
    signing_id: &str,
) -> Option<crate::evidence::ManuscriptExportAttestation> {
    if session.keystroke_count == 0 {
        return None;
    }

    let ext = std::path::Path::new(new_file_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    let ext_str = ext.as_deref()?;

    let is_tier1 = EXPORT_TIER1.binary_search(&ext_str).is_ok();
    let is_tier2 = EXPORT_TIER2.binary_search(&ext_str).is_ok();
    let is_tier3 = EXPORT_TIER3_IMAGE.binary_search(&ext_str).is_ok();

    if !is_tier1 && !is_tier2 && !is_tier3 {
        return None;
    }

    // Tier 2/3 require the writing process to match the session's app.
    if is_tier2 || is_tier3 {
        if signing_id.is_empty() {
            return None;
        }
        let process_bid = signing_id.split(':').next_back().unwrap_or(signing_id);
        if !process_bid.eq_ignore_ascii_case(&session.app_bundle_id) {
            return None;
        }
    }

    let last_focus_ns = session
        .last_focused_at
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64;

    if now_ns.saturating_sub(last_focus_ns) > EXPORT_CORRELATION_WINDOW_NS {
        return None;
    }

    let output_path_hash = hex::encode(
        blake3::hash(new_file_path.as_bytes()).as_bytes(),
    );

    let correlation_method = if is_tier1 {
        "time_window"
    } else {
        "process_match"
    };

    Some(crate::evidence::ManuscriptExportAttestation {
        source_session_id: session.session_id.clone(),
        bundle_hash: bundle_hash.to_string(),
        output_hash: new_file_hash.to_string(),
        output_path_hash,
        source_checkpoint_ns: last_focus_ns,
        export_detected_ns: now_ns,
        export_format: ext_str.to_string(),
        correlation_method: correlation_method.to_string(),
    })
}

const ZIP_LOCAL_HEADER_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// Read a named entry from a ZIP archive as raw bytes.
///
/// Handles STORED (method 0) and DEFLATE (method 8) entries.  Returns `None`
/// on any I/O error, unsupported compression method, or if the entry is not
/// found within the first 500 entries.  The decompressed size is capped at
/// 16 MiB to prevent zip-bomb amplification.
fn read_zip_entry_bytes(path: &Path, entry_name: &str) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path).ok()?;
    const MAX_ENTRIES: usize = 500;
    const MAX_DECOMPRESSED: u64 = 16 * 1024 * 1024;

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
        if sig != ZIP_LOCAL_HEADER_SIG {
            break;
        }

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
            if compressed_size as u64 > MAX_DECOMPRESSED {
                return None;
            }
            let mut compressed = vec![0u8; compressed_size as usize];
            file.read_exact(&mut compressed).ok()?;

            return match compression {
                0 => Some(compressed),
                8 => {
                    use flate2::read::DeflateDecoder;
                    let decoder = DeflateDecoder::new(&compressed[..]);
                    let mut out = Vec::new();
                    decoder.take(MAX_DECOMPRESSED).read_to_end(&mut out).ok()?;
                    Some(out)
                }
                _ => None,
            };
        }

        if compressed_size > 0 {
            file.seek(SeekFrom::Current(compressed_size as i64)).ok()?;
        }
    }

    None
}

/// Find the first ZIP entry whose name ends with `suffix`.
///
/// Returns the entry name, or `None` if the file is not a ZIP or no entry
/// matches within the first 500 entries.
fn find_zip_entry_by_suffix(path: &Path, suffix: &str) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len > 100 * 1024 * 1024 {
        return None;
    }

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).ok()?;
    if magic != ZIP_LOCAL_HEADER_SIG {
        return None;
    }
    file.seek(SeekFrom::Start(0)).ok()?;

    for _ in 0..500 {
        let pos = file.stream_position().ok()?;
        if pos >= file_len {
            break;
        }
        let mut sig = [0u8; 4];
        if file.read_exact(&mut sig).is_err() {
            break;
        }
        if sig != ZIP_LOCAL_HEADER_SIG {
            break;
        }
        let mut header = [0u8; 26];
        file.read_exact(&mut header).ok()?;
        let compressed_size =
            u32::from_le_bytes([header[14], header[15], header[16], header[17]]);
        let name_len = u16::from_le_bytes([header[22], header[23]]) as usize;
        let extra_len = u16::from_le_bytes([header[24], header[25]]) as usize;
        let mut name_buf = vec![0u8; name_len];
        file.read_exact(&mut name_buf).ok()?;
        if extra_len > 0 {
            file.seek(SeekFrom::Current(extra_len as i64)).ok()?;
        }
        let name = String::from_utf8_lossy(&name_buf).into_owned();
        if name.ends_with(suffix) {
            return Some(name);
        }
        if compressed_size > 0 {
            file.seek(SeekFrom::Current(compressed_size as i64)).ok()?;
        }
    }
    None
}

/// Read XML from a file that may be ZIP-wrapped or plain text.
///
/// If the file starts with the ZIP signature, finds an entry matching
/// `inner_suffix` and extracts it via [`read_zip_entry_bytes`].
/// If not ZIP, reads the file directly (capped at [`MAX_HASH_FILE_SIZE`]).
fn read_xml_content(path: &Path, inner_suffix: &str) -> Option<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).ok()?;
    drop(file);

    if magic == ZIP_LOCAL_HEADER_SIG {
        let entry_name = find_zip_entry_by_suffix(path, inner_suffix)?;
        let bytes = read_zip_entry_bytes(path, &entry_name)?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        let meta = std::fs::metadata(path).ok()?;
        if meta.len() > MAX_HASH_FILE_SIZE {
            return None;
        }
        std::fs::read_to_string(path).ok()
    }
}

/// Read a single entry from a ZIP file as a UTF-8 string.
///
/// Delegates to [`read_zip_entry_bytes`] and converts the result to UTF-8.
fn read_zip_entry_as_str(path: &Path, entry_name: &str) -> Option<String> {
    String::from_utf8(read_zip_entry_bytes(path, entry_name)?).ok()
}

/// Compute a stable structural fingerprint for a Final Draft `.fdx` file.
///
/// `.fdx` files are ZIP archives containing a single XML document.  This
/// function locates the XML entry (any entry ending in `.fdx` inside the
/// archive), extracts scene-heading text (`Element Type="Scene Heading"`),
/// and returns the BLAKE3 hash of a canonical `{count}:{heading1}:{heading2}:…`
/// string.  The fingerprint is stable across cosmetic re-saves because it is
/// derived from parsed scene content rather than raw bytes (which vary due to
/// compression timestamps).
///
/// Returns `None` if the file cannot be opened, is not a valid ZIP, or
/// contains no scene headings.
pub fn parse_fdx_scene_fingerprint(path: &Path) -> Option<String> {
    let xml = read_xml_content(path, ".fdx")?;

    // Collect scene headings: <Paragraph Type="Scene Heading"><Text>…</Text></Paragraph>
    let mut headings: Vec<String> = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = xml[search_from..].find("Type=\"Scene Heading\"") {
        let abs = search_from + rel;
        let after = &xml[abs..];
        if let Some(text_start) = after.find("<Text>") {
            let content_start = text_start + "<Text>".len();
            if let Some(text_end) = after[content_start..].find("</Text>") {
                let heading = after[content_start..content_start + text_end].trim();
                if !heading.is_empty() {
                    headings.push(heading.to_string());
                }
            }
        }
        search_from = abs + 1;
    }

    if headings.is_empty() {
        return None;
    }

    let canonical = format!("{}:{}", headings.len(), headings.join(":"));
    Some(hex::encode(blake3::hash(canonical.as_bytes()).as_bytes()))
}

fn parse_fountain_scene_fingerprint(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_FILE_SIZE {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;

    let has_title_page = contents
        .lines()
        .next()
        .map(|l| l.contains(':') && !l.trim().is_empty())
        .unwrap_or(false);
    let mut headings: Vec<String> = Vec::new();
    let mut past_title_page = !has_title_page;

    for line in contents.lines() {
        let trimmed = line.trim();
        if !past_title_page {
            if trimmed.is_empty() {
                past_title_page = true;
            }
            continue;
        }

        let upper = trimmed.to_ascii_uppercase();
        let is_heading = upper.starts_with("INT.")
            || upper.starts_with("EXT.")
            || upper.starts_with("INT./EXT.")
            || upper.starts_with("I/E.")
            || (trimmed.starts_with('.') && trimmed.len() > 1);
        if is_heading {
            headings.push(trimmed.to_string());
        }
    }

    if headings.is_empty() {
        return None;
    }

    let canonical = format!("{}:{}", headings.len(), headings.join(":"));
    Some(hex::encode(blake3::hash(canonical.as_bytes()).as_bytes()))
}

fn parse_opml_outline_fingerprint(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_FILE_SIZE {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;

    let mut items: Vec<String> = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("<outline") {
            continue;
        }
        let depth = (line.len() - line.trim_start().len()) / 2;
        if let Some(pos) = trimmed.find("text=\"") {
            let start = pos + "text=\"".len();
            if let Some(end) = trimmed[start..].find('"') {
                let text = &trimmed[start..start + end];
                items.push(format!("{depth}:{text}"));
            }
        }
    }

    if items.is_empty() {
        return None;
    }

    let canonical = format!("{}:{}", items.len(), items.join(":"));
    Some(hex::encode(blake3::hash(canonical.as_bytes()).as_bytes()))
}

fn structural_fingerprint(path: &Path) -> Option<(&'static str, String)> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "fdx" => parse_fdx_scene_fingerprint(path).map(|fp| ("fdx_scene_fp", fp)),
        "fountain" => {
            parse_fountain_scene_fingerprint(path).map(|fp| ("fountain_scene_fp", fp))
        }
        "opml" => {
            parse_opml_outline_fingerprint(path).map(|fp| ("opml_outline_fp", fp))
        }
        _ => None,
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
            PasteContentKind::default(),
            0,
        );

        assert!(!session.paste_context.is_empty());
        let ctx = session.paste_context.last().unwrap();
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
            PasteContentKind::default(),
            0,
        );
        assert_eq!(
            session.paste_context.last().unwrap().source,
            PasteSource::SameDocument,
        );

        update_keystroke_context_window(
            &mut session,
            paste_time,
            30_000,
            PasteSource::External,
            PasteContentKind::default(),
            0,
        );
        assert_eq!(
            session.paste_context.last().unwrap().source,
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

    #[test]
    fn test_parse_fdx_scene_fingerprint_non_fdx() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("script.txt");
        std::fs::write(&file, "not an fdx file").unwrap();
        assert!(parse_fdx_scene_fingerprint(&file).is_none());
    }

    #[test]
    fn test_parse_fdx_scene_fingerprint_missing_file() {
        let path = std::path::Path::new("/nonexistent/script.fdx");
        assert!(parse_fdx_scene_fingerprint(path).is_none());
    }

    #[test]
    fn test_parse_fdx_scene_fingerprint_plain_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FinalDraft DocumentType="Script" Template="No" Version="4">
<Content>
<Paragraph Type="Scene Heading"><Text>INT. OFFICE - DAY</Text></Paragraph>
<Paragraph Type="Action"><Text>A writer types at a desk.</Text></Paragraph>
<Paragraph Type="Scene Heading"><Text>EXT. PARK - NIGHT</Text></Paragraph>
</Content>
</FinalDraft>"#;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("script.fdx");
        std::fs::write(&file, xml).unwrap();

        let fp = parse_fdx_scene_fingerprint(&file);
        assert!(fp.is_some());
        // Deterministic: same content always produces the same fingerprint.
        assert_eq!(fp, parse_fdx_scene_fingerprint(&file));
    }

    #[test]
    fn test_extract_word_count_fdx_plain_xml() {
        let xml = r#"<?xml version="1.0"?>
<FinalDraft DocumentType="Script" Template="No" Version="4">
<Content>
<Paragraph Type="Scene Heading"><Text>INT. OFFICE - DAY</Text></Paragraph>
<Paragraph Type="Dialogue"><Text>Hello world from the script.</Text></Paragraph>
</Content>
</FinalDraft>"#;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("script.fdx");
        std::fs::write(&file, xml).unwrap();

        let wc = extract_word_count(&file);
        assert!(wc.is_some());
        assert!(wc.unwrap() > 0);
    }

    #[test]
    fn test_has_fdx_revisions_none() {
        let xml = r#"<?xml version="1.0"?>
<FinalDraft DocumentType="Script" Template="No" Version="4">
<Content>
<Paragraph Type="Action"><Text>Clean draft.</Text></Paragraph>
</Content>
</FinalDraft>"#;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("clean.fdx");
        std::fs::write(&file, xml).unwrap();

        assert!(!has_track_changes(&file));
    }

    #[test]
    fn test_has_fdx_revisions_with_revision_attr() {
        let xml = r#"<?xml version="1.0"?>
<FinalDraft DocumentType="Script" Template="No" Version="4">
<Content>
<Paragraph Type="Action" Revision="1"><Text>Revised line.</Text></Paragraph>
</Content>
</FinalDraft>"#;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revised.fdx");
        std::fs::write(&file, xml).unwrap();

        assert!(has_track_changes(&file));
    }

    #[test]
    fn test_has_fdx_revisions_with_script_note() {
        let xml = r##"<?xml version="1.0"?>
<FinalDraft DocumentType="Script" Template="No" Version="4">
<Content>
<Paragraph Type="Action"><Text>Some line.</Text></Paragraph>
<ScriptNote Color="#FFFF00"><Paragraph><Text>Fix this.</Text></Paragraph></ScriptNote>
</Content>
</FinalDraft>"##;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("noted.fdx");
        std::fs::write(&file, xml).unwrap();

        assert!(has_track_changes(&file));
    }
}
