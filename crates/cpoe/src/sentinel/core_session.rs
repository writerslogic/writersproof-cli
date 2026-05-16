// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Session management for the Sentinel: start/stop witnessing, baseline updates.

use super::helpers::*;
use super::types::*;
use crate::crypto::ObfuscatedString;
use crate::ipc::IpcErrorCode;
use crate::wal::{EntryType, Wal};
use crate::{MutexRecover, RwLockRecover};
use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use super::core::Sentinel;

impl Sentinel {
    /// Get the cached event store, opening it lazily if needed.
    fn open_event_store(&self) -> anyhow::Result<std::sync::MutexGuard<'_, Option<crate::store::SecureStore>>> {
        self.get_or_open_store()
            .ok_or_else(|| anyhow::anyhow!("signing key not initialized"))
    }

    /// Begin witnessing a file, creating a session and WAL entry.
    pub fn start_witnessing(
        &self,
        file_path: &Path,
    ) -> std::result::Result<(), (IpcErrorCode, String)> {
        log::debug!("start_witnessing: entry path={}", file_path.display());
        // H-002: Reject relative paths to prevent directory traversal via crafted titles.
        if !file_path.is_absolute() {
            return Err((
                IpcErrorCode::InvalidMessage,
                format!("Relative path not accepted: {}", file_path.display()),
            ));
        }

        if !file_path.exists() {
            return Err((
                IpcErrorCode::FileNotFound,
                format!("File not found: {}", file_path.display()),
            ));
        }

        // H-004: Canonicalize to resolve symlinks before using as session key.
        let canonical = match file_path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                return Err((
                    IpcErrorCode::InvalidMessage,
                    format!("Cannot resolve path {}: {e}", file_path.display()),
                ));
            }
        };
        let path_str = canonical.to_string_lossy().to_string();

        // AUD-041: Acquire signing_key before sessions to maintain lock ordering.
        let key = {
            #[cfg(debug_assertions)]
            let _guard =
                super::core::lock_order::assert_order(super::core::lock_order::SIGNING_KEY);
            self.signing_key.read_recover().key()
        };

        #[cfg(debug_assertions)]
        let _session_guard =
            super::core::lock_order::assert_order(super::core::lock_order::SESSIONS);

        // Single write lock for check+insert to avoid TOCTOU race
        let mut sessions = self.sessions.write_recover();
        if sessions.contains_key(&path_str) {
            return Err((
                IpcErrorCode::AlreadyTracking,
                format!("Already tracking: {}", file_path.display()),
            ));
        }
        let mut session = DocumentSession::new(
            path_str.clone(),
            "cli".to_string(),          // app_bundle_id for CLI-initiated tracking
            "writerslogic".to_string(), // app_name
            ObfuscatedString::new(&path_str),
        );

        if let Ok(hash) = compute_file_hash(&path_str) {
            session.initial_hash = Some(hash.clone());
            session.current_hash = Some(hash);
        }

        // Load cumulative stats from previous sessions via cached store.
        let store_guard = self.get_or_open_store();

        match store_guard {
            Some(ref guard) if guard.is_some() => match guard.as_ref().unwrap().load_document_stats(&path_str) {
                Ok(Some(stats)) => {
                    session.cumulative_keystrokes_base =
                        u64::try_from(stats.total_keystrokes).unwrap_or(0);
                    session.cumulative_focus_ms_base = stats.total_focus_ms;
                    session.session_number = u32::try_from(stats.session_count).unwrap_or(0);
                    session.first_tracked_at = Some(
                        UNIX_EPOCH
                            + Duration::from_secs(
                                u64::try_from(stats.first_tracked_at).unwrap_or(0),
                            ),
                    );
                }
                Ok(None) => {
                    session.first_tracked_at = Some(SystemTime::now());
                }
                Err(e) => {
                    log::warn!("Failed to load document stats for {path_str}: {e}");
                    session.first_tracked_at = Some(SystemTime::now());
                }
            },
            _ => {
                log::warn!("Failed to open store for document stats: signing key unavailable");
                session.first_tracked_at = Some(SystemTime::now());
            }
        }

        let wal_path = self
            .config
            .wal_dir
            .join(format!("{}.wal", session.session_id));
        // Session IDs are normally 32 random bytes hex-encoded (64 hex chars -> 32 bytes).
        // Non-hex IDs (e.g. synthesized ones with a `rfc-` prefix) fall back to a
        // deterministic SHA-256 digest of the ID string so the WAL is always created.
        let mut session_id_bytes = [0u8; 32];
        let hex_str = &session.session_id[..64.min(session.session_id.len())];
        if hex::decode_to_slice(hex_str, &mut session_id_bytes).is_err() {
            log::warn!(
                "session_id not hex-encoded; falling back to SHA-256(session_id) for WAL key"
            );
            let digest = sha2::Sha256::digest(session.session_id.as_bytes());
            session_id_bytes.copy_from_slice(&digest);
        }
        if let Some(ref signing_key) = key {
            // Copy key bytes for Wal::open (which takes SigningKey by value)
            // and zeroize the intermediate copy. SigningKey::from_bytes produces
            // a value whose Drop impl zeroizes internal state.
            let mut key_bytes = signing_key.to_bytes();
            let wal_key = SigningKey::from_bytes(&key_bytes);
            key_bytes.zeroize();
            match Wal::open(&wal_path, session_id_bytes, wal_key) {
                Ok(wal) => {
                    let payload = create_session_start_payload(&session);
                    if let Err(e) = wal.append(EntryType::SessionStart, payload) {
                        log::warn!(
                            "WAL append failed for session {}: {}",
                            session.session_id,
                            e
                        );
                    }
                }
                Err(e) => {
                    log::error!(
                        "WAL::open() failed for session {}: {}; session continues without persistent proof",
                        session.session_id,
                        e
                    );
                }
            }
        } else {
            log::warn!(
                "Signing key not initialized, skipping WAL for session {}",
                session.session_id
            );
        }

        if self
            .session_events_tx
            .send(SessionEvent {
                event_type: SessionEventType::Started,
                session_id: session.session_id.clone(),
                document_path: path_str.clone(),
                timestamp: SystemTime::now(),
                hash: session.initial_hash.clone(),
            })
            .is_err()
        {
            log::debug!("no session event listeners for Started");
        }

        sessions.insert(path_str.clone(), session);
        drop(sessions);
        super::trace!(
            "[START_WITNESSING] session created, setting current_focus={:?} targeted=true",
            path_str
        );
        *self.current_focus.write_recover() = Some(path_str.clone());
        *self.targeted_path.write_recover() = Some(path_str);
        Ok(())
    }

    /// Commit a checkpoint for the given file path if the session has new keystrokes.
    /// Returns true if a checkpoint was committed, false otherwise.
    pub fn commit_checkpoint_for_path(&self, path: &str) -> bool {
        log::debug!("commit_checkpoint_for_path: entry path={}", path);
        if !self.running.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        // AUD-041: Acquire signing_key before sessions so the lock ordering
        // is preserved when we later call open_event_store (which re-reads
        // signing_key internally).
        let sk_cached = {
            #[cfg(debug_assertions)]
            let _sk_guard =
                super::core::lock_order::assert_order(super::core::lock_order::SIGNING_KEY);
            self.signing_key.read_recover().key()
        };

        // Atomically check-and-claim the checkpoint slot so a concurrent
        // caller for the same path cannot start a duplicate commit during
        // the hash/store window. On failure below we roll the count back.
        let (claimed_count, prior_count) = {
            #[cfg(debug_assertions)]
            let _sess_guard =
                super::core::lock_order::assert_order(super::core::lock_order::SESSIONS);
            let mut sessions = self.sessions.write_recover();
            let Some(s) = sessions.get_mut(path) else {
                return false;
            };
            if s.keystroke_count <= s.last_checkpoint_keystrokes {
                return false;
            }
            let prior = s.last_checkpoint_keystrokes;
            s.last_checkpoint_keystrokes = s.keystroke_count;
            (s.keystroke_count, prior)
        };

        // Skip shadow:// paths; they have no real file to hash.
        if path.starts_with("shadow://") {
            return false;
        }

        let file_path = std::path::Path::new(path);
        if !file_path.exists() {
            log::warn!("Cannot auto-checkpoint; file not found: {path}");
            return false;
        }

        let (content_hash, raw_size) = match crate::crypto::hash_file_with_size(file_path) {
            Ok(pair) => pair,
            Err(e) => {
                log::warn!("Auto-checkpoint hash failed for {path}: {e}");
                return false;
            }
        };
        let file_size = i64::try_from(raw_size).unwrap_or_else(|_| {
            log::warn!("file size {} exceeds i64::MAX", raw_size);
            i64::MAX
        });

        if !self.running.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }

        // Phase 0: snapshot session info under a read lock before opening the store.
        // Keeping no sessions lock during Phase 1 maintains the documented ordering:
        // sessions → cached_store (AUD-041 / CS-1).
        let session_info = {
            let sessions = self.sessions.read_recover();
            sessions.get(path).map(|s| {
                (
                    s.session_id.clone(),
                    s.paste_context.is_some(),
                    s.app_bundle_id.clone(),
                    s.window_title.reveal().to_string(),
                    s.transcription_suspicion.ecology_score,
                )
            })
        };

        // Snapshot bundle-specific state for shadow session persistence.
        // Only populated when `path` is a bundle document (.scriv, .ulysses).
        let bundle_snapshot = if super::bundle_monitor::is_bundle_document(
            std::path::Path::new(path),
        ) {
            let sessions = self.sessions.read_recover();
            sessions.get(path).map(|s| {
                let segment_json = serde_json::to_string(&s.segment_counts).ok();
                let scrivx_hash = s
                    .scrivener_project_map
                    .as_ref()
                    .map(|m| m.scrivx_hash.clone());
                let project_uuid = s
                    .scrivener_project_map
                    .as_ref()
                    .and_then(|m| m.uuid_to_title.keys().next().cloned())
                    .unwrap_or_else(|| hex::encode(blake3::hash(path.as_bytes()).as_bytes()));
                (
                    s.session_id.clone(),
                    s.app_bundle_id.clone(),
                    project_uuid,
                    segment_json,
                    scrivx_hash,
                )
            })
        } else {
            None
        };

        // Phase 1: all store I/O in a scoped closure so the cached_store MutexGuard
        // is released before Phase 2 acquires the sessions write lock.
        let store_result: Result<([u8; 32], [u8; 32]), anyhow::Error> = (|| {
            let mut store_guard = self
                .get_or_open_store()
                .ok_or_else(|| anyhow::anyhow!("signing key not initialized"))?;
            let store = store_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("store not available"))?;

            let prev_file_size = store
                .get_events_for_file(path)
                .ok()
                .and_then(|evts| evts.last().map(|e| e.file_size))
                .unwrap_or(0);
            let mut event = crate::store::SecureEvent::new(
                path.to_string(),
                content_hash,
                file_size,
                Some("Auto-checkpoint".to_string()),
            );
            event.size_delta = (file_size - prev_file_size) as i32;
            store.add_secure_event_with_signer(&mut event, sk_cached.as_ref())?;

            if let (Some(ref sk), Some((ref sid, has_paste, ref bundle, ref title, eco_score))) =
                (&sk_cached, &session_info)
            {
                let ts = crate::store::text_fragments::current_timestamp_ms();
                let nonce = crate::store::text_fragments::generate_nonce();
                let ctx = if *has_paste {
                    crate::store::text_fragments::KeystrokeContext::PastedContent
                } else {
                    crate::store::text_fragments::KeystrokeContext::OriginalComposition
                };
                let sig = crate::store::text_fragments::sign_fragment(
                    sk,
                    sid,
                    &content_hash,
                    ts,
                    &nonce,
                );
                let fragment = crate::store::text_fragments::TextFragment {
                    id: None,
                    fragment_hash: content_hash.to_vec(),
                    session_id: sid.clone(),
                    source_app_bundle_id: Some(bundle.clone()).filter(|s| !s.is_empty()),
                    source_window_title: Some(title.clone()).filter(|s| !s.is_empty()),
                    source_signature: sig.to_vec(),
                    nonce: nonce.to_vec(),
                    timestamp: ts,
                    keystroke_context: Some(ctx),
                    keystroke_confidence: Some(if *eco_score > f64::EPSILON {
                        eco_score.clamp(0.0, 1.0)
                    } else {
                        1.0
                    }),
                    keystroke_sequence_hash: None,
                    source_session_id: None,
                    source_evidence_packet: None,
                    wal_entry_hash: None,
                    cloudkit_record_id: None,
                    sync_state: None,
                };
                if let Err(e) = store.insert_text_fragment(&fragment) {
                    log::warn!("Failed to insert text fragment for {path}: {e}");
                }
            }

            // Persist shadow session state for bundle documents so sessions
            // resume correctly across sentinel restarts.
            if let Some((ref sid, ref app_bid, ref proj_uuid, ref seg_json, ref scrivx)) =
                bundle_snapshot
            {
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as i64)
                    .unwrap_or(0);
                if let Err(e) = store.upsert_shadow_session(
                    app_bid,
                    proj_uuid,
                    sid,
                    None,
                    seg_json.as_deref().unwrap_or("{}"),
                    scrivx.as_deref(),
                    now_ns,
                ) {
                    log::warn!("shadow session upsert failed for {path}: {e}");
                }
            }

            Ok((event.content_hash, event.event_hash))
            // store_guard (cached_store Mutex) released here.
        })();

        match store_result {
            Ok((ev_content_hash, ev_event_hash)) => {
                log::info!("Auto-checkpoint committed for {path}");

                // Phase 2: hw cosign — sessions write acquired first, then cached_store
                // inside it (correct lock ordering per AUD-041: sessions → cached_store).
                if let Some(ref tpm) = self.tpm_provider {
                    let mut sessions = self.sessions.write_recover();
                    if let Some(session) = sessions.get_mut(path) {
                        if let Some(guard) = self.get_or_open_store() {
                            try_hw_cosign(
                                session,
                                tpm.as_ref(),
                                &ev_content_hash,
                                Some(&ev_event_hash),
                                (*guard).as_ref().map(|s| (s, path)),
                            );
                        }
                    }
                }

                true
            }
            Err(e) => {
                log::warn!("Auto-checkpoint store write failed for {path}: {e}");
                // Roll back the claim so the next tick can retry, but only if no
                // other commit has advanced the counter past ours in the meantime.
                // No store lock is held here; sessions write is safe to acquire.
                let mut sessions = self.sessions.write_recover();
                if let Some(session) = sessions.get_mut(path) {
                    if session.last_checkpoint_keystrokes == claimed_count {
                        session.last_checkpoint_keystrokes = prior_count;
                    }
                }
                false
            }
        }
    }

    /// Stop witnessing a file, ending its session and updating the baseline.
    pub fn stop_witnessing(
        &self,
        file_path: &Path,
    ) -> std::result::Result<(), (IpcErrorCode, String)> {
        // Canonicalize so the session lookup matches the key used by
        // `start_witnessing`, which resolves symlinks and macOS
        // /var → /private/var before storing. Fall back to the raw path
        // if canonicalization fails (file may have been deleted).
        let path_str = match file_path.canonicalize() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => file_path.to_string_lossy().to_string(),
        };

        // Commit a final checkpoint before removing the session so keystrokes
        // are never lost on abrupt session end.
        self.commit_checkpoint_for_path(&path_str);

        // Pre-cache the event store before acquiring the sessions write lock
        // to maintain lock ordering (signing_key before sessions, per AUD-041).
        let store_result = self.open_event_store();

        let session = self.sessions.write_recover().remove(&path_str);

        if let Some(session) = session {
            // Persist cumulative document stats before tearing down the session.
            let now_ts = crate::utils::now_secs() as i64;
            let elapsed_secs = session.start_time.elapsed().unwrap_or_default().as_secs();
            let first_tracked = session
                .first_tracked_at
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(now_ts);
            match store_result {
                Ok(ref guard) if guard.is_some() => {
                    let store = guard.as_ref().unwrap();
                    let prev_dur = store
                        .load_document_stats(&path_str)
                        .ok()
                        .flatten()
                        .map(|s| s.total_duration_secs)
                        .unwrap_or(0);
                    let stats = crate::store::DocumentStats {
                        file_path: path_str.clone(),
                        total_keystrokes: i64::try_from(session.total_keystrokes())
                            .unwrap_or(i64::MAX),
                        total_focus_ms: session.total_focus_ms_cumulative(),
                        session_count: i64::from(session.session_number + 1),
                        total_duration_secs: prev_dur
                            .saturating_add(i64::try_from(elapsed_secs).unwrap_or(i64::MAX)),
                        first_tracked_at: first_tracked,
                        last_tracked_at: now_ts,
                    };
                    if let Err(e) = store.save_document_stats(&stats) {
                        log::warn!("Failed to save document stats for {path_str}: {e}");
                    }
                }
                Err(e) => {
                    log::warn!("Failed to open store to save document stats: {e}");
                }
                _ => {}
            }

            let session_path = path_str.clone();
            if self
                .session_events_tx
                .send(SessionEvent {
                    event_type: SessionEventType::Ended,
                    session_id: session.session_id,
                    document_path: path_str,
                    timestamp: SystemTime::now(),
                    hash: session.current_hash,
                })
                .is_err()
            {
                log::debug!("no session event listeners for Ended");
            }

            if let Some(shadow_id) = session.shadow_id {
                if let Err(e) = self.shadow.delete(&shadow_id) {
                    log::warn!("shadow buffer delete failed for {shadow_id}: {e}");
                }
            }

            if let Err(e) = self.update_baseline() {
                log::error!("Failed to update baseline: {}", e);
            }

            // Only clear targeted mode if the stopped session is the targeted one.
            // Compare against the path sent in the Ended event (path_str was moved).
            if self.targeted_path().as_deref() == Some(session_path.as_str()) {
                self.clear_targeted_mode();
            }
            Ok(())
        } else {
            Err((
                IpcErrorCode::NotTracking,
                format!("Not tracking: {}", file_path.display()),
            ))
        }
    }

    /// Return the paths of all currently tracked files.
    pub fn tracked_files(&self) -> Vec<String> {
        self.sessions.read_recover().keys().cloned().collect()
    }

    /// Return the sentinel start time, or None if not yet started.
    pub fn start_time(&self) -> Option<SystemTime> {
        *self.start_time.lock_recover()
    }

    /// Compute and persist an updated authorship baseline digest from accumulated activity.
    pub fn update_baseline(&self) -> anyhow::Result<()> {
        let summary = self
            .activity_accumulator
            .read_recover()
            .to_session_summary();
        if summary.keystroke_count < 10 {
            return Ok(());
        }

        // Clone signing key into a local and drop the read lock immediately
        // to avoid holding it across database I/O below.
        let signing_key_local = self
            .signing_key
            .read_recover()
            .key()
            .ok_or_else(|| anyhow::anyhow!("signing key not initialized"))?;
        let public_key = signing_key_local.verifying_key().to_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(public_key);
        let identity_fingerprint = hasher.finalize().to_vec();

        let db_path = self.config.writersproof_dir.join("events.db");
        let mut key_bytes = signing_key_local.to_bytes();
        let hmac_key = crate::crypto::derive_hmac_key(&key_bytes);
        key_bytes.zeroize();
        let store = crate::store::SecureStore::open(&db_path, hmac_key)?;

        let mut current_digest =
            if let Some((cbor, _)) = store.get_baseline_digest(&identity_fingerprint)? {
                serde_json::from_slice::<authorproof_protocol::baseline::BaselineDigest>(&cbor)?
            } else {
                crate::baseline::compute_initial_digest(identity_fingerprint.clone())
            };

        crate::baseline::update_digest_in_place(&mut current_digest, &summary);

        let digest_json = serde_json::to_vec(&current_digest)?;
        let signature = signing_key_local.sign(&digest_json);
        // SigningKey zeroizes its secret material on Drop.
        drop(signing_key_local);

        store.save_baseline_digest(&identity_fingerprint, &digest_json, &signature.to_bytes())?;

        log::info!(
            "Authorship baseline updated. Tier: {:?}",
            current_digest.confidence_tier
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Dictation session management
// ---------------------------------------------------------------------------

impl Sentinel {
    /// Begin a dictation session for `doc_path`.
    ///
    /// Returns `false` if the path is not tracked or a dictation is already active.
    #[allow(dead_code)] // called from ffi::sentinel_es (feature = "ffi")
    pub(crate) fn begin_dictation(
        &self,
        doc_path: &str,
        es_speech_pid: u32,
        audio_transport_type: u8,
        device_uid_hash: [u8; 8],
        ambient_noise_db: f32,
    ) -> bool {
        log::debug!("begin_dictation: doc_path={doc_path}, es_speech_pid={es_speech_pid}");
        // AUD-041: acquire signing_key before sessions.
        let key = {
            #[cfg(debug_assertions)]
            let _guard =
                super::core::lock_order::assert_order(super::core::lock_order::SIGNING_KEY);
            self.signing_key.read_recover().key()
        };
        #[cfg(debug_assertions)]
        let _session_guard =
            super::core::lock_order::assert_order(super::core::lock_order::SESSIONS);

        let mut sessions = self.sessions.write_recover();
        let session = match sessions.get_mut(doc_path) {
            Some(s) => s,
            None => {
                log::debug!("begin_dictation: path not tracked: {doc_path}");
                return false;
            }
        };
        if session.active_dictation.is_some() {
            log::warn!("begin_dictation: dictation already active for {doc_path}");
            return false;
        }

        let start_ns = crate::utils::now_ns();
        let keystrokes_at_begin = super::hid_key_down_count();
        let session_id = session.session_id.clone();
        let id_bytes = dictation_session_id_bytes(&session_id);

        dictation_wal_append(
            &session_id,
            id_bytes,
            &self.config.wal_dir,
            key.as_ref(),
            EntryType::DictationBegin,
            crate::wal::DictationBeginPayload {
                session_id: id_bytes,
                start_ns,
                es_speech_pid,
                audio_transport_type,
                device_uid_hash,
                speaker_output_active: false,
                ambient_noise_db,
            }
            .to_bytes(),
        );

        session.active_dictation = Some(crate::sentinel::types::ActiveDictationSession {
            start_ns,
            es_speech_pid,
            audio_transport_type,
            device_uid_hash,
            fragment_count: 0,
            total_words: 0,
            confidence_sum: 0.0,
            confidence_sum_sq: 0.0,
            speaker_output_ever_active: false,
            ambient_noise_db,
            keystrokes_at_begin,
            total_corrections: 0,
        });
        true
    }

    /// Record an incremental recognition fragment from the speech recognizer.
    ///
    /// Returns `false` if the path is not tracked or no dictation is active.
    #[allow(dead_code)] // called from ffi::sentinel_es (feature = "ffi")
    pub(crate) fn record_dictation_fragment(
        &self,
        doc_path: &str,
        word_count: u32,
        confidence: f32,
        correction_count: u32,
        text_hash: [u8; 32],
        speaker_output_active: bool,
    ) -> bool {
        log::debug!(
            "record_dictation_fragment: doc_path={doc_path}, word_count={word_count}, confidence={confidence}"
        );
        let key = {
            #[cfg(debug_assertions)]
            let _guard =
                super::core::lock_order::assert_order(super::core::lock_order::SIGNING_KEY);
            self.signing_key.read_recover().key()
        };
        #[cfg(debug_assertions)]
        let _session_guard =
            super::core::lock_order::assert_order(super::core::lock_order::SESSIONS);

        let mut sessions = self.sessions.write_recover();
        let session = match sessions.get_mut(doc_path) {
            Some(s) => s,
            None => return false,
        };
        let active = match session.active_dictation.as_mut() {
            Some(a) => a,
            None => {
                log::warn!("record_dictation_fragment: no active dictation for {doc_path}");
                return false;
            }
        };

        let fragment_index = active.fragment_count;
        active.fragment_count += 1;
        active.total_words = active.total_words.saturating_add(word_count);
        active.total_corrections = active.total_corrections.saturating_add(correction_count);
        active.confidence_sum += confidence as f64;
        active.confidence_sum_sq += (confidence as f64) * (confidence as f64);
        if speaker_output_active {
            active.speaker_output_ever_active = true;
        }

        let timestamp_ns = crate::utils::now_ns();
        let session_id = session.session_id.clone();
        let id_bytes = dictation_session_id_bytes(&session_id);

        dictation_wal_append(
            &session_id,
            id_bytes,
            &self.config.wal_dir,
            key.as_ref(),
            EntryType::DictationFragment,
            crate::wal::DictationFragmentPayload {
                session_id: id_bytes,
                fragment_index,
                timestamp_ns,
                word_count,
                confidence,
                speaker_output_active,
                text_hash,
            }
            .to_bytes(),
        );
        true
    }

    /// Finalize the active dictation session for `doc_path`, producing a `DictationEvent`.
    ///
    /// Returns `false` if the path is not tracked or no dictation is active.
    #[allow(dead_code)] // called from ffi::sentinel_es (feature = "ffi")
    pub(crate) fn end_dictation(
        &self,
        doc_path: &str,
        speaker_output_active: bool,
        keystrokes_during_caller: u32,
        cross_window_similarity: f32,
    ) -> bool {
        log::debug!("end_dictation: doc_path={doc_path}, keystrokes_during={keystrokes_during_caller}");
        let key = {
            #[cfg(debug_assertions)]
            let _guard =
                super::core::lock_order::assert_order(super::core::lock_order::SIGNING_KEY);
            self.signing_key.read_recover().key()
        };
        #[cfg(debug_assertions)]
        let _session_guard =
            super::core::lock_order::assert_order(super::core::lock_order::SESSIONS);

        let mut sessions = self.sessions.write_recover();
        let session = match sessions.get_mut(doc_path) {
            Some(s) => s,
            None => return false,
        };
        let active = match session.active_dictation.take() {
            Some(a) => a,
            None => {
                log::warn!("end_dictation: no active dictation for {doc_path}");
                return false;
            }
        };

        let end_ns = crate::utils::now_ns();
        let duration_ns = end_ns.saturating_sub(active.start_ns);
        let wpm = crate::utils::words_per_minute(active.total_words, duration_ns);
        let n = active.fragment_count as f64;
        let conf_mean = if n > 0.0 { (active.confidence_sum / n) as f32 } else { 0.0 };
        let conf_stddev = if n > 1.0 {
            let variance = (active.confidence_sum_sq - active.confidence_sum * active.confidence_sum / n) / (n - 1.0);
            variance.max(0.0).sqrt() as f32
        } else {
            0.0
        };
        let corr_rate = crate::utils::correction_rate(active.total_corrections, active.total_words);

        let keystrokes_hid_end = super::hid_key_down_count();
        let keystrokes_observed =
            keystrokes_hid_end.saturating_sub(active.keystrokes_at_begin) as u32;
        let keystrokes_during = keystrokes_observed.max(keystrokes_during_caller);
        let speaker_ever_active = active.speaker_output_ever_active || speaker_output_active;

        let mut event = crate::evidence::DictationEvent {
            start_ns: active.start_ns,
            end_ns,
            word_count: active.total_words,
            char_count: 0,
            input_method: "com.apple.SpeechRecognitionCore".to_string(),
            mic_active: true,
            words_per_minute: wpm,
            plausibility_score: 0.0,
            es_speech_pid: active.es_speech_pid,
            audio_transport_type: active.audio_transport_type,
            device_uid_hash: active.device_uid_hash,
            fragment_count: active.fragment_count,
            confidence_mean: conf_mean,
            confidence_stddev: conf_stddev,
            correction_rate: corr_rate,
            keystroke_void: keystrokes_observed == 0,
            keystrokes_during_dictation: keystrokes_during,
            speaker_output_active: speaker_ever_active,
            ambient_noise_db: active.ambient_noise_db,
            cross_window_similarity,
        };
        event.plausibility_score =
            crate::forensics::dictation::score_dictation_plausibility(&event);

        let session_id = session.session_id.clone();
        let id_bytes = dictation_session_id_bytes(&session_id);

        dictation_wal_append(
            &session_id,
            id_bytes,
            &self.config.wal_dir,
            key.as_ref(),
            EntryType::DictationEnd,
            crate::wal::DictationEndPayload {
                session_id: id_bytes,
                end_ns,
                total_words: active.total_words,
                total_fragments: active.fragment_count,
                confidence_mean: conf_mean,
                confidence_stddev: conf_stddev,
                keystrokes_during_dictation: keystrokes_during,
                cross_window_similarity,
                plausibility_score: event.plausibility_score,
            }
            .to_bytes(),
        );

        log::info!(
            "Dictation ended: {doc_path}, {} words, {:.1} WPM, plausibility {:.3}",
            active.total_words,
            wpm,
            event.plausibility_score,
        );

        session.dictation_events.push(event);
        true
    }
}

// ---------------------------------------------------------------------------
// Dictation WAL helpers (private to this file)
// ---------------------------------------------------------------------------

#[allow(dead_code)] // used by begin_dictation/end_dictation (feature = "ffi")
fn dictation_session_id_bytes(session_id: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let hex_str = session_id
        .get(..64.min(session_id.len()))
        .unwrap_or(session_id);
    if hex::decode_to_slice(hex_str, &mut out).is_err() {
        let digest = sha2::Sha256::digest(session_id.as_bytes());
        out.copy_from_slice(&digest);
    }
    out
}

#[allow(dead_code)] // used by begin_dictation/end_dictation (feature = "ffi")
fn dictation_wal_append(
    session_id: &str,
    session_id_bytes: [u8; 32],
    wal_dir: &std::path::Path,
    key: Option<&SigningKey>,
    entry_type: EntryType,
    payload: Vec<u8>,
) {
    let Some(key) = key else { return };
    let wal_path = wal_dir.join(format!("{session_id}.wal"));
    let mut key_bytes = key.to_bytes();
    let wal_key = SigningKey::from_bytes(&key_bytes);
    key_bytes.zeroize();
    match Wal::open(&wal_path, session_id_bytes, wal_key) {
        Ok(wal) => {
            if let Err(e) = wal.append(entry_type, payload) {
                log::warn!("WAL {entry_type:?} append failed for session {session_id}: {e}");
            }
        }
        Err(e) => {
            log::warn!("WAL open failed for dictation session {session_id}: {e}");
        }
    }
}
