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
    /// Open the event store using the sentinel's signing key.
    fn open_event_store(&self) -> anyhow::Result<crate::store::SecureStore> {
        let signing_key_local = self
            .signing_key
            .read_recover()
            .key()
            .ok_or_else(|| anyhow::anyhow!("signing key not initialized"))?;
        let db_path = self.config.writersproof_dir.join("events.db");
        crate::store::open_store_with_signing_key(&signing_key_local, &db_path)
    }

    /// Begin witnessing a file, creating a session and WAL entry.
    pub fn start_witnessing(
        &self,
        file_path: &Path,
    ) -> std::result::Result<(), (IpcErrorCode, String)> {
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

        // Load cumulative stats from previous sessions.
        // AUD-041 fix: Do not call self.open_event_store() while holding sessions lock,
        // as it re-acquires signing_key (level 1) after sessions (level 2).
        let db_path = self.config.writersproof_dir.join("events.db");
        let store_res = match key {
            Some(ref sk) => crate::store::open_store_with_signing_key(sk, &db_path),
            None => Err(anyhow::anyhow!("signing key not initialized")),
        };

        match store_res {
            Ok(store) => match store.load_document_stats(&path_str) {
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
            Err(e) => {
                log::warn!("Failed to open store for document stats: {e}");
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
        // Use the cached signing key so no fresh level-1 lock is taken while
        // other locks are held later in this function.
        let db_path = self.config.writersproof_dir.join("events.db");
        let mut store = match sk_cached.as_ref() {
            Some(sk) => match crate::store::open_store_with_signing_key(sk, &db_path) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("Auto-checkpoint store open failed: {e}");
                    return false;
                }
            },
            None => {
                log::warn!("Auto-checkpoint skipped: signing key not initialized");
                return false;
            }
        };

        let mut event = crate::store::SecureEvent::new(
            path.to_string(),
            content_hash,
            file_size,
            Some("Auto-checkpoint".to_string()),
        );

        match store.add_secure_event_with_signer(&mut event, sk_cached.as_ref()) {
            Ok(_) => {
                log::info!("Auto-checkpoint committed for {path}");
                let session_info = {
                    let sessions = self.sessions.read_recover();
                    sessions.get(path).map(|s| {
                        (
                            s.session_id.clone(),
                            s.paste_context.is_some(),
                            s.app_bundle_id.clone(),
                            s.window_title.reveal().to_string(),
                        )
                    })
                };
                if let Some(ref tpm) = self.tpm_provider {
                    let mut sessions = self.sessions.write_recover();
                    if let Some(session) = sessions.get_mut(path) {
                        try_hw_cosign(
                            session,
                            tpm.as_ref(),
                            &event.content_hash,
                            Some(&event.event_hash),
                            Some((&store, path)),
                        );
                    }
                }
                if let (Some(ref sk), Some((ref sid, has_paste, ref bundle, ref title))) =
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
                        keystroke_confidence: Some(1.0),
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
                true
            }
            Err(e) => {
                log::warn!("Auto-checkpoint store write failed for {path}: {e}");
                // Roll back the claim so the next tick can retry, but only if no
                // other commit has advanced the counter past ours in the meantime.
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
                Ok(store) => {
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
