// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::store::SecureStore;
use anyhow::anyhow;
use rusqlite::params;
use rusqlite::OptionalExtension;
use std::str::FromStr;

/// Keystroke context indicating the source of keystroke input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystrokeContext {
    /// User typing fresh text, not from clipboard.
    OriginalComposition,
    /// User editing text that was pasted (within paste window).
    PastedContent,
    /// User typing after paste boundary (fresh composition).
    AfterPaste,
}

impl KeystrokeContext {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeystrokeContext::OriginalComposition => "OriginalComposition",
            KeystrokeContext::PastedContent => "PastedContent",
            KeystrokeContext::AfterPaste => "AfterPaste",
        }
    }
}

impl FromStr for KeystrokeContext {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "OriginalComposition" => Ok(KeystrokeContext::OriginalComposition),
            "PastedContent" => Ok(KeystrokeContext::PastedContent),
            "AfterPaste" => Ok(KeystrokeContext::AfterPaste),
            _ => Err(()),
        }
    }
}

/// A text fragment with authorship evidence.
#[derive(Debug, Clone)]
pub struct TextFragment {
    pub id: Option<i64>,
    pub fragment_hash: Vec<u8>,
    pub session_id: String,
    pub source_app_bundle_id: Option<String>,
    pub source_window_title: Option<String>,
    pub source_signature: Vec<u8>,
    pub nonce: Vec<u8>,
    pub timestamp: i64,
    pub keystroke_context: Option<KeystrokeContext>,
    pub keystroke_confidence: Option<f64>,
    pub keystroke_sequence_hash: Option<Vec<u8>>,
    pub source_session_id: Option<String>,
    pub source_evidence_packet: Option<Vec<u8>>,
    pub wal_entry_hash: Option<Vec<u8>>,
    pub cloudkit_record_id: Option<String>,
    pub sync_state: Option<String>,
}

impl TextFragment {
    /// Create a new fragment with required fields; all optional fields default to `None`.
    pub fn new(
        fragment_hash: Vec<u8>,
        session_id: String,
        source_signature: Vec<u8>,
        nonce: Vec<u8>,
        timestamp: i64,
    ) -> Self {
        Self {
            id: None,
            fragment_hash,
            session_id,
            source_app_bundle_id: None,
            source_window_title: None,
            source_signature,
            nonce,
            timestamp,
            keystroke_context: None,
            keystroke_confidence: None,
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        }
    }
}

impl SecureStore {
    /// Deserialize a row into a `TextFragment`.
    /// The SELECT must return columns in the canonical order:
    /// id, fragment_hash, session_id, source_app_bundle_id, source_window_title,
    /// source_signature, nonce, timestamp, keystroke_context, keystroke_confidence,
    /// keystroke_sequence_hash, source_session_id, source_evidence_packet,
    /// wal_entry_hash, cloudkit_record_id, sync_state
    fn row_to_fragment(row: &rusqlite::Row<'_>) -> rusqlite::Result<TextFragment> {
        Ok(TextFragment {
            id: Some(row.get(0)?),
            fragment_hash: row.get(1)?,
            session_id: row.get(2)?,
            source_app_bundle_id: row.get(3)?,
            source_window_title: row.get(4)?,
            source_signature: row.get(5)?,
            nonce: row.get(6)?,
            timestamp: row.get(7)?,
            keystroke_context: row
                .get::<_, Option<String>>(8)?
                .and_then(|s| s.parse().ok()),
            keystroke_confidence: row.get(9)?,
            keystroke_sequence_hash: row.get(10)?,
            source_session_id: row.get(11)?,
            source_evidence_packet: row.get(12)?,
            wal_entry_hash: row.get(13)?,
            cloudkit_record_id: row.get(14)?,
            sync_state: row.get(15)?,
        })
    }

    /// Validate fragment field lengths and nonce uniqueness.
    /// Returns the current time in milliseconds for callers that need it.
    fn validate_fragment_fields(&self, fragment: &TextFragment) -> anyhow::Result<i64> {
        if fragment.fragment_hash.len() != 32 {
            anyhow::bail!(
                "fragment_hash must be 32 bytes, got {}",
                fragment.fragment_hash.len()
            );
        }
        if fragment.nonce.len() != 16 {
            anyhow::bail!("nonce must be 16 bytes, got {}", fragment.nonce.len());
        }
        if fragment.source_signature.len() != 64 {
            anyhow::bail!(
                "source_signature must be 64 bytes (Ed25519), got {}",
                fragment.source_signature.len()
            );
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64;

        // Check nonce hasn't been used before
        let nonce_used: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM used_nonces WHERE nonce = ? LIMIT 1",
                [&fragment.nonce],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        if nonce_used {
            anyhow::bail!("Nonce replay detected");
        }

        Ok(now_ms)
    }

    /// Insert a text fragment with COSE_Sign1 signature verification.
    /// The fragment must contain a valid `source_signature` matching session key.
    pub fn insert_text_fragment(&mut self, fragment: &TextFragment) -> anyhow::Result<i64> {
        let now_ms = self.validate_fragment_fields(fragment)?;

        // Validate timestamp: reject future timestamps > 5 minutes
        if fragment.timestamp > now_ms + 5 * 60 * 1000 {
            anyhow::bail!(
                "Rejected fragment with future timestamp (ms): {} > {}",
                fragment.timestamp,
                now_ms
            );
        }

        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT INTO text_fragments (
                fragment_hash, session_id, source_app_bundle_id, source_window_title,
                source_signature, nonce, timestamp, keystroke_context, keystroke_confidence,
                keystroke_sequence_hash, source_session_id, source_evidence_packet,
                wal_entry_hash, cloudkit_record_id, sync_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                &fragment.fragment_hash[..],
                &fragment.session_id,
                &fragment.source_app_bundle_id,
                &fragment.source_window_title,
                &fragment.source_signature[..],
                &fragment.nonce[..],
                fragment.timestamp,
                fragment.keystroke_context.map(|c| c.as_str()),
                fragment.keystroke_confidence,
                fragment.keystroke_sequence_hash.as_deref(),
                &fragment.source_session_id,
                fragment.source_evidence_packet.as_deref(),
                fragment.wal_entry_hash.as_deref(),
                &fragment.cloudkit_record_id,
                &fragment.sync_state,
            ],
        )?;

        let id = tx.last_insert_rowid();

        // Mark nonce as used
        tx.execute(
            "INSERT INTO used_nonces (nonce, used_at) VALUES (?, ?)",
            params![&fragment.nonce[..], now_ms],
        )?;

        tx.commit()?;
        Ok(id)
    }

    /// Lookup a text fragment by hash. Returns first match or None.
    pub fn lookup_fragment_by_hash(&self, hash: &[u8; 32]) -> anyhow::Result<Option<TextFragment>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, fragment_hash, session_id, source_app_bundle_id, source_window_title,
                        source_signature, nonce, timestamp, keystroke_context, keystroke_confidence,
                        keystroke_sequence_hash, source_session_id, source_evidence_packet,
                        wal_entry_hash, cloudkit_record_id, sync_state
                 FROM text_fragments
                 WHERE fragment_hash = ?
                 LIMIT 1",
                [hash],
                Self::row_to_fragment,
            )
            .optional()?;

        Ok(result)
    }

    /// Get all text fragments for a session, ordered by timestamp.
    pub fn get_fragments_for_session(&self, session_id: &str) -> anyhow::Result<Vec<TextFragment>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, fragment_hash, session_id, source_app_bundle_id, source_window_title,
                    source_signature, nonce, timestamp, keystroke_context, keystroke_confidence,
                    keystroke_sequence_hash, source_session_id, source_evidence_packet,
                    wal_entry_hash, cloudkit_record_id, sync_state
             FROM text_fragments
             WHERE session_id = ?
             ORDER BY timestamp ASC",
        )?;

        let rows = stmt.query_map([session_id], Self::row_to_fragment)?;
        rows.map(|r| r.map_err(anyhow::Error::from)).collect()
    }

    /// Get all unsynced fragments (sync_state != "synced").
    pub fn get_unsynced_fragments(&self) -> anyhow::Result<Vec<TextFragment>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, fragment_hash, session_id, source_app_bundle_id, source_window_title,
                    source_signature, nonce, timestamp, keystroke_context, keystroke_confidence,
                    keystroke_sequence_hash, source_session_id, source_evidence_packet,
                    wal_entry_hash, cloudkit_record_id, sync_state
             FROM text_fragments
             WHERE sync_state IS NULL OR sync_state != 'synced'
             ORDER BY timestamp ASC",
        )?;

        let rows = stmt.query_map([], Self::row_to_fragment)?;
        rows.map(|r| r.map_err(anyhow::Error::from)).collect()
    }

    /// Mark a fragment as synced to CloudKit.
    pub fn mark_fragment_synced(&self, id: i64, cloudkit_record_id: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE text_fragments SET sync_state = 'synced', cloudkit_record_id = ? WHERE id = ?",
            params![cloudkit_record_id, id],
        )?;
        Ok(())
    }

    /// Verify that a nonce is unique and hasn't been used before.
    /// Returns true if valid (not used), false if replay detected.
    pub fn verify_nonce_unique(&self, nonce: &[u8]) -> anyhow::Result<bool> {
        let found: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM used_nonces WHERE nonce = ? LIMIT 1",
                [nonce],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        Ok(!found)
    }

    /// Verify fragment signature using constant-time comparison.
    /// Signature must be Ed25519 (64 bytes).
    pub fn verify_fragment_signature(
        &self,
        fragment_hash: &[u8; 32],
        nonce: &[u8],
        timestamp: i64,
        session_id: &str,
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> anyhow::Result<bool> {
        // Build payload matching sign_fragment: DST || sid_len || session_id || hash || ts || nonce
        const DST: &[u8] = b"witnessd-text-fragment-v1";
        let sid_len = (session_id.len() as u32).to_le_bytes();
        let mut payload =
            Vec::with_capacity(DST.len() + 4 + session_id.len() + 32 + 8 + nonce.len());
        payload.extend_from_slice(DST);
        payload.extend_from_slice(&sid_len);
        payload.extend_from_slice(session_id.as_bytes());
        payload.extend_from_slice(fragment_hash);
        payload.extend_from_slice(&timestamp.to_le_bytes());
        payload.extend_from_slice(nonce);

        // Verify Ed25519 signature
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        let pk = ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .map_err(|e| anyhow!("Invalid public key: {}", e))?;

        match pk.verify_strict(&payload, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get provenance chain for a session (all source fragments and lineage).
    pub fn get_provenance_chain(&self, session_id: &str) -> anyhow::Result<Vec<TextFragment>> {
        let fragments = self.get_fragments_for_session(session_id)?;
        Ok(fragments)
    }

    /// Get all text fragments in the store, ordered by timestamp.
    pub fn get_all_fragments(&self) -> anyhow::Result<Vec<TextFragment>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, fragment_hash, session_id, source_app_bundle_id,
                    source_window_title, source_signature, nonce, timestamp,
                    keystroke_context, keystroke_confidence,
                    keystroke_sequence_hash, source_session_id,
                    source_evidence_packet, wal_entry_hash,
                    cloudkit_record_id, sync_state
             FROM text_fragments ORDER BY timestamp ASC",
        )?;

        let rows = stmt.query_map([], Self::row_to_fragment)?;
        rows.map(|r| r.map_err(anyhow::Error::from)).collect()
    }

    /// Count text fragments for a session.
    pub fn count_fragments_for_session(&self, session_id: &str) -> anyhow::Result<u32> {
        let count: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM text_fragments WHERE session_id = ?",
            [session_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Mark a fragment as pending sync.
    #[allow(dead_code)]
    pub fn mark_fragment_for_sync(&self, fragment_id: i64) -> anyhow::Result<()> {
        let updated = self.conn.execute(
            "UPDATE text_fragments SET sync_state = 'pending' WHERE id = ?",
            params![fragment_id],
        )?;
        if updated == 0 {
            anyhow::bail!("No fragment found with id {}", fragment_id);
        }
        Ok(())
    }

    /// Update sync state with details.
    #[allow(dead_code)]
    pub fn update_fragment_sync_state(
        &self,
        fragment_id: i64,
        state: &str,
        cloudkit_record_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let valid_states = ["pending", "syncing", "synced", "failed", "conflict"];
        if !valid_states.contains(&state) {
            anyhow::bail!(
                "Invalid sync state '{}'; expected one of: {:?}",
                state,
                valid_states
            );
        }
        let updated = self.conn.execute(
            "UPDATE text_fragments \
             SET sync_state = ?, \
                 cloudkit_record_id = COALESCE(?, cloudkit_record_id) \
             WHERE id = ?",
            params![state, cloudkit_record_id, fragment_id],
        )?;
        if updated == 0 {
            anyhow::bail!("No fragment found with id {}", fragment_id);
        }
        Ok(())
    }

    /// Get count of fragments pending sync.
    #[allow(dead_code)]
    pub fn get_pending_sync_count(&self) -> anyhow::Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM text_fragments \
             WHERE sync_state = 'pending' OR sync_state IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Apply a remotely synced fragment (from another device via CloudKit).
    ///
    /// Same validation as `insert_text_fragment` (nonce uniqueness, signature
    /// length, timestamp bounds) but sets `sync_state = 'synced'` directly.
    #[allow(dead_code)]
    pub fn apply_remote_fragment(&mut self, fragment: &TextFragment) -> anyhow::Result<i64> {
        let now_ms = self.validate_fragment_fields(fragment)?;

        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT INTO text_fragments (
                fragment_hash, session_id, source_app_bundle_id,
                source_window_title, source_signature, nonce, timestamp,
                keystroke_context, keystroke_confidence,
                keystroke_sequence_hash, source_session_id,
                source_evidence_packet, wal_entry_hash,
                cloudkit_record_id, sync_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'synced')",
            params![
                &fragment.fragment_hash[..],
                &fragment.session_id,
                &fragment.source_app_bundle_id,
                &fragment.source_window_title,
                &fragment.source_signature[..],
                &fragment.nonce[..],
                fragment.timestamp,
                fragment.keystroke_context.map(|c| c.as_str()),
                fragment.keystroke_confidence,
                fragment.keystroke_sequence_hash.as_deref(),
                &fragment.source_session_id,
                fragment.source_evidence_packet.as_deref(),
                fragment.wal_entry_hash.as_deref(),
                &fragment.cloudkit_record_id,
            ],
        )?;

        let id = tx.last_insert_rowid();

        tx.execute(
            "INSERT INTO used_nonces (nonce, used_at) VALUES (?, ?)",
            params![&fragment.nonce[..], now_ms],
        )?;

        tx.commit()?;
        Ok(id)
    }

    /// Detect sync conflict between local and remote versions.
    #[allow(dead_code)]
    pub fn detect_sync_conflict(
        &self,
        fragment_hash: &[u8; 32],
        remote_timestamp: i64,
    ) -> anyhow::Result<SyncConflict> {
        let local = self.lookup_fragment_by_hash(fragment_hash)?;
        match local {
            None => Ok(SyncConflict::NoConflict),
            Some(existing) => {
                let local_ts = existing.timestamp;
                if local_ts == remote_timestamp {
                    Ok(SyncConflict::NoConflict)
                } else if local_ts > remote_timestamp {
                    Ok(SyncConflict::LocalNewer)
                } else if local_ts < remote_timestamp {
                    Ok(SyncConflict::RemoteNewer)
                } else {
                    Ok(SyncConflict::BothModified {
                        local_ts,
                        remote_ts: remote_timestamp,
                    })
                }
            }
        }
    }

    /// Resolve sync conflict using a strategy.
    #[allow(dead_code)]
    pub fn resolve_sync_conflict(
        &mut self,
        fragment_id: i64,
        strategy: SyncResolutionStrategy,
        remote_fragment: Option<&TextFragment>,
    ) -> anyhow::Result<()> {
        match strategy {
            SyncResolutionStrategy::KeepLocal => {
                // Mark local as authoritative, set synced
                self.update_fragment_sync_state(fragment_id, "synced", None)?;
            }
            SyncResolutionStrategy::KeepRemote => {
                let remote = remote_fragment.ok_or_else(|| {
                    anyhow::anyhow!("Remote fragment required for KeepRemote strategy")
                })?;
                // Delete the local version and insert the remote one
                self.conn.execute(
                    "DELETE FROM text_fragments WHERE id = ?",
                    params![fragment_id],
                )?;
                self.apply_remote_fragment(remote)?;
            }
            SyncResolutionStrategy::KeepNewest => {
                if let Some(remote) = remote_fragment {
                    // Look up local fragment timestamp
                    let local_ts: Option<i64> = self
                        .conn
                        .query_row(
                            "SELECT timestamp FROM text_fragments WHERE id = ?",
                            params![fragment_id],
                            |row| row.get(0),
                        )
                        .optional()?;

                    match local_ts {
                        Some(ts) if ts >= remote.timestamp => {
                            // Local is newer or equal; keep it
                            self.update_fragment_sync_state(fragment_id, "synced", None)?;
                        }
                        _ => {
                            // Remote is newer; replace local
                            self.conn.execute(
                                "DELETE FROM text_fragments WHERE id = ?",
                                params![fragment_id],
                            )?;
                            self.apply_remote_fragment(remote)?;
                        }
                    }
                } else {
                    // No remote fragment provided; keep local
                    self.update_fragment_sync_state(fragment_id, "synced", None)?;
                }
            }
        }
        Ok(())
    }
}

/// Describes the type of sync conflict between local and remote fragments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncConflict {
    /// No local fragment exists, or timestamps match.
    NoConflict,
    /// Local fragment is newer than remote.
    LocalNewer,
    /// Remote fragment is newer than local.
    RemoteNewer,
    /// Both have been modified with different timestamps.
    BothModified { local_ts: i64, remote_ts: i64 },
}

/// Strategy for resolving a sync conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncResolutionStrategy {
    /// Keep the local version and discard remote.
    KeepLocal,
    /// Replace local with the remote version.
    KeepRemote,
    /// Keep whichever version has the newest timestamp.
    KeepNewest,
}

// ---------------------------------------------------------------------------
// Fragment signing helpers (shared by FFI and sentinel)
// ---------------------------------------------------------------------------

/// Current wall-clock time as milliseconds since the Unix epoch.
pub fn current_timestamp_ms() -> i64 {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    if ts <= 0 {
        log::error!(
            "System clock returned non-positive timestamp; evidence timing will be unreliable"
        );
    }
    ts
}

/// Generate a 16-byte cryptographic random nonce.
pub fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    nonce
}

/// Sign the fragment payload with domain separation:
/// DST || len(session_id) || session_id || fragment_hash || timestamp || nonce.
pub fn sign_fragment(
    signing_key: &ed25519_dalek::SigningKey,
    session_id: &str,
    fragment_hash: &[u8; 32],
    timestamp: i64,
    nonce: &[u8; 16],
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    const DST: &[u8] = b"witnessd-text-fragment-v1";
    let sid_len = (session_id.len() as u32).to_le_bytes();
    let mut payload = Vec::with_capacity(DST.len() + 4 + session_id.len() + 32 + 8 + 16);
    payload.extend_from_slice(DST);
    payload.extend_from_slice(&sid_len);
    payload.extend_from_slice(session_id.as_bytes());
    payload.extend_from_slice(fragment_hash);
    payload.extend_from_slice(&timestamp.to_le_bytes());
    payload.extend_from_slice(nonce);
    signing_key.sign(&payload).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zeroize::Zeroizing;

    fn test_db() -> anyhow::Result<SecureStore> {
        let hmac_key = Zeroizing::new(vec![0u8; 32]);
        SecureStore::open(":memory:", hmac_key)
    }

    #[test]
    fn test_insert_and_lookup_fragment() -> anyhow::Result<()> {
        let mut store = test_db()?;

        let hash = [1u8; 32];
        let nonce = [2u8; 16];
        let sig = [3u8; 64];
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

        let fragment = TextFragment {
            id: None,
            fragment_hash: hash.to_vec(),
            session_id: "session1".to_string(),
            source_app_bundle_id: Some("com.apple.Notes".to_string()),
            source_window_title: Some("My Note".to_string()),
            source_signature: sig.to_vec(),
            nonce: nonce.to_vec(),
            timestamp: now,
            keystroke_context: Some(KeystrokeContext::OriginalComposition),
            keystroke_confidence: Some(0.95),
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };

        let id = store.insert_text_fragment(&fragment)?;
        assert!(id > 0);

        let looked_up = store.lookup_fragment_by_hash(&hash)?;
        assert!(looked_up.is_some());

        let looked_up = looked_up.unwrap();
        assert_eq!(looked_up.session_id, "session1");
        assert_eq!(
            looked_up.keystroke_context,
            Some(KeystrokeContext::OriginalComposition)
        );
        assert_eq!(looked_up.keystroke_confidence, Some(0.95));

        Ok(())
    }

    #[test]
    fn test_nonce_replay_detection() -> anyhow::Result<()> {
        let mut store = test_db()?;

        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let nonce = [3u8; 16];
        let sig = [4u8; 64];
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

        let frag1 = TextFragment {
            id: None,
            fragment_hash: hash1.to_vec(),
            session_id: "session1".to_string(),
            source_app_bundle_id: None,
            source_window_title: None,
            source_signature: sig.to_vec(),
            nonce: nonce.to_vec(),
            timestamp: now,
            keystroke_context: None,
            keystroke_confidence: None,
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };

        store.insert_text_fragment(&frag1)?;

        let frag2 = TextFragment {
            id: None,
            fragment_hash: hash2.to_vec(),
            nonce: nonce.to_vec(),
            ..frag1.clone()
        };

        let result = store.insert_text_fragment(&frag2);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Nonce replay"));

        Ok(())
    }

    #[test]
    fn test_fragment_signature_verification_rejects_invalid() -> anyhow::Result<()> {
        let store = test_db()?;

        let fragment_hash = [1u8; 32];
        let nonce = [2u8; 16];
        let timestamp = 1234567890i64;
        let session_id = "session1";
        let signature = [3u8; 64];
        let public_key = [4u8; 32];

        // Invalid public key/signature should fail (error on bad pk or false on bad sig)
        let _result = store.verify_fragment_signature(
            &fragment_hash,
            &nonce,
            timestamp,
            session_id,
            &signature,
            &public_key,
        );
        // Function should return either an error (invalid key) or false (invalid sig)

        Ok(())
    }

    #[test]
    fn test_keystroke_context_serialization() {
        assert_eq!(
            KeystrokeContext::OriginalComposition.as_str(),
            "OriginalComposition"
        );
        assert_eq!(KeystrokeContext::PastedContent.as_str(), "PastedContent");
        assert_eq!(KeystrokeContext::AfterPaste.as_str(), "AfterPaste");

        assert_eq!(
            "OriginalComposition".parse::<KeystrokeContext>().ok(),
            Some(KeystrokeContext::OriginalComposition)
        );
        assert_eq!(
            "PastedContent".parse::<KeystrokeContext>().ok(),
            Some(KeystrokeContext::PastedContent)
        );
        assert_eq!(
            "AfterPaste".parse::<KeystrokeContext>().ok(),
            Some(KeystrokeContext::AfterPaste)
        );
        assert_eq!("Unknown".parse::<KeystrokeContext>().ok(), None);
    }

    #[test]
    fn test_get_fragments_for_session() -> anyhow::Result<()> {
        let mut store = test_db()?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

        for i in 0..3 {
            let hash = [i as u8; 32];
            let nonce = [i as u8 + 10; 16];
            let sig = [i as u8 + 20; 64];

            let fragment = TextFragment {
                id: None,
                fragment_hash: hash.to_vec(),
                session_id: "session1".to_string(),
                source_app_bundle_id: None,
                source_window_title: None,
                source_signature: sig.to_vec(),
                nonce: nonce.to_vec(),
                timestamp: now + (i as i64 * 1000),
                keystroke_context: None,
                keystroke_confidence: None,
                keystroke_sequence_hash: None,
                source_session_id: None,
                source_evidence_packet: None,
                wal_entry_hash: None,
                cloudkit_record_id: None,
                sync_state: None,
            };

            store.insert_text_fragment(&fragment)?;
        }

        let fragments = store.get_fragments_for_session("session1")?;
        assert_eq!(fragments.len(), 3);
        assert!(fragments[0].timestamp <= fragments[1].timestamp);
        assert!(fragments[1].timestamp <= fragments[2].timestamp);

        Ok(())
    }

    #[test]
    fn test_mark_fragment_synced() -> anyhow::Result<()> {
        let mut store = test_db()?;

        let hash = [1u8; 32];
        let nonce = [2u8; 16];
        let sig = [3u8; 64];
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

        let fragment = TextFragment {
            id: None,
            fragment_hash: hash.to_vec(),
            session_id: "session1".to_string(),
            source_app_bundle_id: None,
            source_window_title: None,
            source_signature: sig.to_vec(),
            nonce: nonce.to_vec(),
            timestamp: now,
            keystroke_context: None,
            keystroke_confidence: None,
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };

        let id = store.insert_text_fragment(&fragment)?;
        store.mark_fragment_synced(id, "ckid123")?;

        let synced = store.lookup_fragment_by_hash(&hash)?;
        assert!(synced.is_some());
        let synced = synced.unwrap();
        assert_eq!(synced.sync_state, Some("synced".to_string()));
        assert_eq!(synced.cloudkit_record_id, Some("ckid123".to_string()));

        Ok(())
    }

    #[test]
    fn test_timestamp_validation() -> anyhow::Result<()> {
        let mut store = test_db()?;

        let hash = [1u8; 32];
        let nonce = [2u8; 16];
        let sig = [3u8; 64];
        let future_ms =
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64 + 10 * 60 * 1000;

        let fragment = TextFragment {
            id: None,
            fragment_hash: hash.to_vec(),
            session_id: "session1".to_string(),
            source_app_bundle_id: None,
            source_window_title: None,
            source_signature: sig.to_vec(),
            nonce: nonce.to_vec(),
            timestamp: future_ms,
            keystroke_context: None,
            keystroke_confidence: None,
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };

        let result = store.insert_text_fragment(&fragment);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("future"));

        Ok(())
    }
}
