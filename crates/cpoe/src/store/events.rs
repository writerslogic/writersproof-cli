// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::crypto;
use crate::store::{SecureEvent, SecureStore};
use crate::DateTimeNanosExt;
use anyhow::anyhow;
use rusqlite::params;
use std::path::Path;
use subtle::ConstantTimeEq;

impl SecureStore {
    /// Add an event, computing its hash chain link and HMAC, then update integrity.
    pub fn add_secure_event(&mut self, e: &mut SecureEvent) -> anyhow::Result<()> {
        self.add_secure_event_with_signer(e, None)
    }

    /// Add an event with optional Lamport signing. When a signing key is provided,
    /// a Lamport one-shot signature is computed over the event hash and stored
    /// alongside the event for post-quantum double-sign detection.
    pub fn add_secure_event_with_signer(
        &mut self,
        e: &mut SecureEvent,
        signing_key: Option<&ed25519_dalek::SigningKey>,
    ) -> anyhow::Result<()> {
        let previous_hash = self.last_hash;
        e.previous_hash = previous_hash;

        let event_data = crypto::EventData {
            device_id: e.device_id,
            timestamp_ns: e.timestamp_ns,
            file_path: e.file_path.clone(),
            content_hash: e.content_hash,
            file_size: e.file_size,
            size_delta: e.size_delta,
            previous_hash: e.previous_hash,
        };

        e.event_hash = crypto::compute_event_hash(&event_data);

        if let Some(sk) = signing_key {
            crypto::sign_event_lamport(sk, e)?;
        }

        let hmac = crypto::compute_event_hmac(&self.hmac_key, &event_data);

        if !e.forensic_score.is_finite() {
            e.forensic_score = 0.0;
        }

        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO secure_events (
                device_id, machine_id, timestamp_ns, file_path, content_hash, file_size, size_delta,
                previous_hash, event_hash, hmac, context_type, context_note, vdf_input, vdf_output,
                vdf_iterations, forensic_score, is_paste, hardware_counter, input_method,
                lamport_signature, lamport_pubkey_fingerprint, challenge_nonce,
                hw_cosign_signature, hw_cosign_pubkey, hw_cosign_salt_commitment,
                hw_cosign_chain_index, hw_cosign_entangled_hash,
                hw_cosign_entropy_digest, hw_cosign_entropy_bytes,
                posme_proof, semantic_summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                &e.device_id[..],
                &e.machine_id,
                e.timestamp_ns,
                &e.file_path,
                &e.content_hash[..],
                e.file_size,
                e.size_delta,
                &e.previous_hash[..],
                &e.event_hash[..],
                &hmac[..],
                e.context_type,
                e.context_note,
                e.vdf_input.as_ref().map(|h| &h[..]),
                e.vdf_output.as_ref().map(|h| &h[..]),
                i64::try_from(e.vdf_iterations).unwrap_or_else(|_| {
                    log::warn!(
                        "vdf_iterations {} exceeds i64::MAX, clamped",
                        e.vdf_iterations
                    );
                    i64::MAX
                }),
                e.forensic_score,
                e.is_paste as i32,
                e.hardware_counter.map(|c| {
                    i64::try_from(c).unwrap_or_else(|_| {
                        log::warn!("hardware_counter {} exceeds i64::MAX, clamped", c);
                        i64::MAX
                    })
                }),
                e.input_method,
                e.lamport_signature.as_deref(),
                e.lamport_pubkey_fingerprint.as_deref(),
                e.challenge_nonce,
                e.hw_cosign_signature.as_deref(),
                e.hw_cosign_pubkey.as_deref(),
                e.hw_cosign_salt_commitment.as_deref(),
                e.hw_cosign_chain_index.map(|c| i64::try_from(c).unwrap_or(i64::MAX)),
                e.hw_cosign_entangled_hash.as_deref(),
                e.hw_cosign_entropy_digest.as_deref(),
                e.hw_cosign_entropy_bytes.map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                e.posme_proof.as_deref(),
                e.semantic_summary
            ],
        )?;

        let id = tx.last_insert_rowid();
        e.id = Some(id);

        let (prev_event_count, last_verified_seq): (i64, i64) = tx.query_row(
            "SELECT event_count, last_verified_sequence FROM integrity WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let event_count = prev_event_count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("event_count overflow"))?;
        let new_integrity_hmac = crypto::compute_integrity_hmac(
            &self.hmac_key,
            &e.event_hash,
            event_count,
            last_verified_seq,
        );
        tx.execute(
            "UPDATE integrity SET chain_hash = ?, event_count = ?, last_verified = ?, hmac = ? WHERE id = 1",
            params![&e.event_hash[..], event_count, chrono::Utc::now().timestamp_nanos_safe(), &new_integrity_hmac[..]]
        )?;

        tx.commit()?;
        self.last_hash = e.event_hash;
        Ok(())
    }

    /// Retrieve all events for a file path, ordered by insertion.
    pub fn get_events_for_file(&self, path: impl AsRef<Path>) -> anyhow::Result<Vec<SecureEvent>> {
        self.get_events_for_file_limited(path, None)
    }

    /// Retrieve events for a file path within a timestamp range (inclusive, nanoseconds).
    pub fn get_events_for_file_in_range(
        &self,
        path: impl AsRef<Path>,
        start_ns: i64,
        end_ns: i64,
    ) -> anyhow::Result<Vec<SecureEvent>> {
        let path = path.as_ref().to_string_lossy();
        let query = "SELECT id, device_id, machine_id, timestamp_ns, file_path, \
                content_hash, file_size, size_delta, previous_hash, event_hash, hmac, \
                context_type, context_note, vdf_input, vdf_output, vdf_iterations, \
                forensic_score, is_paste, hardware_counter, input_method, \
                lamport_signature, lamport_pubkey_fingerprint, challenge_nonce, \
                hw_cosign_signature, hw_cosign_pubkey, hw_cosign_salt_commitment, \
                hw_cosign_chain_index, hw_cosign_entangled_hash, \
                hw_cosign_entropy_digest, hw_cosign_entropy_bytes, \
                posme_proof, semantic_summary \
                FROM secure_events WHERE file_path = ?1 \
                AND timestamp_ns >= ?2 AND timestamp_ns <= ?3 \
                ORDER BY id ASC";
        let mut stmt = self.conn.prepare(query)?;
        let mut events = Vec::new();
        let rows = stmt.query_map(
            params![path.as_ref(), start_ns, end_ns],
            Self::row_to_event_with_hmac,
        )?;
        for row in rows {
            let (event, stored_hmac) = row?;
            self.verify_event_row_hmac(&event, &stored_hmac)?;
            events.push(event);
        }
        Ok(events)
    }

    /// Retrieve events for a file path, ordered by insertion, with an optional limit.
    pub fn get_events_for_file_limited(
        &self,
        path: impl AsRef<Path>,
        limit: Option<u32>,
    ) -> anyhow::Result<Vec<SecureEvent>> {
        let path = path.as_ref().to_string_lossy();
        let base_query = "SELECT id, device_id, machine_id, timestamp_ns, file_path, \
                content_hash, file_size, size_delta, previous_hash, event_hash, hmac, \
                context_type, context_note, vdf_input, vdf_output, vdf_iterations, \
                forensic_score, is_paste, hardware_counter, input_method, \
                lamport_signature, lamport_pubkey_fingerprint, challenge_nonce, \
                hw_cosign_signature, hw_cosign_pubkey, hw_cosign_salt_commitment, \
                hw_cosign_chain_index, hw_cosign_entangled_hash, \
                hw_cosign_entropy_digest, hw_cosign_entropy_bytes, \
                posme_proof, semantic_summary \
                FROM secure_events WHERE file_path = ?1 ORDER BY id ASC";
        let query = match limit {
            Some(_) => format!("{base_query} LIMIT ?2"),
            None => base_query.to_string(),
        };
        let mut stmt = self.conn.prepare(&query)?;

        let mut events = Vec::new();
        let rows: Box<dyn Iterator<Item = rusqlite::Result<(SecureEvent, Vec<u8>)>>> = match limit {
            Some(n) => {
                Box::new(stmt.query_map(params![path.as_ref(), n], Self::row_to_event_with_hmac)?)
            }
            None => Box::new(stmt.query_map(params![path.as_ref()], Self::row_to_event_with_hmac)?),
        };
        for row in rows {
            let (event, stored_hmac) = row?;
            self.verify_event_row_hmac(&event, &stored_hmac)?;
            events.push(event);
        }
        Ok(events)
    }

    /// Verify that `stored_hmac` matches the HMAC recomputed from `event`'s fields.
    /// Returns an error on mismatch to prevent returning tampered data.
    fn verify_event_row_hmac(&self, event: &SecureEvent, stored_hmac: &[u8]) -> anyhow::Result<()> {
        let device_id_arr: [u8; 16] = event.device_id;
        let content_hash_arr: [u8; 32] = event.content_hash;
        let previous_hash_arr: [u8; 32] = event.previous_hash;
        let event_data = crypto::EventData {
            device_id: device_id_arr,
            timestamp_ns: event.timestamp_ns,
            file_path: event.file_path.clone(),
            content_hash: content_hash_arr,
            file_size: event.file_size,
            size_delta: event.size_delta,
            previous_hash: previous_hash_arr,
        };
        let expected = crypto::compute_event_hmac(&self.hmac_key, &event_data);
        if stored_hmac.ct_eq(&expected[..]).unwrap_u8() == 0 {
            return Err(anyhow!(
                "event {} HMAC mismatch: possible mid-session tampering",
                event.id.unwrap_or(-1)
            ));
        }
        Ok(())
    }

    /// Deserialize a row into a `SecureEvent` and its stored HMAC bytes.
    /// The SELECT must include `hmac` at column index 10 (after `event_hash`).
    fn row_to_event_with_hmac(row: &rusqlite::Row<'_>) -> rusqlite::Result<(SecureEvent, Vec<u8>)> {
        let stored_hmac: Vec<u8> = row.get(10)?;
        let event = Self::row_to_event(row)?;
        Ok((event, stored_hmac))
    }

    fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecureEvent> {
        let device_id: Vec<u8> = row.get(1)?;
        let content_hash: Vec<u8> = row.get(5)?;
        let previous_hash: Vec<u8> = row.get(8)?;
        let event_hash: Vec<u8> = row.get(9)?;
        // column 10 is `hmac`; used by row_to_event_with_hmac; skip here
        let vdf_input: Option<Vec<u8>> = row.get(13)?;
        let vdf_output: Option<Vec<u8>> = row.get(14)?;

        Ok(SecureEvent {
            id: Some(row.get(0)?),
            device_id: device_id.try_into().map_err(|_| {
                rusqlite::Error::InvalidColumnType(
                    1,
                    "device_id".into(),
                    rusqlite::types::Type::Blob,
                )
            })?,
            machine_id: row.get(2)?,
            timestamp_ns: row.get(3)?,
            file_path: row.get(4)?,
            content_hash: content_hash.try_into().map_err(|_| {
                rusqlite::Error::InvalidColumnType(
                    5,
                    "content_hash".into(),
                    rusqlite::types::Type::Blob,
                )
            })?,
            file_size: row.get(6)?,
            size_delta: row.get(7)?,
            previous_hash: previous_hash.try_into().map_err(|_| {
                rusqlite::Error::InvalidColumnType(
                    8,
                    "previous_hash".into(),
                    rusqlite::types::Type::Blob,
                )
            })?,
            event_hash: event_hash.try_into().map_err(|_| {
                rusqlite::Error::InvalidColumnType(
                    9,
                    "event_hash".into(),
                    rusqlite::types::Type::Blob,
                )
            })?,
            context_type: row.get(11)?,
            context_note: row.get(12)?,
            vdf_input: vdf_input
                .map(|v| {
                    v.try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            13,
                            "vdf_input".into(),
                            rusqlite::types::Type::Blob,
                        )
                    })
                })
                .transpose()?,
            vdf_output: vdf_output
                .map(|v| {
                    v.try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            14,
                            "vdf_output".into(),
                            rusqlite::types::Type::Blob,
                        )
                    })
                })
                .transpose()?,
            vdf_iterations: u64::try_from(row.get::<_, i64>(15)?).unwrap_or(0),
            forensic_score: row.get(16)?,
            is_paste: row.get::<_, i32>(17)? != 0,
            hardware_counter: row
                .get::<_, Option<i64>>(18)?
                .map(|v| u64::try_from(v).unwrap_or(0)),
            input_method: row.get(19)?,
            lamport_signature: row.get(20)?,
            lamport_pubkey_fingerprint: row.get(21)?,
            challenge_nonce: row.get(22)?,
            hw_cosign_signature: row.get(23)?,
            hw_cosign_pubkey: row.get(24)?,
            hw_cosign_salt_commitment: row.get(25)?,
            hw_cosign_chain_index: row
                .get::<_, Option<i64>>(26)?
                .map(|v| u64::try_from(v).unwrap_or(0)),
            hw_cosign_entangled_hash: row.get(27)?,
            hw_cosign_entropy_digest: row.get(28)?,
            hw_cosign_entropy_bytes: row
                .get::<_, Option<i64>>(29)?
                .map(|v| u64::try_from(v).unwrap_or(0)),
            posme_proof: row.get(30)?,
            semantic_summary: row.get(31)?,
        })
    }

    /// List tracked files with their latest timestamp and event count.
    pub fn list_files(&self) -> anyhow::Result<Vec<(String, i64, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, MAX(timestamp_ns) as last_ts, COUNT(*) as event_count
             FROM secure_events
             GROUP BY file_path
             ORDER BY last_ts DESC",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        rows.map(|r| r.map_err(anyhow::Error::from)).collect()
    }

    /// Return (timestamp, 1) pairs for all events after `start_ts`.
    pub fn get_global_activity(&self, start_ts: i64) -> anyhow::Result<Vec<(i64, i64)>> {
        Ok(self
            .get_all_event_timestamps(start_ts)?
            .into_iter()
            .map(|ts| (ts, 1i64))
            .collect())
    }

    /// Return all event timestamps after `start_ts`, ascending.
    pub fn get_all_event_timestamps(&self, start_ts: i64) -> anyhow::Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ns FROM secure_events WHERE timestamp_ns >= ? ORDER BY timestamp_ns ASC"
        )?;

        let rows = stmt.query_map([start_ts], |row| row.get(0))?;
        rows.map(|r| r.map_err(anyhow::Error::from)).collect()
    }

    /// Retrieve all events grouped by file path in a single query.
    pub fn get_all_events_grouped(
        &self,
    ) -> anyhow::Result<std::collections::HashMap<String, Vec<SecureEvent>>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, device_id, machine_id, timestamp_ns, file_path, \
                content_hash, file_size, size_delta, previous_hash, event_hash, hmac, \
                context_type, context_note, vdf_input, vdf_output, vdf_iterations, \
                forensic_score, is_paste, hardware_counter, input_method, \
                lamport_signature, lamport_pubkey_fingerprint, challenge_nonce, \
                hw_cosign_signature, hw_cosign_pubkey, hw_cosign_salt_commitment, \
                hw_cosign_chain_index, hw_cosign_entangled_hash, \
                hw_cosign_entropy_digest, hw_cosign_entropy_bytes, \
                posme_proof, semantic_summary \
                FROM secure_events ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], Self::row_to_event_with_hmac)?;
        let mut map: std::collections::HashMap<String, Vec<SecureEvent>> =
            std::collections::HashMap::new();
        for row in rows {
            let (event, stored_hmac) = row?;
            self.verify_event_row_hmac(&event, &stored_hmac)?;
            map.entry(event.file_path.clone()).or_default().push(event);
        }
        Ok(map)
    }

    /// Return (timestamp, size_delta) pairs for all events, ascending.
    pub fn get_all_events_summary(&self) -> anyhow::Result<Vec<(i64, i32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ns, size_delta FROM secure_events ORDER BY timestamp_ns ASC",
        )?;

        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.map(|r| r.map_err(anyhow::Error::from)).collect()
    }

    /// Update the file path for all events matching `old_path` to `new_path`.
    /// Used when a rename is detected via content hash continuity.
    ///
    /// # Warning
    ///
    /// This mutates `file_path` without recomputing event hashes or HMACs.
    /// It **MUST NOT** be called on events that have already been stored with
    /// HMAC verification, because `verify_integrity()` will fail afterwards.
    /// The function checks whether the store has any verified events and returns
    /// an error if so.
    pub fn update_file_path(
        &mut self,
        old_path: impl AsRef<Path>,
        new_path: impl AsRef<Path>,
    ) -> anyhow::Result<usize> {
        let old_path = old_path.as_ref().to_string_lossy();
        let new_path = new_path.as_ref().to_string_lossy();
        let tx = self.conn.transaction()?;
        let has_integrity: bool = tx
            .query_row(
                "SELECT COUNT(*) FROM integrity WHERE id = 1 AND event_count > 0",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if has_integrity {
            return Err(anyhow::anyhow!(
                "cannot update file_path: store has HMAC-verified events; \
                 this would break integrity verification"
            ));
        }
        let count = tx.execute(
            "UPDATE secure_events SET file_path = ? WHERE file_path = ?",
            params![new_path.as_ref(), old_path.as_ref()],
        )?;
        tx.commit()?;
        Ok(count)
    }

    /// Export all events for a given device identity (GDPR Article 15 DSAR).
    ///
    /// Returns every `SecureEvent` associated with the given `device_id`,
    /// ordered by insertion, for data subject access request fulfillment.
    pub fn export_all_events_for_identity(
        &self,
        device_id: &[u8; 16],
    ) -> anyhow::Result<Vec<SecureEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, device_id, machine_id, timestamp_ns, file_path, content_hash, file_size, size_delta,
                    previous_hash, event_hash, hmac, context_type, context_note, vdf_input, vdf_output,
                    vdf_iterations, forensic_score, is_paste, hardware_counter, input_method,
                    lamport_signature, lamport_pubkey_fingerprint, challenge_nonce,
                    hw_cosign_signature, hw_cosign_pubkey, hw_cosign_salt_commitment,
                    hw_cosign_chain_index, hw_cosign_entangled_hash,
                    hw_cosign_entropy_digest, hw_cosign_entropy_bytes,
                    posme_proof, semantic_summary
             FROM secure_events WHERE device_id = ? ORDER BY id ASC",
        )?;

        let rows = stmt.query_map([&device_id[..]], Self::row_to_event_with_hmac)?;
        let mut events = Vec::new();
        for row in rows {
            let (event, stored_hmac) = row?;
            self.verify_event_row_hmac(&event, &stored_hmac)?;
            events.push(event);
        }
        Ok(events)
    }

    /// Check retention policy and prune events older than `retention_days`.
    ///
    /// Returns the number of payload rows pruned. Logs the count at info level.
    pub fn enforce_retention(&self, retention_days: u32) -> anyhow::Result<usize> {
        if retention_days == 0 {
            return Err(anyhow::anyhow!("retention_days must be > 0"));
        }
        let count = self.prune_payloads(retention_days as i64)?;
        if count > 0 {
            log::info!(
                "Retention purge: pruned payloads from {} events older than {} days",
                count,
                retention_days
            );
        }
        Ok(count)
    }

    /// Null out context notes and VDF data for events older than `days_to_keep`.
    ///
    /// Pruned fields (`vdf_input`, `vdf_output`) are NOT included in event HMAC
    /// computation, so pruning does not break integrity verification.
    pub fn prune_payloads(&self, days_to_keep: i64) -> anyhow::Result<usize> {
        if days_to_keep < 1 {
            return Err(anyhow::anyhow!("days_to_keep must be >= 1"));
        }
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days_to_keep);
        let cutoff_ns = cutoff.timestamp_nanos_safe();

        let count = self.conn.execute(
            "UPDATE secure_events 
             SET context_note = NULL, vdf_input = NULL, vdf_output = NULL 
             WHERE timestamp_ns < ?",
            [cutoff_ns],
        )?;

        Ok(count)
    }

    /// Update the most recent event for a file path with hardware co-signature data.
    #[allow(clippy::too_many_arguments)]
    pub fn update_hw_cosign(
        &self,
        file_path: &str,
        signature: &[u8],
        pubkey: &[u8],
        salt_commitment: &[u8],
        chain_index: u64,
        entangled_hash: &[u8],
        entropy_digest: Option<&[u8]>,
        entropy_bytes: Option<u64>,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE secure_events SET
                hw_cosign_signature = ?1,
                hw_cosign_pubkey = ?2,
                hw_cosign_salt_commitment = ?3,
                hw_cosign_chain_index = ?4,
                hw_cosign_entangled_hash = ?5,
                hw_cosign_entropy_digest = ?6,
                hw_cosign_entropy_bytes = ?7
             WHERE id = (
                SELECT id FROM secure_events
                WHERE file_path = ?8
                ORDER BY id DESC LIMIT 1
             )",
            rusqlite::params![
                signature,
                pubkey,
                salt_commitment,
                i64::try_from(chain_index).unwrap_or(i64::MAX),
                entangled_hash,
                entropy_digest,
                entropy_bytes.map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                file_path,
            ],
        )?;
        Ok(())
    }
}
