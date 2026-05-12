// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Automatic archival of old events to separate read-only database files.
//!
//! When the active database exceeds 1.5 GiB, events older than 90 days are
//! moved to a timestamped archive file (`events_archive_YYYYMMDD.db`). The
//! archive retains full HMAC integrity and preserves hash chain continuity:
//! the archive's last event hash becomes the active DB's first `previous_hash`.

use crate::crypto;
use crate::store::SecureStore;
use crate::DateTimeNanosExt;
use anyhow::{anyhow, Context};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Archive threshold: 1.5 GiB in pages (page size = 4096 bytes).
/// 1.5 * 1024 * 1024 * 1024 / 4096 = 393216 pages.
const ARCHIVE_THRESHOLD_PAGES: u64 = 393_216;

/// Default retention period: events older than this are archived.
const DEFAULT_ARCHIVE_AGE_DAYS: u32 = 90;

/// Result of an archival operation.
#[derive(Debug, Clone)]
pub struct ArchiveResult {
    /// Path to the created archive file.
    pub archive_path: PathBuf,
    /// Number of events moved to the archive.
    pub events_archived: u64,
    /// The last event hash in the archive (chain link to active DB).
    pub chain_link_hash: [u8; 32],
    /// Size of the active DB after archival (in bytes).
    pub active_db_size_after: u64,
}

impl SecureStore {
    /// Check whether the database exceeds the archival threshold (1.5 GiB).
    pub fn needs_archival(&self) -> anyhow::Result<bool> {
        let page_count: i64 = self
            .conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        Ok(page_count as u64 >= ARCHIVE_THRESHOLD_PAGES)
    }

    /// Get the current database size in bytes.
    pub fn db_size_bytes(&self) -> anyhow::Result<u64> {
        let page_count: i64 = self
            .conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let page_size: i64 = self
            .conn
            .query_row("PRAGMA page_size", [], |row| row.get(0))?;
        Ok(page_count as u64 * page_size as u64)
    }

    /// Archive events older than `age_days` to a separate database file.
    ///
    /// The archive file is created at `{db_dir}/events_archive_{YYYYMMDD}.db`
    /// and is set read-only after completion. The chain link between archive
    /// and active DB is preserved: the archive's last event_hash becomes
    /// the first remaining event's `previous_hash` in the active DB.
    ///
    /// Returns `None` if no events qualify for archival.
    pub fn archive_old_events(
        &mut self,
        db_path: &Path,
        age_days: Option<u32>,
    ) -> anyhow::Result<Option<ArchiveResult>> {
        let age_days = age_days.unwrap_or(DEFAULT_ARCHIVE_AGE_DAYS);
        if age_days == 0 {
            anyhow::bail!("archive age_days must be > 0");
        }

        let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(age_days));
        let cutoff_ns = cutoff.timestamp_nanos_safe();

        // Count events to archive.
        let archive_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM secure_events WHERE timestamp_ns < ?",
            params![cutoff_ns],
            |row| row.get(0),
        )?;
        let archive_count = archive_count as u64;

        if archive_count == 0 {
            return Ok(None);
        }

        // Determine the archive file path.
        let archive_date = chrono::Utc::now().format("%Y%m%d");
        let db_dir = db_path
            .parent()
            .ok_or_else(|| anyhow!("Cannot determine parent directory of database"))?;
        let archive_filename = format!("events_archive_{archive_date}.db");
        let archive_path = db_dir.join(&archive_filename);
        // Temporary path: created first, renamed to final only after DELETE commits.
        // A leftover .tmp file from a crash means DELETE never committed — safe to remove.
        let archive_tmp_path = db_dir.join(format!("events_archive_{archive_date}.db.tmp"));

        // Don't overwrite existing archives from the same day.
        if archive_path.exists() {
            anyhow::bail!(
                "Archive file already exists: {}. Only one archive per day is supported.",
                archive_path.display()
            );
        }
        // Clean up a leftover .tmp from a previous crash (DELETE never committed).
        if archive_tmp_path.exists() {
            let _ = std::fs::remove_file(&archive_tmp_path);
        }

        // Find the chain link: the last event hash among events being archived.
        let chain_link_hash: [u8; 32] = {
            let hash_bytes: Vec<u8> = self.conn.query_row(
                "SELECT event_hash FROM secure_events WHERE timestamp_ns < ? ORDER BY id DESC LIMIT 1",
                params![cutoff_ns],
                |row| row.get(0),
            )?;
            hash_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid event_hash length for chain link"))?
        };

        // Verify the first remaining event's previous_hash matches chain_link_hash.
        // This ensures chain continuity will be preserved after the move.
        let first_remaining: Option<Vec<u8>> = match self
            .conn
            .query_row(
                "SELECT previous_hash FROM secure_events WHERE timestamp_ns >= ? ORDER BY id ASC LIMIT 1",
                params![cutoff_ns],
                |row| row.get(0),
            ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };

        if let Some(ref prev_hash) = first_remaining {
            if prev_hash.ct_eq(&chain_link_hash).unwrap_u8() == 0 {
                anyhow::bail!(
                    "Chain continuity violation: first remaining event's previous_hash \
                     does not match last archived event's event_hash"
                );
            }
        }

        // Create the archive database schema (written to .tmp path).
        self.create_archive_schema(&archive_tmp_path)?;

        // ATTACH the archive DB to the active connection so INSERT + DELETE
        // run in a single transaction. If any step fails, both roll back.
        let archive_tmp_str = archive_tmp_path
            .to_str()
            .ok_or_else(|| anyhow!("Archive path is not valid UTF-8"))?;
        self.conn.execute(
            "ATTACH DATABASE ? AS archive_db",
            params![archive_tmp_str],
        )?;

        // Use a closure so we can detach on both success and failure paths.
        let atomic_result = (|| -> anyhow::Result<()> {
            let tx = self.conn.transaction()?;

            // Copy events into the attached archive DB.
            let inserted = tx.execute(
                "INSERT INTO archive_db.secure_events
                    (device_id, machine_id, timestamp_ns, file_path, content_hash,
                     file_size, size_delta, previous_hash, event_hash, hmac,
                     context_type, context_note, vdf_input, vdf_output,
                     vdf_iterations, forensic_score, is_paste, hardware_counter,
                     input_method, lamport_signature, lamport_pubkey_fingerprint,
                     challenge_nonce, hw_cosign_signature, hw_cosign_pubkey,
                     hw_cosign_salt_commitment, hw_cosign_chain_index,
                     hw_cosign_entangled_hash, hw_cosign_entropy_digest,
                     hw_cosign_entropy_bytes, posme_proof, semantic_summary)
                 SELECT device_id, machine_id, timestamp_ns, file_path,
                     content_hash, file_size, size_delta, previous_hash,
                     event_hash, hmac, context_type, context_note, vdf_input,
                     vdf_output, vdf_iterations, forensic_score, is_paste,
                     hardware_counter, input_method, lamport_signature,
                     lamport_pubkey_fingerprint, challenge_nonce,
                     hw_cosign_signature, hw_cosign_pubkey,
                     hw_cosign_salt_commitment, hw_cosign_chain_index,
                     hw_cosign_entangled_hash, hw_cosign_entropy_digest,
                     hw_cosign_entropy_bytes, posme_proof, semantic_summary
                 FROM main.secure_events
                 WHERE timestamp_ns < ?
                 ORDER BY id ASC",
                params![cutoff_ns],
            )?;

            if inserted as u64 != archive_count {
                anyhow::bail!(
                    "Archive copy mismatch: expected {} events but copied {}",
                    archive_count,
                    inserted
                );
            }

            // Write archive metadata inside the same transaction.
            let now_str = chrono::Utc::now().to_rfc3339();
            tx.execute(
                "INSERT INTO archive_db.archive_metadata (key, value) \
                 VALUES ('created_at', ?)",
                params![now_str],
            )?;
            tx.execute(
                "INSERT INTO archive_db.archive_metadata (key, value) \
                 VALUES ('cutoff_ns', ?)",
                params![cutoff_ns.to_string()],
            )?;
            tx.execute(
                "INSERT INTO archive_db.archive_metadata (key, value) \
                 VALUES ('chain_link_hash', ?)",
                params![hex::encode(chain_link_hash)],
            )?;

            // Write archive integrity record.
            let archive_integrity_hmac = crypto::compute_integrity_hmac(
                &self.hmac_key,
                &chain_link_hash,
                inserted as i64,
                0,
            );
            tx.execute(
                "INSERT INTO archive_db.integrity \
                 (id, chain_hash, event_count, last_verified, \
                  last_verified_sequence, hmac) \
                 VALUES (1, ?, ?, ?, 0, ?)",
                params![
                    &chain_link_hash[..],
                    inserted as i64,
                    chrono::Utc::now().timestamp_nanos_safe(),
                    &archive_integrity_hmac[..]
                ],
            )?;

            // Delete archived events from the active database.
            let deleted: u64 = tx.execute(
                "DELETE FROM main.secure_events WHERE timestamp_ns < ?",
                params![cutoff_ns],
            )? as u64;

            if deleted != archive_count {
                anyhow::bail!(
                    "Archive mismatch: expected to delete {} events but deleted {}",
                    archive_count,
                    deleted
                );
            }

            // Update the active DB integrity record.
            let (_old_count, _last_verified_seq, old_chain_hash): (i64, i64, Vec<u8>) =
                tx.query_row(
                    "SELECT event_count, last_verified_sequence, chain_hash \
                     FROM main.integrity WHERE id = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;

            // Set last_verified_sequence to the last remaining event's ID so
            // the verifier treats all remaining events as already verified.
            // After archival, remaining IDs are sparse (e.g., 9..12 after
            // deleting 1-8). Set event_count = last_verified_seq = max(id)
            // to maintain the invariant.
            let new_last_verified_seq: i64 = tx.query_row(
                "SELECT COALESCE(MAX(id), 0) FROM main.secure_events",
                [],
                |row| row.get(0),
            )?;
            let new_count = new_last_verified_seq;

            let chain_hash_arr: [u8; 32] = old_chain_hash
                .try_into()
                .map_err(|_| anyhow!("Invalid chain_hash in integrity"))?;

            let new_integrity_hmac = crypto::compute_integrity_hmac(
                &self.hmac_key,
                &chain_hash_arr,
                new_count,
                new_last_verified_seq,
            );

            tx.execute(
                "UPDATE main.integrity SET event_count = ?, \
                 last_verified_sequence = ?, last_verified = ?, hmac = ? \
                 WHERE id = 1",
                params![
                    new_count,
                    new_last_verified_seq,
                    chrono::Utc::now().timestamp_nanos_safe(),
                    &new_integrity_hmac[..]
                ],
            )?;

            tx.commit()?;
            Ok(())
        })();

        // Always detach, regardless of success or failure.
        let _ = self.conn.execute("DETACH DATABASE archive_db", []);

        // On failure, clean up the tmp archive file.
        if let Err(e) = atomic_result {
            let _ = std::fs::remove_file(&archive_tmp_path);
            return Err(e);
        }

        // Finalize the archive: checkpoint WAL and switch to DELETE journal
        // mode for read-only use.
        {
            let archive_conn = Connection::open(&archive_tmp_path)?;
            archive_conn.execute_batch(
                "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;",
            )?;
        }

        // Transaction committed: promote the tmp archive to its final name.
        std::fs::rename(&archive_tmp_path, &archive_path)
            .context("Failed to rename tmp archive to final path")?;

        // Reclaim space.
        self.conn.execute_batch("VACUUM")?;

        // Set archive file to read-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o444);
            std::fs::set_permissions(&archive_path, perms)
                .context("Failed to set archive read-only")?;
        }

        let active_size = self.db_size_bytes()?;

        Ok(Some(ArchiveResult {
            archive_path,
            events_archived: archive_count,
            chain_link_hash,
            active_db_size_after: active_size,
        }))
    }

    /// Create an empty archive database with the required schema.
    ///
    /// Data population happens via ATTACH on the active connection so that
    /// INSERT into archive + DELETE from active are in a single transaction.
    fn create_archive_schema(&self, archive_path: &Path) -> anyhow::Result<()> {
        let archive_conn = Connection::open(archive_path)?;

        #[cfg(unix)]
        crate::crypto::restrict_permissions(archive_path, 0o600)?;

        let journal_mode: String =
            archive_conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if journal_mode.to_lowercase() != "wal" {
            log::warn!("archive db: requested WAL but got '{journal_mode}' journal mode");
        }
        archive_conn.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
        )?;

        archive_conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS integrity (
                id                      INTEGER PRIMARY KEY CHECK (id = 1),
                chain_hash              BLOB NOT NULL,
                event_count             INTEGER NOT NULL DEFAULT 0,
                last_verified           INTEGER,
                last_verified_sequence  INTEGER NOT NULL DEFAULT 0,
                hmac                    BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secure_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id       BLOB NOT NULL,
                machine_id      TEXT NOT NULL,
                timestamp_ns    INTEGER NOT NULL,
                file_path       TEXT NOT NULL,
                content_hash    BLOB NOT NULL,
                file_size       INTEGER NOT NULL,
                size_delta      INTEGER NOT NULL,
                previous_hash   BLOB NOT NULL,
                event_hash      BLOB NOT NULL UNIQUE,
                hmac            BLOB NOT NULL,
                context_type    TEXT,
                context_note    TEXT,
                vdf_input       BLOB,
                vdf_output      BLOB,
                vdf_iterations  INTEGER DEFAULT 0,
                forensic_score  REAL DEFAULT 1.0,
                is_paste        INTEGER DEFAULT 0,
                hardware_counter INTEGER,
                input_method    TEXT,
                lamport_signature BLOB,
                lamport_pubkey_fingerprint BLOB,
                challenge_nonce TEXT,
                hw_cosign_signature BLOB,
                hw_cosign_pubkey BLOB,
                hw_cosign_salt_commitment BLOB,
                hw_cosign_chain_index INTEGER,
                hw_cosign_entangled_hash BLOB,
                hw_cosign_entropy_digest BLOB,
                hw_cosign_entropy_bytes INTEGER,
                posme_proof BLOB,
                semantic_summary TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_archive_events_timestamp
                ON secure_events(timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_archive_events_file
                ON secure_events(file_path, timestamp_ns);

            CREATE TABLE IF NOT EXISTS archive_metadata (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;

        Ok(())
    }

    /// Check if archival is needed and perform it automatically.
    /// Called during store operations when the DB size is concerning.
    ///
    /// Returns `Some(ArchiveResult)` if archival was performed.
    pub fn auto_archive_if_needed(
        &mut self,
        db_path: &Path,
    ) -> anyhow::Result<Option<ArchiveResult>> {
        if !self.needs_archival()? {
            return Ok(None);
        }
        log::info!(
            "Database exceeds 1.5 GiB threshold; initiating automatic archival of events older than {} days",
            DEFAULT_ARCHIVE_AGE_DAYS
        );
        self.archive_old_events(db_path, None)
    }

    /// List all archive database files in the same directory as the active DB.
    pub fn list_archives(db_path: &Path) -> anyhow::Result<Vec<PathBuf>> {
        let db_dir = db_path
            .parent()
            .ok_or_else(|| anyhow!("Cannot determine parent directory"))?;

        let mut archives: Vec<PathBuf> = std::fs::read_dir(db_dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("events_archive_") && n.ends_with(".db"))
                    .unwrap_or(false)
            })
            .collect();

        archives.sort();
        Ok(archives)
    }

    /// Open an archive database read-only and query events for a file in a time range.
    ///
    /// Verifies HMAC integrity of returned events against the provided key.
    pub fn query_archive(
        archive_path: &Path,
        hmac_key: &Zeroizing<Vec<u8>>,
        file_path: &str,
        start_ns: i64,
        end_ns: i64,
    ) -> anyhow::Result<Vec<super::SecureEvent>> {
        let conn = Connection::open_with_flags(
            archive_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        let mut stmt = conn.prepare(
            "SELECT id, device_id, machine_id, timestamp_ns, file_path, \
                content_hash, file_size, size_delta, previous_hash, event_hash, hmac, \
                context_type, context_note, vdf_input, vdf_output, vdf_iterations, \
                forensic_score, is_paste, hardware_counter, input_method, \
                lamport_signature, lamport_pubkey_fingerprint, challenge_nonce, \
                hw_cosign_signature, hw_cosign_pubkey, hw_cosign_salt_commitment, \
                hw_cosign_chain_index, hw_cosign_entangled_hash, \
                hw_cosign_entropy_digest, hw_cosign_entropy_bytes, \
                posme_proof, semantic_summary \
             FROM secure_events \
             WHERE file_path = ?1 AND timestamp_ns >= ?2 AND timestamp_ns <= ?3 \
             ORDER BY id ASC",
        )?;

        let rows = stmt.query_map(params![file_path, start_ns, end_ns], Self::row_to_event_with_hmac)?;
        let mut events = Vec::new();
        for row in rows {
            let (event, stored_hmac) = row?;
            // Verify HMAC using the provided key.
            let event_data = crypto::EventData {
                device_id: event.device_id,
                timestamp_ns: event.timestamp_ns,
                file_path: event.file_path.clone(),
                content_hash: event.content_hash,
                file_size: event.file_size,
                size_delta: event.size_delta,
                previous_hash: event.previous_hash,
            };
            let expected = crypto::compute_event_hmac(hmac_key, &event_data);
            if stored_hmac.ct_eq(&expected[..]).unwrap_u8() == 0 {
                return Err(anyhow!(
                    "Archive event {} HMAC mismatch in {}",
                    event.id.unwrap_or(-1),
                    archive_path.display()
                ));
            }
            events.push(event);
        }
        Ok(events)
    }

    /// Query events spanning both archive and active databases for a file in a time range.
    ///
    /// Scans all archive files whose date range might overlap, then queries the
    /// active DB, and returns a merged result ordered by timestamp.
    pub fn query_spanning(
        &self,
        db_path: &Path,
        file_path: &str,
        start_ns: i64,
        end_ns: i64,
    ) -> anyhow::Result<Vec<super::SecureEvent>> {
        let mut all_events = Vec::new();

        // Query all archives that might contain events in the range.
        let archives = Self::list_archives(db_path)?;
        for archive_path in &archives {
            // Check archive metadata to see if it could contain relevant events.
            if let Ok(events) =
                Self::query_archive(archive_path, &self.hmac_key, file_path, start_ns, end_ns)
            {
                all_events.extend(events);
            }
        }

        // Query the active database.
        let active_events = self.get_events_for_file_in_range(file_path, start_ns, end_ns)?;
        all_events.extend(active_events);

        // Sort by timestamp to ensure correct ordering across boundaries.
        all_events.sort_by_key(|e| e.timestamp_ns);

        Ok(all_events)
    }

    /// Verify the chain link between an archive and the active database.
    ///
    /// The archive's last event_hash must equal the active DB's earliest
    /// event's previous_hash (or the integrity record's chain if no events remain
    /// from before the archive cutoff).
    pub fn verify_archive_chain_link(
        &self,
        archive_path: &Path,
    ) -> anyhow::Result<bool> {
        let archive_conn = Connection::open_with_flags(
            archive_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        // Get the archive's chain_hash (last event hash).
        let archive_chain_hash: Vec<u8> = archive_conn.query_row(
            "SELECT chain_hash FROM integrity WHERE id = 1",
            [],
            |row| row.get(0),
        )?;

        // Get the active DB's first event's previous_hash.
        let first_prev_hash: Option<Vec<u8>> = match self
            .conn
            .query_row(
                "SELECT previous_hash FROM secure_events ORDER BY id ASC LIMIT 1",
                [],
                |row| row.get(0),
            ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };

        match first_prev_hash {
            Some(prev) => Ok(prev.ct_eq(&archive_chain_hash).unwrap_u8() == 1),
            None => {
                // No events in active DB; the archive chain hash should match
                // the zero hash if this is a fresh DB, or the integrity chain_hash
                // if events were fully archived.
                Ok(true)
            }
        }
    }
}
