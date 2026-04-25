// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::crypto;
use crate::store::SecureStore;
use crate::DateTimeNanosExt;
use anyhow::anyhow;
use rusqlite::params;
use subtle::ConstantTimeEq;

const KNOWN_TABLES: &[&str] = &[
    "integrity",
    "secure_events",
    "clipboard_events",
    "text_fragments",
    "keystroke_sequences",
    "used_nonces",
    "baselines",
    "fingerprints",
];

fn has_column(conn: &rusqlite::Connection, table: &str, col: &str) -> anyhow::Result<bool> {
    anyhow::ensure!(
        KNOWN_TABLES.contains(&table),
        "has_column called with unknown table: {table}"
    );
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let found = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .any(|name| matches!(name.as_deref(), Ok(c) if c == col));
    Ok(found)
}

impl SecureStore {
    pub(crate) fn init_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
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
                challenge_nonce TEXT
            );

            CREATE TABLE IF NOT EXISTS physical_baselines (
                signal_name     TEXT PRIMARY KEY,
                sample_count    INTEGER NOT NULL DEFAULT 0,
                mean            REAL NOT NULL DEFAULT 0.0,
                m2              REAL NOT NULL DEFAULT 0.0
            );

            CREATE TABLE IF NOT EXISTS fingerprints (
                profile_id      TEXT PRIMARY KEY,
                data_json       TEXT NOT NULL,
                updated_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS baseline_digests (
                identity_fingerprint BLOB PRIMARY KEY,
                digest_cbor          BLOB NOT NULL,
                signature            BLOB NOT NULL,
                updated_at           INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS document_stats (
                file_path           TEXT PRIMARY KEY,
                total_keystrokes    INTEGER NOT NULL DEFAULT 0,
                total_focus_ms      INTEGER NOT NULL DEFAULT 0,
                session_count       INTEGER NOT NULL DEFAULT 0,
                total_duration_secs INTEGER NOT NULL DEFAULT 0,
                first_tracked_at    INTEGER NOT NULL,
                last_tracked_at     INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS text_fragments (
                id                          INTEGER PRIMARY KEY AUTOINCREMENT,
                fragment_hash               BLOB NOT NULL UNIQUE,
                session_id                  TEXT NOT NULL,
                source_app_bundle_id        TEXT,
                source_window_title         TEXT,
                source_signature            BLOB NOT NULL,
                nonce                       BLOB NOT NULL UNIQUE,
                timestamp                   INTEGER NOT NULL,
                keystroke_context           TEXT,
                keystroke_confidence        REAL,
                keystroke_sequence_hash     BLOB,
                source_session_id           TEXT,
                source_evidence_packet      BLOB,
                wal_entry_hash              BLOB,
                cloudkit_record_id          TEXT,
                sync_state                  TEXT,
                CONSTRAINT valid_signature CHECK(source_signature IS NOT NULL)
            );

            CREATE TABLE IF NOT EXISTS keystroke_sequences (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id              TEXT NOT NULL,
                sequence_hash           BLOB NOT NULL,
                keystroke_count         INTEGER,
                timestamp_start         INTEGER,
                timestamp_end           INTEGER
            );

            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce                   BLOB PRIMARY KEY,
                used_at                 INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS clipboard_events (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                fragment_hash           BLOB NOT NULL,
                app_bundle_id           TEXT NOT NULL,
                window_title            TEXT,
                text_hash               BLOB NOT NULL,
                pasteboard_change_count INTEGER NOT NULL,
                timestamp               INTEGER NOT NULL,
                captured_at             INTEGER NOT NULL,
                hmac                    BLOB,
                signed_evidence         BLOB
            );

            CREATE INDEX IF NOT EXISTS idx_secure_events_timestamp ON secure_events(timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_secure_events_file ON secure_events(file_path, timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_secure_events_file_id ON secure_events(file_path, id);
            CREATE INDEX IF NOT EXISTS idx_text_fragments_hash ON text_fragments(fragment_hash);
            CREATE INDEX IF NOT EXISTS idx_text_fragments_session ON text_fragments(session_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_keystroke_sequences_session ON keystroke_sequences(session_id);
            CREATE INDEX IF NOT EXISTS idx_clipboard_events_fragment ON clipboard_events(fragment_hash);
            CREATE INDEX IF NOT EXISTS idx_clipboard_events_timestamp ON clipboard_events(timestamp);"
        )?;

        // Migration: add `last_verified_sequence` to pre-existing integrity rows
        if !has_column(&self.conn, "integrity", "last_verified_sequence")? {
            self.conn.execute_batch(
                "ALTER TABLE integrity ADD COLUMN last_verified_sequence INTEGER NOT NULL DEFAULT 0;",
            )?;
        }

        // Migration: add `hardware_counter` to pre-existing schemas
        if !has_column(&self.conn, "secure_events", "hardware_counter")? {
            self.conn
                .execute_batch("ALTER TABLE secure_events ADD COLUMN hardware_counter INTEGER;")?;
        }

        // Migration: add `input_method` to pre-existing schemas
        if !has_column(&self.conn, "secure_events", "input_method")? {
            self.conn
                .execute_batch("ALTER TABLE secure_events ADD COLUMN input_method TEXT;")?;
        }

        // Migration: add Lamport signature columns to pre-existing schemas
        if !has_column(&self.conn, "secure_events", "lamport_signature")? {
            self.conn.execute_batch(
                "ALTER TABLE secure_events ADD COLUMN lamport_signature BLOB;
                 ALTER TABLE secure_events ADD COLUMN lamport_pubkey_fingerprint BLOB;",
            )?;
        }

        // Migration: add `hmac` to pre-existing clipboard_events
        if !has_column(&self.conn, "clipboard_events", "hmac")? {
            self.conn
                .execute_batch("ALTER TABLE clipboard_events ADD COLUMN hmac BLOB;")?;
        }

        // Migration: add `signed_evidence` to pre-existing clipboard_events
        if !has_column(&self.conn, "clipboard_events", "signed_evidence")? {
            self.conn
                .execute_batch("ALTER TABLE clipboard_events ADD COLUMN signed_evidence BLOB;")?;
        }

        if !has_column(&self.conn, "secure_events", "challenge_nonce")? {
            self.conn
                .execute_batch("ALTER TABLE secure_events ADD COLUMN challenge_nonce TEXT;")?;
        }

        if !has_column(&self.conn, "secure_events", "hw_cosign_signature")? {
            self.conn.execute_batch(
                "ALTER TABLE secure_events ADD COLUMN hw_cosign_signature BLOB;
                 ALTER TABLE secure_events ADD COLUMN hw_cosign_pubkey BLOB;
                 ALTER TABLE secure_events ADD COLUMN hw_cosign_salt_commitment BLOB;
                 ALTER TABLE secure_events ADD COLUMN hw_cosign_chain_index INTEGER;
                 ALTER TABLE secure_events ADD COLUMN hw_cosign_entangled_hash BLOB;
                 ALTER TABLE secure_events ADD COLUMN hw_cosign_entropy_digest BLOB;
                 ALTER TABLE secure_events ADD COLUMN hw_cosign_entropy_bytes INTEGER;",
            )?;
        }

        if !has_column(&self.conn, "secure_events", "posme_proof")? {
            self.conn
                .execute_batch("ALTER TABLE secure_events ADD COLUMN posme_proof BLOB;")?;
        }

        // Migration: ensure text_fragments tables exist (created in init_schema, but check for older DBs)
        if !has_column(&self.conn, "text_fragments", "fragment_hash")? {
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS text_fragments (
                    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
                    fragment_hash               BLOB NOT NULL UNIQUE,
                    session_id                  TEXT NOT NULL,
                    source_app_bundle_id        TEXT,
                    source_window_title         TEXT,
                    source_signature            BLOB NOT NULL,
                    nonce                       BLOB NOT NULL UNIQUE,
                    timestamp                   INTEGER NOT NULL,
                    keystroke_context           TEXT,
                    keystroke_confidence        REAL,
                    keystroke_sequence_hash     BLOB,
                    source_session_id           TEXT,
                    source_evidence_packet      BLOB,
                    wal_entry_hash              BLOB,
                    cloudkit_record_id          TEXT,
                    sync_state                  TEXT,
                    FOREIGN KEY(session_id) REFERENCES document_sessions(session_id),
                    CONSTRAINT valid_signature CHECK(source_signature IS NOT NULL)
                );
                CREATE TABLE IF NOT EXISTS keystroke_sequences (
                    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id              TEXT NOT NULL,
                    sequence_hash           BLOB NOT NULL,
                    keystroke_count         INTEGER,
                    timestamp_start         INTEGER,
                    timestamp_end           INTEGER,
                    FOREIGN KEY(session_id) REFERENCES document_sessions(session_id)
                );
                CREATE TABLE IF NOT EXISTS used_nonces (
                    nonce                   BLOB PRIMARY KEY,
                    used_at                 INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_text_fragments_hash ON text_fragments(fragment_hash);
                CREATE INDEX IF NOT EXISTS idx_text_fragments_session ON text_fragments(session_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_keystroke_sequences_session ON keystroke_sequences(session_id);",
            )?;
        }

        Ok(())
    }

    /// Verify the event chain incrementally: only events with id > last_verified_sequence
    /// are re-checked. Already-verified events are trusted, which reduces open-time cost
    /// from O(n) to O(new) on subsequent opens.
    pub fn verify_integrity(&mut self) -> anyhow::Result<()> {
        let res = self.conn.query_row(
            "SELECT chain_hash, event_count, last_verified_sequence, hmac FROM integrity WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        );

        match res {
            Ok((chain_hash, event_count, last_verified_seq, stored_hmac)) => {
                let chain_hash_arr: [u8; 32] = chain_hash
                    .try_into()
                    .map_err(|_| anyhow!("Invalid chain_hash length in integrity record"))?;

                let expected_hmac = crypto::compute_integrity_hmac(
                    &self.hmac_key,
                    &chain_hash_arr,
                    event_count,
                    last_verified_seq,
                );
                if stored_hmac.ct_eq(&expected_hmac).unwrap_u8() == 0 {
                    return Err(anyhow!("Integrity record HMAC mismatch"));
                }

                // Fetch the hash of the last already-verified event so we can continue
                // the chain check from that point without re-reading earlier rows.
                let resume_hash: [u8; 32] = if last_verified_seq > 0 {
                    let hash_bytes: Vec<u8> = self.conn.query_row(
                        "SELECT event_hash FROM secure_events WHERE id = ? LIMIT 1",
                        params![last_verified_seq],
                        |row| row.get(0),
                    )?;
                    hash_bytes
                        .try_into()
                        .map_err(|_| anyhow!("Invalid event_hash for last verified event"))?
                } else {
                    [0u8; 32]
                };

                // Only scan events that have not yet been verified.
                let mut stmt = self.conn.prepare(
                    "SELECT id, event_hash, previous_hash, hmac, device_id, timestamp_ns,
                            file_path, content_hash, file_size, size_delta
                     FROM secure_events
                     WHERE id > ?
                     ORDER BY id ASC",
                )?;

                let mut rows = stmt.query(params![last_verified_seq])?;
                let mut last_hash = resume_hash;
                let mut count = 0i64;
                let mut new_last_seq = last_verified_seq;

                while let Some(row) = rows.next()? {
                    let id: i64 = row.get(0)?;
                    let event_hash: Vec<u8> = row.get(1)?;
                    let previous_hash: Vec<u8> = row.get(2)?;
                    let stored_event_hmac: Vec<u8> = row.get(3)?;
                    let device_id: Vec<u8> = row.get(4)?;
                    let timestamp_ns: i64 = row.get(5)?;
                    let file_path: String = row.get(6)?;
                    let content_hash: Vec<u8> = row.get(7)?;
                    let file_size: i64 = row.get(8)?;
                    let size_delta: i32 = row.get(9)?;

                    let device_id_arr: [u8; 16] = device_id
                        .try_into()
                        .map_err(|_| anyhow!("Invalid device_id"))?;
                    let content_hash_arr: [u8; 32] = content_hash
                        .try_into()
                        .map_err(|_| anyhow!("Invalid content_hash"))?;
                    let previous_hash_arr: [u8; 32] = previous_hash
                        .try_into()
                        .map_err(|_| anyhow!("Invalid previous_hash"))?;

                    if last_verified_seq == 0 && count == 0 {
                        // First event ever: previous_hash must be the zero sentinel.
                        if previous_hash_arr.ct_eq(&[0u8; 32]).unwrap_u8() != 1 {
                            return Err(anyhow!("First event {} has non-zero previous_hash", id));
                        }
                    } else if previous_hash_arr.ct_eq(&last_hash).unwrap_u8() != 1 {
                        return Err(anyhow!("Chain break at event {}", id));
                    }

                    let event_data = crypto::EventData {
                        device_id: device_id_arr,
                        timestamp_ns,
                        file_path: file_path.clone(),
                        content_hash: content_hash_arr,
                        file_size,
                        size_delta,
                        previous_hash: previous_hash_arr,
                    };

                    let expected_event_hash = crypto::compute_event_hash(&event_data);
                    if event_hash.ct_eq(&expected_event_hash).unwrap_u8() == 0 {
                        return Err(anyhow!("Event {} hash mismatch", id));
                    }

                    let expected_event_hmac =
                        crypto::compute_event_hmac(&self.hmac_key, &event_data);
                    if stored_event_hmac.ct_eq(&expected_event_hmac).unwrap_u8() == 0 {
                        return Err(anyhow!("Event {} HMAC mismatch", id));
                    }

                    last_hash = expected_event_hash;
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("integrity verification count overflow"))?;
                    new_last_seq = id;
                }

                // Total event count must match the integrity record.
                if last_verified_seq + count != event_count {
                    return Err(anyhow!("Event count mismatch"));
                }

                // Persist the new high-water mark so the next open skips these rows.
                // Recompute the HMAC to cover the updated last_verified_sequence.
                if new_last_seq > last_verified_seq {
                    let updated_hmac = crypto::compute_integrity_hmac(
                        &self.hmac_key,
                        &chain_hash_arr,
                        event_count,
                        new_last_seq,
                    );
                    self.conn.execute(
                        "UPDATE integrity SET last_verified_sequence = ?, last_verified = ?, hmac = ? WHERE id = 1",
                        params![new_last_seq, chrono::Utc::now().timestamp_nanos_safe(), &updated_hmac[..]],
                    )?;
                }

                self.last_hash = last_hash;
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                self.last_hash = [0u8; 32];
                let initial_hmac =
                    crypto::compute_integrity_hmac(&self.hmac_key, &self.last_hash, 0, 0);
                self.conn.execute(
                    "INSERT INTO integrity \
                        (id, chain_hash, event_count, last_verified, last_verified_sequence, hmac) \
                        VALUES (1, ?, 0, ?, 0, ?)",
                    params![
                        &self.last_hash[..],
                        chrono::Utc::now().timestamp_nanos_safe(),
                        &initial_hmac[..]
                    ],
                )?;
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
}
