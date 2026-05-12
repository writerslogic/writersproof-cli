// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use rusqlite::Connection;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub mod access_log;
pub mod archive;
pub mod baselines;
pub mod document_stats;
pub mod events;
pub mod fingerprints;
pub mod integrity;
pub mod text_fragments;
pub mod types;

#[cfg(test)]
mod archive_tests;
#[cfg(test)]
mod tests;

pub use document_stats::DocumentStats;
pub use text_fragments::{KeystrokeContext, TextFragment};
pub use types::{SecureEvent, ShadowSessionRow};

/// SQLite busy timeout in milliseconds. Shared with `AccessLog` (see `access_log.rs`).
pub(crate) const BUSY_TIMEOUT_MS: u32 = 5000;

/// Maximum SQLite page count. With the default 4096-byte page size this caps
/// the database at ~2 GiB, preventing unbounded disk growth from long sessions.
const MAX_PAGE_COUNT: u64 = 524_288;

/// HMAC-integrity-protected SQLite event store with hash chaining.
pub struct SecureStore {
    pub(crate) conn: Connection,
    pub(crate) hmac_key: Zeroizing<Vec<u8>>,
    pub(crate) last_hash: [u8; 32],
}

impl std::fmt::Debug for SecureStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureStore")
            .field("hmac_key", &"[REDACTED]")
            .field("last_hash", &self.last_hash)
            .finish()
    }
}

impl SecureStore {
    /// Open or create a secure store at `path`, initializing schema and verifying integrity.
    pub fn open<P: AsRef<Path>>(path: P, hmac_key: Zeroizing<Vec<u8>>) -> anyhow::Result<Self> {
        if hmac_key.len() != 32 {
            anyhow::bail!("HMAC key must be exactly 32 bytes, got {}", hmac_key.len());
        }
        let path = path.as_ref();
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        {
            let path_str = path.to_string_lossy();
            if path_str != ":memory:" {
                crate::crypto::restrict_permissions(path, 0o600)?;
            }
        }

        let journal_mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if journal_mode.to_lowercase() != "wal" {
            log::warn!("events db: requested WAL but got '{journal_mode}' journal mode");
        }
        conn.execute_batch(&format!(
            "PRAGMA busy_timeout={BUSY_TIMEOUT_MS}; PRAGMA foreign_keys=ON; \
             PRAGMA synchronous=FULL; \
             PRAGMA max_page_count={MAX_PAGE_COUNT};"
        ))?;

        let mut store = Self {
            conn,
            hmac_key,
            last_hash: [0u8; 32],
        };

        store.init_schema()?;
        store.verify_integrity()?;

        Ok(store)
    }

    /// Persist a clipboard event to the database.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_clipboard_event(
        &self,
        fragment_hash: &[u8; 32],
        app_bundle_id: &str,
        window_title: &str,
        text_hash: &[u8; 32],
        pasteboard_change_count: i32,
        timestamp: i64,
        captured_at: i64,
        signed_evidence: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        // Reject timestamps more than 15 minutes in the future. The 15-minute window
        // matches NTP's maximum step-back tolerance: a clock corrected backward by up
        // to ~10 minutes would make a legitimately captured timestamp appear that far
        // ahead of "now", so a 5-minute window caused false rejections after NTP jumps.
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .map_err(|e| anyhow::anyhow!("System clock unavailable: {e}"))?;
        let fifteen_min_ns = 15 * 60 * 1_000_000_000i64;
        if timestamp > now_ns + fifteen_min_ns || captured_at > now_ns + fifteen_min_ns {
            anyhow::bail!("Clipboard event timestamp is too far in the future");
        }

        // Compute HMAC-SHA256 over evidence-critical fields.
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.hmac_key)
            .expect("HMAC key length already validated");
        mac.update(fragment_hash);
        mac.update(&(app_bundle_id.len() as u32).to_be_bytes());
        mac.update(app_bundle_id.as_bytes());
        mac.update(&(window_title.len() as u32).to_be_bytes());
        mac.update(window_title.as_bytes());
        mac.update(text_hash);
        mac.update(&pasteboard_change_count.to_le_bytes());
        mac.update(&timestamp.to_le_bytes());
        mac.update(&captured_at.to_le_bytes());
        if let Some(se) = signed_evidence {
            mac.update(se);
        }
        let hmac_tag: [u8; 32] = mac.finalize().into_bytes().into();

        self.conn.execute(
            "INSERT INTO clipboard_events
             (fragment_hash, app_bundle_id, window_title, text_hash, pasteboard_change_count, timestamp, captured_at, hmac, signed_evidence)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                fragment_hash,
                app_bundle_id,
                window_title,
                text_hash,
                pasteboard_change_count,
                timestamp,
                captured_at,
                hmac_tag,
                signed_evidence
            ],
        )?;
        Ok(())
    }

    /// Persist or update a shadow session keyed by `(bundle_id, project_uuid)`.
    ///
    /// Called whenever a bundle-based session checkpoint is committed so the
    /// session state survives a sentinel restart.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_shadow_session(
        &self,
        bundle_id: &str,
        project_uuid: &str,
        session_id: &str,
        wal_path: Option<&str>,
        segment_counts_json: &str,
        scrivx_hash: Option<&str>,
        last_checkpoint_ns: i64,
    ) -> anyhow::Result<()> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        self.conn.execute(
            "INSERT INTO shadow_sessions
             (bundle_id, project_uuid, session_id, wal_path, segment_counts_json,
              scrivx_hash, last_checkpoint_ns, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(bundle_id, project_uuid) DO UPDATE SET
                 session_id          = excluded.session_id,
                 wal_path            = excluded.wal_path,
                 segment_counts_json = excluded.segment_counts_json,
                 scrivx_hash         = excluded.scrivx_hash,
                 last_checkpoint_ns  = excluded.last_checkpoint_ns,
                 updated_at          = excluded.updated_at",
            rusqlite::params![
                bundle_id,
                project_uuid,
                session_id,
                wal_path,
                segment_counts_json,
                scrivx_hash,
                last_checkpoint_ns,
                now_ns,
            ],
        )?;
        Ok(())
    }

    /// Load a previously persisted shadow session for `(bundle_id, project_uuid)`.
    ///
    /// Returns `None` if no row exists (first launch or after cleanup).
    pub fn load_shadow_session(
        &self,
        bundle_id: &str,
        project_uuid: &str,
    ) -> anyhow::Result<Option<ShadowSessionRow>> {
        let result = self.conn.query_row(
            "SELECT bundle_id, project_uuid, session_id, wal_path, segment_counts_json,
                    scrivx_hash, last_checkpoint_ns, updated_at
             FROM shadow_sessions
             WHERE bundle_id = ? AND project_uuid = ?",
            rusqlite::params![bundle_id, project_uuid],
            |row| {
                Ok(ShadowSessionRow {
                    bundle_id: row.get(0)?,
                    project_uuid: row.get(1)?,
                    session_id: row.get(2)?,
                    wal_path: row.get(3)?,
                    segment_counts_json: row.get(4)?,
                    scrivx_hash: row.get(5)?,
                    last_checkpoint_ns: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        );
        match result {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Record a manuscript export attestation with HMAC protection.
    ///
    /// The HMAC covers the four hash fields and both timestamps to make the
    /// attestation tamper-evident even if the database file is copied.
    pub fn insert_export_event(
        &self,
        attestation: &crate::evidence::ManuscriptExportAttestation,
    ) -> anyhow::Result<()> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.hmac_key)
            .expect("HMAC key length already validated");
        mac.update(attestation.source_session_id.as_bytes());
        mac.update(attestation.bundle_hash.as_bytes());
        mac.update(attestation.output_hash.as_bytes());
        mac.update(attestation.output_path_hash.as_bytes());
        mac.update(&attestation.source_checkpoint_ns.to_le_bytes());
        mac.update(&attestation.export_detected_ns.to_le_bytes());
        let hmac_tag: [u8; 32] = mac.finalize().into_bytes().into();

        self.conn.execute(
            "INSERT INTO export_events
             (source_session_id, bundle_hash, output_hash, output_path_hash,
              source_checkpoint_ns, export_detected_ns, hmac)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                attestation.source_session_id,
                attestation.bundle_hash,
                attestation.output_hash,
                attestation.output_path_hash,
                attestation.source_checkpoint_ns,
                attestation.export_detected_ns,
                hmac_tag,
            ],
        )?;
        Ok(())
    }
}

/// Expose the raw connection for benchmarks and integration tests.
/// Only available with the `test-utils` feature; never use in production code.
#[cfg(feature = "test-utils")]
impl SecureStore {
    pub fn raw_conn(&self) -> &Connection {
        &self.conn
    }
    pub fn raw_conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

/// Open a [`SecureStore`] by deriving the HMAC key from an Ed25519 signing key.
///
/// Extracts the key bytes, derives the HMAC key via [`crate::crypto::derive_hmac_key`],
/// zeroizes intermediates, and opens the store at `db_path`.
pub fn open_store_with_signing_key(
    signing_key: &ed25519_dalek::SigningKey,
    db_path: &Path,
) -> anyhow::Result<SecureStore> {
    let mut key_bytes = signing_key.to_bytes();
    let hmac_key = crate::crypto::derive_hmac_key(&key_bytes);
    key_bytes.zeroize();
    SecureStore::open(db_path, hmac_key)
}
