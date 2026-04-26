// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use rusqlite::Connection;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub mod access_log;
pub mod baselines;
pub mod document_stats;
pub mod events;
pub mod fingerprints;
pub mod integrity;
pub mod text_fragments;
pub mod types;

#[cfg(test)]
mod tests;

pub use document_stats::DocumentStats;
pub use text_fragments::{KeystrokeContext, TextFragment};
pub use types::SecureEvent;

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

        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
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
        // Reject timestamps more than 5 minutes in the future.
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let five_min_ns = 5 * 60 * 1_000_000_000i64;
        if timestamp > now_ns + five_min_ns || captured_at > now_ns + five_min_ns {
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
