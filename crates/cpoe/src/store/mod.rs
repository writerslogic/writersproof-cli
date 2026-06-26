// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use rusqlite::Connection;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Acquire an exclusive advisory lock on a sidecar `.db.lock` file.
///
/// Returns `Some(File)` whose lifetime holds the lock (released on drop),
/// or `None` for in-memory databases. Fails fast with an actionable error
/// if another process already holds the lock.
pub(crate) fn acquire_db_lock(db_path: &Path) -> anyhow::Result<Option<std::fs::File>> {
    if db_path.to_string_lossy() == ":memory:" {
        return Ok(None);
    }
    let lock_path = db_path.with_extension("db.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| anyhow::anyhow!("Failed to open lock file {}: {e}", lock_path.display()))?;

    #[cfg(unix)]
    {
        crate::crypto::restrict_permissions(&lock_path, 0o600)?;
        use std::os::unix::io::AsRawFd;
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                anyhow::bail!(
                    "Database is locked by another process: {}. \
                     Close the other instance before opening.",
                    db_path.display()
                );
            }
            anyhow::bail!(
                "Failed to acquire database lock on {}: {err}",
                db_path.display()
            );
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
        };
        let handle = HANDLE(file.as_raw_handle());
        let mut overlapped = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                Some(0),
                1,
                0,
                &mut overlapped,
            )
        };
        if ok.is_err() {
            anyhow::bail!(
                "Database is locked by another process: {}. \
                 Close the other instance before opening.",
                db_path.display()
            );
        }
    }

    Ok(Some(file))
}

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
    /// Advisory file lock held for the lifetime of this store to prevent
    /// concurrent write access from other processes (e.g. CLI + GUI app).
    /// Dropped automatically when the store is closed, releasing the lock.
    _lock_file: Option<std::fs::File>,
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

        let journal_mode: String =
            conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if journal_mode.to_lowercase() != "wal" {
            log::warn!("events db: requested WAL but got '{journal_mode}' journal mode");
        }
        // fullfsync=ON makes SQLite use F_FULLFSYNC on macOS instead of
        // fsync(), ensuring the disk write cache is flushed to stable storage.
        // Without this, a power failure after fsync() returns can lose data on
        // some macOS configurations where fsync() only flushes to the drive's
        // volatile cache.
        conn.execute_batch(&format!(
            "PRAGMA busy_timeout={BUSY_TIMEOUT_MS}; PRAGMA foreign_keys=ON; \
             PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; \
             PRAGMA secure_delete=ON; \
             PRAGMA max_page_count={MAX_PAGE_COUNT};"
        ))?;

        let lock_file = acquire_db_lock(path)?;

        let mut store = Self {
            conn,
            hmac_key,
            last_hash: [0u8; 32],
            _lock_file: lock_file,
        };

        store.init_schema()?;
        store.verify_integrity()?;

        Ok(store)
    }

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
        content_kind: Option<u8>,
        pasteboard_types: Option<&str>,
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
        if let Some(ck) = content_kind {
            mac.update(&[ck]);
        }
        let hmac_tag: [u8; 32] = mac.finalize().into_bytes().into();

        self.conn.execute(
            "INSERT INTO clipboard_events
             (fragment_hash, app_bundle_id, window_title, text_hash, pasteboard_change_count, timestamp, captured_at, hmac, signed_evidence, content_kind, pasteboard_types)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                fragment_hash,
                app_bundle_id,
                window_title,
                text_hash,
                pasteboard_change_count,
                timestamp,
                captured_at,
                hmac_tag,
                signed_evidence,
                content_kind,
                pasteboard_types
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

    /// Register a C2PA manifest hash paired with the document's SimHash for stripping detection.
    ///
    /// Uses INSERT OR IGNORE so repeated exports of the same manifest are idempotent.
    pub fn insert_manifest_registry(
        &self,
        document_simhash: i64,
        manifest_hash: &str,
        document_path: &str,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO manifest_registry
             (document_simhash, manifest_hash, document_path)
             VALUES (?, ?, ?)",
            rusqlite::params![document_simhash, manifest_hash, document_path],
        )?;
        Ok(())
    }

    /// Look up a manifest registry row by SimHash distance.
    ///
    /// Returns `(manifest_hash, document_path)` for the closest stored entry whose
    /// SimHash Hamming distance from `query_simhash` is at most `max_distance` bits.
    /// Returns `None` if no match is found.
    pub fn lookup_manifest_by_simhash(
        &self,
        query_simhash: i64,
        max_distance: u32,
    ) -> anyhow::Result<Option<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT document_simhash, manifest_hash, document_path FROM manifest_registry",
        )?;
        let mut best: Option<(u32, String, String)> = None;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (stored_simhash, manifest_hash, doc_path) = row?;
            let dist = ((query_simhash as u64) ^ (stored_simhash as u64)).count_ones();
            if dist <= max_distance && best.as_ref().map_or(true, |(d, _, _)| dist < *d) {
                best = Some((dist, manifest_hash, doc_path));
            }
        }
        Ok(best.map(|(_, mh, dp)| (mh, dp)))
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

/// Minimum free disk space (in bytes) required before starting a write-heavy
/// operation such as export or archival. 50 MiB provides headroom for SQLite
/// WAL checkpoint, temporary files, and the output artifact.
const MIN_FREE_SPACE_BYTES: u64 = 50 * 1024 * 1024;

/// Check that the volume containing `path` has at least [`MIN_FREE_SPACE_BYTES`]
/// free. Returns `Ok(available)` on success or an actionable error when space is
/// insufficient.
pub fn check_disk_space(path: &Path) -> anyhow::Result<u64> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let c_path = CString::new(
            path.to_str()
                .ok_or_else(|| anyhow::anyhow!("Path is not valid UTF-8"))?,
        )?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if ret != 0 {
            return Err(anyhow::anyhow!(
                "Failed to query disk space for {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let available = stat.f_bavail as u64 * stat.f_frsize;
        if available < MIN_FREE_SPACE_BYTES {
            anyhow::bail!(
                "Insufficient disk space: {} MiB available, {} MiB required. \
                 Free space on the volume containing {} before retrying.",
                available / (1024 * 1024),
                MIN_FREE_SPACE_BYTES / (1024 * 1024),
                path.display()
            );
        }
        Ok(available)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(u64::MAX)
    }
}
