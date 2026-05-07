// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::fingerprint::AuthorFingerprint;
use crate::store::SecureStore;
use rusqlite::params;

impl SecureStore {
    /// Load a stored author fingerprint by profile ID.
    pub fn get_fingerprint(&self, profile_id: &str) -> anyhow::Result<Option<AuthorFingerprint>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data_json FROM fingerprints WHERE profile_id = ?")?;
        let mut rows = stmt.query([profile_id])?;

        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            let fingerprint: AuthorFingerprint = serde_json::from_str(&json)?;
            Ok(Some(fingerprint))
        } else {
            Ok(None)
        }
    }

    /// Persist an author fingerprint, replacing any existing one with the same ID.
    pub fn save_fingerprint(&self, fingerprint: &AuthorFingerprint) -> anyhow::Result<()> {
        let json = serde_json::to_string(fingerprint)?;
        let now = chrono::Utc::now().timestamp();

        self.conn.execute(
            "INSERT OR REPLACE INTO fingerprints (profile_id, data_json, updated_at) VALUES (?, ?, ?)",
            params![fingerprint.id, json, now]
        )?;
        Ok(())
    }

    /// Return the number of completed sessions for a profile (bootstrap counter).
    /// Returns 0 when no row exists yet.
    pub fn get_fingerprint_session_count(&self, profile_id: &str) -> anyhow::Result<u32> {
        let result = self.conn.query_row(
            "SELECT COALESCE(session_count, 0) FROM fingerprints WHERE profile_id = ?",
            [profile_id],
            |row| row.get::<_, i64>(0),
        );
        match result {
            Ok(n) => Ok(u32::try_from(n).unwrap_or(u32::MAX)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Increment the session counter for a profile by 1.
    ///
    /// If no row exists yet, an empty row is inserted first so the counter can
    /// be incremented before the full fingerprint data is available.
    pub fn increment_fingerprint_session_count(&self, profile_id: &str) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO fingerprints (profile_id, data_json, updated_at, session_count)
             VALUES (?, '{}', ?, 1)
             ON CONFLICT(profile_id) DO UPDATE SET
                 session_count = COALESCE(session_count, 0) + 1,
                 updated_at    = excluded.updated_at",
            params![profile_id, now],
        )?;
        Ok(())
    }
}
