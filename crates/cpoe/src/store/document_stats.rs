// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Cumulative per-document statistics that persist across tracking sessions.

use crate::store::SecureStore;
use rusqlite::params;
use std::path::Path;

#[derive(Debug)]
/// Cumulative statistics for a tracked document across all sessions.
pub struct DocumentStats {
    pub file_path: String,
    pub total_keystrokes: i64,
    pub total_focus_ms: i64,
    pub session_count: i64,
    pub total_duration_secs: i64,
    pub first_tracked_at: i64,
    pub last_tracked_at: i64,
    pub total_checkpoints: i64,
}

impl SecureStore {
    /// Load cumulative stats for a document, or None if never tracked.
    pub fn load_document_stats(
        &self,
        file_path: impl AsRef<Path>,
    ) -> anyhow::Result<Option<DocumentStats>> {
        let file_path = file_path.as_ref().to_string_lossy();
        let mut stmt = self.conn.prepare(
            "SELECT file_path, total_keystrokes, total_focus_ms, session_count,
                    total_duration_secs, first_tracked_at, last_tracked_at, total_checkpoints
             FROM document_stats WHERE file_path = ?1",
        )?;

        let result = stmt.query_row(params![file_path.as_ref()], |row| {
            Ok(DocumentStats {
                file_path: row.get(0)?,
                total_keystrokes: row.get(1)?,
                total_focus_ms: row.get(2)?,
                session_count: row.get(3)?,
                total_duration_secs: row.get(4)?,
                first_tracked_at: row.get(5)?,
                last_tracked_at: row.get(6)?,
                total_checkpoints: row.get(7)?,
            })
        });

        match result {
            Ok(stats) => Ok(Some(stats)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Load cumulative stats for all documents, keyed by file path.
    pub fn load_all_document_stats(
        &self,
    ) -> anyhow::Result<std::collections::HashMap<String, DocumentStats>> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, total_keystrokes, total_focus_ms, session_count,
                    total_duration_secs, first_tracked_at, last_tracked_at, total_checkpoints
             FROM document_stats",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(DocumentStats {
                file_path: row.get(0)?,
                total_keystrokes: row.get(1)?,
                total_focus_ms: row.get(2)?,
                session_count: row.get(3)?,
                total_duration_secs: row.get(4)?,
                first_tracked_at: row.get(5)?,
                last_tracked_at: row.get(6)?,
                total_checkpoints: row.get(7)?,
            })
        })?;

        let mut map = std::collections::HashMap::new();
        for row in rows {
            let stats = row?;
            map.insert(stats.file_path.clone(), stats);
        }
        Ok(map)
    }

    /// Load stats for a title:// session by matching the prefix before `#w`.
    /// When an app restarts, the CGWindowID changes, so exact path match fails.
    /// Returns the most recently tracked session for the same title:// base.
    pub fn load_title_session_stats(
        &self,
        title_path: &str,
    ) -> anyhow::Result<Option<DocumentStats>> {
        let base = match title_path.rfind("#w") {
            Some(pos) => &title_path[..pos],
            None => title_path,
        };
        let pattern = format!("{base}%");
        let mut stmt = self.conn.prepare(
            "SELECT file_path, total_keystrokes, total_focus_ms, session_count,
                    total_duration_secs, first_tracked_at, last_tracked_at, total_checkpoints
             FROM document_stats WHERE file_path LIKE ?1
             ORDER BY last_tracked_at DESC LIMIT 1",
        )?;

        let result = stmt.query_row(params![pattern], |row| {
            Ok(DocumentStats {
                file_path: row.get(0)?,
                total_keystrokes: row.get(1)?,
                total_focus_ms: row.get(2)?,
                session_count: row.get(3)?,
                total_duration_secs: row.get(4)?,
                first_tracked_at: row.get(5)?,
                last_tracked_at: row.get(6)?,
                total_checkpoints: row.get(7)?,
            })
        });

        match result {
            Ok(stats) => Ok(Some(stats)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Insert or update cumulative stats for a document.
    pub fn save_document_stats(&self, stats: &DocumentStats) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO document_stats
                (file_path, total_keystrokes, total_focus_ms, session_count,
                 total_duration_secs, first_tracked_at, last_tracked_at, total_checkpoints)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(file_path) DO UPDATE SET
                total_keystrokes = ?2,
                total_focus_ms = ?3,
                session_count = ?4,
                total_duration_secs = ?5,
                first_tracked_at = ?6,
                last_tracked_at = ?7,
                total_checkpoints = ?8",
            params![
                stats.file_path,
                stats.total_keystrokes,
                stats.total_focus_ms,
                stats.session_count,
                stats.total_duration_secs,
                stats.first_tracked_at,
                stats.last_tracked_at,
                stats.total_checkpoints,
            ],
        )?;
        Ok(())
    }
}
