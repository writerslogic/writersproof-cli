// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Persistent URL-to-session index for browser sessions.
//!
//! Stores lightweight records in `browser-sessions/sessions.json` so that
//! the sentinel can link a new session to a prior session for the same URL,
//! giving verifiers a continuous evidence chain across Chrome restarts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

const SESSIONS_FILE: &str = "sessions.json";
/// Sessions older than 7 days are not linked (writer has likely started fresh).
const MAX_AGE_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionRecord {
    pub(crate) session_id: String,
    pub(crate) cumulative_chars: u64,
    pub(crate) last_ordinal: u64,
    pub(crate) last_active_ns: u64,
}

pub(crate) type SessionIndex = HashMap<String, SessionRecord>;

pub(crate) fn load(dir: &Path) -> SessionIndex {
    let path = dir.join(SESSIONS_FILE);
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(e) => {
            eprintln!("Warning: failed to read session index: {e}");
            HashMap::new()
        }
    }
}

pub(crate) fn save(dir: &Path, index: &SessionIndex) {
    let path = dir.join(SESSIONS_FILE);
    match serde_json::to_string(index) {
        Ok(s) => {
            if let Err(e) = std::fs::write(&path, s) {
                eprintln!("Warning: failed to write session index: {e}");
            }
        }
        Err(e) => eprintln!("Warning: failed to serialize session index: {e}"),
    }
}

/// Look up a recent prior session for `url`. Returns `None` if none exists
/// or the record is older than `MAX_AGE_NS`.
pub(crate) fn lookup_recent(index: &SessionIndex, url: &str, now_ns: u64) -> Option<&SessionRecord> {
    index.get(url).filter(|r| {
        now_ns.saturating_sub(r.last_active_ns) < MAX_AGE_NS
    })
}

/// Upsert the session record for `url`, then persist to disk.
pub(crate) fn upsert_and_save(
    dir: &Path,
    url: &str,
    session_id: &str,
    cumulative_chars: u64,
    last_ordinal: u64,
    now_ns: u64,
) {
    let mut index = load(dir);
    index.insert(url.to_string(), SessionRecord {
        session_id: session_id.to_string(),
        cumulative_chars,
        last_ordinal,
        last_active_ns: now_ns,
    });
    // Evict entries older than MAX_AGE_NS to bound file growth.
    index.retain(|_, r| now_ns.saturating_sub(r.last_active_ns) < MAX_AGE_NS);
    save(dir, &index);
}
