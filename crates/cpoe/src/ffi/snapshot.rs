// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers::{get_data_dir, load_signing_key};
use super::types::FfiResult;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSnapshotEntry {
    pub id: i64,
    pub document_path: String,
    pub timestamp_ns: i64,
    pub word_count: i32,
    pub word_count_delta: i32,
    pub draft_label: Option<String>,
    pub is_restore: bool,
    pub session_group: u32,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSnapshotContent {
    pub success: bool,
    pub plaintext: Option<String>,
    pub error_message: Option<String>,
}

impl FfiSnapshotContent {
    fn ok(plaintext: String) -> Self {
        Self {
            success: true,
            plaintext: Some(plaintext),
            error_message: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            plaintext: None,
            error_message: Some(msg.into()),
        }
    }
}

impl super::types::FfiErrResult for FfiSnapshotContent {
    fn ffi_err(msg: impl Into<String>) -> Self {
        Self::err(msg)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSnapshotSaveResult {
    pub success: bool,
    pub snapshot_id: i64,
    pub size_warning: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDiffOp {
    pub tag: String,
    pub text: String,
}

fn open_snapshot_store() -> Result<crate::snapshot::SnapshotStore, String> {
    let data_dir = get_data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let sk = load_signing_key()?;
    let db_path = data_dir.join("snapshots.db");
    crate::snapshot::SnapshotStore::open(&db_path, &sk)
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_snapshot_save(document_path: String, plaintext: String) -> FfiSnapshotSaveResult {
    if crate::sentinel::helpers::validate_path(&document_path).is_err() {
        return FfiSnapshotSaveResult {
            success: false,
            snapshot_id: -1,
            size_warning: None,
            error_message: Some("Invalid document path".to_string()),
        };
    }
    let mut store = match open_snapshot_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiSnapshotSaveResult {
                success: false,
                snapshot_id: -1,
                size_warning: None,
                error_message: Some(e),
            }
        }
    };
    match store.save(&document_path, &plaintext, false) {
        Ok(id) => {
            let size_warning = store.storage_size().ok().and_then(|info| {
                if info.over_threshold {
                    Some(format!(
                        "Snapshot storage is {:.0} MB",
                        info.total_bytes as f64 / 1_000_000.0
                    ))
                } else {
                    None
                }
            });
            FfiSnapshotSaveResult {
                success: true,
                snapshot_id: id,
                size_warning,
                error_message: None,
            }
        }
        Err(e) => FfiSnapshotSaveResult {
            success: false,
            snapshot_id: -1,
            size_warning: None,
            error_message: Some(e),
        },
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_snapshot_list(document_path: String) -> Vec<FfiSnapshotEntry> {
    if crate::sentinel::helpers::validate_path(&document_path).is_err() {
        return Vec::new();
    }
    let store = match open_snapshot_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("ffi_snapshot_list: {e}");
            return Vec::new();
        }
    };
    match store.list(&document_path) {
        Ok(entries) => entries
            .into_iter()
            .map(|e| FfiSnapshotEntry {
                id: e.id,
                document_path: e.document_path,
                timestamp_ns: e.timestamp_ns,
                word_count: e.word_count,
                word_count_delta: e.word_count_delta,
                draft_label: e.draft_label,
                is_restore: e.is_restore,
                session_group: e.session_group,
            })
            .collect(),
        Err(e) => {
            log::warn!("ffi_snapshot_list: {e}");
            Vec::new()
        }
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_snapshot_get(snapshot_id: i64) -> FfiSnapshotContent {
    let store = match open_snapshot_store() {
        Ok(s) => s,
        Err(e) => return FfiSnapshotContent::err(e),
    };
    match store.get(snapshot_id) {
        Ok(text) => FfiSnapshotContent::ok(text),
        Err(e) => FfiSnapshotContent::err(e),
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_snapshot_diff(snapshot_id: i64, current_text: String) -> Vec<FfiDiffOp> {
    let store = match open_snapshot_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("ffi_snapshot_diff: {e}");
            return Vec::new();
        }
    };
    let old_text = match store.get(snapshot_id) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("ffi_snapshot_diff: {e}");
            return Vec::new();
        }
    };
    crate::snapshot::word_diff(&old_text, &current_text)
        .into_iter()
        .map(|op| FfiDiffOp {
            tag: op.tag.as_str().to_string(),
            text: op.text,
        })
        .collect()
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_snapshot_mark_draft(snapshot_id: i64, label: String) -> FfiResult {
    let store = match open_snapshot_store() {
        Ok(s) => s,
        Err(e) => return FfiResult::err(e),
    };
    match store.mark_draft(snapshot_id, &label) {
        Ok(()) => FfiResult::ok("Draft label updated"),
        Err(e) => FfiResult::err(e),
    }
}

/// Restore a snapshot. Takes the document_path to verify the snapshot belongs
/// to the expected document — prevents cross-document restore if a stale
/// snapshot_id is passed.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_snapshot_restore(
    document_path: String,
    snapshot_id: i64,
    current_text: String,
) -> FfiSnapshotContent {
    if crate::sentinel::helpers::validate_path(&document_path).is_err() {
        return FfiSnapshotContent::err("Invalid document path");
    }
    let mut store = match open_snapshot_store() {
        Ok(s) => s,
        Err(e) => return FfiSnapshotContent::err(e),
    };
    // Verify snapshot belongs to this document
    match store.get_document_path(snapshot_id) {
        Ok(ref stored_path) if stored_path == &document_path => {}
        Ok(stored_path) => {
            return FfiSnapshotContent::err(format!(
                "snapshot {} belongs to '{}', not '{}'",
                snapshot_id, stored_path, document_path
            ));
        }
        Err(e) => return FfiSnapshotContent::err(e),
    }
    match store.restore(&document_path, snapshot_id, &current_text) {
        Ok(restored) => FfiSnapshotContent::ok(restored),
        Err(e) => FfiSnapshotContent::err(e),
    }
}
