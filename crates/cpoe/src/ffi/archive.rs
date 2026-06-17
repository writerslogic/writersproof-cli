// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{get_db_path, open_store};
use crate::ffi::types::{catch_ffi_panic, try_ffi, FfiErrResult};

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiArchiveResult {
    pub success: bool,
    pub error_message: Option<String>,
    pub archive_path: Option<String>,
    pub events_archived: u64,
    pub active_db_size_after: u64,
}

crate::ffi::types::impl_ffi_err!(FfiArchiveResult);

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiArchiveInfo {
    pub path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiArchiveListResult {
    pub success: bool,
    pub error_message: Option<String>,
    pub archives: Vec<FfiArchiveInfo>,
    pub active_db_size_bytes: u64,
    pub needs_archival: bool,
}

crate::ffi::types::impl_ffi_err!(FfiArchiveListResult);

/// Manually trigger archival of events older than the specified number of days.
/// If `age_days` is 0, defaults to 90 days.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_archive_old_events(age_days: u32) -> FfiArchiveResult {
    catch_ffi_panic!(@err FfiArchiveResult, {
    log::debug!("ffi_archive_old_events: age_days={}", age_days);
    let db_path = try_ffi!(get_db_path().ok_or("Database path not found"), FfiArchiveResult);
    let mut store = try_ffi!(open_store(), FfiArchiveResult);

    let age = if age_days == 0 { None } else { Some(age_days) };
    let result = try_ffi!(store.archive_old_events(&db_path, age), FfiArchiveResult);

    match result {
        Some(r) => FfiArchiveResult {
            success: true,
            error_message: None,
            archive_path: Some(r.archive_path.to_string_lossy().into_owned()),
            events_archived: r.events_archived,
            active_db_size_after: r.active_db_size_after,
        },
        None => FfiArchiveResult {
            success: true,
            error_message: None,
            archive_path: None,
            events_archived: 0,
            active_db_size_after: try_ffi!(store.db_size_bytes(), FfiArchiveResult),
        },
    }
    })
}

/// List all archive files and report active DB status.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_list_archives() -> FfiArchiveListResult {
    catch_ffi_panic!(@err FfiArchiveListResult, {
    log::debug!("ffi_list_archives");
    let db_path = try_ffi!(
        get_db_path().ok_or("Database path not found"),
        FfiArchiveListResult
    );
    let store = try_ffi!(open_store(), FfiArchiveListResult);

    let archive_paths = try_ffi!(
        crate::store::SecureStore::list_archives(&db_path),
        FfiArchiveListResult
    );

    let archives: Vec<FfiArchiveInfo> = archive_paths
        .iter()
        .map(|p| {
            let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            FfiArchiveInfo {
                path: p.to_string_lossy().into_owned(),
                size_bytes: size,
            }
        })
        .collect();

    let active_size = try_ffi!(store.db_size_bytes(), FfiArchiveListResult);
    let needs = try_ffi!(store.needs_archival(), FfiArchiveListResult);

    FfiArchiveListResult {
        success: true,
        error_message: None,
        archives,
        active_db_size_bytes: active_size,
        needs_archival: needs,
    }
    })
}

/// Query events for a file path across both active and archive databases.
/// Returns events within the given nanosecond timestamp range.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_query_events_spanning(path: String, start_ns: i64, end_ns: i64) -> FfiSpanningQueryResult {
    catch_ffi_panic!(@err FfiSpanningQueryResult, {
    log::debug!("ffi_query_events_spanning: path={}, start_ns={}, end_ns={}", path, start_ns, end_ns);
    let db_path = try_ffi!(
        get_db_path().ok_or("Database path not found"),
        FfiSpanningQueryResult
    );
    let canonical = try_ffi!(
        crate::ffi::helpers::validate_path_str(&path),
        FfiSpanningQueryResult
    );
    let store = try_ffi!(open_store(), FfiSpanningQueryResult);

    let events = try_ffi!(
        store.query_spanning(&db_path, &canonical, start_ns, end_ns),
        FfiSpanningQueryResult
    );

    FfiSpanningQueryResult {
        success: true,
        error_message: None,
        event_count: events.len() as u64,
        earliest_timestamp_ns: events.first().map(|e| e.timestamp_ns),
        latest_timestamp_ns: events.last().map(|e| e.timestamp_ns),
    }
    })
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSpanningQueryResult {
    pub success: bool,
    pub error_message: Option<String>,
    pub event_count: u64,
    pub earliest_timestamp_ns: Option<i64>,
    pub latest_timestamp_ns: Option<i64>,
}

crate::ffi::types::impl_ffi_err!(FfiSpanningQueryResult);

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiRetentionResult {
    pub success: bool,
    pub error_message: Option<String>,
    pub events_pruned: u64,
}

crate::ffi::types::impl_ffi_err!(FfiRetentionResult);

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDataExportResult {
    pub success: bool,
    pub error_message: Option<String>,
    pub event_count: u64,
    pub export_path: Option<String>,
}

crate::ffi::types::impl_ffi_err!(FfiDataExportResult);

/// Enforce data retention policy: prune event payloads older than `retention_days`.
/// Returns the number of events pruned. Minimum 1 day.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_enforce_retention(retention_days: u32) -> FfiRetentionResult {
    catch_ffi_panic!(@err FfiRetentionResult, {
    log::debug!("ffi_enforce_retention: retention_days={}", retention_days);
    let store = try_ffi!(open_store(), FfiRetentionResult);
    let count = try_ffi!(store.enforce_retention(retention_days), FfiRetentionResult);
    FfiRetentionResult {
        success: true,
        error_message: None,
        events_pruned: count as u64,
    }
    })
}

/// Export all events for a device identity (GDPR Article 15 DSAR).
/// `device_id_hex` is a 32-character hex string (16 bytes).
/// Writes JSON to `{data_dir}/dsar_export.json` and returns the path.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_all_events_for_identity(device_id_hex: String) -> FfiDataExportResult {
    catch_ffi_panic!(@err FfiDataExportResult, {
    log::debug!("ffi_export_all_events_for_identity");
    let id_bytes = try_ffi!(
        hex::decode(&device_id_hex).map_err(|e| format!("Invalid device ID hex: {e}")),
        FfiDataExportResult
    );
    if id_bytes.len() != 16 {
        return FfiDataExportResult::ffi_err(format!(
            "Device ID must be 16 bytes (32 hex chars), got {}",
            id_bytes.len()
        ));
    }
    let mut device_id = [0u8; 16];
    device_id.copy_from_slice(&id_bytes);

    let store = try_ffi!(open_store(), FfiDataExportResult);
    let events = try_ffi!(
        store.export_all_events_for_identity(&device_id),
        FfiDataExportResult
    );

    let data_dir = try_ffi!(
        crate::ffi::helpers::get_data_dir().ok_or("Data directory not found"),
        FfiDataExportResult
    );
    let export_path = data_dir.join("dsar_export.json");
    // SecureEvent doesn't derive Serialize; emit all fields with hex-encoded byte arrays.
    let summaries: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "device_id": hex::encode(e.device_id),
                "machine_id": e.machine_id,
                "timestamp_ns": e.timestamp_ns,
                "file_path": e.file_path,
                "content_hash": hex::encode(e.content_hash),
                "file_size": e.file_size,
                "size_delta": e.size_delta,
                "previous_hash": hex::encode(e.previous_hash),
                "event_hash": hex::encode(e.event_hash),
                "context_type": e.context_type,
                "context_note": e.context_note,
                "vdf_input": e.vdf_input.map(hex::encode),
                "vdf_output": e.vdf_output.map(hex::encode),
                "vdf_iterations": e.vdf_iterations,
                "forensic_score": e.forensic_score,
                "is_paste": e.is_paste,
                "hardware_counter": e.hardware_counter,
                "input_method": e.input_method,
                "challenge_nonce": e.challenge_nonce,
                "hw_cosign_chain_index": e.hw_cosign_chain_index,
                "hw_cosign_entropy_bytes": e.hw_cosign_entropy_bytes,
                "semantic_summary": e.semantic_summary,
            })
        })
        .collect();
    let json = try_ffi!(
        serde_json::to_vec_pretty(&summaries)
            .map_err(|e| format!("JSON serialization failed: {e}")),
        FfiDataExportResult
    );
    try_ffi!(
        std::fs::write(&export_path, &json).map_err(|e| format!("Write failed: {e}")),
        FfiDataExportResult
    );

    FfiDataExportResult {
        success: true,
        error_message: None,
        event_count: events.len() as u64,
        export_path: Some(export_path.to_string_lossy().into_owned()),
    }
    })
}

/// Return the current device identity as a 32-character hex string.
/// Used by the Swift GDPR UI to call `ffi_export_all_events_for_identity`.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_device_id_hex() -> String {
    let (id, _) = crate::ffi::helpers::device_identity();
    hex::encode(id)
}
