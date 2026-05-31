// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{get_db_path, open_store};
use crate::ffi::types::{catch_ffi_panic, try_ffi};

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
