// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI functions for witnessing start/stop/status.

use super::sentinel::get_sentinel;
use crate::ffi::types::{
    catch_ffi_panic, try_ffi, FfiPermissionState, FfiResult, FfiSentinelStatus, FfiWitnessingStatus,
};
use crate::{MutexRecover, RwLockRecover};

/// Start witnessing a specific file path.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_start_witnessing(path: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_sentinel_start_witnessing: path={}", path);
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) => s,
        None => {
            return FfiResult::err(
                "Sentinel not initialized — call ffi_sentinel_start() first".to_string(),
            );
        }
    };

    if !sentinel.is_running() {
        return FfiResult::err("Sentinel not running".to_string());
    }

    // AUD-084: Validate path to prevent traversal attacks (canonicalize to resolve symlinks)
    let validated_path = try_ffi!(
        crate::sentinel::helpers::validate_path(&path)
            .map_err(|e| format!("Invalid path: {e}")),
        FfiResult
    );

    match sentinel.start_witnessing(&validated_path) {
        Ok(()) => FfiResult::ok(format!("Now witnessing: {}", validated_path.display())),
        Err((_code, msg)) => FfiResult::err(msg),
    }
    })
}

/// Stop witnessing a specific file path.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_stop_witnessing(path: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_sentinel_stop_witnessing: path={}", path);
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) => s,
        None => {
            return FfiResult::err("Sentinel not initialized".to_string());
        }
    };

    // H-025: Validate path before passing to stop_witnessing (same as start_witnessing).
    let validated_path = try_ffi!(
        crate::sentinel::helpers::validate_path(&path)
            .map_err(|e| format!("Invalid path: {e}")),
        FfiResult
    );

    match sentinel.stop_witnessing(&validated_path) {
        Ok(()) => FfiResult::ok(format!("Stopped witnessing: {}", validated_path.display())),
        Err((_code, msg)) => FfiResult::err(msg),
    }
    })
}

fn format_duration(total_secs: i64) -> String {
    if total_secs >= 3600 {
        format!(
            "{}h {}m {}s",
            total_secs / 3600,
            (total_secs % 3600) / 60,
            total_secs % 60
        )
    } else if total_secs >= 60 {
        format!("{}m {}s", total_secs / 60, total_secs % 60)
    } else {
        format!("{}s", total_secs)
    }
}

/// Get current sentinel status.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_status() -> FfiSentinelStatus {
    catch_ffi_panic!(FfiSentinelStatus {
        running: false,
        tracked_file_count: 0,
        tracked_files: vec![],
        uptime_secs: 0,
        keystroke_count: 0,
        focus_duration: String::new(),
        permission_state: FfiPermissionState::Unknown,
    }, {
    log::debug!("ffi_sentinel_status called");
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) => s,
        None => {
            return FfiSentinelStatus {
                running: false,
                tracked_file_count: 0,
                tracked_files: vec![],
                uptime_secs: 0,
                keystroke_count: 0,
                focus_duration: String::new(),
                permission_state: FfiPermissionState::Unknown,
            };
        }
    };

    let tracked = sentinel.tracked_files();

    let summary = sentinel
        .activity_accumulator
        .read_recover()
        .to_session_summary();

    let total_focus_ms: i64 = sentinel
        .sessions()
        .iter()
        .map(|s| s.total_focus_duration().as_millis() as i64)
        .sum();

    let permission_state = {
        use crate::sentinel::permission_monitor::PermissionState;
        match *sentinel.permission_state.lock_recover() {
            PermissionState::Full => FfiPermissionState::Full,
            PermissionState::KeystrokeDegraded => FfiPermissionState::KeystrokeDegraded,
            PermissionState::Revoked => FfiPermissionState::Revoked,
        }
    };

    FfiSentinelStatus {
        running: sentinel.is_running(),
        tracked_file_count: tracked.len() as u32,
        tracked_files: tracked,
        uptime_secs: summary.duration_secs,
        keystroke_count: summary.keystroke_count,
        focus_duration: format_duration(total_focus_ms / 1000),
        permission_state,
    }
    })
}

/// Return the current permission state for keystroke capture.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_permission_state() -> FfiPermissionState {
    catch_ffi_panic!(FfiPermissionState::Unknown, {
    log::debug!("ffi_sentinel_permission_state called");
    use crate::sentinel::permission_monitor::PermissionState;
    match get_sentinel() {
        Some(s) => match *s.permission_state.lock_recover() {
            PermissionState::Full => FfiPermissionState::Full,
            PermissionState::KeystrokeDegraded => FfiPermissionState::KeystrokeDegraded,
            PermissionState::Revoked => FfiPermissionState::Revoked,
        },
        None => FfiPermissionState::Unknown,
    }
    })
}

/// Fallback score from cadence when store is unavailable or has insufficient data.
fn fallback_score(cadence_score: f64, focus_penalty: f64) -> f64 {
    if cadence_score > 0.0 {
        crate::utils::Probability::clamp(cadence_score - focus_penalty).get()
    } else {
        0.0
    }
}

struct StoreMetrics {
    event_count: u64,
    forensic_score: f64,
    error: Option<String>,
}

fn query_store_metrics(path: &str, cadence_score: f64, focus_penalty: f64) -> StoreMetrics {
    const MIN_MEANINGFUL_SCORE: f64 = 0.01;

    let store = match crate::ffi::helpers::open_store() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("failed to open store for witnessing status: {e}");
            return StoreMetrics {
                event_count: 0,
                forensic_score: fallback_score(cadence_score, focus_penalty),
                error: Some(format!("store unavailable: {e}")),
            };
        }
    };

    let events = match store.get_events_for_file(path) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("failed to load events for {path}: {e}");
            return StoreMetrics {
                event_count: 0,
                forensic_score: fallback_score(cadence_score, focus_penalty),
                error: Some(format!("event query failed: {e}")),
            };
        }
    };

    let count = events.len() as u64;
    let store_score = if events.len() >= 2 {
        let profile = crate::forensics::ForensicEngine::evaluate_authorship(path, &events);
        profile.metrics.edit_entropy / crate::ffi::helpers::ENTROPY_NORMALIZATION_FACTOR
    } else {
        0.0
    };

    let score = if store_score >= MIN_MEANINGFUL_SCORE {
        crate::utils::Probability::clamp(store_score - focus_penalty).get()
    } else {
        fallback_score(cadence_score, focus_penalty)
    };

    StoreMetrics {
        event_count: count,
        forensic_score: score,
        error: None,
    }
}

fn not_tracking(capture_active: bool) -> FfiWitnessingStatus {
    FfiWitnessingStatus {
        is_tracking: false,
        document_path: None,
        keystroke_count: 0,
        elapsed_secs: 0.0,
        change_count: 0,
        save_count: 0,
        event_count: 0,
        forensic_score: 0.0,
        last_paste_chars: 0,
        event_confidence: 1.0,
        document_has_focus: false,
        keystroke_capture_active: capture_active,
        error_message: None,
        editing_ratio: 0.0,
        session_activity: String::new(),
        total_deletions: 0,
        undo_count: 0,
    }
}

/// Get live witnessing metrics for the first active session.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_witnessing_status() -> FfiWitnessingStatus {
    catch_ffi_panic!(not_tracking(false), {
    log::debug!("ffi_sentinel_witnessing_status called");
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) => s,
        None => return not_tracking(false),
    };

    let capture_active = sentinel.is_keystroke_capture_active();

    // Show the most relevant session:
    // 1. The currently focused document (if it has a session)
    // 2. A manually-tracked document (started via UI, has app_bundle_id = "cli")
    // 3. Any active session as fallback
    let current_path = sentinel.current_focus();
    let sessions = sentinel.sessions();
    let session_paths: Vec<(&str, &str, u64)> = sessions
        .iter()
        .map(|s| (s.path.as_str(), s.app_bundle_id.as_str(), s.keystroke_count))
        .collect();
    log::debug!(
        "[STATUS] focus={:?} capture_active={} session_count={} sessions={:?}",
        current_path,
        capture_active,
        session_paths.len(),
        session_paths
    );
    let focused_session = current_path
        .as_ref()
        .and_then(|p| sessions.iter().find(|s| &s.path == p));
    let doc_has_focus = focused_session.is_some();
    log::debug!(
        "[STATUS] focused_session_found={} current_focus={:?}",
        doc_has_focus,
        current_path
    );
    let session = focused_session.or_else(|| {
        sessions
            .iter()
            .find(|s| s.app_bundle_id == "cli")
            .or_else(|| sessions.iter().max_by_key(|s| s.total_keystrokes()))
    });
    let session = match session {
        Some(s) => {
            log::debug!(
                "[STATUS] showing session path={:?} keystrokes={} has_focus={}",
                s.path,
                s.total_keystrokes(),
                s.has_focus
            );
            s
        }
        None => {
            log::debug!("[STATUS] no session found, returning not_tracking");
            return not_tracking(capture_active);
        }
    };

    let keystroke_count = session.total_keystrokes();
    log::debug!(
        "witnessing: doc={} doc_keystrokes={} focus={:?}",
        session.path,
        keystroke_count,
        sentinel.current_focus()
    );

    let elapsed_secs = session
        .start_time
        .elapsed()
        .unwrap_or_default()
        .as_secs_f64();

    let host_paste_chars = sentinel.take_last_paste_chars();

    let cadence_score = sentinel.document_cadence_score(&session.path);

    let focus = crate::forensics::analysis::analyze_focus_patterns(
        &Vec::from(session.focus_switches.clone()),
        session.total_focus_ms,
    );
    let focus_penalty = crate::forensics::compute_focus_penalty(&focus);

    let metrics = query_store_metrics(&session.path, cadence_score, focus_penalty);

    let last_paste_chars = host_paste_chars;

    FfiWitnessingStatus {
        is_tracking: true,
        document_path: Some(session.path.clone()),
        keystroke_count,
        elapsed_secs,
        change_count: u64::from(session.change_count),
        save_count: u64::from(session.save_count),
        event_count: metrics.event_count,
        forensic_score: metrics.forensic_score,
        last_paste_chars,
        event_confidence: session.average_event_confidence(),
        document_has_focus: doc_has_focus,
        keystroke_capture_active: capture_active,
        error_message: metrics.error,
        editing_ratio: session.semantic_counts.editing_ratio(),
        session_activity: session
            .semantic_counts
            .session_activity_type()
            .map(|t| t.to_string())
            .unwrap_or_default(),
        total_deletions: session.semantic_counts.total_deletions(),
        undo_count: session.semantic_counts.undo,
    }
    })
}
