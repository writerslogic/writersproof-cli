// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI functions for witnessing start/stop/status.

use super::sentinel::get_sentinel;
use crate::ffi::types::{
    try_ffi, FfiPermissionState, FfiResult, FfiSentinelStatus, FfiWitnessingStatus,
};
use crate::RwLockRecover;

/// Start witnessing a specific file path.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_start_witnessing(path: String) -> FfiResult {
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
}

/// Stop witnessing a specific file path.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_stop_witnessing(path: String) -> FfiResult {
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
}

fn format_duration(total_secs: i64) -> String {
    crate::utils::format_duration_compact(total_secs)
}

/// Get current sentinel status.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_status() -> FfiSentinelStatus {
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
                temporal_binding_active: false,
            };
        }
    };

    let tracked = sentinel.tracked_files();

    let summary = crate::fingerprint::global::get_global_accumulator()
        .read_recover()
        .to_session_summary();

    let total_focus_ms: i64 = {
        let sessions_map = sentinel.sessions.read_recover();
        sessions_map
            .values()
            .map(|s| s.total_focus_duration().as_millis() as i64)
            .sum()
    };

    let has_nonce = sentinel.pending_challenge.read_recover().is_some();

    FfiSentinelStatus {
        running: sentinel.is_running(),
        tracked_file_count: tracked.len() as u32,
        tracked_files: tracked,
        uptime_secs: summary.duration_secs,
        keystroke_count: summary.keystroke_count,
        focus_duration: format_duration(total_focus_ms / 1000),
        permission_state: FfiPermissionState::Full,
        temporal_binding_active: has_nonce,
    }
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
        let raw = profile.metrics.edit_entropy / crate::ffi::helpers::ENTROPY_NORMALIZATION_FACTOR;
        if raw.is_finite() { raw } else { 0.0 }
    } else {
        0.0
    };

    // Use the best available signal: live cadence or stored forensics.
    // This prevents score drops when a session restarts (idle timeout,
    // focus loss) since stored evidence persists across sessions.
    let best_raw = store_score.max(cadence_score);
    let score = if best_raw >= MIN_MEANINGFUL_SCORE {
        crate::utils::Probability::clamp(best_raw - focus_penalty).get()
    } else {
        0.0
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
        words_per_minute: 0.0,
        ai_tools_detected: Vec::new(),
        capture_gaps: 0,
        evidence_confidence: "Full".into(),
        confidence_reason: None,
        evidence_maturity: 0.0,
        copy_count: 0,
        cut_count: 0,
        paste_count: 0,
        redo_count: 0,
        character_count: 0,
        navigation_count: 0,
        find_count: 0,
        save_count_semantic: 0,
        tab_count: 0,
        return_count: 0,
        scroll_event_count: 0,
        cursor_attention_score: 0.0,
        temporal_binding_active: false,
    }
}

/// Snapshot of session data extracted under the sessions read lock,
/// avoiding a full DocumentSession clone for the status poll.
struct SessionSnapshot {
    path: String,
    keystroke_count: u64,
    elapsed_secs: f64,
    change_count: u64,
    save_count: u64,
    event_confidence: f64,
    doc_has_focus: bool,
    total_focus_ms: i64,
    focus_switches: Vec<crate::sentinel::types::FocusSwitchRecord>,
    editing_ratio: f64,
    session_activity: String,
    total_deletions: u64,
    undo_count: u64,
    words_per_minute: f64,
    ai_tools_detected: Vec<String>,
    capture_gaps: u32,
    evidence_confidence: String,
    confidence_reason: Option<String>,
    copy_count: u64,
    cut_count: u64,
    paste_count: u64,
    redo_count: u64,
    character_count: u64,
    navigation_count: u64,
    find_count: u64,
    save_count_semantic: u64,
    tab_count: u64,
    return_count: u64,
    scroll_event_count: u64,
    scroll_attention: crate::sentinel::types::ScrollAttentionAccumulator,
}

/// Get live witnessing metrics for the first active session.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_witnessing_status() -> FfiWitnessingStatus {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) => s,
        None => return not_tracking(false),
    };

    let capture_active = sentinel.is_keystroke_capture_active();

    // Extract only the data we need under a single read lock, avoiding
    // clone of all DocumentSession objects (SYS-008 hot-path optimization).
    let current_path = sentinel.current_focus();
    let snapshot = {
        let sessions_map = sentinel.sessions.read_recover();

        #[cfg(debug_assertions)]
        {
            let session_paths: Vec<(&str, &str, u64)> = sessions_map
                .iter()
                .map(|(p, s)| (p.as_str(), s.app_bundle_id.as_str(), s.keystroke_count))
                .collect();
            crate::sentinel::trace!(
                "[STATUS] focus={:?} capture_active={} sessions={:?}",
                current_path,
                capture_active,
                session_paths
            );
        }

        // Find the best session: focused > targeted > cli.
        // When no document has focus and no targeted witnessing is active,
        // report not_tracking rather than showing a stale document.
        let focused_session = current_path
            .as_ref()
            .and_then(|p| sessions_map.get(p.as_str()));
        let targeted = sentinel.targeted_path();
        let targeted_session = targeted.as_ref()
            .and_then(|p| sessions_map.get(p.as_str()));
        // Report focus as true when either the AX probe resolved the document
        // OR the targeted session still has has_focus set (covers the 100-200ms
        // AX latency window during app switches, so paste detection works).
        let doc_has_focus = focused_session.is_some()
            || targeted_session.map(|s| s.has_focus).unwrap_or(false);
        let session = focused_session
            .or(targeted_session)
            .or_else(|| {
                sessions_map
                    .values()
                    .find(|s| s.app_bundle_id == "cli")
            });
        let session = match session {
            Some(s) => {
                crate::sentinel::trace!(
                    "[STATUS] showing session path={:?} keystrokes={}",
                    s.path,
                    s.total_keystrokes()
                );
                s
            }
            None => {
                crate::sentinel::trace!("[STATUS] no session found");
                return not_tracking(capture_active);
            }
        };

        // Extract all needed fields under the lock; avoid cloning the entire session.
        // focus_switches is cloned here because analyze_focus_patterns needs &[FocusSwitchRecord].
        SessionSnapshot {
            path: session.path.clone(),
            keystroke_count: session.keystroke_count,
            elapsed_secs: session.start_time.elapsed().unwrap_or_else(|e| {
                log::warn!("session start_time.elapsed() failed (clock went backward?): {e}");
                std::time::Duration::ZERO
            }).as_secs_f64(),
            change_count: u64::from(session.change_count),
            save_count: u64::from(session.save_count),
            event_confidence: session.average_event_confidence(),
            doc_has_focus,
            total_focus_ms: session.total_focus_ms,
            focus_switches: session.focus_switches.iter().cloned().collect(),
            editing_ratio: session.semantic_counts.editing_ratio(),
            session_activity: session
                .semantic_counts
                .session_activity_type()
                .map(|t| t.to_string())
                .unwrap_or_default(),
            total_deletions: session.semantic_counts.total_deletions(),
            undo_count: session.semantic_counts.undo,
            words_per_minute: session.recent_wpm(),
            ai_tools_detected: session
                .ai_tools_detected
                .iter()
                .map(|t| t.signing_id.clone())
                .collect(),
            capture_gaps: session.capture_gaps,
            evidence_confidence: session.evidence_confidence.to_string(),
            confidence_reason: session.confidence_reason.clone(),
            copy_count: session.semantic_counts.copy,
            cut_count: session.semantic_counts.cut,
            paste_count: session.semantic_counts.paste,
            redo_count: session.semantic_counts.redo,
            character_count: session.semantic_counts.characters,
            navigation_count: session.semantic_counts.navigation,
            find_count: session.semantic_counts.find,
            save_count_semantic: session.semantic_counts.save,
            tab_count: session.semantic_counts.tab,
            return_count: session.semantic_counts.r#return,
            scroll_event_count: session.scroll_attention.total_scroll_events,
            scroll_attention: session.scroll_attention.clone(),
        }
    }; // read lock released

    log::debug!(
        "witnessing: doc={} doc_keystrokes={} focus={:?}",
        snapshot.path,
        snapshot.keystroke_count,
        current_path
    );

    // Compute cursor attention score outside the lock
    let cursor_attention_score = crate::forensics::cursor_attention::analyze(
        &snapshot.scroll_attention,
    )
    .map(|ca| ca.composite_score)
    .unwrap_or(0.0);

    let host_paste_chars = sentinel.take_last_paste_chars();

    let cadence_score = sentinel.document_cadence_score(&snapshot.path);
    let maturity = crate::forensics::evidence_maturity(
        snapshot.keystroke_count,
        snapshot.total_focus_ms as f64 / 1000.0,
    );
    let mature_cadence = cadence_score * maturity;

    let focus = crate::forensics::analysis::analyze_focus_patterns(
        &snapshot.focus_switches,
        snapshot.total_focus_ms,
    );
    let focus_penalty = crate::forensics::compute_focus_penalty(&focus);

    let metrics = query_store_metrics(&snapshot.path, mature_cadence, focus_penalty);
    let has_nonce = sentinel.pending_challenge.read_recover().is_some();

    FfiWitnessingStatus {
        is_tracking: true,
        document_path: Some(snapshot.path),
        keystroke_count: snapshot.keystroke_count,
        elapsed_secs: snapshot.elapsed_secs,
        change_count: snapshot.change_count,
        save_count: snapshot.save_count,
        event_count: metrics.event_count,
        forensic_score: metrics.forensic_score,
        last_paste_chars: host_paste_chars,
        event_confidence: snapshot.event_confidence,
        document_has_focus: snapshot.doc_has_focus,
        keystroke_capture_active: capture_active,
        error_message: metrics.error,
        editing_ratio: snapshot.editing_ratio,
        session_activity: snapshot.session_activity,
        total_deletions: snapshot.total_deletions,
        undo_count: snapshot.undo_count,
        words_per_minute: snapshot.words_per_minute,
        ai_tools_detected: snapshot.ai_tools_detected,
        capture_gaps: snapshot.capture_gaps,
        evidence_confidence: snapshot.evidence_confidence,
        confidence_reason: snapshot.confidence_reason,
        evidence_maturity: maturity,
        copy_count: snapshot.copy_count,
        cut_count: snapshot.cut_count,
        paste_count: snapshot.paste_count,
        redo_count: snapshot.redo_count,
        character_count: snapshot.character_count,
        navigation_count: snapshot.navigation_count,
        find_count: snapshot.find_count,
        save_count_semantic: snapshot.save_count_semantic,
        tab_count: snapshot.tab_count,
        return_count: snapshot.return_count,
        scroll_event_count: snapshot.scroll_event_count,
        cursor_attention_score,
        temporal_binding_active: has_nonce,
    }
}
