// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Velocity analysis and session detection.

use super::types::{
    EventData, SegmentVelocityProfile, SessionStats, SortedEvents, VelocityMetrics,
    DEFAULT_SESSION_GAP_SEC, THRESHOLD_HIGH_VELOCITY_BPS,
};

/// Maximum inter-event delta in seconds before treating as a session gap.
const MAX_DELTA_SEC: f64 = 60.0;

/// Upper bound of plausible human typing speed in bytes per second.
const HUMAN_MAX_BYTES_PER_SEC: f64 = 50.0;

/// Analyze edit velocity patterns (bytes/sec).
pub fn analyze_velocity(sorted: SortedEvents<'_>) -> VelocityMetrics {
    let mut metrics = VelocityMetrics::default();

    if sorted.len() < 2 {
        return metrics;
    }

    let mut velocities = Vec::with_capacity(sorted.len() - 1);
    let mut high_velocity_bursts = 0;
    let mut autocomplete_chars: i64 = 0;

    for window in sorted.windows(2) {
        let delta_ns = window[1]
            .timestamp_ns
            .saturating_sub(window[0].timestamp_ns);
        let delta_sec = crate::utils::ns_to_secs(delta_ns);

        if delta_sec > 0.0 && delta_sec < MAX_DELTA_SEC {
            let bytes_delta = window[1].size_delta.abs() as f64;
            let bps = bytes_delta / delta_sec;
            velocities.push(bps);

            if bps > THRESHOLD_HIGH_VELOCITY_BPS {
                high_velocity_bursts += 1;

                if bps > HUMAN_MAX_BYTES_PER_SEC {
                    let excess = (bps - HUMAN_MAX_BYTES_PER_SEC) * delta_sec;
                    if excess.is_finite() && excess < i64::MAX as f64 {
                        autocomplete_chars += excess as i64;
                    }
                }
            }
        }
    }

    if !velocities.is_empty() {
        metrics.mean_bps = velocities.iter().sum::<f64>() / velocities.len() as f64;
        metrics.max_bps = velocities.iter().cloned().fold(0.0, f64::max);
    }

    metrics.high_velocity_bursts = high_velocity_bursts;
    metrics.autocomplete_chars = autocomplete_chars;

    // Sanitize non-finite values
    if !metrics.mean_bps.is_finite() {
        metrics.mean_bps = 0.0;
    }
    if !metrics.max_bps.is_finite() {
        metrics.max_bps = 0.0;
    }

    metrics
}

/// Count sessions in pre-sorted events without cloning.
///
/// # Panics
/// Debug-asserts that `sorted_events` is sorted by `timestamp_ns`.
pub fn count_sessions_sorted(sorted_events: &[EventData], gap_threshold_sec: f64) -> usize {
    if sorted_events.is_empty() {
        return 0;
    }
    debug_assert!(
        sorted_events
            .windows(2)
            .all(|w| w[0].timestamp_ns <= w[1].timestamp_ns),
        "count_sessions_sorted requires pre-sorted events"
    );
    let mut count = 1;
    for i in 1..sorted_events.len() {
        let delta_ns = sorted_events[i]
            .timestamp_ns
            .saturating_sub(sorted_events[i - 1].timestamp_ns);
        if crate::utils::ns_to_secs(delta_ns) > gap_threshold_sec {
            count += 1;
        }
    }
    count
}

/// Split events into session slices using `gap_threshold_sec`.
///
/// Returns borrowed slices into `sorted` so callers can iterate session
/// contents without cloning. A session is a maximal run of events whose
/// consecutive inter-event deltas are all `<= gap_threshold_sec`.
pub fn detect_sessions<'a>(
    sorted: SortedEvents<'a>,
    gap_threshold_sec: f64,
) -> Vec<&'a [EventData]> {
    if sorted.is_empty() {
        return Vec::new();
    }

    let slice: &'a [EventData] = sorted.as_slice();
    let mut sessions: Vec<&'a [EventData]> = Vec::new();
    let mut start = 0usize;
    for i in 1..slice.len() {
        let delta_ns = slice[i]
            .timestamp_ns
            .saturating_sub(slice[i - 1].timestamp_ns);
        if crate::utils::ns_to_secs(delta_ns) > gap_threshold_sec {
            sessions.push(&slice[start..i]);
            start = i;
        }
    }
    sessions.push(&slice[start..]);
    sessions
}

/// Compute aggregate session statistics.
pub fn compute_session_stats(sorted: SortedEvents<'_>) -> SessionStats {
    let mut stats = SessionStats::default();

    if sorted.is_empty() {
        return stats;
    }

    let sessions = detect_sessions(sorted, DEFAULT_SESSION_GAP_SEC);
    stats.session_count = sessions.len();

    let mut total_duration = 0.0;
    for session in &sessions {
        if let (Some(first), Some(last)) = (session.first(), session.last()) {
            let dur_ns = last.timestamp_ns.saturating_sub(first.timestamp_ns).max(0);
            let dur_sec = crate::utils::ns_to_secs(dur_ns);
            if dur_sec.is_finite() {
                total_duration += dur_sec;
            }
        }
    }

    stats.total_editing_time_sec = total_duration;
    if stats.session_count > 0 {
        stats.avg_session_duration_sec = total_duration / stats.session_count as f64;
    }

    let first = sessions
        .first()
        .and_then(|s| s.first())
        .map_or(0, |e| e.timestamp_ns);
    let last = sessions
        .last()
        .and_then(|s| s.last())
        .map_or(0, |e| e.timestamp_ns);
    stats.time_span_sec = crate::utils::ns_to_secs(last.saturating_sub(first));

    stats
}

/// Classify whether a bundle-relative path contains prose content.
///
/// Prose paths: any file under `Files/Data/` or `Files/Docs/` with a text
/// extension (`.rtf`, `.txt`, `.md`).
/// Non-prose: synopsis files, metadata XML, search indexes, binder state,
/// and anything outside the content subtree.
fn is_prose_segment(rel_path: &str) -> bool {
    let in_content = rel_path.contains("Files/Data/") || rel_path.contains("Files/Docs/");
    if !in_content {
        return false;
    }
    let lower = rel_path.to_ascii_lowercase();
    lower.ends_with(".rtf") || lower.ends_with(".txt") || lower.ends_with(".md")
}

/// Compute per-segment velocity profiles from a map of bundle-relative paths to
/// their [`EventData`] slices.
///
/// Each entry in `segments` is `(rel_path, events)` where events are pre-sorted
/// by `timestamp_ns`.  Non-prose segments are included but flagged `is_prose: false`
/// so callers can exclude them from aggregate behavioral scores.
pub fn analyze_segment_velocity(segments: &[(&str, &[EventData])]) -> Vec<SegmentVelocityProfile> {
    segments
        .iter()
        .map(|(rel_path, events)| {
            let prose = is_prose_segment(rel_path);
            let keystroke_count = events.len() as u64;

            if events.len() < 2 {
                return SegmentVelocityProfile {
                    rel_path: rel_path.to_string(),
                    is_prose: prose,
                    mean_bps: 0.0,
                    max_bps: 0.0,
                    keystroke_count,
                    high_velocity_bursts: 0,
                };
            }

            let mut velocities = Vec::with_capacity(events.len() - 1);
            let mut high_bursts = 0usize;

            for w in events.windows(2) {
                let delta_ns = w[1].timestamp_ns.saturating_sub(w[0].timestamp_ns);
                let delta_sec = crate::utils::ns_to_secs(delta_ns);
                if delta_sec > 0.0 && delta_sec < MAX_DELTA_SEC {
                    let bps = w[1].size_delta.unsigned_abs() as f64 / delta_sec;
                    velocities.push(bps);
                    if bps > THRESHOLD_HIGH_VELOCITY_BPS {
                        high_bursts += 1;
                    }
                }
            }

            let mean_bps = if velocities.is_empty() {
                0.0
            } else {
                let s: f64 = velocities.iter().sum();
                let m = s / velocities.len() as f64;
                if m.is_finite() { m } else { 0.0 }
            };
            let max_bps = velocities
                .iter()
                .cloned()
                .fold(0.0_f64, f64::max)
                .max(0.0);
            let max_bps = if max_bps.is_finite() { max_bps } else { 0.0 };

            SegmentVelocityProfile {
                rel_path: rel_path.to_string(),
                is_prose: prose,
                mean_bps,
                max_bps,
                keystroke_count,
                high_velocity_bursts: high_bursts,
            }
        })
        .collect()
}
