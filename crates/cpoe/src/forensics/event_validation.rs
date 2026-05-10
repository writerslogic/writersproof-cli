// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Per-keystroke multi-layer validation for CGEventTap hardening.
//!
//! Each keystroke is treated as a probabilistic signal and scored against
//! multiple independent checks. The resulting confidence value indicates
//! how likely the event originated from genuine human input.

use std::collections::VecDeque;

use crate::utils::finite_or;
use crate::utils::stats::mean_and_std_dev;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum plausible inter-key interval (10 ms).
const MIN_HUMAN_IKI_NS: i64 = 10_000_000;

/// Number of recent events used for coefficient-of-variation analysis.
const ROBOTIC_CV_WINDOW: usize = 20;

/// CV below this threshold indicates robotic periodicity.
const ROBOTIC_CV_LIMIT: f64 = 0.05;

/// Maximum tolerable forward jump between consecutive timestamps (1 s).
const CLOCK_JUMP_LIMIT_NS: i64 = 1_000_000_000;

/// Window for burst detection (1 s).
const BURST_WINDOW_NS: i64 = 1_000_000_000;

/// Maximum keys allowed within [`BURST_WINDOW_NS`].
const BURST_MAX_KEYS: usize = 15;

/// Minimum Shannon entropy (bits) over the recent keycode window.
const UNIFORM_KEYCODE_ENTROPY_MIN: f64 = 2.0;

/// IKI below which a large zone jump is suspicious (50 ms).
const ZONE_RAPID_IKI_NS: i64 = 50_000_000;

/// Minimum zone distance that counts as a large jump.
const ZONE_DISTANCE_THRESHOLD: i8 = 5;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Boolean flags indicating which validation checks failed.
#[derive(Debug, Clone, Default)]
pub struct EventValidationFlags {
    pub pid_mismatch: bool,
    pub impossible_iki: bool,
    pub robotic_periodicity: bool,
    pub clock_discontinuity: bool,
    pub focus_inconsistent: bool,
    pub burst_superhuman: bool,
    pub uniform_keycode: bool,
    pub impossible_zone_transition: bool,
}

/// Validation outcome for a single keystroke event.
#[derive(Debug, Clone)]
pub struct EventValidationResult {
    pub confidence: f64,
    pub flags: EventValidationFlags,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Per-document rolling state used by [`validate_keystroke_event`].
#[derive(Debug, Clone)]
pub struct EventValidationState {
    pub recent_timestamps: VecDeque<i64>,
    pub recent_keycodes: VecDeque<u16>,
    pub recent_zones: VecDeque<u8>,
    pub last_timestamp_ns: i64,
    pub confidence_sum: f64,
    /// Kahan compensation variable for `confidence_sum` accumulation.
    pub confidence_compensation: f64,
    pub confidence_count: u64,
}

impl Default for EventValidationState {
    fn default() -> Self {
        Self {
            recent_timestamps: VecDeque::with_capacity(ROBOTIC_CV_WINDOW),
            recent_keycodes: VecDeque::with_capacity(ROBOTIC_CV_WINDOW),
            recent_zones: VecDeque::with_capacity(ROBOTIC_CV_WINDOW),
            last_timestamp_ns: 0,
            confidence_sum: 0.0,
            confidence_compensation: 0.0,
            confidence_count: 0,
        }
    }
}

impl EventValidationState {
    /// Running average confidence across all validated events.
    /// Returns 1.0 when no events have been scored yet.
    pub fn average_confidence(&self) -> f64 {
        if self.confidence_count == 0 {
            1.0
        } else {
            self.confidence_sum / self.confidence_count as f64
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Coefficient of variation (std-dev / mean) for a slice of nanosecond values.
/// Returns [`f64::MAX`] when the mean is zero to avoid division by zero.
pub fn compute_cv(values: &[i64]) -> f64 {
    if values.is_empty() {
        return f64::MAX;
    }
    let f64_values: Vec<f64> = values.iter().map(|&v| v as f64).collect();
    let (mean, std) = mean_and_std_dev(&f64_values);
    if mean.abs() < f64::EPSILON {
        return f64::MAX;
    }
    finite_or(std / mean, 0.0)
}

/// Shannon entropy (bits) of the keycode distribution in the window.
///
/// Uses stack-allocated sort + run-length counting instead of a heap-allocated
/// HashMap, since the window is small (ROBOTIC_CV_WINDOW = 20). This keeps
/// the entire operation within L1 cache on the CGEventTap hot path.
pub fn compute_keycode_entropy(keycodes: &VecDeque<u16>) -> f64 {
    let len = keycodes.len();
    if len == 0 {
        return 0.0;
    }
    // Copy to a stack-allocated buffer, sort, and count contiguous runs.
    let mut buf = [0u16; 64]; // ROBOTIC_CV_WINDOW is 20; 64 is generous headroom.
    let n = len.min(buf.len());
    for (i, &k) in keycodes.iter().take(n).enumerate() {
        buf[i] = k;
    }
    buf[..n].sort_unstable();

    let n_f = n as f64;
    let mut entropy = 0.0f64;
    let mut run_start = 0;
    while run_start < n {
        let mut run_end = run_start + 1;
        while run_end < n && buf[run_end] == buf[run_start] {
            run_end += 1;
        }
        let p = (run_end - run_start) as f64 / n_f;
        entropy -= p * p.log2();
        run_start = run_end;
    }
    entropy
}

// ---------------------------------------------------------------------------
// Core validation
// ---------------------------------------------------------------------------

/// Score a single keystroke event against multiple independent checks.
///
/// The function mutates `state` to maintain rolling windows and returns the
/// per-event confidence together with the flags that fired.
#[allow(clippy::too_many_arguments)]
pub fn validate_keystroke_event(
    timestamp_ns: i64,
    keycode: u16,
    zone: u8,
    source_pid: i64,
    _frontmost_pid: Option<u32>,
    session_has_focus: bool,
    state: &mut EventValidationState,
) -> EventValidationResult {
    let mut confidence = 1.0_f64;
    let mut flags = EventValidationFlags::default();

    let iki = if state.last_timestamp_ns > 0 {
        timestamp_ns - state.last_timestamp_ns
    } else {
        i64::MAX
    };

    // --- pid mismatch ---
    // Injected/synthetic events have pid 0; real keystrokes have a non-zero source pid.
    // Negative PIDs indicate pre-verified tap sources (e.g., CGEventTap) and are not penalized.
    if source_pid == 0 {
        flags.pid_mismatch = true;
        confidence -= 0.40;
    }

    // --- impossible IKI ---
    if state.last_timestamp_ns > 0 && iki < MIN_HUMAN_IKI_NS {
        flags.impossible_iki = true;
        confidence -= 0.50;
    }

    // --- clock discontinuity ---
    if state.last_timestamp_ns > 0
        && (timestamp_ns < state.last_timestamp_ns || iki > CLOCK_JUMP_LIMIT_NS)
    {
        flags.clock_discontinuity = true;
        confidence -= 0.30;
    }

    // --- focus inconsistency ---
    if !session_has_focus {
        flags.focus_inconsistent = true;
        confidence -= 0.20;
    }

    // --- burst detection ---
    // Filter out non-monotonic timestamps to avoid underflow bias.
    let burst_count = state
        .recent_timestamps
        .iter()
        .filter(|&&ts| ts <= timestamp_ns)
        .filter(|&&ts| (timestamp_ns - ts) <= BURST_WINDOW_NS)
        .count();
    if burst_count > BURST_MAX_KEYS {
        flags.burst_superhuman = true;
        confidence -= 0.25;
    }

    // --- robotic periodicity ---
    if state.recent_timestamps.len() >= ROBOTIC_CV_WINDOW {
        let ikis: Vec<i64> = state
            .recent_timestamps
            .iter()
            .zip(state.recent_timestamps.iter().skip(1))
            .map(|(&a, &b)| b - a)
            .filter(|&iki| iki > 0)
            .collect();
        if !ikis.is_empty() && compute_cv(&ikis) < ROBOTIC_CV_LIMIT {
            flags.robotic_periodicity = true;
            confidence -= 0.30;
        }
    }

    // --- uniform keycode distribution ---
    if state.recent_keycodes.len() >= ROBOTIC_CV_WINDOW
        && compute_keycode_entropy(&state.recent_keycodes) < UNIFORM_KEYCODE_ENTROPY_MIN
    {
        flags.uniform_keycode = true;
        confidence -= 0.15;
    }

    // --- impossible zone transition ---
    if let Some(&last_zone) = state.recent_zones.back() {
        let zone_dist = (zone as i8 - last_zone as i8).abs();
        if zone_dist >= ZONE_DISTANCE_THRESHOLD && iki < ZONE_RAPID_IKI_NS {
            flags.impossible_zone_transition = true;
            confidence -= 0.15;
        }
    }

    // Clamp to [0.0, 1.0].
    confidence = crate::utils::Probability::clamp(confidence).get();

    // --- update rolling state ---
    if state.recent_timestamps.len() >= ROBOTIC_CV_WINDOW {
        state.recent_timestamps.pop_front();
    }
    state.recent_timestamps.push_back(timestamp_ns);

    if state.recent_keycodes.len() >= ROBOTIC_CV_WINDOW {
        state.recent_keycodes.pop_front();
    }
    state.recent_keycodes.push_back(keycode);

    if state.recent_zones.len() >= ROBOTIC_CV_WINDOW {
        state.recent_zones.pop_front();
    }
    state.recent_zones.push_back(zone);

    state.last_timestamp_ns = timestamp_ns;
    // Kahan compensated summation to avoid f64 drift over millions of events
    let y = confidence - state.confidence_compensation;
    let t = state.confidence_sum + y;
    state.confidence_compensation = (t - state.confidence_sum) - y;
    state.confidence_sum = t;
    state.confidence_count += 1;

    EventValidationResult { confidence, flags }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> EventValidationState {
        EventValidationState::default()
    }

    #[test]
    fn test_normal_typing_high_confidence() {
        let mut state = make_state();
        // Simulate realistic human typing at ~80 WPM (roughly 150 ms IKI)
        // with natural variance. Use a non-zero source_pid (real keystroke).
        let base = 1_000_000_000_i64; // 1 s
        let intervals = [
            148, 162, 134, 155, 170, 143, 160, 138, 152, 167, 141, 158, 145, 163, 137, 156, 149,
            161, 144, 153,
        ];
        let mut ts = base;
        let mut last_confidence = 1.0;
        for (i, &ms) in intervals.iter().enumerate() {
            ts += ms * 1_000_000; // ms -> ns
            let keycode = (i as u16 % 26) + 4; // spread of keycodes
            let zone = (i as u8 % 4) + 1; // modest zone changes
            let r = validate_keystroke_event(ts, keycode, zone, 1234, None, true, &mut state);
            last_confidence = r.confidence;
        }
        assert!(
            last_confidence > 0.8,
            "normal typing should score > 0.8, got {last_confidence}"
        );
    }

    #[test]
    fn test_impossible_iki_penalty() {
        let mut state = make_state();
        let base = 1_000_000_000_i64;
        // First event (clean slate). Use non-zero source_pid (real keystroke).
        let r1 = validate_keystroke_event(base, 10, 1, 1234, None, true, &mut state);
        assert!(r1.confidence > 0.9);
        // Second event only 1 ms later.
        let r2 = validate_keystroke_event(base + 1_000_000, 11, 1, 1234, None, true, &mut state);
        assert!(r2.flags.impossible_iki);
        assert!(r2.confidence < r1.confidence);
    }

    #[test]
    fn test_robotic_periodicity() {
        let mut state = make_state();
        let base = 1_000_000_000_i64;
        // Feed exactly 21 events at perfectly uniform 100 ms intervals.
        for i in 0..=ROBOTIC_CV_WINDOW {
            let ts = base + (i as i64) * 100_000_000;
            let keycode = (i as u16 % 26) + 4;
            let _ = validate_keystroke_event(ts, keycode, 1, 0, None, true, &mut state);
        }
        // The 22nd event should trigger robotic periodicity.
        let ts = base + ((ROBOTIC_CV_WINDOW + 1) as i64) * 100_000_000;
        let r = validate_keystroke_event(ts, 10, 1, 0, None, true, &mut state);
        assert!(
            r.flags.robotic_periodicity,
            "should detect robotic periodicity"
        );
        assert!(r.confidence < 0.8);
    }

    #[test]
    fn test_burst_detection() {
        let mut state = make_state();
        let base = 1_000_000_000_i64;
        // 20 keys in 500 ms (25 ms apart).
        for i in 0..20 {
            let ts = base + (i as i64) * 25_000_000;
            let keycode = (i as u16 % 10) + 4;
            let _ = validate_keystroke_event(ts, keycode, 1, 0, None, true, &mut state);
        }
        // The most recent result should have burst_superhuman flagged.
        let ts = base + 20 * 25_000_000;
        let r = validate_keystroke_event(ts, 10, 1, 0, None, true, &mut state);
        assert!(r.flags.burst_superhuman, "should detect burst");
        assert!(r.confidence < 0.9);
    }

    #[test]
    fn test_pid_mismatch() {
        let mut state = make_state();
        // source_pid == 0 indicates an injected/synthetic event; should trigger pid_mismatch.
        let r = validate_keystroke_event(1_000_000_000, 10, 1, 0, None, true, &mut state);
        assert!(r.flags.pid_mismatch);
        assert!(r.confidence < 0.7);
    }

    #[test]
    fn test_focus_inconsistent() {
        let mut state = make_state();
        let r = validate_keystroke_event(1_000_000_000, 10, 1, 0, None, false, &mut state);
        assert!(r.flags.focus_inconsistent);
        assert!(r.confidence <= 0.8);
    }

    #[test]
    fn test_clean_slate() {
        let mut state = make_state();
        // Use non-zero source_pid (real keystroke) so no pid_mismatch penalty applies.
        let r = validate_keystroke_event(1_000_000_000, 10, 1, 1234, None, true, &mut state);
        assert!(
            r.confidence > 0.9,
            "first keystroke should score high, got {}",
            r.confidence
        );
        assert!(!r.flags.impossible_iki);
        assert!(!r.flags.clock_discontinuity);
        assert!(!r.flags.burst_superhuman);
    }
}
