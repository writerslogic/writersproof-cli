// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared forensic scoring helpers used across FFI call sites.
//!
//! Consolidates cadence-score, focus-penalty, and combined-score logic
//! that was previously duplicated in multiple FFI modules.

use super::types::{FocusMetrics, SegmentVelocityProfile};
use crate::jitter::SimpleJitterSample;
use crate::sentinel::types::FocusSwitchRecord;
use crate::utils::Probability;

/// Minimum number of jitter samples below which the cadence score is 0.0.
const MIN_CADENCE_SAMPLES: usize = 10;
/// Number of samples at which the keystroke dimension of evidence maturity
/// reaches its maximum contribution.  500 keystrokes ≈ ~100 words ≈ ~2 solid
/// paragraphs of original prose.
const FULL_CONFIDENCE_SAMPLES: usize = 500;
/// Minimum focused writing time (seconds) before evidence begins accruing.
const MIN_WRITING_SECS: f64 = 30.0;
/// Focused writing duration (seconds) at which the time dimension of evidence
/// maturity reaches its maximum.  Five minutes of sustained focused typing is
/// a strong indicator of original authorship.
const FULL_CONFIDENCE_SECS: f64 = 300.0;

/// Weighted mean bytes-per-second (prose segments only) above which a
/// velocity penalty begins.  Calibrated to the upper end of sustained human
/// typing speed (~80 WPM × 5 bytes ≈ 33 BPS; 80 BPS is already fast paste).
const PROSE_VELOCITY_PENALTY_THRESHOLD_BPS: f64 = 80.0;
/// Maximum penalty applied by [`apply_segment_velocity_penalty`].
const PROSE_VELOCITY_MAX_PENALTY: f64 = 0.20;

/// Logarithmic ramp: maps a linear progress value in `[0, 1]` to a
/// curve that grows quickly at first and then slows.
/// `ln(1 + x) / ln(2)` maps `[0, 1] → [0, 1]` with diminishing returns.
fn log_ramp(linear: f64) -> f64 {
    if !linear.is_finite() || linear <= 0.0 {
        return 0.0;
    }
    let clamped = linear.min(1.0);
    (1.0 + clamped).ln() / 2.0_f64.ln()
}

/// Compute a cadence score from raw jitter samples.
///
/// Returns 0.0 when fewer than [`MIN_CADENCE_SAMPLES`] samples are
/// available.  The raw cadence quality (human-like vs robotic) is multiplied
/// by a keystroke-count evidence maturity factor that ramps logarithmically.
pub fn cadence_score_from_samples(samples: &[SimpleJitterSample]) -> f64 {
    let n = samples.len();
    if n < MIN_CADENCE_SAMPLES {
        return 0.0;
    }
    let raw = super::compute_cadence_score(&super::analyze_cadence(samples));
    if n >= FULL_CONFIDENCE_SAMPLES {
        raw
    } else {
        let linear = (n - MIN_CADENCE_SAMPLES) as f64
            / (FULL_CONFIDENCE_SAMPLES - MIN_CADENCE_SAMPLES) as f64;
        raw * log_ramp(linear)
    }
}

/// Compute evidence maturity: a composite of keystroke depth and focused
/// writing duration.  Returns a value in `[0.0, 1.0]` representing how much
/// evidence has been accumulated, independent of whether the typing *looks*
/// human.
///
/// Both dimensions use logarithmic ramps so the score grows quickly during
/// the first few minutes and then plateaus.  The two dimensions are averaged
/// so that 500 keystrokes in 5 seconds (paste) scores much lower than 500
/// keystrokes over 5 minutes (writing).
pub fn evidence_maturity(keystroke_count: u64, focused_secs: f64) -> f64 {
    let ks = keystroke_count as usize;

    let ks_maturity = if ks < MIN_CADENCE_SAMPLES {
        0.0
    } else if ks >= FULL_CONFIDENCE_SAMPLES {
        1.0
    } else {
        let linear = (ks - MIN_CADENCE_SAMPLES) as f64
            / (FULL_CONFIDENCE_SAMPLES - MIN_CADENCE_SAMPLES) as f64;
        log_ramp(linear)
    };

    let time_maturity = if focused_secs < MIN_WRITING_SECS {
        0.0
    } else if focused_secs >= FULL_CONFIDENCE_SECS {
        1.0
    } else {
        let linear =
            (focused_secs - MIN_WRITING_SECS) / (FULL_CONFIDENCE_SECS - MIN_WRITING_SECS);
        log_ramp(linear)
    };

    (ks_maturity + time_maturity) / 2.0
}

/// Compute focus-switching penalty from focus pattern metrics.
///
/// Returns a penalty in `[0.0, 0.15]` to subtract from a forensic score:
/// - 0.15 if a reading-from-source pattern was detected,
/// - 0.10 if more than 3 AI-app switches occurred,
/// - 0.0 otherwise.
pub fn compute_focus_penalty(focus: &FocusMetrics) -> f64 {
    let base = if focus.reading_pattern_detected {
        0.15
    } else if focus.ai_app_switch_count > 3 {
        0.10
    } else {
        return 0.0;
    };
    // If most focus switches happened during active typing (mid_typing_switch_ratio > 0.5),
    // the user is reference-checking (cognitive), not staging content (transcriptive).
    // Reduce the penalty proportionally.
    if focus.mid_typing_switch_ratio > 0.5 {
        base * (1.0 - focus.mid_typing_switch_ratio).max(0.2)
    } else {
        base
    }
}

/// Apply a velocity penalty to `score` based on prose-only segment profiles.
///
/// Non-prose segments (synopses, metadata XML, search indexes) are excluded so
/// that Scrivener's internal churn does not inflate the apparent velocity.  The
/// penalty is proportional to how far the keystroke-weighted mean BPS of prose
/// segments exceeds [`PROSE_VELOCITY_PENALTY_THRESHOLD_BPS`], capped at
/// [`PROSE_VELOCITY_MAX_PENALTY`].
///
/// No-op when there are no prose segments or fewer than two total prose events.
pub fn apply_segment_velocity_penalty(
    score: &mut Probability,
    segments: &[SegmentVelocityProfile],
) {
    // Work only with segments that contain prose content.
    let prose: Vec<&SegmentVelocityProfile> =
        segments.iter().filter(|s| s.is_prose).collect();

    if prose.is_empty() {
        return;
    }

    // Keystroke-weighted mean BPS across all prose segments.
    let total_keystrokes: u64 = prose.iter().map(|s| s.keystroke_count).sum();
    if total_keystrokes < 2 {
        return;
    }

    let weighted_bps: f64 = prose
        .iter()
        .map(|s| s.mean_bps * s.keystroke_count as f64)
        .sum::<f64>()
        / total_keystrokes as f64;

    if !weighted_bps.is_finite() || weighted_bps <= PROSE_VELOCITY_PENALTY_THRESHOLD_BPS {
        return;
    }

    // Scale linearly from 0 at threshold to max penalty at 2× threshold.
    let excess = (weighted_bps - PROSE_VELOCITY_PENALTY_THRESHOLD_BPS)
        / PROSE_VELOCITY_PENALTY_THRESHOLD_BPS;
    let penalty = (PROSE_VELOCITY_MAX_PENALTY * excess).min(PROSE_VELOCITY_MAX_PENALTY);
    *score = Probability::clamp(score.get() - penalty);
}

/// Apply an attestation tier penalty to a score.
///
/// Software-fallback attestation (no SE/TPM) reduces the score by 0.25 to
/// reflect that the evidence binding is weaker than hardware-backed attestation.
/// Hardware-bound attestation incurs no penalty.
pub fn apply_attestation_tier_penalty(
    score: &mut Probability,
    tier: crate::tpm::AttestationTier,
) {
    let penalty = tier.score_penalty();
    if penalty > 0.0 {
        *score = Probability::clamp(score.get() - penalty);
    }
}

/// Compute a combined forensic score from jitter samples and focus
/// switch records for a session that has no store-backed checkpoint
/// data yet.
///
/// The score is `cadence_quality × evidence_maturity - focus_penalty`,
/// clamped to `[0.0, 1.0]`.
pub fn session_forensic_score(
    jitter_samples: &[SimpleJitterSample],
    focus_switches: &[FocusSwitchRecord],
    total_focus_ms: i64,
) -> f64 {
    let cadence = cadence_score_from_samples(jitter_samples);
    let maturity = evidence_maturity(
        jitter_samples.len() as u64,
        total_focus_ms as f64 / 1000.0,
    );
    let focus = super::analysis::analyze_focus_patterns(focus_switches, total_focus_ms);
    let penalty = compute_focus_penalty(&focus);
    crate::utils::Probability::clamp(cadence * maturity - penalty).get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadence_score_below_min_is_zero() {
        let samples: Vec<SimpleJitterSample> = (0..9)
            .map(|i| SimpleJitterSample {
                duration_since_last_ns: (i as u64 + 1) * 100_000_000,
                timestamp_ns: (i as i64) * 200_000_000,
                ..Default::default()
            })
            .collect();
        assert_eq!(cadence_score_from_samples(&samples), 0.0);
    }

    #[test]
    fn cadence_score_ramps_between_thresholds() {
        let make = |n: usize| -> Vec<SimpleJitterSample> {
            (0..n)
                .map(|i| SimpleJitterSample {
                    duration_since_last_ns: (i as u64 + 1) * 100_000_000,
                    timestamp_ns: (i as i64) * 200_000_000,
                    ..Default::default()
                })
                .collect()
        };
        let score_50 = cadence_score_from_samples(&make(50));
        let score_200 = cadence_score_from_samples(&make(200));
        let score_500 = cadence_score_from_samples(&make(500));
        // Mid-ramp scores should be strictly less than full-confidence score.
        assert!(score_50 < score_500 || score_500 == 0.0);
        assert!(score_200 < score_500 || score_500 == 0.0);
        // Monotonically increasing with more samples (same underlying data pattern).
        assert!(score_50 <= score_200);
    }

    #[test]
    fn cadence_score_above_full_confidence() {
        let samples: Vec<SimpleJitterSample> = (0..600)
            .map(|i| SimpleJitterSample {
                duration_since_last_ns: (i as u64 + 1) * 100_000_000,
                timestamp_ns: (i as i64) * 200_000_000,
                ..Default::default()
            })
            .collect();
        let score = cadence_score_from_samples(&samples);
        assert!(score >= 0.0);
    }

    #[test]
    fn evidence_maturity_below_minimums_is_zero() {
        // Too few keystrokes, not enough time.
        assert_eq!(evidence_maturity(5, 10.0), 0.0);
        // Enough keystrokes but no time.
        assert_eq!(evidence_maturity(500, 0.0), 0.5);
        // Enough time but no keystrokes.
        assert_eq!(evidence_maturity(0, 300.0), 0.5);
    }

    #[test]
    fn evidence_maturity_full_is_one() {
        let m = evidence_maturity(500, 300.0);
        assert!((m - 1.0).abs() < f64::EPSILON, "expected 1.0, got {m}");
    }

    #[test]
    fn evidence_maturity_paste_burst_low() {
        // 500 keystrokes in 5 seconds = paste, not writing.
        // Keystroke dimension maxed, time dimension near zero → ~0.5.
        let m = evidence_maturity(500, 5.0);
        assert!(m <= 0.55, "paste burst should have low maturity, got {m}");
    }

    #[test]
    fn evidence_maturity_paragraph_modest() {
        // ~60 keystrokes over 45 seconds — one paragraph of original writing.
        let m = evidence_maturity(60, 45.0);
        assert!(m < 0.35, "single paragraph should be <35% maturity, got {m}");
        assert!(m > 0.0, "should be nonzero for real typing");
    }

    #[test]
    fn evidence_maturity_monotonic_in_both_dims() {
        let m1 = evidence_maturity(100, 60.0);
        let m2 = evidence_maturity(200, 60.0);
        let m3 = evidence_maturity(200, 120.0);
        assert!(m2 >= m1, "more keystrokes should not decrease maturity");
        assert!(m3 >= m2, "more time should not decrease maturity");
    }

    #[test]
    fn focus_penalty_no_flags() {
        let focus = FocusMetrics::default();
        assert_eq!(compute_focus_penalty(&focus), 0.0);
    }

    #[test]
    fn focus_penalty_reading_pattern() {
        let focus = FocusMetrics {
            reading_pattern_detected: true,
            ..Default::default()
        };
        assert!((compute_focus_penalty(&focus) - 0.15).abs() < f64::EPSILON);
    }

    #[test]
    fn focus_penalty_ai_switches() {
        let focus = FocusMetrics {
            ai_app_switch_count: 5,
            ..Default::default()
        };
        assert!((compute_focus_penalty(&focus) - 0.10).abs() < f64::EPSILON);
    }

    #[test]
    fn session_score_empty_inputs() {
        let score = session_forensic_score(&[], &[], 0);
        assert_eq!(score, 0.0);
    }

    fn make_profile(is_prose: bool, mean_bps: f64, keystrokes: u64) -> SegmentVelocityProfile {
        SegmentVelocityProfile {
            rel_path: String::new(),
            is_prose,
            mean_bps,
            max_bps: mean_bps,
            keystroke_count: keystrokes,
            high_velocity_bursts: 0,
        }
    }

    #[test]
    fn segment_velocity_penalty_no_prose_segments() {
        let mut score = Probability::clamp(0.9);
        let segments = vec![make_profile(false, 200.0, 1000)];
        apply_segment_velocity_penalty(&mut score, &segments);
        assert!((score.get() - 0.9).abs() < f64::EPSILON, "non-prose should not affect score");
    }

    #[test]
    fn segment_velocity_penalty_below_threshold() {
        let mut score = Probability::clamp(0.9);
        let segments = vec![make_profile(true, 30.0, 500)];
        apply_segment_velocity_penalty(&mut score, &segments);
        assert!((score.get() - 0.9).abs() < f64::EPSILON, "under-threshold prose should not penalize");
    }

    #[test]
    fn segment_velocity_penalty_above_threshold() {
        let mut score = Probability::clamp(1.0);
        // 160 BPS = 2× threshold → full max penalty
        let segments = vec![make_profile(true, 160.0, 500)];
        apply_segment_velocity_penalty(&mut score, &segments);
        assert!(score.get() < 1.0, "over-threshold prose should penalize");
        assert!(score.get() >= 1.0 - PROSE_VELOCITY_MAX_PENALTY - f64::EPSILON);
    }

    #[test]
    fn attestation_tier_hardware_no_penalty() {
        let mut score = Probability::clamp(0.8);
        apply_attestation_tier_penalty(&mut score, crate::tpm::AttestationTier::HardwareBound);
        assert!((score.get() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn attestation_tier_software_applies_penalty() {
        let mut score = Probability::clamp(0.8);
        apply_attestation_tier_penalty(&mut score, crate::tpm::AttestationTier::SoftwareFallback);
        assert!((score.get() - 0.55).abs() < f64::EPSILON, "expected 0.55, got {}", score.get());
    }

    #[test]
    fn attestation_tier_software_penalty_clamps_at_zero() {
        let mut score = Probability::clamp(0.1);
        apply_attestation_tier_penalty(&mut score, crate::tpm::AttestationTier::SoftwareFallback);
        assert!(score.get() >= 0.0);
    }

    #[test]
    fn segment_velocity_penalty_excludes_non_prose_weight() {
        let mut score_prose_only = Probability::clamp(1.0);
        let mut score_mixed = Probability::clamp(1.0);
        let prose = make_profile(true, 160.0, 500);
        // Adding a non-prose segment with low BPS should not dilute the prose penalty.
        let non_prose = make_profile(false, 1.0, 100_000);
        apply_segment_velocity_penalty(&mut score_prose_only, &[prose.clone()]);
        apply_segment_velocity_penalty(&mut score_mixed, &[prose, non_prose]);
        assert!(
            (score_prose_only.get() - score_mixed.get()).abs() < f64::EPSILON,
            "non-prose weight must not dilute prose penalty"
        );
    }
}
