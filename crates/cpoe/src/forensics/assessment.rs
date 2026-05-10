// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Anomaly detection and assessment.

use chrono::DateTime;
use std::collections::HashMap;

use super::types::{
    Anomaly, AnomalyType, Assessment, CadenceMetrics, FocusMetrics, PrimaryMetrics, RegionData,
    RiskLevel, Severity, SortedEvents, ALERT_THRESHOLD, MIN_EVENTS_FOR_ANALYSIS,
    MIN_EVENTS_FOR_ASSESSMENT, THRESHOLD_GAP_HOURS, THRESHOLD_HIGH_VELOCITY_BPS,
    THRESHOLD_LOW_ENTROPY, THRESHOLD_MONOTONIC_APPEND, THRESHOLD_PAUSE_ENTROPY,
    THRESHOLD_TIMING_ENTROPY,
};
use crate::utils::Probability;

/// Max Shannon entropy for 20-bin edit-position histogram: log2(20).
pub(crate) const ENTROPY_NORMALIZATION: f64 = 4.321928;
/// Below this normalized entropy, editing pattern is suspiciously ordered.
const LOW_ENTROPY_SCORE_THRESHOLD: f64 = 0.35;
/// Monotonic append ratio above which penalty starts.
const MONOTONIC_PENALTY_START: f64 = 0.85;
/// Coefficient of variation below which typing cadence is suspiciously uniform.
const CV_ROBOTIC_THRESHOLD: f64 = 0.2;
/// Per-anomaly penalty in authenticity score.
const ANOMALY_PENALTY: f64 = 0.05;

/// Deletion clustering lower bound for scattered-deletion anomaly.
const DELETION_CLUSTERING_LOW: f64 = 0.9;
/// Deletion clustering upper bound for scattered-deletion anomaly.
const DELETION_CLUSTERING_HIGH: f64 = 1.1;
/// Monotonic append ratio for "suspicious" verdict (stricter than penalty start).
const MONOTONIC_SUSPICIOUS: f64 = 0.90;
/// Positive-to-negative edit ratio above which pattern is suspicious.
const POS_NEG_SUSPICIOUS: f64 = 0.95;
/// Default score when insufficient data is available.
/// Must be below the verification threshold (0.5) so documents with
/// too few events are never marked as "verified".
const INSUFFICIENT_DATA_SCORE: f64 = 0.0;
/// Penalty multiplier for high monotonic append ratio.
const MONOTONIC_PENALTY_WEIGHT: f64 = 0.2;
/// Penalty for low normalized edit entropy.
const LOW_ENTROPY_PENALTY: f64 = 0.15;
/// Penalty for high positive/negative edit ratio.
const POS_NEG_PENALTY: f64 = 0.1;
/// Penalty when cadence is flagged robotic.
const ROBOTIC_CADENCE_PENALTY: f64 = 0.35;
/// Penalty multiplier for low coefficient of variation.
const COV_PENALTY_WEIGHT: f64 = 0.15;
/// Biological cadence score above which a reward is applied.
const BIOLOGICAL_CADENCE_THRESHOLD: f64 = 0.5;
/// Maximum reward for biological cadence evidence.
const BIOLOGICAL_CADENCE_REWARD: f64 = 0.05;
/// Cadence-only penalty for robotic flag.
const CADENCE_ROBOTIC_PENALTY: f64 = 0.5;
/// Cadence-only penalty multiplier for low CoV.
const CADENCE_COV_PENALTY: f64 = 0.2;
/// Assessment score at or above which risk is Low.
const RISK_LOW_THRESHOLD: f64 = 0.7;
/// Assessment score at or above which risk is Medium (below Low).
const RISK_MEDIUM_THRESHOLD: f64 = 0.4;
/// Warning count triggering suspicious verdict.
const SUSPICIOUS_WARNING_COUNT: usize = 3;
/// Indicator count triggering suspicious verdict.
const SUSPICIOUS_INDICATOR_COUNT: usize = 2;
/// Indicator count triggering immediate suspicious verdict.
const SUSPICIOUS_INDICATOR_CRITICAL: usize = 3;
/// Maximum inter-event delta (seconds) for velocity anomaly detection.
const VELOCITY_WINDOW_SEC: f64 = 60.0;

/// IKI autocorrelation above which typing rhythm is suspiciously uniform.
const IKI_AUTOCORR_TRANSCRIPTIVE: f64 = 0.3;
/// Maximum penalty for high IKI autocorrelation.
const IKI_AUTOCORR_PENALTY: f64 = 0.15;
/// Correction ratio below which lack of edits is penalized.
const CORRECTION_RATIO_LOW: f64 = 0.02;
/// Penalty for suspiciously low correction ratio.
const LOW_CORRECTION_PENALTY: f64 = 0.1;
/// Minimum events before correction ratio penalty applies.
const CORRECTION_MIN_EVENTS: usize = 50;
/// Post-pause CV above which variable thinking is rewarded.
const POST_PAUSE_CV_REWARD_THRESHOLD: f64 = 0.25;
/// Reward for high post-pause CV.
const POST_PAUSE_CV_REWARD: f64 = 0.05;
/// Deep-thought pause fraction above which reward applies.
const DEEP_PAUSE_REWARD_THRESHOLD: f64 = 0.1;
/// Reward for presence of deep thinking pauses.
const DEEP_PAUSE_REWARD: f64 = 0.05;
/// Cross-hand timing ratio below which uniform hand transitions are penalized.
const CROSS_HAND_UNIFORM_THRESHOLD: f64 = 1.1;
/// Penalty for uniform cross-hand timing.
const CROSS_HAND_PENALTY: f64 = 0.1;
/// Out-of-focus ratio above which penalty applies.
const FOCUS_OUT_OF_FOCUS_THRESHOLD: f64 = 0.5;
/// Penalty for excessive out-of-focus time.
const FOCUS_OUT_OF_FOCUS_PENALTY: f64 = 0.1;

/// Detect anomalies in editing patterns (topology + temporal).
pub fn detect_anomalies(
    sorted: SortedEvents<'_>,
    regions: &HashMap<i64, Vec<RegionData>>,
    metrics: &PrimaryMetrics,
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    if metrics.monotonic_append_ratio > THRESHOLD_MONOTONIC_APPEND {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::MonotonicAppend,
            description: "High monotonic append ratio suggests sequential content generation"
                .to_string(),
            severity: Severity::Warning,
            context: Some(format!(
                "Ratio: {:.2}%",
                metrics.monotonic_append_ratio.get() * 100.0
            )),
        });
    }

    if metrics.edit_entropy < THRESHOLD_LOW_ENTROPY && metrics.edit_entropy > 0.0 {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::LowEntropy,
            description: "Low revision entropy indicates concentrated editing patterns".to_string(),
            severity: Severity::Warning,
            context: Some(format!("Revision entropy: {:.3}", metrics.edit_entropy)),
        });
    }

    if metrics.timing_entropy > 0.0 && metrics.timing_entropy < THRESHOLD_TIMING_ENTROPY {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::LowEntropy,
            description: "Low timing entropy: inter-keystroke intervals lack natural variation"
                .to_string(),
            severity: Severity::Warning,
            context: Some(format!("Timing entropy: {:.3}", metrics.timing_entropy)),
        });
    }

    if metrics.pause_entropy > 0.0 && metrics.pause_entropy < THRESHOLD_PAUSE_ENTROPY {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::LowEntropy,
            description: "Low pause entropy: pause durations are unnaturally uniform".to_string(),
            severity: Severity::Warning,
            context: Some(format!("Pause entropy: {:.3}", metrics.pause_entropy)),
        });
    }

    if metrics.deletion_clustering > DELETION_CLUSTERING_LOW
        && metrics.deletion_clustering < DELETION_CLUSTERING_HIGH
    {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::ScatteredDeletions,
            description: "Scattered deletion pattern suggests artificial editing".to_string(),
            severity: Severity::Warning,
            context: Some(format!(
                "Clustering coef: {:.3}",
                metrics.deletion_clustering
            )),
        });
    }

    anomalies.extend(detect_temporal_anomalies(sorted, regions));

    anomalies
}

/// Detect temporal gaps and high-velocity editing periods.
fn detect_temporal_anomalies(
    sorted: SortedEvents<'_>,
    _regions: &HashMap<i64, Vec<RegionData>>,
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    if sorted.len() < 2 {
        return anomalies;
    }

    for window in sorted.windows(2) {
        let prev = &window[0];
        let curr = &window[1];

        let delta_ns = curr.timestamp_ns.saturating_sub(prev.timestamp_ns);
        let delta_sec = crate::utils::ns_to_secs(delta_ns);
        let delta_hours = delta_sec / 3600.0;

        if delta_hours > THRESHOLD_GAP_HOURS {
            anomalies.push(Anomaly {
                timestamp: Some(DateTime::from_timestamp_nanos(curr.timestamp_ns)),
                anomaly_type: AnomalyType::Gap,
                description: "Long editing gap detected".to_string(),
                severity: Severity::Info,
                context: Some(format!("Gap: {:.1} hours", delta_hours)),
            });
        }

        if delta_sec > 0.0 && delta_sec < VELOCITY_WINDOW_SEC {
            let bytes_delta = curr.size_delta.unsigned_abs() as f64;
            let bytes_per_sec = bytes_delta / delta_sec;
            if bytes_per_sec > THRESHOLD_HIGH_VELOCITY_BPS {
                anomalies.push(Anomaly {
                    timestamp: Some(DateTime::from_timestamp_nanos(curr.timestamp_ns)),
                    anomaly_type: AnomalyType::HighVelocity,
                    description: "High-velocity content addition detected".to_string(),
                    severity: Severity::Warning,
                    context: Some(format!("Velocity: {:.1} bytes/sec", bytes_per_sec)),
                });
            }
        }
    }

    anomalies
}

/// Determine overall assessment verdict from metrics and anomalies.
pub fn determine_assessment(
    metrics: &PrimaryMetrics,
    anomalies: &[Anomaly],
    event_count: usize,
) -> Assessment {
    if event_count < MIN_EVENTS_FOR_ASSESSMENT {
        return Assessment::Insufficient;
    }

    let (alert_count, warning_count) =
        anomalies
            .iter()
            .fold((0, 0), |(a, w), anom| match anom.severity {
                Severity::Alert => (a + 1, w),
                Severity::Warning => (a, w + 1),
                _ => (a, w),
            });

    let mut suspicious_indicators = 0;

    if metrics.monotonic_append_ratio > MONOTONIC_SUSPICIOUS {
        suspicious_indicators += 1;
    }

    if metrics.edit_entropy < THRESHOLD_LOW_ENTROPY && metrics.edit_entropy > 0.0 {
        suspicious_indicators += 1;
    }

    if metrics.positive_negative_ratio > POS_NEG_SUSPICIOUS {
        suspicious_indicators += 1;
    }

    if metrics.deletion_clustering > DELETION_CLUSTERING_LOW
        && metrics.deletion_clustering < DELETION_CLUSTERING_HIGH
    {
        suspicious_indicators += 1;
    }

    if alert_count >= ALERT_THRESHOLD || suspicious_indicators >= SUSPICIOUS_INDICATOR_CRITICAL {
        return Assessment::Suspicious;
    }

    if warning_count >= SUSPICIOUS_WARNING_COUNT
        || suspicious_indicators >= SUSPICIOUS_INDICATOR_COUNT
    {
        return Assessment::Suspicious;
    }

    Assessment::Consistent
}

/// Overall assessment score in `[0.0, 1.0]` (higher = more human-like).
pub fn compute_assessment_score(
    primary: &PrimaryMetrics,
    cadence: &CadenceMetrics,
    anomaly_count: usize,
    event_count: usize,
    biological_cadence_score: f64,
) -> f64 {
    if event_count < MIN_EVENTS_FOR_ANALYSIS {
        return INSUFFICIENT_DATA_SCORE;
    }

    // Guard non-finite inputs; treat them as neutral (no penalty/reward).
    let bio_score = if biological_cadence_score.is_finite() {
        biological_cadence_score
    } else {
        0.0
    };

    let mut score = 1.0;

    let mar = if primary.monotonic_append_ratio.is_finite() {
        primary.monotonic_append_ratio.get()
    } else {
        0.0
    };
    if mar > MONOTONIC_PENALTY_START {
        score -= MONOTONIC_PENALTY_WEIGHT * (mar - MONOTONIC_PENALTY_START)
            / (1.0 - MONOTONIC_PENALTY_START);
    }

    let edit_entropy = if primary.edit_entropy.is_finite() {
        primary.edit_entropy
    } else {
        ENTROPY_NORMALIZATION
    };
    let normalized_entropy = (edit_entropy / ENTROPY_NORMALIZATION).min(1.0);
    if normalized_entropy < LOW_ENTROPY_SCORE_THRESHOLD {
        score -= LOW_ENTROPY_PENALTY;
    }

    if primary.positive_negative_ratio > POS_NEG_SUSPICIOUS {
        score -= POS_NEG_PENALTY;
    }

    if primary.deletion_clustering > DELETION_CLUSTERING_LOW
        && primary.deletion_clustering < DELETION_CLUSTERING_HIGH
    {
        score -= POS_NEG_PENALTY;
    }

    if cadence.is_robotic {
        score -= ROBOTIC_CADENCE_PENALTY;
    }

    let cov = if cadence.coefficient_of_variation.is_finite() {
        cadence.coefficient_of_variation
    } else {
        CV_ROBOTIC_THRESHOLD
    };
    if cov < CV_ROBOTIC_THRESHOLD {
        score -= COV_PENALTY_WEIGHT * (CV_ROBOTIC_THRESHOLD - cov) / CV_ROBOTIC_THRESHOLD;
    }

    score -= ANOMALY_PENALTY * anomaly_count as f64;

    if bio_score > BIOLOGICAL_CADENCE_THRESHOLD {
        score += BIOLOGICAL_CADENCE_REWARD * (bio_score - BIOLOGICAL_CADENCE_THRESHOLD)
            / BIOLOGICAL_CADENCE_THRESHOLD;
    }

    // Penalty: high IKI autocorrelation (rhythmic/transcriptive typing)
    let iki_ac = if cadence.iki_autocorrelation.is_finite() {
        cadence.iki_autocorrelation
    } else {
        0.0
    };
    if iki_ac > IKI_AUTOCORR_TRANSCRIPTIVE {
        score -= IKI_AUTOCORR_PENALTY * (iki_ac - IKI_AUTOCORR_TRANSCRIPTIVE)
            / (1.0 - IKI_AUTOCORR_TRANSCRIPTIVE);
    }

    // Penalty: low correction ratio (no edits/revisions)
    if cadence.correction_ratio < CORRECTION_RATIO_LOW && event_count >= CORRECTION_MIN_EVENTS {
        score -= LOW_CORRECTION_PENALTY;
    }

    // Reward: high post-pause CV (variable thinking patterns)
    if cadence.post_pause_cv > POST_PAUSE_CV_REWARD_THRESHOLD {
        score += POST_PAUSE_CV_REWARD;
    }

    // Reward: deep thinking pauses present
    if cadence.pause_depth_distribution[2] > DEEP_PAUSE_REWARD_THRESHOLD {
        score += DEEP_PAUSE_REWARD;
    }

    // Penalty: low cross-hand timing ratio (uniform timing across hand transitions)
    if cadence.cross_hand_timing_ratio > 0.0
        && cadence.cross_hand_timing_ratio < CROSS_HAND_UNIFORM_THRESHOLD
    {
        score -= CROSS_HAND_PENALTY;
    }

    // Penalty: low burst speed CV (constant speed within bursts = transcription)
    if cadence.burst_speed_cv > 0.0 && cadence.burst_speed_cv < 0.15 && cadence.burst_count >= 3 {
        score -= 0.10;
    }

    // Penalty: zero-variance windows (stretches with no timing variation)
    if cadence.zero_variance_windows > 3 {
        score -= 0.15;
    } else if cadence.zero_variance_windows > 0 {
        score -= 0.05;
    }

    crate::utils::Probability::clamp(score).get()
}

/// Quick cadence-only score for real-time use before full topology is available.
pub fn compute_cadence_score(cadence: &CadenceMetrics) -> f64 {
    let mut score = 1.0;

    if cadence.is_robotic {
        score -= CADENCE_ROBOTIC_PENALTY;
    }

    let cov = if cadence.coefficient_of_variation.is_finite() {
        cadence.coefficient_of_variation
    } else {
        CV_ROBOTIC_THRESHOLD
    };
    if cov < CV_ROBOTIC_THRESHOLD {
        let penalty = (CV_ROBOTIC_THRESHOLD - cov) / CV_ROBOTIC_THRESHOLD;
        score -= CADENCE_COV_PENALTY * penalty;
    }

    if cadence.percentiles[4] == 0.0 {
        return INSUFFICIENT_DATA_SCORE;
    }

    // Transcription signals
    if cadence.burst_speed_cv > 0.0 && cadence.burst_speed_cv < 0.15 && cadence.burst_count >= 3 {
        score -= 0.10;
    }
    if cadence.zero_variance_windows > 3 {
        score -= 0.15;
    }

    crate::utils::Probability::clamp(score).get()
}

/// Apply focus-switching penalties to an assessment score.
///
/// Call after `compute_assessment_score` when `FocusMetrics` are available.
pub fn apply_focus_penalties(score: &mut Probability, focus: &FocusMetrics) {
    let mut s = score.get();
    // Delegate reading-pattern and AI-switch penalties to the canonical implementation
    // in scoring.rs, which applies mid_typing_switch_ratio modulation.
    s -= super::scoring::compute_focus_penalty(focus);
    if focus.out_of_focus_ratio > FOCUS_OUT_OF_FOCUS_THRESHOLD {
        s -= FOCUS_OUT_OF_FOCUS_PENALTY;
    }
    *score = Probability::clamp(s);
}

/// Apply cross-window transcription penalties to an assessment score.
///
/// Call after `compute_assessment_score` when cross-window match data is available.
/// Each match above the 0.70 threshold applies a penalty proportional to its
/// similarity score, capped at 0.30 total.
pub fn apply_cross_window_penalties(
    score: &mut Probability,
    matches: &[crate::transcription::CrossWindowMatch],
) {
    /// Per-match penalty at similarity = 1.0.
    const CROSS_WINDOW_MAX_PER_MATCH: f64 = 0.20;
    /// Total cap on cross-window penalty.
    const CROSS_WINDOW_PENALTY_CAP: f64 = 0.30;
    /// Similarity floor below which no penalty applies.
    const CROSS_WINDOW_SIM_FLOOR: f64 = 0.70;

    let mut total_penalty = 0.0;
    for m in matches {
        if m.similarity_score >= CROSS_WINDOW_SIM_FLOOR {
            let excess =
                (m.similarity_score - CROSS_WINDOW_SIM_FLOOR) / (1.0 - CROSS_WINDOW_SIM_FLOOR);
            total_penalty += CROSS_WINDOW_MAX_PER_MATCH * excess;
        }
    }
    total_penalty = total_penalty.min(CROSS_WINDOW_PENALTY_CAP);
    *score = Probability::clamp(score.get() - total_penalty);
}

/// Apply enhanced forensic signal adjustments to the assessment score.
///
/// Each enhanced signal shifts the assessment score toward its own verdict:
/// high composite scores (cognitive) reward, low scores (transcriptive) penalize.
/// The effect is bounded to avoid overwhelming the base assessment.
pub fn apply_enhanced_signal_adjustments(
    score: &mut Probability,
    cognitive_load: Option<&super::cognitive_load::CognitiveLoadMetrics>,
    revision_topology: Option<&super::revision_topology::RevisionTopologyMetrics>,
    error_ecology: Option<&super::error_ecology::ErrorEcologyMetrics>,
    likelihood_model: Option<&super::likelihood_model::LikelihoodModelMetrics>,
) {
    /// Maximum total adjustment from enhanced signals.
    const MAX_TOTAL_ADJUSTMENT: f64 = 0.20;
    /// Neutral point: scores above this reward, below penalize.
    const NEUTRAL: f64 = 0.5;

    let mut adjustment = 0.0f64;
    let mut signal_count = 0u32;

    if let Some(cl) = cognitive_load {
        adjustment += (cl.composite_score - NEUTRAL) * 0.08;
        signal_count += 1;
    }
    if let Some(rt) = revision_topology {
        adjustment += (rt.composite_score - NEUTRAL) * 0.05;
        signal_count += 1;
    }
    if let Some(ee) = error_ecology {
        adjustment += (ee.composite_score - NEUTRAL) * 0.05;
        signal_count += 1;
    }
    if let Some(lm) = likelihood_model {
        adjustment += (lm.composite_score - NEUTRAL) * 0.10;
        signal_count += 1;
    }

    if signal_count == 0 {
        return;
    }

    let clamped = adjustment.clamp(-MAX_TOTAL_ADJUSTMENT, MAX_TOTAL_ADJUSTMENT);
    *score = Probability::clamp(score.get() + clamped);
}

/// Map assessment score to risk level.
pub fn determine_risk_level(score: f64, event_count: usize) -> RiskLevel {
    if event_count < MIN_EVENTS_FOR_ANALYSIS {
        return RiskLevel::Insufficient;
    }

    if score >= RISK_LOW_THRESHOLD {
        RiskLevel::Low
    } else if score >= RISK_MEDIUM_THRESHOLD {
        RiskLevel::Medium
    } else {
        RiskLevel::High
    }
}
