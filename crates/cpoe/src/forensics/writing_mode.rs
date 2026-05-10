// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Writing mode classification: cognitive (compositional) vs transcriptive (copying).
//!
//! Cognitive writing is non-linear: burst-pause-revise cycles, deep thinking pauses,
//! variable rhythm, significant corrections, and edits scattered through the document.
//! Transcriptive writing is linear: steady metronome cadence, large append-only blocks,
//! minimal backspaces, and no deep thinking pauses.

use serde::{Deserialize, Serialize};

use crate::utils::stats::lerp_score;

#[cfg(test)]
use super::types::EventData;
use super::types::{CadenceMetrics, PrimaryMetrics, SortedEvents};

/// Minimum events for writing mode classification.
pub const MIN_EVENTS_FOR_MODE: usize = 20;

/// Minimum consecutive positive deltas to count as a burst before revision.
const MIN_BURST_FOR_REVISION: usize = 3;

/// Minimum consecutive positive deltas to count as a pure-append stretch.
const PURE_APPEND_MIN_LENGTH: usize = 10;

/// Deletion must be >= this fraction of preceding burst to count as a revision
/// (filters single-character typo fixes).
const MIN_REVISION_DEPTH_FRACTION: f64 = 0.05;

// --- Signal scoring profiles ---
// Each signal maps a raw metric to [0.0, 1.0] via lerp_score(value, low, high).
// When `invert` is true, high raw values indicate transcriptive (score is flipped).

struct ScoringSignal {
    low: f64,
    high: f64,
    weight: f64,
    invert: bool,
}

impl ScoringSignal {
    const fn new(low: f64, high: f64, weight: f64) -> Self {
        Self { low, high, weight, invert: false }
    }
    const fn inverted(low: f64, high: f64, weight: f64) -> Self {
        Self { low, high, weight, invert: true }
    }
    fn score(&self, value: f64) -> f64 {
        let s = lerp_score(value, self.low, self.high);
        if self.invert { 1.0 - s } else { s }
    }
}

const CORRECTION_RATIO: ScoringSignal = ScoringSignal::new(0.02, 0.05, 0.20);
const BURST_SPEED_CV: ScoringSignal = ScoringSignal::new(0.15, 0.25, 0.15);
const ZERO_VAR_WINDOWS: ScoringSignal = ScoringSignal::inverted(0.0, 5.0, 0.15);
const IKI_AUTOCORR: ScoringSignal = ScoringSignal::inverted(0.15, 0.40, 0.10);
const POST_PAUSE_CV: ScoringSignal = ScoringSignal::new(0.10, 0.30, 0.10);
const DEEP_PAUSE: ScoringSignal = ScoringSignal::new(0.0, 0.10, 0.10);
const POS_NEG_RATIO: ScoringSignal = ScoringSignal::inverted(0.85, 0.98, 0.05);
const MONOTONIC_APPEND: ScoringSignal = ScoringSignal::inverted(0.70, 0.90, 0.05);
const REVISION_FRACTION: ScoringSignal = ScoringSignal::new(0.02, 0.15, 0.07);
const THINKING_PAUSE_RATIO: ScoringSignal = ScoringSignal::new(0.0, 0.08, 0.05);
const BURST_LENGTH_CV: ScoringSignal = ScoringSignal::new(0.20, 0.60, 0.05);

/// Pause before a burst, in nanoseconds, that separates distinct typing events.
const BURST_SEPARATOR_NS: i64 = 1_000_000_000;

/// Fraction of session tail (last 20%) used for scatter analysis.
const SCATTER_TAIL_FRACTION: f64 = 0.20;
/// Minimum fraction of backspace events in the tail to be suspicious.
const SCATTER_TAIL_SUSPICIOUS: f64 = 0.70;

const REVISION_SCATTER_WEIGHT: f64 = 0.04;
const PAUSE_BURST_CORR_WEIGHT: f64 = 0.04;

/// Minimum inter-event gap (nanoseconds) to count as a "thinking pause" (2 seconds).
const THINKING_PAUSE_THRESHOLD_NS: i64 = 2_000_000_000;

/// Cognitive score at or above this threshold classifies as Cognitive.
const COGNITIVE_THRESHOLD: f64 = 0.65;
/// Cognitive score at or below this threshold classifies as Transcriptive.
const TRANSCRIPTIVE_THRESHOLD: f64 = 0.35;

/// The detected writing mode for a document session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WritingMode {
    /// Original composition: burst-pause-revise cycles, deep thinking pauses,
    /// variable rhythm, significant corrections.
    Cognitive,
    /// Copying/retyping existing content: steady cadence, minimal corrections,
    /// linear append pattern, no deep thinking pauses.
    Transcriptive,
    /// Signals from both modes present.
    Mixed,
    /// Insufficient data to classify.
    Insufficient,
}

impl std::fmt::Display for WritingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WritingMode::Cognitive => write!(f, "cognitive"),
            WritingMode::Transcriptive => write!(f, "transcriptive"),
            WritingMode::Mixed => write!(f, "mixed"),
            WritingMode::Insufficient => write!(f, "insufficient"),
        }
    }
}

/// Detailed analysis supporting the writing mode classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WritingModeAnalysis {
    /// The classified writing mode.
    pub mode: WritingMode,
    /// Composite score: 0.0 = strongly transcriptive, 1.0 = strongly cognitive.
    pub cognitive_score: f64,
    /// Confidence in the classification (0.0-1.0).
    pub confidence: f64,
    /// Revision cycle analysis from size_delta sequences.
    pub revision_pattern: RevisionPattern,
    /// Ratio of events preceded by a thinking pause (>2s gap).
    pub thinking_pause_ratio: f64,
    /// Coefficient of variation of burst lengths (higher = more cognitive).
    pub burst_length_cv: f64,
    /// Optional deep cognitive layer metrics (populated when word-level data available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cognitive_layer: Option<CognitiveLayerMetrics>,
}

/// Deep cognitive analysis metrics from word-level and timing-level signals.
/// These provide additional evidence beyond the event-level signals and are
/// included in evidence packets and forensic reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveLayerMetrics {
    /// Sentence Initiation Delay ratio (cognitive: 8-30x, transcriptive: 2-4x).
    pub sentence_initiation_ratio: f64,
    /// IKI histogram modality score (cognitive: multi-modal >0.7, transcriptive: <0.3).
    pub iki_modality_score: f64,
    /// Bigram fluency differential (cognitive: >2.5, transcriptive: <1.5).
    pub bigram_fluency_ratio: f64,
    /// Lexical Retrieval Delay Pearson correlation (cognitive: >0.25, transcriptive: ~0).
    pub lrd_correlation: f64,
    /// Non-append edit ratio (cognitive: >0.15, transcriptive: <0.03).
    pub non_append_ratio: f64,
    /// Error fingerprint: semantic correction ratio (cognitive: >0.4, transcriptive: <0.15).
    pub semantic_correction_ratio: f64,
    /// Joint signal consistency check (0 = consistent, >0.5 = spoofing suspected).
    pub spoofing_indicator: f64,
    /// Deviation from personal baseline (0 = normal, >0.6 = anomalous).
    pub baseline_deviation: f64,
}

/// Analysis of revision patterns from consecutive size_delta sequences.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevisionPattern {
    /// Number of burst->delete->burst revision cycles detected.
    pub revision_cycle_count: usize,
    /// Number of pure-append stretches (>= 10 consecutive positive deltas).
    pub pure_append_stretch_count: usize,
    /// Average fraction of burst content deleted in revision cycles (0.0-1.0).
    pub avg_revision_depth: f64,
    /// Longest pure-append streak (consecutive positive deltas).
    pub max_append_streak: usize,
    /// Ratio of events in revision cycles vs total events.
    pub revision_fraction: f64,
}

/// Classify writing mode from existing forensic metrics and event data.
pub fn classify_writing_mode(
    primary: &PrimaryMetrics,
    cadence: &CadenceMetrics,
    sorted: SortedEvents<'_>,
    event_count: usize,
) -> WritingModeAnalysis {
    if event_count < MIN_EVENTS_FOR_MODE {
        return WritingModeAnalysis {
            mode: WritingMode::Insufficient,
            cognitive_score: 0.0,
            confidence: 0.0,
            revision_pattern: RevisionPattern::default(),
            thinking_pause_ratio: 0.0,
            burst_length_cv: 0.0,
            cognitive_layer: None,
        };
    }

    let revision = analyze_revision_patterns(sorted);
    let thinking_pause_ratio = compute_thinking_pause_ratio(sorted);
    let burst_length_cv = compute_burst_length_cv(sorted);
    let revision_scatter = compute_revision_scatter_score(sorted);
    let pause_burst_corr = compute_pause_burst_correlation(sorted);

    // Score each signal: 0.0 = transcriptive, 1.0 = cognitive.
    let scores: [(f64, f64); 13] = [
        (CORRECTION_RATIO.score(cadence.correction_ratio.get()), CORRECTION_RATIO.weight),
        (BURST_SPEED_CV.score(cadence.burst_speed_cv), BURST_SPEED_CV.weight),
        (ZERO_VAR_WINDOWS.score(cadence.zero_variance_windows as f64), ZERO_VAR_WINDOWS.weight),
        (IKI_AUTOCORR.score(cadence.iki_autocorrelation), IKI_AUTOCORR.weight),
        (POST_PAUSE_CV.score(cadence.post_pause_cv), POST_PAUSE_CV.weight),
        (DEEP_PAUSE.score(cadence.pause_depth_distribution[2]), DEEP_PAUSE.weight),
        (POS_NEG_RATIO.score(primary.positive_negative_ratio.get()), POS_NEG_RATIO.weight),
        (MONOTONIC_APPEND.score(primary.monotonic_append_ratio.get()), MONOTONIC_APPEND.weight),
        (REVISION_FRACTION.score(revision.revision_fraction), REVISION_FRACTION.weight),
        (THINKING_PAUSE_RATIO.score(thinking_pause_ratio), THINKING_PAUSE_RATIO.weight),
        (BURST_LENGTH_CV.score(burst_length_cv), BURST_LENGTH_CV.weight),
        (revision_scatter, REVISION_SCATTER_WEIGHT),
        (pause_burst_corr, PAUSE_BURST_CORR_WEIGHT),
    ];

    let cognitive_score: f64 = scores.iter().map(|(s, w)| s * w).sum();
    let cognitive_score = crate::utils::Probability::clamp(cognitive_score).get();

    let mode = if cognitive_score >= COGNITIVE_THRESHOLD {
        WritingMode::Cognitive
    } else if cognitive_score <= TRANSCRIPTIVE_THRESHOLD {
        WritingMode::Transcriptive
    } else {
        WritingMode::Mixed
    };

    let confidence = match mode {
        WritingMode::Cognitive => {
            ((cognitive_score - COGNITIVE_THRESHOLD) / (1.0 - COGNITIVE_THRESHOLD)).min(1.0)
        }
        WritingMode::Transcriptive => {
            ((TRANSCRIPTIVE_THRESHOLD - cognitive_score) / TRANSCRIPTIVE_THRESHOLD).min(1.0)
        }
        WritingMode::Mixed => {
            let dist = (cognitive_score - TRANSCRIPTIVE_THRESHOLD)
                .min(COGNITIVE_THRESHOLD - cognitive_score);
            let half_range = (COGNITIVE_THRESHOLD - TRANSCRIPTIVE_THRESHOLD) / 2.0;
            (dist / half_range).min(1.0)
        }
        WritingMode::Insufficient => 0.0,
    };

    WritingModeAnalysis {
        mode,
        cognitive_score,
        confidence,
        revision_pattern: revision,
        thinking_pause_ratio,
        burst_length_cv,
        cognitive_layer: None, // Populated by caller when word-level data available
    }
}

/// Analyze revision patterns from consecutive size_delta sequences.
///
/// Detects burst->delete->burst cycles (cognitive revision pattern) vs
/// pure-append stretches (transcriptive pattern) from file size changes.
pub fn analyze_revision_patterns(sorted: SortedEvents<'_>) -> RevisionPattern {
    if sorted.len() < MIN_BURST_FOR_REVISION {
        return RevisionPattern::default();
    }

    let deltas: Vec<i32> = sorted.iter().map(|e| e.size_delta).collect();

    let mut revision_cycles = 0usize;
    let mut revision_event_count = 0usize;
    let mut revision_depths = Vec::new();
    let mut pure_append_stretches = 0usize;
    let mut max_append_streak = 0usize;

    let mut i = 0;
    while i < deltas.len() {
        // Look for a burst of positive deltas.
        let burst_start = i;
        let mut burst_bytes: i64 = 0;
        while i < deltas.len() && deltas[i] >= 0 {
            burst_bytes += deltas[i] as i64;
            i += 1;
        }
        let burst_len = i - burst_start;

        // Track pure-append streaks.
        if burst_len > max_append_streak {
            max_append_streak = burst_len;
        }
        if burst_len >= PURE_APPEND_MIN_LENGTH {
            pure_append_stretches += 1;
        }

        if burst_len < MIN_BURST_FOR_REVISION || burst_bytes == 0 {
            // Not enough burst to be a revision source; skip all trailing deletions.
            while i < deltas.len() && deltas[i] < 0 {
                i += 1;
            }
            continue;
        }

        // Look for deletions following the burst.
        let del_start = i;
        let mut del_bytes: i64 = 0;
        while i < deltas.len() && deltas[i] < 0 {
            del_bytes += deltas[i].abs() as i64;
            i += 1;
        }
        let del_len = i - del_start;

        if del_len == 0 {
            continue;
        }

        let depth = del_bytes as f64 / burst_bytes as f64;
        if depth >= MIN_REVISION_DEPTH_FRACTION {
            revision_cycles += 1;
            revision_event_count += burst_len + del_len;
            revision_depths.push(depth.min(1.0));
        }
    }

    let avg_revision_depth = if revision_depths.is_empty() {
        0.0
    } else {
        revision_depths.iter().sum::<f64>() / revision_depths.len() as f64
    };

    let revision_fraction = if deltas.is_empty() {
        0.0
    } else {
        revision_event_count as f64 / deltas.len() as f64
    };

    RevisionPattern {
        revision_cycle_count: revision_cycles,
        pure_append_stretch_count: pure_append_stretches,
        avg_revision_depth,
        max_append_streak,
        revision_fraction,
    }
}

/// Compute the ratio of events preceded by a thinking pause (>2s gap).
/// Cognitive writers pause to think before bursts; transcribers type continuously.
fn compute_thinking_pause_ratio(sorted: SortedEvents<'_>) -> f64 {
    if sorted.len() < 2 {
        return 0.0;
    }
    let mut thinking_pauses = 0usize;
    for pair in sorted.windows(2) {
        let gap_ns = pair[1].timestamp_ns.saturating_sub(pair[0].timestamp_ns);
        if gap_ns >= THINKING_PAUSE_THRESHOLD_NS {
            thinking_pauses += 1;
        }
    }
    thinking_pauses as f64 / (sorted.len() - 1) as f64
}

/// Compute the coefficient of variation of burst lengths.
/// Cognitive writers produce bursts of wildly different sizes; transcribers
/// produce uniform chunks (they're reading and retyping at a steady pace).
fn compute_burst_length_cv(sorted: SortedEvents<'_>) -> f64 {
    if sorted.len() < 4 {
        return 0.0;
    }
    let mut burst_lengths: Vec<f64> = Vec::new();
    let mut current_burst = 0usize;
    for pair in sorted.windows(2) {
        let gap_ns = pair[1].timestamp_ns.saturating_sub(pair[0].timestamp_ns);
        if gap_ns < 500_000_000 {
            // Within 500ms = same burst
            current_burst += 1;
        } else {
            if current_burst > 0 {
                burst_lengths.push(current_burst as f64);
            }
            current_burst = 1;
        }
    }
    if current_burst > 0 {
        burst_lengths.push(current_burst as f64);
    }
    if burst_lengths.len() < 3 {
        return 0.0;
    }
    crate::utils::stats::coefficient_of_variation(&burst_lengths)
}

/// Score based on where backspace/deletion events are distributed across the session.
///
/// Genuine cognitive writing scatters corrections throughout the document. A session
/// where >70% of all deletion events cluster in the last 20% of the session timeline
/// is consistent with cleanup after pasting externally-generated content.
/// Returns 1.0 (cognitive) when scatter is healthy, 0.0 when suspicious.
fn compute_revision_scatter_score(sorted: SortedEvents<'_>) -> f64 {
    if sorted.len() < MIN_EVENTS_FOR_MODE {
        return 0.5;
    }

    let deletions: Vec<i64> = sorted
        .iter()
        .filter(|e| e.size_delta < 0)
        .map(|e| e.timestamp_ns)
        .collect();

    if deletions.len() < 3 {
        return 0.5;
    }

    let t_first = sorted.first().map(|e| e.timestamp_ns).unwrap_or(0);
    let t_last = sorted.last().map(|e| e.timestamp_ns).unwrap_or(0);
    let span = (t_last - t_first) as f64;
    if span <= 0.0 {
        return 0.5;
    }

    let tail_start = t_first as f64 + span * (1.0 - SCATTER_TAIL_FRACTION);
    let tail_count = deletions.iter().filter(|&&ts| ts as f64 >= tail_start).count();
    let tail_frac = tail_count as f64 / deletions.len() as f64;

    if tail_frac >= SCATTER_TAIL_SUSPICIOUS {
        0.0
    } else {
        1.0 - tail_frac / SCATTER_TAIL_SUSPICIOUS
    }
}

/// Score based on Spearman correlation between pre-burst pause duration and burst size.
///
/// In genuine cognitive writing, longer pauses precede larger or more complex bursts
/// (the writer is thinking before typing more). In transcription or AI-copied content,
/// pauses are uniform and burst sizes are not correlated with preceding pause duration.
/// Returns a score in [0, 1]: 0.0 when correlation is near zero (suspicious), 1.0 when strong.
fn compute_pause_burst_correlation(sorted: SortedEvents<'_>) -> f64 {
    if sorted.len() < MIN_EVENTS_FOR_MODE {
        return 0.5;
    }

    // Collect (pause_ns, burst_size_bytes) pairs.
    let mut pairs: Vec<(f64, f64)> = Vec::new();
    let mut i = 0;
    while i + 1 < sorted.len() {
        let gap = sorted[i + 1].timestamp_ns.saturating_sub(sorted[i].timestamp_ns);
        if gap >= BURST_SEPARATOR_NS {
            // This is a pause; measure burst size starting at i+1.
            let mut burst_bytes: i64 = 0;
            let mut j = i + 1;
            while j < sorted.len() {
                let next_gap = if j + 1 < sorted.len() {
                    sorted[j + 1].timestamp_ns.saturating_sub(sorted[j].timestamp_ns)
                } else {
                    i64::MAX
                };
                burst_bytes += sorted[j].size_delta.max(0) as i64;
                if next_gap >= BURST_SEPARATOR_NS {
                    break;
                }
                j += 1;
            }
            if burst_bytes > 0 {
                pairs.push((gap as f64, burst_bytes as f64));
            }
            i = j;
        } else {
            i += 1;
        }
    }

    if pairs.len() < 4 {
        return 0.5;
    }

    let pauses: Vec<f64> = pairs.iter().map(|p| p.0).collect();
    let bursts: Vec<f64> = pairs.iter().map(|p| p.1).collect();
    let rho = crate::utils::stats::spearman_correlation(&pauses, &bursts);
    // Map [-1, 1] → [0, 1]: correlation ≥ 0.1 is cognitive, near 0 is suspicious.
    ((rho + 1.0) / 2.0).clamp(0.0, 1.0)
}

/// Optional enhanced signal scores for writing mode enrichment.
///
/// When the new forensic modules produce results, their composite scores
/// are blended into the writing mode classification to improve accuracy.
#[derive(Debug)]
pub struct EnhancedSignals {
    /// Cognitive load-timing entanglement composite (0=transcriptive, 1=cognitive).
    pub cognitive_load_score: Option<f64>,
    /// Revision topology composite (0=transcriptive, 1=cognitive).
    pub revision_topology_score: Option<f64>,
    /// Error ecology composite (0=transcriptive, 1=cognitive).
    pub error_ecology_score: Option<f64>,
    /// Likelihood model posterior P(cognitive) (0=transcriptive, 1=cognitive).
    pub likelihood_p_cognitive: Option<f64>,
    /// Composition mode composite (0=AI-mediated, 1=pure composition).
    pub composition_mode_score: Option<f64>,
}

/// Weight allocated to each enhanced signal when present.
/// These are redistributed from the existing signal weights to keep
/// the total weight at 1.0.
const ENHANCED_COGNITIVE_LOAD_WEIGHT: f64 = 0.12;
const ENHANCED_REVISION_TOPO_WEIGHT: f64 = 0.06;
const ENHANCED_ERROR_ECOLOGY_WEIGHT: f64 = 0.06;
const ENHANCED_LIKELIHOOD_WEIGHT: f64 = 0.10;
const ENHANCED_COMPOSITION_WEIGHT: f64 = 0.06;

/// Enrich an existing `WritingModeAnalysis` with enhanced signal scores.
///
/// The enhanced signals' total weight (up to 0.40) is redistributed
/// from the base signals proportionally. When no enhanced signals are
/// available, the original classification is returned unchanged.
pub fn enrich_writing_mode(
    analysis: &mut WritingModeAnalysis,
    signals: &EnhancedSignals,
) {
    let mut enhanced_score = 0.0f64;
    let mut enhanced_weight = 0.0f64;

    if let Some(s) = signals.cognitive_load_score {
        enhanced_score += s * ENHANCED_COGNITIVE_LOAD_WEIGHT;
        enhanced_weight += ENHANCED_COGNITIVE_LOAD_WEIGHT;
    }
    if let Some(s) = signals.revision_topology_score {
        enhanced_score += s * ENHANCED_REVISION_TOPO_WEIGHT;
        enhanced_weight += ENHANCED_REVISION_TOPO_WEIGHT;
    }
    if let Some(s) = signals.error_ecology_score {
        enhanced_score += s * ENHANCED_ERROR_ECOLOGY_WEIGHT;
        enhanced_weight += ENHANCED_ERROR_ECOLOGY_WEIGHT;
    }
    if let Some(s) = signals.likelihood_p_cognitive {
        enhanced_score += s * ENHANCED_LIKELIHOOD_WEIGHT;
        enhanced_weight += ENHANCED_LIKELIHOOD_WEIGHT;
    }
    if let Some(s) = signals.composition_mode_score {
        enhanced_score += s * ENHANCED_COMPOSITION_WEIGHT;
        enhanced_weight += ENHANCED_COMPOSITION_WEIGHT;
    }

    if enhanced_weight < f64::EPSILON {
        return;
    }

    // Blend: shrink the base score's effective weight and add enhanced.
    let base_weight = 1.0 - enhanced_weight;
    let blended = analysis.cognitive_score * base_weight + enhanced_score;
    let blended = crate::utils::Probability::clamp(blended).get();

    analysis.cognitive_score = blended;

    // Reclassify mode from blended score.
    analysis.mode = if blended >= COGNITIVE_THRESHOLD {
        WritingMode::Cognitive
    } else if blended <= TRANSCRIPTIVE_THRESHOLD {
        WritingMode::Transcriptive
    } else {
        WritingMode::Mixed
    };

    // Recompute confidence.
    analysis.confidence = match analysis.mode {
        WritingMode::Cognitive => {
            ((blended - COGNITIVE_THRESHOLD) / (1.0 - COGNITIVE_THRESHOLD)).min(1.0)
        }
        WritingMode::Transcriptive => {
            ((TRANSCRIPTIVE_THRESHOLD - blended) / TRANSCRIPTIVE_THRESHOLD).min(1.0)
        }
        WritingMode::Mixed => {
            let dist =
                (blended - TRANSCRIPTIVE_THRESHOLD).min(COGNITIVE_THRESHOLD - blended);
            let half_range = (COGNITIVE_THRESHOLD - TRANSCRIPTIVE_THRESHOLD) / 2.0;
            (dist / half_range).min(1.0)
        }
        WritingMode::Insufficient => 0.0,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_events(deltas: &[i32]) -> Vec<EventData> {
        let mut file_size: i64 = 1000;
        deltas
            .iter()
            .enumerate()
            .map(|(i, &d)| {
                file_size += d as i64;
                EventData {
                    id: i as i64,
                    timestamp_ns: (i as i64 + 1) * 1_000_000_000,
                    file_size,
                    size_delta: d,
                    file_path: "test.txt".to_string(),
                }
            })
            .collect()
    }

    fn cognitive_cadence() -> CadenceMetrics {
        CadenceMetrics {
            correction_ratio: crate::utils::Probability::clamp(0.08),
            burst_speed_cv: 0.35,
            zero_variance_windows: 0,
            iki_autocorrelation: 0.05,
            post_pause_cv: 0.40,
            pause_depth_distribution: [0.4, 0.35, 0.25],
            coefficient_of_variation: 0.45,
            burst_count: 5,
            is_robotic: false,
            cross_hand_timing_ratio: 1.5,
            percentiles: [50_000_000.0; 5],
            ..CadenceMetrics::default()
        }
    }

    fn transcriptive_cadence() -> CadenceMetrics {
        CadenceMetrics {
            correction_ratio: crate::utils::Probability::clamp(0.01),
            burst_speed_cv: 0.08,
            zero_variance_windows: 6,
            iki_autocorrelation: 0.50,
            post_pause_cv: 0.05,
            pause_depth_distribution: [0.95, 0.05, 0.0],
            coefficient_of_variation: 0.10,
            burst_count: 2,
            is_robotic: true,
            cross_hand_timing_ratio: 1.0,
            percentiles: [100_000_000.0; 5],
            ..CadenceMetrics::default()
        }
    }

    #[test]
    fn test_cognitive_classification() {
        // Burst-pause-revise pattern: write 20 chars, delete 5, write 15, delete 3, ...
        let deltas: Vec<i32> = [
            20, 15, 10, -5, -3, 18, 12, 8, -4, -2, 14, 10, 12, -6, 15, 10, 8, -3, 12, 10, 15, -5,
            8, 10,
        ]
        .to_vec();
        let events = make_events(&deltas);
        let primary = PrimaryMetrics {
            monotonic_append_ratio: crate::utils::Probability::clamp(0.50),
            edit_entropy: 3.5,
            median_interval: 2.0,
            positive_negative_ratio: crate::utils::Probability::clamp(0.70),
            deletion_clustering: 0.5,
        };

        let result = classify_writing_mode(
            &primary,
            &cognitive_cadence(),
            SortedEvents::new(&events),
            events.len(),
        );
        assert_eq!(result.mode, WritingMode::Cognitive);
        assert!(result.cognitive_score >= COGNITIVE_THRESHOLD);
        assert!(result.confidence > 0.0);
        assert!(result.revision_pattern.revision_cycle_count >= 2);
    }

    #[test]
    fn test_transcriptive_classification() {
        // Pure append: all positive deltas, no deletions.
        let deltas: Vec<i32> = vec![10; 25];
        let events = make_events(&deltas);
        let primary = PrimaryMetrics {
            monotonic_append_ratio: crate::utils::Probability::clamp(0.95),
            edit_entropy: 0.5,
            median_interval: 0.15,
            positive_negative_ratio: crate::utils::Probability::clamp(0.99),
            deletion_clustering: 0.0,
        };

        let result = classify_writing_mode(
            &primary,
            &transcriptive_cadence(),
            SortedEvents::new(&events),
            events.len(),
        );
        assert_eq!(result.mode, WritingMode::Transcriptive);
        assert!(result.cognitive_score <= TRANSCRIPTIVE_THRESHOLD);
        assert!(result.revision_pattern.revision_cycle_count == 0);
        assert!(result.revision_pattern.pure_append_stretch_count >= 1);
    }

    #[test]
    fn test_mixed_classification() {
        // Some cognitive signals, some transcriptive.
        let deltas: Vec<i32> = [
            10, 10, 10, 10, -3, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
            -2, 10,
        ]
        .to_vec();
        let events = make_events(&deltas);
        let primary = PrimaryMetrics {
            monotonic_append_ratio: crate::utils::Probability::clamp(0.80),
            edit_entropy: 2.0,
            median_interval: 0.5,
            positive_negative_ratio: crate::utils::Probability::clamp(0.90),
            deletion_clustering: 0.3,
        };
        // Cadence halfway between cognitive and transcriptive.
        let cadence = CadenceMetrics {
            correction_ratio: crate::utils::Probability::clamp(0.03),
            burst_speed_cv: 0.20,
            zero_variance_windows: 2,
            iki_autocorrelation: 0.25,
            post_pause_cv: 0.18,
            pause_depth_distribution: [0.6, 0.3, 0.1],
            coefficient_of_variation: 0.25,
            burst_count: 3,
            is_robotic: false,
            percentiles: [80_000_000.0; 5],
            ..CadenceMetrics::default()
        };

        let result =
            classify_writing_mode(&primary, &cadence, SortedEvents::new(&events), events.len());
        assert_eq!(result.mode, WritingMode::Mixed);
        assert!(result.cognitive_score > TRANSCRIPTIVE_THRESHOLD);
        assert!(result.cognitive_score < COGNITIVE_THRESHOLD);
    }

    #[test]
    fn test_insufficient_data() {
        let events = make_events(&[10, 5, -2]);
        let primary = PrimaryMetrics::default();
        let cadence = CadenceMetrics::default();

        let result =
            classify_writing_mode(&primary, &cadence, SortedEvents::new(&events), events.len());
        assert_eq!(result.mode, WritingMode::Insufficient);
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn test_revision_patterns_cognitive() {
        // Clear burst->delete->burst cycles.
        let deltas = [20, 15, 10, -8, -5, 18, 12, 10, -6, -3, 15, 10, 8];
        let events = make_events(&deltas);
        let pattern = analyze_revision_patterns(SortedEvents::new(&events));

        assert!(pattern.revision_cycle_count >= 2);
        assert!(pattern.avg_revision_depth > MIN_REVISION_DEPTH_FRACTION);
        assert!(pattern.revision_fraction > 0.0);
    }

    #[test]
    fn test_revision_patterns_pure_append() {
        // All positive: no revision cycles.
        let deltas: Vec<i32> = vec![10; 15];
        let events = make_events(&deltas);
        let pattern = analyze_revision_patterns(SortedEvents::new(&events));

        assert_eq!(pattern.revision_cycle_count, 0);
        assert!(pattern.pure_append_stretch_count >= 1);
        assert_eq!(pattern.max_append_streak, 15);
        assert_eq!(pattern.revision_fraction, 0.0);
    }

    #[test]
    fn test_revision_pattern_typo_filter() {
        // Tiny deletions after large bursts should be filtered out (below 5% depth).
        let deltas = [
            100, 100, 100, -1, 100, 100, 100, -1, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50,
        ];
        let events = make_events(&deltas);
        let pattern = analyze_revision_patterns(SortedEvents::new(&events));

        // -1 after 300 bytes = 0.3%, below the 5% threshold.
        assert_eq!(pattern.revision_cycle_count, 0);
    }

    #[test]
    fn test_empty_events() {
        let pattern = analyze_revision_patterns(SortedEvents::new(&[]));
        assert_eq!(pattern.revision_cycle_count, 0);
        assert_eq!(pattern.revision_fraction, 0.0);
    }

    #[test]
    fn test_zero_delta_does_not_split_burst() {
        // Auto-save (delta=0) in the middle of a burst should not break it.
        // Without fix: [10, 10, 0, 10, -8] would be two short bursts (2 + 1),
        // both below MIN_BURST_FOR_REVISION, missing the revision cycle.
        let deltas = [10, 10, 0, 10, -8, 15, 10, 0, 10, -5];
        let events = make_events(&deltas);
        let pattern = analyze_revision_patterns(SortedEvents::new(&events));

        assert_eq!(pattern.revision_cycle_count, 2);
        assert!(pattern.avg_revision_depth > MIN_REVISION_DEPTH_FRACTION);
    }
}
