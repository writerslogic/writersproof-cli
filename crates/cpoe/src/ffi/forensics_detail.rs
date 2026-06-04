// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::load_events_for_path;
use crate::ffi::types::{catch_ffi_panic, try_ffi};
use crate::utils::finite_or;

/// Guard an `Option<f64>`: returns `None` if the inner value is non-finite.
#[inline]
fn finite_opt(v: Option<f64>) -> Option<f64> {
    v.filter(|x| x.is_finite())
}

/// Saturating `usize` to `u32` conversion (caps at `u32::MAX`).
#[inline]
fn usize_u32(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Saturating `u128` to `i64` conversion for epoch millis.
#[inline]
fn millis_i64(v: u128) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Trailing window duration for live cadence score (30 seconds).
/// Short enough for the meter to respond within seconds when typing
/// patterns change (e.g. switching from transcription to original
/// writing), while still capturing enough samples for statistical
/// cadence analysis at typical typing speeds.
const LIVE_CADENCE_WINDOW_NS: i64 = 30_000_000_000;

/// Downsample raw jitter samples into ~`target` normalized IKI values (0.0-1.0).
/// Returns an empty vec if fewer than `min_samples` keystrokes are available.
fn downsample_iki_sparkline(
    samples: &[crate::jitter::SimpleJitterSample],
    target: usize,
    min_samples: usize,
) -> Vec<f64> {
    if samples.len() < min_samples {
        return Vec::new();
    }
    // Extract IKI in milliseconds, clamping outliers.
    let ikis: Vec<f64> = samples
        .windows(2)
        .filter_map(|w| {
            w[1].timestamp_ns
                .checked_sub(w[0].timestamp_ns)
                .map(|d| d as f64 / 1_000_000.0)
        })
        .filter(|&d| d > 0.0 && d < 5000.0) // Cap at 5s to exclude session gaps
        .collect();
    if ikis.len() < min_samples {
        return Vec::new();
    }
    // Downsample via bucket averaging.
    let bucket_size = (ikis.len() as f64 / target as f64).max(1.0);
    let mut result = Vec::with_capacity(target);
    let mut i = 0.0;
    while (i as usize) < ikis.len() && result.len() < target {
        let start = i as usize;
        let end = ((i + bucket_size) as usize).min(ikis.len());
        if start < end {
            let sum: f64 = ikis[start..end].iter().sum();
            result.push(sum / (end - start) as f64);
        }
        i += bucket_size;
    }
    // Normalize to 0.0-1.0 range.
    let max = result.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if max > 0.0 && max.is_finite() {
        for v in &mut result {
            *v = (*v / max).clamp(0.0, 1.0);
        }
    }
    result
}

/// Return the suffix of `samples` whose timestamps fall within
/// `window_ns` nanoseconds of the newest sample. Samples are
/// append-ordered by timestamp, so a reverse linear scan suffices.
fn recent_jitter_window(
    samples: &[crate::jitter::SimpleJitterSample],
    window_ns: i64,
) -> &[crate::jitter::SimpleJitterSample] {
    let Some(newest) = samples.last() else {
        return samples;
    };
    let cutoff = newest.timestamp_ns.saturating_sub(window_ns);
    // Samples are append-ordered; find the first within the window.
    let start = samples.partition_point(|s| s.timestamp_ns < cutoff);
    &samples[start..]
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForensicBreakdown {
    pub success: bool,
    pub monotonic_append_ratio: f64,
    pub edit_entropy: f64,
    pub median_interval: f64,
    pub mean_iki_ms: f64,
    pub std_dev_iki_ms: f64,
    pub coefficient_of_variation: f64,
    pub burst_count: u32,
    pub pause_count: u32,
    pub mean_bps: f64,
    pub max_bps: f64,
    pub hurst_exponent: Option<f64>,
    pub assessment_score: f64,
    pub perplexity_score: f64,
    pub risk_level: String,
    pub protocol_verdict: String,
    pub anomaly_count: u32,
    pub anomalies: Vec<FfiAnomaly>,
    /// Writing mode: "cognitive", "transcriptive", "mixed", or "insufficient".
    pub writing_mode: String,
    /// Composite cognitive score (0.0 = transcriptive, 1.0 = cognitive).
    pub writing_mode_score: f64,
    /// Confidence in writing mode classification (0.0-1.0).
    pub writing_mode_confidence: f64,
    /// Number of burst->delete->burst revision cycles detected.
    pub revision_cycle_count: u32,
    /// Fraction of keystrokes that are backspace/delete.
    pub correction_ratio: f64,
    /// CV of typing speed within bursts.
    pub burst_speed_cv: f64,
    /// Pause depth distribution: [sentence_fraction, paragraph_fraction, deep_fraction].
    pub pause_depth_distribution: Vec<f64>,
    /// Joint signal consistency: 0.0 = consistent, >0.5 = possible spoofing.
    pub spoofing_indicator: f64,
    /// Sentence initiation delay ratio (cognitive: 8-30x, transcriptive: 2-4x).
    pub sentence_initiation_ratio: f64,
    /// Lexical retrieval delay correlation (cognitive: >0.25, transcriptive: ~0).
    pub lrd_correlation: f64,
    /// IKI distribution modality (cognitive: multi-modal >0.7, transcriptive: <0.3).
    pub iki_modality_score: f64,
    /// Deviation from personal writing baseline (0 = normal, >0.6 = anomalous).
    pub baseline_deviation: f64,
    /// Mean plausibility of dictation events (1.0 = fully plausible, <0.3 = likely forged).
    pub dictation_plausibility: f64,
    /// Fraction of content that was dictated (0.0 = all typed, 1.0 = all dictated).
    pub dictation_ratio: f64,
    /// Whether multiple speakers were detected in dictation segments.
    pub multi_speaker_detected: bool,
    /// Interim recognition revisions per minute (real speech: 4-12, TTS: 0-1).
    pub dictation_revision_density: f64,
    /// Self-repair disfluency cycles per minute (real: 3-8, TTS: 0).
    pub dictation_disfluency_density: f64,
    /// CV of inter-burst timing across dictation events (high = real, low = TTS).
    pub dictation_burst_cv: f64,
    /// Enhanced cognitive/transcriptive signal analysis (5 new dimensions).
    pub enhanced_signals: Option<FfiEnhancedSignals>,
    /// Cross-modal consistency: per-check results verifying all evidence channels agree.
    pub cross_modal: Option<FfiCrossModalResult>,
    /// Focus-switching pattern analysis during editing.
    pub focus: Option<FfiFocusMetrics>,
    /// Real-time transcription suspicion assessment.
    pub transcription_suspicion: Option<FfiTranscriptionSuspicion>,
    /// Fatigue trajectory analysis across the session.
    pub fatigue: Option<FfiFatigueMetrics>,
    /// Repair locality: how far back corrections reach.
    pub repair_locality: Option<FfiRepairLocality>,
    /// Cognitive-Linguistic Complexity metrics.
    pub clc: Option<FfiClcMetrics>,
    /// Per-file segment velocity profiles (for Scrivener multi-file projects).
    pub segment_profiles: Vec<FfiSegmentProfile>,
    /// Bitfield of which analyses completed (see analysis_names for labels).
    pub analysis_completed: u32,
    /// Bitfield of which analyses failed.
    pub analysis_failed: u32,
    /// Ordered analysis names corresponding to bit positions 0..18.
    pub analysis_names: Vec<String>,
    /// Biological cadence steadiness score (0.0-1.0).
    pub biological_cadence_score: f64,
    /// Timing steganography detection confidence (0.0-1.0).
    pub steg_confidence: f64,
    /// Additional cadence fields not previously exposed.
    pub cadence_extended: Option<FfiCadenceExtended>,
    /// Signal-to-noise ratio analysis.
    pub snr: Option<FfiSnrAnalysis>,
    /// Lyapunov exponent (chaos) analysis.
    pub lyapunov: Option<FfiLyapunovAnalysis>,
    /// IKI compression ratio analysis.
    pub iki_compression: Option<FfiIkiCompressionAnalysis>,
    /// Topological data analysis of keystroke dynamics.
    pub labyrinth: Option<FfiLabyrinthAnalysis>,
    /// Forgery cost estimation from the user-adversary threat model.
    pub forgery_cost: Option<FfiForgeryEstimate>,
    /// Cross-window transcription matches detected during the session.
    pub cross_window_matches: Vec<FfiCrossWindowMatch>,
    /// Unified typing velocity metrics with percentiles.
    pub typing_metrics: Option<FfiTypingMetrics>,
    /// Writing mode revision pattern details.
    pub revision_pattern: Option<FfiRevisionPattern>,
    /// Writing mode top-level signals.
    pub thinking_pause_ratio: f64,
    pub burst_length_cv: f64,
    /// Primary metrics not already exposed at top level.
    pub positive_negative_ratio: f64,
    pub deletion_clustering: f64,
    pub timing_entropy: f64,
    pub pause_entropy: f64,
    /// AI tools detected during the session with category details.
    pub ai_tools: Vec<FfiDetectedAiTool>,
    /// Session statistics across the evidence chain.
    pub session_stats: Option<FfiSessionStats>,
    /// Behavioral fingerprint from forensic analysis.
    pub behavioral_fingerprint: Option<FfiBehavioralFingerprint>,
    /// Behavioral forgery analysis flags.
    pub forgery_analysis: Option<FfiForgeryAnalysis>,
    /// High-velocity burst count exceeding 100 BPS.
    pub high_velocity_bursts: u32,
    /// Estimated characters from autocomplete/AI (excess over human max velocity).
    pub autocomplete_chars: i64,
    pub cursor_attention: Option<FfiCursorAttention>,
    /// Active probe combined score (Galton + reflex gate).
    pub active_probes_score: Option<f64>,
    pub active_probes_valid: Option<bool>,
    /// Error topology score and validity.
    pub error_topology_score: Option<f64>,
    pub error_topology_valid: Option<bool>,
    /// Spectral analysis (pink noise classification).
    pub spectral_slope: Option<f64>,
    pub spectral_noise_type: Option<String>,
    pub spectral_valid: Option<bool>,
    /// Behavioral baseline comparison (Mahalanobis distance).
    pub baseline_mahalanobis: Option<f64>,
    pub baseline_anomalous: Option<bool>,
    /// Language classification scores (category -> score).
    pub language_scores: Vec<FfiLanguageScore>,
    /// AI fluency flag from word-trigram perplexity.
    pub ai_fluency_flag: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiLanguageScore {
    pub category: String,
    pub score: f64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCursorAttention {
    pub scroll_event_count: u64,
    pub scroll_bidirectional_ratio: f64,
    pub reversal_rate: f64,
    pub scroll_edit_correlation: f64,
    pub scroll_before_edit_ratio: f64,
    pub scroll_velocity_cv: f64,
    pub position_entropy: f64,
    pub read_back_frequency: f64,
    pub dwell_distribution: Vec<f64>,
    pub dwell_gini: f64,
    pub composite_score: f64,
}

/// Enhanced forensic signal metrics grouped by analysis dimension.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiEnhancedSignals {
    pub cognitive_load: Option<FfiCognitiveLoadSignals>,
    pub revision_topology: Option<FfiRevisionTopologySignals>,
    pub error_ecology: Option<FfiErrorEcologySignals>,
    pub likelihood_model: Option<FfiLikelihoodSignals>,
    pub composition_mode: Option<FfiCompositionModeSignals>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCognitiveLoadSignals {
    /// Composite score (0=transcriptive, 1=cognitive).
    pub score: f64,
    /// IKI-surprisal Spearman rho (cognitive: 0.3-0.6, transcriptive: ~0).
    pub iki_surprisal_rho: f64,
    /// Per-sentence velocity arc R² (cognitive: >0.3, transcriptive: <0.1).
    pub sentence_arc_r_squared: f64,
    /// Deep pauses at structural boundaries (cognitive: >0.6, transcriptive: <0.3).
    pub structural_pause_concentration: f64,
    /// Number of deep pauses analyzed.
    pub deep_pause_count: u32,
    /// Number of sentences analyzed.
    pub sentence_count: u32,
    pub word_count: u32,
    pub boundary_count: u32,
    /// "Creative", "Editing", "Transcription", or "Unknown".
    pub cognitive_mode: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiRevisionTopologySignals {
    pub score: f64,
    /// DAG branching factor (cognitive: >2, transcriptive: ~1).
    pub branching_factor: f64,
    /// Mean region revisit depth (cognitive: 2-4, transcriptive: 0-1).
    pub revisit_depth: f64,
    /// Mean distance from edit position to frontier (cognitive: 0.3-0.6).
    pub frontier_distance: f64,
    pub active_region_count: u32,
    /// Aggregate semantic revision ratio (substitution + restructuring + insertion).
    pub semantic_revision_ratio: f64,
    /// Per-type revision breakdown.
    pub sub_word_motor_pct: f64,
    pub word_substitution_pct: f64,
    pub clause_restructuring_pct: f64,
    pub positional_insertion_pct: f64,
    /// Total classified revision events.
    pub total_revisions: u32,
    /// Detour ratio: sum(|cursor_jumps|) / total_chars (retype: ~0, composition: >0.3).
    pub detour_ratio: f64,
    /// Fraction of edits behind the leading edge (retype: ~0%, composition: 15-40%).
    pub leading_edge_divergence: f64,
    /// Shannon entropy of insertion positions (retype: low, composition: high).
    pub insertion_point_entropy: f64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiErrorEcologySignals {
    pub score: f64,
    /// Rapid self-correction fraction (cognitive: >0.3).
    pub rapid_correction_pct: f64,
    /// Immediate small corrections within ~3s.
    pub immediate_small_correction_pct: f64,
    /// Delayed corrections after pauses (revision).
    pub delayed_correction_pct: f64,
    /// Bulk correction fraction (transcriptive: >0.3).
    pub bulk_correction_pct: f64,
    /// False start fraction (cognitive: >0.15).
    pub false_start_pct: f64,
    /// Overall correction rate (corrections / total keystrokes).
    pub correction_rate: f64,
    /// Total correction events.
    pub total_corrections: u32,
    /// Jensen-Shannon divergence from cognitive reference distribution.
    pub jsd_from_cognitive: f64,
    /// Jensen-Shannon divergence from transcriptive reference distribution.
    pub jsd_from_transcriptive: f64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiLikelihoodSignals {
    /// Session posterior P(cognitive).
    pub p_cognitive: f64,
    /// Aggregate session log-likelihood ratio.
    pub session_llr: f64,
    /// Mean per-window LLR.
    pub mean_llr: f64,
    /// LLR standard deviation (high = mixed session).
    pub llr_std_dev: f64,
    /// Minimum per-window LLR.
    pub min_window_llr: f64,
    /// Maximum per-window LLR.
    pub max_window_llr: f64,
    /// Fraction of windows classified as cognitive.
    pub cognitive_window_fraction: f64,
    /// Total windows analyzed.
    pub window_count: u32,
    /// Timestamped per-window cognitive probability timeline.
    /// Each point has a seconds-since-session-start and P(cognitive).
    pub timeline: Vec<FfiLikelihoodTimelinePoint>,
}

/// A single point on the cognitive probability timeline.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiLikelihoodTimelinePoint {
    /// Seconds since the start of the session.
    pub seconds_from_start: f64,
    /// Posterior P(cognitive) for this window.
    pub p_cognitive: f64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCompositionModeSignals {
    pub score: f64,
    /// Dominant mode: "pure_composition", "reference_assisted", "paste_domesticate",
    /// "paste_veneer", or "ai_mediated".
    pub dominant_mode: String,
    /// Number of AI-mediated cycles detected.
    pub ai_cycle_count: u32,
    pub paste_event_count: u32,
    pub focus_switch_count: u32,
    /// Per-mode probability distribution.
    pub pure_composition_pct: f64,
    pub reference_assisted_pct: f64,
    pub paste_domesticate_pct: f64,
    pub paste_veneer_pct: f64,
    pub ai_mediated_pct: f64,
    /// Paste events broken down by content kind.
    pub paste_prose_count: u32,
    pub paste_structured_data_count: u32,
    pub paste_media_count: u32,
    pub paste_formatting_only_count: u32,
    pub paste_mixed_count: u32,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiAnomaly {
    pub timestamp_epoch_ms: Option<i64>,
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
}

/// Cross-modal consistency analysis: verifies all evidence channels agree.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCrossModalResult {
    pub score: f64,
    pub verdict: String,
    pub checks: Vec<FfiCrossModalCheck>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCrossModalCheck {
    pub name: String,
    pub passed: bool,
    pub score: f64,
    pub detail: String,
}

/// Focus-switching pattern analysis.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiFocusMetrics {
    pub switch_count: u32,
    pub out_of_focus_ratio: f64,
    pub ai_app_switch_count: u32,
    pub avg_away_duration_sec: f64,
    pub reading_pattern_detected: bool,
    pub mid_typing_switch_ratio: f64,
}

/// Streaming transcription suspicion assessment.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiTranscriptionSuspicion {
    pub is_suspicious: bool,
    pub unexplained_correction_ratio: f64,
    pub ecology_score: f64,
    pub sample_count: u32,
}

/// Three-phase fatigue trajectory metrics.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiFatigueMetrics {
    pub residual_sse: f64,
    pub warmup_fraction: f64,
    pub plateau_fraction: f64,
    pub fatigue_fraction: f64,
    pub fatigue_slope_iki_per_kstroke: f64,
    pub dominant_phase: u8,
}

/// Repair locality metrics.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiRepairLocality {
    pub mean_offset_chars: f64,
    pub offset_cv: f64,
    pub recent_repair_pct: f64,
    pub distant_repair_pct: f64,
}

/// Cognitive-Linguistic Complexity metrics.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiClcMetrics {
    pub mean_surprisal_bpw: f64,
    pub std_dev_surprisal: f64,
    pub low_surprisal_pct: f64,
    pub iki_surprisal_correlation: f64,
}

/// Per-segment velocity profile for bundle documents.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSegmentProfile {
    pub rel_path: String,
    pub is_prose: bool,
    pub mean_bps: f64,
    pub max_bps: f64,
    pub keystroke_count: u64,
    pub high_velocity_bursts: u32,
}

/// Extended cadence fields not in the base FfiForensicBreakdown.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCadenceExtended {
    pub zero_variance_windows: u32,
    pub mean_dwell_ns: f64,
    pub dwell_cv: f64,
    pub mean_flight_ns: f64,
    pub flight_cv: f64,
    pub iki_autocorrelation: f64,
    pub post_pause_cv: f64,
    pub cross_hand_timing_ratio: f64,
    pub planning_pause_rate: Option<f64>,
    pub translating_burst_ratio: Option<f64>,
    pub revision_spike_count: Option<u32>,
    pub structural_homogeneity_score: Option<f64>,
    pub clc_surprisal_score: Option<f64>,
    pub repair_locality_mean_offset: Option<f64>,
    pub fatigue_trajectory_residual: Option<f64>,
    pub fatigue_phase: Option<u8>,
    /// IKI percentiles: [p10, p25, p50, p75, p90] in nanoseconds.
    pub percentiles: Vec<f64>,
    pub avg_burst_length: f64,
    pub avg_pause_duration_ns: f64,
    pub is_robotic: bool,
    pub median_iki_ns: f64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSnrAnalysis {
    pub snr_db: f64,
    pub flagged: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiLyapunovAnalysis {
    pub exponent: f64,
    pub flagged: bool,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiIkiCompressionAnalysis {
    pub ratio: f64,
    pub flagged: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiLabyrinthAnalysis {
    pub correlation_dimension: f64,
    pub recurrence_rate: f64,
    pub determinism: f64,
    pub rqa_entropy: f64,
    pub confidence: f64,
    pub is_valid: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForgeryEstimate {
    pub overall_difficulty: f64,
    pub estimated_forge_time_sec: f64,
    pub tier: String,
    pub weakest_link: Option<String>,
    pub components: Vec<FfiForgeryEstimateComponent>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForgeryEstimateComponent {
    pub name: String,
    pub present: bool,
    pub cost_cpu_sec: f64,
    pub explanation: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCrossWindowMatch {
    pub source_app: String,
    pub source_window_title: String,
    pub similarity_score: f64,
    pub matched_length: u32,
    pub detected_at_epoch_ms: i64,
}

/// Unified typing velocity metrics with IKI percentiles.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiTypingMetrics {
    pub bps_mean: f64,
    pub bps_p95: f64,
    pub iki_p25: f64,
    pub iki_p50: f64,
    pub iki_p75: f64,
    pub cv: f64,
    pub sample_count: u32,
}

/// Writing mode revision pattern details.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiRevisionPattern {
    pub revision_cycle_count: u32,
    pub pure_append_stretch_count: u32,
    pub avg_revision_depth: f64,
    pub max_append_streak: u32,
    pub revision_fraction: f64,
}

/// Detected AI tool with category and observation basis.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDetectedAiTool {
    pub signing_id: String,
    /// "DirectGenerative", "AssistantCopilot", "BrowserHosted", "Automation", "ClipboardTransform".
    pub category: String,
    /// "Observed", "Inferred", "Correlated".
    pub basis: String,
    pub detected_at_epoch_ms: i64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSessionStats {
    pub session_count: u32,
    pub avg_session_duration_sec: f64,
    pub total_editing_time_sec: f64,
    pub time_span_sec: f64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiBehavioralFingerprint {
    pub keystroke_interval_mean: f64,
    pub keystroke_interval_std: f64,
    pub keystroke_interval_skewness: f64,
    pub keystroke_interval_kurtosis: f64,
    pub interval_buckets: Vec<f64>,
    pub sentence_pause_mean: f64,
    pub paragraph_pause_mean: f64,
    pub thinking_pause_frequency: f64,
    pub burst_length_mean: f64,
    pub burst_speed_variance: f64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForgeryAnalysis {
    pub is_suspicious: bool,
    pub confidence: f64,
    pub flags: Vec<String>,
}

impl FfiForensicBreakdown {
    fn error(msg: String) -> Self {
        Self {
            success: false,
            monotonic_append_ratio: 0.0,
            edit_entropy: 0.0,
            median_interval: 0.0,
            mean_iki_ms: 0.0,
            std_dev_iki_ms: 0.0,
            coefficient_of_variation: 0.0,
            burst_count: 0,
            pause_count: 0,
            mean_bps: 0.0,
            max_bps: 0.0,
            hurst_exponent: None,
            assessment_score: 0.0,
            perplexity_score: 0.0,
            risk_level: "unknown".to_string(),
            protocol_verdict: "unknown".to_string(),
            anomaly_count: 0,
            anomalies: Vec::new(),
            writing_mode: "insufficient".to_string(),
            writing_mode_score: 0.0,
            writing_mode_confidence: 0.0,
            revision_cycle_count: 0,
            correction_ratio: 0.0,
            burst_speed_cv: 0.0,
            pause_depth_distribution: vec![0.0, 0.0, 0.0],
            spoofing_indicator: 0.0,
            sentence_initiation_ratio: 0.0,
            lrd_correlation: 0.0,
            iki_modality_score: 0.0,
            baseline_deviation: 0.0,
            dictation_plausibility: 0.0,
            dictation_ratio: 0.0,
            multi_speaker_detected: false,
            dictation_revision_density: 0.0,
            dictation_disfluency_density: 0.0,
            dictation_burst_cv: 0.0,
            enhanced_signals: None,
            cross_modal: None,
            focus: None,
            transcription_suspicion: None,
            fatigue: None,
            repair_locality: None,
            clc: None,
            segment_profiles: Vec::new(),
            analysis_completed: 0,
            analysis_failed: 0,
            analysis_names: Vec::new(),
            biological_cadence_score: 0.0,
            steg_confidence: 0.0,
            cadence_extended: None,
            snr: None,
            lyapunov: None,
            iki_compression: None,
            labyrinth: None,
            forgery_cost: None,
            cross_window_matches: Vec::new(),
            typing_metrics: None,
            revision_pattern: None,
            thinking_pause_ratio: 0.0,
            burst_length_cv: 0.0,
            positive_negative_ratio: 0.0,
            deletion_clustering: 0.0,
            timing_entropy: 0.0,
            pause_entropy: 0.0,
            ai_tools: Vec::new(),
            session_stats: None,
            behavioral_fingerprint: None,
            forgery_analysis: None,
            high_velocity_bursts: 0,
            autocomplete_chars: 0,
            cursor_attention: None,
            active_probes_score: None,
            active_probes_valid: None,
            error_topology_score: None,
            error_topology_valid: None,
            spectral_slope: None,
            spectral_noise_type: None,
            spectral_valid: None,
            baseline_mahalanobis: None,
            baseline_anomalous: None,
            language_scores: Vec::new(),
            ai_fluency_flag: false,
            error_message: Some(msg),
        }
    }
}

crate::ffi::types::impl_ffi_err!(FfiForensicBreakdown);

/// Return a detailed forensic breakdown for a tracked file.
///
/// Runs both the authorship profile (anomaly detection) and the full forensic
/// metrics pipeline (cadence, velocity, behavioral fingerprint, etc.), returning
/// rich structured data suitable for native UI display.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_forensic_breakdown(path: String) -> FfiForensicBreakdown {
    catch_ffi_panic!(@err FfiForensicBreakdown, {
    super::types::run_on_stack(move || {
    log::debug!("ffi_get_forensic_breakdown: path={}", path);
    let (path, _store, events) = try_ffi!(load_events_for_path(&path), FfiForensicBreakdown);

    if events.is_empty() {
        return FfiForensicBreakdown::error("No events found for this file".to_string());
    }

    let profile = crate::forensics::ForensicEngine::evaluate_authorship(&path, &events);
    let (mut metrics, _regions) = crate::ffi::helpers::run_full_forensics(&events);

    // Enrich from live sentinel session (single lookup to avoid repeated clones).
    let mut dictation_plausibility = 0.0;
    let mut dictation_ratio = 0.0;
    let mut multi_speaker_detected = false;
    let mut dictation_revision_density = 0.0;
    let mut dictation_disfluency_density = 0.0;
    let mut dictation_burst_cv = 0.0;
    let mut live_ai_tools: Vec<FfiDetectedAiTool> = Vec::new();
    let mut live_cursor_attention: Option<FfiCursorAttention> = None;

    if let Some(sentinel) = super::sentinel::get_sentinel() {
        if let Ok(session) = sentinel.session(&path) {
            // Writing mode cognitive layer enrichment.
            if let Some(layer) = session.cognitive.analyze() {
                if let Some(ref mut wm) = metrics.writing_mode {
                    wm.cognitive_layer = Some(layer);
                }
            }

            // Cross-window transcription matches.
            let matches = session.transcription_detector.matches();
            if !matches.is_empty() {
                metrics.cross_window_matches = matches.to_vec();
                crate::forensics::apply_cross_window_penalties(
                    &mut metrics.assessment_score,
                    &metrics.cross_window_matches,
                );
            }

            // Dictation scoring.
            if !session.dictation_events.is_empty() {
                let dict_words: u32 = session.dictation_events.iter().map(|e| e.word_count).sum();
                let typed_words = usize_u32(session.cognitive.word_boundary_count()).saturating_sub(dict_words);
                let segments = crate::forensics::dictation::cluster_speaker_segments(
                    &session.dictation_events,
                );
                let multi = segments.iter().any(|s| s.speaker_label > 0);
                let comp = crate::forensics::dictation::apply_dictation_adjustment(
                    metrics.assessment_score.get(),
                    &session.dictation_events,
                    typed_words,
                    multi,
                );
                dictation_plausibility = finite_or(comp.dictated_score, 0.0);
                dictation_ratio = finite_or(comp.dictation_ratio, 0.0);
                multi_speaker_detected = comp.multi_speaker_detected;
                let analytics = crate::forensics::dictation::compute_dictation_analytics(
                    &session.dictation_events, typed_words,
                );
                dictation_revision_density = finite_or(analytics.mean_interim_revisions_per_min, 0.0);
                dictation_disfluency_density = finite_or(analytics.mean_disfluency_per_min, 0.0);
                dictation_burst_cv = finite_or(analytics.burst_timing_cv, 0.0);
            }

            // AI tools detected.
            live_ai_tools = session
                .ai_tools_detected
                .iter()
                .map(|t| FfiDetectedAiTool {
                    signing_id: t.signing_id.clone(),
                    category: t.category.to_string(),
                    basis: t.basis.to_string(),
                    detected_at_epoch_ms: t
                        .detected_at
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| millis_i64(d.as_millis()))
                        .unwrap_or(0),
                })
                .collect();

            // Cursor attention from scroll/position data.
            live_cursor_attention =
                crate::forensics::cursor_attention::analyze(&session.scroll_attention)
                    .map(|ca| FfiCursorAttention {
                        scroll_event_count: ca.scroll_event_count,
                        scroll_bidirectional_ratio: finite_or(ca.scroll_bidirectional_ratio, 0.0),
                        reversal_rate: finite_or(ca.reversal_rate, 0.0),
                        scroll_edit_correlation: finite_or(ca.scroll_edit_correlation, 0.0),
                        scroll_before_edit_ratio: finite_or(ca.scroll_before_edit_ratio, 0.0),
                        scroll_velocity_cv: finite_or(ca.scroll_velocity_cv, 0.0),
                        position_entropy: finite_or(ca.position_entropy, 0.0),
                        read_back_frequency: finite_or(ca.read_back_frequency, 0.0),
                        dwell_distribution: ca.dwell_distribution.to_vec(),
                        dwell_gini: finite_or(ca.dwell_gini, 0.0),
                        composite_score: finite_or(ca.composite_score, 0.0),
                    });
        }
    }

    let protocol_verdict = metrics.map_to_protocol_verdict();

    let anomalies: Vec<FfiAnomaly> = profile
        .anomalies
        .iter()
        .map(|a| FfiAnomaly {
            timestamp_epoch_ms: a.timestamp.map(|t| t.timestamp_millis()),
            anomaly_type: a.anomaly_type.to_string(),
            description: a.description.clone(),
            severity: a.severity.to_string(),
        })
        .collect();

    let fb = super::forensic_fields::build_forensic_breakdown(&profile, &metrics);
    let std_dev_iki_ms = finite_or(metrics.cadence.std_dev_iki_ns / 1_000_000.0, 0.0);

    FfiForensicBreakdown {
        success: true,
        monotonic_append_ratio: profile.metrics.monotonic_append_ratio.get(),
        edit_entropy: finite_or(profile.metrics.edit_entropy, 0.0),
        median_interval: finite_or(profile.metrics.median_interval, 0.0),
        mean_iki_ms: fb.mean_iki_ms,
        std_dev_iki_ms,
        coefficient_of_variation: fb.coefficient_of_variation,
        burst_count: fb.burst_count,
        pause_count: fb.pause_count,
        mean_bps: fb.mean_bps,
        max_bps: fb.max_bps,
        hurst_exponent: fb.hurst_exponent,
        assessment_score: fb.assessment_score,
        perplexity_score: finite_or(metrics.perplexity_score, 0.0),
        risk_level: metrics.risk_level.to_string().to_lowercase(),
        protocol_verdict: protocol_verdict.to_string(),
        anomaly_count: usize_u32(profile.anomalies.len()),
        anomalies,
        writing_mode: metrics
            .writing_mode
            .as_ref()
            .map(|wm| wm.mode.to_string())
            .unwrap_or_else(|| "insufficient".to_string()),
        writing_mode_score: metrics
            .writing_mode
            .as_ref()
            .map(|wm| finite_or(wm.cognitive_score, 0.0))
            .unwrap_or(0.0),
        writing_mode_confidence: metrics
            .writing_mode
            .as_ref()
            .map(|wm| finite_or(wm.confidence, 0.0))
            .unwrap_or(0.0),
        revision_cycle_count: fb.revision_cycle_count,
        correction_ratio: fb.correction_ratio,
        burst_speed_cv: fb.burst_speed_cv,
        pause_depth_distribution: fb.pause_depth.iter().map(|&v| finite_or(v, 0.0)).collect(),
        spoofing_indicator: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| finite_or(cl.spoofing_indicator, 0.0))
            .unwrap_or(0.0),
        sentence_initiation_ratio: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| finite_or(cl.sentence_initiation_ratio, 0.0))
            .unwrap_or(0.0),
        lrd_correlation: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| finite_or(cl.lrd_correlation, 0.0))
            .unwrap_or(0.0),
        iki_modality_score: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| finite_or(cl.iki_modality_score, 0.0))
            .unwrap_or(0.0),
        baseline_deviation: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| finite_or(cl.baseline_deviation, 0.0))
            .unwrap_or(0.0),
        dictation_plausibility,
        dictation_ratio,
        multi_speaker_detected,
        dictation_revision_density,
        dictation_disfluency_density,
        dictation_burst_cv,
        enhanced_signals: build_enhanced_signals(&metrics, &path),
        cross_modal: metrics.cross_modal.as_ref().map(|cm| FfiCrossModalResult {
            score: finite_or(cm.score, 0.0),
            verdict: cm.verdict.to_string(),
            checks: cm
                .checks
                .iter()
                .map(|c| FfiCrossModalCheck {
                    name: c.name.clone(),
                    passed: c.passed,
                    score: finite_or(c.score, 0.0),
                    detail: c.detail.clone(),
                })
                .collect(),
        }),
        focus: {
            let f = &metrics.focus;
            if f.switch_count > 0 || f.ai_app_switch_count > 0 {
                Some(FfiFocusMetrics {
                    switch_count: usize_u32(f.switch_count),
                    out_of_focus_ratio: f.out_of_focus_ratio.get(),
                    ai_app_switch_count: usize_u32(f.ai_app_switch_count),
                    avg_away_duration_sec: finite_or(f.avg_away_duration_sec, 0.0),
                    reading_pattern_detected: f.reading_pattern_detected,
                    mid_typing_switch_ratio: finite_or(f.mid_typing_switch_ratio, 0.0),
                })
            } else {
                None
            }
        },
        transcription_suspicion: metrics.transcription_suspicion.as_ref().map(|ts| {
            FfiTranscriptionSuspicion {
                is_suspicious: ts.is_suspicious,
                unexplained_correction_ratio: finite_or(ts.unexplained_correction_ratio, 0.0),
                ecology_score: finite_or(ts.ecology_score, 0.0),
                sample_count: usize_u32(ts.sample_count),
            }
        }),
        fatigue: metrics.fatigue_trajectory.as_ref().map(|ft| FfiFatigueMetrics {
            residual_sse: finite_or(ft.residual_sse, 0.0),
            warmup_fraction: finite_or(ft.warmup_fraction, 0.0),
            plateau_fraction: finite_or(ft.plateau_fraction, 0.0),
            fatigue_fraction: finite_or(ft.fatigue_fraction, 0.0),
            fatigue_slope_iki_per_kstroke: finite_or(ft.fatigue_slope_iki_per_kstroke, 0.0),
            dominant_phase: ft.dominant_phase,
        }),
        repair_locality: metrics.repair_locality.as_ref().map(|rl| FfiRepairLocality {
            mean_offset_chars: finite_or(rl.mean_offset_chars, 0.0),
            offset_cv: finite_or(rl.offset_cv, 0.0),
            recent_repair_pct: finite_or(rl.recent_repair_pct, 0.0),
            distant_repair_pct: finite_or(rl.distant_repair_pct, 0.0),
        }),
        clc: metrics.clc_metrics.as_ref().map(|c| FfiClcMetrics {
            mean_surprisal_bpw: finite_or(c.mean_surprisal_bpw, 0.0),
            std_dev_surprisal: finite_or(c.std_dev_surprisal, 0.0),
            low_surprisal_pct: finite_or(c.low_surprisal_pct, 0.0),
            iki_surprisal_correlation: finite_or(c.iki_surprisal_correlation, 0.0),
        }),
        segment_profiles: metrics
            .segment_profiles
            .iter()
            .map(|sp| FfiSegmentProfile {
                rel_path: sp.rel_path.clone(),
                is_prose: sp.is_prose,
                mean_bps: finite_or(sp.mean_bps, 0.0),
                max_bps: finite_or(sp.max_bps, 0.0),
                keystroke_count: sp.keystroke_count,
                high_velocity_bursts: usize_u32(sp.high_velocity_bursts),
            })
            .collect(),
        analysis_completed: metrics.analysis_status.completed,
        analysis_failed: metrics.analysis_status.failed,
        analysis_names: vec![
            "Perplexity", "PrimaryMetrics", "Cadence", "Hurst",
            "BiologicalCadence", "Behavioral", "Snr", "Lyapunov",
            "IkiCompression", "Labyrinth", "Clc", "RepairLocality",
            "Fatigue", "CognitiveLoad", "ErrorEcology", "LikelihoodModel",
            "CrossModal", "RevisionTopology", "Velocity",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        biological_cadence_score: fb.biological_cadence_score,
        steg_confidence: fb.steg_confidence,
        cadence_extended: Some(FfiCadenceExtended {
            zero_variance_windows: usize_u32(metrics.cadence.zero_variance_windows),
            mean_dwell_ns: finite_or(metrics.cadence.mean_dwell_ns, 0.0),
            dwell_cv: finite_or(metrics.cadence.dwell_cv, 0.0),
            mean_flight_ns: finite_or(metrics.cadence.mean_flight_ns, 0.0),
            flight_cv: finite_or(metrics.cadence.flight_cv, 0.0),
            iki_autocorrelation: finite_or(metrics.cadence.iki_autocorrelation, 0.0),
            post_pause_cv: finite_or(metrics.cadence.post_pause_cv, 0.0),
            cross_hand_timing_ratio: finite_or(metrics.cadence.cross_hand_timing_ratio, 0.0),
            planning_pause_rate: finite_opt(metrics.cadence.planning_pause_rate),
            translating_burst_ratio: finite_opt(metrics.cadence.translating_burst_ratio),
            revision_spike_count: metrics.cadence.revision_spike_count,
            structural_homogeneity_score: finite_opt(metrics.cadence.structural_homogeneity_score),
            clc_surprisal_score: finite_opt(metrics.cadence.clc_surprisal_score),
            repair_locality_mean_offset: finite_opt(metrics.cadence.repair_locality_mean_offset),
            fatigue_trajectory_residual: finite_opt(metrics.cadence.fatigue_trajectory_residual),
            fatigue_phase: metrics.cadence.fatigue_phase,
            percentiles: metrics.cadence.percentiles.iter().map(|&v| finite_or(v, 0.0)).collect(),
            avg_burst_length: finite_or(metrics.cadence.avg_burst_length, 0.0),
            avg_pause_duration_ns: finite_or(metrics.cadence.avg_pause_duration_ns, 0.0),
            is_robotic: metrics.cadence.is_robotic,
            median_iki_ns: finite_or(metrics.cadence.median_iki_ns, 0.0),
        }),
        snr: metrics.snr.as_ref().map(|s| FfiSnrAnalysis {
            snr_db: finite_or(s.snr_db, 0.0),
            flagged: s.flagged,
        }),
        lyapunov: metrics.lyapunov.as_ref().map(|l| FfiLyapunovAnalysis {
            exponent: finite_or(l.exponent, 0.0),
            flagged: l.flagged,
            confidence: finite_or(l.confidence, 0.0),
        }),
        iki_compression: metrics
            .iki_compression
            .as_ref()
            .map(|c| FfiIkiCompressionAnalysis {
                ratio: finite_or(c.ratio, 0.0),
                flagged: c.flagged,
            }),
        labyrinth: metrics.labyrinth.as_ref().map(|l| FfiLabyrinthAnalysis {
            correlation_dimension: finite_or(l.correlation_dimension, 0.0),
            recurrence_rate: finite_or(l.recurrence_rate, 0.0),
            determinism: finite_or(l.determinism, 0.0),
            rqa_entropy: finite_or(l.rqa_entropy, 0.0),
            confidence: finite_or(l.confidence, 0.0),
            is_valid: l.is_valid,
        }),
        forgery_cost: metrics.forgery_cost.as_ref().map(|fc| FfiForgeryEstimate {
            overall_difficulty: finite_or(fc.overall_difficulty, 0.0),
            estimated_forge_time_sec: finite_or(fc.estimated_forge_time_sec, 0.0),
            tier: fc.tier.to_string(),
            weakest_link: fc.weakest_link.clone(),
            components: fc
                .components
                .iter()
                .map(|c| FfiForgeryEstimateComponent {
                    name: c.name.clone(),
                    present: c.present,
                    cost_cpu_sec: finite_or(c.cost_cpu_sec, 0.0),
                    explanation: c.explanation.clone(),
                })
                .collect(),
        }),
        cross_window_matches: metrics
            .cross_window_matches
            .iter()
            .map(|m| FfiCrossWindowMatch {
                source_app: m.source_app.clone(),
                source_window_title: m.source_window_title.clone(),
                similarity_score: finite_or(m.similarity_score, 0.0),
                matched_length: usize_u32(m.matched_length),
                detected_at_epoch_ms: m.detected_at.timestamp_millis(),
            })
            .collect(),
        typing_metrics: metrics.typing_metrics.as_ref().map(|tm| FfiTypingMetrics {
            bps_mean: finite_or(tm.bps_mean, 0.0),
            bps_p95: finite_or(tm.bps_p95, 0.0),
            iki_p25: finite_or(tm.iki_p25, 0.0),
            iki_p50: finite_or(tm.iki_p50, 0.0),
            iki_p75: finite_or(tm.iki_p75, 0.0),
            cv: finite_or(tm.cv, 0.0),
            sample_count: usize_u32(tm.sample_count),
        }),
        revision_pattern: metrics.writing_mode.as_ref().map(|wm| FfiRevisionPattern {
            revision_cycle_count: usize_u32(wm.revision_pattern.revision_cycle_count),
            pure_append_stretch_count: usize_u32(wm.revision_pattern.pure_append_stretch_count),
            avg_revision_depth: finite_or(wm.revision_pattern.avg_revision_depth, 0.0),
            max_append_streak: usize_u32(wm.revision_pattern.max_append_streak),
            revision_fraction: finite_or(wm.revision_pattern.revision_fraction, 0.0),
        }),
        thinking_pause_ratio: fb.thinking_pause_ratio,
        burst_length_cv: metrics
            .writing_mode
            .as_ref()
            .map(|wm| finite_or(wm.burst_length_cv, 0.0))
            .unwrap_or(0.0),
        positive_negative_ratio: finite_or(profile.metrics.positive_negative_ratio.get(), 0.0),
        deletion_clustering: finite_or(profile.metrics.deletion_clustering, 0.0),
        timing_entropy: fb.timing_entropy,
        pause_entropy: fb.pause_entropy,
        ai_tools: live_ai_tools,
        session_stats: {
            let ss = &metrics.session_stats;
            if ss.session_count > 0 {
                Some(FfiSessionStats {
                    session_count: usize_u32(ss.session_count),
                    avg_session_duration_sec: finite_or(ss.avg_session_duration_sec, 0.0),
                    total_editing_time_sec: finite_or(ss.total_editing_time_sec, 0.0),
                    time_span_sec: finite_or(ss.time_span_sec, 0.0),
                })
            } else {
                None
            }
        },
        behavioral_fingerprint: metrics.behavioral.as_ref().map(|b| FfiBehavioralFingerprint {
            keystroke_interval_mean: finite_or(b.keystroke_interval_mean, 0.0),
            keystroke_interval_std: finite_or(b.keystroke_interval_std, 0.0),
            keystroke_interval_skewness: finite_or(b.keystroke_interval_skewness, 0.0),
            keystroke_interval_kurtosis: finite_or(b.keystroke_interval_kurtosis, 0.0),
            interval_buckets: b.interval_buckets.iter().map(|&v| finite_or(v, 0.0)).collect(),
            sentence_pause_mean: finite_or(b.sentence_pause_mean, 0.0),
            paragraph_pause_mean: finite_or(b.paragraph_pause_mean, 0.0),
            thinking_pause_frequency: finite_or(b.thinking_pause_frequency, 0.0),
            burst_length_mean: finite_or(b.burst_length_mean, 0.0),
            burst_speed_variance: finite_or(b.burst_speed_variance, 0.0),
        }),
        forgery_analysis: metrics.forgery_analysis.as_ref().map(|fa| FfiForgeryAnalysis {
            is_suspicious: fa.is_suspicious,
            confidence: finite_or(fa.confidence, 0.0),
            flags: fa.flags.iter().map(|f| f.to_string()).collect(),
        }),
        high_velocity_bursts: usize_u32(metrics.velocity.high_velocity_bursts),
        autocomplete_chars: metrics.velocity.autocomplete_chars,
        cursor_attention: live_cursor_attention,
        active_probes_score: metrics.active_probes.as_ref().map(|ap| finite_or(ap.combined_score, 0.0)),
        active_probes_valid: metrics.active_probes.as_ref().map(|ap| ap.all_valid),
        error_topology_score: metrics.error_topology.as_ref().map(|et| finite_or(et.score, 0.0)),
        error_topology_valid: metrics.error_topology.as_ref().map(|et| et.is_valid),
        spectral_slope: metrics.spectral_analysis.as_ref().map(|pn| finite_or(pn.spectral_slope, 0.0)),
        spectral_noise_type: metrics.spectral_analysis.as_ref().map(|pn| format!("{:?}", pn.noise_type)),
        spectral_valid: metrics.spectral_analysis.as_ref().map(|pn| pn.is_valid),
        baseline_mahalanobis: metrics.baseline_comparison.as_ref().map(|bc| finite_or(bc.mahalanobis_distance, 0.0)),
        baseline_anomalous: metrics.baseline_comparison.as_ref().map(|bc| bc.is_anomalous),
        language_scores: metrics.language_scores.as_ref().map(|ls| {
            ls.iter().map(|(k, &v)| FfiLanguageScore {
                category: k.clone(),
                score: finite_or(v, 0.0),
            }).collect()
        }).unwrap_or_default(),
        ai_fluency_flag: metrics.ai_fluency_flag,
        error_message: None,
    }
    })
    })
}

fn build_enhanced_signals(
    metrics: &crate::forensics::ForensicMetrics,
    path: &str,
) -> Option<FfiEnhancedSignals> {
    let has_any = metrics.cognitive_load.is_some()
        || metrics.revision_topology.is_some()
        || metrics.error_ecology.is_some()
        || metrics.likelihood_model.is_some()
        || metrics.composition_mode.is_some();
    if !has_any {
        return None;
    }

    let cognitive_load = metrics.cognitive_load.as_ref().map(|c| FfiCognitiveLoadSignals {
        score: finite_or(c.composite_score, 0.0),
        iki_surprisal_rho: finite_or(c.iki_surprisal_rho, 0.0),
        sentence_arc_r_squared: finite_or(c.sentence_arc_r_squared, 0.0),
        structural_pause_concentration: finite_or(c.structural_pause_concentration, 0.0),
        deep_pause_count: usize_u32(c.deep_pause_count),
        sentence_count: usize_u32(c.sentence_count),
        word_count: usize_u32(c.word_count),
        boundary_count: usize_u32(c.boundary_count),
        cognitive_mode: c.cognitive_mode().to_string(),
    });

    let revision_topology =
        metrics
            .revision_topology
            .as_ref()
            .map(|r| FfiRevisionTopologySignals {
                score: finite_or(r.composite_score, 0.0),
                branching_factor: finite_or(r.graph.mean_branching_factor, 0.0),
                revisit_depth: finite_or(r.graph.mean_revisit_depth, 0.0),
                frontier_distance: finite_or(r.graph.mean_frontier_distance, 0.0),
                active_region_count: usize_u32(r.graph.active_region_count),
                semantic_revision_ratio: finite_or(
                    r.revision_types.word_substitution_pct
                        + r.revision_types.clause_restructuring_pct
                        + r.revision_types.positional_insertion_pct,
                    0.0,
                ),
                sub_word_motor_pct: finite_or(r.revision_types.sub_word_motor_pct, 0.0),
                word_substitution_pct: finite_or(r.revision_types.word_substitution_pct, 0.0),
                clause_restructuring_pct: finite_or(r.revision_types.clause_restructuring_pct, 0.0),
                positional_insertion_pct: finite_or(r.revision_types.positional_insertion_pct, 0.0),
                total_revisions: usize_u32(r.revision_types.total_revisions),
                detour_ratio: finite_or(r.detour_ratio, 0.0),
                leading_edge_divergence: finite_or(r.leading_edge_divergence, 0.0),
                insertion_point_entropy: finite_or(r.insertion_point_entropy, 0.0),
            });

    let error_ecology = metrics.error_ecology.as_ref().map(|e| FfiErrorEcologySignals {
        score: finite_or(e.composite_score, 0.0),
        rapid_correction_pct: finite_or(e.rapid_self_correction_pct, 0.0),
        immediate_small_correction_pct: finite_or(e.immediate_small_correction_pct, 0.0),
        delayed_correction_pct: finite_or(e.delayed_correction_pct, 0.0),
        bulk_correction_pct: finite_or(e.bulk_correction_pct, 0.0),
        false_start_pct: finite_or(e.false_start_pct, 0.0),
        correction_rate: finite_or(e.correction_rate, 0.0),
        total_corrections: usize_u32(e.total_corrections),
        jsd_from_cognitive: finite_or(e.jsd_from_cognitive, 0.0),
        jsd_from_transcriptive: finite_or(e.jsd_from_transcriptive, 0.0),
    });

    let likelihood_model = metrics.likelihood_model.as_ref().map(|lm| {
        FfiLikelihoodSignals {
            p_cognitive: finite_or(lm.session_p_cognitive, 0.0),
            session_llr: finite_or(lm.session_llr, 0.0),
            mean_llr: finite_or(lm.mean_window_llr, 0.0),
            llr_std_dev: finite_or(lm.llr_std_dev, 0.0),
            min_window_llr: finite_or(lm.min_window_llr, 0.0),
            max_window_llr: finite_or(lm.max_window_llr, 0.0),
            cognitive_window_fraction: if lm.window_count > 0 {
                finite_or(lm.cognitive_window_count as f64 / lm.window_count as f64, 0.0)
            } else {
                0.0
            },
            window_count: usize_u32(lm.window_count),
            timeline: lm
                .window_timeline
                .iter()
                .map(|&(secs, p)| FfiLikelihoodTimelinePoint {
                    seconds_from_start: finite_or(secs, 0.0),
                    p_cognitive: finite_or(p, 0.0),
                })
                .collect(),
        }
    });

    // Populate composition mode from live sentinel session data.
    let composition_mode = metrics
        .composition_mode
        .as_ref()
        .map(build_composition_ffi)
        .or_else(|| {
            // Fall back to computing from sentinel if the pipeline didn't populate it.
            let sentinel = super::sentinel::get_sentinel()?;
            let sessions = sentinel.sessions();
            let session = sessions.iter().find(|s| s.path == path)?;
            let switches: Vec<_> = session.focus_switches.iter().cloned().collect();
            let pastes: Vec<_> = session
                .paste_context
                .iter()
                .cloned()
                .collect();
            let event_count = session.cognitive.keystroke_count();
            let cm = crate::forensics::composition_mode::analyze_composition_mode(
                &switches, &pastes, event_count,
            )?;
            Some(build_composition_ffi(&cm))
        });

    Some(FfiEnhancedSignals {
        cognitive_load,
        revision_topology,
        error_ecology,
        likelihood_model,
        composition_mode,
    })
}

fn build_composition_ffi(
    cm: &crate::forensics::composition_mode::CompositionModeMetrics,
) -> FfiCompositionModeSignals {
    FfiCompositionModeSignals {
        score: finite_or(cm.composite_score, 0.0),
        dominant_mode: cm
            .dominant_mode
            .map(|m| m.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        ai_cycle_count: usize_u32(cm.ai_cycle_count),
        paste_event_count: usize_u32(cm.paste_event_count),
        focus_switch_count: usize_u32(cm.focus_switch_count),
        pure_composition_pct: finite_or(cm.distribution.pure_composition, 0.0),
        reference_assisted_pct: finite_or(cm.distribution.reference_assisted, 0.0),
        paste_domesticate_pct: finite_or(cm.distribution.paste_domesticate, 0.0),
        paste_veneer_pct: finite_or(cm.distribution.paste_veneer, 0.0),
        ai_mediated_pct: finite_or(cm.distribution.ai_mediated, 0.0),
        paste_prose_count: usize_u32(cm.paste_content_breakdown.prose_count),
        paste_structured_data_count: usize_u32(cm.paste_content_breakdown.structured_data_count),
        paste_media_count: usize_u32(cm.paste_content_breakdown.media_count),
        paste_formatting_only_count: usize_u32(cm.paste_content_breakdown.formatting_only_count),
        paste_mixed_count: usize_u32(cm.paste_content_breakdown.mixed_count),
    }
}

/// Lightweight live scores for dashboard polling.
///
/// Reads the last-computed metrics from the sentinel session cache
/// without re-running the forensics pipeline. O(1) cost, safe to call
/// at 1Hz from the UI refresh loop.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiLiveScores {
    pub success: bool,
    /// Writing mode: "cognitive", "transcriptive", "mixed", "insufficient".
    pub writing_mode: String,
    /// Composite cognitive score (0.0-1.0).
    pub cognitive_score: f64,
    /// Assessment score (0.0-1.0, higher = more human-like).
    pub assessment_score: f64,
    /// Risk level: "low", "medium", "high", "insufficient data".
    pub risk_level: String,
    /// Total keystrokes in the current session.
    pub keystroke_count: u32,
    /// Session duration in seconds.
    pub session_duration_sec: f64,
    /// Real-time cadence score (0.0-1.0).
    pub cadence_score: f64,
    /// Current composition mode (if available).
    pub composition_mode: String,
    /// Evidence maturity (0.0-1.0): how much evidence has accumulated.
    pub evidence_maturity: f64,
    /// Recent words per minute from sliding window.
    pub words_per_minute: f64,
    /// Number of AI tools detected active during this session.
    pub ai_tools_active_count: u32,
    /// Number of capture gaps (dropped events) in this session.
    pub capture_gaps: u32,
    /// Evidence confidence: "full", "partial", or "heuristic".
    pub evidence_confidence: String,
    /// Why confidence was downgraded, if not full.
    pub confidence_reason: Option<String>,
    /// Whether transcription suspicion is flagged for this session.
    pub transcription_suspicious: bool,
    /// Downsampled IKI sparkline (~60 points, normalized 0.0-1.0).
    /// Empty if fewer than 10 keystrokes in the session.
    pub iki_sparkline: Vec<f64>,
    pub error_message: Option<String>,
}

fn live_scores_err(msg: &str) -> FfiLiveScores {
    FfiLiveScores {
        success: false,
        writing_mode: "insufficient".into(),
        cognitive_score: 0.0,
        assessment_score: 0.0,
        risk_level: "insufficient data".into(),
        keystroke_count: 0,
        session_duration_sec: 0.0,
        cadence_score: 0.0,
        composition_mode: "unknown".into(),
        evidence_maturity: 0.0,
        words_per_minute: 0.0,
        ai_tools_active_count: 0,
        capture_gaps: 0,
        evidence_confidence: "heuristic".into(),
        confidence_reason: None,
        transcription_suspicious: false,
        iki_sparkline: Vec::new(),
        error_message: Some(msg.to_string()),
    }
}

/// Fast live score polling for the dashboard.
///
/// Returns cached metrics from the sentinel session for the given path.
/// Does NOT re-run the forensics pipeline. Call `ffi_get_forensic_breakdown`
/// for full analysis.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_live_scores(path: String) -> FfiLiveScores {
    catch_ffi_panic!(live_scores_err("engine internal error"), {
    log::debug!("ffi_get_live_scores: path={}", path);
    let sentinel = match super::sentinel::get_sentinel() {
        Some(s) => s,
        None => return live_scores_err("Sentinel not running"),
    };

    let session = match sentinel.session(&path) {
        Ok(s) => s,
        Err(_) => return live_scores_err("No active session for this path"),
    };

    let keystroke_count = usize_u32(session.cognitive.keystroke_count());
    let duration = finite_or(
        session
            .start_time
            .elapsed()
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0),
        0.0,
    );

    // Cadence score from a trailing window of jitter samples.
    let window = recent_jitter_window(&session.jitter_samples, LIVE_CADENCE_WINDOW_NS);
    let cadence_score = finite_or(
        if window.len() < 10 {
            0.0
        } else {
            let metrics = crate::forensics::analyze_cadence(window);
            crate::forensics::compute_cadence_score(&metrics)
        },
        0.0,
    );

    // Blend multiple cached signals into a composite cognitive score.
    // The cadence score alone is a single IKI-based signal; adding the
    // cognitive accumulator's real-time analysis (sentence initiation,
    // spoofing indicator, editing patterns) and composition mode produces
    // a more accurate and responsive score.
    let cognitive_layer = session.cognitive.analyze();
    let editing_ratio = session.semantic_counts.editing_ratio();

    let switches: Vec<_> = session.focus_switches.iter().cloned().collect();
    let pastes: Vec<_> = session.paste_context.iter().cloned().collect();
    let comp_mode = crate::forensics::composition_mode::analyze_composition_mode(
        &switches,
        &pastes,
        keystroke_count as usize,
    );
    let composition_score = comp_mode.as_ref().map(|c| c.composite_score).unwrap_or(1.0);

    // Evidence maturity factor: sessions start with high assumed quality
    // (benefit of the doubt) and quality gates tighten as data accumulates.
    // At 20 keystrokes, maturity is ~0.04; at 200, ~0.4; at 500+, ~1.0.
    let maturity = (keystroke_count as f64 / 500.0).min(1.0);

    let (writing_mode, cognitive_score) = if keystroke_count < 20 {
        ("insufficient".to_string(), 0.8)
    } else {
        // Composite: 45% cadence, 25% cognitive layer, 15% composition, 15% editing
        let cognitive_prob = cognitive_layer
            .as_ref()
            .map(|cl| {
                // Weighted blend of cognitive signals. Spoofing indicator
                // acts as a penalty (high disagreement between signals).
                let raw = (cl.sentence_initiation_ratio.clamp(0.0, 1.0) * 0.4
                    + cl.iki_modality_score.clamp(0.0, 1.0) * 0.3
                    + cl.non_append_ratio.clamp(0.0, 0.5) * 0.3 * 2.0)
                    .clamp(0.0, 1.0);
                let spoof_penalty = cl.spoofing_indicator.clamp(0.0, 0.3);
                (raw - spoof_penalty).max(0.0)
            })
            .unwrap_or(cadence_score);

        let editing_signal = if editing_ratio > 0.15 {
            1.0 // Substantial editing = cognitive authoring
        } else if editing_ratio > 0.05 {
            0.6
        } else {
            0.2 // Append-only = likely transcriptive
        };

        let measured = cadence_score * 0.45
            + cognitive_prob * 0.25
            + composition_score * 0.15
            + editing_signal * 0.15;

        // Blend measured score with a generous prior (0.8) based on data maturity.
        // Early session: mostly prior (benefit of the doubt).
        // Mature session: mostly measured (evidence-driven).
        let mut composite = measured * maturity + 0.8 * (1.0 - maturity);

        if session.transcription_suspicion.is_suspicious {
            composite -= 0.15 * maturity;
        }
        if !session.ai_tools_detected.is_empty() {
            composite -= 0.10 * maturity;
        }
        let composite = composite.clamp(0.0, 1.0);

        // Hysteresis: use the previous mode to bias thresholds so the label
        // doesn't flicker. Entering "transcriptive" requires a lower score
        // than leaving it requires a higher one.
        // Hysteresis: biased thresholds based on previous mode.
        // Entering a state requires crossing a higher bar than staying in it.
        let prev_mode = session.last_writing_mode.as_deref().unwrap_or("insufficient");
        let mode = match prev_mode {
            "transcriptive" => {
                if composite >= 0.55 { "cognitive" } else if composite >= 0.45 { "mixed" } else { "transcriptive" }
            }
            "cognitive" => {
                if composite >= 0.45 { "cognitive" } else if composite >= 0.25 { "mixed" } else { "transcriptive" }
            }
            _ => {
                if composite >= 0.55 { "cognitive" } else if composite < 0.35 { "transcriptive" } else { "mixed" }
            }
        };
        (mode.to_string(), composite)
    };

    // Persist writing mode for hysteresis on next poll.
    {
        use crate::RwLockRecover as _;
        let mut sessions = sentinel.sessions.write_recover();
        if let Some(s) = sessions.get_mut(path.as_str()) {
            s.last_writing_mode = Some(writing_mode.clone());
        }
    }

    let risk_level = if cognitive_score >= 0.7 {
        "low"
    } else if cognitive_score >= 0.4 {
        "medium"
    } else if keystroke_count < 10 {
        "insufficient data"
    } else {
        "high"
    };

    let focused_secs = session.total_focus_ms as f64 / 1000.0;
    let evidence_maturity = finite_or(
        crate::forensics::scoring::evidence_maturity(keystroke_count as u64, focused_secs),
        0.0,
    );

    FfiLiveScores {
        success: true,
        writing_mode,
        cognitive_score,
        assessment_score: cadence_score,
        risk_level: risk_level.to_string(),
        keystroke_count,
        session_duration_sec: duration,
        cadence_score,
        composition_mode: comp_mode
            .and_then(|c| c.dominant_mode)
            .map(|m| m.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        evidence_maturity,
        words_per_minute: finite_or(session.recent_wpm(), 0.0),
        ai_tools_active_count: usize_u32(session.ai_tools_detected.len()),
        capture_gaps: session.capture_gaps,
        evidence_confidence: session.evidence_confidence.to_string(),
        confidence_reason: session.confidence_reason.clone(),
        transcription_suspicious: session.transcription_suspicion.is_suspicious,
        iki_sparkline: downsample_iki_sparkline(&session.jitter_samples, 60, 10),
        error_message: None,
    }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_scores_no_sentinel_returns_error() {
        // In test context, sentinel is never initialized.
        let result = ffi_get_live_scores("/tmp/nonexistent.txt".to_string());
        assert!(!result.success);
        assert_eq!(result.writing_mode, "insufficient");
        assert_eq!(result.risk_level, "insufficient data");
        assert_eq!(result.keystroke_count, 0);
        assert!(result.error_message.is_some());
        assert!(
            result.error_message.as_ref().unwrap().contains("Sentinel"),
            "Error should mention sentinel: {:?}",
            result.error_message,
        );
    }

    #[test]
    fn live_scores_default_numeric_fields_are_zero() {
        let result = ffi_get_live_scores("/tmp/no_session.txt".to_string());
        assert!(!result.success);
        assert_eq!(result.cognitive_score, 0.0);
        assert_eq!(result.assessment_score, 0.0);
        assert_eq!(result.session_duration_sec, 0.0);
        assert_eq!(result.cadence_score, 0.0);
        assert_eq!(result.composition_mode, "unknown");
    }
}
