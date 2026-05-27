// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Core types, constants, and enums for forensic analysis.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::utils::Probability;

use crate::analysis::{
    BehavioralFingerprint, ForgeryAnalysis, IkiCompressionAnalysis, LabyrinthAnalysis,
    LyapunovAnalysis, SnrAnalysis,
};
use crate::forensics::cross_modal::CrossModalResult;
use crate::forensics::forgery_cost::ForgeryCostEstimate;
use crate::forensics::writing_mode::WritingModeAnalysis;
use authorproof_protocol::forensics::{
    ForensicAnalysis as ProtocolForensicAnalysis, ForensicVerdict,
};

/// Edits past this position (95%) count as "append".
pub const DEFAULT_APPEND_THRESHOLD: f32 = 0.95;

/// Bin count for edit entropy histogram.
pub const DEFAULT_HISTOGRAM_BINS: usize = 20;

/// Minimum events for stable analysis.
pub const MIN_EVENTS_FOR_ANALYSIS: usize = 5;

/// Minimum events for a verdict.
pub const MIN_EVENTS_FOR_ASSESSMENT: usize = 10;

/// Session gap threshold: 30 minutes.
pub const DEFAULT_SESSION_GAP_SEC: f64 = 1800.0;

/// Above this append ratio, AI generation is suspected.
pub const THRESHOLD_MONOTONIC_APPEND: f64 = 0.85;

/// Per-type entropy thresholds from draft-condrey-rats-pop-appraisal.
/// Each is checked against its corresponding metric in assessment.rs.
pub const THRESHOLD_TIMING_ENTROPY: f64 = 3.0;
pub const THRESHOLD_REVISION_ENTROPY: f64 = 3.0;
pub const THRESHOLD_PAUSE_ENTROPY: f64 = 2.0;

/// Bytes/sec above which velocity is flagged as anomalous.
pub const THRESHOLD_HIGH_VELOCITY_BPS: f64 = 100.0;

/// Gap longer than this (hours) triggers an anomaly.
pub const THRESHOLD_GAP_HOURS: f64 = 24.0;

/// Alert-level anomalies needed for `Suspicious` verdict.
pub const ALERT_THRESHOLD: usize = 2;

/// CV below this indicates robotic typing.
pub const ROBOTIC_CV_THRESHOLD: f64 = 0.15;

/// Estimated fraction of keystrokes that are deletions.
pub const DEFAULT_EDIT_RATIO: f64 = 0.15;

/// Discrepancy ratio above this is `Suspicious`.
pub const SUSPICIOUS_RATIO_THRESHOLD: f64 = 0.3;

/// Discrepancy ratio above this is `Inconsistent`.
pub const INCONSISTENT_RATIO_THRESHOLD: f64 = 0.5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventData {
    pub id: i64,
    pub timestamp_ns: i64,
    pub file_size: i64,
    pub size_delta: i32,
    pub file_path: String,
}

impl EventData {
    /// Convert a slice of `SecureEvent` into forensic `EventData` records.
    pub fn from_secure_events(events: &[crate::store::SecureEvent]) -> Vec<Self> {
        events
            .iter()
            .enumerate()
            .map(|(i, e)| Self {
                id: e.id.unwrap_or(i64::try_from(i).unwrap_or(i64::MAX)),
                timestamp_ns: e.timestamp_ns,
                file_size: e.file_size,
                size_delta: e.size_delta,
                file_path: e.file_path.clone(),
            })
            .collect()
    }
}

/// Newtype guaranteeing events are sorted by `timestamp_ns` ascending.
///
/// Sort once at the forensics pipeline entry (`analyze_forensics_ext_with_focus`)
/// and pass this to all analyzers to avoid redundant per-analyzer sorts.
#[derive(Clone, Copy, Debug)]
pub struct SortedEvents<'a>(&'a [EventData]);

impl<'a> SortedEvents<'a> {
    /// Wrap a pre-sorted slice. Debug-asserts the sort invariant.
    pub fn new(events: &'a [EventData]) -> Self {
        debug_assert!(
            events
                .windows(2)
                .all(|w| w[0].timestamp_ns <= w[1].timestamp_ns),
            "SortedEvents::new requires pre-sorted events"
        );
        Self(events)
    }

    /// Return the underlying slice with its original `'a` lifetime.
    pub fn as_slice(self) -> &'a [EventData] {
        self.0
    }
}

impl<'a> std::ops::Deref for SortedEvents<'a> {
    type Target = [EventData];
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionData {
    /// Position in document as fraction `[0.0, 1.0]`.
    pub start_pct: f32,
    /// Position in document as fraction `[0.0, 1.0]`.
    pub end_pct: f32,
    /// +1 insertion, -1 deletion, 0 replacement.
    pub delta_sign: i8,
    pub byte_count: i32,
}

/// Compute estimated cursor position and edit extent from file size trajectory.
///
/// Returns `(cursor_pct, extent)` both clamped to `[0.0, 1.0]`.
pub fn compute_edit_extents(file_size: i64, size_delta: i32, max_file_size: f32) -> (f32, f32) {
    let max = max_file_size.max(1.0);
    let cursor = ((file_size as f32 - size_delta.unsigned_abs() as f32) / max).clamp(0.0, 1.0);
    let extent = (size_delta.unsigned_abs() as f32 / max).clamp(0.0, 1.0);
    (cursor, extent)
}

/// Build per-event edit region maps from secure events.
///
/// Each event with an `id` gets a single `RegionData` entry derived from its
/// file size and size delta via `compute_edit_extents`.
pub fn build_edit_regions(
    events: &[crate::store::SecureEvent],
) -> std::collections::HashMap<i64, Vec<RegionData>> {
    let max_file_size = events.iter().map(|e| e.file_size.max(1)).max().unwrap_or(1) as f32;
    let mut regions = std::collections::HashMap::new();
    for e in events {
        if let Some(id) = e.id {
            let delta = e.size_delta;
            let sign = if delta > 0 {
                1
            } else if delta < 0 {
                -1
            } else {
                0
            };
            let (cursor_pct, extent) = compute_edit_extents(e.file_size, delta, max_file_size);
            let end_pct = (cursor_pct + extent).min(1.0);
            regions.insert(
                id,
                vec![RegionData {
                    start_pct: cursor_pct,
                    end_pct,
                    delta_sign: sign,
                    byte_count: delta.abs(),
                }],
            );
        }
    }
    regions
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrimaryMetrics {
    /// Fraction of edits at document end (>0.95 position).
    pub monotonic_append_ratio: Probability,
    /// Shannon entropy of edit positions (20-bin histogram).
    /// This is the spec's "revision entropy".
    pub edit_entropy: f64,
    /// Shannon entropy of inter-keystroke intervals (timing diversity).
    /// Per draft-condrey-rats-pop; threshold: 3.0 bits.
    #[serde(default)]
    pub timing_entropy: f64,
    /// Shannon entropy of pause durations (pause diversity).
    /// Per draft-condrey-rats-pop; threshold: 2.0 bits.
    #[serde(default)]
    pub pause_entropy: f64,
    /// Median inter-event interval (seconds).
    pub median_interval: f64,
    /// `insertions / (insertions + deletions)`.
    pub positive_negative_ratio: Probability,
    /// Nearest-neighbor distance ratio for deletions (<1 = clustered).
    pub deletion_clustering: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CadenceMetrics {
    pub mean_iki_ns: f64,
    pub std_dev_iki_ns: f64,
    /// `std_dev / mean`
    pub coefficient_of_variation: f64,
    pub median_iki_ns: f64,
    pub burst_count: usize,
    /// Pauses > 2s.
    pub pause_count: usize,
    pub avg_burst_length: f64,
    pub avg_pause_duration_ns: f64,
    /// CV below `ROBOTIC_CV_THRESHOLD`.
    pub is_robotic: bool,
    /// IKI percentiles: p10, p25, p50, p75, p90.
    pub percentiles: [f64; 5],
    /// Ratio of cross-hand IKI std_dev to same-hand IKI std_dev.
    /// Human typing shows >1.3; transcriptive <1.1.
    pub cross_hand_timing_ratio: f64,
    /// CV of the first 5 keystrokes after each pause (>1s).
    /// Cognitive >0.25; transcriptive <0.15.
    pub post_pause_cv: f64,
    /// Lag-1 autocorrelation of IKI sequence.
    /// Cognitive: -0.1 to 0.2; transcriptive: >0.3.
    pub iki_autocorrelation: f64,
    /// Fraction of keystrokes that are backspace/delete (zone 0xFF).
    /// Cognitive >0.05; transcriptive <0.02.
    pub correction_ratio: Probability,
    /// Distribution of pause durations: [sentence_1_3s, paragraph_3_10s, deep_thought_10s_plus].
    pub pause_depth_distribution: [f64; 3],
    /// CV of typing speeds within individual bursts. Transcriptive <0.15;
    /// cognitive >0.25 (natural speed variation within each burst).
    pub burst_speed_cv: f64,
    /// Count of 500ms windows with near-zero IKI variance (sigma < 5ms).
    /// Any non-zero count is suspicious; >3 strongly indicates transcription.
    pub zero_variance_windows: usize,
    /// Mean key hold duration (keyDown to keyUp) in nanoseconds.
    /// Human typing: 80-150ms typical. Synthetic: very consistent or very short.
    pub mean_dwell_ns: f64,
    /// CV of dwell times. Human: >0.2 (variable hold durations).
    /// Robotic: <0.1 (perfectly consistent hold times).
    pub dwell_cv: f64,
    /// Mean flight time (keyUp to next keyDown) in nanoseconds.
    /// Represents the gap between releasing one key and pressing the next.
    pub mean_flight_ns: f64,
    /// CV of flight times. Human: >0.3 (variable transition times).
    pub flight_cv: f64,
    /// Cognitive-Linguistic Complexity: n-gram surprisal score.
    /// Higher values indicate more natural/diverse language patterns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clc_surprisal_score: Option<f64>,
    /// Repair locality tracking: mean offset of backspace events relative to cursor.
    /// Human edits cluster repairs near recent text (low offset); synthetic edits scattered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_locality_mean_offset: Option<f64>,
    /// Coefficient of variation for repair localities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_locality_cv: Option<f64>,
    /// Three-phase fatigue trajectory: residual from flat baseline model.
    /// Positive indicates fatigue (rising IKI over time); negative indicates improvement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fatigue_trajectory_residual: Option<f64>,
    /// Phase classification from fatigue model: 0=warmup, 1=plateau, 2=fatigue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fatigue_phase: Option<u8>,
    /// CV of inter-pause-gap lengths. AI-transcribed text has abnormally uniform
    /// pause gaps (CV < 0.15 is suspicious). Higher = more naturally variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structural_homogeneity_score: Option<f64>,
    /// Planning pause rate: fraction of keystrokes preceded by a >2s pause.
    /// Composition ~0.062, transcription ~0.007-0.009 (diary calibration data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planning_pause_rate: Option<f64>,
    /// Fraction of bursts that are pure translating (forward typing only).
    /// `translating / (translating + revising)` per checkpoint-style counting.
    /// Composition ~0.40, transcription ~0.81 (diary calibration data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub translating_burst_ratio: Option<f64>,
    /// Count of 50-event windows where revision density exceeds 2x session
    /// baseline + 0.02. Composition produces revision spikes; transcription does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_spike_count: Option<u32>,
}

/// Cognitive-Linguistic Complexity metrics from n-gram surprisal analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClcMetrics {
    /// Mean surprisal (bits per word) across all checkpoint windows.
    /// Higher = more natural/diverse; lower = more predictable/mechanical.
    pub mean_surprisal_bpw: f64,
    /// Standard deviation of surprisal across windows.
    pub std_dev_surprisal: f64,
    /// Percentage of windows with low surprisal (<3 bpw), indicating formulaic text.
    pub low_surprisal_pct: f64,
    /// Correlation coefficient between IKI samples and surprisal in the same window.
    /// Near 0 = no correlation; positive = faster typing during predictable text.
    pub iki_surprisal_correlation: f64,
}

/// Repair locality tracking: document offset of backspace events relative to cursor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepairLocalityMetrics {
    /// Mean document offset (characters) of backspace target from cursor position.
    /// Human: clusters near recent text (5-20 chars); synthetic: scattered (50+ chars).
    pub mean_offset_chars: f64,
    /// Coefficient of variation of repair offsets.
    /// Human: <0.5 (focused repairs); synthetic: >1.0 (scattered).
    pub offset_cv: f64,
    /// Percentage of repairs within recent window (0-10 chars from cursor).
    pub recent_repair_pct: f64,
    /// Percentage of repairs scattered far from cursor (>50 chars).
    pub distant_repair_pct: f64,
}

/// Three-phase fatigue trajectory: warmup, plateau, fatigue phases in IKI sequence.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FatigueTrajectoryMetrics {
    /// Piecewise linear fit residual (sum of squared errors from baseline).
    /// Lower = better fit to fatigue model; higher = constant/random pattern.
    pub residual_sse: f64,
    /// Phase 0 duration (warmup): fraction of session before plateau.
    pub warmup_fraction: f64,
    /// Phase 1 duration (plateau): fraction of stable typing speed.
    pub plateau_fraction: f64,
    /// Phase 2 duration (fatigue): fraction of increasing IKI (tiredness).
    pub fatigue_fraction: f64,
    /// Slope of Phase 2 (fatigue phase): IKI increase per 1000 keystrokes.
    /// Positive = IKI increasing (fatigue); negative = improvement.
    pub fatigue_slope_iki_per_kstroke: f64,
    /// Dominant phase: 0=warmup, 1=plateau, 2=fatigue, 3=insufficient data.
    pub dominant_phase: u8,
}

/// Focus pattern metrics for cognitive/transcriptive analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FocusMetrics {
    /// Total number of focus switches during editing.
    pub switch_count: usize,
    /// Fraction of editing time spent out-of-focus.
    pub out_of_focus_ratio: Probability,
    /// Number of switches to known AI/browser apps.
    pub ai_app_switch_count: usize,
    /// Average duration of focus-away periods in seconds.
    pub avg_away_duration_sec: f64,
    /// Whether the pattern suggests reading from external source.
    pub reading_pattern_detected: bool,
    /// Fraction of focus switches that occurred within 2s of a keystroke event.
    /// High ratio (>0.5) indicates reference-checking during active composition (cognitive).
    /// Low ratio (<0.2) indicates content staging between typing bursts (transcriptive).
    pub mid_typing_switch_ratio: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForensicMetrics {
    pub primary: PrimaryMetrics,
    pub cadence: CadenceMetrics,
    pub behavioral: Option<BehavioralFingerprint>,
    pub forgery_analysis: Option<ForgeryAnalysis>,
    pub velocity: VelocityMetrics,
    pub session_stats: SessionStats,
    /// `[0.0, 1.0]` -- higher = more human-like.
    pub assessment_score: Probability,
    /// Lower = more expected/human-like.
    pub perplexity_score: f64,
    /// Confidence that timing steganography is present.
    pub steg_confidence: Probability,
    pub anomaly_count: usize,
    pub risk_level: RiskLevel,
    /// Biological cadence steadiness score (0.0-1.0, higher = steadier).
    pub biological_cadence_score: Probability,
    /// Cross-modal consistency analysis (keystroke/content/jitter coherence).
    pub cross_modal: Option<CrossModalResult>,
    /// Forgery cost estimation for user-adversary threat model.
    pub forgery_cost: Option<ForgeryCostEstimate>,
    /// Number of checkpoints in the evidence chain (distinct from session_count).
    pub checkpoint_count: usize,
    /// Hurst exponent from cadence timing analysis, if computed.
    pub hurst_exponent: Option<f64>,
    pub snr: Option<SnrAnalysis>,
    pub lyapunov: Option<LyapunovAnalysis>,
    pub iki_compression: Option<IkiCompressionAnalysis>,
    pub labyrinth: Option<LabyrinthAnalysis>,
    /// Focus-switching pattern analysis.
    pub focus: FocusMetrics,
    /// Writing mode classification (cognitive vs. transcriptive).
    pub writing_mode: Option<WritingModeAnalysis>,
    /// Cross-window transcription matches detected during the session.
    #[serde(default)]
    pub cross_window_matches: Vec<crate::transcription::CrossWindowMatch>,
    /// Cognitive-Linguistic Complexity metrics (CLC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clc_metrics: Option<ClcMetrics>,
    /// Repair locality tracking metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_locality: Option<RepairLocalityMetrics>,
    /// Three-phase fatigue trajectory analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fatigue_trajectory: Option<FatigueTrajectoryMetrics>,
    /// Text fragment provenance metrics (composition ratios, source trust).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<super::provenance_metrics::ProvenanceMetrics>,
    /// Per-chapter/segment velocity profiles for bundle documents (.scriv, .fdx, Vellum).
    /// Empty for non-bundle sessions. Non-prose segments (synopsis, metadata) are flagged
    /// `is_prose: false` and excluded from the aggregate behavioral authenticity score.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub segment_profiles: Vec<SegmentVelocityProfile>,
    /// Cognitive load-timing entanglement metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cognitive_load: Option<super::cognitive_load::CognitiveLoadMetrics>,
    /// Revision topology and semantic delta metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_topology: Option<super::revision_topology::RevisionTopologyMetrics>,
    /// Error ecology classification metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_ecology: Option<super::error_ecology::ErrorEcologyMetrics>,
    /// Composition mode state machine metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composition_mode: Option<super::composition_mode::CompositionModeMetrics>,
    /// Per-window generative likelihood model metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub likelihood_model: Option<super::likelihood_model::LikelihoodModelMetrics>,
    /// Tracks which analyses completed successfully vs. failed/skipped.
    #[serde(default)]
    pub analysis_status: AnalysisStatus,
    /// Real-time transcription suspicion assessment from error ecology streaming.
    /// Present when the sentinel evaluated correction patterns during live capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcription_suspicion: Option<super::error_ecology::TranscriptionSuspicion>,
    /// Pre-computed unified typing metrics (BPS, IKI percentiles, CV).
    /// Computed once from IKI intervals, available for downstream consumers
    /// to avoid redundant percentile calculations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typing_metrics: Option<TypingMetrics>,
    /// Active probe results (Galton invariant + reflex gate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_probes: Option<crate::analysis::ActiveProbeResults>,
    /// Error topology analysis (correction patterns, key adjacency).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_topology: Option<crate::analysis::ErrorTopology>,
    /// Spectral analysis (FFT-based noise classification).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spectral_analysis: Option<crate::analysis::PinkNoiseAnalysis>,
    /// Behavioral fingerprint baseline comparison (Mahalanobis distance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_comparison: Option<crate::analysis::BaselineComparison>,
    /// Per-category language classification scores.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language_scores: Option<std::collections::HashMap<String, f64>>,
    /// Word-trigram perplexity below AI fluency threshold.
    #[serde(default)]
    pub ai_fluency_flag: bool,
}

/// Bitfield tracking which forensic analyses completed successfully.
///
/// When an analysis fails or is skipped (insufficient data, computation error),
/// the corresponding bit remains unset. Consumers can use this to:
/// - Lower confidence when key analyses were unavailable
/// - Distinguish "metric is zero because input was clean" from "metric was never computed"
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisStatus {
    /// Bitfield of completed analyses. Each bit corresponds to an [`AnalysisKind`].
    pub completed: u32,
    /// Bitfield of analyses that failed (error, not just skipped for insufficient data).
    pub failed: u32,
}

/// Individual analysis types tracked by [`AnalysisStatus`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisKind {
    Perplexity = 0,
    PrimaryMetrics = 1,
    Cadence = 2,
    Hurst = 3,
    BiologicalCadence = 4,
    Behavioral = 5,
    Snr = 6,
    Lyapunov = 7,
    IkiCompression = 8,
    Labyrinth = 9,
    Clc = 10,
    RepairLocality = 11,
    Fatigue = 12,
    CognitiveLoad = 13,
    ErrorEcology = 14,
    LikelihoodModel = 15,
    CrossModal = 16,
    RevisionTopology = 17,
    Velocity = 18,
}

impl AnalysisStatus {
    /// Mark an analysis as successfully completed.
    pub fn mark_completed(&mut self, kind: AnalysisKind) {
        self.completed |= 1 << (kind as u8);
    }

    /// Mark an analysis as failed (error during computation).
    pub fn mark_failed(&mut self, kind: AnalysisKind) {
        self.failed |= 1 << (kind as u8);
    }

    /// Check if an analysis completed successfully.
    pub fn is_completed(&self, kind: AnalysisKind) -> bool {
        self.completed & (1 << (kind as u8)) != 0
    }

    /// Check if an analysis failed.
    pub fn is_failed(&self, kind: AnalysisKind) -> bool {
        self.failed & (1 << (kind as u8)) != 0
    }

    /// Count how many analyses completed successfully.
    pub fn completed_count(&self) -> u32 {
        self.completed.count_ones()
    }

    /// Count how many analyses failed.
    pub fn failed_count(&self) -> u32 {
        self.failed.count_ones()
    }

    /// Fraction of attempted analyses that succeeded (0.0-1.0).
    /// Returns 1.0 if no analyses were attempted.
    pub fn success_ratio(&self) -> f64 {
        let attempted = self.completed | self.failed;
        let total = attempted.count_ones();
        if total == 0 {
            return 1.0;
        }
        self.completed.count_ones() as f64 / total as f64
    }
}

/// Jitter-derived entropy quality metrics for evidence confidence scaling.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JitterQuality {
    /// Shannon entropy of IKI intervals (bits). Higher = more random = more human.
    pub entropy_bits: f64,
    /// Fraction of keyboard zones observed (0.0-1.0). Higher = more coverage.
    pub zone_coverage: f64,
    /// Number of jitter samples contributing to this assessment.
    pub sample_count: usize,
}

impl JitterQuality {
    /// Compute a confidence scaling factor in [0.0, 1.0] based on jitter quality.
    /// Used by the evidence builder to modulate packet confidence.
    pub fn confidence_factor(&self) -> f64 {
        const MIN_ACCEPTABLE_ENTROPY: f64 = 3.0;
        const MIN_ACCEPTABLE_SAMPLES: usize = 20;
        const MIN_ACCEPTABLE_ZONE_COVERAGE: f64 = 0.3;

        if self.sample_count < MIN_ACCEPTABLE_SAMPLES {
            return 0.5; // Insufficient data — partial confidence
        }
        let entropy_factor = (self.entropy_bits / MIN_ACCEPTABLE_ENTROPY).min(1.0);
        let zone_factor = (self.zone_coverage / MIN_ACCEPTABLE_ZONE_COVERAGE).min(1.0);
        (entropy_factor * 0.7 + zone_factor * 0.3).clamp(0.0, 1.0)
    }
}

/// Forensic gate result for checkpoint creation decisions.
#[derive(Debug, Clone)]
pub enum ForensicGateVerdict {
    /// Proceed normally with checkpoint creation.
    Proceed,
    /// Checkpoint allowed but flagged as low-confidence.
    LowConfidence { reason: String },
    /// Increase VDF cost multiplier before creating checkpoint.
    IncreaseCost { multiplier: u32, reason: String },
}

/// Per-segment velocity and prose-classification metrics for bundle documents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SegmentVelocityProfile {
    /// Path relative to the bundle root (e.g. `"Files/Data/<UUID>/content.rtf"`).
    pub rel_path: String,
    /// `true` if the segment contains prose content eligible for behavioral scoring.
    pub is_prose: bool,
    /// Mean bytes/second edit velocity for this segment.
    pub mean_bps: f64,
    /// Peak bytes/second burst recorded for this segment.
    pub max_bps: f64,
    /// Total keystroke count attributed to this segment.
    pub keystroke_count: u64,
    /// Number of velocity bursts exceeding `THRESHOLD_HIGH_VELOCITY_BPS`.
    pub high_velocity_bursts: usize,
}

/// Pre-computed typing metrics shared across scoring, cadence, and velocity modules.
///
/// Computed once from raw IKI intervals, consumed by multiple downstream analyses
/// to avoid redundant BPS/percentile calculations.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TypingMetrics {
    /// Mean bytes per second across prose segments.
    pub bps_mean: f64,
    /// 95th percentile BPS.
    pub bps_p95: f64,
    /// Inter-keystroke interval percentiles: p25, p50, p75.
    pub iki_p25: f64,
    pub iki_p50: f64,
    pub iki_p75: f64,
    /// Coefficient of variation of IKI intervals.
    pub cv: f64,
    /// Number of IKI samples used for computation.
    pub sample_count: usize,
}

impl TypingMetrics {
    /// Compute unified typing metrics from raw IKI intervals (nanoseconds).
    pub fn from_iki_ns(ikis: &[f64]) -> Self {
        if ikis.len() < 2 {
            return Self::default();
        }

        let n = ikis.len();
        let mean = ikis.iter().sum::<f64>() / n as f64;
        let variance = ikis.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        let std_dev = variance.sqrt();
        let cv = if mean > 0.0 { std_dev / mean } else { 0.0 };

        // Percentiles via partial sort
        let mut buf = ikis.to_vec();
        let cmp = |a: &f64, b: &f64| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
        let pct_idx = |p: usize| -> usize {
            ((p as f64 / 100.0 * (n - 1) as f64).round() as usize).min(n - 1)
        };

        let i25 = pct_idx(25);
        let i50 = pct_idx(50);
        let i75 = pct_idx(75);
        let i95 = pct_idx(95);

        buf.select_nth_unstable_by(i95, cmp);
        let bps_p95_ns = buf[i95];
        buf.select_nth_unstable_by(i75, cmp);
        let iki_p75 = buf[i75];
        buf.select_nth_unstable_by(i50, cmp);
        let iki_p50 = buf[i50];
        buf.select_nth_unstable_by(i25, cmp);
        let iki_p25 = buf[i25];

        // Convert mean IKI (ns) to BPS: 1 keystroke per mean_iki_ns
        let bps_mean = if mean > 0.0 { 1e9 / mean } else { 0.0 };
        let bps_p95 = if bps_p95_ns > 0.0 {
            1e9 / bps_p95_ns
        } else {
            0.0
        };

        Self {
            bps_mean,
            bps_p95,
            iki_p25,
            iki_p50,
            iki_p75,
            cv,
            sample_count: n,
        }
    }
}

impl ForensicMetrics {
    /// Map to protocol-standard `ForensicVerdict`.
    pub fn map_to_protocol_verdict(&self) -> ForensicVerdict {
        if let Some(forgery) = &self.forgery_analysis {
            if forgery.is_suspicious {
                // V4, not V5: a single heuristic flag is insufficient to confirm forgery.
                // V5ConfirmedForgery requires broken chain integrity (handled in verify()).
                return ForensicVerdict::V4LikelySynthetic;
            }
        }

        // Cross-modal inconsistency is strong evidence of forgery
        if let Some(cm) = &self.cross_modal {
            if cm.verdict == crate::forensics::cross_modal::CrossModalVerdict::Inconsistent {
                return ForensicVerdict::V4LikelySynthetic;
            }
        }

        // Cross-window transcription: high-similarity match against visible windows
        if self
            .cross_window_matches
            .iter()
            .any(|m| m.similarity_score >= 0.80)
        {
            return ForensicVerdict::V3Suspicious;
        }

        // High ratio of unverified sourced content is suspicious
        if let Some(ref prov) = self.provenance {
            if prov.sourced_unknown_ratio > 0.5 && prov.source_trustworthiness < 0.3 {
                return ForensicVerdict::V3Suspicious;
            }
        }

        // Likelihood model: strong transcriptive posterior across all windows
        if let Some(ref lm) = self.likelihood_model {
            if lm.session_p_cognitive < 0.15 && lm.window_count >= 3 {
                return ForensicVerdict::V3Suspicious;
            }
        }

        // Composition mode: dominant AI-mediated or paste-veneer
        if let Some(ref cm) = self.composition_mode {
            if cm.composite_score < 0.15 && cm.ai_cycle_count >= 3 {
                return ForensicVerdict::V3Suspicious;
            }
        }

        match self.risk_level {
            RiskLevel::Low => {
                // V1 requires high confidence AND sufficient analysis coverage.
                // If >25% of attempted analyses failed, cap at V2.
                if self.assessment_score > 0.9 && self.analysis_status.success_ratio() >= 0.75 {
                    ForensicVerdict::V1VerifiedHuman
                } else {
                    ForensicVerdict::V2LikelyHuman
                }
            }
            RiskLevel::Medium => ForensicVerdict::V3Suspicious,
            RiskLevel::High => {
                if self.cadence.is_robotic {
                    ForensicVerdict::V4LikelySynthetic
                } else {
                    ForensicVerdict::V3Suspicious
                }
            }
            RiskLevel::Insufficient => ForensicVerdict::V6InsufficientData,
        }
    }

    /// Convert to `ProtocolForensicAnalysis` for wire serialization.
    pub fn to_protocol_analysis(&self) -> ProtocolForensicAnalysis {
        ProtocolForensicAnalysis {
            verdict: self.map_to_protocol_verdict(),
            flags: Vec::new(),
            coefficient_of_variation: self.cadence.coefficient_of_variation,
            linearity_score: Some(self.primary.monotonic_append_ratio.get()),
            hurst_exponent: self.hurst_exponent,
            checkpoint_count: self.checkpoint_count,
            chain_duration_secs: self.session_stats.total_editing_time_sec.max(0.0) as u64,
            explanation: if let Some(ref prov) = self.provenance {
                format!(
                    "Assessment: {:.2}, Composition: {:.0}% original, Trust: {:.2}",
                    self.assessment_score,
                    prov.original_composition_ratio * 100.0,
                    prov.source_trustworthiness,
                )
            } else {
                format!("Internal Assessment Score: {:.2}", self.assessment_score)
            },
        }
    }
}

/// Edit velocity (bytes/sec) metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VelocityMetrics {
    pub mean_bps: f64,
    pub max_bps: f64,
    pub high_velocity_bursts: usize,
    /// Estimated characters from autocomplete (excess over human max).
    pub autocomplete_chars: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    pub session_count: usize,
    pub avg_session_duration_sec: f64,
    pub total_editing_time_sec: f64,
    /// Wall-clock span from first to last event (seconds).
    pub time_span_sec: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Insufficient,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Insufficient => write!(f, "INSUFFICIENT DATA"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorshipProfile {
    pub file_path: String,
    pub event_count: usize,
    pub time_span: ChronoDuration,
    pub session_count: usize,
    pub first_event: DateTime<Utc>,
    pub last_event: DateTime<Utc>,
    pub metrics: PrimaryMetrics,
    pub anomalies: Vec<Anomaly>,
    pub assessment: Assessment,
}

impl AuthorshipProfile {
    pub fn writing_mode(&self) -> &str {
        match self.assessment {
            Assessment::Consistent => "cognitive",
            Assessment::Insufficient => "undetermined",
            Assessment::Suspicious => "transcriptive",
        }
    }
    pub fn risk_level(&self) -> &str {
        match self.assessment {
            Assessment::Consistent => "low",
            Assessment::Suspicious => "high",
            Assessment::Insufficient => "undetermined",
        }
    }
}

impl Default for AuthorshipProfile {
    fn default() -> Self {
        Self {
            file_path: String::new(),
            event_count: 0,
            time_span: ChronoDuration::zero(),
            session_count: 0,
            first_event: Utc::now(),
            last_event: Utc::now(),
            metrics: PrimaryMetrics::default(),
            anomalies: Vec::new(),
            assessment: Assessment::Insufficient,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub timestamp: Option<DateTime<Utc>>,
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub severity: Severity,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    Gap,
    HighVelocity,
    MonotonicAppend,
    LowEntropy,
    RoboticCadence,
    UndetectedPaste,
    ContentMismatch,
    ScatteredDeletions,
}

impl fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnomalyType::Gap => write!(f, "gap"),
            AnomalyType::HighVelocity => write!(f, "high_velocity"),
            AnomalyType::MonotonicAppend => write!(f, "monotonic_append"),
            AnomalyType::LowEntropy => write!(f, "low_entropy"),
            AnomalyType::RoboticCadence => write!(f, "robotic_cadence"),
            AnomalyType::UndetectedPaste => write!(f, "undetected_paste"),
            AnomalyType::ContentMismatch => write!(f, "content_mismatch"),
            AnomalyType::ScatteredDeletions => write!(f, "scattered_deletions"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Alert,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Alert => write!(f, "alert"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointFlags {
    pub ordinal: u64,
    pub event_count: usize,
    pub timing_cv: f64,
    pub max_velocity_bps: f64,
    pub all_append: bool,
    pub flagged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerCheckpointResult {
    pub checkpoint_flags: Vec<CheckpointFlags>,
    pub pct_flagged: Probability,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Assessment {
    Consistent,
    Suspicious,
    #[default]
    Insufficient,
}

impl fmt::Display for Assessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Assessment::Consistent => write!(f, "CONSISTENT WITH HUMAN AUTHORSHIP"),
            Assessment::Suspicious => write!(f, "SUSPICIOUS PATTERNS DETECTED"),
            Assessment::Insufficient => write!(f, "INSUFFICIENT DATA"),
        }
    }
}
