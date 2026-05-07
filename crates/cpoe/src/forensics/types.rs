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

/// Minimum timing entropy (bits/sample) per draft-condrey-rats-pop-appraisal.
pub const THRESHOLD_TIMING_ENTROPY: f64 = 3.0;
/// Minimum revision entropy (bits) per draft-condrey-rats-pop-appraisal.
pub const THRESHOLD_REVISION_ENTROPY: f64 = 3.0;
/// Minimum pause entropy (bits) per draft-condrey-rats-pop-appraisal.
pub const THRESHOLD_PAUSE_ENTROPY: f64 = 2.0;
/// Below this edit entropy, non-human editing is suspected.
/// Uses the minimum of the per-type thresholds as a general floor.
pub const THRESHOLD_LOW_ENTROPY: f64 = 2.0;

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
    pub edit_entropy: f64,
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

        match self.risk_level {
            RiskLevel::Low => {
                if self.assessment_score > 0.9 {
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
    pub fn revision_cycle_count(&self) -> u32 {
        u32::try_from(self.session_count).unwrap_or(u32::MAX)
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
