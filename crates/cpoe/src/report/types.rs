// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// ENFSI verbal equivalence scale for likelihood ratios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnfsiTier {
    /// LR < 1 — evidence supports the alternative hypothesis
    Against,
    /// LR 1–10
    Weak,
    /// LR 10–100
    Moderate,
    /// LR 100–1,000
    ModeratelyStrong,
    /// LR 1,000–10,000
    Strong,
    /// LR >= 10,000
    VeryStrong,
    /// Non-finite LR (NaN or Inf)
    Inconclusive,
}

impl EnfsiTier {
    /// Classify a likelihood ratio into the corresponding ENFSI tier.
    pub fn from_lr(lr: f64) -> Self {
        if !lr.is_finite() {
            return Self::Inconclusive;
        }
        if lr < 1.0 {
            Self::Against
        } else if lr < 10.0 {
            Self::Weak
        } else if lr < 100.0 {
            Self::Moderate
        } else if lr < 1_000.0 {
            Self::ModeratelyStrong
        } else if lr < 10_000.0 {
            Self::Strong
        } else {
            Self::VeryStrong
        }
    }

    /// Return the human-readable label for this tier.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Against => "Against",
            Self::Weak => "Weak support",
            Self::Moderate => "Moderate support",
            Self::ModeratelyStrong => "Moderately strong",
            Self::Strong => "Strong support",
            Self::VeryStrong => "Very strong support",
            Self::Inconclusive => "Inconclusive",
        }
    }
}

/// Verdict classification based on assessment score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// Score 80-100: strong human authorship indicators.
    VerifiedHuman,
    /// Score 60-79: moderate human authorship indicators.
    LikelyHuman,
    /// Score 40-59: insufficient evidence to determine.
    Inconclusive,
    /// Score 20-39: anomalous patterns detected.
    Suspicious,
    /// Score 0-19: synthetic generation indicators.
    LikelySynthetic,
    /// Too few events or checkpoints to make any determination.
    InsufficientData,
}

impl Verdict {
    /// Map an assessment score (0-100) to a verdict classification.
    /// Use `from_score_with_events` when event count is available.
    pub fn from_score(score: u32) -> Self {
        match score {
            80..=100 => Self::VerifiedHuman,
            60..=79 => Self::LikelyHuman,
            40..=59 => Self::Inconclusive,
            20..=39 => Self::Suspicious,
            _ => Self::LikelySynthetic,
        }
    }

    /// Map a score to a verdict, returning `InsufficientData` when there
    /// are too few events to make a meaningful determination.
    pub fn from_score_with_events(score: u32, event_count: usize) -> Self {
        if event_count < 5 {
            return Self::InsufficientData;
        }
        Self::from_score(score)
    }

    /// Return the display label for this verdict.
    pub fn label(&self) -> &'static str {
        match self {
            Self::InsufficientData => "INSUFFICIENT DATA",
            Self::VerifiedHuman => "VERIFIED HUMAN",
            Self::LikelyHuman => "LIKELY HUMAN",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::Suspicious => "SUSPICIOUS",
            Self::LikelySynthetic => "LIKELY SYNTHETIC",
        }
    }

    /// Return a descriptive subtitle for the verdict.
    pub fn subtitle(&self) -> &'static str {
        match self {
            Self::InsufficientData => "Not Enough Evidence to Assess",
            Self::VerifiedHuman => "Strong Constraint Indicators",
            Self::LikelyHuman => "Moderate Constraint Indicators",
            Self::Inconclusive => "Insufficient Evidence",
            Self::Suspicious => "Anomalous Patterns Detected",
            Self::LikelySynthetic => "Synthetic Generation Indicators",
        }
    }

    /// Return the CSS color hex string for this verdict.
    pub fn css_color(&self) -> &'static str {
        match self {
            Self::InsufficientData => "#757575",
            Self::VerifiedHuman => "#2e7d32",
            Self::LikelyHuman => "#558b2f",
            Self::Inconclusive => "#f57f17",
            Self::Suspicious => "#e65100",
            Self::LikelySynthetic => "#b71c1c",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportCheckpoint {
    pub ordinal: u64,
    pub timestamp: DateTime<Utc>,
    pub content_hash: String,
    pub content_size: u64,
    pub vdf_iterations: Option<u64>,
    pub elapsed_ms: Option<u64>,
}

/// Session summary for the timeline section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSession {
    pub index: usize,
    pub start: DateTime<Utc>,
    pub duration_min: f64,
    pub event_count: usize,
    pub words_drafted: Option<u64>,
    pub device: Option<String>,
    pub summary: String,
}

/// Process evidence metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessEvidence {
    pub revision_intensity: Option<f64>,
    pub revision_baseline: Option<String>,
    pub pause_median_sec: Option<f64>,
    pub pause_p95_sec: Option<f64>,
    pub pause_max_sec: Option<f64>,
    pub paste_ratio_pct: Option<f64>,
    pub paste_operations: Option<u64>,
    pub paste_max_chars: Option<u64>,
    pub iki_cv: Option<f64>,
    pub bigram_consistency: Option<f64>,
    pub total_keystrokes: Option<u64>,
    pub deletion_sequences: Option<u64>,
    pub avg_deletion_length: Option<f64>,
    pub select_delete_ops: Option<u64>,
    pub swf_checkpoints: Option<u64>,
    pub swf_avg_compute_ms: Option<u64>,
    pub swf_chain_verified: bool,
    pub swf_backdating_hours: Option<f64>,
}

/// An anomaly or flag detected during analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFlag {
    pub category: String,
    pub flag: String,
    pub detail: String,
    pub signal: FlagSignal,
}

/// Signal direction of a detected flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlagSignal {
    /// Indicates human authorship behavior.
    Human,
    /// Neither human nor synthetic signal.
    Neutral,
    /// Indicates synthetic generation behavior.
    Synthetic,
}

impl FlagSignal {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Human => "Human",
            Self::Neutral => "Neutral",
            Self::Synthetic => "Synthetic",
        }
    }

    pub fn css_color(&self) -> &'static str {
        match self {
            Self::Human => "#2e7d32",
            Self::Neutral => "#757575",
            Self::Synthetic => "#c62828",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionScore {
    pub name: String,
    pub score: u32,
    pub lr: f64,
    pub log_lr: f64,
    pub confidence: f64,
    pub key_discriminator: String,
    pub color: String,
    pub analysis: Vec<DimensionDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionDetail {
    pub label: String,
    pub text: String,
}

/// Statistical methodology summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatisticalMethodology {
    pub lr_computation: String,
    pub confidence_interval: String,
    pub calibration: String,
}

/// Writing flow visualization data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDataPoint {
    pub offset_min: f64,
    pub intensity: f64,
    pub phase: String,
}

/// Forgery resistance info for the report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForgeryInfo {
    pub tier: String,
    pub estimated_forge_time_sec: f64,
    pub weakest_link: Option<String>,
    pub components: Vec<ForgeryComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeryComponent {
    pub name: String,
    pub present: bool,
    pub cost_cpu_sec: f64,
    pub explanation: String,
}

/// Detailed forensic metrics from the analysis pipeline.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForensicBreakdown {
    pub writing_mode: String,
    pub cognitive_score: f64,
    pub writing_mode_confidence: f64,
    pub revision_cycle_count: u32,
    pub hurst_exponent: Option<f64>,
    pub assessment_score: f64,
    pub risk_level: String,
    pub mean_iki_ms: f64,
    pub coefficient_of_variation: f64,
    pub burst_count: u32,
    pub pause_count: u32,
    pub correction_ratio: f64,
    pub burst_speed_cv: f64,
    pub pause_depth: [f64; 3],
    pub mean_bps: f64,
    pub max_bps: f64,
    // Extended forensic signals (populated when available)
    pub biological_cadence_score: f64,
    pub steg_confidence: f64,
    pub thinking_pause_ratio: f64,
    pub timing_entropy: f64,
    pub pause_entropy: f64,
    pub snr_db: Option<f64>,
    pub snr_flagged: bool,
    pub lyapunov_exponent: Option<f64>,
    pub lyapunov_flagged: bool,
    pub iki_compression_ratio: Option<f64>,
    pub iki_compression_flagged: bool,
    pub forgery_difficulty: Option<f64>,
    pub forgery_tier: Option<String>,
    pub forgery_time_sec: Option<f64>,
    pub fatigue_warmup_pct: Option<f64>,
    pub fatigue_plateau_pct: Option<f64>,
    pub fatigue_pct: Option<f64>,
    pub fatigue_slope: Option<f64>,
    pub cross_modal_score: Option<f64>,
    pub cross_modal_verdict: Option<String>,
    pub transcription_suspicious: bool,
    pub repair_recent_pct: Option<f64>,
    pub repair_distant_pct: Option<f64>,
    pub cognitive_load_score: Option<f64>,
    pub revision_topology_score: Option<f64>,
    pub error_ecology_score: Option<f64>,
    pub likelihood_p_cognitive: Option<f64>,
    pub composition_mode: Option<String>,
    pub labyrinth_determinism: Option<f64>,
    pub labyrinth_recurrence: Option<f64>,
}

/// Spatial edit region showing where in the document edits occurred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRegion {
    pub start_pct: f64,
    pub end_pct: f64,
    pub delta_sign: i32,
    pub byte_count: i64,
}

/// Time-bounded activity context period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityContext {
    pub period_type: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub duration_min: f64,
    pub note: Option<String>,
}

/// Summary of an author's declaration for report display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclarationInfo {
    pub statement: String,
    pub title: String,
    pub ai_tools: Vec<String>,
    pub input_modalities: Vec<String>,
    pub collaborator_count: usize,
    pub signature_valid: bool,
    pub created_at: DateTime<Utc>,
}

/// Summary of the key hierarchy for report display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHierarchyInfo {
    pub master_fingerprint: String,
    pub device_id: String,
    pub session_id: String,
    pub ratchet_count: i32,
    pub checkpoint_signatures: usize,
    pub session_started: DateTime<Utc>,
}

/// Physical context evidence binding session to hardware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalContextInfo {
    pub clock_skew_ns: u64,
    pub thermal_proxy: u32,
    pub silicon_puf_hash: String,
    pub io_latency_ns: u64,
    pub combined_hash: String,
}

/// Temporal beacon attestation from WritersProof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconInfo {
    pub drand_round: u64,
    pub nist_pulse_index: u64,
    pub fetched_at: String,
    pub wp_key_id: Option<String>,
}

/// A severity-graded anomaly detected during forensic analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportAnomaly {
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarReport {
    pub report_id: String,
    pub algorithm_version: String,
    pub generated_at: DateTime<Utc>,
    pub schema_version: String,
    pub is_sample: bool,

    pub score: u32,
    pub verdict: Verdict,
    pub verdict_description: String,
    pub likelihood_ratio: f64,
    pub enfsi_tier: EnfsiTier,

    pub document_hash: String,
    pub evidence_hash: Option<String>,
    pub evidence_cbor_b64: Option<String>,
    pub signing_key_fingerprint: String,
    pub document_words: Option<u64>,
    pub document_chars: Option<u64>,
    pub document_sentences: Option<u64>,
    pub document_paragraphs: Option<u64>,
    pub evidence_bundle_version: String,
    pub session_count: usize,
    pub total_duration_min: f64,
    pub revision_events: u64,
    pub device_attestation: String,

    pub checkpoints: Vec<ReportCheckpoint>,

    pub sessions: Vec<ReportSession>,

    pub process: ProcessEvidence,

    pub flags: Vec<ReportFlag>,

    pub forgery: ForgeryInfo,

    // Populated when NLP analysis is available
    pub dimensions: Vec<DimensionScore>,

    pub writing_flow: Vec<FlowDataPoint>,

    pub methodology: Option<StatisticalMethodology>,

    pub limitations: Vec<String>,

    pub analyzed_text: Option<String>,

    pub forensic_metrics: Option<ForensicBreakdown>,
    pub edit_topology: Vec<EditRegion>,
    pub activity_contexts: Vec<ActivityContext>,
    pub declaration_summary: Option<DeclarationInfo>,
    pub key_hierarchy_summary: Option<KeyHierarchyInfo>,
    pub physical_context: Option<PhysicalContextInfo>,
    pub beacon_info: Option<BeaconInfo>,
    pub anomalies: Vec<ReportAnomaly>,
    pub verifiable_credential_json: Option<String>,
    pub author_did: Option<String>,
    pub provenance_breakdown: Option<ProvenanceBreakdown>,
}

/// Provenance breakdown for the WAR report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceBreakdown {
    pub total_fragments: usize,
    pub original_composition_pct: f64,
    pub sourced_unknown_pct: f64,
    pub sourced_verified_pct: f64,
    pub chain_depth: u32,
    pub source_trustworthiness: f64,
    pub authenticity_score: f64,
    pub sources: Vec<ProvenanceSource>,
}

/// A source session contributing content via paste.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceSource {
    pub session_id: String,
    pub app_bundle_id: Option<String>,
    pub fragment_count: usize,
    pub verified: bool,
}

impl WarReport {
    /// Generate a report ID in the format WAR-XXXXXXXX.
    pub fn generate_id() -> String {
        let mut bytes = [0u8; 4];
        if let Err(e) = getrandom::getrandom(&mut bytes) {
            log::warn!("CSPRNG unavailable, falling back to timestamp ID: {}", e);
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            return format!("WAR-{:08X}", (ts & 0xFFFF_FFFF) as u32);
        }
        let hex = hex::encode(bytes).to_uppercase();
        format!("WAR-{}", hex)
    }
}

/// Compute a likelihood ratio from an assessment score (0-100).
///
/// Scores ≤ 50 map linearly to LR 0.01–1.0 (evidence against human authorship).
/// Scores > 50 map exponentially: LR = 10^((score - 50) / 10), reaching
/// ~100,000 at score 100.
pub fn compute_likelihood_ratio(score: u32) -> f64 {
    if score <= 50 {
        (score as f64 / 50.0).max(0.01)
    } else {
        10.0_f64.powf((score as f64 - 50.0) / 10.0)
    }
}
