// SPDX-License-Identifier: Apache-2.0

use crate::rfc::EvidencePacket;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Top-level process proof assertion (`com.writerslogic.process-proof`).
///
/// Contains the verdict, trust assessment, and composite signal scores.
/// This is the first assertion a verifier reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessProofAssertion {
    pub version: u32,
    #[serde(rename = "evidenceId")]
    pub evidence_id: String,
    #[serde(rename = "evidenceHash")]
    pub evidence_hash: String,
    /// Overall verdict: "human-authored", "mixed-input", "transcriptive", "insufficient".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    /// Overall assessment score [0.0, 1.0].
    #[serde(rename = "assessmentScore", skip_serializing_if = "Option::is_none")]
    pub assessment_score: Option<f64>,
    /// Risk level: "low", "medium", "high", "insufficient".
    #[serde(rename = "riskLevel", skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    /// Writing mode: "cognitive", "transcriptive", "mixed", "insufficient".
    #[serde(rename = "writingMode", skip_serializing_if = "Option::is_none")]
    pub writing_mode: Option<String>,
    /// Composition mode: "direct-composition", "ai-mediated", "mixed".
    #[serde(rename = "compositionMode", skip_serializing_if = "Option::is_none")]
    pub composition_mode: Option<String>,
    /// Attestation tier: 1=software, 2=enhanced, 3=hardware.
    #[serde(rename = "attestationTier", skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<u8>,
    /// Per-dimension composite signal scores [0.0, 1.0].
    #[serde(rename = "signalScores", skip_serializing_if = "Option::is_none")]
    pub signal_scores: Option<ForensicSignalScores>,
    /// Estimated adversary effort to forge this evidence [0.0, 1.0].
    #[serde(rename = "forgeryDifficulty", skip_serializing_if = "Option::is_none")]
    pub forgery_difficulty: Option<f64>,
    #[serde(rename = "transcriptionSuspicious", skip_serializing_if = "Option::is_none")]
    pub transcription_suspicious: Option<bool>,
    #[serde(rename = "aiFluencyFlag", skip_serializing_if = "Option::is_none")]
    pub ai_fluency_flag: Option<bool>,
    /// Count of successful analysis modules (out of 18).
    #[serde(rename = "analysisCompleteness", skip_serializing_if = "Option::is_none")]
    pub analysis_completeness: Option<u32>,
    #[serde(rename = "processStart", skip_serializing_if = "Option::is_none")]
    pub process_start: Option<String>,
    #[serde(rename = "processEnd", skip_serializing_if = "Option::is_none")]
    pub process_end: Option<String>,
}

/// Per-dimension forensic signal scores projected into C2PA assertions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicSignalScores {
    /// Cognitive load-timing entanglement (IKI-surprisal correlation).
    #[serde(rename = "cognitiveLoad")]
    pub cognitive_load: f64,
    /// Revision topology and semantic delta (DAG non-linearity).
    #[serde(rename = "revisionTopology")]
    pub revision_topology: f64,
    /// Error ecology (motor vs visual error distribution).
    #[serde(rename = "errorEcology")]
    pub error_ecology: f64,
    /// Per-window generative likelihood model posterior P(cognitive).
    #[serde(rename = "likelihoodModel")]
    pub likelihood_model: f64,
    /// Composition mode (pure composition vs AI-mediated).
    #[serde(rename = "compositionMode")]
    pub composition_mode: f64,
}

/// Per-checkpoint jitter seal binding a checkpoint to its temporal proof (C2PA §12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterSeal {
    pub sequence: u64,
    pub timestamp: u64,
    pub seal_hash: String,
}

impl ProcessProofAssertion {
    pub fn from_evidence(packet: &EvidencePacket, original_bytes: &[u8]) -> Self {
        let hash = Sha256::digest(original_bytes);
        Self {
            version: 2,
            evidence_id: hex::encode(&packet.packet_id),
            evidence_hash: hex::encode(hash),
            verdict: None,
            assessment_score: None,
            risk_level: None,
            writing_mode: None,
            composition_mode: None,
            attestation_tier: packet.attestation_tier.map(|t| t as u8),
            signal_scores: None,
            forgery_difficulty: None,
            transcription_suspicious: None,
            ai_fluency_flag: None,
            analysis_completeness: None,
            process_start: None,
            process_end: None,
        }
    }
}

/// Keystroke cadence assertion (`com.writerslogic.keystroke-cadence`).
///
/// Timing fingerprint enabling independent cadence verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeCadenceAssertion {
    pub version: u32,
    #[serde(rename = "keystrokeCount")]
    pub keystroke_count: u64,
    #[serde(rename = "sessionDurationSec")]
    pub session_duration_sec: f64,
    pub timing: CadenceTiming,
    pub dwell: CadenceDwell,
    pub corrections: CadenceCorrections,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fatigue: Option<CadenceFatigue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spectral: Option<CadenceSpectral>,
    #[serde(rename = "hurstExponent", skip_serializing_if = "Option::is_none")]
    pub hurst_exponent: Option<f64>,
    #[serde(rename = "biologicalCadenceScore", skip_serializing_if = "Option::is_none")]
    pub biological_cadence_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CadenceTiming {
    #[serde(rename = "meanIkiMs")]
    pub mean_iki_ms: f64,
    #[serde(rename = "medianIkiMs")]
    pub median_iki_ms: f64,
    #[serde(rename = "coefficientOfVariation")]
    pub coefficient_of_variation: f64,
    #[serde(rename = "ikiPercentiles")]
    pub iki_percentiles: [f64; 5],
    #[serde(rename = "burstCount")]
    pub burst_count: u64,
    #[serde(rename = "avgBurstLength")]
    pub avg_burst_length: f64,
    #[serde(rename = "pauseCount")]
    pub pause_count: u64,
    #[serde(rename = "avgPauseDurationMs")]
    pub avg_pause_duration_ms: f64,
    #[serde(rename = "pauseDepthDistribution")]
    pub pause_depth_distribution: [f64; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CadenceDwell {
    #[serde(rename = "meanDwellMs")]
    pub mean_dwell_ms: f64,
    #[serde(rename = "dwellCv")]
    pub dwell_cv: f64,
    #[serde(rename = "meanFlightMs")]
    pub mean_flight_ms: f64,
    #[serde(rename = "flightCv")]
    pub flight_cv: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CadenceCorrections {
    #[serde(rename = "correctionRatio")]
    pub correction_ratio: f64,
    #[serde(rename = "crossHandTimingRatio")]
    pub cross_hand_timing_ratio: f64,
    #[serde(rename = "postPauseCv")]
    pub post_pause_cv: f64,
    #[serde(rename = "ikiAutocorrelation")]
    pub iki_autocorrelation: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CadenceFatigue {
    pub phase: u8,
    #[serde(rename = "trajectoryResidual")]
    pub trajectory_residual: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CadenceSpectral {
    pub slope: f64,
    #[serde(rename = "noiseType")]
    pub noise_type: String,
}

/// Cognitive markers assertion (`com.writerslogic.cognitive-markers`).
///
/// Deep behavioral analysis: the evidence that typing was cognitive, not mechanical.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveMarkersAssertion {
    pub version: u32,
    #[serde(rename = "cognitiveLoad", skip_serializing_if = "Option::is_none")]
    pub cognitive_load: Option<CognitiveLoadSignals>,
    #[serde(rename = "revisionTopology", skip_serializing_if = "Option::is_none")]
    pub revision_topology: Option<RevisionTopologySignals>,
    #[serde(rename = "errorEcology", skip_serializing_if = "Option::is_none")]
    pub error_ecology: Option<ErrorEcologySignals>,
    #[serde(rename = "likelihoodModel", skip_serializing_if = "Option::is_none")]
    pub likelihood_model: Option<LikelihoodModelSignals>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focus: Option<FocusSignals>,
    #[serde(rename = "editMetrics", skip_serializing_if = "Option::is_none")]
    pub edit_metrics: Option<EditMetricSignals>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveLoadSignals {
    #[serde(rename = "ikiSurprisalRho")]
    pub iki_surprisal_rho: f64,
    #[serde(rename = "sentenceArcRSquared")]
    pub sentence_arc_r_squared: f64,
    #[serde(rename = "structuralPauseConcentration")]
    pub structural_pause_concentration: f64,
    #[serde(rename = "compositeScore")]
    pub composite_score: f64,
    #[serde(rename = "deepPauseCount")]
    pub deep_pause_count: u64,
    #[serde(rename = "boundaryCount")]
    pub boundary_count: u64,
    #[serde(rename = "wordCount")]
    pub word_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionTopologySignals {
    #[serde(rename = "meanBranchingFactor")]
    pub mean_branching_factor: f64,
    #[serde(rename = "meanRevisitDepth")]
    pub mean_revisit_depth: f64,
    #[serde(rename = "meanFrontierDistance")]
    pub mean_frontier_distance: f64,
    #[serde(rename = "activeRegionCount")]
    pub active_region_count: u64,
    #[serde(rename = "detourRatio")]
    pub detour_ratio: f64,
    #[serde(rename = "leadingEdgeDivergence")]
    pub leading_edge_divergence: f64,
    #[serde(rename = "insertionPointEntropy")]
    pub insertion_point_entropy: f64,
    #[serde(rename = "revisionTypes")]
    pub revision_types: RevisionTypeBreakdown,
    #[serde(rename = "compositeScore")]
    pub composite_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionTypeBreakdown {
    #[serde(rename = "subWordMotorPct")]
    pub sub_word_motor_pct: f64,
    #[serde(rename = "wordSubstitutionPct")]
    pub word_substitution_pct: f64,
    #[serde(rename = "clauseRestructuringPct")]
    pub clause_restructuring_pct: f64,
    #[serde(rename = "positionalInsertionPct")]
    pub positional_insertion_pct: f64,
    #[serde(rename = "totalRevisions")]
    pub total_revisions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEcologySignals {
    #[serde(rename = "rapidSelfCorrectionPct")]
    pub rapid_self_correction_pct: f64,
    #[serde(rename = "immediateSmallCorrectionPct")]
    pub immediate_small_correction_pct: f64,
    #[serde(rename = "delayedCorrectionPct")]
    pub delayed_correction_pct: f64,
    #[serde(rename = "bulkCorrectionPct")]
    pub bulk_correction_pct: f64,
    #[serde(rename = "falseStartPct")]
    pub false_start_pct: f64,
    #[serde(rename = "totalCorrections")]
    pub total_corrections: u64,
    #[serde(rename = "correctionRate")]
    pub correction_rate: f64,
    #[serde(rename = "jsdFromCognitive")]
    pub jsd_from_cognitive: f64,
    #[serde(rename = "jsdFromTranscriptive")]
    pub jsd_from_transcriptive: f64,
    #[serde(rename = "compositeScore")]
    pub composite_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LikelihoodModelSignals {
    #[serde(rename = "sessionLlr")]
    pub session_llr: f64,
    #[serde(rename = "sessionPCognitive")]
    pub session_p_cognitive: f64,
    #[serde(rename = "windowCount")]
    pub window_count: u64,
    #[serde(rename = "cognitiveWindowCount")]
    pub cognitive_window_count: u64,
    #[serde(rename = "transcriptiveWindowCount")]
    pub transcriptive_window_count: u64,
    #[serde(rename = "meanWindowLlr")]
    pub mean_window_llr: f64,
    #[serde(rename = "llrStdDev")]
    pub llr_std_dev: f64,
    #[serde(rename = "compositeScore")]
    pub composite_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FocusSignals {
    #[serde(rename = "switchCount")]
    pub switch_count: u64,
    #[serde(rename = "outOfFocusRatio")]
    pub out_of_focus_ratio: f64,
    #[serde(rename = "aiAppSwitchCount")]
    pub ai_app_switch_count: u64,
    #[serde(rename = "midTypingSwitchRatio")]
    pub mid_typing_switch_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditMetricSignals {
    #[serde(rename = "monotonicAppendRatio")]
    pub monotonic_append_ratio: f64,
    #[serde(rename = "editEntropy")]
    pub edit_entropy: f64,
    #[serde(rename = "timingEntropy")]
    pub timing_entropy: f64,
    #[serde(rename = "pauseEntropy")]
    pub pause_entropy: f64,
    #[serde(rename = "positiveNegativeRatio")]
    pub positive_negative_ratio: f64,
    #[serde(rename = "deletionClustering")]
    pub deletion_clustering: f64,
}

/// Evidence chain assertion (`com.writerslogic.evidence-chain`).
///
/// Per-checkpoint temporal seals binding evidence to time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChainAssertion {
    pub version: u32,
    #[serde(rename = "checkpointCount")]
    pub checkpoint_count: u64,
    #[serde(rename = "chainDurationSec")]
    pub chain_duration_sec: f64,
    pub seals: Vec<JitterSeal>,
    #[serde(rename = "sessionStats", skip_serializing_if = "Option::is_none")]
    pub session_stats: Option<SessionStatsSignals>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatsSignals {
    #[serde(rename = "sessionCount")]
    pub session_count: u64,
    #[serde(rename = "avgSessionDurationSec")]
    pub avg_session_duration_sec: f64,
    #[serde(rename = "totalEditingTimeSec")]
    pub total_editing_time_sec: f64,
    #[serde(rename = "timeSpanSec")]
    pub time_span_sec: f64,
}

impl EvidenceChainAssertion {
    pub fn from_evidence(packet: &EvidencePacket) -> Self {
        let seals: Vec<JitterSeal> = packet
            .checkpoints
            .iter()
            .map(|cp| JitterSeal {
                sequence: cp.sequence,
                timestamp: cp.timestamp,
                seal_hash: hex::encode(&cp.checkpoint_hash.digest),
            })
            .collect();
        let chain_duration_sec = if let (Some(first), Some(last)) =
            (packet.checkpoints.first(), packet.checkpoints.last())
        {
            (last.timestamp.saturating_sub(first.timestamp)) as f64 / 1000.0
        } else {
            0.0
        };
        Self {
            version: 1,
            checkpoint_count: seals.len() as u64,
            chain_duration_sec,
            seals,
            session_stats: None,
        }
    }
}

/// Standard C2PA actions assertion (§12.1, CBOR map).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionsAssertion {
    pub actions: Vec<Action>,
}

/// Single C2PA action entry (e.g., "c2pa.created").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(rename = "softwareAgent", skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<SoftwareAgent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<ActionParameters>,
}

/// Software agent can be a string or a structured claim-generator-info map (§12.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SoftwareAgent {
    Simple(String),
    Info(ClaimGeneratorInfo),
}

/// Optional parameters for a C2PA action entry (§12.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionParameters {
    /// Human-readable description of the action performed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// C2PA hash-data assertion binding manifest to the asset (§9.1, CBOR map).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashDataAssertion {
    pub name: String,
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    /// Algorithm identifier per §15.4.
    #[serde(rename = "alg")]
    pub algorithm: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<ExclusionRange>,
    /// Padding bytes for embedded manifest re-signing (§9.1).
    #[serde(with = "serde_bytes", default)]
    pub pad: Vec<u8>,
}

/// Byte range exclusion for embedded manifests (§9.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionRange {
    pub start: u64,
    pub length: u64,
}

/// Byte range exclusion for `hash_with_exclusions` (uses `usize` for direct indexing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashExclusion {
    pub start: usize,
    pub length: usize,
}

/// Local timestamp assertion used as an offline TSA fallback.
///
/// When a network-based RFC 3161 timestamp is unavailable, a local wall-clock
/// timestamp bound to an optional VDF proof provides best-effort temporal
/// ordering. Validators treat this as weaker evidence than a TSA timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalTimestampAssertion {
    /// Wall clock time in nanoseconds since Unix epoch (UTC).
    #[serde(rename = "wallClockNs")]
    pub wall_clock_ns: i64,
    /// SHA-256 hash of the VDF proof output, if a VDF was run at timestamp time.
    #[serde(rename = "vdfProofHash", skip_serializing_if = "Option::is_none")]
    pub vdf_proof_hash: Option<[u8; 32]>,
    /// Number of VDF iterations executed (0 if no VDF was run).
    #[serde(rename = "vdfIterations")]
    pub vdf_iterations: u64,
}

/// C2PA metadata assertion for dc:title and dc:format (replaces claim-level fields in v2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataAssertion {
    #[serde(rename = "dc:title", skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(rename = "dc:format", skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Hashed external reference assertion (C2PA 2.4, hashed-external-reference-map).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReferenceAssertion {
    pub location: HashedExtUri,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AssertionMetadata>,
}

/// Hashed external URI map (C2PA 2.4, hashed-ext-uri-map).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedExtUri {
    pub url: String,
    pub alg: String,
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    #[serde(rename = "dc:format", skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_types: Option<Vec<AssetType>>,
}

/// Asset type descriptor for external references.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetType {
    #[serde(rename = "type")]
    pub type_id: String,
}

/// Assertion metadata with process timing and data source (C2PA 2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionMetadata {
    #[serde(rename = "processStart", skip_serializing_if = "Option::is_none")]
    pub process_start: Option<String>,
    #[serde(rename = "processEnd", skip_serializing_if = "Option::is_none")]
    pub process_end: Option<String>,
    #[serde(rename = "dataSource", skip_serializing_if = "Option::is_none")]
    pub data_source: Option<DataSource>,
}

/// Data source descriptor for assertion metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSource {
    #[serde(rename = "type")]
    pub source_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// C2PA claim v2 per §10 and §15.6. All field names match the CDDL schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2paClaim {
    /// §10.5, required in claim-map-v2 (single generator-info-map in V2).
    pub claim_generator_info: ClaimGeneratorInfo,

    /// §10.3, required.
    #[serde(rename = "instanceID")]
    pub instance_id: String,

    /// §10.7, required.
    pub signature: String,

    /// §15.4, hash algorithm for assertion references.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// §10.6
    pub created_assertions: Vec<HashedUri>,
}

/// §10.5
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimGeneratorInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "specVersion", skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
}

/// Hashed URI reference per §8.4.2 and §15.10.3.
/// The hash is binary (CBOR bstr), computed over the JUMBF superbox
/// contents (description + content boxes, excluding the 8-byte superbox header)
/// per §8.4.2.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedUri {
    pub url: String,
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    /// Hash algorithm identifier (e.g., "sha256") per §15.4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

/// Assertion JUMBF bytes are pre-built so the hashes in
/// `claim.created_assertions` match the actual bytes written
/// into JUMBF output (no double-serialization risk).
#[derive(Debug, Clone)]
pub struct C2paManifest {
    pub claim: C2paClaim,
    /// Pre-serialized CBOR bytes of the claim, used for both signing and JUMBF embedding
    /// to avoid re-serialization which could produce different bytes and break signatures.
    pub claim_cbor: Vec<u8>,
    /// Must match assertion URL paths.
    pub manifest_label: String,
    pub assertion_boxes: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}

/// Asset metadata for multi-asset and embedded manifest support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetInfo {
    /// MIME type (e.g., "application/pdf", "image/png").
    pub mime_type: String,
    /// File extension without leading dot (e.g., "pdf", "png").
    pub file_extension: String,
}

/// Result of C2PA manifest structural validation per §15.10.1.2.
#[derive(Debug)]
pub struct ValidationResult {
    /// Fatal validation failures that make the manifest non-conformant.
    pub errors: Vec<String>,
    /// Non-fatal issues that do not invalidate the manifest.
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// C2PA AI disclosure assertion per §12.8 and AIDisclosure.adoc.
///
/// Declares AI involvement in content creation, including the level of
/// human oversight during the authoring process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiDisclosureAssertion {
    /// Type of AI model involved (e.g., "language_model", "none").
    #[serde(rename = "modelType")]
    pub model_type: String,
    /// Human-readable name of the AI tool (if detected).
    #[serde(rename = "modelName", skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    /// Level of human oversight during creation.
    #[serde(rename = "contentProfile", skip_serializing_if = "Option::is_none")]
    pub content_profile: Option<AiContentProfile>,
}

/// Content profile describing human oversight level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiContentProfile {
    /// One of: "fully_autonomous", "prompt_guided", "human_validated".
    #[serde(rename = "humanOversightLevel")]
    pub human_oversight_level: String,
}


/// C2PA ingredient representing a prior version of the asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2paIngredient {
    pub title: String,
    pub relationship: String,
    #[serde(rename = "documentHash", skip_serializing_if = "Option::is_none")]
    pub document_hash: Option<String>,
    #[serde(rename = "instanceID", skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(rename = "dc:format", skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "informationalURI", skip_serializing_if = "Option::is_none")]
    pub informational_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<IngredientMetadata>,
}

/// Metadata for a C2PA ingredient sourced from a CPoE checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngredientMetadata {
    pub checkpoint_ordinal: u64,
    pub timestamp: String,
    pub vdf_verified: bool,
    pub content_size: u64,
}

/// Reference to a W3C Verifiable Credential linked to this manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcReferenceAssertion {
    pub vc_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vc_url: Option<String>,
    pub algorithm: String,
}

/// Summary of a parsed JUMBF superbox structure (ISO 19566-5).
#[derive(Debug)]
pub struct JumbfInfo {
    /// Total byte size of the outermost JUMBF superbox including header.
    pub total_size: usize,
    /// Number of immediate child boxes within the superbox.
    pub child_boxes: u32,
}
