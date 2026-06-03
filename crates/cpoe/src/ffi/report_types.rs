// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiWarReportResult {
    pub success: bool,
    pub report: Option<FfiWarReport>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiWarReport {
    pub report_id: String,
    pub algorithm_version: String,
    pub generated_at_epoch_ms: i64,
    pub schema_version: String,
    pub score: u32,
    pub verdict: String,
    pub verdict_description: String,
    pub likelihood_ratio: f64,
    pub enfsi_tier: String,
    pub document_hash: String,
    pub signing_key_fingerprint: String,
    pub document_chars: Option<u64>,
    pub evidence_bundle_version: String,
    pub session_count: u32,
    pub total_duration_min: f64,
    pub revision_events: u64,
    pub device_attestation: String,
    pub checkpoints: Vec<FfiReportCheckpoint>,
    pub sessions: Vec<FfiReportSession>,
    pub process: FfiProcessEvidence,
    pub flags: Vec<FfiReportFlag>,
    pub forgery: FfiForgeryInfo,
    pub dimensions: Vec<FfiDimensionScore>,
    pub limitations: Vec<String>,
    pub guilloche_seed_hex: String,
    pub provenance: Option<FfiProvenanceBreakdown>,
    pub document_words: Option<u64>,
    pub document_sentences: Option<u64>,
    pub document_paragraphs: Option<u64>,
    pub writing_flow: Vec<FfiFlowDataPoint>,
    pub edit_topology: Vec<FfiEditRegion>,
    pub activity_contexts: Vec<FfiActivityContext>,
    pub anomalies: Vec<FfiReportAnomaly>,
    pub declaration_summary: Option<FfiDeclarationInfo>,
    pub key_hierarchy_summary: Option<FfiKeyHierarchyInfo>,
    pub physical_context: Option<FfiPhysicalContextInfo>,
    pub beacon_info: Option<FfiBeaconInfo>,
    pub author_did: Option<String>,
    pub verifiable_credential_json: Option<String>,
    pub is_sample: bool,
    pub evidence_hash: Option<String>,
    pub methodology: Option<FfiStatisticalMethodology>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiProvenanceBreakdown {
    pub total_fragments: u32,
    pub original_composition_pct: f64,
    pub sourced_unknown_pct: f64,
    pub sourced_verified_pct: f64,
    pub chain_depth: u32,
    pub source_trustworthiness: f64,
    pub authenticity_score: f64,
    pub sources: Vec<FfiProvenanceSource>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiProvenanceSource {
    pub session_id: String,
    pub app_bundle_id: String,
    pub fragment_count: u32,
    pub verified: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiReportCheckpoint {
    pub ordinal: u64,
    pub timestamp_epoch_ms: i64,
    pub content_hash: String,
    pub content_size: u64,
    pub vdf_iterations: Option<u64>,
    pub elapsed_ms: Option<u64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiReportSession {
    pub index: u32,
    pub start_epoch_ms: i64,
    pub duration_min: f64,
    pub event_count: u32,
    pub words_drafted: Option<u64>,
    pub device: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiProcessEvidence {
    pub paste_operations: Option<u64>,
    pub swf_checkpoints: Option<u64>,
    pub swf_avg_compute_ms: Option<u64>,
    pub swf_chain_verified: bool,
    pub swf_backdating_hours: Option<f64>,
    pub revision_intensity: Option<f64>,
    pub revision_baseline: Option<String>,
    pub pause_median_sec: Option<f64>,
    pub pause_p90_sec: Option<f64>,
    pub pause_max_sec: Option<f64>,
    pub paste_ratio_pct: Option<f64>,
    pub paste_max_chars: Option<u64>,
    pub iki_cv: Option<f64>,
    pub bigram_consistency: Option<f64>,
    pub total_keystrokes: Option<u64>,
    pub deletion_sequences: Option<u64>,
    pub avg_deletion_length: Option<f64>,
    pub select_delete_ops: Option<u64>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiReportFlag {
    pub category: String,
    pub flag: String,
    pub detail: String,
    pub signal: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForgeryInfo {
    pub tier: String,
    pub estimated_forge_time_sec: f64,
    pub weakest_link: Option<String>,
    pub components: Vec<FfiForgeryComponent>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForgeryComponent {
    pub name: String,
    pub present: bool,
    pub cost_cpu_sec: f64,
    pub explanation: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDimensionScore {
    pub name: String,
    pub score: u32,
    pub lr: f64,
    pub log_lr: f64,
    pub confidence: f64,
    pub key_discriminator: String,
    pub color: String,
    pub analysis: Vec<FfiDimensionDetail>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDimensionDetail {
    pub label: String,
    pub text: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiFlowDataPoint {
    pub offset_min: f64,
    pub intensity: f64,
    pub phase: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiEditRegion {
    pub start_pct: f64,
    pub end_pct: f64,
    pub delta_sign: i32,
    pub byte_count: i64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiActivityContext {
    pub period_type: String,
    pub start_epoch_ms: i64,
    pub end_epoch_ms: i64,
    pub duration_min: f64,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiReportAnomaly {
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDeclarationInfo {
    pub statement: String,
    pub title: String,
    pub ai_tools: Vec<String>,
    pub input_modalities: Vec<String>,
    pub collaborator_count: u32,
    pub signature_valid: bool,
    pub created_at_epoch_ms: i64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiKeyHierarchyInfo {
    pub master_fingerprint: String,
    pub device_id: String,
    pub session_id: String,
    pub ratchet_count: i32,
    pub checkpoint_signatures: u32,
    pub session_started_epoch_ms: i64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiPhysicalContextInfo {
    pub clock_skew_ns: u64,
    pub thermal_proxy: u32,
    pub silicon_puf_hash: String,
    pub io_latency_ns: u64,
    pub combined_hash: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiBeaconInfo {
    pub drand_round: u64,
    pub nist_pulse_index: u64,
    pub fetched_at: String,
    pub wp_key_id: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiStatisticalMethodology {
    pub lr_computation: String,
    pub confidence_interval: String,
    pub calibration: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiHtmlResult {
    pub success: bool,
    pub html: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiPdfResult {
    pub success: bool,
    pub pdf_bytes: Option<Vec<u8>>,
    pub error_message: Option<String>,
}
