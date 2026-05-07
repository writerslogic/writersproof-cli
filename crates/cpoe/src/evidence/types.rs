// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Core evidence types: structs, enums, and trait implementations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::analysis::{BehavioralFingerprint, ForgeryAnalysis};
use crate::collaboration;
use crate::continuation;
use crate::declaration;
use crate::jitter;
use crate::presence;
use crate::provenance;
use crate::tpm;
use crate::vdf;
use authorproof_protocol::rfc::{BiologyInvariantClaim, JitterBinding, TimeEvidence};

use crate::platform::HidDeviceInfo;

use crate::serde_utils::{
    deserialize_optional_nonce, deserialize_optional_pubkey, deserialize_optional_signature,
    serialize_optional_nonce, serialize_optional_pubkey, serialize_optional_signature,
};

/// Trust tier for evidence hardening level.
///
/// Indicates how well the evidence resists adversarial manipulation,
/// from local-only (easily forged) to externally attested (independently verifiable).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TrustTier {
    /// No signature, no nonce. Evidence is self-reported.
    Local = 1,
    /// Signed by key hierarchy, but no verifier nonce.
    Signed = 2,
    /// Signed + verifier nonce proves freshness.
    NonceBound = 3,
    /// WritersProof certificate issued — independently verifiable.
    Attested = 4,
}

fn default_version() -> i32 {
    1
}

/// Hardware co-signature entangled with document content, software signature, and device time.
///
/// Binds four elements into a single hardware-attested proof:
/// - Document content hash (content binding)
/// - Software Ed25519 signature (causal chain)
/// - TPM/Secure Enclave clock + monotonic counter (temporal binding)
/// - Device identity (device binding)
///
/// The entangled hash is: SHA-256("cpoe-hw-cosign-v1" || doc_hash || sw_signature
///                                 || tpm_clock_ms || monotonic_counter || device_id
///                                 || prev_hw_signature)
/// Signed by the hardware-bound key that never leaves the TPM/Secure Enclave.
///
/// Self-entanglement: each co-signature chains the previous one's signature bytes
/// into its hash input. This creates a hardware-signed causal chain where forging
/// checkpoint N requires valid hardware signatures for all preceding checkpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCosignature {
    pub entangled_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub device_id: String,
    pub tpm_clock_ms: u64,
    pub monotonic_counter: u64,
    pub provider_type: String,
    pub algorithm: String,
    /// SHA-256 commitment to the SE-derived threshold salt used for co-sign scheduling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt_commitment: Option<Vec<u8>>,
    /// Previous hardware co-signature bytes for self-entanglement chain.
    /// Genesis (first) co-signature uses an empty vec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hw_signature: Option<Vec<u8>>,
    /// Sequence number in the hardware co-signature chain (0-indexed).
    #[serde(default)]
    pub chain_index: u64,
    /// What software binding was used in the entangled hash.
    /// "ed25519" = packet-level Ed25519 signature (64B).
    /// "event_hmac" = checkpoint event hash from HMAC chain (32B).
    /// "none" = no software binding available (32B zeros).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_type: Option<String>,
}

/// Compute the canonical entangled hash for hardware co-signatures.
///
/// Both the sentinel checkpoint path and the packet signing path MUST
/// use this function to avoid hash asymmetry.
pub fn compute_hw_entangled_hash(
    doc_hash: &[u8],
    sw_binding: &[u8],
    tpm_clock_ms: u64,
    monotonic_counter: u64,
    device_id: &str,
    public_key: &[u8],
    prev_hw_signature: &[u8],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(HW_COSIGN_DST);
    h.update(doc_hash);
    // Length-prefix the software binding to prevent ambiguity between
    // 64-byte Ed25519 signatures and 32-byte event hashes.
    h.update((sw_binding.len() as u32).to_be_bytes());
    h.update(sw_binding);
    h.update(tpm_clock_ms.to_be_bytes());
    h.update(monotonic_counter.to_be_bytes());
    h.update(device_id.as_bytes());
    h.update((public_key.len() as u32).to_be_bytes());
    h.update(public_key);
    h.update(prev_hw_signature);
    h.finalize().into()
}

/// Domain separator for the hardware co-signature entangled hash.
pub const HW_COSIGN_DST: &[u8] = b"cpoe-hw-cosign-v1";
/// Domain separator for packet-id derivation (wire export).
pub const PACKET_ID_DST: &[u8] = b"cpoe-packet-id-v1";
/// Domain separator for checkpoint-id derivation (wire export).
pub const CHECKPOINT_ID_DST: &[u8] = b"cpoe-checkpoint-id-v1";
/// Domain separator for packet content hashing.
pub const PACKET_CONTENT_DST: &[u8] = b"cpoe-packet-content-v3";
/// Domain separator for nonce-bound signing payload.
pub const NONCE_BINDING_DST: &[u8] = b"cpoe-nonce-binding-v1";

/// Complete evidence packet containing all attestation data for a document session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    #[serde(default = "default_version")]
    pub version: i32,
    #[serde(default = "chrono::Utc::now")]
    pub exported_at: DateTime<Utc>,
    pub provenance: Option<RecordProvenance>,
    #[serde(default)]
    pub document: DocumentInfo,
    #[serde(default)]
    pub checkpoints: Vec<CheckpointProof>,
    #[serde(default = "crate::vdf::default_parameters")]
    pub vdf_params: vdf::Parameters,
    #[serde(default)]
    pub chain_hash: String,
    pub declaration: Option<declaration::Declaration>,
    pub presence: Option<presence::Evidence>,
    pub hardware: Option<HardwareEvidence>,
    pub keystroke: Option<KeystrokeEvidence>,
    pub behavioral: Option<BehavioralEvidence>,
    #[serde(default)]
    pub contexts: Vec<ContextPeriod>,
    pub external: Option<ExternalAnchors>,
    pub key_hierarchy: Option<KeyHierarchyEvidencePacket>,
    /// RFC-compliant jitter binding (RFC Section: Jitter Binding).
    /// Contains entropy commitment, statistical summary, active probes, and labyrinth structure.
    pub jitter_binding: Option<JitterBinding>,
    /// RFC-compliant time evidence (RFC Section: Time Evidence).
    /// Contains TSA responses and Roughtime samples.
    pub time_evidence: Option<TimeEvidence>,
    /// Cross-document provenance links (RFC Section: Provenance Links)
    pub provenance_links: Option<provenance::ProvenanceSection>,
    /// Multi-packet continuation info (RFC Section: Continuation Tokens)
    pub continuation: Option<continuation::ContinuationSection>,
    /// Collaborative authorship attestations (RFC Section: Collaborative Authorship)
    pub collaboration: Option<collaboration::CollaborationSection>,
    /// VDF aggregate proof for efficient verification (RFC Section: VDF Aggregation)
    pub vdf_aggregate: Option<vdf::VdfAggregateProof>,
    /// Verifier-provided 32-byte freshness nonce; prevents replay of old packets.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_nonce",
        deserialize_with = "deserialize_optional_nonce"
    )]
    pub verifier_nonce: Option<[u8; 32]>,
    /// Ed25519 signature over packet_hash (|| verifier_nonce if present).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_signature",
        deserialize_with = "deserialize_optional_signature"
    )]
    pub packet_signature: Option<[u8; 64]>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_pubkey",
        deserialize_with = "deserialize_optional_pubkey"
    )]
    pub signing_public_key: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_cosignature: Option<HardwareCosignature>,
    /// RFC-compliant biology invariant claim (RFC Section: Biology Invariant).
    /// Contains behavioral biometric evidence with millibits scoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub biology_claim: Option<BiologyInvariantClaim>,
    /// Physical context evidence binding session to machine hardware signals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_context: Option<PhysicalContextEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<TrustTier>,
    /// MMR root hash covering all checkpoints (anti-deletion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmr_root: Option<String>,
    /// Serialized MMR range proof covering all checkpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmr_proof: Option<String>,
    /// WritersProof attestation certificate ID (when externally attested).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writersproof_certificate_id: Option<String>,
    /// Behavioral baseline verification data (PoP Zero-Trust Baseline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_verification: Option<authorproof_protocol::baseline::BaselineVerification>,
    /// Dictation input events captured during the session.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dictation_events: Vec<DictationEvent>,
    #[serde(default)]
    pub claims: Vec<Claim>,
    #[serde(default)]
    pub limitations: Vec<String>,
    /// WritersProof temporal beacon attestation.
    /// Contains drand + NIST beacon values fetched and counter-signed by WritersProof.
    /// The `wp_signature` is included in the H2 seal computation — evidence signed
    /// with a beacon attestation produces a different seal than evidence without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon_attestation: Option<WpBeaconAttestation>,
    /// Reference to associated W3C Verifiable Credential (Phase 4).
    /// Contains credential ID and issuer for wallet integration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_reference: Option<CredentialReference>,
    /// Compile-to-export hash chain: links this evidence packet to a derived
    /// manuscript file produced by Scrivener, Final Draft, Vellum, or Ulysses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_attestation: Option<ManuscriptExportAttestation>,
    /// Document binder/outline structure snapshot captured at checkpoint time.
    /// Present for bundle-based apps (Scrivener `.scriv`, Final Draft `.fdx`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_structure: Option<DocumentStructureSnapshot>,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            version: 1,
            exported_at: Utc::now(),
            provenance: None,
            document: DocumentInfo::default(),
            checkpoints: Vec::new(),
            vdf_params: vdf::default_parameters(),
            chain_hash: String::new(),
            declaration: None,
            presence: None,
            hardware: None,
            keystroke: None,
            behavioral: None,
            contexts: Vec::new(),
            external: None,
            key_hierarchy: None,
            jitter_binding: None,
            time_evidence: None,
            provenance_links: None,
            continuation: None,
            collaboration: None,
            vdf_aggregate: None,
            verifier_nonce: None,
            packet_signature: None,
            signing_public_key: None,
            author_did: None,
            hardware_cosignature: None,
            biology_claim: None,
            physical_context: None,
            trust_tier: None,
            mmr_root: None,
            mmr_proof: None,
            writersproof_certificate_id: None,
            baseline_verification: None,
            dictation_events: Vec::new(),
            claims: Vec::new(),
            limitations: Vec::new(),
            beacon_attestation: None,
            credential_reference: None,
            export_attestation: None,
            document_structure: None,
        }
    }
}

/// Key hierarchy snapshot proving session certificate chain and ratchet state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHierarchyEvidencePacket {
    #[serde(default = "default_version")]
    pub version: i32,
    pub master_fingerprint: String,
    pub master_public_key: String,
    pub device_id: String,
    pub session_id: String,
    pub session_public_key: String,
    pub session_started: DateTime<Utc>,
    pub session_certificate: String,
    pub ratchet_count: i32,
    pub ratchet_public_keys: Vec<String>,
    pub checkpoint_signatures: Vec<CheckpointSignature>,
    /// Hex-encoded initial document hash bound into the session certificate signature.
    /// Required to reconstruct `build_cert_data` for signature verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_document_hash: Option<String>,
}

/// Signature binding a checkpoint hash to a ratchet key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointSignature {
    pub ordinal: u64,
    pub checkpoint_hash: String,
    pub ratchet_index: i32,
    pub signature: String,
}

/// WritersProof temporal beacon attestation.
///
/// Contains drand and NIST beacon values fetched and counter-signed by WritersProof.
/// The `wp_signature` field is an Ed25519 signature over:
/// `(checkpoint_hash || drand_round || drand_randomness || nist_pulse_index || nist_output_value || fetched_at)`
///
/// This signature is included in the H2 seal hash, making evidence with beacon
/// attestation cryptographically distinct from evidence without it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpBeaconAttestation {
    /// drand League of Entropy round number.
    pub drand_round: u64,
    /// drand randomness output (hex-encoded, 32 bytes).
    pub drand_randomness: String,
    /// NIST Randomness Beacon pulse index.
    pub nist_pulse_index: u64,
    /// NIST beacon output value (hex-encoded, 64 bytes).
    pub nist_output_value: String,
    /// NIST pulse timestamp (RFC 3339).
    pub nist_timestamp: String,
    /// When WritersProof fetched the beacon values (RFC 3339).
    pub fetched_at: String,
    /// WritersProof Ed25519 counter-signature over the bundle (hex-encoded, 64 bytes).
    pub wp_signature: String,
    /// Key ID of the CA key used to produce `wp_signature` (hex fingerprint).
    /// Absent in attestations created before key rotation support was added;
    /// the verifier falls back to timestamp-based key selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wp_key_id: Option<String>,
}

/// Reference to a W3C Verifiable Credential issued by WritersLogic.
///
/// Allows evidence packets to be linked to digital credentials for wallet export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialReference {
    /// Unique credential identifier (UUID v4)
    pub credential_id: String,

    /// Issuer domain (always "writerslogic.com")
    pub issuer: String,

    /// Credential type (always "writersproof.authorship.v1")
    pub credential_type: String,

    /// ISO 8601 timestamp when credential was issued
    pub issued_at: String,

    /// ISO 8601 timestamp when credential expires
    pub expires_at: String,

    /// SHA-256 hash of the evidence packet this credential references
    pub evidence_hash: String,
}

/// Hash-chain attestation linking a compile/export event to its source session.
///
/// Produced when a known bundle app (Scrivener, Final Draft, Vellum) creates a
/// derived output file (`.docx`, `.pdf`, `.fdx`) within 30 seconds of the last
/// active checkpoint for the session that owns the source bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManuscriptExportAttestation {
    /// Session ID that produced the source content.
    pub source_session_id: String,
    /// BLAKE3 hash of the bundle root at compile time (hex).
    pub bundle_hash: String,
    /// BLAKE3 hash of the exported output file (hex).
    pub output_hash: String,
    /// SHA-256 hash of the output file path (privacy-preserving; hex).
    pub output_path_hash: String,
    /// Unix nanoseconds of the last active checkpoint before export.
    pub source_checkpoint_ns: i64,
    /// Unix nanoseconds when the output file was first observed.
    pub export_detected_ns: i64,
}

/// One entry in a document's binder/scene tree snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentStructureEntry {
    /// Unique identifier from the source format (Scrivener BinderItem ID, FDX Scene heading).
    pub uuid: String,
    /// Human-readable title of the item.
    pub title: String,
    /// Nesting depth within the binder/outline tree (0 = root).
    pub depth: u32,
    /// Type label from the source format (e.g. `"Text"`, `"Folder"`, `"Scene"`).
    pub item_type: String,
}

/// Snapshot of a document's internal structure, captured at session checkpoint time.
///
/// For Scrivener: parsed from `project.scrivx`. For Final Draft: parsed from the
/// ZIP-embedded FDX XML. The snapshot proves the structure existed at checkpoint time
/// without revealing the document's content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentStructureSnapshot {
    /// BLAKE3 hash of the document path string (privacy-preserving; hex).
    pub document_path_hash: String,
    /// Binder/outline entries captured from the project metadata file.
    pub entries: Vec<DocumentStructureEntry>,
    /// BLAKE3 hash of the raw metadata source file (hex).
    pub source_hash: String,
    /// When this snapshot was taken.
    pub captured_at: chrono::DateTime<chrono::Utc>,
}

/// Classification of a context period within a writing session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContextPeriodType {
    /// Active writing with document focus.
    Focused,
    /// AI-assisted writing (copilot, dictation, etc.).
    Assisted,
    /// Content sourced from outside the session (paste, import).
    External,
    /// Pause or away-from-keyboard interval.
    Break,
    /// Research activity (browser, reference material).
    Research,
    /// Editing or revising existing content.
    Revision,
    /// Idle period with no meaningful input.
    Idle,
}

impl std::fmt::Display for ContextPeriodType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Focused => "focused",
            Self::Assisted => "assisted",
            Self::External => "external",
            Self::Break => "break",
            Self::Research => "research",
            Self::Revision => "revision",
            Self::Idle => "idle",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for ContextPeriodType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "focused" => Ok(Self::Focused),
            "assisted" => Ok(Self::Assisted),
            "external" => Ok(Self::External),
            "break" => Ok(Self::Break),
            "research" => Ok(Self::Research),
            "revision" => Ok(Self::Revision),
            "idle" => Ok(Self::Idle),
            other => Err(format!("unknown context period type: {other}")),
        }
    }
}

/// Time-bounded context annotation (e.g. break, research, revision).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPeriod {
    #[serde(rename = "type")]
    pub period_type: ContextPeriodType,
    pub note: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DocumentInfo {
    pub title: String,
    pub path: String,
    pub final_hash: String,
    pub final_size: u64,
}

/// Provenance metadata identifying the recording device, OS, and session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordProvenance {
    pub device_id: String,
    pub signing_pubkey: String,
    pub key_source: String,
    pub hostname: String,
    pub os: String,
    pub os_version: Option<String>,
    pub architecture: String,
    pub session_id: String,
    pub session_started: DateTime<Utc>,
    pub input_devices: Vec<InputDeviceInfo>,
    pub access_control: Option<AccessControlInfo>,
}

/// HID input device descriptor with vendor/product IDs and fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub product_name: String,
    pub serial_number: Option<String>,
    pub connection_type: String,
    pub fingerprint: String,
}

impl From<&HidDeviceInfo> for InputDeviceInfo {
    fn from(hid: &HidDeviceInfo) -> Self {
        let transport = hid.transport_type();
        Self {
            vendor_id: u16::try_from(hid.vendor_id).unwrap_or(0),
            product_id: u16::try_from(hid.product_id).unwrap_or(0),
            product_name: hid.product_name.clone(),
            serial_number: hid.serial_number.clone(),
            connection_type: transport.as_str().to_owned(),
            fingerprint: hid.fingerprint(),
        }
    }
}

/// File and process access control state at capture time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlInfo {
    pub captured_at: DateTime<Utc>,
    pub file_owner_uid: i32,
    pub file_owner_name: Option<String>,
    pub file_permissions: String,
    pub file_group_gid: Option<i32>,
    pub file_group_name: Option<String>,
    pub process_uid: i32,
    pub process_euid: i32,
    pub process_username: Option<String>,
    pub limitations: Vec<String>,
}

/// Single checkpoint in the evidence chain with VDF proof and content hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointProof {
    pub ordinal: u64,
    pub content_hash: String,
    pub content_size: u64,
    pub timestamp: DateTime<Utc>,
    pub message: Option<String>,
    pub vdf_input: Option<String>,
    pub vdf_output: Option<String>,
    pub vdf_iterations: Option<u64>,
    pub elapsed_time: Option<Duration>,
    pub previous_hash: String,
    /// Hash of this checkpoint's full chain state (content + ordinal + previous hash).
    pub hash: String,
    pub signature: Option<String>,
}

/// Hardware attestation evidence binding TPM/TEE state to session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareEvidence {
    pub bindings: Vec<tpm::Binding>,
    pub device_id: String,
    /// Session-bound nonce for TPM quote anti-replay.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_nonce",
        deserialize_with = "deserialize_optional_nonce"
    )]
    pub attestation_nonce: Option<[u8; 32]>,
}

/// Keystroke session evidence with timing samples and rate analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeEvidence {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub duration: Duration,
    pub total_keystrokes: u64,
    pub total_samples: i32,
    pub keystrokes_per_minute: f64,
    pub unique_doc_states: i32,
    pub chain_valid: bool,
    pub plausible_human_rate: bool,
    pub samples: Vec<jitter::Sample>,
    /// Per-keystroke behavioral timing data (zone, dwell, flight) for forensic analysis.
    /// Empty in older packets that predate this field.
    #[serde(default)]
    pub typing_samples: Vec<jitter::SimpleJitterSample>,
    /// Ratio of samples using hardware entropy (0.0..1.0, cpoe_jitter only).
    #[serde(default)]
    pub phys_ratio: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralEvidence {
    pub edit_topology: Vec<EditRegion>,
    pub metrics: Option<ForensicMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<BehavioralFingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forgery_analysis: Option<ForgeryAnalysis>,
}

/// Spatial edit region within the document (position range + byte delta).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRegion {
    pub start_pct: f64,
    pub end_pct: f64,
    pub delta_sign: i32,
    pub byte_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMetrics {
    pub monotonic_append_ratio: f64,
    pub edit_entropy: f64,
    pub median_interval_seconds: f64,
    pub positive_negative_ratio: f64,
    pub deletion_clustering: f64,
    pub assessment: Option<String>,
    pub anomaly_count: Option<i32>,
}

/// Physical environment evidence for machine binding and non-repudiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalContextEvidence {
    pub clock_skew: u64,
    pub thermal_proxy: u32,
    pub silicon_puf_hash: String,
    pub io_latency_ns: u64,
    pub combined_hash: String,
}

/// Evidence of dictation input during a writing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictationEvent {
    /// Timestamp when dictation started (nanoseconds since epoch).
    pub start_ns: i64,
    /// Timestamp when dictation ended.
    pub end_ns: i64,
    /// Number of words produced.
    pub word_count: u32,
    /// Number of characters produced.
    pub char_count: u32,
    /// Input method identifier (e.g., "com.apple.inputmethod.DictationIME").
    pub input_method: String,
    /// Whether microphone hardware was active during the dictation window.
    pub mic_active: bool,
    /// Words per minute (computed: word_count / duration_minutes).
    pub words_per_minute: f64,
    /// Behavioral plausibility score (0.0-1.0).
    /// Based on WPM range (80-200 normal), duration consistency, etc.
    pub plausibility_score: f64,
}

/// External timestamping anchors (OTS, RFC 3161, notary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAnchors {
    pub opentimestamps: Vec<OtsProof>,
    pub rfc3161: Vec<Rfc3161Proof>,
    pub proofs: Vec<AnchorProof>,
}

/// OpenTimestamps proof for a chain hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtsProof {
    pub chain_hash: String,
    pub proof: String,
    pub status: String,
    pub block_height: Option<u64>,
    pub block_time: Option<DateTime<Utc>>,
}

/// RFC 3161 timestamp authority response for a chain hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc3161Proof {
    pub chain_hash: String,
    pub tsa_url: String,
    pub response: String,
    pub timestamp: DateTime<Utc>,
}

/// External anchor proof from a timestamping provider (TSA, notary, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorProof {
    pub provider: String,
    pub provider_name: String,
    pub legal_standing: String,
    pub regions: Vec<String>,
    pub hash: String,
    pub timestamp: DateTime<Utc>,
    pub status: String,
    pub raw_proof: String,
    pub verify_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    #[serde(rename = "type")]
    pub claim_type: ClaimType,
    pub description: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClaimType {
    /// Checkpoint chain hash integrity verified.
    #[serde(rename = "chain_integrity")]
    ChainIntegrity,
    /// Elapsed time bound by VDF proof.
    #[serde(rename = "time_elapsed")]
    TimeElapsed,
    /// Author declaration recorded.
    #[serde(rename = "process_declared")]
    ProcessDeclared,
    /// Author presence verified via challenges.
    #[serde(rename = "presence_verified")]
    PresenceVerified,
    /// Keystroke timing data verified as human-plausible.
    #[serde(rename = "keystrokes_verified")]
    KeystrokesVerified,
    /// Hardware TPM/TEE attestation included.
    #[serde(rename = "hardware_attested")]
    HardwareAttested,
    /// Behavioral forensic analysis completed.
    #[serde(rename = "behavior_analyzed")]
    BehaviorAnalyzed,
    /// Context periods (breaks, research) recorded.
    #[serde(rename = "contexts_recorded")]
    ContextsRecorded,
    /// External timestamp anchors (OTS, RFC 3161) present.
    #[serde(rename = "external_anchored")]
    ExternalAnchored,
    /// Key hierarchy certificate chain included.
    #[serde(rename = "key_hierarchy")]
    KeyHierarchy,
    /// Dictation input verified as plausible speech-to-text.
    #[serde(rename = "dictation_verified")]
    DictationVerified,
}
