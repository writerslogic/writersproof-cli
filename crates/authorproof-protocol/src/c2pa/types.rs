// SPDX-License-Identifier: Apache-2.0

use crate::rfc::EvidencePacket;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ASSERTION_LABEL_CPOE;

/// C2PA process assertion carrying CPoP evidence metadata.
///
/// `jitter_seals` are derived from each checkpoint's `checkpoint_hash` (not `jitter_hash`)
/// because the checkpoint hash commits to the full checkpoint state including any jitter
/// binding, making it the strongest per-checkpoint seal available in all attestation tiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAssertion {
    pub label: String,
    pub version: u32,
    pub evidence_id: String,
    pub evidence_hash: String,
    pub jitter_seals: Vec<JitterSeal>,
    /// Forensic signal scores from the 5 analysis dimensions.
    /// Each is a composite [0.0, 1.0] where 1.0 = strongly cognitive.
    #[serde(rename = "forensicSignals", skip_serializing_if = "Option::is_none")]
    pub forensic_signals: Option<ForensicSignalScores>,
    /// Dominant composition mode during authoring.
    #[serde(rename = "compositionMode", skip_serializing_if = "Option::is_none")]
    pub composition_mode: Option<String>,
    /// Writing mode classification: "cognitive", "transcriptive", "mixed".
    #[serde(rename = "writingMode", skip_serializing_if = "Option::is_none")]
    pub writing_mode: Option<String>,
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

impl ProcessAssertion {
    pub fn from_evidence(packet: &EvidencePacket, original_bytes: &[u8]) -> Self {
        let hash = Sha256::digest(original_bytes);

        let jitter_seals = packet
            .checkpoints
            .iter()
            .map(|cp| JitterSeal {
                sequence: cp.sequence,
                timestamp: cp.timestamp,
                seal_hash: hex::encode(&cp.checkpoint_hash.digest),
            })
            .collect();

        Self {
            label: ASSERTION_LABEL_CPOE.to_string(),
            version: packet.version,
            evidence_id: hex::encode(&packet.packet_id),
            evidence_hash: hex::encode(hash),
            jitter_seals,
            forensic_signals: None,
            composition_mode: None,
            writing_mode: None,
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
    #[serde(default)]
    pub exclusions: Vec<ExclusionRange>,
}

/// Byte range exclusion for embedded manifests (§9.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionRange {
    pub start: u64,
    pub length: u64,
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
    /// §10.5, required in claim-map-v2.
    pub claim_generator_info: Vec<ClaimGeneratorInfo>,

    /// §10.3, required.
    #[serde(rename = "instanceID")]
    pub instance_id: String,

    /// §10.7, required.
    pub signature: String,

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

/// Summary of a parsed JUMBF superbox structure (ISO 19566-5).
#[derive(Debug)]
pub struct JumbfInfo {
    /// Total byte size of the outermost JUMBF superbox including header.
    pub total_size: usize,
    /// Number of immediate child boxes within the superbox.
    pub child_boxes: u32,
}
