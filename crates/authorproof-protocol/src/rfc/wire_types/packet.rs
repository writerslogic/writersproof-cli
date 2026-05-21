// SPDX-License-Identifier: Apache-2.0

//! Wire-format evidence packet type per CDDL `evidence-packet`.

use serde::{Deserialize, Serialize};

use super::checkpoint::CheckpointWire;
use super::components::{
    BaselineVerification, ChannelBinding, DocumentRef, PhysicalLiveness, PresenceChallenge,
    ProfileDeclarationWire,
};
use super::enums::{AttestationTier, ContentTier};
use super::hash::HashValue;
use super::serde_helpers::fixed_bytes_16;
use super::CBOR_TAG_EVIDENCE_PACKET;
use crate::codec::{self, CodecError};

/// Wire-format evidence packet per CDDL `evidence-packet`.
///
/// Wrapped with CBOR tag 1129336645 (CPoE) for transmission.
///
/// ```cddl
/// evidence-packet = {
///     1 => uint,                    ; version
///     2 => tstr,                    ; profile-uri
///     3 => uuid,                    ; packet-id
///     4 => cpoe-timestamp,           ; created
///     5 => document-ref,            ; document
///     6 => [3* checkpoint],         ; checkpoints (min 3)
///     ? 7 => attestation-tier,
///     ? 8 => [* tstr],              ; limitations
///     ? 9 => profile-declaration,
///     ? 10 => [+ presence-challenge],
///     ? 11 => channel-binding,
///     ? 13 => content-tier,
///     ? 14 => hash-value,           ; previous-packet-ref
///     ? 15 => uint,                 ; packet-sequence
///     ? 18 => physical-liveness,
///     ? 19 => baseline-verification,
///     ? 20 => tstr,                  ; author-did
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePacketWire {
    /// Must be 1
    #[serde(rename = "1")]
    pub version: u64,

    #[serde(rename = "2")]
    pub profile_uri: String,

    #[serde(rename = "3", with = "fixed_bytes_16")]
    pub packet_id: [u8; 16],

    /// Epoch ms
    #[serde(rename = "4")]
    pub created: u64,

    #[serde(rename = "5")]
    pub document: DocumentRef,

    /// Minimum 3 checkpoints required
    #[serde(rename = "6")]
    pub checkpoints: Vec<CheckpointWire>,

    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<AttestationTier>,

    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub limitations: Option<Vec<String>>,

    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileDeclarationWire>,

    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub presence_challenges: Option<Vec<PresenceChallenge>>,

    #[serde(rename = "11", default, skip_serializing_if = "Option::is_none")]
    pub channel_binding: Option<ChannelBinding>,

    /// Ed25519 public key that signed this packet (32 bytes).
    #[serde(rename = "12", default, skip_serializing_if = "Option::is_none")]
    pub signing_public_key: Option<serde_bytes::ByteBuf>,

    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub content_tier: Option<ContentTier>,

    #[serde(rename = "14", default, skip_serializing_if = "Option::is_none")]
    pub previous_packet_ref: Option<HashValue>,

    /// 1-based
    #[serde(rename = "15", default, skip_serializing_if = "Option::is_none")]
    pub packet_sequence: Option<u64>,

    #[serde(rename = "18", default, skip_serializing_if = "Option::is_none")]
    pub physical_liveness: Option<PhysicalLiveness>,

    #[serde(rename = "19", default, skip_serializing_if = "Option::is_none")]
    pub baseline_verification: Option<BaselineVerification>,

    /// Author DID URI (e.g., "did:webvh:..." or "did:key:...").
    #[serde(rename = "20", default, skip_serializing_if = "Option::is_none")]
    pub author_did: Option<String>,

    /// Original document content embedded in the evidence packet.
    /// When present, the .cpoe file is a self-contained archive: evidence
    /// plus the document it attests. The content hash in `document` (key 5)
    /// must match SHA-256 of this field.
    #[serde(rename = "21", default, skip_serializing_if = "Option::is_none")]
    pub document_content: Option<serde_bytes::ByteBuf>,

    /// Original document filename (for extraction).
    #[serde(rename = "22", default, skip_serializing_if = "Option::is_none")]
    pub document_filename: Option<String>,

    /// Project files: other documents in the same writing project.
    /// Each entry has filename, content hash, and checkpoint count.
    /// Enables project-level evidence for multi-file workflows (Scrivener, LaTeX).
    #[serde(rename = "23", default, skip_serializing_if = "Option::is_none")]
    pub project_files: Option<Vec<ProjectFileRef>>,

    /// Monotonic hardware counter value at session export time.
    ///
    /// Sourced from the TPM monotonic counter or SE-backed HMAC counter chain.
    /// Verifiers reject evidence where this value is not strictly greater than
    /// the previous session's counter for the same signing identity.
    #[serde(rename = "24", default, skip_serializing_if = "Option::is_none")]
    pub session_counter: Option<u64>,

    /// Session-level forensic metrics computed at export time.
    #[serde(rename = "25", default, skip_serializing_if = "Option::is_none")]
    pub forensic_summary: Option<ForensicSummaryWire>,
}

/// Session-level behavioral metrics embedded in the evidence packet.
///
/// These are raw observational metrics only.  Scores and verdicts belong
/// in the attestation result (`.cwar`), not in the evidence packet, so
/// that relying parties can apply their own policy to the raw signals.
///
/// ```cddl
/// forensic-summary = {
///     1 => float,    ; words-per-minute
///     2 => float,    ; mean-iki-ms
///     3 => float,    ; correction-ratio
///     5 => tstr,     ; writing-mode
///     ? 7 => float,  ; hurst-exponent
///     8 => uint,     ; keystroke-count
///     9 => float,    ; editing-ratio
///     10 => uint,    ; checkpoint-count
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicSummaryWire {
    #[serde(rename = "1")]
    pub words_per_minute: f64,
    #[serde(rename = "2")]
    pub mean_iki_ms: f64,
    #[serde(rename = "3")]
    pub correction_ratio: f64,
    #[serde(rename = "5")]
    pub writing_mode: String,
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub hurst_exponent: Option<f64>,
    #[serde(rename = "8")]
    pub keystroke_count: u64,
    #[serde(rename = "9")]
    pub editing_ratio: f64,
    #[serde(rename = "10")]
    pub checkpoint_count: u64,
    #[serde(rename = "11")]
    pub assessment_score: f64,
    #[serde(rename = "12")]
    pub coefficient_of_variation: f64,
    #[serde(rename = "13")]
    pub biological_cadence_score: f64,
    #[serde(rename = "14")]
    pub timing_entropy: f64,
    #[serde(rename = "15")]
    pub pause_entropy: f64,
    #[serde(rename = "16", default, skip_serializing_if = "Option::is_none")]
    pub cognitive_load_score: Option<f64>,
    #[serde(rename = "17", default, skip_serializing_if = "Option::is_none")]
    pub revision_topology_score: Option<f64>,
    #[serde(rename = "18", default, skip_serializing_if = "Option::is_none")]
    pub error_ecology_score: Option<f64>,
    #[serde(rename = "19", default, skip_serializing_if = "Option::is_none")]
    pub likelihood_p_cognitive: Option<f64>,
    #[serde(rename = "20", default, skip_serializing_if = "Option::is_none")]
    pub forgery_difficulty: Option<f64>,
    #[serde(rename = "21", default, skip_serializing_if = "Option::is_none")]
    pub cross_modal_score: Option<f64>,
    #[serde(rename = "22", default, skip_serializing_if = "Option::is_none")]
    pub snr_db: Option<f64>,
    #[serde(rename = "23", default, skip_serializing_if = "Option::is_none")]
    pub lyapunov_exponent: Option<f64>,
    #[serde(rename = "24")]
    pub transcription_suspicious: bool,
    #[serde(rename = "25", default, skip_serializing_if = "Option::is_none")]
    pub composition_mode: Option<String>,
}

impl EvidencePacketWire {
    /// Verify that this packet's `session_counter` is strictly greater than
    /// `previous_counter` for the same signing identity.
    ///
    /// Returns `Ok(())` when:
    /// - `session_counter` is absent in either packet (counter not used).
    /// - `previous_counter` is `None` (first session for this identity).
    /// - `self.session_counter > previous_counter`.
    ///
    /// Returns `Err` when both counters are present and the new one is not
    /// strictly greater, indicating a replayed or out-of-order session.
    pub fn verify_session_counter_order(
        &self,
        previous_counter: Option<u64>,
    ) -> Result<(), String> {
        match (self.session_counter, previous_counter) {
            (Some(new), Some(prev)) if new <= prev => Err(format!(
                "session counter {new} is not greater than previous {prev}; possible replay"
            )),
            _ => Ok(()),
        }
    }
}

/// Reference to a file within a writing project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectFileRef {
    /// Relative filename within the project.
    #[serde(rename = "1")]
    pub filename: String,
    /// SHA-256 content hash.
    #[serde(rename = "2")]
    pub content_hash: String,
    /// Number of checkpoints for this file.
    #[serde(rename = "3")]
    pub checkpoint_count: u64,
    /// Total keystrokes recorded for this file.
    #[serde(rename = "4")]
    pub keystroke_count: u64,
}

/// Minimum number of checkpoints per CDDL: `6 => [3* checkpoint]`.
const MIN_CHECKPOINTS: usize = 3;
/// Maximum checkpoints before rejecting as DoS payload.
const MAX_CHECKPOINTS: usize = 10_000;
/// Maximum number of limitation strings.
const MAX_LIMITATIONS: usize = 100;
/// Maximum number of presence challenges.
const MAX_PRESENCE_CHALLENGES: usize = 100;
use super::MAX_STRING_LEN;

impl EvidencePacketWire {
    /// Encode to CBOR with the CPoE semantic tag.
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode_tagged(self, CBOR_TAG_EVIDENCE_PACKET)
    }

    /// Decode from tagged CBOR bytes with validation.
    pub fn decode_cbor(data: &[u8]) -> Result<Self, CodecError> {
        let packet: Self = codec::cbor::decode_tagged(data, CBOR_TAG_EVIDENCE_PACKET)?;
        packet.validate()?;
        Ok(packet)
    }

    /// Encode to CBOR without the semantic tag.
    pub fn encode_cbor_untagged(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode(self)
    }

    /// Decode from untagged CBOR bytes with validation.
    pub fn decode_cbor_untagged(data: &[u8]) -> Result<Self, CodecError> {
        let packet: Self = codec::cbor::decode(data)?;
        packet.validate()?;
        Ok(packet)
    }

    /// Check CDDL-mandated invariants and size limits after deserialization.
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.version != 1 {
            return Err(CodecError::Validation(format!(
                "unsupported version {}, expected 1",
                self.version
            )));
        }

        if self.profile_uri.is_empty() || self.profile_uri.len() > MAX_STRING_LEN {
            return Err(CodecError::Validation(format!(
                "profile_uri length {} out of range [1, {}]",
                self.profile_uri.len(),
                MAX_STRING_LEN
            )));
        }

        // Require at least 4 non-zero bytes to guard against low-entropy IDs.
        const MIN_NONZERO_BYTES: usize = 4;
        let nonzero_count = self.packet_id.iter().filter(|&&b| b != 0).count();
        if nonzero_count < MIN_NONZERO_BYTES {
            return Err(CodecError::Validation(format!(
                "packet_id has only {} non-zero bytes (minimum {})",
                nonzero_count, MIN_NONZERO_BYTES
            )));
        }

        if self.created == 0 {
            return Err(CodecError::Validation(
                "created timestamp must not be zero".into(),
            ));
        }

        if self.checkpoints.len() < MIN_CHECKPOINTS {
            return Err(CodecError::Validation(format!(
                "need at least {} checkpoints, got {}",
                MIN_CHECKPOINTS,
                self.checkpoints.len()
            )));
        }
        if self.checkpoints.len() > MAX_CHECKPOINTS {
            return Err(CodecError::Validation(format!(
                "too many checkpoints: {} (max {})",
                self.checkpoints.len(),
                MAX_CHECKPOINTS
            )));
        }

        if let Some(ref lims) = self.limitations {
            if lims.len() > MAX_LIMITATIONS {
                return Err(CodecError::Validation(format!(
                    "too many limitations: {} (max {})",
                    lims.len(),
                    MAX_LIMITATIONS
                )));
            }
            for (i, s) in lims.iter().enumerate() {
                if s.len() > MAX_STRING_LEN {
                    return Err(CodecError::Validation(format!(
                        "limitation[{}] too long: {} (max {})",
                        i,
                        s.len(),
                        MAX_STRING_LEN
                    )));
                }
            }
        }
        if let Some(ref pcs) = self.presence_challenges {
            if pcs.is_empty() {
                return Err(CodecError::Validation(
                    "presence_challenges must be non-empty if present".into(),
                ));
            }
            if pcs.len() > MAX_PRESENCE_CHALLENGES {
                return Err(CodecError::Validation(format!(
                    "too many presence_challenges: {} (max {})",
                    pcs.len(),
                    MAX_PRESENCE_CHALLENGES
                )));
            }
            for (i, pc) in pcs.iter().enumerate() {
                pc.validate().map_err(|e| {
                    CodecError::Validation(format!("presence_challenge[{}]: {}", i, e))
                })?;
            }
        }

        self.document.validate().map_err(CodecError::Validation)?;
        if let Some(ref name) = self.document.filename {
            if name.len() > MAX_STRING_LEN {
                return Err(CodecError::Validation(format!(
                    "document filename too long: {} (max {})",
                    name.len(),
                    MAX_STRING_LEN
                )));
            }
            if name.contains('\0') {
                return Err(CodecError::Validation(
                    "document filename contains null byte".into(),
                ));
            }
        }

        for (i, cp) in self.checkpoints.iter().enumerate() {
            cp.validate()
                .map_err(|e| CodecError::Validation(format!("checkpoint[{}]: {}", i, e)))?;
            if cp.sequence != i as u64 {
                return Err(CodecError::Validation(format!(
                    "checkpoint[{}] has sequence {} (expected monotonic {})",
                    i, cp.sequence, i
                )));
            }
        }

        if let Some(ref pl) = self.physical_liveness {
            pl.validate().map_err(CodecError::Validation)?;
        }

        if let Some(ref prof) = self.profile {
            prof.validate().map_err(CodecError::Validation)?;
        }

        if let Some(seq) = self.packet_sequence {
            if seq == 0 {
                return Err(CodecError::Validation(
                    "packet_sequence is 1-based, got 0".into(),
                ));
            }
        }

        if let Some(ref did) = self.author_did {
            if did.is_empty() || did.len() > MAX_STRING_LEN {
                return Err(CodecError::Validation(format!(
                    "author_did length {} out of range [1, {}]",
                    did.len(),
                    MAX_STRING_LEN
                )));
            }
            if !did.starts_with("did:") {
                return Err(CodecError::Validation(
                    "author_did must start with 'did:'".into(),
                ));
            }
        }

        // Validate embedded document: content hash must match if present.
        // Only SHA-256 is supported — reject other algorithms to prevent
        // hash comparison bypass via non-32-byte digest lengths.
        if let Some(ref content) = self.document_content {
            if content.len() > 100_000_000 {
                return Err(CodecError::Validation(format!(
                    "document_content too large: {} bytes (max 100MB)",
                    content.len()
                )));
            }
            if self.document.content_hash.algorithm != super::enums::HashAlgorithm::Sha256 {
                return Err(CodecError::Validation(
                    "document_content requires SHA-256 content_hash for verification".into(),
                ));
            }
            use sha2::{Digest, Sha256};
            let hash: [u8; 32] = Sha256::digest(content.as_ref()).into();
            // Constant-time comparison to prevent oracle-based probing
            use subtle::ConstantTimeEq;
            if hash.ct_eq(&self.document.content_hash.digest).unwrap_u8() == 0 {
                return Err(CodecError::Validation(
                    "document_content hash does not match document.content_hash".into(),
                ));
            }
        }

        if let Some(ref name) = self.document_filename {
            if name.len() > MAX_STRING_LEN {
                return Err(CodecError::Validation(format!(
                    "document_filename too long: {} (max {})",
                    name.len(), MAX_STRING_LEN
                )));
            }
            if name.contains('\0') {
                return Err(CodecError::Validation(
                    "document_filename contains null byte".into(),
                ));
            }
            if name.contains('/') || name.contains('\\') || name.contains("..") {
                return Err(CodecError::Validation(
                    "document_filename contains path traversal characters".into(),
                ));
            }
        }

        if let Some(ref pf) = self.project_files {
            if pf.len() > 1000 {
                return Err(CodecError::Validation(format!(
                    "too many project_files: {} (max 1000)",
                    pf.len()
                )));
            }
        }

        Ok(())
    }
}
