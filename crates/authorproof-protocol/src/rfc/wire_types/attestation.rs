// SPDX-License-Identifier: Apache-2.0

//! Wire-format attestation result and forensic types per CDDL schema.
//!
//! Implements `entropy-report`, `forgery-cost-estimate`, `absence-claim`,
//! `forensic-flag`, `forensic-summary`, and `attestation-result`.

use serde::{Deserialize, Serialize};

use super::enums::{AbsenceType, AttestationTier, ConfidenceTier, CostUnit, Verdict};
use super::hash::{HashValue, TimeWindow};
use super::CBOR_TAG_ATTESTATION_RESULT;
use crate::codec::{self, CodecError};

/// Entropy assessment report per CDDL `entropy-report`.
///
/// ```cddl
/// entropy-report = {
///     1 => float32,
///     2 => float32,
///     3 => float32,
///     4 => bool,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    /// Timing entropy (bits/sample)
    #[serde(rename = "1")]
    pub timing_entropy: f32,

    /// Revision entropy (bits)
    #[serde(rename = "2")]
    pub revision_entropy: f32,

    /// Pause entropy (bits)
    #[serde(rename = "3")]
    pub pause_entropy: f32,

    /// Meets required threshold.
    /// Intentionally not cross-checked against entropy values during validation;
    /// this field is self-reported by the prover and verified by the appraiser.
    #[serde(rename = "4")]
    pub meets_threshold: bool,
}

impl EntropyReport {
    /// Return `true` if all entropy values meet the spec appraisal thresholds.
    pub fn validate_thresholds(&self) -> bool {
        self.timing_entropy >= 3.0 && self.revision_entropy >= 3.0 && self.pause_entropy >= 2.0
    }
}

/// Forgery cost estimate per CDDL `forgery-cost-estimate`.
///
/// ```cddl
/// forgery-cost-estimate = {
///     1 => float32,
///     2 => float32,
///     3 => float32,
///     4 => float32,
///     5 => cost-unit,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeryCostEstimate {
    /// SWF forgery cost
    #[serde(rename = "1")]
    pub c_swf: f32,

    /// Entropy forgery cost
    #[serde(rename = "2")]
    pub c_entropy: f32,

    /// Hardware forgery cost
    #[serde(rename = "3")]
    pub c_hardware: f32,

    /// Total cost
    #[serde(rename = "4")]
    pub c_total: f32,

    /// Unit
    #[serde(rename = "5")]
    pub currency: CostUnit,
}

/// Absence claim per CDDL `absence-claim`.
///
/// ```cddl
/// absence-claim = {
///     1 => absence-type,
///     2 => time-window,
///     3 => tstr,
///     ? 4 => any,
///     5 => bool,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbsenceClaim {
    /// Absence type
    #[serde(rename = "1")]
    pub absence_type: AbsenceType,

    /// Time window
    #[serde(rename = "2")]
    pub window: TimeWindow,

    /// Claim identifier
    #[serde(rename = "3")]
    pub claim_id: String,

    /// Threshold/parameter
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ciborium::Value>,

    /// Assertion holds
    #[serde(rename = "5")]
    pub assertion: bool,
}

/// Individual forensic flag per CDDL `forensic-flag`.
///
/// ```cddl
/// forensic-flag = {
///     1 => tstr,
///     2 => bool,
///     3 => uint,
///     4 => uint,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicFlag {
    /// Mechanism name (e.g., "SNR", "CLC")
    #[serde(rename = "1")]
    pub mechanism: String,

    /// Triggered
    #[serde(rename = "2")]
    pub triggered: bool,

    /// Affected windows
    #[serde(rename = "3")]
    pub affected_windows: u64,

    /// Total windows
    #[serde(rename = "4")]
    pub total_windows: u64,
}

/// Forensic assessment summary per CDDL `forensic-summary`.
///
/// ```cddl
/// forensic-summary = {
///     1 => uint,
///     2 => uint,
///     3 => uint,
///     4 => uint,
///     ? 5 => [+ forensic-flag],
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicSummary {
    /// Flags triggered
    #[serde(rename = "1")]
    pub flags_triggered: u64,

    /// Flags evaluated
    #[serde(rename = "2")]
    pub flags_evaluated: u64,

    /// Anomalous checkpoints
    #[serde(rename = "3")]
    pub affected_checkpoints: u64,

    /// Total checkpoints
    #[serde(rename = "4")]
    pub total_checkpoints: u64,

    /// Per-flag detail
    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<ForensicFlag>>,
}

/// Human-to-tool effort attribution for attestation results per CDDL `effort-attribution`.
///
/// ```cddl
/// effort-attribution = {
///     1 => float32,
///     2 => uint,
///     3 => uint,
///     ? 4 => uint,
///     ? 5 => uint,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffortAttribution {
    #[serde(rename = "1")]
    pub human_fraction: f32,

    #[serde(rename = "2")]
    pub human_checkpoints: u64,

    #[serde(rename = "3")]
    pub receipt_checkpoints: u64,

    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub tool_attributed_chars: Option<u64>,

    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub total_chars: Option<u64>,
}

/// Wire-format attestation result per CDDL `attestation-result`.
///
/// Wrapped with CBOR tag 1129791826 (CWAR) for transmission.
///
/// **Validation**: Raw serde deserialization (e.g. `ciborium::from_reader`)
/// does NOT enforce size/version constraints. Always use [`Self::decode_cbor`]
/// or [`Self::decode_cbor_untagged`] which call [`Self::validate`] after decode,
/// or call `validate()` manually after deserializing through other paths.
///
/// ```cddl
/// attestation-result = {
///     1 => uint,                    ; version
///     2 => hash-value,              ; evidence-ref
///     3 => verdict,                 ; appraisal verdict
///     4 => attestation-tier,        ; assessed assurance level
///     5 => uint,                    ; chain-length
///     6 => uint,                    ; chain-duration (seconds)
///     ? 7 => entropy-report,
///     ? 8 => forgery-cost-estimate,
///     ? 9 => [+ absence-claim],
///     ? 10 => [* tstr],             ; warnings
///     11 => bstr,                   ; verifier-signature
///     12 => cpoe-timestamp,          ; created
///     ? 13 => forensic-summary,
///     ? 14 => confidence-tier,
///     ? 15 => effort-attribution,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResultWire {
    /// Schema version (must be 1)
    #[serde(rename = "1")]
    pub version: u64,

    /// Evidence packet reference
    #[serde(rename = "2")]
    pub evidence_ref: HashValue,

    /// Verdict
    #[serde(rename = "3")]
    pub verdict: Verdict,

    /// Assessed tier
    #[serde(rename = "4")]
    pub assessed_tier: AttestationTier,

    /// Chain length (checkpoints)
    #[serde(rename = "5")]
    pub chain_length: u64,

    /// Chain duration (seconds)
    #[serde(rename = "6")]
    pub chain_duration: u64,

    /// Entropy assessment (omitted for CORE)
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub entropy_report: Option<EntropyReport>,

    /// Forgery cost estimate
    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub forgery_cost: Option<ForgeryCostEstimate>,

    /// Absence claims
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub absence_claims: Option<Vec<AbsenceClaim>>,

    /// Warnings
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,

    /// Verifier signature (`COSE_Sign1`)
    #[serde(rename = "11", with = "serde_bytes")]
    pub verifier_signature: Vec<u8>,

    /// Appraisal timestamp (epoch ms)
    #[serde(rename = "12")]
    pub created: u64,

    /// Forensic summary
    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub forensic_summary: Option<ForensicSummary>,

    /// Confidence tier per CDDL `confidence-tier`
    #[serde(rename = "14", default, skip_serializing_if = "Option::is_none")]
    pub confidence_tier: Option<ConfidenceTier>,

    /// Effort attribution
    #[serde(rename = "15", default, skip_serializing_if = "Option::is_none")]
    pub effort_attribution: Option<EffortAttribution>,
}

/// Max absence claims.
const MAX_ABSENCE_CLAIMS: usize = 100;
/// Max warnings.
const MAX_WARNINGS: usize = 100;
use super::MAX_STRING_LEN;
/// Max forensic flags.
const MAX_FORENSIC_FLAGS: usize = 200;

impl AttestationResultWire {
    /// Encode to tagged CBOR (tag 1129791826 CWAR).
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode_tagged(self, CBOR_TAG_ATTESTATION_RESULT)
    }

    /// Decode from tagged CBOR bytes with validation.
    pub fn decode_cbor(data: &[u8]) -> Result<Self, CodecError> {
        let result: Self = codec::cbor::decode_tagged(data, CBOR_TAG_ATTESTATION_RESULT)?;
        result.validate()?;
        Ok(result)
    }

    /// Encode to untagged CBOR.
    pub fn encode_cbor_untagged(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode(self)
    }

    /// Decode from untagged CBOR bytes with validation.
    pub fn decode_cbor_untagged(data: &[u8]) -> Result<Self, CodecError> {
        let result: Self = codec::cbor::decode(data)?;
        result.validate()?;
        Ok(result)
    }

    /// Validate size limits after deserialization.
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.version != 1 {
            return Err(CodecError::Validation(format!(
                "unsupported WAR version {}, expected 1",
                self.version
            )));
        }
        if self.created == 0 {
            return Err(CodecError::Validation(
                "created timestamp must be non-zero".into(),
            ));
        }
        if self.chain_length == 0 {
            return Err(CodecError::Validation(
                "chain_length must be non-zero".into(),
            ));
        }
        if let Some(ref claims) = self.absence_claims {
            if claims.len() > MAX_ABSENCE_CLAIMS {
                return Err(CodecError::Validation(format!(
                    "too many absence_claims: {} (max {})",
                    claims.len(),
                    MAX_ABSENCE_CLAIMS
                )));
            }
            for (i, claim) in claims.iter().enumerate() {
                if claim.claim_id.len() > MAX_STRING_LEN {
                    return Err(CodecError::Validation(format!(
                        "absence_claims[{}].claim_id too long: {}",
                        i,
                        claim.claim_id.len()
                    )));
                }
            }
        }
        self.evidence_ref
            .validate_digest_length()
            .map_err(CodecError::Validation)?;
        if let Some(ref warnings) = self.warnings {
            if warnings.len() > MAX_WARNINGS {
                return Err(CodecError::Validation(format!(
                    "too many warnings: {} (max {})",
                    warnings.len(),
                    MAX_WARNINGS
                )));
            }
            for (i, w) in warnings.iter().enumerate() {
                if w.len() > MAX_STRING_LEN {
                    return Err(CodecError::Validation(format!(
                        "warning[{}] too long: {} (max {})",
                        i,
                        w.len(),
                        MAX_STRING_LEN
                    )));
                }
            }
        }
        if let Some(tier) = self.confidence_tier {
            let raw = tier as u8;
            if raw == 0 || raw > 4 {
                return Err(CodecError::Validation(format!(
                    "confidence_tier out of range: {} (must be 1..=4)",
                    raw
                )));
            }
        }
        if let Some(ref summary) = self.forensic_summary {
            if let Some(ref flags) = summary.flags {
                if flags.len() > MAX_FORENSIC_FLAGS {
                    return Err(CodecError::Validation(format!(
                        "too many forensic_flags: {} (max {})",
                        flags.len(),
                        MAX_FORENSIC_FLAGS
                    )));
                }
            }
        }
        Ok(())
    }
}
