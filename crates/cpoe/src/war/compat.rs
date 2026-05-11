// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Multi-version detection and legacy format conversion.
//!
//! Handles WAR V1.0, V1.1, V2.0 ASCII-armored blocks and
//! raw EAR CBOR tokens. Provides bidirectional conversion
//! between [`AttestationResultWire`] and [`EarToken`].

use std::collections::BTreeMap;

use chrono::Utc;

use crate::error::{Error, Result};
use crate::war::ear::{
    Ar4siStatus, EarAppraisal, EarToken, TrustworthinessVector, VerifierId, POP_EAR_PROFILE,
};
use crate::war::types::{Block, Version};
use authorproof_protocol::codec;
use authorproof_protocol::rfc::wire_types::attestation::AttestationResultWire;
use authorproof_protocol::rfc::wire_types::enums::{AttestationTier, Verdict};
use authorproof_protocol::rfc::wire_types::hash::HashValue;

/// Detected WAR format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedFormat {
    /// V1.0 ASCII-armored
    AsciiV1_0,
    /// V1.1 ASCII-armored
    AsciiV1_1,
    /// V2.0 ASCII-armored (with EAR)
    AsciiV2_0,
    /// Raw EAR CBOR token (tagged)
    EarCbor,
}

/// Detect the format version from raw data.
pub fn detect_version(data: &[u8]) -> Result<DetectedFormat> {
    if let Ok(text) = std::str::from_utf8(data) {
        if text.contains(crate::war::types::MARKER_BEGIN) {
            if text.contains("Version: WAR/2.0") {
                return Ok(DetectedFormat::AsciiV2_0);
            } else if text.contains("Version: WAR/1.1") {
                return Ok(DetectedFormat::AsciiV1_1);
            } else {
                return Ok(DetectedFormat::AsciiV1_0);
            }
        }
    }

    if codec::cbor::has_tag(data, codec::CBOR_TAG_CWAR) {
        return Ok(DetectedFormat::EarCbor);
    }

    Err(Error::validation("unrecognized WAR format"))
}

/// Decode any supported WAR format into a Block.
pub fn decode_any(data: &[u8]) -> Result<Block> {
    let format = detect_version(data)?;
    match format {
        DetectedFormat::AsciiV1_0 | DetectedFormat::AsciiV1_1 | DetectedFormat::AsciiV2_0 => {
            let text = std::str::from_utf8(data)
                .map_err(|e| Error::validation(format!("invalid UTF-8: {e}")))?;
            Block::decode_ascii(text)
                .map_err(|e| Error::validation(format!("ASCII decode failed: {e}")))
        }
        DetectedFormat::EarCbor => {
            let ear: EarToken = codec::cbor::decode_cwar(data)
                .map_err(|e| Error::validation(format!("EAR CBOR decode failed: {e}")))?;
            Ok(Block::from_ear(ear))
        }
    }
}

impl Block {
    /// Construct a Block from a decoded EAR token (no evidence attached).
    pub fn from_ear(ear: EarToken) -> Self {
        let seal = ear
            .pop_appraisal()
            .and_then(|a| a.pop_seal.as_ref())
            .map(|s| crate::war::types::Seal {
                h1: s.h1,
                h2: s.h2,
                h3: s.h3,
                signature: s.signature,
                public_key: s.public_key,
                reconstructed: false,
            })
            .unwrap_or_else(|| {
                log::debug!("from_ear: EAR token has no pop_seal; using zero-initialized fallback");
                crate::war::types::Seal {
                    h1: [0u8; 32],
                    h2: [0u8; 32],
                    h3: [0u8; 32],
                    signature: [0u8; 64],
                    public_key: [0u8; 32],
                    reconstructed: true,
                }
            });

        // signed == false distinguishes "seal absent" from "seal present".
        let signed = seal.signature != [0u8; 64];

        let author = if seal.public_key != [0u8; 32] {
            let fingerprint = &crate::utils::crypto_types::Ed25519Pubkey::from_bytes(seal.public_key).to_hex()[..16];
            format!("key:{fingerprint}")
        } else {
            "unknown".to_string()
        };

        let timestamp = chrono::DateTime::from_timestamp(ear.iat, 0).unwrap_or_else(Utc::now);

        Self {
            version: Version::V2_0,
            author,
            document_id: ear
                .pop_appraisal()
                .and_then(|a| a.pop_evidence_ref.as_ref())
                .and_then(|r| {
                    if r.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(r);
                        Some(arr)
                    } else {
                        None
                    }
                })
                .unwrap_or([0u8; 32]),
            timestamp,
            statement: String::new(),
            seal,
            tool: None,
            tier: None,
            score: None,
            checkpoints: None,
            duration_secs: None,
            rfc3161_timestamp: None,
            evidence: None,
            signed,
            verifier_nonce: None,
            ear: Some(ear),
        }
    }
}

/// Extension trait for converting between AttestationResultWire and EarToken.
pub trait AttestationResultWireExt {
    /// Convert this legacy attestation result to an EAR token.
    fn to_ear(&self) -> EarToken;
}

impl AttestationResultWireExt for AttestationResultWire {
    fn to_ear(&self) -> EarToken {
        let status = match self.verdict {
            Verdict::Authentic => Ar4siStatus::Affirming,
            Verdict::Inconclusive => Ar4siStatus::Warning,
            Verdict::Suspicious | Verdict::Invalid => Ar4siStatus::Contraindicated,
        };

        let hw_component = match self.assessed_tier {
            AttestationTier::HardwareHardened | AttestationTier::HardwareBound => {
                Ar4siStatus::Affirming as i8
            }
            AttestationTier::AttestedSoftware => Ar4siStatus::Warning as i8,
            AttestationTier::SoftwareOnly => Ar4siStatus::None as i8,
        };

        let tv = TrustworthinessVector {
            instance_identity: hw_component,
            configuration: Ar4siStatus::Affirming as i8,
            executables: Ar4siStatus::None as i8,
            file_system: Ar4siStatus::Affirming as i8,
            hardware: hw_component,
            runtime_opaque: Ar4siStatus::Affirming as i8,
            storage_opaque: Ar4siStatus::None as i8,
            sourced_data: if self.entropy_report.is_some() {
                Ar4siStatus::Affirming as i8
            } else {
                Ar4siStatus::None as i8
            },
        };

        let evidence_ref = {
            let digest = &self.evidence_ref.digest;
            if digest.len() == 32 {
                Some(digest.clone())
            } else {
                None
            }
        };

        let appraisal = EarAppraisal {
            ear_status: status,
            ear_trustworthiness_vector: Some(tv),
            ear_appraisal_policy_id: None,
            pop_seal: None,
            pop_evidence_ref: evidence_ref,
            pop_entropy_report: self.entropy_report.clone(),
            pop_forgery_cost: self.forgery_cost.clone(),
            pop_forensic_summary: self.forensic_summary.clone(),
            pop_chain_length: Some(self.chain_length),
            pop_chain_duration: Some(self.chain_duration),
            pop_process_start: None,
            pop_process_end: None,
            pop_absence_claims: self.absence_claims.clone(),
            pop_warnings: self.warnings.clone(),
        };

        let mut submods = BTreeMap::new();
        submods.insert("pop".to_string(), appraisal);

        EarToken {
            eat_profile: POP_EAR_PROFILE.to_string(),
            iat: i64::try_from(self.created / 1000).unwrap_or_else(|_| {
                log::warn!(
                    "EAR iat overflow: created={}, using current time",
                    self.created
                );
                Utc::now().timestamp()
            }),
            ear_verifier_id: VerifierId::default(),
            submods,
        }
    }
}

impl EarToken {
    /// Convert this EAR token back to a legacy `AttestationResultWire`.
    pub fn to_attestation_result_wire(&self) -> AttestationResultWire {
        let appr = self.pop_appraisal();

        let verdict = match self.overall_status() {
            Ar4siStatus::Affirming => Verdict::Authentic,
            Ar4siStatus::Warning => Verdict::Inconclusive,
            Ar4siStatus::Contraindicated => Verdict::Invalid,
            Ar4siStatus::None => Verdict::Inconclusive,
        };

        let assessed_tier = appr
            .and_then(|a| a.ear_trustworthiness_vector.as_ref())
            .map(|tv| match tv.hardware {
                x if x >= Ar4siStatus::Affirming as i8 => AttestationTier::HardwareBound,
                x if x >= Ar4siStatus::Warning as i8 => AttestationTier::AttestedSoftware,
                _ => AttestationTier::SoftwareOnly,
            })
            .unwrap_or(AttestationTier::SoftwareOnly);

        let evidence_ref = appr
            .and_then(|a| a.pop_evidence_ref.as_ref())
            .map(|r| HashValue {
                algorithm: authorproof_protocol::rfc::wire_types::enums::HashAlgorithm::Sha256,
                digest: r.clone(),
            })
            .unwrap_or(HashValue {
                algorithm: authorproof_protocol::rfc::wire_types::enums::HashAlgorithm::Sha256,
                digest: vec![0u8; 32],
            });

        AttestationResultWire {
            version: 1,
            evidence_ref,
            verdict,
            assessed_tier,
            chain_length: appr.and_then(|a| a.pop_chain_length).unwrap_or(0),
            chain_duration: appr.and_then(|a| a.pop_chain_duration).unwrap_or(0),
            entropy_report: appr.and_then(|a| a.pop_entropy_report.clone()),
            forgery_cost: appr.and_then(|a| a.pop_forgery_cost.clone()),
            absence_claims: appr.and_then(|a| a.pop_absence_claims.clone()),
            warnings: appr.and_then(|a| a.pop_warnings.clone()),
            verifier_signature: Vec::new(),
            created: u64::try_from(self.iat.max(0))
                .unwrap_or(0)
                .saturating_mul(1000),
            forensic_summary: appr.and_then(|a| a.pop_forensic_summary.clone()),
            effort_attribution: None,
            confidence_tier: None,
        }
    }
}
