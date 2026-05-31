// SPDX-License-Identifier: Apache-2.0

//! EAR (Entity Attestation Result) types per draft-ietf-rats-ear.
//!
//! Maps WritersLogic's proof-of-process appraisal onto standard RATS EAR
//! structures with AR4SI trust vectors. Private-use keys 70001-70009
//! carry WritersLogic-specific claims.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::rfc::wire_types::attestation::{
    AbsenceClaim, EntropyReport, ForensicSummary, ForgeryCostEstimate,
};

/// EAT profile URI for CPoE Attestation Results per draft-condrey-cpoe-protocol.
pub const CPOE_EAR_PROFILE: &str = "urn:ietf:params:rats:eat:profile:cpoe:1.0";

/// Evidence packet profile URI per draft-condrey-cpoe-protocol.
pub const CPOE_EVIDENCE_PROFILE: &str = "urn:ietf:params:cpoe:profile:1.0";

/// Legacy EAT profile URI (draft-condrey-rats-pop). Kept for backward compatibility
/// when verifying old evidence packets.
pub const POP_EAR_PROFILE: &str = "urn:ietf:params:rats:eat:profile:pop:1.0";

pub const CWT_KEY_IAT: i64 = 6;
pub const CWT_KEY_EAT_PROFILE: i64 = 265;
pub const CWT_KEY_SUBMODS: i64 = 266;
pub const EAR_KEY_STATUS: i64 = 1000;
pub const EAR_KEY_TRUST_VECTOR: i64 = 1001;
pub const EAR_KEY_POLICY_ID: i64 = 1003;
pub const EAR_KEY_VERIFIER_ID: i64 = 1004;

pub const POP_KEY_SEAL: i64 = 70001;
pub const POP_KEY_EVIDENCE_REF: i64 = 70002;
pub const POP_KEY_ENTROPY: i64 = 70003;
pub const POP_KEY_FORGERY_COST: i64 = 70004;
pub const POP_KEY_FORENSIC: i64 = 70005;
pub const POP_KEY_CHAIN_LENGTH: i64 = 70006;
pub const POP_KEY_CHAIN_DURATION: i64 = 70007;
pub const POP_KEY_ABSENCE: i64 = 70008;
pub const POP_KEY_WARNINGS: i64 = 70009;
pub const POP_KEY_PROCESS_START: i64 = 70010;
pub const POP_KEY_PROCESS_END: i64 = 70011;

/// AR4SI appraisal status per draft-ietf-rats-ar4si.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i8)]
pub enum Ar4siStatus {
    /// No status determined
    None = 0,
    /// Evidence affirms trustworthiness
    Affirming = 2,
    /// Evidence contains warnings
    Warning = 32,
    /// Evidence contradicts trustworthiness
    Contraindicated = 96,
}

impl Ar4siStatus {
    /// Convert a raw i8 value to the corresponding status variant.
    /// Unknown values map to `Contraindicated` (fail-closed) to prevent
    /// unrecognized status codes from silently passing attestation.
    pub fn from_i8(v: i8) -> Self {
        match v {
            0 => Self::None,
            2 => Self::Affirming,
            32 => Self::Warning,
            96 => Self::Contraindicated,
            _ => Self::Contraindicated,
        }
    }

    /// Return the lowercase string name of this status.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Affirming => "affirming",
            Self::Warning => "warning",
            Self::Contraindicated => "contraindicated",
        }
    }
}

/// AR4SI trustworthiness vector — maps from WritersLogic evidence components.
///
/// Each component is a tier value from -128 to 127:
/// - 2 = affirming, 32 = warning, 96 = contraindicated, 0 = none
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustworthinessVector {
    /// Hardware attestation tier (TPM/Secure Enclave)
    #[serde(rename = "0")]
    pub instance_identity: i8,
    /// Software configuration integrity
    #[serde(rename = "1")]
    pub configuration: i8,
    /// Binary attestation (TPM quote)
    #[serde(rename = "2")]
    pub executables: i8,
    /// Document hash chain integrity (H1/H2/H3)
    #[serde(rename = "3")]
    pub file_system: i8,
    /// TPM/Secure Enclave tier
    #[serde(rename = "4")]
    pub hardware: i8,
    /// VDF proof strength
    #[serde(rename = "5")]
    pub runtime_opaque: i8,
    /// Key hierarchy integrity
    #[serde(rename = "6")]
    pub storage_opaque: i8,
    /// Behavioral entropy + jitter
    #[serde(rename = "7")]
    pub sourced_data: i8,
}

impl TrustworthinessVector {
    /// Returns the maximum component value (most concerning).
    ///
    /// AR4SI status values increase with severity: None(0) < Affirming(2) <
    /// Warning(32) < Contraindicated(96). The worst-case (highest value)
    /// determines the overall trust posture.
    pub fn max_component(&self) -> i8 {
        [
            self.instance_identity,
            self.configuration,
            self.executables,
            self.file_system,
            self.hardware,
            self.runtime_opaque,
            self.storage_opaque,
            self.sourced_data,
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
    }

    /// Derive overall AR4SI status from the most concerning component.
    ///
    /// Each component is mapped through `Ar4siStatus::from_i8` first, so
    /// non-standard values are treated as Contraindicated (fail-closed).
    /// The worst (highest severity) mapped status wins.
    pub fn overall_status(&self) -> Ar4siStatus {
        [
            self.instance_identity,
            self.configuration,
            self.executables,
            self.file_system,
            self.hardware,
            self.runtime_opaque,
            self.storage_opaque,
            self.sourced_data,
        ]
        .into_iter()
        .map(Ar4siStatus::from_i8)
        .max_by_key(|s| *s as i8)
        .unwrap_or(Ar4siStatus::None)
    }

    /// Format as compact header string: "II=2 CO=2 EX=0 FS=2 HW=2 RO=2 SO=2 SD=2"
    pub fn header_string(&self) -> String {
        format!(
            "II={} CO={} EX={} FS={} HW={} RO={} SO={} SD={}",
            self.instance_identity,
            self.configuration,
            self.executables,
            self.file_system,
            self.hardware,
            self.runtime_opaque,
            self.storage_opaque,
            self.sourced_data,
        )
    }

    /// Parse from header string format. Rejects non-standard AR4SI values.
    pub fn parse_header(s: &str) -> Option<Self> {
        const VALID_AR4SI: &[i8] = &[0, 2, 32, 96];
        let mut vals = [0i8; 8];
        let labels = ["II=", "CO=", "EX=", "FS=", "HW=", "RO=", "SO=", "SD="];
        for (i, label) in labels.iter().enumerate() {
            let part = s.split_whitespace().find(|p| p.starts_with(label))?;
            let v: i8 = part.strip_prefix(label)?.parse().ok()?;
            if !VALID_AR4SI.contains(&v) {
                return None;
            }
            vals[i] = v;
        }
        Some(Self {
            instance_identity: vals[0],
            configuration: vals[1],
            executables: vals[2],
            file_system: vals[3],
            hardware: vals[4],
            runtime_opaque: vals[5],
            storage_opaque: vals[6],
            sourced_data: vals[7],
        })
    }
}

/// JSON-serializable projection of the trust vector for profile output (VC, C2PA).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustVectorProjection {
    pub instance_identity: i8,
    pub configuration: i8,
    pub executables: i8,
    pub file_system: i8,
    pub hardware: i8,
    pub runtime_opaque: i8,
    pub storage_opaque: i8,
    pub sourced_data: i8,
}

impl From<&TrustworthinessVector> for TrustVectorProjection {
    fn from(tv: &TrustworthinessVector) -> Self {
        Self {
            instance_identity: tv.instance_identity,
            configuration: tv.configuration,
            executables: tv.executables,
            file_system: tv.file_system,
            hardware: tv.hardware,
            runtime_opaque: tv.runtime_opaque,
            storage_opaque: tv.storage_opaque,
            sourced_data: tv.sourced_data,
        }
    }
}

/// Verifier identity per EAR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierId {
    /// Build identifier string (e.g. "cpoe-engine/0.3.6")
    pub build: String,
    /// Developer/organization name
    pub developer: String,
}

impl Default for VerifierId {
    fn default() -> Self {
        Self {
            build: format!("cpoe-engine/{}", env!("CARGO_PKG_VERSION")),
            developer: "writerslogic".to_string(),
        }
    }
}

/// Seal claims extracted from a WAR block for embedding in EAR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealClaims {
    /// H1: document/checkpoint/declaration binding hash
    #[serde(with = "crate::rfc::serde_helpers::hex_bytes")]
    pub h1: [u8; 32],
    /// H2: jitter/identity binding hash
    #[serde(with = "crate::rfc::serde_helpers::hex_bytes")]
    pub h2: [u8; 32],
    /// H3: VDF/document binding hash (signed)
    #[serde(with = "crate::rfc::serde_helpers::hex_bytes")]
    pub h3: [u8; 32],
    /// Ed25519 signature over H3
    #[serde(with = "crate::rfc::serde_helpers::hex_bytes")]
    pub signature: [u8; 64],
    /// Author's Ed25519 public key
    #[serde(with = "crate::rfc::serde_helpers::hex_bytes")]
    pub public_key: [u8; 32],
}

/// Single submodule appraisal within an EAR token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarAppraisal {
    /// AR4SI status
    #[serde(rename = "1000")]
    pub ear_status: Ar4siStatus,

    /// Trustworthiness vector
    #[serde(rename = "1001", default, skip_serializing_if = "Option::is_none")]
    pub ear_trustworthiness_vector: Option<TrustworthinessVector>,

    /// Appraisal policy ID
    #[serde(rename = "1003", default, skip_serializing_if = "Option::is_none")]
    pub ear_appraisal_policy_id: Option<String>,

    /// WAR seal claims
    #[serde(rename = "70001", default, skip_serializing_if = "Option::is_none")]
    pub pop_seal: Option<SealClaims>,

    /// SHA-256 of evidence packet
    #[serde(rename = "70002", default, skip_serializing_if = "Option::is_none")]
    pub pop_evidence_ref: Option<Vec<u8>>,

    /// Entropy assessment report
    #[serde(rename = "70003", default, skip_serializing_if = "Option::is_none")]
    pub pop_entropy_report: Option<EntropyReport>,

    /// Forgery cost estimate
    #[serde(rename = "70004", default, skip_serializing_if = "Option::is_none")]
    pub pop_forgery_cost: Option<ForgeryCostEstimate>,

    /// Forensic assessment summary
    #[serde(rename = "70005", default, skip_serializing_if = "Option::is_none")]
    pub pop_forensic_summary: Option<ForensicSummary>,

    /// Checkpoint chain length
    #[serde(rename = "70006", default, skip_serializing_if = "Option::is_none")]
    pub pop_chain_length: Option<u64>,

    /// Chain duration (seconds)
    #[serde(rename = "70007", default, skip_serializing_if = "Option::is_none")]
    pub pop_chain_duration: Option<u64>,

    /// Absence claims
    #[serde(rename = "70008", default, skip_serializing_if = "Option::is_none")]
    pub pop_absence_claims: Option<Vec<AbsenceClaim>>,

    /// Warning messages
    #[serde(rename = "70009", default, skip_serializing_if = "Option::is_none")]
    pub pop_warnings: Option<Vec<String>>,

    /// Process start timestamp (ISO 8601)
    #[serde(rename = "70010", default, skip_serializing_if = "Option::is_none")]
    pub pop_process_start: Option<String>,

    /// Process end timestamp (ISO 8601)
    #[serde(rename = "70011", default, skip_serializing_if = "Option::is_none")]
    pub pop_process_end: Option<String>,
}

/// EAR token per draft-ietf-rats-ear, carrying one or more appraisals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarToken {
    /// EAT profile URI (CWT key 265)
    #[serde(rename = "265")]
    pub eat_profile: String,

    /// Issued-at timestamp, epoch seconds (CWT key 6)
    #[serde(rename = "6")]
    pub iat: i64,

    /// Verifier identity (key 1004)
    #[serde(rename = "1004")]
    pub ear_verifier_id: VerifierId,

    /// Submodule appraisals keyed by name (key 266)
    #[serde(rename = "266")]
    pub submods: BTreeMap<String, EarAppraisal>,
}

impl EarToken {
    /// Verify that the token was issued within the given maximum age.
    pub fn verify_freshness(&self, max_age: std::time::Duration) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let age_secs = now.saturating_sub(self.iat);
        age_secs >= 0 && age_secs <= max_age.as_secs() as i64
    }

    /// Overall status: the worst (highest severity) status across all submodule appraisals.
    ///
    /// AR4SI status values increase with severity, so the maximum value
    /// represents the most concerning appraisal result (fail-closed).
    pub fn overall_status(&self) -> Ar4siStatus {
        self.submods
            .values()
            .map(|a| a.ear_status as i8)
            .max()
            .map(Ar4siStatus::from_i8)
            .unwrap_or(Ar4siStatus::None)
    }

    // TODO: draft-condrey-cpoe-appraisal specifies the submods key should be the
    // evidence-ref hash, not the fixed string "pop". Update all callers and
    // constructors (submods.insert("pop", ...)) to use the packet hash as key.
    pub fn pop_appraisal(&self) -> Option<&EarAppraisal> {
        self.submods.get("pop")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ar4si_from_i8_known_values() {
        assert_eq!(Ar4siStatus::from_i8(0), Ar4siStatus::None);
        assert_eq!(Ar4siStatus::from_i8(2), Ar4siStatus::Affirming);
        assert_eq!(Ar4siStatus::from_i8(32), Ar4siStatus::Warning);
        assert_eq!(Ar4siStatus::from_i8(96), Ar4siStatus::Contraindicated);
    }

    #[test]
    fn test_ar4si_from_i8_unknown_values_fail_closed() {
        assert_eq!(Ar4siStatus::from_i8(1), Ar4siStatus::Contraindicated);
        assert_eq!(Ar4siStatus::from_i8(-1), Ar4siStatus::Contraindicated);
        assert_eq!(Ar4siStatus::from_i8(127), Ar4siStatus::Contraindicated);
        assert_eq!(Ar4siStatus::from_i8(50), Ar4siStatus::Contraindicated);
    }

    #[test]
    fn test_overall_status_worst_wins() {
        let mut tv = TrustworthinessVector::default();
        assert_eq!(tv.overall_status(), Ar4siStatus::None);

        tv.hardware = Ar4siStatus::Affirming as i8;
        assert_eq!(tv.overall_status(), Ar4siStatus::Affirming);

        tv.sourced_data = Ar4siStatus::Warning as i8;
        assert_eq!(tv.overall_status(), Ar4siStatus::Warning);

        tv.file_system = Ar4siStatus::Contraindicated as i8;
        assert_eq!(tv.overall_status(), Ar4siStatus::Contraindicated);
    }

    #[test]
    fn test_contraindicated_not_masked_by_none() {
        let mut tv = TrustworthinessVector::default();
        tv.hardware = Ar4siStatus::Contraindicated as i8;
        // All other components are None(0); overall must still be Contraindicated
        assert_eq!(tv.overall_status(), Ar4siStatus::Contraindicated);
    }

    #[test]
    fn test_nonstandard_component_values_treated_as_contraindicated() {
        let mut tv = TrustworthinessVector::default();
        // Value 10 is not a valid AR4SI status; should be treated as Contraindicated
        tv.hardware = 10;
        assert_eq!(tv.overall_status(), Ar4siStatus::Contraindicated);

        // Negative values also map to Contraindicated
        tv = TrustworthinessVector::default();
        tv.sourced_data = -5;
        assert_eq!(tv.overall_status(), Ar4siStatus::Contraindicated);
    }

    #[test]
    fn test_ear_token_overall_status_worst_submod() {
        let mut submods = BTreeMap::new();
        submods.insert(
            "pop".to_string(),
            EarAppraisal {
                ear_status: Ar4siStatus::Affirming,
                ear_trustworthiness_vector: None,
                ear_appraisal_policy_id: None,
                pop_seal: None,
                pop_evidence_ref: None,
                pop_entropy_report: None,
                pop_forgery_cost: None,
                pop_forensic_summary: None,
                pop_chain_length: None,
                pop_chain_duration: None,
                pop_absence_claims: None,
                pop_warnings: None,
                pop_process_start: None,
                pop_process_end: None,
            },
        );
        submods.insert(
            "other".to_string(),
            EarAppraisal {
                ear_status: Ar4siStatus::Warning,
                ear_trustworthiness_vector: None,
                ear_appraisal_policy_id: None,
                pop_seal: None,
                pop_evidence_ref: None,
                pop_entropy_report: None,
                pop_forgery_cost: None,
                pop_forensic_summary: None,
                pop_chain_length: None,
                pop_chain_duration: None,
                pop_absence_claims: None,
                pop_warnings: None,
                pop_process_start: None,
                pop_process_end: None,
            },
        );

        let token = EarToken {
            eat_profile: CPOE_EAR_PROFILE.to_string(),
            iat: 0,
            ear_verifier_id: VerifierId::default(),
            submods,
        };

        assert_eq!(token.overall_status(), Ar4siStatus::Warning);
    }

    #[test]
    fn test_max_component() {
        let tv = TrustworthinessVector {
            instance_identity: 0,
            configuration: 2,
            executables: 0,
            file_system: 96,
            hardware: 32,
            runtime_opaque: 0,
            storage_opaque: 2,
            sourced_data: 0,
        };
        assert_eq!(tv.max_component(), 96);
    }

    #[test]
    fn test_header_roundtrip() {
        let tv = TrustworthinessVector {
            instance_identity: 2,
            configuration: 2,
            executables: 0,
            file_system: 2,
            hardware: 32,
            runtime_opaque: 2,
            storage_opaque: 2,
            sourced_data: 96,
        };
        let header = tv.header_string();
        let parsed = TrustworthinessVector::parse_header(&header).unwrap();
        assert_eq!(tv, parsed);
    }
}
