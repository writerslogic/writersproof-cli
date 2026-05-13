// SPDX-License-Identifier: Apache-2.0

// NOTE: cpoe_engine extends Block with evidence: Option<Box<Packet>>
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// WAR block format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Version {
    /// Legacy parallel computation (WAR/1.0)
    V1_0,
    /// Entangled computation with jitter binding (WAR/1.1)
    V1_1,
    /// EAR appraisal with attestation results (WAR/2.0)
    V2_0,
}

impl Version {
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::V1_0 => "WAR/1.0",
            Version::V1_1 => "WAR/1.1",
            Version::V2_0 => "WAR/2.0",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "WAR/1.0" => Some(Version::V1_0),
            "WAR/1.1" => Some(Version::V1_1),
            "WAR/2.0" => Some(Version::V2_0),
            _ => None,
        }
    }
}

/// A WAR evidence block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub version: Version,
    /// From declaration or public key fingerprint.
    pub author: String,
    /// SHA-256 of final content.
    pub document_id: [u8; 32],
    pub timestamp: DateTime<Utc>,
    pub statement: String,
    pub seal: Seal,
    /// H3 signature is valid.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signed: bool,
    /// Freshness nonce for replay attack prevention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_nonce: Option<[u8; 32]>,
    /// EAR appraisal token (WAR/2.0+)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ear: Option<super::ear::EarToken>,
}

impl Block {
    /// Validate version/EAR field consistency.
    ///
    /// WAR/1.0 and WAR/1.1 blocks must not carry EAR fields.
    /// WAR/2.0 blocks must carry an EAR token.
    /// Returns `Err` with a description of the violation.
    pub fn validate(&self) -> Result<(), String> {
        match self.version {
            Version::V1_0 | Version::V1_1 => {
                if self.ear.is_some() {
                    return Err(format!(
                        "{} block must not contain an EAR token",
                        self.version.as_str()
                    ));
                }
            }
            Version::V2_0 => {
                if self.ear.is_none() {
                    return Err("WAR/2.0 block is missing required EAR token".to_string());
                }
            }
        }
        Ok(())
    }
}

/// The cryptographic seal binding all evidence together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Seal {
    /// H1: SHA-256(doc || checkpoint_root || declaration)
    #[serde(with = "crate::rfc::serde_helpers::hex_bytes")]
    pub h1: [u8; 32],
    /// H2: SHA-256(H1 || jitter || pubkey)
    #[serde(with = "crate::rfc::serde_helpers::hex_bytes")]
    pub h2: [u8; 32],
    /// H3: SHA-256(H2 || vdf_output || doc)
    #[serde(with = "crate::rfc::serde_helpers::hex_bytes")]
    pub h3: [u8; 32],
    /// H4: Ed25519 signature of H3
    #[serde(with = "crate::rfc::serde_helpers::hex_bytes")]
    pub signature: [u8; 64],
    #[serde(with = "crate::rfc::serde_helpers::hex_bytes")]
    pub public_key: [u8; 32],
}

/// Result of WAR block verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub valid: bool,
    pub checks: Vec<CheckResult>,
    pub summary: String,
    pub details: ForensicDetails,
}

/// Individual verification check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// e.g. "seal_signature", "hash_chain"
    pub name: String,
    pub passed: bool,
    pub message: String,
}

/// Detailed forensic information from verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicDetails {
    pub version: String,
    pub author: String,
    pub document_id: String,
    pub timestamp: DateTime<Utc>,
    pub components: Vec<String>,
    /// Total elapsed time from VDF proofs.
    pub elapsed_time_secs: Option<f64>,
    pub checkpoint_count: Option<usize>,
    pub keystroke_count: Option<u64>,
    pub has_jitter_seal: bool,
    pub has_hardware_attestation: bool,
    pub has_verifier_nonce: bool,
    /// Hex-encoded, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_nonce: Option<String>,
}
