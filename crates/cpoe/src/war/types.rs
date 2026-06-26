// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::evidence::Packet;
use chrono::{DateTime, Utc};
use hex;
use serde::{Deserialize, Serialize};

// Re-export identical types from protocol to avoid duplication.
pub use authorproof_protocol::war::types::{
    CheckResult, ForensicDetails, VerificationReport, Version,
};

// ASCII-armor delimiters (single source of truth for encoder, decoder, and detection)
pub const HEADER_BEGIN: &str = "-----BEGIN CPoE WAR-----";
pub const HEADER_END: &str = "-----END CPoE WAR-----";
pub const SEAL_BEGIN: &str = "-----BEGIN SEAL-----";
pub const SEAL_END: &str = "-----END SEAL-----";

// Substring markers used for detection (without the dashes, for contains() matching)
pub const MARKER_BEGIN: &str = "BEGIN CPoE WAR";
pub const MARKER_END: &str = "END CPoE WAR";

/// A WAR (Written Authorship Report) evidence block.
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

    // ── Structured metadata (new in WAR/1.1+) ──
    /// Tool declaration: "none", "reference", or "ai:ToolName:extent".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Evidence strength tier: "T1" (basic) through "T4" (maximum).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Forensic confidence score (0–100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
    /// Number of checkpoints in the evidence chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoints: Option<u64>,
    /// Total writing duration in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,

    /// RFC 3161 timestamp response token (DER-encoded TimeStampResp).
    /// Included in COSE_Sign1 unprotected headers for C2PA manifest interop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc3161_timestamp: Option<Vec<u8>>,

    // ── Internal / non-serialized fields ──
    /// Not included in ASCII output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Box<Packet>>,
    /// H3 signature is valid.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signed: bool,
    /// Freshness nonce for replay attack prevention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_nonce: Option<[u8; 32]>,
    /// EAR appraisal token (WAR/2.0+)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ear: Option<super::EarToken>,
}

/// The cryptographic seal binding all evidence together.
#[derive(Debug, Clone)]
pub struct Seal {
    /// H1: SHA-256(doc ‖ checkpoint_root ‖ declaration)
    pub h1: [u8; 32],
    /// H2: SHA-256(H1 ‖ jitter ‖ pubkey)
    pub h2: [u8; 32],
    /// H3: SHA-256(H2 ‖ vdf_output ‖ doc)
    pub h3: [u8; 32],
    /// H4: Ed25519 signature of H3
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
    /// True when this seal was reconstructed from a format (e.g. EAR) that
    /// lacked the original seal data, so all hash/signature fields are zeroed.
    pub reconstructed: bool,
}

impl Serialize for Seal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let field_count = if self.reconstructed { 6 } else { 5 };
        let mut state = serializer.serialize_struct("Seal", field_count)?;
        state.serialize_field("h1", &hex::encode(self.h1))?;
        state.serialize_field("h2", &hex::encode(self.h2))?;
        state.serialize_field("h3", &hex::encode(self.h3))?;
        state.serialize_field("signature", &hex::encode(self.signature))?;
        state.serialize_field("public_key", &hex::encode(self.public_key))?;
        if self.reconstructed {
            state.serialize_field("reconstructed", &true)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for Seal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SealHelper {
            h1: String,
            h2: String,
            h3: String,
            signature: String,
            public_key: String,
            #[serde(default)]
            reconstructed: bool,
        }

        use crate::utils::crypto_types::{Ed25519Pubkey, Ed25519Sig, HexHash};

        let helper = SealHelper::deserialize(deserializer)?;

        let h1 = HexHash::from_hex(&helper.h1).map_err(serde::de::Error::custom)?;
        let h2 = HexHash::from_hex(&helper.h2).map_err(serde::de::Error::custom)?;
        let h3 = HexHash::from_hex(&helper.h3).map_err(serde::de::Error::custom)?;
        let signature =
            Ed25519Sig::from_hex(&helper.signature).map_err(serde::de::Error::custom)?;
        let public_key =
            Ed25519Pubkey::from_hex(&helper.public_key).map_err(serde::de::Error::custom)?;

        Ok(Seal {
            h1: h1.0,
            h2: h2.0,
            h3: h3.0,
            signature: signature.0,
            public_key: public_key.0,
            reconstructed: helper.reconstructed,
        })
    }
}
