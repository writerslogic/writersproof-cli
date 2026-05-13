// SPDX-License-Identifier: Apache-2.0

//! C2PA assertion profile — projects an EAR token into a C2PA JUMBF assertion.

use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, String>;
use crate::war::ear::{EarToken, TrustVectorProjection};

/// C2PA assertion label for WritersLogic PoP attestation.
pub const ASSERTION_LABEL: &str = "com.writerslogic.cpoe-attestation.v1";

/// C2PA assertion containing EAR-derived data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2paAssertion {
    pub label: String,
    pub data: C2paAssertionData,
}

/// Inner data payload of the C2PA assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2paAssertionData {
    pub ear_profile: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trustworthiness_vector: Option<TrustVectorProjection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal: Option<SealJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_duration_secs: Option<u64>,
    pub verifier_id: VerifierIdJson,
}

/// JSON representation of seal for C2PA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealJson {
    pub h1: String,
    pub h2: String,
    pub h3: String,
    pub signature: String,
    pub public_key: String,
}

/// JSON verifier identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierIdJson {
    pub build: String,
    pub developer: String,
}

/// C2PA action entry for `c2pa.actions.v2`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2paAction {
    pub action: String,
    #[serde(rename = "digitalSourceType")]
    pub digital_source_type: String,
    #[serde(rename = "softwareAgent")]
    pub software_agent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

/// Produce a C2PA assertion from an EAR token.
pub fn to_c2pa_assertion(ear: &EarToken) -> Result<C2paAssertion> {
    let appr = ear
        .pop_appraisal()
        .ok_or_else(|| String::from("EAR token missing 'pop' submodule"))?;

    let tv_json = appr
        .ear_trustworthiness_vector
        .as_ref()
        .map(TrustVectorProjection::from);

    let seal_json = appr.pop_seal.as_ref().map(|s| SealJson {
        h1: hex::encode(s.h1),
        h2: hex::encode(s.h2),
        h3: hex::encode(s.h3),
        signature: hex::encode(s.signature),
        public_key: hex::encode(s.public_key),
    });

    let evidence_ref = appr.pop_evidence_ref.as_ref().map(hex::encode);

    Ok(C2paAssertion {
        label: ASSERTION_LABEL.to_string(),
        data: C2paAssertionData {
            ear_profile: ear.eat_profile.clone(),
            status: appr.ear_status.as_str().to_owned(),
            trustworthiness_vector: tv_json,
            seal: seal_json,
            evidence_ref,
            chain_length: appr.pop_chain_length,
            chain_duration_secs: appr.pop_chain_duration,
            verifier_id: VerifierIdJson {
                build: ear.ear_verifier_id.build.clone(),
                developer: ear.ear_verifier_id.developer.clone(),
            },
        },
    })
}

/// Produce a C2PA action entry from an EAR token.
pub fn to_c2pa_action(ear: &EarToken) -> Result<C2paAction> {
    let appr = ear
        .pop_appraisal()
        .ok_or_else(|| String::from("EAR token missing 'pop' submodule"))?;

    let tier_str = appr
        .ear_trustworthiness_vector
        .as_ref()
        .map(|tv| {
            // Normalize through from_i8 so non-standard values (3-31)
            // are treated as Contraindicated, not Affirming.
            match crate::war::ear::Ar4siStatus::from_i8(tv.hardware) {
                crate::war::ear::Ar4siStatus::Affirming => "hardware_bound",
                crate::war::ear::Ar4siStatus::Warning => "attested_software",
                _ => "software_only",
            }
        })
        .unwrap_or("software_only");

    let params = serde_json::json!({
        "pop.attestation_tier": tier_str,
        "pop.chain_duration_secs": appr.pop_chain_duration.unwrap_or(0),
    });

    Ok(C2paAction {
        action: "c2pa.created".to_string(),
        digital_source_type: "http://cv.iptc.org/newscodes/digitalsourcetype/humanCreation"
            .to_string(),
        software_agent: ear.ear_verifier_id.build.clone(),
        parameters: Some(params),
    })
}
