// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! C2PA assertion profile — projects an EAR token into a C2PA JUMBF assertion.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::war::common::{derive_attestation_tier, SerializedTrustVector};
use crate::war::ear::EarToken;

/// C2PA assertion label for CPoE PoP attestation.
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
    pub trustworthiness_vector: Option<SerializedTrustVector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal: Option<SealJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_duration_secs: Option<u64>,
    /// RFC 3339 timestamp when the creation process began (C2PA PR #2009 processStart).
    #[serde(rename = "processStart", skip_serializing_if = "Option::is_none")]
    pub process_start: Option<String>,
    /// RFC 3339 timestamp when the creation process ended (C2PA PR #2009 processEnd).
    #[serde(rename = "processEnd", skip_serializing_if = "Option::is_none")]
    pub process_end: Option<String>,
    /// IANA media type of the attested asset (dc:format per C2PA spec).
    #[serde(rename = "dc:format", skip_serializing_if = "Option::is_none")]
    pub dc_format: Option<String>,
    pub verifier_id: VerifierIdJson,
    #[serde(rename = "writingMode", skip_serializing_if = "Option::is_none")]
    pub writing_mode: Option<String>,
    #[serde(rename = "compositionMode", skip_serializing_if = "Option::is_none")]
    pub composition_mode: Option<String>,
    #[serde(rename = "forensicSignals", skip_serializing_if = "Option::is_none")]
    pub forensic_signals: Option<C2paForensicSignals>,
}

/// Per-dimension forensic signal scores in the C2PA assertion JSON sidecar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2paForensicSignals {
    #[serde(rename = "cognitiveLoad")]
    pub cognitive_load: f64,
    #[serde(rename = "revisionTopology")]
    pub revision_topology: f64,
    #[serde(rename = "errorEcology")]
    pub error_ecology: f64,
    #[serde(rename = "likelihoodModel")]
    pub likelihood_model: f64,
    #[serde(rename = "compositionMode")]
    pub composition_mode: f64,
    #[serde(rename = "detourRatio")]
    pub detour_ratio: f64,
    #[serde(rename = "leadingEdgeDivergence")]
    pub leading_edge_divergence: f64,
    #[serde(rename = "insertionPointEntropy")]
    pub insertion_point_entropy: f64,
}

impl C2paAssertion {
    /// Enrich the assertion with forensic signal scores computed from events.
    pub fn enrich_forensic_signals(
        &mut self,
        writing_mode: Option<String>,
        composition_mode: Option<String>,
        signals: Option<C2paForensicSignals>,
    ) {
        self.data.writing_mode = writing_mode;
        self.data.composition_mode = composition_mode;
        self.data.forensic_signals = signals;
    }
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
        .ok_or_else(|| Error::evidence("EAR token missing 'pop' submodule"))?;

    let tv_json = appr
        .ear_trustworthiness_vector
        .as_ref()
        .map(SerializedTrustVector::from);

    let seal_json = appr.pop_seal.as_ref().map(|s| {
        use crate::utils::crypto_types::{Ed25519Pubkey, Ed25519Sig, HexHash};
        SealJson {
            h1: HexHash::from_bytes(s.h1).to_hex(),
            h2: HexHash::from_bytes(s.h2).to_hex(),
            h3: HexHash::from_bytes(s.h3).to_hex(),
            signature: Ed25519Sig::from_bytes(s.signature).to_hex(),
            public_key: Ed25519Pubkey::from_bytes(s.public_key).to_hex(),
        }
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
            process_start: appr.pop_process_start.clone(),
            process_end: appr.pop_process_end.clone(),
            dc_format: None, // Set by caller based on asset file extension
            writing_mode: None,
            composition_mode: None,
            forensic_signals: None,
            verifier_id: VerifierIdJson {
                build: ear.ear_verifier_id.build.clone(),
                developer: ear.ear_verifier_id.developer.clone(),
            },
        },
    })
}

/// Produce a C2PA action entry from an EAR token.
///
/// `ai_disclosure` determines the IPTC digitalSourceType:
/// - `None` or absent: humanCreation
/// - `AiAssisted`: compositeWithTrainedAlgorithmicMedia
/// - `AiGenerated`: trainedAlgorithmicMedia
pub fn to_c2pa_action(
    ear: &EarToken,
    ai_disclosure: Option<&super::standards::AiDisclosureLevel>,
) -> Result<C2paAction> {
    let appr = ear
        .pop_appraisal()
        .ok_or_else(|| Error::evidence("EAR token missing 'pop' submodule"))?;

    let tier_str = appr
        .ear_trustworthiness_vector
        .as_ref()
        .map(|tv| derive_attestation_tier(tv))
        .unwrap_or("software_only");

    let digital_source_type = ai_disclosure
        .map(|level| level.to_iptc_digital_source_type())
        .unwrap_or(super::standards::IPTC_HUMAN_CREATION);

    let params = serde_json::json!({
        "pop.attestation_tier": tier_str,
        "pop.chain_duration_secs": appr.pop_chain_duration,
    });

    Ok(C2paAction {
        action: "c2pa.created".to_string(),
        digital_source_type: digital_source_type.to_string(),
        software_agent: ear.ear_verifier_id.build.clone(),
        parameters: Some(params),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::war::profiles::standards::AiDisclosureLevel;
    use crate::war::profiles::test_helpers::make_ear;

    #[test]
    fn test_c2pa_action_with_ai_disclosure() {
        let ear = make_ear(10, 7200);

        // No AI disclosure: humanCreation.
        let action_none = to_c2pa_action(&ear, None).expect("action");
        assert_eq!(
            action_none.digital_source_type,
            "http://cv.iptc.org/newscodes/digitalsourcetype/humanCreation"
        );
        assert_eq!(action_none.action, "c2pa.created");

        // AI-assisted disclosure: compositeWithTrainedAlgorithmicMedia.
        let assisted = AiDisclosureLevel::AiAssisted;
        let action_assist = to_c2pa_action(&ear, Some(&assisted)).expect("action");
        assert_eq!(
            action_assist.digital_source_type,
            "http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia"
        );

        // AI-generated disclosure: trainedAlgorithmicMedia.
        let generated = AiDisclosureLevel::AiGenerated;
        let action_gen = to_c2pa_action(&ear, Some(&generated)).expect("action");
        assert_eq!(
            action_gen.digital_source_type,
            "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
        );
    }

    #[test]
    fn test_c2pa_assertion_structure() {
        let ear = make_ear(10, 7200);
        let assertion = to_c2pa_assertion(&ear).expect("assertion");
        assert_eq!(assertion.label, ASSERTION_LABEL);
        assert_eq!(assertion.data.status, "affirming");
        assert_eq!(assertion.data.chain_length, Some(10));
        assert_eq!(assertion.data.chain_duration_secs, Some(7200));
    }
}
