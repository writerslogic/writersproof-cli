// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use serde::Serialize;

/// DIF Presentation Exchange 2.0 Presentation Definition.
///
/// Allows verifiers to request specific CPoE attestation claims from a holder.
#[derive(Debug, Clone, Serialize)]
pub struct PresentationDefinition {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub input_descriptors: Vec<InputDescriptor>,
}

/// Describes a single input the verifier requires.
#[derive(Debug, Clone, Serialize)]
pub struct InputDescriptor {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub constraints: Constraints,
}

/// Constraints on the fields a verifier requires.
#[derive(Debug, Clone, Serialize)]
pub struct Constraints {
    pub fields: Vec<Field>,
}

/// A single field constraint within an input descriptor.
#[derive(Debug, Clone, Serialize)]
pub struct Field {
    pub path: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

const TIER_ORDER: &[&str] = &["bronze", "silver", "gold", "platinum"];

fn tiers_at_or_above(min_tier: &str) -> Vec<&'static str> {
    let start = TIER_ORDER
        .iter()
        .position(|&t| t == min_tier)
        .unwrap_or_else(|| {
            log::warn!("unknown forensic tier '{min_tier}', defaulting to bronze");
            0
        });
    TIER_ORDER[start..].to_vec()
}

/// Build a presentation definition requesting a CPoE attestation.
///
/// The definition requires:
/// - A checkpoint chain duration of at least `min_chain_duration_secs` seconds.
/// - A forensic tier at or above `min_tier` (e.g. "gold", "silver", "bronze").
pub fn cpoe_attestation_request(
    min_chain_duration_secs: u64,
    min_tier: &str,
) -> PresentationDefinition {
    PresentationDefinition {
        id: "cpoe-attestation-request".to_string(),
        name: Some("CPoE Authorship Attestation".to_string()),
        purpose: Some("Verify human authorship via cryptographic proof-of-process".to_string()),
        input_descriptors: vec![
            InputDescriptor {
                id: "chain_duration".to_string(),
                name: Some("Checkpoint Chain Duration".to_string()),
                purpose: Some(format!(
                    "Chain must span at least {} seconds",
                    min_chain_duration_secs
                )),
                constraints: Constraints {
                    fields: vec![Field {
                        path: vec!["$.chain_duration_secs".to_string()],
                        filter: Some(serde_json::json!({
                            "type": "number",
                            "minimum": min_chain_duration_secs
                        })),
                        purpose: None,
                    }],
                },
            },
            InputDescriptor {
                id: "forensic_tier".to_string(),
                name: Some("Forensic Assessment Tier".to_string()),
                purpose: Some(format!("Tier must be at least {}", min_tier)),
                constraints: Constraints {
                    fields: vec![Field {
                        path: vec!["$.forensic_tier".to_string()],
                        filter: Some(serde_json::json!({
                            "type": "string",
                            "enum": tiers_at_or_above(min_tier)
                        })),
                        purpose: None,
                    }],
                },
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presentation_definition_for_cpoe() {
        let pd = cpoe_attestation_request(3600, "gold");

        assert_eq!(pd.id, "cpoe-attestation-request");
        assert_eq!(pd.input_descriptors.len(), 2);

        let chain = &pd.input_descriptors[0];
        assert_eq!(chain.id, "chain_duration");
        assert_eq!(chain.constraints.fields.len(), 1);
        assert_eq!(chain.constraints.fields[0].path[0], "$.chain_duration_secs");
        let filter = chain.constraints.fields[0].filter.as_ref().unwrap();
        assert_eq!(filter["minimum"], 3600);

        let tier = &pd.input_descriptors[1];
        assert_eq!(tier.id, "forensic_tier");
        let tier_filter = tier.constraints.fields[0].filter.as_ref().unwrap();
        let tier_enum = tier_filter["enum"].as_array().unwrap();
        assert!(tier_enum.iter().any(|v| v == "gold"));
        assert!(tier_enum.iter().any(|v| v == "platinum"));
    }

    #[test]
    fn test_presentation_exchange_constraints_structure() {
        let pd = cpoe_attestation_request(1800, "silver");

        // Verify top-level metadata.
        assert_eq!(pd.id, "cpoe-attestation-request");
        assert!(pd.name.is_some());
        assert!(pd.purpose.is_some());

        // Chain duration descriptor.
        let chain = &pd.input_descriptors[0];
        assert_eq!(chain.constraints.fields.len(), 1);
        let field = &chain.constraints.fields[0];
        assert_eq!(field.path, vec!["$.chain_duration_secs"]);
        let filter = field.filter.as_ref().unwrap();
        assert_eq!(filter["type"], "number");
        assert_eq!(filter["minimum"], 1800);

        // Forensic tier descriptor: enum includes silver and above.
        let tier = &pd.input_descriptors[1];
        assert_eq!(tier.constraints.fields.len(), 1);
        let tier_field = &tier.constraints.fields[0];
        assert_eq!(tier_field.path, vec!["$.forensic_tier"]);
        let tier_filter = tier_field.filter.as_ref().unwrap();
        assert_eq!(tier_filter["type"], "string");
        let allowed = tier_filter["enum"].as_array().unwrap();
        assert_eq!(allowed.len(), 3); // silver, gold, platinum
        assert!(allowed.iter().any(|v| v == "silver"));
        assert!(allowed.iter().any(|v| v == "gold"));
        assert!(allowed.iter().any(|v| v == "platinum"));
        assert!(!allowed.iter().any(|v| v == "bronze"));

        // JSON serialization should produce valid structure.
        let json = serde_json::to_value(&pd).expect("serialize");
        assert!(json["input_descriptors"].is_array());
        assert_eq!(json["input_descriptors"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_presentation_exchange_different_tiers() {
        // bronze accepts all tiers
        let pd = cpoe_attestation_request(60, "bronze");
        let filter = pd.input_descriptors[1].constraints.fields[0]
            .filter
            .as_ref()
            .unwrap();
        assert_eq!(filter["enum"].as_array().unwrap().len(), 4);

        // gold accepts gold + platinum
        let pd = cpoe_attestation_request(60, "gold");
        let filter = pd.input_descriptors[1].constraints.fields[0]
            .filter
            .as_ref()
            .unwrap();
        let allowed = filter["enum"].as_array().unwrap();
        assert_eq!(allowed.len(), 2);
        assert!(allowed.iter().any(|v| v == "gold"));
        assert!(allowed.iter().any(|v| v == "platinum"));

        // platinum accepts only platinum
        let pd = cpoe_attestation_request(60, "platinum");
        let filter = pd.input_descriptors[1].constraints.fields[0]
            .filter
            .as_ref()
            .unwrap();
        assert_eq!(filter["enum"].as_array().unwrap().len(), 1);
    }
}
