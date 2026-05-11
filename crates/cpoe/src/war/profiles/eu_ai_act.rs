// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! EU AI Act Article 50 transparency obligations compliance metadata.
//!
//! Article 50 (effective 2 August 2026) requires providers of AI systems
//! to ensure that AI-generated or substantially modified content is
//! "clearly and distinguishably marked" in a machine-readable format.
//! This module maps CPoE's `Declaration` and `AiExtent` onto structured
//! compliance metadata suitable for embedding in WAR blocks, C2PA
//! manifests, or standalone compliance reports.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::standards::{
    AiDisclosureLevel, IPTC_COMPOSITE_WITH_TRAINED_MODEL, IPTC_HUMAN_CREATION,
    IPTC_TRAINED_ALGORITHMIC_MEDIA,
};
use crate::declaration::{AiExtent, Declaration};

/// Machine-readable label: content created entirely by a human.
pub const LABEL_HUMAN_AUTHORED: &str = "human-authored";
/// Machine-readable label: content created with AI assistance.
pub const LABEL_AI_ASSISTED: &str = "ai-assisted";
/// Machine-readable label: content with substantial AI modification.
pub const LABEL_AI_ASSISTED_SUBSTANTIAL: &str = "ai-assisted-substantial";
/// Machine-readable label: content primarily or entirely AI-generated.
pub const LABEL_AI_GENERATED: &str = "ai-generated";

/// Minimum keystroke count for evidence to qualify as evidence-backed.
const MIN_EVIDENCE_KEYSTROKE_COUNT: u64 = 5;

/// Minimum entropy bits for evidence to qualify as evidence-backed.
const MIN_EVIDENCE_ENTROPY_BITS: f64 = 1.5;

/// EU AI Act Article 50 transparency obligations compliance metadata.
///
/// Effective 2 August 2026. Requires machine-readable marking of
/// AI-generated content per Article 50(2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Article50Compliance {
    /// Whether the content was generated or substantially modified by AI.
    pub ai_generated: bool,
    /// AI disclosure level mapped from CPoE's `AiExtent`.
    pub disclosure_level: String,
    /// Machine-readable label per Article 50(2): "clearly and distinguishably marked".
    pub machine_readable_label: String,
    /// IPTC Digital Source Type URI (the machine-readable standard referenced by the
    /// EU Code of Practice on AI-generated content).
    pub iptc_digital_source_type: String,
    /// C2PA assertion label carrying the disclosure, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c2pa_assertion_label: Option<String>,
    /// Whether behavioral evidence backs the disclosure (unique to CPoE).
    pub evidence_backed: bool,
    /// RFC 3339 timestamp of compliance assessment.
    pub assessed_at: String,
}

impl Article50Compliance {
    /// Derive Article 50 compliance metadata from a CPoE declaration.
    ///
    /// Mapping:
    /// - `AiExtent::None` -> not AI-generated, label "human-authored"
    /// - `AiExtent::Minimal` -> not AI-generated (AI-assisted), label "ai-assisted"
    /// - `AiExtent::Moderate` -> AI-generated (borderline), label "ai-assisted-substantial"
    /// - `AiExtent::Substantial` -> AI-generated, label "ai-generated"
    pub fn from_declaration(decl: &Declaration) -> Self {
        let max_extent = decl.max_ai_extent();

        let (ai_generated, label, iptc) = match max_extent {
            AiExtent::None => (false, LABEL_HUMAN_AUTHORED, IPTC_HUMAN_CREATION),
            AiExtent::Minimal => (false, LABEL_AI_ASSISTED, IPTC_COMPOSITE_WITH_TRAINED_MODEL),
            AiExtent::Moderate => (
                true,
                LABEL_AI_ASSISTED_SUBSTANTIAL,
                IPTC_COMPOSITE_WITH_TRAINED_MODEL,
            ),
            AiExtent::Substantial => (true, LABEL_AI_GENERATED, IPTC_TRAINED_ALGORITHMIC_MEDIA),
        };

        let disclosure_level = AiDisclosureLevel::from_ai_extent(max_extent);
        let disclosure_str = match disclosure_level {
            AiDisclosureLevel::None => "none",
            AiDisclosureLevel::AiAssisted => "ai-assisted",
            AiDisclosureLevel::AiGenerated => "ai-generated",
        };

        // Evidence-backed requires a jitter seal with minimum quality thresholds;
        // presence alone does not suffice (a zero or trivial seal is not evidence).
        let evidence_backed = decl.jitter_sealed.as_ref().is_some_and(|j| {
            j.jitter_hash != [0u8; 32]
                && j.keystroke_count >= MIN_EVIDENCE_KEYSTROKE_COUNT
                && j.entropy_bits >= MIN_EVIDENCE_ENTROPY_BITS
                && j.duration_ms > 0
        });

        // Include C2PA assertion label when AI involvement is present.
        let c2pa_assertion_label = if ai_generated {
            Some(super::c2pa::ASSERTION_LABEL.to_string())
        } else {
            None
        };

        Self {
            ai_generated,
            disclosure_level: disclosure_str.to_string(),
            machine_readable_label: label.to_string(),
            iptc_digital_source_type: iptc.to_string(),
            c2pa_assertion_label,
            evidence_backed,
            assessed_at: Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declaration::{
        AiExtent, AiPurpose, AiToolUsage, Declaration, InputModality, ModalityType,
    };
    use chrono::Utc;

    fn make_decl(ai_tools: Vec<AiToolUsage>) -> Declaration {
        Declaration {
            document_hash: [1u8; 32],
            chain_hash: [2u8; 32],
            title: "Test".to_string(),
            input_modalities: vec![InputModality {
                modality_type: ModalityType::Keyboard,
                percentage: 100.0,
                note: None,
            }],
            ai_tools,
            collaborators: Vec::new(),
            statement: "I wrote this.".to_string(),
            created_at: Utc::now(),
            version: 1,
            author_public_key: Vec::new(),
            signature: Vec::new(),
            jitter_sealed: None,
        }
    }

    fn make_ai_tool(extent: AiExtent) -> AiToolUsage {
        AiToolUsage {
            tool: "TestTool".to_string(),
            version: None,
            purpose: AiPurpose::Drafting,
            interaction: None,
            extent,
            sections: Vec::new(),
        }
    }

    #[test]
    fn test_article50_no_ai() {
        let decl = make_decl(Vec::new());
        let c = Article50Compliance::from_declaration(&decl);
        assert!(!c.ai_generated);
        assert_eq!(c.machine_readable_label, LABEL_HUMAN_AUTHORED);
        assert_eq!(c.iptc_digital_source_type, IPTC_HUMAN_CREATION);
        assert!(c.c2pa_assertion_label.is_none());
        assert_eq!(c.disclosure_level, "none");
    }

    #[test]
    fn test_article50_minimal_ai() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Minimal)]);
        let c = Article50Compliance::from_declaration(&decl);
        assert!(
            !c.ai_generated,
            "minimal AI is not AI-generated per Article 50"
        );
        assert_eq!(c.machine_readable_label, LABEL_AI_ASSISTED);
        assert_eq!(
            c.iptc_digital_source_type,
            IPTC_COMPOSITE_WITH_TRAINED_MODEL
        );
        assert!(c.c2pa_assertion_label.is_none());
    }

    #[test]
    fn test_article50_moderate_ai() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Moderate)]);
        let c = Article50Compliance::from_declaration(&decl);
        assert!(c.ai_generated, "moderate AI is borderline AI-generated");
        assert_eq!(c.machine_readable_label, LABEL_AI_ASSISTED_SUBSTANTIAL);
        assert!(c.c2pa_assertion_label.is_some());
    }

    #[test]
    fn test_article50_substantial_ai() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Substantial)]);
        let c = Article50Compliance::from_declaration(&decl);
        assert!(c.ai_generated);
        assert_eq!(c.machine_readable_label, LABEL_AI_GENERATED);
        assert_eq!(c.iptc_digital_source_type, IPTC_TRAINED_ALGORITHMIC_MEDIA);
        assert!(c.c2pa_assertion_label.is_some());
        assert_eq!(c.disclosure_level, "ai-generated");
    }

    #[test]
    fn test_eu_ai_act_none_is_human() {
        let decl = make_decl(Vec::new());
        let c = Article50Compliance::from_declaration(&decl);
        assert!(!c.ai_generated, "AiExtent::None should not be AI-generated");
        assert_eq!(c.machine_readable_label, LABEL_HUMAN_AUTHORED);
    }

    #[test]
    fn test_eu_ai_act_substantial_is_ai() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Substantial)]);
        let c = Article50Compliance::from_declaration(&decl);
        assert!(
            c.ai_generated,
            "AiExtent::Substantial should be AI-generated"
        );
        assert_eq!(c.machine_readable_label, LABEL_AI_GENERATED);
    }

    #[test]
    fn test_eu_ai_act_iptc_mapping() {
        // None -> humanCreation
        let decl_none = make_decl(Vec::new());
        let c_none = Article50Compliance::from_declaration(&decl_none);
        assert_eq!(
            c_none.iptc_digital_source_type,
            "http://cv.iptc.org/newscodes/digitalsourcetype/humanCreation"
        );

        // Minimal -> compositeWithTrainedAlgorithmicMedia
        let decl_min = make_decl(vec![make_ai_tool(AiExtent::Minimal)]);
        let c_min = Article50Compliance::from_declaration(&decl_min);
        assert_eq!(
            c_min.iptc_digital_source_type,
            "http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia"
        );

        // Moderate -> compositeWithTrainedAlgorithmicMedia
        let decl_mod = make_decl(vec![make_ai_tool(AiExtent::Moderate)]);
        let c_mod = Article50Compliance::from_declaration(&decl_mod);
        assert_eq!(
            c_mod.iptc_digital_source_type,
            "http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia"
        );

        // Substantial -> trainedAlgorithmicMedia
        let decl_sub = make_decl(vec![make_ai_tool(AiExtent::Substantial)]);
        let c_sub = Article50Compliance::from_declaration(&decl_sub);
        assert_eq!(
            c_sub.iptc_digital_source_type,
            "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
        );
    }

    #[test]
    fn test_article50_assessed_at_is_rfc3339() {
        let decl = make_decl(Vec::new());
        let c = Article50Compliance::from_declaration(&decl);
        assert!(
            chrono::DateTime::parse_from_rfc3339(&c.assessed_at).is_ok(),
            "assessed_at should be RFC 3339"
        );
    }

    #[test]
    fn test_article50_evidence_backed_without_jitter() {
        let decl = make_decl(Vec::new());
        let c = Article50Compliance::from_declaration(&decl);
        assert!(
            !c.evidence_backed,
            "no jitter seal means not evidence-backed"
        );
    }

    #[test]
    fn test_article50_evidence_backed_with_jitter() {
        let mut decl = make_decl(Vec::new());
        decl.jitter_sealed = Some(crate::declaration::DeclarationJitter {
            jitter_hash: [3u8; 32],
            keystroke_count: 100,
            duration_ms: 5000,
            avg_interval_ms: 120.0,
            entropy_bits: 4.5,
            hardware_sealed: true,
        });
        let c = Article50Compliance::from_declaration(&decl);
        assert!(c.evidence_backed, "jitter seal means evidence-backed");
    }
}
