// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared test fixtures for WAR profile tests.
//!
//! Centralizes `make_ear`, `make_decl`, `make_ai_tool`, and `test_signing_key`
//! so profile test modules don't each carry their own copies.

use crate::declaration::{
    AiExtent, AiPurpose, AiToolUsage, Declaration, InputModality, ModalityType,
};
use crate::war::ear::{Ar4siStatus, EarAppraisal, EarToken, VerifierId};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;

/// Build a test EAR token with configurable chain parameters.
pub fn make_ear(chain_length: u64, chain_duration: u64) -> EarToken {
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
            pop_chain_length: Some(chain_length),
            pop_chain_duration: Some(chain_duration),
            pop_absence_claims: None,
            pop_warnings: None,
            pop_process_start: None,
            pop_process_end: None,
        },
    );
    EarToken {
        eat_profile: crate::war::ear::CPOE_EAR_PROFILE.to_string(),
        iat: Utc::now().timestamp(),
        ear_verifier_id: VerifierId::default(),
        submods,
    }
}

/// Build a minimal test declaration with the given AI tool list.
pub fn make_decl(ai_tools: Vec<AiToolUsage>) -> Declaration {
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

/// Build a test AI tool usage entry with the given extent.
pub fn make_ai_tool(extent: AiExtent) -> AiToolUsage {
    AiToolUsage {
        tool: "TestTool".to_string(),
        version: None,
        purpose: AiPurpose::Drafting,
        interaction: None,
        extent,
        sections: Vec::new(),
    }
}

/// Deterministic test signing key (not for production use).
pub fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}
