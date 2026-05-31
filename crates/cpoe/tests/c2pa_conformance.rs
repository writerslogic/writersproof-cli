// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! C2PA conformance tests for CPoE's C2PA output.
//!
//! Validates that `to_c2pa_assertion()` and `to_c2pa_action()` produce output
//! conforming to C2PA specs-core requirements: correct labels, required fields,
//! IPTC digital source type mapping, and CWT roundtrip fidelity.
//!
//! Run with: `cargo test --test c2pa_conformance`

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use chrono::DateTime;
use ed25519_dalek::SigningKey;
use tempfile::TempDir;

use cpoe_engine::checkpoint;
use cpoe_engine::declaration;
use cpoe_engine::evidence;
use cpoe_engine::evidence::Packet;
use cpoe_engine::rats::{decode_eat_cwt_verified, encode_eat_cwt};
use cpoe_engine::tpm::{Provider, SoftwareProvider};
use cpoe_engine::trust_policy::profiles;
use cpoe_engine::vdf;
use cpoe_engine::war::ear::{
    Ar4siStatus, EarAppraisal, EarToken, TrustworthinessVector, VerifierId, CPOE_EAR_PROFILE,
};
use cpoe_engine::war::profiles::c2pa::{self, ASSERTION_LABEL};
use cpoe_engine::war::profiles::standards::AiDisclosureLevel;
use cpoe_engine::war::Block;

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// Create a minimal evidence packet with a checkpoint chain and declaration.
fn create_test_evidence() -> (Packet, TempDir) {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("test_doc.txt");
    fs::write(&path, b"Test document content for C2PA conformance").expect("write");

    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("create chain");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit");

    let latest = chain.latest().expect("latest");
    let signing_key = test_signing_key();
    let decl = declaration::no_ai_declaration(
        latest.content_hash,
        latest.hash,
        "Test Document",
        "I wrote this document myself without AI assistance.",
    )
    .sign(&signing_key)
    .expect("sign");

    let packet = evidence::Builder::new("Test Document", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build packet");

    (packet, dir)
}

/// Build an appraised WAR block and extract the EAR token.
fn appraised_ear() -> (EarToken, TempDir) {
    let (packet, dir) = create_test_evidence();
    let signing_key = test_signing_key();
    let policy = profiles::basic();

    let block =
        Block::from_packet_appraised(&packet, &signing_key, &policy).expect("appraised block");
    let ear = block.ear.expect("block should have EAR token");
    (ear, dir)
}

// ---------------------------------------------------------------------------
// 1. test_c2pa_assertion_has_required_fields
// ---------------------------------------------------------------------------

#[test]
fn test_c2pa_assertion_has_required_fields() {
    let (ear, _dir) = appraised_ear();

    let assertion = c2pa::to_c2pa_assertion(&ear).expect("to_c2pa_assertion");

    // label: entity-specific namespace pattern (reverse domain, versioned)
    assert!(!assertion.label.is_empty(), "label must be non-empty");
    assert!(
        assertion.label.contains('.'),
        "label must use reverse-domain notation: {}",
        assertion.label
    );

    // ear_profile matches the EAT profile URI
    assert_eq!(
        assertion.data.ear_profile, CPOE_EAR_PROFILE,
        "ear_profile must match the EAT profile URI"
    );

    // status is non-empty
    assert!(
        !assertion.data.status.is_empty(),
        "status must be non-empty"
    );

    // verifier_id has build and developer
    assert!(
        !assertion.data.verifier_id.build.is_empty(),
        "verifier_id.build must be non-empty"
    );
    assert!(
        !assertion.data.verifier_id.developer.is_empty(),
        "verifier_id.developer must be non-empty"
    );

    // processStart and processEnd are valid RFC 3339 timestamps
    let start = assertion
        .data
        .process_start
        .as_ref()
        .expect("processStart must be present");
    let end = assertion
        .data
        .process_end
        .as_ref()
        .expect("processEnd must be present");
    DateTime::parse_from_rfc3339(start)
        .unwrap_or_else(|e| panic!("processStart is not valid RFC 3339: {}: {}", start, e));
    DateTime::parse_from_rfc3339(end)
        .unwrap_or_else(|e| panic!("processEnd is not valid RFC 3339: {}: {}", end, e));

    // Verify full JSON roundtrip
    let json = serde_json::to_string_pretty(&assertion).expect("serialize");
    let decoded: c2pa::C2paAssertion = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.label, assertion.label);
    assert_eq!(decoded.data.status, assertion.data.status);
    assert_eq!(decoded.data.ear_profile, assertion.data.ear_profile);
}

// ---------------------------------------------------------------------------
// 2. test_c2pa_action_has_required_fields
// ---------------------------------------------------------------------------

#[test]
fn test_c2pa_action_has_required_fields() {
    let (ear, _dir) = appraised_ear();

    let action = c2pa::to_c2pa_action(&ear, None).expect("to_c2pa_action");

    // action must be a valid C2PA action
    assert_eq!(
        action.action, "c2pa.created",
        "action must be 'c2pa.created'"
    );

    // digitalSourceType must be a valid IPTC URI
    assert!(
        action
            .digital_source_type
            .starts_with("http://cv.iptc.org/newscodes/digitalsourcetype/"),
        "digitalSourceType must be a valid IPTC URI: {}",
        action.digital_source_type
    );

    // softwareAgent is non-empty
    assert!(
        !action.software_agent.is_empty(),
        "softwareAgent must be non-empty"
    );

    // parameters should be present with pop-specific keys
    let params = action
        .parameters
        .as_ref()
        .expect("parameters must be present");
    assert!(
        params.get("pop.attestation_tier").is_some(),
        "parameters must include pop.attestation_tier"
    );
}

// ---------------------------------------------------------------------------
// 3. test_c2pa_action_respects_ai_disclosure
// ---------------------------------------------------------------------------

#[test]
fn test_c2pa_action_respects_ai_disclosure() {
    let (ear, _dir) = appraised_ear();

    // None -> humanCreation
    let action_none = c2pa::to_c2pa_action(&ear, None).expect("action with no disclosure");
    assert!(
        action_none.digital_source_type.ends_with("/humanCreation"),
        "None disclosure should map to humanCreation, got: {}",
        action_none.digital_source_type
    );

    // AiAssisted -> compositeWithTrainedAlgorithmicMedia
    let action_assisted =
        c2pa::to_c2pa_action(&ear, Some(&AiDisclosureLevel::AiAssisted)).expect("action assisted");
    assert!(
        action_assisted
            .digital_source_type
            .ends_with("/compositeWithTrainedAlgorithmicMedia"),
        "AiAssisted should map to compositeWithTrainedAlgorithmicMedia, got: {}",
        action_assisted.digital_source_type
    );

    // AiGenerated -> trainedAlgorithmicMedia
    let action_generated = c2pa::to_c2pa_action(&ear, Some(&AiDisclosureLevel::AiGenerated))
        .expect("action generated");
    assert!(
        action_generated
            .digital_source_type
            .ends_with("/trainedAlgorithmicMedia"),
        "AiGenerated should map to trainedAlgorithmicMedia, got: {}",
        action_generated.digital_source_type
    );
}

// ---------------------------------------------------------------------------
// 4. test_rats_cwt_roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_rats_cwt_roundtrip() {
    let mut submods = BTreeMap::new();
    submods.insert(
        "pop".to_string(),
        EarAppraisal {
            ear_status: Ar4siStatus::Affirming,
            ear_trustworthiness_vector: Some(TrustworthinessVector {
                instance_identity: 2,
                configuration: 2,
                executables: 0,
                file_system: 2,
                hardware: 2,
                runtime_opaque: 2,
                storage_opaque: 2,
                sourced_data: 2,
            }),
            ear_appraisal_policy_id: Some("pop-default-v1".to_string()),
            pop_seal: None,
            pop_evidence_ref: None,
            pop_entropy_report: None,
            pop_forgery_cost: None,
            pop_forensic_summary: None,
            pop_chain_length: Some(42),
            pop_chain_duration: Some(3600),
            pop_absence_claims: None,
            pop_warnings: Some(vec!["low entropy in segment 3".to_string()]),
            pop_process_start: None,
            pop_process_end: None,
        },
    );

    let ear = EarToken {
        eat_profile: CPOE_EAR_PROFILE.to_string(),
        iat: 1711324800,
        ear_verifier_id: VerifierId::default(),
        submods,
    };

    let provider = SoftwareProvider::new();
    let cwt_bytes = encode_eat_cwt(&ear, &provider).expect("CWT encode");
    assert!(!cwt_bytes.is_empty(), "CWT bytes must not be empty");

    let pk: [u8; 32] = provider.public_key().try_into().unwrap();
    let decoded = decode_eat_cwt_verified(&cwt_bytes, &pk).expect("CWT decode");

    // Core EAR fields preserved
    assert_eq!(decoded.eat_profile, ear.eat_profile);
    assert_eq!(decoded.iat, ear.iat);
    assert_eq!(decoded.ear_verifier_id.build, ear.ear_verifier_id.build);
    assert_eq!(
        decoded.ear_verifier_id.developer,
        ear.ear_verifier_id.developer
    );

    // Submodule appraisal preserved
    let pop = decoded.pop_appraisal().expect("missing pop submod");
    let orig = ear.pop_appraisal().expect("missing original pop submod");

    assert_eq!(pop.ear_status, orig.ear_status);
    assert_eq!(pop.pop_chain_length, orig.pop_chain_length);
    assert_eq!(pop.pop_chain_duration, orig.pop_chain_duration);
    assert_eq!(pop.pop_warnings, orig.pop_warnings);
    assert_eq!(pop.ear_appraisal_policy_id, orig.ear_appraisal_policy_id);

    // Trust vector roundtrip
    let tv = pop
        .ear_trustworthiness_vector
        .as_ref()
        .expect("missing trust vector");
    let orig_tv = orig
        .ear_trustworthiness_vector
        .as_ref()
        .expect("missing original trust vector");
    assert_eq!(tv, orig_tv);
}

// ---------------------------------------------------------------------------
// 5. test_assertion_label_follows_c2pa_naming
// ---------------------------------------------------------------------------

#[test]
fn test_assertion_label_follows_c2pa_naming() {
    // C2PA entity-specific assertion labels must follow the pattern:
    // <reverse-domain>.<assertion-name>.v<version>
    // e.g. "com.writerslogic.cpoe-attestation.v1"

    let label = ASSERTION_LABEL;

    // Must contain at least 3 dot-separated segments
    let segments: Vec<&str> = label.split('.').collect();
    assert!(
        segments.len() >= 3,
        "C2PA assertion label must have at least 3 dot-separated segments: {}",
        label
    );

    // First segment should be a TLD (com, org, etc.)
    let tld = segments[0];
    assert!(
        ["com", "org", "net", "io"].contains(&tld),
        "C2PA label should start with a recognized TLD: {}",
        label
    );

    // Last segment should be a version identifier (v1, v2, etc.)
    let last = segments.last().expect("non-empty");
    assert!(
        last.starts_with('v') && last[1..].chars().all(|c| c.is_ascii_digit()),
        "C2PA label must end with a version segment (e.g. v1): {}",
        label
    );

    // Verify the constant matches what to_c2pa_assertion() produces
    let (ear, _dir) = appraised_ear();
    let assertion = c2pa::to_c2pa_assertion(&ear).expect("assertion");
    assert_eq!(
        assertion.label, label,
        "to_c2pa_assertion label must match ASSERTION_LABEL constant"
    );
}
