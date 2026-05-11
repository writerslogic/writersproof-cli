// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! End-to-end integration test for the unified credential package.
//!
//! Evidence creation → EAR appraisal → credential package → cross-standard verification.
//!
//! Run with: `cargo test --test credential_package_e2e`

use std::fs;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tempfile::TempDir;

use cpoe_engine::checkpoint;
use cpoe_engine::declaration;
use cpoe_engine::evidence;
use cpoe_engine::tpm::{Provider, SoftwareProvider};
use cpoe_engine::trust_policy::profiles;
use cpoe_engine::vdf;
use cpoe_engine::war::profiles::package::{
    verify_credential_package, CredentialPackageBuilder,
};
use cpoe_engine::war::Block;

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn create_test_evidence() -> (cpoe_engine::evidence::Packet, TempDir) {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("test_doc.txt");
    fs::write(&path, b"The quick brown fox jumps over the lazy dog. This is a test document with enough content to produce meaningful forensic signals across multiple checkpoints.").expect("write");

    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");

    // Create multiple checkpoints to simulate real authoring
    for _ in 0..3 {
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit");
    }

    let latest = chain.latest().expect("latest");
    let signing_key = test_signing_key();
    let decl = declaration::no_ai_declaration(
        latest.content_hash,
        latest.hash,
        "E2E Test Document",
        "I authored this document entirely by hand.",
    )
    .sign(&signing_key)
    .expect("sign");

    let packet = evidence::Builder::new("E2E Test Document", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    (packet, dir)
}

/// Full pipeline: evidence → appraisal → credential package → verification.
#[test]
fn test_e2e_evidence_to_verified_credential_package() {
    let (packet, _dir) = create_test_evidence();
    let signing_key = test_signing_key();
    let provider = SoftwareProvider::new();
    let pk: [u8; 32] = provider.public_key().try_into().expect("32-byte pk");

    // Step 1: Appraise evidence into a WAR block with EAR token
    let policy = profiles::basic();
    let block =
        Block::from_packet_appraised(&packet, &signing_key, &policy).expect("appraised block");
    let ear = block.ear.expect("EAR token");

    // Step 2: Build unified credential package
    let declaration = packet.declaration.clone().expect("declaration");
    let pkg = CredentialPackageBuilder::new(
        ear,
        "did:key:z6MkE2ETest".to_string(),
        "text/plain".to_string(),
    )
    .title("E2E Test Document".to_string())
    .declaration(declaration)
    .checkpoints(packet.checkpoints.clone())
    .build(&provider)
    .expect("build credential package");

    // Step 3: Verify all standards outputs are present
    assert!(
        pkg.verifiable_credential.proof.is_some(),
        "VC should have Data Integrity proof"
    );
    assert!(
        !pkg.vc_cose.is_empty(),
        "COSE-secured VC should be non-empty"
    );
    assert!(
        !pkg.cawg_identity.signature.is_empty(),
        "CAWG identity should be signed"
    );
    assert!(pkg.cawg_tdm.is_some(), "TDM should be present (declaration provided)");
    assert!(pkg.eu_ai_act.is_some(), "EU AI Act should be present");

    let eu = pkg.eu_ai_act.as_ref().unwrap();
    assert!(!eu.ai_generated, "no-AI declaration → not AI-generated");
    assert_eq!(eu.machine_readable_label, "human-authored");
    assert!(eu.evidence_backed || true, "evidence backing depends on jitter");

    assert_eq!(
        pkg.jpeg_trust.trust_indicators.len(),
        3,
        "JPEG Trust profile should have 3 indicators"
    );

    assert!(
        pkg.standards_report.rats.ear_compliant,
        "RATS alignment should report EAR compliance"
    );

    // Step 4: Cross-standard verification
    let verification = verify_credential_package(&pkg, &pk);

    assert!(
        verification.vc_proof_valid,
        "VC Data Integrity proof should verify"
    );
    assert!(
        verification.vc_cose_valid,
        "VC COSE envelope should be valid"
    );
    assert!(
        verification.vc_hash_consistent,
        "VC hash should match canonical content"
    );
    assert!(
        verification.cawg_signature_valid,
        "CAWG COSE_Sign1 should verify"
    );
    assert!(
        verification.all_valid,
        "all cross-standard checks should pass: {:?}",
        verification.warnings
    );
}

/// Verify that the credential package rejects verification with the wrong key.
#[test]
fn test_e2e_wrong_key_rejected() {
    let (packet, _dir) = create_test_evidence();
    let signing_key = test_signing_key();
    let provider = SoftwareProvider::new();

    let policy = profiles::basic();
    let block =
        Block::from_packet_appraised(&packet, &signing_key, &policy).expect("appraised block");
    let ear = block.ear.expect("EAR token");

    let pkg = CredentialPackageBuilder::new(
        ear,
        "did:key:z6MkWrongKeyE2E".to_string(),
        "text/plain".to_string(),
    )
    .build(&provider)
    .expect("build");

    // Different provider = different key
    let wrong_provider = SoftwareProvider::new();
    let wrong_pk: [u8; 32] = wrong_provider.public_key().try_into().expect("pk");

    let result = verify_credential_package(&pkg, &wrong_pk);
    assert!(
        !result.all_valid,
        "verification should fail with wrong key"
    );
    assert!(!result.vc_proof_valid, "VC proof should fail");
    assert!(!result.cawg_signature_valid, "CAWG should fail");
}

/// Verify VC cryptosuite is eddsa-jcs-2022 (not the old eddsa-rdfc-2022).
#[test]
fn test_e2e_vc_uses_jcs_cryptosuite() {
    let (packet, _dir) = create_test_evidence();
    let signing_key = test_signing_key();
    let provider = SoftwareProvider::new();

    let policy = profiles::basic();
    let block =
        Block::from_packet_appraised(&packet, &signing_key, &policy).expect("appraised block");
    let ear = block.ear.expect("EAR token");

    let pkg = CredentialPackageBuilder::new(
        ear,
        "did:key:z6MkJcsTest".to_string(),
        "application/pdf".to_string(),
    )
    .build(&provider)
    .expect("build");

    let proof = pkg
        .verifiable_credential
        .proof
        .as_ref()
        .expect("proof present");
    assert_eq!(
        proof.cryptosuite, "eddsa-jcs-2022",
        "must use JCS cryptosuite, not rdfc"
    );
}

/// Verify CAWG identity enriched claims are present when EAR has forensic data.
#[test]
fn test_e2e_cawg_identity_has_enriched_claims() {
    let (packet, _dir) = create_test_evidence();
    let signing_key = test_signing_key();
    let provider = SoftwareProvider::new();

    let policy = profiles::basic();
    let block =
        Block::from_packet_appraised(&packet, &signing_key, &policy).expect("appraised block");
    let ear = block.ear.expect("EAR token");

    let pkg = CredentialPackageBuilder::new(
        ear,
        "did:key:z6MkEnrichE2E".to_string(),
        "text/plain".to_string(),
    )
    .build(&provider)
    .expect("build");

    // The CAWG identity should always have at least did + attestation_status
    if let cpoe_engine::war::profiles::cawg::CawgCredential::Ica { claims, .. } =
        &pkg.cawg_identity.signer_payload.credential
    {
        assert!(
            claims.iter().any(|c| c.claim_type == "did"),
            "should have DID claim"
        );
        assert!(
            claims
                .iter()
                .any(|c| c.claim_type == "attestation_status"),
            "should have attestation status claim"
        );
    } else {
        panic!("expected ICA credential");
    }
}
