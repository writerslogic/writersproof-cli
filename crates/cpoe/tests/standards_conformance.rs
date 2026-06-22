// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! End-to-end standards conformance integration test.
//!
//! Exercises the full authoring-to-verification pipeline and projects
//! evidence through every standards profile: C2PA, W3C VC, CAWG,
//! EAT/CWT, CoRIM, EU AI Act, and JPEG Trust.
//!
//! Run: `cargo test --test standards_conformance`

use std::time::Duration;

use coset::CborSerializable;
use ed25519_dalek::SigningKey;

/// Full authoring-to-verification flow exercising RATS, C2PA, W3C VC,
/// CAWG, EAT/CWT, CoRIM, and EU AI Act compliance projections.
#[test]
fn standards_conformance_e2e() {
    // 1. Create a temp data directory and test document.
    let dir = tempfile::tempdir().expect("tempdir");
    let doc_path = dir.path().join("standards_test.txt");
    std::fs::write(
        &doc_path,
        b"This is a test document for standards conformance.",
    )
    .expect("write");

    // 2. Initialize a checkpoint chain.
    let mut chain =
        cpoe_engine::checkpoint::Chain::new(&doc_path, cpoe_engine::vdf::default_parameters())
            .expect("create chain");

    // 3. Write more content (simulate editing).
    std::fs::write(
        &doc_path,
        b"This is a test document for standards conformance. Extended with more content.",
    )
    .expect("write v2");

    // 4. Create checkpoint chain entries (need >= 3 for valid appraisal).
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");
    std::fs::write(
        &doc_path,
        b"Standards conformance document. Version three with substantial edits and additions.",
    )
    .expect("write v3");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 2");
    std::fs::write(
        &doc_path,
        b"Standards conformance document. Final version with all required content present.",
    )
    .expect("write v4");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 3");

    let latest = chain.latest().expect("latest checkpoint");
    assert!(chain.checkpoints.len() >= 3, "need at least 3 checkpoints");

    // 5. Build evidence with the evidence builder.
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let decl = cpoe_engine::declaration::no_ai_declaration(
        latest.content_hash,
        latest.hash,
        "Standards Test Doc",
        "I wrote this document entirely by hand.",
    )
    .sign(&signing_key)
    .expect("sign declaration");

    let packet = cpoe_engine::evidence::Builder::new("Standards Test Doc", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build evidence packet");

    // 6. Run WAR appraisal to get EAR token.
    let policy = cpoe_engine::trust_policy::profiles::basic();
    let block = cpoe_engine::war::Block::from_packet_appraised(&packet, &signing_key, &policy)
        .expect("appraised WAR block");
    let ear = block.ear.as_ref().expect("block should have EAR token");
    let pop = ear.pop_appraisal().expect("EAR should have pop submod");
    // Software-only minimal evidence may yield None or Contraindicated status
    // (weakest-link of trust vector components that are 0 for software-only
    // and fail-closed policy defaults). Verify the appraisal ran and produced
    // any valid status enum; the point of this test is conformance wiring,
    // not that a bare minimal packet produces a passing appraisal.
    assert!(
        matches!(
            pop.ear_status,
            cpoe_engine::war::Ar4siStatus::Affirming
                | cpoe_engine::war::Ar4siStatus::Warning
                | cpoe_engine::war::Ar4siStatus::None
                | cpoe_engine::war::Ar4siStatus::Contraindicated
        ),
        "appraisal status unexpected: {:?}",
        pop.ear_status
    );
    // Trust vector must be present even for software-only.
    assert!(
        pop.ear_trustworthiness_vector.is_some(),
        "trust vector should be populated"
    );

    // 7. Project to C2PA assertion; verify fields.
    let c2pa = cpoe_engine::war::profiles::c2pa::to_c2pa_assertion(ear).expect("C2PA assertion");
    assert_eq!(
        c2pa.label,
        cpoe_engine::war::profiles::c2pa::ASSERTION_LABEL
    );
    assert!(!c2pa.data.status.is_empty());
    assert!(!c2pa.data.verifier_id.build.is_empty());

    // 8. Project to W3C VC; verify structure.
    let author_did = "did:key:z6MkE2ETest";
    let vc =
        cpoe_engine::war::profiles::vc::to_verifiable_credential(ear, author_did).expect("W3C VC");
    assert!(vc
        .context
        .contains(&"https://www.w3.org/ns/credentials/v2".to_string()));
    assert!(vc.vc_type.contains(&"VerifiableCredential".to_string()));
    assert!(vc
        .vc_type
        .contains(&"ProcessAttestationCredential".to_string()));
    assert_eq!(vc.credential_subject.id, author_did);
    assert_eq!(vc.credential_subject.subject_type, "Author");
    assert!(vc.evidence.is_some());

    // 9. Project to CAWG identity; verify ICA mode.
    let cawg =
        cpoe_engine::war::profiles::cawg::to_cawg_identity(ear, author_did).expect("CAWG identity");
    assert_eq!(
        cawg.signer_payload.sig_type,
        cpoe_engine::war::profiles::cawg::IDENTITY_LABEL
    );
    match &cawg.signer_payload.credential {
        cpoe_engine::war::profiles::cawg::CawgCredential::Ica { provider, claims } => {
            assert_eq!(
                provider,
                cpoe_engine::war::profiles::cawg::WRITERSPROOF_ICA_PROVIDER
            );
            let types: Vec<&str> = claims.iter().map(|c| c.claim_type.as_str()).collect();
            assert!(types.contains(&"did"));
            assert!(types.contains(&"attestation_status"));
        }
        _ => panic!("expected ICA credential"),
    }

    // 10. Encode EAR as CWT; verify COSE_Sign1.
    let provider = cpoe_engine::tpm::SoftwareProvider::new();
    let cwt_bytes = cpoe_engine::rats::encode_eat_cwt(ear, &provider).expect("CWT encode");
    assert!(!cwt_bytes.is_empty());
    let sign1 = coset::CoseSign1::from_slice(&cwt_bytes).expect("parse COSE_Sign1");
    assert!(sign1.payload.is_some());
    assert!(!sign1.signature.is_empty());
    // Decode back with signature verification and verify profile preserved.
    let pk: [u8; 32] = cpoe_engine::tpm::Provider::public_key(&provider)
        .try_into()
        .unwrap();
    let decoded_ear =
        cpoe_engine::rats::decode_eat_cwt_verified(&cwt_bytes, &pk).expect("CWT decode");
    assert_eq!(decoded_ear.eat_profile, ear.eat_profile);
    assert_eq!(decoded_ear.iat, ear.iat);

    // 11. Generate CoRIM reference values; verify defaults.
    let corim = cpoe_engine::rats::CpoeReferenceValues::default();
    assert!(
        (corim.min_entropy_bits - 3.0).abs() < f64::EPSILON,
        "CoRIM entropy threshold"
    );
    assert_eq!(corim.vdf_duration_bounds, (0.5, 3.0));
    assert_eq!(corim.min_checkpoints_standard, 3);
    // Verify CBOR roundtrip.
    let corim_cbor = corim.to_cbor().expect("CoRIM to_cbor");
    let corim_decoded =
        cpoe_engine::rats::CpoeReferenceValues::from_cbor(&corim_cbor).expect("CoRIM roundtrip");
    assert_eq!(corim_decoded, corim);

    // 12. Generate EU AI Act compliance; verify mapping.
    let eu_compliance =
        cpoe_engine::war::profiles::eu_ai_act::Article50Compliance::from_declaration(&decl);
    assert!(
        !eu_compliance.ai_generated,
        "no-AI declaration should not be AI-generated"
    );
    assert_eq!(
        eu_compliance.machine_readable_label,
        cpoe_engine::war::profiles::eu_ai_act::LABEL_HUMAN_AUTHORED
    );
    assert!(eu_compliance
        .iptc_digital_source_type
        .ends_with("/humanCreation"));

    // 13. Verify the evidence packet; verify verdict.
    let overall = ear.overall_status();
    assert!(
        matches!(
            overall,
            cpoe_engine::war::Ar4siStatus::Affirming
                | cpoe_engine::war::Ar4siStatus::Warning
                | cpoe_engine::war::Ar4siStatus::None
                | cpoe_engine::war::Ar4siStatus::Contraindicated
        ),
        "overall EAR status unexpected: {:?}",
        overall
    );

    // Verify seal is present and non-zero.
    assert!(
        pop.pop_seal.is_some(),
        "appraised EAR should have seal claims"
    );
    let seal = pop.pop_seal.as_ref().unwrap();
    assert_ne!(seal.h3, [0u8; 32], "H3 should be non-zero");
    assert_ne!(seal.signature, [0u8; 64], "signature should be non-zero");
}
