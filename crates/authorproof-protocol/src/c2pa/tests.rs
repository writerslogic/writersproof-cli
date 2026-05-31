// SPDX-License-Identifier: Apache-2.0

use super::embed::{embed_in_pdf, hash_with_exclusions, sidecar_path, supports_embedding};
use super::trust::{evaluate_trust, TrustLevel};
use super::validation::{verify_manifest_signature, verify_manifest_with_key};
use super::*;
use crate::rfc::{Checkpoint, DocumentRef, EvidencePacket, HashAlgorithm, HashValue};
use coset::CborSerializable;
use ed25519_dalek::SigningKey;
use sha2::Digest;

extern crate c2pa as c2pa_sdk;

fn test_evidence_packet() -> EvidencePacket {
    EvidencePacket {
        version: 1,
        profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
        packet_id: vec![0xAA; 16],
        created: 1710000000000,
        document: DocumentRef {
            content_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: vec![0xAB; 32],
            },
            filename: Some("test.txt".to_string()),
            byte_length: 1024,
            char_count: 512,
        },
        checkpoints: vec![
            make_checkpoint(0, 1710000001000),
            make_checkpoint(1, 1710000002000),
            make_checkpoint(2, 1710000003000),
        ],
        attestation_tier: None,
        baseline_verification: None,
    }
}

fn make_checkpoint(seq: u64, ts: u64) -> Checkpoint {
    Checkpoint {
        sequence: seq,
        checkpoint_id: vec![0u8; 16],
        timestamp: ts,
        content_hash: HashValue {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![seq as u8; 32],
        },
        char_count: 100 + seq * 50,
        prev_hash: HashValue {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![0u8; 32],
        },
        checkpoint_hash: HashValue {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![seq as u8 + 0x10; 32],
        },
        jitter_hash: None,
    }
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[1u8; 32])
}

fn build_test_manifest() -> C2paManifest {
    let packet = test_evidence_packet();
    let evidence_bytes = b"fake evidence cbor".to_vec();
    let doc_hash = [0xABu8; 32];
    let key = test_signing_key();

    C2paManifestBuilder::new(packet, evidence_bytes, doc_hash)
        .document_filename("test.txt")
        .title("Test Document")
        .build_manifest(&key)
        .unwrap()
}

#[test]
fn cpoe_assertion_from_evidence() {
    let packet = test_evidence_packet();
    let evidence_bytes = b"fake evidence cbor";
    let assertion = ProcessProofAssertion::from_evidence(&packet, evidence_bytes);

    assert_eq!(assertion.version, 2);
    assert!(!assertion.evidence_hash.is_empty());
    assert!(!assertion.evidence_id.is_empty());
}

#[test]
fn evidence_chain_from_evidence() {
    let packet = test_evidence_packet();
    let chain = EvidenceChainAssertion::from_evidence(&packet);

    assert_eq!(chain.version, 1);
    assert_eq!(chain.checkpoint_count, 3);
    assert_eq!(chain.seals.len(), 3);
    assert!(chain.chain_duration_sec > 0.0);
}

#[test]
fn claim_v2_required_fields() {
    let manifest = build_test_manifest();

    assert!(
        !manifest.claim.instance_id.is_empty(),
        "instanceID required"
    );
    assert!(
        manifest.claim.instance_id.starts_with("xmp:iid:"),
        "instanceID should use XMP format"
    );
    assert!(
        !manifest.claim.signature.is_empty(),
        "signature URI required"
    );
    assert!(
        manifest.claim.signature.contains("c2pa.signature"),
        "signature should reference signature box"
    );
    assert!(
        !manifest.claim.claim_generator_info.name.is_empty(),
        "claim_generator_info must have name"
    );
    // 4 core assertions (hash-data, actions, process-proof, evidence-chain) + 1 metadata (title)
    assert_eq!(manifest.claim.created_assertions.len(), 5);
}

#[test]
fn manifest_label_consistent_in_urls() {
    let manifest = build_test_manifest();

    for assertion in &manifest.claim.created_assertions {
        assert!(
            assertion.url.contains(&manifest.manifest_label),
            "Assertion URL '{}' must contain manifest label '{}'",
            assertion.url,
            manifest.manifest_label
        );
    }

    assert!(
        manifest.claim.signature.contains(&manifest.manifest_label),
        "Signature URL must contain manifest label"
    );
}

#[test]
fn assertion_hashes_match_stored_boxes() {
    let manifest = build_test_manifest();

    assert_eq!(
        manifest.assertion_boxes.len(),
        manifest.claim.created_assertions.len()
    );

    for (assertion_ref, box_bytes) in manifest
        .claim
        .created_assertions
        .iter()
        .zip(manifest.assertion_boxes.iter())
    {
        let computed = sha2::Sha256::digest(&box_bytes[8..]);
        assert_eq!(
            assertion_ref.hash,
            computed.to_vec(),
            "Stored box hash must match claim reference"
        );
    }
}

#[test]
fn hashed_uri_uses_binary_hash() {
    let manifest = build_test_manifest();
    for assertion_ref in &manifest.claim.created_assertions {
        assert_eq!(assertion_ref.hash.len(), 32, "SHA-256 = 32 raw bytes");
    }
}

#[test]
fn signature_contains_public_key_in_protected_header() {
    let manifest = build_test_manifest();

    let sign1 = coset::CoseSign1::from_slice(&manifest.signature).expect("valid COSE_Sign1");
    let protected = sign1.protected.header;
    let pk_entry = protected
        .rest
        .iter()
        .find(|(label, _)| *label == coset::Label::Int(33)); // x5chain
    assert!(
        pk_entry.is_some(),
        "Public key must be in protected header (C2PA 2.4)"
    );

    if let Some((_, ciborium::Value::Bytes(pk_bytes))) = pk_entry {
        let key = test_signing_key();
        assert_eq!(
            pk_bytes.as_slice(),
            key.verifying_key().to_bytes().as_slice(),
            "Embedded key must match signer"
        );
    } else {
        panic!("Public key header value must be bytes");
    }
}

#[test]
fn standard_manifest_validation_passes() {
    let manifest = build_test_manifest();
    let result = validate_manifest(&manifest);
    assert!(
        result.is_valid(),
        "Valid manifest should pass: {:?}",
        result.errors
    );
}

#[test]
fn validation_catches_label_mismatch() {
    let mut manifest = build_test_manifest();
    manifest.manifest_label = "urn:wrong:label".to_string();
    let result = validate_manifest(&manifest);
    assert!(!result.is_valid());
    assert!(
        result.errors.iter().any(|e| e.contains("manifest label")),
        "Should catch label mismatch: {:?}",
        result.errors
    );
}

#[test]
fn validation_catches_hash_mismatch() {
    let mut manifest = build_test_manifest();
    if let Some(first_box) = manifest.assertion_boxes.first_mut() {
        if first_box.len() > 10 {
            first_box[10] ^= 0xFF;
        }
    }
    let result = validate_manifest(&manifest);
    assert!(!result.is_valid());
    assert!(
        result.errors.iter().any(|e| e.contains("hash mismatch")),
        "Should catch hash mismatch: {:?}",
        result.errors
    );
}

#[test]
fn validation_catches_missing_hard_binding() {
    let mut manifest = build_test_manifest();
    manifest
        .claim
        .created_assertions
        .retain(|a| !a.url.contains(ASSERTION_LABEL_HASH_DATA));
    manifest.assertion_boxes.remove(0); // hash.data is first
    let result = validate_manifest(&manifest);
    assert!(!result.is_valid());
    assert!(result.errors.iter().any(|e| e.contains("hard binding")));
}

#[test]
fn validation_catches_missing_actions() {
    let mut manifest = build_test_manifest();
    manifest
        .claim
        .created_assertions
        .retain(|a| !a.url.contains(ASSERTION_LABEL_ACTIONS));
    manifest.assertion_boxes.remove(1); // actions is second
    let result = validate_manifest(&manifest);
    assert!(!result.is_valid());
    assert!(result.errors.iter().any(|e| e.contains("actions")));
}

#[test]
fn encode_jumbf_roundtrip() {
    let manifest = build_test_manifest();
    let jumbf = encode_jumbf(&manifest).unwrap();

    assert!(jumbf.len() > 100);
    let info = verify_jumbf_structure(&jumbf).unwrap();
    assert!(info.child_boxes >= 2);
    assert_eq!(&jumbf[4..8], b"jumb");

    let box_len = u32::from_be_bytes([jumbf[0], jumbf[1], jumbf[2], jumbf[3]]) as usize;
    assert_eq!(box_len, jumbf.len());
}

#[test]
fn jumbf_contains_manifest_label() {
    let manifest = build_test_manifest();
    let jumbf = encode_jumbf(&manifest).unwrap();
    let jumbf_str = String::from_utf8_lossy(&jumbf);

    assert!(
        jumbf_str.contains(&manifest.manifest_label),
        "JUMBF must contain the manifest label as the box label"
    );
    assert!(
        jumbf_str.contains("c2pa.claim.v2"),
        "JUMBF must contain c2pa.claim.v2 label"
    );
}

#[test]
fn jumbf_contains_cbor_content() {
    let manifest = build_test_manifest();
    let jumbf = encode_jumbf(&manifest).unwrap();
    let has_cbor_box = jumbf.windows(4).any(|w| w == b"cbor");
    assert!(has_cbor_box, "JUMBF should contain cbor content boxes");
}

#[test]
fn jumbf_structure_validation_errors() {
    assert!(verify_jumbf_structure(&[]).is_err());
    assert!(verify_jumbf_structure(&[0; 4]).is_err());

    let mut bad = vec![0, 0, 0, 16];
    bad.extend_from_slice(b"xxxx");
    bad.extend_from_slice(&[0; 8]);
    assert!(verify_jumbf_structure(&bad).is_err());
}

#[test]
fn jumbf_extended_size_box() {
    // Build a valid extended-size JUMBF superbox:
    // compact_len=1, type="jumb", extended_len=<total>, then a jumd child.
    let jumd_content = [0u8; 17]; // 16-byte UUID + 1-byte toggles
    let jumd_len: u32 = 8 + jumd_content.len() as u32;
    let total: u64 = 16 + jumd_len as u64; // 16-byte extended header + child

    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_be_bytes()); // compact_len = 1
    buf.extend_from_slice(b"jumb");
    buf.extend_from_slice(&total.to_be_bytes()); // extended size
    buf.extend_from_slice(&jumd_len.to_be_bytes());
    buf.extend_from_slice(b"jumd");
    buf.extend_from_slice(&jumd_content);

    let info = verify_jumbf_structure(&buf).unwrap();
    assert_eq!(info.total_size, total as usize);
    assert_eq!(info.child_boxes, 1);
}

#[test]
fn unique_packet_id_produces_unique_manifest() {
    let mut p1 = test_evidence_packet();
    let mut p2 = test_evidence_packet();
    p1.packet_id = vec![0x01; 16];
    p2.packet_id = vec![0x02; 16];
    let key = test_signing_key();

    let m1 = C2paManifestBuilder::new(p1, b"ev1".to_vec(), [0xAA; 32])
        .build_manifest(&key)
        .unwrap();
    let m2 = C2paManifestBuilder::new(p2, b"ev2".to_vec(), [0xBB; 32])
        .build_manifest(&key)
        .unwrap();

    assert_ne!(m1.manifest_label, m2.manifest_label);
    assert_ne!(m1.claim.instance_id, m2.claim.instance_id);
}

#[test]
fn full_pipeline_build_validate_encode() {
    let packet = test_evidence_packet();
    let evidence_bytes = b"fake evidence cbor".to_vec();
    let doc_hash = [0xABu8; 32];
    let key = test_signing_key();

    let builder = C2paManifestBuilder::new(packet, evidence_bytes, doc_hash)
        .document_filename("test.txt")
        .title("Test Document");

    let manifest = builder.build_manifest(&key).unwrap();

    let validation = validate_manifest(&manifest);
    assert!(validation.is_valid(), "Errors: {:?}", validation.errors);

    let jumbf = encode_jumbf(&manifest).unwrap();
    assert!(jumbf.len() > 200);

    let info = verify_jumbf_structure(&jumbf).unwrap();
    assert_eq!(info.total_size, jumbf.len());
}

#[test]
fn test_manifest_with_format_produces_metadata_assertion() {
    let packet = test_evidence_packet();
    let key = test_signing_key();

    let manifest = C2paManifestBuilder::new(packet, b"ev".to_vec(), [0xAB; 32])
        .format("image/jpeg")
        .build_manifest(&key)
        .unwrap();

    // Format is now in a c2pa.metadata assertion, not the claim.
    let has_metadata = manifest
        .claim
        .created_assertions
        .iter()
        .any(|a| a.url.contains(ASSERTION_LABEL_METADATA));
    assert!(
        has_metadata,
        "Metadata assertion should be present when format is set"
    );
    let validation = validate_manifest(&manifest);
    assert!(validation.is_valid(), "Errors: {:?}", validation.errors);
}

#[test]
fn test_manifest_without_format_has_no_metadata_assertion() {
    let packet = test_evidence_packet();
    let key = test_signing_key();

    let manifest = C2paManifestBuilder::new(packet, b"ev".to_vec(), [0xAB; 32])
        .build_manifest(&key)
        .unwrap();

    let has_metadata = manifest
        .claim
        .created_assertions
        .iter()
        .any(|a| a.url.contains(ASSERTION_LABEL_METADATA));
    assert!(
        !has_metadata,
        "No metadata assertion when format is not set"
    );
    let validation = validate_manifest(&manifest);
    assert!(validation.is_valid(), "Errors: {:?}", validation.errors);
}

#[test]
fn test_asset_info_construction() {
    let info = AssetInfo {
        mime_type: "application/pdf".to_string(),
        file_extension: "pdf".to_string(),
    };
    assert_eq!(info.mime_type, "application/pdf");
    assert_eq!(info.file_extension, "pdf");

    let json = serde_json::to_string(&info).unwrap();
    let roundtrip: AssetInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip.mime_type, info.mime_type);
    assert_eq!(roundtrip.file_extension, info.file_extension);
}

#[test]
fn verify_manifest_signature_valid() {
    let manifest = build_test_manifest();
    let result = verify_manifest_signature(&manifest).expect("should parse and verify");
    assert!(result, "Signature on freshly built manifest should be valid");
}

#[test]
fn verify_manifest_with_known_key() {
    let manifest = build_test_manifest();
    let key = test_signing_key();
    let pk = key.verifying_key().to_bytes();
    let result = verify_manifest_with_key(&manifest, &pk).expect("should parse and verify");
    assert!(result, "Signature should verify against the signing key");
}

#[test]
fn verify_manifest_with_wrong_key_returns_false() {
    let manifest = build_test_manifest();
    let wrong_key = SigningKey::from_bytes(&[2u8; 32]);
    let wrong_pk = wrong_key.verifying_key().to_bytes();
    let result = verify_manifest_with_key(&manifest, &wrong_pk).expect("should parse");
    assert!(!result, "Signature should not verify against a different key");
}

#[test]
fn verify_manifest_tampered_signature_returns_false() {
    let mut manifest = build_test_manifest();
    let sign1 = coset::CoseSign1::from_slice(&manifest.signature).unwrap();
    let mut tampered = sign1;
    if let Some(byte) = tampered.signature.last_mut() {
        *byte ^= 0xFF;
    }
    manifest.signature = tampered.to_vec().unwrap();

    let result = verify_manifest_signature(&manifest).expect("should parse");
    assert!(!result, "Tampered signature should fail verification");
}

#[test]
fn verify_manifest_empty_signature_is_error() {
    let mut manifest = build_test_manifest();
    manifest.signature = Vec::new();
    let result = verify_manifest_signature(&manifest);
    assert!(result.is_err(), "Empty signature bytes should be a parse error");
}

#[test]
fn validate_manifest_includes_signature_check() {
    let manifest = build_test_manifest();
    let result = validate_manifest(&manifest);
    assert!(
        result.is_valid(),
        "Valid manifest with valid signature should pass: {:?}",
        result.errors
    );
    assert!(
        result.warnings.is_empty(),
        "No warnings expected: {:?}",
        result.warnings
    );
}

#[test]
fn validate_manifest_catches_bad_signature() {
    let mut manifest = build_test_manifest();
    let sign1 = coset::CoseSign1::from_slice(&manifest.signature).unwrap();
    let mut tampered = sign1;
    if let Some(byte) = tampered.signature.last_mut() {
        *byte ^= 0xFF;
    }
    manifest.signature = tampered.to_vec().unwrap();

    let result = validate_manifest(&manifest);
    assert!(!result.is_valid());
    assert!(
        result.errors.iter().any(|e| e.contains("signature verification failed")),
        "Should report signature failure: {:?}",
        result.errors
    );
}

#[test]
fn process_assertion_forensic_signals_json_roundtrip() {
    let packet = test_evidence_packet();
    let mut assertion = ProcessProofAssertion::from_evidence(&packet, b"test bytes");

    let signals = ForensicSignalScores {
        cognitive_load: 0.82,
        revision_topology: 0.65,
        error_ecology: 0.91,
        likelihood_model: 0.74,
        composition_mode: 0.88,
    };
    assertion.signal_scores = Some(signals);
    assertion.composition_mode = Some("pure_composition".to_string());
    assertion.writing_mode = Some("cognitive".to_string());

    let json = serde_json::to_string(&assertion).expect("serialize");
    let roundtrip: ProcessProofAssertion = serde_json::from_str(&json).expect("deserialize");

    let rt_signals = roundtrip.signal_scores.expect("signal_scores present");
    assert!((rt_signals.cognitive_load - 0.82).abs() < f64::EPSILON);
    assert!((rt_signals.revision_topology - 0.65).abs() < f64::EPSILON);
    assert!((rt_signals.error_ecology - 0.91).abs() < f64::EPSILON);
    assert!((rt_signals.likelihood_model - 0.74).abs() < f64::EPSILON);
    assert!((rt_signals.composition_mode - 0.88).abs() < f64::EPSILON);
    assert_eq!(roundtrip.composition_mode.as_deref(), Some("pure_composition"));
    assert_eq!(roundtrip.writing_mode.as_deref(), Some("cognitive"));

    // Verify camelCase serde field names in JSON output.
    assert!(json.contains("\"cognitiveLoad\""), "should use camelCase: {json}");
    assert!(json.contains("\"revisionTopology\""), "should use camelCase: {json}");
    assert!(json.contains("\"errorEcology\""), "should use camelCase: {json}");
    assert!(json.contains("\"likelihoodModel\""), "should use camelCase: {json}");
    assert!(json.contains("\"compositionMode\""), "should use camelCase: {json}");
    assert!(json.contains("\"writingMode\""), "should use camelCase: {json}");
    assert!(json.contains("\"signalScores\""), "should use camelCase: {json}");
}

#[test]
fn process_assertion_without_signals_omits_fields() {
    let packet = test_evidence_packet();
    let assertion = ProcessProofAssertion::from_evidence(&packet, b"test bytes");

    let json = serde_json::to_string(&assertion).expect("serialize");
    assert!(!json.contains("signalScores"), "None fields should be skipped: {json}");
    assert!(!json.contains("compositionMode"), "None fields should be skipped: {json}");
    assert!(!json.contains("writingMode"), "None fields should be skipped: {json}");
}

#[test]
fn manifest_with_forensic_signals_and_ai_disclosure() {
    let packet = test_evidence_packet();
    let key = test_signing_key();

    let signals = ForensicSignalScores {
        cognitive_load: 0.75,
        revision_topology: 0.60,
        error_ecology: 0.85,
        likelihood_model: 0.70,
        composition_mode: 0.90,
    };

    let disclosure = AiDisclosureAssertion {
        model_type: "none".to_string(),
        model_name: None,
        content_profile: Some(AiContentProfile {
            human_oversight_level: "human_validated".to_string(),
        }),
    };

    let manifest = C2paManifestBuilder::new(packet, b"evidence".to_vec(), [0xAB; 32])
        .forensic_signals(
            signals,
            Some("pure_composition".to_string()),
            Some("cognitive".to_string()),
        )
        .ai_disclosure(disclosure)
        .build_manifest(&key)
        .unwrap();

    // Forensic signals and AI disclosure each add an assertion box.
    // Core: hash_data + actions + cpoe = 3, plus ai_disclosure = 4.
    assert_eq!(
        manifest.assertion_boxes.len(),
        manifest.claim.created_assertions.len(),
        "assertion box count must match claim references"
    );
    assert!(
        manifest.assertion_boxes.len() >= 4,
        "Should have at least 4 assertions (3 core + ai_disclosure), got {}",
        manifest.assertion_boxes.len()
    );

    // Verify AI disclosure assertion is present.
    let has_ai = manifest
        .claim
        .created_assertions
        .iter()
        .any(|a| a.url.contains(ASSERTION_LABEL_AI_DISCLOSURE));
    assert!(has_ai, "AI disclosure assertion should be present");

    // Verify process-proof assertion contains forensic signals by finding and decoding it.
    let pp_idx = manifest
        .claim
        .created_assertions
        .iter()
        .position(|a| a.url.contains(ASSERTION_LABEL_PROCESS_PROOF))
        .expect("process-proof assertion should exist");
    let pp_payload = extract_assertion_content(&manifest.assertion_boxes[pp_idx], "cbor")
        .expect("process-proof must contain CBOR content box");
    let pp: ProcessProofAssertion =
        ciborium::from_reader(&pp_payload[..]).expect("process-proof CBOR must deserialize");
    assert!(pp.signal_scores.is_some(), "process-proof should contain signal scores");

    // Validate the full manifest structure.
    let result = validate_manifest(&manifest);
    assert!(result.is_valid(), "Manifest with signals should validate: {:?}", result.errors);
}

#[test]
fn test_hash_exclusion_range_correctness() {
    let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let exclusions = vec![HashExclusion { start: 2, length: 3 }];
    let result = hash_with_exclusions(&data, &exclusions);

    let mut expected_data = data;
    expected_data[2] = 0;
    expected_data[3] = 0;
    expected_data[4] = 0;
    let expected: [u8; 32] = sha2::Sha256::digest(expected_data).into();

    assert_eq!(result, expected, "Exclusion must zero bytes 2..5");

    let without: [u8; 32] = sha2::Sha256::digest(data).into();
    assert_ne!(result, without, "Excluded hash must differ from plain hash");
}

#[test]
fn test_pdf_embed_preserves_header() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
                xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n\
                trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF\n"
        .to_vec();
    let jumbf = b"test c2pa manifest for pdf";
    let embedded = embed_in_pdf(&pdf, jumbf).expect("embed_in_pdf must succeed");

    assert_eq!(&embedded[..5], b"%PDF-", "PDF header must be intact");
    assert_eq!(&embedded[..pdf.len()], &pdf[..], "original content preserved");
    let text = String::from_utf8_lossy(&embedded);
    assert!(text.contains("/C2PA"), "must contain /C2PA reference");
    assert!(text.contains("/Subtype /C2PA"), "stream must have /Subtype /C2PA");
    assert!(text.ends_with("%%EOF\n"), "must end with %%EOF");
}

#[test]
fn test_pdf_embed_rejects_non_pdf() {
    assert!(embed_in_pdf(b"not a pdf", b"jumbf").is_err());
}

#[test]
fn test_sidecar_path_for_text_documents() {
    assert_eq!(sidecar_path("/docs/essay.md"), "/docs/essay.md.c2pa");
    assert_eq!(sidecar_path("/docs/paper.txt"), "/docs/paper.txt.c2pa");
    assert_eq!(sidecar_path("/docs/thesis.rtf"), "/docs/thesis.rtf.c2pa");
}

#[test]
fn test_supports_embedding_text_formats() {
    assert!(supports_embedding("pdf"), "PDF supports embedding");
    assert!(!supports_embedding("txt"), "plain text uses sidecar");
    assert!(!supports_embedding("md"), "markdown uses sidecar");
    assert!(!supports_embedding("rtf"), "RTF uses sidecar");
    assert!(!supports_embedding("docx"), "DOCX uses sidecar");
}

#[test]
fn test_cert_chain_builder() {
    let packet = test_evidence_packet();
    let key = test_signing_key();
    let chain = vec![vec![0x30u8, 0x00], vec![0x30u8, 0x01]];

    let manifest = C2paManifestBuilder::new(packet, b"ev".to_vec(), [0xAB; 32])
        .cert_chain(chain)
        .build_manifest(&key)
        .unwrap();

    let result = validate_manifest(&manifest);
    assert!(result.is_valid(), "cert_chain manifest must validate: {:?}", result.errors);
}

#[test]
fn test_local_timestamp_assertion() {
    let packet = test_evidence_packet();
    let key = test_signing_key();
    let ts = LocalTimestampAssertion {
        wall_clock_ns: 1_710_000_000_000_000_000i64,
        vdf_proof_hash: Some([0xABu8; 32]),
        vdf_iterations: 100_000,
    };

    let manifest = C2paManifestBuilder::new(packet, b"ev".to_vec(), [0xAB; 32])
        .local_timestamp(ts)
        .build_manifest(&key)
        .unwrap();

    let has_ts = manifest
        .claim
        .created_assertions
        .iter()
        .any(|a| a.url.contains(super::ASSERTION_LABEL_LOCAL_TIMESTAMP));
    assert!(has_ts, "Local timestamp assertion must be in manifest");

    let result = validate_manifest(&manifest);
    assert!(result.is_valid(), "local_timestamp manifest must validate: {:?}", result.errors);
}

#[test]
fn test_trust_level_evaluation() {
    assert_eq!(evaluate_trust(&[]), TrustLevel::SelfSigned);
    assert_eq!(evaluate_trust(&[vec![0x30]]), TrustLevel::SelfSigned);
    assert_eq!(
        evaluate_trust(&[vec![0x30], vec![0x31]]),
        TrustLevel::CertChain
    );
    assert!(TrustLevel::TrustAnchored > TrustLevel::CertChain);
    assert!(TrustLevel::CertChain > TrustLevel::SelfSigned);
}

// ============================================================
// End-to-end C2PA verification: keystrokes → manifest → verify
// ============================================================

/// Extract the content payload from a JUMBF assertion superbox.
///
/// Walks the child boxes looking for one whose type matches `content_type`
/// ("json" or "cbor") and returns the payload bytes after the box header.
fn extract_assertion_content(box_bytes: &[u8], content_type: &str) -> Option<Vec<u8>> {
    if box_bytes.len() < 16 {
        return None;
    }
    let expected = content_type.as_bytes();
    let mut offset = 8; // skip outer jumb header
    while offset + 8 <= box_bytes.len() {
        let child_len =
            u32::from_be_bytes(box_bytes[offset..offset + 4].try_into().ok()?) as usize;
        if child_len < 8 || offset + child_len > box_bytes.len() {
            return None;
        }
        let child_type = &box_bytes[offset + 4..offset + 8];
        if child_type == expected {
            return Some(box_bytes[offset + 8..offset + child_len].to_vec());
        }
        offset += child_len;
    }
    None
}

/// Create a valid 1×1 white grayscale PNG for asset-level C2PA testing.
///
/// The zlib stream is a hand-computed stored block (no compression library needed).
/// CRC-32 checksums are computed via `crc32fast` (already a dev-dependency).
fn create_minimal_png() -> Vec<u8> {
    fn append_chunk(buf: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(chunk_type);
        buf.extend_from_slice(data);
        let mut crc_in = Vec::with_capacity(4 + data.len());
        crc_in.extend_from_slice(chunk_type);
        crc_in.extend_from_slice(data);
        buf.extend_from_slice(&crc32fast::hash(&crc_in).to_be_bytes());
    }

    let mut buf = Vec::with_capacity(128);
    // PNG signature
    buf.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

    // IHDR: 1×1, 8-bit grayscale
    #[rustfmt::skip]
    let ihdr: [u8; 13] = [
        0x00, 0x00, 0x00, 0x01, // width
        0x00, 0x00, 0x00, 0x01, // height
        0x08,                   // bit depth
        0x00,                   // color type (grayscale)
        0x00, 0x00, 0x00,       // compression, filter, interlace
    ];
    append_chunk(&mut buf, b"IHDR", &ihdr);

    // IDAT: zlib( deflate_stored([filter=0, pixel=0xFF]) )
    // CMF=0x08 CINFO=0, FLG=0x1D (fcheck makes (CMF*256+FLG)%31==0)
    // Stored block: bfinal=1 btype=00, len=2, nlen=0xFFFD, data=[0x00, 0xFF]
    // Adler-32 of [0x00, 0xFF]: s1=256, s2=258 → 0x01020100
    #[rustfmt::skip]
    let idat: [u8; 13] = [
        0x08, 0x1D,                     // zlib header
        0x01, 0x02, 0x00, 0xFD, 0xFF,   // stored block header
        0x00, 0xFF,                      // filter=None, pixel=white
        0x01, 0x02, 0x01, 0x00,         // Adler-32
    ];
    append_chunk(&mut buf, b"IDAT", &idat);

    // IEND
    append_chunk(&mut buf, b"IEND", &[]);
    buf
}

/// Full end-to-end test: simulated keystrokes → EvidencePacket → CBOR →
/// C2PA manifest → JUMBF → verify every layer.
///
/// Simulates a real authoring session with 3 checkpoints, each with
/// incrementally-growing content and realistic timing. Verifies:
///
///  1. Evidence packet CBOR roundtrip
///  2. X.509 certificate generation + roundtrip
///  3. C2PA manifest structural validation (§15.10.1.2)
///  4. COSE_Sign1 Ed25519 signature verification
///  5. x5chain contains DER X.509 certificate
///  6. JUMBF box structure (ISO 19566-5)
///  7. com.writerslogic.process-proof + evidence-chain assertions present
///  8. Forensic signal scores round-trip through the assertion
///  9. c2pa.hash.data assertion matches document SHA-256
/// 10. c2pa.actions.v2 records c2pa.created
/// 11. c2pa.external-reference links to evidence packet
/// 12. All assertion hashes in the claim match actual box contents
#[test]
fn end_to_end_keystrokes_to_verified_c2pa_manifest() {
    // === Phase 1: Simulate authoring session ===
    let document = b"Hello world. This is a test document written by a human author.";
    let doc_hash: [u8; 32] = sha2::Sha256::digest(document).into();

    let stage1 = b"Hello ";
    let stage2 = b"Hello world. ";
    let stage3: &[u8] = document;

    let base_time = 1_710_000_000_000u64; // 2024-03-09

    let packet = EvidencePacket {
        version: 1,
        profile_uri: crate::war::ear::CPOE_EVIDENCE_PROFILE.to_string(),
        packet_id: vec![0x42; 16],
        created: base_time,
        document: DocumentRef {
            content_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: doc_hash.to_vec(),
            },
            filename: Some("test_document.txt".to_string()),
            byte_length: document.len() as u64,
            char_count: document.len() as u64,
        },
        checkpoints: vec![
            Checkpoint {
                sequence: 0,
                checkpoint_id: vec![0x01; 16],
                timestamp: base_time + 5_000,
                content_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: sha2::Sha256::digest(stage1).to_vec(),
                },
                char_count: stage1.len() as u64,
                prev_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: vec![0u8; 32],
                },
                checkpoint_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: sha2::Sha256::digest(b"checkpoint-0-seal").to_vec(),
                },
                jitter_hash: Some(HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: sha2::Sha256::digest(b"jitter-entropy-0").to_vec(),
                }),
            },
            Checkpoint {
                sequence: 1,
                checkpoint_id: vec![0x02; 16],
                timestamp: base_time + 30_000,
                content_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: sha2::Sha256::digest(stage2).to_vec(),
                },
                char_count: stage2.len() as u64,
                prev_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: sha2::Sha256::digest(b"checkpoint-0-seal").to_vec(),
                },
                checkpoint_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: sha2::Sha256::digest(b"checkpoint-1-seal").to_vec(),
                },
                jitter_hash: Some(HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: sha2::Sha256::digest(b"jitter-entropy-1").to_vec(),
                }),
            },
            Checkpoint {
                sequence: 2,
                checkpoint_id: vec![0x03; 16],
                timestamp: base_time + 120_000,
                content_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: sha2::Sha256::digest(stage3).to_vec(),
                },
                char_count: stage3.len() as u64,
                prev_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: sha2::Sha256::digest(b"checkpoint-1-seal").to_vec(),
                },
                checkpoint_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: sha2::Sha256::digest(b"checkpoint-2-seal").to_vec(),
                },
                jitter_hash: Some(HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: sha2::Sha256::digest(b"jitter-entropy-2").to_vec(),
                }),
            },
        ],
        attestation_tier: Some(crate::rfc::AttestationTier::SoftwareOnly),
        baseline_verification: None,
    };

    // === Phase 2: CBOR encode evidence (with CPoE semantic tag) ===
    let evidence_bytes =
        crate::codec::encode_evidence(&packet).expect("CBOR encode evidence");
    assert!(evidence_bytes.len() > 100, "evidence CBOR should be non-trivial");

    let decoded: EvidencePacket =
        crate::codec::decode_evidence(&evidence_bytes).expect("CBOR decode evidence");
    assert_eq!(decoded.version, packet.version);
    assert_eq!(decoded.packet_id, packet.packet_id);
    assert_eq!(decoded.checkpoints.len(), 3);
    assert_eq!(decoded.document.content_hash.digest, doc_hash.to_vec());

    // === Phase 3: Generate Ed25519 signing key + X.509 certificate ===
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let cert_der =
        super::cert::generate_self_signed_cert(&signing_key).expect("generate self-signed cert");
    let extracted_pk =
        super::cert::extract_public_key_from_cert(&cert_der).expect("extract pubkey from cert");
    assert_eq!(extracted_pk, signing_key.verifying_key().to_bytes());

    // === Phase 4: Build C2PA manifest with forensic signals ===
    let signals = ForensicSignalScores {
        cognitive_load: 0.82,
        revision_topology: 0.65,
        error_ecology: 0.91,
        likelihood_model: 0.74,
        composition_mode: 0.88,
    };

    let manifest = C2paManifestBuilder::new(packet.clone(), evidence_bytes.clone(), doc_hash)
        .cert_der(cert_der.clone())
        .document_filename("test_document.txt")
        .title("Test Document — E2E Verification")
        .format("text/plain")
        .evidence_url("https://writersproof.com/evidence/test-packet")
        .forensic_signals(
            signals,
            Some("pure_composition".to_string()),
            Some("cognitive".to_string()),
        )
        .build_manifest(&signing_key)
        .expect("build C2PA manifest");

    // === Phase 5: Structural validation (§15.10.1.2) ===
    let validation = validate_manifest(&manifest);
    assert!(
        validation.is_valid(),
        "C2PA structural validation failed: {:?}",
        validation.errors
    );
    assert!(
        validation.warnings.is_empty(),
        "unexpected validation warnings: {:?}",
        validation.warnings
    );

    // === Phase 6: COSE_Sign1 signature verification ===
    assert!(
        verify_manifest_signature(&manifest).expect("sig verify must not error"),
        "COSE_Sign1 Ed25519 signature must verify via x5chain"
    );
    assert!(
        verify_manifest_with_key(&manifest, &signing_key.verifying_key().to_bytes())
            .expect("sig verify with key must not error"),
        "signature must verify against known signing key"
    );

    // === Phase 7: Verify x5chain contains X.509 certificate ===
    let sign1 = coset::CoseSign1::from_slice(&manifest.signature).expect("parse COSE_Sign1");
    let x5chain_value = sign1
        .protected
        .header
        .rest
        .iter()
        .find(|(label, _)| *label == coset::Label::Int(33))
        .map(|(_, v)| v)
        .expect("x5chain (label 33) must be in protected header");
    match x5chain_value {
        ciborium::Value::Bytes(bytes) => {
            assert!(
                bytes.len() > 32,
                "x5chain must hold a DER cert ({} bytes), not a raw key",
                bytes.len()
            );
            let pk = super::cert::extract_public_key_from_cert(bytes)
                .expect("x5chain cert must be a valid X.509 certificate");
            assert_eq!(pk, signing_key.verifying_key().to_bytes());
        }
        other => panic!("x5chain value must be Bytes, got {other:?}"),
    }

    // === Phase 8: JUMBF encode + structural verification ===
    let jumbf = encode_jumbf(&manifest).expect("JUMBF encode");
    assert!(
        jumbf.len() > 500,
        "JUMBF should be substantial ({} bytes)",
        jumbf.len()
    );

    let jumbf_info = verify_jumbf_structure(&jumbf).expect("JUMBF structure");
    assert_eq!(jumbf_info.total_size, jumbf.len());
    assert!(jumbf_info.child_boxes >= 2);

    let jumbf_text = String::from_utf8_lossy(&jumbf);
    assert!(jumbf_text.contains(&manifest.manifest_label));
    assert!(jumbf_text.contains("c2pa.claim.v2"));
    assert!(jumbf_text.contains("c2pa.assertions"));
    assert!(jumbf_text.contains("c2pa.signature"));

    // === Phase 9: Verify com.writerslogic.process-proof assertion ===
    let pp_idx = manifest
        .claim
        .created_assertions
        .iter()
        .position(|a| a.url.contains(ASSERTION_LABEL_PROCESS_PROOF))
        .expect("process-proof assertion must exist in claim");
    let cbor_payload = extract_assertion_content(&manifest.assertion_boxes[pp_idx], "cbor")
        .expect("process-proof must contain CBOR content box");
    let pop: ProcessProofAssertion =
        ciborium::from_reader(&cbor_payload[..]).expect("process-proof CBOR must deserialize");

    assert_eq!(pop.version, 2);
    assert_eq!(pop.evidence_id, hex::encode(vec![0x42u8; 16]));
    assert_eq!(
        pop.evidence_hash,
        hex::encode(sha2::Sha256::digest(&evidence_bytes))
    );

    // Forensic signals roundtrip.
    let fs = pop
        .signal_scores
        .expect("signal_scores must be present");
    assert!((fs.cognitive_load - 0.82).abs() < f64::EPSILON);
    assert!((fs.revision_topology - 0.65).abs() < f64::EPSILON);
    assert!((fs.error_ecology - 0.91).abs() < f64::EPSILON);
    assert!((fs.likelihood_model - 0.74).abs() < f64::EPSILON);
    assert!((fs.composition_mode - 0.88).abs() < f64::EPSILON);
    assert_eq!(pop.composition_mode.as_deref(), Some("pure_composition"));
    assert_eq!(pop.writing_mode.as_deref(), Some("cognitive"));

    // === Phase 9b: Verify com.writerslogic.evidence-chain assertion ===
    let ec_idx = manifest
        .claim
        .created_assertions
        .iter()
        .position(|a| a.url.contains(ASSERTION_LABEL_EVIDENCE_CHAIN))
        .expect("evidence-chain assertion must exist in claim");
    let ec_payload = extract_assertion_content(&manifest.assertion_boxes[ec_idx], "cbor")
        .expect("evidence-chain must contain CBOR content box");
    let chain: EvidenceChainAssertion =
        ciborium::from_reader(&ec_payload[..]).expect("evidence-chain CBOR must deserialize");

    assert_eq!(chain.checkpoint_count, 3);
    assert_eq!(chain.seals.len(), 3);
    for (i, seal) in chain.seals.iter().enumerate() {
        assert_eq!(seal.sequence, i as u64, "seal {i} sequence");
        assert_eq!(
            seal.seal_hash,
            hex::encode(&packet.checkpoints[i].checkpoint_hash.digest),
            "seal {i} hash must come from checkpoint_hash"
        );
        assert_eq!(seal.timestamp, packet.checkpoints[i].timestamp);
    }

    // === Phase 10: Verify c2pa.hash.data assertion ===
    let hash_idx = manifest
        .claim
        .created_assertions
        .iter()
        .position(|a| a.url.contains(ASSERTION_LABEL_HASH_DATA))
        .expect("c2pa.hash.data must exist");
    let hash_payload = extract_assertion_content(&manifest.assertion_boxes[hash_idx], "cbor")
        .expect("hash-data must contain CBOR box");
    let hash_data: HashDataAssertion =
        ciborium::from_reader(&hash_payload[..]).expect("hash-data CBOR");
    assert_eq!(hash_data.hash, doc_hash.to_vec(), "document hash mismatch");
    assert_eq!(hash_data.algorithm, "sha256");
    assert_eq!(hash_data.name, "test_document.txt");

    // === Phase 11: Verify c2pa.actions.v2 assertion ===
    let actions_idx = manifest
        .claim
        .created_assertions
        .iter()
        .position(|a| a.url.contains(ASSERTION_LABEL_ACTIONS))
        .expect("c2pa.actions.v2 must exist");
    let actions_payload =
        extract_assertion_content(&manifest.assertion_boxes[actions_idx], "cbor")
            .expect("actions must contain CBOR box");
    let actions: ActionsAssertion =
        ciborium::from_reader(&actions_payload[..]).expect("actions CBOR");
    assert_eq!(actions.actions.len(), 1);
    assert_eq!(actions.actions[0].action, "c2pa.created");
    assert!(actions.actions[0].when.is_some(), "created action must have timestamp");

    // === Phase 12: Verify c2pa.external-reference assertion ===
    let ext_idx = manifest
        .claim
        .created_assertions
        .iter()
        .position(|a| a.url.contains(ASSERTION_LABEL_EXTERNAL_REF))
        .expect("c2pa.external-reference must exist (evidence_url was set)");
    let ext_payload = extract_assertion_content(&manifest.assertion_boxes[ext_idx], "cbor")
        .expect("external-reference must contain CBOR box");
    let ext_ref: ExternalReferenceAssertion =
        ciborium::from_reader(&ext_payload[..]).expect("external-reference CBOR");
    assert_eq!(
        ext_ref.location.url,
        "https://writersproof.com/evidence/test-packet"
    );
    assert_eq!(ext_ref.location.alg, "sha256");
    assert_eq!(
        ext_ref.location.hash,
        sha2::Sha256::digest(&evidence_bytes).to_vec(),
        "external-reference hash must match evidence bytes"
    );

    // === Phase 13: Verify claim integrity ===
    assert!(manifest.claim.instance_id.starts_with("xmp:iid:"));
    assert!(manifest.claim.signature.contains("c2pa.signature"));
    assert!(manifest.claim.claim_generator_info.name.contains("CPoE"));

    // Every assertion hash in the claim must match the actual box contents.
    assert_eq!(
        manifest.claim.created_assertions.len(),
        manifest.assertion_boxes.len()
    );
    for (i, (ref_uri, box_bytes)) in manifest
        .claim
        .created_assertions
        .iter()
        .zip(manifest.assertion_boxes.iter())
        .enumerate()
    {
        let computed = sha2::Sha256::digest(&box_bytes[8..]);
        assert_eq!(
            ref_uri.hash,
            computed.to_vec(),
            "assertion {i} ({}) hash mismatch",
            ref_uri.url
        );
    }
}

/// Verify our JUMBF output with the c2pa-rs reference implementation.
///
/// Builds a C2PA manifest for a minimal PNG, writes it as a sidecar, and
/// feeds the result to `c2pa::Reader`. This catches any spec-compliance
/// issues that our own validator might miss.
#[test]
fn c2pa_rs_reader_parses_our_jumbf() {
    let png_bytes = create_minimal_png();
    let doc_hash: [u8; 32] = sha2::Sha256::digest(&png_bytes).into();
    let base_time = 1_710_000_000_000u64;

    let packet = EvidencePacket {
        version: 1,
        profile_uri: crate::war::ear::CPOE_EVIDENCE_PROFILE.to_string(),
        packet_id: vec![0x42; 16],
        created: base_time,
        document: DocumentRef {
            content_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: doc_hash.to_vec(),
            },
            filename: Some("test.png".to_string()),
            byte_length: png_bytes.len() as u64,
            char_count: 0,
        },
        checkpoints: vec![make_checkpoint(0, base_time + 5_000)],
        attestation_tier: Some(crate::rfc::AttestationTier::SoftwareOnly),
        baseline_verification: None,
    };

    let evidence_bytes =
        crate::codec::encode_evidence(&packet).unwrap();

    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let cert_der = super::cert::generate_self_signed_cert(&signing_key).unwrap();

    let jumbf = C2paManifestBuilder::new(packet, evidence_bytes, doc_hash)
        .cert_der(cert_der)
        .document_filename("test.png")
        .format("image/png")
        .build_jumbf(&signing_key)
        .unwrap();

    // ---- c2pa-rs verification via Reader + Context API (v0.84+) ----
    // Disable trust/timestamp verification (self-signed cert, no TSA) but keep
    // structural validation so c2pa-rs fully parses JUMBF, claim, and assertions.
    let context = c2pa_sdk::Context::new()
        .with_settings(c2pa_sdk::settings::Settings::new()
            .with_json(r#"{"verify":{"verify_after_reading":false}}"#)
            .unwrap())
        .unwrap();
    let reader = c2pa_sdk::Reader::from_context(context)
        .with_manifest_data_and_stream(&jumbf, "image/png", &mut std::io::Cursor::new(png_bytes.clone()))
        .unwrap_or_else(|e| {
            panic!(
                "c2pa-rs could not parse our JUMBF output: {e}\n\
                 JUMBF: {} bytes",
                jumbf.len()
            )
        });

    // Check JSON output from c2pa-rs Reader.
    let json_str = reader.json();
    let root: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");

    // c2pa-rs must detect our manifest label in the JUMBF store.
    assert_eq!(
        root["active_manifest"].as_str(),
        Some("urn:cpoe:42424242424242424242424242424242"),
        "c2pa-rs must detect our manifest label in the JUMBF"
    );

    // If manifests were fully loaded, verify assertion content.
    let manifests = root["manifests"].as_object().expect("manifests object");
    if !manifests.is_empty() {
        assert!(
            json_str.contains("com.writerslogic.process-proof"),
            "c2pa-rs manifest JSON must contain our process-proof assertion.\nJSON:\n{}",
            json_str
        );
        assert!(json_str.contains("c2pa.hash.data"));
        assert!(json_str.contains("c2pa.actions"));
    }

    // Verify no claim-level parsing errors (the critical fix).
    let has_claim_error = root["validation_status"]
        .as_array()
        .map(|statuses| {
            statuses.iter().any(|s| {
                s["code"].as_str().map_or(false, |c| c.contains("claim."))
            })
        })
        .unwrap_or(false);
    assert!(
        !has_claim_error,
        "c2pa-rs must parse our claim CBOR without claim-level errors.\nJSON:\n{}",
        json_str
    );
}

#[test]
fn generate_conformance_sample_c2pa() {
    use std::io::Write;
    let out_dir = match std::env::var("CPOE_CONFORMANCE_DIR") {
        Ok(d) => d,
        Err(_) => return, // skip unless env var set
    };

    let essay = include_bytes!("../../../../c2pa-conformance-sample/sample-essay.txt");
    let doc_hash: [u8; 32] = sha2::Sha256::digest(essay).into();

    let base_time = 1_717_000_000_000u64;
    let packet = EvidencePacket {
        version: 1,
        profile_uri: crate::war::ear::CPOE_EVIDENCE_PROFILE.to_string(),
        packet_id: vec![0x42; 16],
        created: base_time,
        document: DocumentRef {
            content_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: doc_hash.to_vec(),
            },
            filename: Some("sample-essay.txt".to_string()),
            byte_length: essay.len() as u64,
            char_count: essay.len() as u64,
        },
        checkpoints: vec![
            make_checkpoint(0, base_time + 60_000),
            make_checkpoint(1, base_time + 180_000),
            make_checkpoint(2, base_time + 300_000),
        ],
        attestation_tier: Some(crate::rfc::AttestationTier::SoftwareOnly),
        baseline_verification: None,
    };

    let evidence_bytes = crate::codec::encode_evidence(&packet).unwrap();
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let cert_der = super::cert::generate_self_signed_cert(&signing_key).unwrap();

    let jumbf = C2paManifestBuilder::new(packet, evidence_bytes, doc_hash)
        .cert_der(cert_der)
        .document_filename("sample-essay.txt")
        .format("text/plain")
        .title("The Role of Cryptographic Attestation in Modern Publishing")
        .evidence_url("https://verify.writersproof.com/evidence/conformance-sample")
        .build_jumbf(&signing_key)
        .unwrap();

    // Build reverse sidecar (JUMBF + embedded asset)
    let container = super::container::build_reverse_sidecar(
        &jumbf, essay, "sample-essay.txt", "text/plain"
    ).unwrap();

    let sidecar_path = format!("{}/sample-essay.c2pa", out_dir);
    let jumbf_path = format!("{}/sample-essay.jumbf", out_dir);

    std::fs::write(&sidecar_path, &container).unwrap();
    std::fs::write(&jumbf_path, &jumbf).unwrap();
    eprintln!("Wrote {} (container: {} bytes, JUMBF: {} bytes)", sidecar_path, container.len(), jumbf.len());
}
