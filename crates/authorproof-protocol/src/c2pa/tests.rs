// SPDX-License-Identifier: Apache-2.0

use super::embed::{embed_in_pdf, hash_with_exclusions, sidecar_path, supports_embedding};
use super::trust::{evaluate_trust, TrustLevel};
use super::validation::{verify_manifest_signature, verify_manifest_with_key};
use super::*;
use crate::rfc::{Checkpoint, DocumentRef, EvidencePacket, HashAlgorithm, HashValue};
use coset::CborSerializable;
use ed25519_dalek::SigningKey;
use sha2::Digest;

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
    let assertion = ProcessAssertion::from_evidence(&packet, evidence_bytes);

    assert_eq!(assertion.label, ASSERTION_LABEL_CPOE);
    assert_eq!(assertion.version, 1);
    assert_eq!(assertion.jitter_seals.len(), 3);
    assert!(!assertion.evidence_hash.is_empty());
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
        !manifest.claim.claim_generator_info.is_empty(),
        "claim_generator_info required"
    );
    assert!(
        !manifest.claim.claim_generator_info[0].name.is_empty(),
        "first entry must have name"
    );
    // 3 core assertions + 1 metadata assertion (title was set in build_test_manifest)
    assert_eq!(manifest.claim.created_assertions.len(), 4);
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
    let mut assertion = ProcessAssertion::from_evidence(&packet, b"test bytes");

    let signals = ForensicSignalScores {
        cognitive_load: 0.82,
        revision_topology: 0.65,
        error_ecology: 0.91,
        likelihood_model: 0.74,
        composition_mode: 0.88,
    };
    assertion.forensic_signals = Some(signals);
    assertion.composition_mode = Some("pure_composition".to_string());
    assertion.writing_mode = Some("cognitive".to_string());

    let json = serde_json::to_string(&assertion).expect("serialize");
    let roundtrip: ProcessAssertion = serde_json::from_str(&json).expect("deserialize");

    let rt_signals = roundtrip.forensic_signals.expect("forensic_signals present");
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
    assert!(json.contains("\"forensicSignals\""), "should use camelCase: {json}");
}

#[test]
fn process_assertion_without_signals_omits_fields() {
    let packet = test_evidence_packet();
    let assertion = ProcessAssertion::from_evidence(&packet, b"test bytes");

    let json = serde_json::to_string(&assertion).expect("serialize");
    assert!(!json.contains("forensicSignals"), "None fields should be skipped: {json}");
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

    // Verify CPoE assertion contains forensic signals by finding and decoding it.
    let cpoe_idx = manifest
        .claim
        .created_assertions
        .iter()
        .position(|a| a.url.contains(ASSERTION_LABEL_CPOE))
        .expect("CPoE assertion should exist");
    let cpoe_box = &manifest.assertion_boxes[cpoe_idx];
    // The box has an 8-byte jumb header, then a jumd child, then a json child.
    // Search for our signal value in the raw bytes as a sanity check.
    let box_str = String::from_utf8_lossy(cpoe_box);
    assert!(
        box_str.contains("cognitiveLoad"),
        "CPoE assertion box should contain forensic signals"
    );

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
