// SPDX-License-Identifier: Apache-2.0
use authorproof_protocol::crypto::hash_sha256;
use authorproof_protocol::evidence::{Builder, Verifier};
use authorproof_protocol::rfc::DocumentRef;
use ed25519_dalek::SigningKey;
use rand::RngCore;

#[test]
fn test_cpoe_full_roundtrip() {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let doc_content = b"Integration test document";
    let document = DocumentRef {
        content_hash: hash_sha256(doc_content),
        filename: Some("test.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64,
    };

    let mut builder = Builder::new(document, Box::new(signing_key))
        .unwrap()
        .with_min_entropy_bits(1);
    builder
        .add_checkpoint(b"Checkpoint 1", 12)
        .expect("Add checkpoint failed");
    builder
        .add_checkpoint(b"Checkpoint 2", 12)
        .expect("Add checkpoint failed");
    builder
        .add_checkpoint(b"Checkpoint 3", 12)
        .expect("Add checkpoint failed");

    let signed_evidence = builder.finalize().expect("Finalize failed");

    let verifier = Verifier::new(verifying_key);
    let result = verifier
        .verify(&signed_evidence)
        .expect("Verification failed");

    assert_eq!(result.checkpoints.len(), 3);
    assert_eq!(result.checkpoints[0].sequence, 0);
    assert_eq!(result.checkpoints[1].sequence, 1);
    assert_eq!(result.checkpoints[2].sequence, 2);
}

#[test]
fn test_cpoe_tamper_detection() {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let doc_content = b"Tamper test document";
    let document = DocumentRef {
        content_hash: hash_sha256(doc_content),
        filename: Some("test.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64,
    };

    let mut builder = Builder::new(document, Box::new(signing_key))
        .unwrap()
        .with_min_entropy_bits(1);
    builder.add_checkpoint(b"Safe checkpoint 1", 5).unwrap();
    builder.add_checkpoint(b"Safe checkpoint 2", 5).unwrap();
    builder.add_checkpoint(b"Safe checkpoint 3", 5).unwrap();
    let signed_evidence = builder.finalize().unwrap();

    // Tamper with the data (it's COSE signed, so any change should fail verification)
    let mut tampered_evidence = signed_evidence.clone();
    if let Some(byte) = tampered_evidence.last_mut() {
        *byte ^= 0xFF;
    }

    let verifier = Verifier::new(verifying_key);
    assert!(verifier.verify(&tampered_evidence).is_err());
}

#[test]
fn test_cpoe_playback_attack_detection() {
    use authorproof_protocol::codec::encode_evidence;
    use authorproof_protocol::crypto::sign_evidence_cose;
    use authorproof_protocol::rfc::{AttestationTier, Checkpoint, EvidencePacket};
    extern crate ciborium;

    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let doc_content = b"Playback attack document";
    let doc_hash = hash_sha256(doc_content);
    let packet_id = vec![1u8; 16];
    let created = 1000u64;

    let document = DocumentRef {
        content_hash: doc_hash,
        filename: Some("attack.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64,
    };

    let mut doc_cbor = Vec::new();
    ciborium::into_writer(&document, &mut doc_cbor).expect("CBOR encode document-ref");
    let mut last_hash = hash_sha256(&doc_cbor);

    let mut checkpoints = Vec::new();
    for i in 0..4u64 {
        let content_hash = hash_sha256(format!("Checkpoint {}", i).as_bytes());
        let checkpoint_hash = authorproof_protocol::crypto::compute_causality_lock(
            &packet_id,
            &last_hash.digest,
            &content_hash.digest,
        )
        .expect("compute causality lock");

        checkpoints.push(Checkpoint {
            sequence: i,
            checkpoint_id: vec![i as u8; 16],
            timestamp: created + (i + 1) * 1000,
            content_hash,
            char_count: 10,
            prev_hash: last_hash.clone(),
            checkpoint_hash: checkpoint_hash.clone(),
            jitter_hash: None,
        });
        last_hash = checkpoint_hash;
    }

    let packet = EvidencePacket {
        version: 1,
        profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
        packet_id,
        created,
        document,
        checkpoints,
        attestation_tier: Some(AttestationTier::HardwareBound),
        baseline_verification: None,
    };

    let encoded = encode_evidence(&packet).unwrap();
    let signer: Box<dyn authorproof_protocol::crypto::EvidenceSigner> = Box::new(signing_key);
    let signed = sign_evidence_cose(&encoded, signer.as_ref()).unwrap();

    let verifier = Verifier::new(verifying_key);
    let packet = verifier
        .verify(&signed)
        .expect("Verifier should pass structural checks");

    // Adversarial collapse detection is handled by the forensics engine
    let timestamps: Vec<u64> = std::iter::once(packet.created)
        .chain(packet.checkpoints.iter().map(|cp| cp.timestamp))
        .collect();
    let engine =
        authorproof_protocol::forensics::ForensicsEngine::from_timestamps(&timestamps, true);
    let analysis = engine.analyze();
    assert_eq!(
        analysis.verdict,
        authorproof_protocol::forensics::ForensicVerdict::V4LikelySynthetic,
        "Forensics engine should detect uniform timing as synthetic"
    );
}

#[test]
#[ignore = "CSR generation not available with x509-cert 0.2; tracked separately for when the dependency is upgraded"]
fn test_identity_csr_generation() {
    use authorproof_protocol::identity::IdentityManager;

    let id_manager = IdentityManager::generate();
    let csr_der = id_manager
        .generate_csr("CN=CPoEDevice,O=CPoE,C=US")
        .expect("CSR generation failed");

    assert!(!csr_der.is_empty());

    // Basic DER check: starts with a sequence tag (0x30)
    assert_eq!(csr_der[0], 0x30);
}

#[test]
fn test_verify_evidence_cose_rejects_wrong_key() {
    use authorproof_protocol::crypto::verify_evidence_cose;

    let mut key_a_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_a_bytes);
    let signing_key_a = SigningKey::from_bytes(&key_a_bytes);

    let mut key_b_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_b_bytes);
    let signing_key_b = SigningKey::from_bytes(&key_b_bytes);
    let verifying_key_b = signing_key_b.verifying_key();

    let doc_content = b"Wrong key test document";
    let document = DocumentRef {
        content_hash: hash_sha256(doc_content),
        filename: Some("wrong_key.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64,
    };

    let mut builder = Builder::new(document, Box::new(signing_key_a))
        .unwrap()
        .with_min_entropy_bits(1);
    builder.add_checkpoint(b"checkpoint 1", 10).unwrap();
    builder.add_checkpoint(b"checkpoint 2", 10).unwrap();
    builder.add_checkpoint(b"checkpoint 3", 10).unwrap();
    let signed_evidence = builder.finalize().unwrap();

    let result = verify_evidence_cose(&signed_evidence, &verifying_key_b);
    assert!(result.is_err());
    match result {
        Err(authorproof_protocol::error::Error::Crypto(_)) => {}
        other => panic!("Expected Error::Crypto, got {:?}", other),
    }
}

#[test]
fn test_verify_evidence_cose_rejects_truncated_cose() {
    use authorproof_protocol::crypto::verify_evidence_cose;

    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let truncated = [0u8; 10];
    let result = verify_evidence_cose(&truncated, &verifying_key);
    assert!(result.is_err());
    match result {
        Err(authorproof_protocol::error::Error::Crypto(_)) => {}
        other => panic!("Expected Error::Crypto, got {:?}", other),
    }
}

#[test]
fn test_compute_causality_lock_v2_differs_from_v1() {
    use authorproof_protocol::crypto::{compute_causality_lock, compute_causality_lock_v2};

    let key = b"test-key-material";
    let prev_hash = [0xAA; 32];
    let current_hash = [0xBB; 32];

    let v1 = compute_causality_lock(key, &prev_hash, &current_hash).unwrap();
    let v2 = compute_causality_lock_v2(key, &prev_hash, &current_hash, &[]).unwrap();

    assert_ne!(
        v1.digest, v2.digest,
        "v1 and v2 with empty phys_entropy should differ due to domain separator"
    );
}

#[test]
fn test_verifier_rejects_wrong_profile_uri() {
    use authorproof_protocol::codec::{decode_evidence, encode_evidence};
    use authorproof_protocol::crypto::{sign_evidence_cose, verify_evidence_cose};

    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let doc_content = b"Profile URI test document";
    let document = DocumentRef {
        content_hash: hash_sha256(doc_content),
        filename: Some("profile.txt".to_string()),
        byte_length: doc_content.len() as u64,
        char_count: doc_content.len() as u64,
    };

    let mut builder = Builder::new(document, Box::new(signing_key.clone()))
        .unwrap()
        .with_min_entropy_bits(1);
    builder.add_checkpoint(b"checkpoint 1", 10).unwrap();
    builder.add_checkpoint(b"checkpoint 2", 10).unwrap();
    builder.add_checkpoint(b"checkpoint 3", 10).unwrap();
    let signed_evidence = builder.finalize().unwrap();

    // Decode the COSE envelope to get the payload
    let payload = verify_evidence_cose(&signed_evidence, &verifying_key).unwrap();
    let mut packet = decode_evidence(&payload).unwrap();

    // Tamper with the profile_uri
    packet.profile_uri = "urn:fake:wrong:profile".to_string();

    // Re-encode and re-sign with the same key
    let re_encoded = encode_evidence(&packet).unwrap();
    let signer: Box<dyn authorproof_protocol::crypto::EvidenceSigner> = Box::new(signing_key);
    let re_signed = sign_evidence_cose(&re_encoded, signer.as_ref()).unwrap();

    let verifier = Verifier::new(verifying_key);
    let result = verifier.verify(&re_signed);
    assert!(result.is_err());
    match result {
        Err(authorproof_protocol::error::Error::Validation(msg)) => {
            assert!(
                msg.contains("profile_uri"),
                "Expected profile_uri in error message, got: {}",
                msg
            );
        }
        other => panic!(
            "Expected Error::Validation about profile_uri, got {:?}",
            other
        ),
    }
}

#[test]
fn test_decode_evidence_rejects_truncated_cbor() {
    use authorproof_protocol::codec::decode_evidence;

    // Partial CPoE tag bytes - not valid CBOR
    let truncated = [0x43, 0x50, 0x4F];
    let result = decode_evidence(&truncated);
    assert!(
        result.is_err(),
        "decode_evidence should reject truncated CBOR"
    );
}
