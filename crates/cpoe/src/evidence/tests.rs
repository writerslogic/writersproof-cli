// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::checkpoint;
use crate::declaration;
use crate::evidence::*;
use crate::presence;
use crate::tpm;
use crate::vdf;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

fn temp_document_path() -> PathBuf {
    let name = format!("writerslogic-evidence-test-{}.txt", uuid::Uuid::new_v4());
    std::env::temp_dir().join(name)
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn create_test_chain(dir: &TempDir) -> (checkpoint::Chain, PathBuf) {
    let path = dir.path().join("test_document.txt");
    fs::write(&path, b"test content").expect("write doc");
    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
    chain.commit(None).expect("commit");
    (chain, path)
}

fn create_test_declaration(chain: &checkpoint::Chain) -> declaration::Declaration {
    let latest = chain.latest().expect("latest");
    let signing_key = test_signing_key();
    declaration::no_ai_declaration(
        latest.content_hash,
        latest.hash,
        "Test Doc",
        "I wrote this.",
    )
    .sign(&signing_key)
    .expect("sign declaration")
}

#[test]
fn test_packet_roundtrip_and_verify() {
    let path = temp_document_path();
    fs::write(&path, b"hello writerslogic").expect("write temp doc");

    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
    chain.commit(None).expect("commit");

    let latest = chain.latest().expect("latest");
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let decl = declaration::no_ai_declaration(
        latest.content_hash,
        latest.hash,
        "Test Doc",
        "I wrote this.",
    )
    .sign(&signing_key)
    .expect("sign declaration");

    let packet = Builder::new("Test Doc", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build packet");

    packet
        .verify_self_signed(chain.metadata.vdf_params)
        .expect("verify packet");

    let encoded = packet.encode().expect("encode");
    let decoded = Packet::decode(&encoded).expect("decode");
    assert_eq!(decoded.document.title, packet.document.title);
    assert_eq!(decoded.checkpoints.len(), packet.checkpoints.len());
    assert_eq!(decoded.chain_hash, packet.chain_hash);

    let _ = fs::remove_file(&path);
}

#[test]
fn test_builder_requires_declaration() {
    let path = temp_document_path();
    fs::write(&path, b"hello writerslogic").expect("write temp doc");

    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
    chain.commit(None).expect("commit");

    let err = Builder::new("Test Doc", &chain).build().unwrap_err();
    assert!(err.to_string().contains("declaration is required"));

    let _ = fs::remove_file(&path);
}

#[test]
fn test_packet_with_multiple_checkpoints() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("doc.txt");
    fs::write(&path, b"initial").expect("write");

    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    fs::write(&path, b"final").expect("final");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 2");

    let decl = create_test_declaration(&chain);
    let packet = Builder::new("Multi Checkpoint", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    assert_eq!(packet.checkpoints.len(), 3);
    packet
        .verify_self_signed(chain.metadata.vdf_params)
        .expect("verify");
}

#[test]
fn test_packet_verify_chain_hash_mismatch() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    packet.chain_hash = "wrong_hash".to_string();

    let err = packet
        .verify_self_signed(chain.metadata.vdf_params)
        .unwrap_err();
    assert!(err.to_string().contains("chain hash mismatch"));
}

#[test]
fn test_packet_verify_document_hash_mismatch() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    packet.document.final_hash = "wrong_hash".to_string();

    let err = packet
        .verify_self_signed(chain.metadata.vdf_params)
        .unwrap_err();
    assert!(err.to_string().contains("document final hash mismatch"));
}

#[test]
fn test_packet_verify_document_size_mismatch() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    packet.document.final_size = 9999;

    let err = packet
        .verify_self_signed(chain.metadata.vdf_params)
        .unwrap_err();
    assert!(err.to_string().contains("document final size mismatch"));
}

#[test]
fn test_packet_verify_broken_chain_link() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("doc.txt");
    fs::write(&path, b"initial").expect("write");

    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    let decl = create_test_declaration(&chain);
    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    packet.checkpoints[1].previous_hash = "wrong".to_string();

    let err = packet
        .verify_self_signed(chain.metadata.vdf_params)
        .unwrap_err();
    assert!(err.to_string().contains("broken chain link"));
}

#[test]
fn test_packet_verify_invalid_declaration() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let mut decl = create_test_declaration(&chain);

    decl.signature[0] ^= 0xFF;

    let err = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("declaration signature invalid"));
}

#[test]
fn test_packet_total_elapsed_time() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("doc.txt");
    fs::write(&path, b"initial").expect("write");

    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(50))
        .expect("commit 1");

    let decl = create_test_declaration(&chain);
    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let elapsed = packet.total_elapsed_time();
    assert!(elapsed > Duration::from_secs(0));
}

#[test]
fn test_packet_hash() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let hash = packet.hash().expect("hash");
    assert_ne!(hash, [0u8; 32]);

    let hash2 = packet.hash().expect("hash");
    assert_eq!(hash, hash2);
}

#[test]
fn test_builder_with_presence() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut verifier = presence::Verifier::new(presence::Config {
        enabled_challenges: vec![presence::ChallengeType::TypeWord],
        challenge_interval: Duration::from_secs(1),
        interval_variance: 0.0,
        response_window: Duration::from_secs(60),
    })
    .unwrap();
    verifier.start_session().expect("start");
    let challenge = verifier.issue_challenge().expect("issue");
    let word = challenge
        .prompt
        .strip_prefix("Type the word: ")
        .expect("prompt");
    verifier
        .respond_to_challenge(&challenge.id, word)
        .expect("respond");
    let session = verifier.end_session().expect("end");

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .with_presence(&[session])
        .build()
        .expect("build");

    assert!(packet.presence.is_some());
}

#[test]
fn test_builder_with_empty_presence() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .with_presence(&[])
        .build()
        .expect("build");

    assert!(packet.presence.is_none());
}

#[test]
fn test_builder_with_contexts() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let contexts = vec![ContextPeriod {
        period_type: ContextPeriodType::Focused,
        note: Some("writing session".to_string()),
        start_time: Utc::now(),
        end_time: Utc::now(),
    }];

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .with_contexts(contexts)
        .build()
        .expect("build");

    assert_eq!(packet.contexts.len(), 1);
}

#[test]
fn test_builder_with_behavioral() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let regions = vec![EditRegion {
        start_pct: 0.0,
        end_pct: 50.0,
        delta_sign: 1,
        byte_count: 100,
    }];

    let metrics = ForensicMetrics {
        monotonic_append_ratio: 0.8,
        edit_entropy: 0.5,
        median_interval_seconds: 2.0,
        positive_negative_ratio: 0.9,
        deletion_clustering: 0.1,
        assessment: Some("normal".to_string()),
        anomaly_count: Some(0),
    };

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .with_behavioral(regions, Some(metrics))
        .build()
        .expect("build");

    assert!(packet.behavioral.is_some());
}

#[test]
fn test_builder_with_provenance() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let prov = RecordProvenance {
        device_id: "test-device".to_string(),
        signing_pubkey: "abc123".to_string(),
        key_source: "software".to_string(),
        hostname: "testhost".to_string(),
        os: "linux".to_string(),
        os_version: Some("5.0".to_string()),
        architecture: "x86_64".to_string(),
        session_id: "session-1".to_string(),
        session_started: Utc::now(),
        input_devices: vec![],
        access_control: None,
    };

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .with_provenance(prov)
        .build()
        .expect("build");

    assert!(packet.provenance.is_some());
    assert_eq!(
        packet.provenance.as_ref().expect("provenance").device_id,
        "test-device"
    );
}

#[test]
fn test_claims_generated() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    assert!(packet
        .claims
        .iter()
        .any(|c| matches!(c.claim_type, ClaimType::ChainIntegrity)));
    assert!(packet
        .claims
        .iter()
        .any(|c| matches!(c.claim_type, ClaimType::ProcessDeclared)));
}

#[test]
fn test_limitations_generated() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    assert!(packet
        .limitations
        .iter()
        .any(|l| l.contains("cognitive origin")));
}

#[test]
fn test_empty_chain() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("empty.txt");
    fs::write(&path, b"content").expect("write");

    let chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
    let signing_key = test_signing_key();
    let decl = declaration::no_ai_declaration([1u8; 32], [2u8; 32], "Empty Chain", "Test")
        .sign(&signing_key)
        .expect("sign");

    let packet = Builder::new("Empty", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    assert!(packet.checkpoints.is_empty());
    assert!(packet.chain_hash.is_empty());
}

#[test]
fn test_packet_verify_first_checkpoint_nonzero_previous() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    packet.checkpoints[0].previous_hash = "not-valid-hex!".to_string();

    let err = packet
        .verify_self_signed(chain.metadata.vdf_params)
        .unwrap_err();
    assert!(err.to_string().contains("invalid genesis previous hash"));
}

#[test]
fn test_ai_declaration_claims() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("doc.txt");
    fs::write(&path, b"content").expect("write");

    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
    chain.commit(None).expect("commit");

    let latest = chain.latest().expect("latest");
    let signing_key = test_signing_key();
    let decl =
        declaration::ai_assisted_declaration(latest.content_hash, latest.hash, "AI Assisted")
            .add_modality(declaration::ModalityType::Keyboard, 80.0, None)
            .add_modality(declaration::ModalityType::Paste, 20.0, None)
            .add_ai_tool(
                "ChatGPT",
                None,
                declaration::AiPurpose::Feedback,
                None,
                declaration::AiExtent::Moderate,
            )
            .with_statement("Used AI for feedback")
            .sign(&signing_key)
            .expect("sign");

    let packet = Builder::new("AI Doc", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    assert!(packet
        .limitations
        .iter()
        .any(|l| l.contains("AI tool usage")));
}

#[test]
fn test_document_info() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("doc.txt");
    fs::write(&path, b"hello world").expect("write");

    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
    chain.commit(None).expect("commit");
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test Doc", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    assert_eq!(packet.document.title, "Test Doc");
    assert!(packet.document.path.contains("doc.txt"));
    assert!(!packet.document.final_hash.is_empty());
    assert_eq!(packet.document.final_size, 11);
}

#[test]
fn test_checkpoint_proof_fields() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("doc.txt");
    fs::write(&path, b"initial").expect("write");

    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
    chain
        .commit_with_vdf_duration(Some("first commit".to_string()), Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    let decl = create_test_declaration(&chain);
    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let cp0 = &packet.checkpoints[0];
    assert_eq!(cp0.ordinal, 0);
    assert_eq!(cp0.message, Some("first commit".to_string()));
    assert!(!cp0.content_hash.is_empty());
    assert!(!cp0.hash.is_empty());

    let cp1 = &packet.checkpoints[1];
    assert_eq!(cp1.ordinal, 1);
    assert!(cp1.vdf_input.is_some());
    assert!(cp1.vdf_output.is_some());
    assert!(cp1.vdf_iterations.is_some());
}

#[test]
fn test_external_anchors() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let ots = vec![OtsProof {
        chain_hash: "abc123".to_string(),
        proof: "base64proof".to_string(),
        status: "pending".to_string(),
        block_height: None,
        block_time: None,
    }];

    let rfc = vec![Rfc3161Proof {
        chain_hash: "abc123".to_string(),
        tsa_url: "https://tsa.example.com".to_string(),
        response: "base64response".to_string(),
        timestamp: Utc::now(),
    }];

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .with_external_anchors(ots, rfc)
        .build()
        .expect("build");

    assert!(packet.external.is_some());
    let external = packet.external.expect("external anchors");
    assert_eq!(external.opentimestamps.len(), 1);
    assert_eq!(external.rfc3161.len(), 1);
}

#[test]
fn test_version() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    assert_eq!(packet.version, 1);
}

#[test]
fn test_vdf_params_preserved() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    assert_eq!(
        packet.vdf_params.iterations_per_second,
        chain.metadata.vdf_params.iterations_per_second
    );
    assert_eq!(
        packet.vdf_params.min_iterations,
        chain.metadata.vdf_params.min_iterations
    );
    assert_eq!(
        packet.vdf_params.max_iterations,
        chain.metadata.vdf_params.max_iterations
    );
}

#[test]
fn test_hardware_evidence_with_attestation_nonce() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let nonce: [u8; 32] = [0x42u8; 32];

    let binding = tpm::Binding {
        version: 1,
        provider_type: "software".to_string(),
        device_id: "test-device".to_string(),
        timestamp: Utc::now(),
        attested_hash: vec![1, 2, 3],
        signature: vec![4, 5, 6],
        public_key: vec![7, 8, 9],
        monotonic_counter: None,
        safe_clock: Some(true),
        attestation: None,
    };

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .with_hardware(vec![binding], "test-device".to_string(), Some(nonce))
        .build()
        .expect("build");

    assert!(packet.hardware.is_some());
    let hw = packet.hardware.as_ref().expect("hardware evidence");
    assert_eq!(hw.device_id, "test-device");
    assert!(hw.attestation_nonce.is_some());
    assert_eq!(hw.attestation_nonce.expect("attestation nonce"), nonce);

    assert!(packet.hardware.is_some());
}

#[test]
fn test_hardware_evidence_without_nonce() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let binding = tpm::Binding {
        version: 1,
        provider_type: "software".to_string(),
        device_id: "test-device".to_string(),
        timestamp: Utc::now(),
        attested_hash: vec![1, 2, 3],
        signature: vec![4, 5, 6],
        public_key: vec![7, 8, 9],
        monotonic_counter: None,
        safe_clock: Some(true),
        attestation: None,
    };

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .with_hardware(vec![binding], "test-device".to_string(), None)
        .build()
        .expect("build");

    assert!(packet.hardware.is_some());
    let hw = packet.hardware.as_ref().expect("hardware evidence");
    assert!(hw.attestation_nonce.is_none());
}

#[test]
fn test_hardware_evidence_nonce_serialization() {
    let nonce: [u8; 32] = [0xABu8; 32];
    let hw = HardwareEvidence {
        bindings: vec![],
        device_id: "test".to_string(),
        attestation_nonce: Some(nonce),
    };

    let json = serde_json::to_string(&hw).expect("serialize");
    assert!(json.contains(&hex::encode(nonce)));

    let decoded: HardwareEvidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.attestation_nonce, Some(nonce));
}

#[test]
fn test_hardware_evidence_nonce_none_serialization() {
    let hw = HardwareEvidence {
        bindings: vec![],
        device_id: "test".to_string(),
        attestation_nonce: None,
    };

    let json = serde_json::to_string(&hw).expect("serialize");
    assert!(!json.contains("attestation_nonce"));

    let decoded: HardwareEvidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.attestation_nonce, None);
}

#[test]
fn test_packet_sign_without_nonce() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let signing_key = test_signing_key();
    packet.sign(&signing_key).expect("sign");

    assert!(packet.is_signed());
    assert!(!packet.has_verifier_nonce());
    assert!(packet.packet_signature.is_some());
    assert!(packet.signing_public_key.is_some());

    packet.verify_signature(None).expect("verify");
}

#[test]
fn test_packet_sign_with_nonce() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let signing_key = test_signing_key();
    let nonce: [u8; 32] = [0x42u8; 32];
    packet.sign_with_nonce(&signing_key, nonce).expect("sign");

    assert!(packet.is_signed());
    assert!(packet.has_verifier_nonce());
    assert_eq!(packet.verifier_nonce.as_ref(), Some(&nonce));

    packet.verify_signature(Some(&nonce)).expect("verify");
}

#[test]
fn test_packet_verify_with_wrong_nonce() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let signing_key = test_signing_key();
    let nonce: [u8; 32] = [0x42u8; 32];
    packet.sign_with_nonce(&signing_key, nonce).expect("sign");

    let wrong_nonce: [u8; 32] = [0x99u8; 32];
    let err = packet.verify_signature(Some(&wrong_nonce)).unwrap_err();
    assert!(err.to_string().contains("nonce mismatch"));
}

#[test]
fn test_packet_verify_expects_nonce_but_none_present() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let signing_key = test_signing_key();
    packet.sign(&signing_key).expect("sign");

    let expected_nonce: [u8; 32] = [0x42u8; 32];
    let err = packet.verify_signature(Some(&expected_nonce)).unwrap_err();
    assert!(err
        .to_string()
        .contains("expected verifier nonce but none present"));
}

#[test]
fn test_packet_verify_not_signed() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let err = packet.verify_signature(None).unwrap_err();
    assert!(err.to_string().contains("packet not signed"));
}

#[test]
fn test_packet_nonce_replay_attack_prevention() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let signing_key = test_signing_key();
    let nonce1: [u8; 32] = [0x11u8; 32];
    let nonce2: [u8; 32] = [0x22u8; 32];

    packet.sign_with_nonce(&signing_key, nonce1).expect("sign");

    packet
        .verify_signature(Some(&nonce1))
        .expect("verify nonce1");

    let err = packet.verify_signature(Some(&nonce2)).unwrap_err();
    assert!(err.to_string().contains("nonce mismatch"));
}

#[test]
fn test_packet_nonce_serialization() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let signing_key = test_signing_key();
    let nonce: [u8; 32] = [0xABu8; 32];
    packet.sign_with_nonce(&signing_key, nonce).expect("sign");

    let encoded = packet.encode().expect("encode");
    let decoded = Packet::decode(&encoded).expect("decode");

    assert_eq!(decoded.verifier_nonce, packet.verifier_nonce);
    assert_eq!(decoded.packet_signature, packet.packet_signature);
    assert_eq!(decoded.signing_public_key, packet.signing_public_key);

    decoded
        .verify_signature(Some(&nonce))
        .expect("verify after roundtrip");
}

#[test]
fn test_set_verifier_nonce_clears_signature() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let signing_key = test_signing_key();
    let nonce1: [u8; 32] = [0x11u8; 32];

    packet.sign_with_nonce(&signing_key, nonce1).expect("sign");
    assert!(packet.is_signed());

    let nonce2: [u8; 32] = [0x22u8; 32];
    packet.set_verifier_nonce(nonce2);

    assert!(!packet.is_signed());
    assert!(packet.packet_signature.is_none());
    assert!(packet.signing_public_key.is_none());
    assert!(packet.has_verifier_nonce());
    assert_eq!(packet.verifier_nonce.as_ref(), Some(&nonce2));
}

#[test]
fn test_content_hash_stability() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let hash1 = packet.content_hash().expect("content_hash");
    let hash2 = packet.content_hash().expect("content_hash");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_signing_payload_without_nonce() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let content = packet.content_hash().expect("content_hash");
    let payload = packet.signing_payload().expect("signing_payload");
    assert_eq!(content, payload);
}

#[test]
fn test_signing_payload_with_nonce() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let nonce: [u8; 32] = [0x42u8; 32];
    packet.set_verifier_nonce(nonce);

    let content = packet.content_hash().expect("content_hash");
    let payload = packet.signing_payload().expect("signing_payload");
    assert_ne!(content, payload);
}

#[test]
fn test_different_nonces_produce_different_payloads() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet1 = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let mut packet2 = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let nonce1: [u8; 32] = [0x11u8; 32];
    let nonce2: [u8; 32] = [0x22u8; 32];

    packet1.set_verifier_nonce(nonce1);
    packet2.set_verifier_nonce(nonce2);

    let payload1 = packet1.signing_payload().expect("signing_payload");
    let payload2 = packet2.signing_payload().expect("signing_payload");
    assert_ne!(payload1, payload2);
}

#[test]
fn test_cbor_encoding_with_ppp_tag() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let encoded = packet.encode().expect("encode");

    assert!(
        authorproof_protocol::codec::cbor::has_tag(
            &encoded,
            authorproof_protocol::codec::CBOR_TAG_CPOE
        ),
        "encoded packet should have CPoE semantic tag"
    );

    let format = authorproof_protocol::codec::Format::detect(&encoded);
    assert_eq!(format, Some(authorproof_protocol::codec::Format::Cbor));

    let decoded = Packet::decode(&encoded).expect("decode");
    assert_eq!(decoded.document.title, packet.document.title);
    assert_eq!(decoded.chain_hash, packet.chain_hash);
}

#[test]
fn test_json_format_encoding() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let encoded = packet
        .encode_with_format(authorproof_protocol::codec::Format::Json)
        .expect("encode json");

    let format = authorproof_protocol::codec::Format::detect(&encoded);
    assert_eq!(format, Some(authorproof_protocol::codec::Format::Json));

    assert_eq!(encoded[0], b'{');

    let decoded = Packet::decode(&encoded).expect("decode");
    assert_eq!(decoded.document.title, packet.document.title);
}

#[test]
fn test_cbor_missing_tag_rejected() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let untagged = authorproof_protocol::codec::cbor::encode(&packet).expect("encode untagged");

    let result = Packet::decode(&untagged);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("missing or invalid CBOR PPP tag"));
}

#[test]
fn test_trust_tier_local() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    assert_eq!(packet.trust_tier, Some(TrustTier::Local));
    assert_eq!(packet.compute_trust_tier(), TrustTier::Local);
}

#[test]
fn test_trust_tier_signed() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let signing_key = test_signing_key();
    packet.sign(&signing_key).expect("sign");

    assert_eq!(packet.compute_trust_tier(), TrustTier::Signed);
}

#[test]
fn test_trust_tier_nonce_bound() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mut packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let signing_key = test_signing_key();
    let nonce = [0x42u8; 32];
    packet.sign_with_nonce(&signing_key, nonce).expect("sign");

    assert_eq!(packet.compute_trust_tier(), TrustTier::NonceBound);
}

#[test]
fn test_trust_tier_attested() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .with_writersproof_certificate("cert-123".to_string())
        .build()
        .expect("build");

    assert_eq!(packet.trust_tier, Some(TrustTier::Attested));
    assert_eq!(packet.compute_trust_tier(), TrustTier::Attested);
}

#[test]
fn test_trust_tier_ordering() {
    assert!(TrustTier::Local < TrustTier::Signed);
    assert!(TrustTier::Signed < TrustTier::NonceBound);
    assert!(TrustTier::NonceBound < TrustTier::Attested);
}

#[test]
fn test_mmr_proof_in_packet() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let mmr_root = [0xAA; 32];
    let range_proof = b"serialized-range-proof";

    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .with_mmr_proof(mmr_root, range_proof)
        .build()
        .expect("build");

    assert_eq!(packet.mmr_root, Some(hex::encode(mmr_root)));
    assert_eq!(packet.mmr_proof, Some(hex::encode(range_proof)));
}

#[test]
fn test_writersproof_nonce_in_packet() {
    let dir = TempDir::new().expect("temp dir");
    let (chain, _) = create_test_chain(&dir);
    let decl = create_test_declaration(&chain);

    let nonce = [0xBB; 32];
    let packet = Builder::new("Test", &chain)
        .with_declaration(&decl)
        .with_writersproof_nonce(nonce)
        .build()
        .expect("build");

    assert_eq!(packet.verifier_nonce, Some(nonce));
}
