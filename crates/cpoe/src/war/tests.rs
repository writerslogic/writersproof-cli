// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::checkpoint;
use crate::declaration;
use crate::evidence;
use crate::evidence::Packet;
use crate::vdf;
use crate::war::profiles::test_helpers::test_signing_key;
use std::fs;
use std::time::Duration;
use tempfile::TempDir;

fn create_test_evidence() -> (Packet, TempDir) {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("test_doc.txt");
    fs::write(&path, b"Test document content for WAR block").expect("write");

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

#[test]
fn test_version_parsing() {
    assert_eq!(Version::parse("WAR/1.0"), Some(Version::V1_0));
    assert_eq!(Version::parse("WAR/1.1"), Some(Version::V1_1));
    assert_eq!(Version::parse("invalid"), None);

    assert_eq!(Version::V1_0.as_str(), "WAR/1.0");
    assert_eq!(Version::V1_1.as_str(), "WAR/1.1");
}

#[test]
fn test_seal_encode_decode_roundtrip() {
    let seal = Seal {
        h1: [1u8; 32],
        h2: [2u8; 32],
        h3: [3u8; 32],
        signature: [4u8; 64],
        public_key: [5u8; 32],
        reconstructed: false,
    };

    let hex = seal.encode_hex();
    let decoded = Seal::decode_hex(&hex).expect("decode");

    assert_eq!(decoded.h1, seal.h1);
    assert_eq!(decoded.h2, seal.h2);
    assert_eq!(decoded.h3, seal.h3);
    assert_eq!(decoded.signature, seal.signature);
    assert_eq!(decoded.public_key, seal.public_key);
}

#[test]
fn test_block_from_packet() {
    let (packet, _dir) = create_test_evidence();
    let block = Block::from_packet(&packet).expect("create block");

    assert_eq!(block.version, Version::V1_0);
    assert!(!block.author.is_empty());
    assert_eq!(
        block.statement,
        "I wrote this document myself without AI assistance."
    );
    assert!(block.evidence.is_some());
    assert!(!block.signed);
}

#[test]
fn test_block_from_packet_signed() {
    let (packet, _dir) = create_test_evidence();
    let signing_key = test_signing_key();
    let block = Block::from_packet_signed(&packet, &signing_key).expect("create signed block");

    assert!(block.signed);
    assert_ne!(block.seal.signature, [0u8; 64]);

    let report = block.verify(None);
    assert!(
        report.valid,
        "Signed block should verify: {}",
        report.summary
    );

    let seal_check = report.checks.iter().find(|c| c.name == "seal_signature");
    assert!(seal_check.is_some(), "Should have seal_signature check");
    assert!(
        seal_check.expect("seal_signature check present").passed,
        "Seal signature should pass"
    );
}

#[test]
fn test_block_ascii_encode_decode() {
    let (packet, _dir) = create_test_evidence();
    let block = Block::from_packet(&packet).expect("create block");

    let ascii = block.encode_ascii();
    assert!(ascii.contains("BEGIN CPoE WAR"));
    assert!(ascii.contains("END CPoE WAR"));
    assert!(ascii.contains("BEGIN SEAL"));
    assert!(ascii.contains("END SEAL"));
    assert!(ascii.contains("Version: WAR/1.0"));

    let decoded = Block::decode_ascii(&ascii).expect("decode");
    assert_eq!(decoded.version, block.version);
    assert_eq!(decoded.author, block.author);
    assert_eq!(decoded.document_id, block.document_id);
    // Statement may have minor whitespace differences from word-wrap
    assert!(decoded.statement.contains("I wrote this document"));
}

#[test]
fn test_block_verification_unsigned() {
    let (packet, _dir) = create_test_evidence();
    let block = Block::from_packet(&packet).expect("create block");

    let report = block.verify(None);

    // Unsigned blocks must fail verification — accepting unsigned blocks
    // would allow forged evidence to bypass seal signature checks.
    assert!(
        !report.valid,
        "Unsigned block must NOT pass verification: {}",
        report.summary
    );
    assert!(report
        .checks
        .iter()
        .any(|c| c.name == "seal_signature" && !c.passed));
    assert!(!report.summary.is_empty());
}

#[test]
fn test_word_wrap() {
    let text = "This is a test of the word wrapping function.";
    let wrapped = word_wrap(text, 20);

    for line in &wrapped {
        assert!(line.len() <= 20, "Line too long: {}", line);
    }
    assert!(wrapped.len() > 1);
}

#[test]
fn test_forensic_details() {
    let (packet, _dir) = create_test_evidence();
    let block = Block::from_packet(&packet).expect("create block");

    let report = block.verify(None);
    let details = &report.details;

    assert_eq!(details.version, "WAR/1.0");
    assert!(!details.author.is_empty());
    assert!(!details.document_id.is_empty());
    assert!(details.components.contains(&"document".to_string()));
    assert!(details.components.contains(&"declaration".to_string()));
}

#[test]
fn test_block_with_jitter_seal_is_v1_1() {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("test_doc.txt");
    fs::write(&path, b"Test content").expect("write");

    let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("create chain");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit");

    let latest = chain.latest().expect("latest");
    let signing_key = test_signing_key();

    let jitter = declaration::DeclarationJitter::from_samples(&[1000u32; 10], 1000, false)
        .expect("from_samples");
    let decl =
        declaration::no_ai_declaration(latest.content_hash, latest.hash, "Test", "Statement")
            .with_jitter_seal(jitter)
            .sign(&signing_key)
            .expect("sign");

    let packet = evidence::Builder::new("Test", &chain)
        .with_declaration(&decl)
        .build()
        .expect("build");

    let block = Block::from_packet(&packet).expect("create block");
    assert_eq!(block.version, Version::V1_1);
}

#[test]
fn test_seal_decode_invalid_length() {
    let err = Seal::decode_hex("abcd").unwrap_err();
    assert!(err.contains("invalid seal length"));
}

#[test]
fn test_block_missing_declaration() {
    let (mut packet, _dir) = create_test_evidence();
    packet.declaration = None;

    let err = Block::from_packet(&packet).unwrap_err();
    assert!(err.contains("missing declaration"));
}

#[test]
fn test_block_with_verifier_nonce() {
    let (mut packet, _dir) = create_test_evidence();

    let nonce: [u8; 32] = [0x42u8; 32];
    packet.verifier_nonce = Some(nonce);

    let block = Block::from_packet(&packet).expect("create block");

    assert!(block.verifier_nonce.is_some());
    assert_eq!(block.verifier_nonce.expect("verifier nonce present"), nonce);
}

#[test]
fn test_block_without_verifier_nonce() {
    let (packet, _dir) = create_test_evidence();

    let block = Block::from_packet(&packet).expect("create block");

    assert!(block.verifier_nonce.is_none());
}

#[test]
fn test_block_ascii_encode_with_verifier_nonce() {
    let (mut packet, _dir) = create_test_evidence();

    let nonce: [u8; 32] = [0xABu8; 32];
    packet.verifier_nonce = Some(nonce);

    let block = Block::from_packet(&packet).expect("create block");
    let ascii = block.encode_ascii();

    assert!(ascii.contains("BEGIN CPoE WAR"));
    assert!(ascii.contains("Verifier-Nonce:"));
    assert!(ascii.contains(&hex::encode(nonce)));
}

#[test]
fn test_block_ascii_encode_without_verifier_nonce() {
    let (packet, _dir) = create_test_evidence();

    let block = Block::from_packet(&packet).expect("create block");
    let ascii = block.encode_ascii();

    assert!(ascii.contains("BEGIN CPoE WAR"));
    assert!(!ascii.contains("Verifier-Nonce:"));
}

#[test]
fn test_block_ascii_decode_with_verifier_nonce() {
    let (mut packet, _dir) = create_test_evidence();

    let nonce: [u8; 32] = [0xCDu8; 32];
    packet.verifier_nonce = Some(nonce);

    let block = Block::from_packet(&packet).expect("create block");
    let ascii = block.encode_ascii();

    let decoded = Block::decode_ascii(&ascii).expect("decode");
    assert!(decoded.verifier_nonce.is_some());
    assert_eq!(
        decoded
            .verifier_nonce
            .expect("decoded verifier nonce present"),
        nonce
    );
}

#[test]
fn test_block_ascii_decode_without_verifier_nonce() {
    let (packet, _dir) = create_test_evidence();

    let block = Block::from_packet(&packet).expect("create block");
    let ascii = block.encode_ascii();

    let decoded = Block::decode_ascii(&ascii).expect("decode");
    assert!(decoded.verifier_nonce.is_none());
}

#[test]
fn test_forensic_details_with_verifier_nonce() {
    let (mut packet, _dir) = create_test_evidence();

    let nonce: [u8; 32] = [0xEFu8; 32];
    packet.verifier_nonce = Some(nonce);

    let block = Block::from_packet(&packet).expect("create block");
    let report = block.verify(None);

    assert!(report.details.has_verifier_nonce);
    assert!(report.details.verifier_nonce.is_some());
    assert_eq!(
        report
            .details
            .verifier_nonce
            .as_ref()
            .expect("verifier nonce in details"),
        &hex::encode(nonce)
    );
}

#[test]
fn test_forensic_details_without_verifier_nonce() {
    let (packet, _dir) = create_test_evidence();

    let block = Block::from_packet(&packet).expect("create block");
    let report = block.verify(None);

    assert!(!report.details.has_verifier_nonce);
    assert!(report.details.verifier_nonce.is_none());
}

#[test]
fn test_block_roundtrip_with_nonce() {
    let (mut packet, _dir) = create_test_evidence();

    let nonce: [u8; 32] = [0x99u8; 32];
    packet.verifier_nonce = Some(nonce);

    let signing_key = test_signing_key();
    let block = Block::from_packet_signed(&packet, &signing_key).expect("create signed block");

    let ascii = block.encode_ascii();
    let decoded = Block::decode_ascii(&ascii).expect("decode");

    assert_eq!(decoded.version, block.version);
    assert_eq!(decoded.author, block.author);
    assert_eq!(decoded.document_id, block.document_id);
    assert_eq!(decoded.verifier_nonce, block.verifier_nonce);
    assert_eq!(decoded.seal.h1, block.seal.h1);
    assert_eq!(decoded.seal.h2, block.seal.h2);
    assert_eq!(decoded.seal.h3, block.seal.h3);
    assert_eq!(decoded.seal.signature, block.seal.signature);
    assert_eq!(decoded.seal.public_key, block.seal.public_key);
}

#[test]
fn test_c2pa_assertion_from_appraised_block() {
    let (packet, _dir) = create_test_evidence();
    let signing_key = test_signing_key();
    let policy = crate::trust_policy::profiles::basic();

    let block =
        Block::from_packet_appraised(&packet, &signing_key, &policy).expect("appraised block");

    let ear = block.ear.as_ref().expect("block should have EAR token");
    let assertion =
        profiles::c2pa::to_c2pa_assertion(ear).expect("to_c2pa_assertion should succeed");

    assert_eq!(assertion.label, profiles::c2pa::ASSERTION_LABEL);
    assert!(!assertion.data.ear_profile.is_empty());
    assert!(!assertion.data.status.is_empty());
    assert!(assertion.data.seal.is_some(), "seal should be present");
    assert!(
        assertion.data.chain_length.is_some(),
        "chain_length should be present"
    );

    // Verify it round-trips through JSON.
    let json = serde_json::to_string_pretty(&assertion).expect("serialize");
    let decoded: profiles::c2pa::C2paAssertion = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.label, assertion.label);
    assert_eq!(decoded.data.status, assertion.data.status);
}
