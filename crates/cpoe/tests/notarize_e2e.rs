// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! End-to-end notarization round-trip test against the live WritersProof API.
//!
//! 1. Build a real evidence packet from a tracked file
//! 2. POST to api.writersproof.com/v1/notarize
//! 3. Download the countersigned packet from the returned ID
//! 4. Resolve CA public key from /.well-known/did.json
//! 5. Verify both signatures (author key from wire key 12, CA from DID)
//! 6. Confirm inner payload is byte-identical to the original

use std::fs;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;

use authorproof_protocol::crypto::{
    sign_evidence_cose, strip_countersignature,
    verify_countersigned_packet, verify_evidence_cose,
};
use cpoe_engine::checkpoint;
use cpoe_engine::evidence::wire_conversion::chain_to_wire;
use cpoe_engine::vdf;

fn test_api_key() -> String {
    if let Ok(key) = std::env::var("WP_TEST_API_KEY") {
        return key;
    }
    let path = Path::new("/tmp/wp_test_api_key.txt");
    if path.exists() {
        return fs::read_to_string(path)
            .expect("read API key file")
            .trim()
            .to_string();
    }
    panic!(
        "No API key found. Set WP_TEST_API_KEY env var or write to /tmp/wp_test_api_key.txt"
    );
}

fn test_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
}

/// Build a real evidence packet with checkpoints from a tracked file.
fn build_test_evidence(
    signing_key: &ed25519_dalek::SigningKey,
) -> (Vec<u8>, TempDir) {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("test_notarize_doc.txt");
    fs::write(
        &path,
        "This document was authored by a human writer for testing \
         the WritersProof notarization pipeline end-to-end.",
    )
    .expect("write test doc");

    let mut chain =
        checkpoint::Chain::new(&path, vdf::default_parameters()).expect("create chain");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    // Add more content and commit again to meet minimum checkpoint count.
    fs::write(
        &path,
        "This document was authored by a human writer for testing \
         the WritersProof notarization pipeline end-to-end.\n\n\
         Second paragraph added after initial checkpoint.",
    )
    .expect("write more content");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 2");

    fs::write(
        &path,
        "This document was authored by a human writer for testing \
         the WritersProof notarization pipeline end-to-end.\n\n\
         Second paragraph added after initial checkpoint.\n\n\
         Third paragraph for the final checkpoint.",
    )
    .expect("write final content");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 3");

    // Convert checkpoint chain to wire format (same pipeline as FFI export).
    let mut wire = chain_to_wire(&chain).expect("chain_to_wire");
    wire.signing_public_key =
        Some(serde_bytes::ByteBuf::from(signing_key.verifying_key().to_bytes().to_vec()));

    let cbor = wire.encode_cbor().expect("encode wire CBOR");
    let signed = sign_evidence_cose(&cbor, signing_key).expect("COSE sign");

    (signed, dir)
}

/// Decode a multibase base58btc string (z-prefix) into raw bytes.
/// Strips the 2-byte Ed25519 multicodec prefix (0xed01).
fn decode_multibase_ed25519(multibase: &str) -> Vec<u8> {
    assert!(multibase.starts_with('z'), "expected z-prefix multibase");
    let b58 = &multibase[1..];
    let decoded = bs58::decode(b58).into_vec().expect("base58 decode");
    assert!(
        decoded.len() >= 2 && decoded[0] == 0xed && decoded[1] == 0x01,
        "expected Ed25519 multicodec prefix 0xed01"
    );
    decoded[2..].to_vec()
}

#[test]
fn notarize_full_round_trip() {
    let api_key = test_api_key();
    let signing_key = test_signing_key();
    let (cpoe_bytes, _dir) = build_test_evidence(&signing_key);

    println!("Built evidence packet: {} bytes", cpoe_bytes.len());

    // --- Step 1: POST to /v1/notarize ---
    let client = reqwest::blocking::Client::new();
    let post_resp = client
        .post("https://api.writersproof.com/v1/notarize")
        .header("X-API-Key", &api_key)
        .header("Content-Type", "application/c2pa")
        .body(cpoe_bytes.clone())
        .timeout(Duration::from_secs(30))
        .send()
        .expect("POST /v1/notarize");

    let status = post_resp.status();
    let resp_text = post_resp.text().expect("read response");
    assert!(
        status.is_success(),
        "POST /v1/notarize failed: {} {}",
        status,
        resp_text,
    );

    let resp: serde_json::Value = serde_json::from_str(&resp_text).expect("parse JSON");
    let notarization_id = resp["notarization_id"]
        .as_str()
        .expect("notarization_id in response");
    let download_url = resp["download_url"]
        .as_str()
        .expect("download_url in response");
    println!(
        "Notarized: id={} url={} size={}",
        notarization_id,
        download_url,
        resp["countersigned_size"],
    );

    // --- Step 2: Download countersigned packet ---
    let download_resp = client
        .get(format!(
            "https://api.writersproof.com{}",
            download_url
        ))
        .header("X-API-Key", &api_key)
        .timeout(Duration::from_secs(30))
        .send()
        .expect("GET download");

    assert!(
        download_resp.status().is_success(),
        "Download failed: {}",
        download_resp.status(),
    );
    let countersigned = download_resp.bytes().expect("read countersigned bytes");
    println!("Downloaded countersigned packet: {} bytes", countersigned.len());
    assert!(countersigned.len() > cpoe_bytes.len());

    // --- Step 3: Resolve CA public key from DID document ---
    let did_resp = client
        .get("https://api.writersproof.com/.well-known/did.json")
        .timeout(Duration::from_secs(10))
        .send()
        .expect("GET DID document");
    assert!(did_resp.status().is_success());

    let did_doc: serde_json::Value =
        serde_json::from_str(&did_resp.text().expect("DID body")).expect("parse DID JSON");

    let vm = &did_doc["verificationMethod"][0];
    assert_eq!(
        vm["id"].as_str().unwrap(),
        "did:web:api.writersproof.com#notarize-ca-1",
    );
    let multibase = vm["publicKeyMultibase"].as_str().expect("publicKeyMultibase");
    let ca_pubkey_bytes = decode_multibase_ed25519(multibase);
    assert_eq!(ca_pubkey_bytes.len(), 32, "Ed25519 public key must be 32 bytes");

    let ca_verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
        ca_pubkey_bytes.as_slice().try_into().unwrap(),
    )
    .expect("parse CA verifying key");

    println!(
        "Resolved CA key from DID: {}",
        hex::encode(&ca_pubkey_bytes),
    );

    // --- Step 4: Verify both signatures ---
    let author_verifying_key = signing_key.verifying_key();

    let evidence_payload = verify_countersigned_packet(
        &countersigned,
        &ca_verifying_key,
        &author_verifying_key,
    )
    .expect("verify both signatures");

    println!(
        "Both signatures verified. Evidence payload: {} bytes",
        evidence_payload.len(),
    );

    // --- Step 5: Strip countersig, confirm byte-identical ---
    let recovered_cpoe = strip_countersignature(&countersigned, &ca_verifying_key)
        .expect("strip countersignature");

    assert_eq!(
        recovered_cpoe, cpoe_bytes,
        "Inner .cpoe must be byte-identical to original",
    );
    println!("Inner payload byte-identical to original: OK");

    // Verify the recovered .cpoe still works standalone.
    let standalone_payload =
        verify_evidence_cose(&recovered_cpoe, &author_verifying_key)
            .expect("verify recovered .cpoe standalone");
    assert_eq!(standalone_payload, evidence_payload);
    println!("Standalone verification of recovered .cpoe: OK");

    println!("\n=== NOTARIZE E2E ROUND-TRIP: ALL CHECKS PASSED ===");
    println!("Notarization ID: {}", notarization_id);
}
