// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial
#![allow(clippy::needless_borrows_for_generic_args)]

use super::*;
use chrono::Utc;
use tempfile::TempDir;

fn test_puf() -> SoftwarePUF {
    SoftwarePUF::new_from_seed("device-1", vec![7u8; 32]).expect("create test puf")
}

fn different_puf() -> SoftwarePUF {
    SoftwarePUF::new_from_seed("device-2", vec![8u8; 32]).expect("create different puf")
}

#[test]
fn test_session_certificate_verification() {
    let puf = test_puf();
    let session = start_session(&puf, [9u8; 32]).expect("start session");
    verify_session_certificate(&session.certificate).expect("verify certificate");
}

#[test]
fn test_checkpoint_signature_verification() {
    let puf = test_puf();
    let mut session = start_session(&puf, [3u8; 32]).expect("start session");
    session.sign_checkpoint([1u8; 32]).expect("sign");
    session.sign_checkpoint([2u8; 32]).expect("sign");
    verify_checkpoint_signatures(&session.signatures()).expect("verify signatures");
}

#[test]
fn test_key_hierarchy_evidence_verification() {
    let puf = test_puf();
    let identity = derive_master_identity(&puf).expect("identity");
    let mut session = start_session(&puf, [6u8; 32]).expect("start session");
    session.sign_checkpoint([8u8; 32]).expect("sign");
    let evidence = session.export(&identity);
    verify_key_hierarchy(&evidence).expect("verify evidence");
}

#[test]
fn test_validate_cert_byte_lengths_invalid() {
    let dummy_id = [0u8; 32];
    let dummy_hash = [0u8; 32];
    let err = validate_cert_byte_lengths(
        &[1u8; 10],
        &[2u8; 32],
        &[3u8; 64],
        &dummy_id,
        Utc::now(),
        &dummy_hash,
    )
    .unwrap_err();
    assert!(matches!(err, KeyHierarchyError::InvalidCert));
}

#[test]
fn test_session_recovery_with_ratchet() {
    let puf = test_puf();
    let document_hash = [4u8; 32];
    let mut session = start_session(&puf, document_hash).expect("start session");
    session.sign_checkpoint([1u8; 32]).expect("sign");
    session.sign_checkpoint([2u8; 32]).expect("sign");

    let recovery = session
        .export_recovery_state(&puf)
        .expect("export recovery");
    let recovered = recover_session(&puf, &recovery, document_hash).expect("recover session");
    assert_eq!(recovered.signatures().len(), session.signatures().len());
    assert_eq!(recovered.current_ordinal(), session.current_ordinal());
}

#[test]
fn test_derive_master_identity() {
    let puf = test_puf();
    let identity = derive_master_identity(&puf).expect("derive identity");

    assert_eq!(identity.public_key.len(), 32);
    assert!(!identity.fingerprint.is_empty());
    assert_eq!(identity.device_id, "device-1");
    assert_eq!(identity.version, VERSION);
}

#[test]
fn test_same_puf_produces_same_identity() {
    let puf1 = test_puf();
    let puf2 = test_puf();

    let identity1 = derive_master_identity(&puf1).expect("derive 1");
    let identity2 = derive_master_identity(&puf2).expect("derive 2");

    assert_eq!(identity1.public_key, identity2.public_key);
    assert_eq!(identity1.fingerprint, identity2.fingerprint);
}

#[test]
fn test_different_puf_produces_different_identity() {
    let puf1 = test_puf();
    let puf2 = different_puf();

    let identity1 = derive_master_identity(&puf1).expect("derive 1");
    let identity2 = derive_master_identity(&puf2).expect("derive 2");

    assert_ne!(identity1.public_key, identity2.public_key);
    assert_ne!(identity1.fingerprint, identity2.fingerprint);
}

#[test]
fn test_session_sign_checkpoint_increments_ordinal() {
    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start session");

    assert_eq!(session.current_ordinal(), 0);

    session.sign_checkpoint([1u8; 32]).expect("sign 1");
    assert_eq!(session.current_ordinal(), 1);

    session.sign_checkpoint([2u8; 32]).expect("sign 2");
    assert_eq!(session.current_ordinal(), 2);
}

#[test]
fn test_session_end_wipes_ratchet() {
    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start session");

    session.sign_checkpoint([1u8; 32]).expect("sign");
    session.end();

    let err = session.sign_checkpoint([2u8; 32]).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::RatchetWiped));
}

#[test]
fn test_session_recovery_fails_with_wrong_puf() {
    let puf1 = test_puf();
    let puf2 = different_puf();
    let document_hash = [4u8; 32];

    let mut session = start_session(&puf1, document_hash).expect("start session");
    session.sign_checkpoint([1u8; 32]).expect("sign");
    let recovery = session.export_recovery_state(&puf1).expect("export");

    let err = recover_session(&puf2, &recovery, document_hash).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::SessionRecoveryFailed));
}

#[test]
fn test_session_recovery_fails_with_wrong_document_hash() {
    let puf = test_puf();
    let original_hash = [4u8; 32];
    let wrong_hash = [5u8; 32];

    let mut session = start_session(&puf, original_hash).expect("start session");
    session.sign_checkpoint([1u8; 32]).expect("sign");
    let recovery = session.export_recovery_state(&puf).expect("export");

    let err = recover_session(&puf, &recovery, wrong_hash).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::SessionRecoveryFailed));
}

#[test]
fn test_verify_checkpoint_signatures_ordinal_mismatch() {
    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start session");
    session.sign_checkpoint([1u8; 32]).expect("sign");
    session.sign_checkpoint([2u8; 32]).expect("sign");

    let mut sigs = session.signatures();
    sigs[1].ordinal = 5;

    let err = verify_checkpoint_signatures(&sigs).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::OrdinalMismatch));
}

#[test]
fn test_verify_checkpoint_signatures_invalid_signature() {
    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start session");
    session.sign_checkpoint([1u8; 32]).expect("sign");

    let mut sigs = session.signatures();
    sigs[0].signature[0] ^= 0xFF;

    let err = verify_checkpoint_signatures(&sigs).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::SignatureFailed));
}

#[test]
fn test_verify_ratchet_signature() {
    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start session");
    let sig = session.sign_checkpoint([0xAAu8; 32]).expect("sign");

    verify_ratchet_signature(&sig.public_key, &sig.checkpoint_hash, &sig.signature)
        .expect("verify");
}

#[test]
fn test_verify_ratchet_signature_invalid_public_key() {
    let err = verify_ratchet_signature(&[1u8; 16], &[2u8; 32], &[3u8; 64]).unwrap_err();
    assert!(err.to_string().contains("invalid ratchet public key size"));
}

#[test]
fn test_verify_ratchet_signature_invalid_checkpoint_hash() {
    let err = verify_ratchet_signature(&[1u8; 32], &[2u8; 16], &[3u8; 64]).unwrap_err();
    assert!(err.to_string().contains("invalid checkpoint hash size"));
}

#[test]
fn test_verify_ratchet_signature_invalid_signature_size() {
    let err = verify_ratchet_signature(&[1u8; 32], &[2u8; 32], &[3u8; 32]).unwrap_err();
    assert!(err.to_string().contains("invalid signature size"));
}

#[test]
fn test_fingerprint_for_public_key() {
    let pubkey = [0xABu8; 32];
    let fingerprint = fingerprint_for_public_key(&pubkey);
    assert_eq!(fingerprint.len(), 16);
}

#[test]
fn test_same_pubkey_same_fingerprint() {
    let pubkey = [0xCDu8; 32];
    let fp1 = fingerprint_for_public_key(&pubkey);
    let fp2 = fingerprint_for_public_key(&pubkey);
    assert_eq!(fp1, fp2);
}

#[test]
fn test_validate_cert_byte_lengths_invalid_session_pubkey() {
    let dummy_id = [0u8; 32];
    let dummy_hash = [0u8; 32];
    let err = validate_cert_byte_lengths(
        &[1u8; 32],
        &[2u8; 16],
        &[3u8; 64],
        &dummy_id,
        Utc::now(),
        &dummy_hash,
    )
    .unwrap_err();
    assert!(matches!(err, KeyHierarchyError::InvalidCert));
}

#[test]
fn test_validate_cert_byte_lengths_invalid_cert_signature() {
    let dummy_id = [0u8; 32];
    let dummy_hash = [0u8; 32];
    let err = validate_cert_byte_lengths(
        &[1u8; 32],
        &[2u8; 32],
        &[3u8; 32],
        &dummy_id,
        Utc::now(),
        &dummy_hash,
    )
    .unwrap_err();
    assert!(matches!(err, KeyHierarchyError::InvalidCert));
}

#[test]
fn test_session_export() {
    let puf = test_puf();
    let identity = derive_master_identity(&puf).expect("identity");
    let mut session = start_session(&puf, [1u8; 32]).expect("start");
    session.sign_checkpoint([1u8; 32]).expect("sign");
    session.sign_checkpoint([2u8; 32]).expect("sign");

    let evidence = session.export(&identity);

    assert_eq!(evidence.version, VERSION as i32);
    assert_eq!(evidence.master_fingerprint, identity.fingerprint);
    assert_eq!(evidence.master_public_key, identity.public_key);
    assert_eq!(evidence.ratchet_count, 2);
    assert_eq!(evidence.checkpoint_signatures.len(), 2);
    assert_eq!(evidence.ratchet_public_keys.len(), 2);
}

#[test]
fn test_verify_key_hierarchy_invalid_cert() {
    let puf = test_puf();
    let identity = derive_master_identity(&puf).expect("identity");
    let mut session = start_session(&puf, [1u8; 32]).expect("start");
    session.sign_checkpoint([1u8; 32]).expect("sign");

    let mut evidence = session.export(&identity);
    evidence
        .session_certificate
        .as_mut()
        .expect("session certificate")
        .signature[0] ^= 0xFF;

    let err = verify_key_hierarchy(&evidence).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::InvalidCert));
}

#[test]
fn test_verify_key_hierarchy_fingerprint_mismatch() {
    let puf = test_puf();
    let identity = derive_master_identity(&puf).expect("identity");
    let mut session = start_session(&puf, [1u8; 32]).expect("start");
    session.sign_checkpoint([1u8; 32]).expect("sign");

    let mut evidence = session.export(&identity);
    evidence.master_fingerprint = "wrong_fingerprint".to_string();

    let err = verify_key_hierarchy(&evidence).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::InvalidCert));
}

#[test]
fn test_verify_key_hierarchy_ratchet_count_mismatch() {
    let puf = test_puf();
    let identity = derive_master_identity(&puf).expect("identity");
    let mut session = start_session(&puf, [1u8; 32]).expect("start");
    session.sign_checkpoint([1u8; 32]).expect("sign");

    let mut evidence = session.export(&identity);
    evidence.ratchet_count = 999;

    let err = verify_key_hierarchy(&evidence).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::InvalidCert));
}

#[test]
fn test_software_puf_new_with_path() {
    let dir = TempDir::new().expect("create temp dir");
    let seed_path = dir.path().join("test_puf_seed");

    let puf = SoftwarePUF::new_with_path(&seed_path).expect("create puf");
    assert_eq!(puf.seed().len(), 32);
    assert!(!puf.device_id().is_empty());
    assert_eq!(puf.seed_path(), seed_path);

    let puf2 = SoftwarePUF::new_with_path(&seed_path).expect("reopen puf");
    assert_eq!(puf.seed(), puf2.seed());
    assert_eq!(puf.device_id(), puf2.device_id());
}

#[test]
fn test_software_puf_get_response() {
    let puf = test_puf();

    let challenge1 = b"challenge1";
    let challenge2 = b"challenge2";

    let response1 = puf.get_response(challenge1).expect("response 1");
    let response2 = puf.get_response(challenge2).expect("response 2");

    assert_eq!(response1.len(), 32);
    assert_eq!(response2.len(), 32);
    assert_ne!(response1, response2);

    let response1_again = puf.get_response(challenge1).expect("response 1 again");
    assert_eq!(response1, response1_again);
}

#[test]
fn test_empty_puf_fails() {
    let result = SoftwarePUF::new_from_seed("device", vec![]);
    assert!(result.is_err());
    match result {
        Err(KeyHierarchyError::Crypto(msg)) => {
            assert!(msg.contains("32 bytes"), "unexpected error message: {msg}");
        }
        Err(e) => panic!("Expected Crypto error, got: {e:?}"),
        Ok(_) => panic!("Expected error for empty seed"),
    }
}

#[test]
fn test_session_recovery_no_data() {
    let puf = test_puf();
    let recovery = SessionRecoveryState {
        certificate: SessionCertificate {
            session_id: [0u8; 32],
            session_pubkey: [0u8; 32],
            created_at: Utc::now(),
            document_hash: [0u8; 32],
            master_pubkey: [0u8; 32],
            signature: [0u8; 64],
            version: VERSION,
            expires_at: None,
            start_quote: None,
            end_quote: None,
            start_counter: None,
            end_counter: None,
            start_reset_count: None,
            start_restart_count: None,
            end_reset_count: None,
            end_restart_count: None,
        },
        signatures: vec![],
        last_ratchet_state: vec![],
        export_count: 0,
    };

    let err = recover_session(&puf, &recovery, [1u8; 32]).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::NoRecoveryData));
}

#[test]
fn test_export_recovery_after_end_fails() {
    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start");
    session.sign_checkpoint([1u8; 32]).expect("sign");
    session.end();

    let err = session.export_recovery_state(&puf).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::RatchetWiped));
}

#[test]
fn test_signatures_returned_in_order() {
    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start");

    for i in 0..5 {
        session.sign_checkpoint([(i + 1) as u8; 32]).expect("sign");
    }

    let sigs = session.signatures();
    for (i, sig) in sigs.iter().enumerate() {
        assert_eq!(sig.ordinal, i as u64);
    }
}

#[test]
fn test_verify_session_certificate_tampered_pubkey() {
    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start");
    session.certificate.session_pubkey[0] ^= 0xFF;

    let err = verify_session_certificate(&session.certificate).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::InvalidCert));
}

#[test]
fn test_legacy_migration_verification() {
    let dir = TempDir::new().expect("create temp dir");
    let legacy_path = dir.path().join("legacy_key");
    let seed = [42u8; 32];
    std::fs::write(&legacy_path, &seed).expect("write legacy key");

    let puf = test_puf();
    let (migration, _identity) = migrate_from_legacy_key(&puf, &legacy_path).expect("migrate");

    verify_legacy_migration(&migration).expect("verify migration");
}

#[test]
fn test_legacy_migration_invalid_sizes() {
    let migration = LegacyKeyMigration {
        legacy_public_key: vec![0u8; 16],
        new_master_public_key: vec![0u8; 32],
        migration_timestamp: Utc::now(),
        transition_signature: [0u8; 64],
        version: VERSION,
    };

    let err = verify_legacy_migration(&migration).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::InvalidMigration));
}

#[test]
fn test_start_session_from_legacy_key() {
    let dir = TempDir::new().expect("create temp dir");
    let legacy_path = dir.path().join("legacy_key");
    let seed = [42u8; 32];
    std::fs::write(&legacy_path, &seed).expect("write legacy key");

    let session =
        start_session_from_legacy_key(&legacy_path, [1u8; 32]).expect("start from legacy");
    verify_session_certificate(&session.certificate).expect("verify cert");
}

#[test]
fn test_legacy_key_64_bytes() {
    let dir = TempDir::new().expect("create temp dir");
    let legacy_path = dir.path().join("legacy_key_64");
    // Build a valid 64-byte expanded key: seed || public_key_from_seed
    let seed = [42u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let mut key_data = [0u8; 64];
    key_data[..32].copy_from_slice(&seed);
    key_data[32..].copy_from_slice(&pub_bytes);
    std::fs::write(&legacy_path, &key_data).expect("write 64 byte key");

    let session =
        start_session_from_legacy_key(&legacy_path, [1u8; 32]).expect("start from 64-byte legacy");
    verify_session_certificate(&session.certificate).expect("verify cert");
}

#[test]
fn test_legacy_key_not_found() {
    let err = start_session_from_legacy_key("/nonexistent/key", [1u8; 32]).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::Io(_)));
}

#[test]
fn test_legacy_key_invalid_size() {
    let dir = TempDir::new().expect("create temp dir");
    let legacy_path = dir.path().join("invalid_key");
    std::fs::write(&legacy_path, &[1u8; 20]).expect("write invalid key");

    let err = start_session_from_legacy_key(&legacy_path, [1u8; 32]).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::LegacyKeyNotFound));
}

#[test]
fn test_session_binding_no_quotes() {
    let puf = test_puf();
    let session = start_session(&puf, [1u8; 32]).expect("start");
    let report = verify_session_binding(&session.certificate).expect("verify binding");
    assert!(!report.has_start_quote);
    assert!(!report.has_end_quote);
    assert!(report.counter_delta.is_none());
    assert!(!report.reboot_detected);
    assert!(!report.restart_detected);
    assert!(report.warnings.is_empty());
}

#[test]
fn test_session_binding_reboot_detected() {
    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start");
    session.certificate.start_reset_count = Some(5);
    session.certificate.end_reset_count = Some(6);
    session.certificate.start_restart_count = Some(10);
    session.certificate.end_restart_count = Some(10);
    session.certificate.start_counter = Some(100);
    session.certificate.end_counter = Some(105);

    let report = verify_session_binding(&session.certificate).expect("verify binding");
    assert!(report.reboot_detected);
    assert!(!report.restart_detected);
    assert_eq!(report.counter_delta, Some(5));
    assert!(!report.warnings.is_empty());
}

#[test]
fn test_session_binding_counter_rollback() {
    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start");
    session.certificate.start_counter = Some(100);
    session.certificate.end_counter = Some(50);

    let err = verify_session_binding(&session.certificate).unwrap_err();
    assert!(matches!(err, KeyHierarchyError::Crypto(_)));
}

#[test]
fn test_entangled_nonce_deterministic() {
    let session_id = [1u8; 32];
    let data_hash = [2u8; 32];
    let mmr_root = [3u8; 32];

    let nonce1 = compute_entangled_nonce(&session_id, &data_hash, &mmr_root);
    let nonce2 = compute_entangled_nonce(&session_id, &data_hash, &mmr_root);
    assert_eq!(nonce1, nonce2);

    let nonce3 = compute_entangled_nonce(&session_id, &data_hash, &[4u8; 32]);
    assert_ne!(nonce1, nonce3);
}

#[test]
fn test_session_bind_start_quote_with_software_provider() {
    use crate::tpm::SoftwareProvider;

    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start");
    let mmr_root = [5u8; 32];

    let provider = SoftwareProvider::new();
    session.bind_start_quote(&provider, &mmr_root);

    assert!(session.certificate.start_quote.is_some());
    assert!(session.certificate.start_reset_count.is_some());
    assert!(session.certificate.start_restart_count.is_some());
}

#[test]
fn test_session_end_with_provider() {
    use crate::tpm::SoftwareProvider;

    let puf = test_puf();
    let mut session = start_session(&puf, [1u8; 32]).expect("start");
    let mmr_root = [5u8; 32];

    let provider = SoftwareProvider::new();
    session.bind_start_quote(&provider, &mmr_root);
    session.sign_checkpoint([10u8; 32]).expect("sign");
    session.end_with_provider(&provider, &mmr_root);

    assert!(session.certificate.end_quote.is_some());
    assert!(session.certificate.end_reset_count.is_some());
    assert!(session.certificate.end_restart_count.is_some());

    let report = verify_session_binding(&session.certificate).expect("verify");
    assert!(!report.reboot_detected);
    assert!(!report.restart_detected);
}

#[test]
fn test_recovery_signature_tamper_rejected() {
    let puf = test_puf();
    let doc_hash = [1u8; 32];
    let mut session = start_session(&puf, doc_hash).expect("start");

    session.sign_checkpoint([10u8; 32]).expect("sign");
    session.sign_checkpoint([20u8; 32]).expect("sign");
    let mut recovery = session.export_recovery_state(&puf).expect("export");

    // Remove a signature to fake a different chain state; AAD mismatch
    // causes AEAD decryption to fail.
    recovery.signatures.pop();
    let tampered = recover_session(&puf, &recovery, doc_hash);
    assert!(
        tampered.is_err(),
        "tampered signature list should fail AEAD decryption"
    );
}

#[test]
fn test_recovery_export_count_detects_replay() {
    let puf = test_puf();
    let doc_hash = [1u8; 32];
    let mut session = start_session(&puf, doc_hash).expect("start");

    session.sign_checkpoint([10u8; 32]).expect("sign");
    let early_recovery = session.export_recovery_state(&puf).expect("export early");

    session.sign_checkpoint([20u8; 32]).expect("sign");
    let late_recovery = session.export_recovery_state(&puf).expect("export late");

    // External system can detect replay via monotonic export_count
    assert!(early_recovery.export_count < late_recovery.export_count);
    assert_eq!(early_recovery.export_count, 1);
    assert_eq!(late_recovery.export_count, 2);
}

#[test]
fn test_recovery_export_count_preserved() {
    let puf = test_puf();
    let doc_hash = [1u8; 32];
    let mut session = start_session(&puf, doc_hash).expect("start");

    session.sign_checkpoint([10u8; 32]).expect("sign");
    let recovery = session.export_recovery_state(&puf).expect("export");
    assert_eq!(recovery.export_count, 1);

    let mut recovered = recover_session(&puf, &recovery, doc_hash).expect("recover");
    let re_export = recovered.export_recovery_state(&puf).expect("re-export");
    assert_eq!(re_export.export_count, 2);
}
