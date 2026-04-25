// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::DateTimeNanosExt;
use tempfile::TempDir;

fn test_hmac_key() -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(vec![0x42u8; 32])
}

fn create_test_event(file_path: &str, content_hash: [u8; 32]) -> SecureEvent {
    SecureEvent {
        id: None,
        device_id: [1u8; 16],
        machine_id: "test-machine".to_string(),
        timestamp_ns: chrono::Utc::now().timestamp_nanos_safe(),
        file_path: file_path.to_string(),
        content_hash,
        file_size: 1000,
        size_delta: 100,
        previous_hash: [0u8; 32],
        event_hash: [0u8; 32],
        context_type: Some("test".to_string()),
        context_note: Some("test note".to_string()),
        vdf_input: Some([0xAAu8; 32]),
        vdf_output: Some([0xBBu8; 32]),
        vdf_iterations: 1000,
        forensic_score: 0.95,
        is_paste: false,
        hardware_counter: None,
        input_method: None,
        lamport_signature: None,
        lamport_pubkey_fingerprint: None,
        challenge_nonce: None,
        hw_cosign_signature: None,
        hw_cosign_pubkey: None,
        hw_cosign_salt_commitment: None,
        hw_cosign_chain_index: None,
        hw_cosign_entangled_hash: None,
        hw_cosign_entropy_digest: None,
        hw_cosign_entropy_bytes: None,
        posme_proof: None,
    }
}

#[test]
fn test_store_open_and_init() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
    drop(store);

    let _store = SecureStore::open(&db_path, test_hmac_key()).expect("reopen store");
}

#[test]
fn test_insert_single_event() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
    let mut event = create_test_event("/test/file.txt", [1u8; 32]);

    store.add_secure_event(&mut event).expect("insert event");

    assert!(event.id.is_some());
    assert_ne!(event.event_hash, [0u8; 32]);
}

#[test]
fn test_insert_multiple_events_chain() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

    let mut event1 = create_test_event("/test/file.txt", [1u8; 32]);
    store.add_secure_event(&mut event1).expect("insert event 1");
    let hash1 = event1.event_hash;

    let mut event2 = create_test_event("/test/file.txt", [2u8; 32]);
    event2.timestamp_ns += 1_000_000;
    store.add_secure_event(&mut event2).expect("insert event 2");

    assert_eq!(event2.previous_hash, hash1);
}

#[test]
fn test_get_events_for_file() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

    let mut event1 = create_test_event("/test/file1.txt", [1u8; 32]);
    store.add_secure_event(&mut event1).expect("insert event 1");

    let mut event2 = create_test_event("/test/file2.txt", [2u8; 32]);
    event2.timestamp_ns += 1_000_000;
    store.add_secure_event(&mut event2).expect("insert event 2");

    let mut event3 = create_test_event("/test/file1.txt", [3u8; 32]);
    event3.timestamp_ns += 2_000_000;
    store.add_secure_event(&mut event3).expect("insert event 3");

    let file1_events = store
        .get_events_for_file("/test/file1.txt")
        .expect("get events");
    assert_eq!(file1_events.len(), 2);

    let file2_events = store
        .get_events_for_file("/test/file2.txt")
        .expect("get events");
    assert_eq!(file2_events.len(), 1);
}

#[test]
fn test_list_files() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

    let mut event1 = create_test_event("/test/file1.txt", [1u8; 32]);
    store.add_secure_event(&mut event1).expect("insert event 1");

    let mut event2 = create_test_event("/test/file2.txt", [2u8; 32]);
    event2.timestamp_ns += 1_000_000;
    store.add_secure_event(&mut event2).expect("insert event 2");

    let files = store.list_files().expect("list files");
    assert_eq!(files.len(), 2);
}

#[test]
fn test_update_baseline() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

    store
        .update_baseline("typing_speed", 100.0)
        .expect("update 1");
    store
        .update_baseline("typing_speed", 110.0)
        .expect("update 2");
    store
        .update_baseline("typing_speed", 90.0)
        .expect("update 3");

    let baselines = store.get_baselines().expect("get baselines");
    assert_eq!(baselines.len(), 1);

    let (name, mean, _std_dev) = &baselines[0];
    assert_eq!(name, "typing_speed");
    assert!(*mean > 90.0 && *mean < 110.0);
}

#[test]
fn test_baseline_multiple_signals() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

    store.update_baseline("signal_a", 50.0).expect("update a");
    store.update_baseline("signal_b", 100.0).expect("update b");

    let baselines = store.get_baselines().expect("get baselines");
    assert_eq!(baselines.len(), 2);
}

#[test]
fn test_integrity_verification_on_reopen() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    {
        let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
        let mut event = create_test_event("/test/file.txt", [1u8; 32]);
        store.add_secure_event(&mut event).expect("insert event");
    }

    let _store = SecureStore::open(&db_path, test_hmac_key()).expect("reopen store");
}

#[test]
fn test_wrong_hmac_key_fails_verification() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    {
        let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
        let mut event = create_test_event("/test/file.txt", [1u8; 32]);
        store.add_secure_event(&mut event).expect("insert event");
    }

    let wrong_key = zeroize::Zeroizing::new(vec![0xFFu8; 32]);
    let result = SecureStore::open(&db_path, wrong_key);
    assert!(result.is_err());
}

#[test]
fn test_event_with_optional_fields() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

    let mut event = SecureEvent {
        id: None,
        device_id: [1u8; 16],
        machine_id: "test".to_string(),
        timestamp_ns: chrono::Utc::now().timestamp_nanos_safe(),
        file_path: "/test.txt".to_string(),
        content_hash: [1u8; 32],
        file_size: 100,
        size_delta: 10,
        previous_hash: [0u8; 32],
        event_hash: [0u8; 32],
        context_type: None,
        context_note: None,
        vdf_input: None,
        vdf_output: None,
        vdf_iterations: 0,
        forensic_score: 1.0,
        is_paste: false,
        hardware_counter: None,
        input_method: None,
        lamport_signature: None,
        lamport_pubkey_fingerprint: None,
        challenge_nonce: None,
        hw_cosign_signature: None,
        hw_cosign_pubkey: None,
        hw_cosign_salt_commitment: None,
        hw_cosign_chain_index: None,
        hw_cosign_entangled_hash: None,
        hw_cosign_entropy_digest: None,
        hw_cosign_entropy_bytes: None,
        posme_proof: None,
    };

    store.add_secure_event(&mut event).expect("insert event");
    assert!(event.id.is_some());
}

#[test]
fn test_lamport_signature_roundtrip() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut event = create_test_event("/test/lamport.txt", [0xAA; 32]);

    store
        .add_secure_event_with_signer(&mut event, Some(&signing_key))
        .expect("insert signed event");

    assert!(event.lamport_signature.is_some());
    assert_eq!(
        event.lamport_signature.as_ref().expect("lamport sig").len(),
        8192
    );
    assert!(event.lamport_pubkey_fingerprint.is_some());
    assert_eq!(
        event
            .lamport_pubkey_fingerprint
            .as_ref()
            .expect("lamport fingerprint")
            .len(),
        8
    );

    let events = store
        .get_events_for_file("/test/lamport.txt")
        .expect("get events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].lamport_signature, event.lamport_signature);
    assert_eq!(
        events[0].lamport_pubkey_fingerprint,
        event.lamport_pubkey_fingerprint
    );
}

#[test]
fn test_lamport_signature_verifies() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);
    let mut event = create_test_event("/test/verify.txt", [0xBB; 32]);

    store
        .add_secure_event_with_signer(&mut event, Some(&signing_key))
        .expect("insert signed event");

    // Verify the Lamport signature by re-deriving the key
    let lamport_sig_bytes = event.lamport_signature.as_ref().expect("lamport sig");
    let lamport_sig = crate::crypto::lamport::LamportSignature::from_bytes(lamport_sig_bytes)
        .expect("parse lamport sig");

    // Re-derive the public key from the same seed
    let hk =
        hkdf::Hkdf::<sha2::Sha256>::new(Some(b"cpoe-lamport-event-v1"), &signing_key.to_bytes());
    let mut seed = [0u8; 32];
    hk.expand(&event.event_hash, &mut seed)
        .expect("hkdf expand");
    let (_privkey, pubkey) = crate::crypto::lamport::LamportPrivateKey::from_seed(&seed);

    assert!(pubkey.verify(&event.event_hash, &lamport_sig));
}

#[test]
fn test_paste_event() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

    let mut event = create_test_event("/test/file.txt", [1u8; 32]);
    event.is_paste = true;

    store.add_secure_event(&mut event).expect("insert event");

    let events = store
        .get_events_for_file("/test/file.txt")
        .expect("get events");
    assert_eq!(events.len(), 1);
    assert!(events[0].is_paste);
}

#[test]
fn test_negative_size_delta() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");

    let mut event = create_test_event("/test/file.txt", [1u8; 32]);
    event.size_delta = -500;

    store.add_secure_event(&mut event).expect("insert event");

    let events = store
        .get_events_for_file("/test/file.txt")
        .expect("get events");
    assert_eq!(events[0].size_delta, -500);
}

#[test]
fn test_empty_file_list() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
    let files = store.list_files().expect("list files");
    assert!(files.is_empty());
}

#[test]
fn test_empty_baselines() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
    let baselines = store.get_baselines().expect("get baselines");
    assert!(baselines.is_empty());
}

#[test]
fn test_events_for_nonexistent_file() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
    let events = store
        .get_events_for_file("/nonexistent.txt")
        .expect("get events");
    assert!(events.is_empty());
}

#[test]
fn test_event_ordering() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("test.db");

    let mut store = SecureStore::open(&db_path, test_hmac_key()).expect("open store");
    let base_ts = chrono::Utc::now().timestamp_nanos_safe();

    for i in 0..5 {
        let mut event = create_test_event("/test/file.txt", [(i + 1) as u8; 32]);
        event.timestamp_ns = base_ts + (i as i64 * 1_000_000);
        store.add_secure_event(&mut event).expect("insert event");
    }

    let events = store
        .get_events_for_file("/test/file.txt")
        .expect("get events");
    assert_eq!(events.len(), 5);

    for i in 1..events.len() {
        assert!(events[i].id > events[i - 1].id);
    }
}
