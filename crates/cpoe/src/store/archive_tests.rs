// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::store::archive::ArchiveResult;
use crate::DateTimeNanosExt;
use tempfile::TempDir;

fn test_hmac_key() -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(vec![0x42u8; 32])
}

fn create_event_at(file_path: &str, content_hash: [u8; 32], timestamp_ns: i64) -> SecureEvent {
    SecureEvent {
        id: None,
        device_id: [1u8; 16],
        machine_id: "test-machine".to_string(),
        timestamp_ns,
        file_path: file_path.to_string(),
        content_hash,
        file_size: 1000,
        size_delta: 100,
        previous_hash: [0u8; 32],
        event_hash: [0u8; 32],
        context_type: Some("test".to_string()),
        context_note: None,
        vdf_input: None,
        vdf_output: None,
        vdf_iterations: 0,
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
        semantic_summary: None,
    }
}

/// Helper: insert events spread across time (some old, some recent).
fn populate_store_with_old_and_new(
    store: &mut SecureStore,
    old_count: usize,
    new_count: usize,
) -> (i64, i64) {
    let now_ns = chrono::Utc::now().timestamp_nanos_safe();
    let day_ns = 86400i64 * 1_000_000_000;

    // Old events: 120 days ago
    let old_base = now_ns - 120 * day_ns;
    for i in 0..old_count {
        let mut e = create_event_at(
            "/test/doc.txt",
            [(i as u8).wrapping_add(1); 32],
            old_base + (i as i64) * 1_000_000,
        );
        store.add_secure_event(&mut e).expect("insert old event");
    }

    // New events: 30 days ago
    let new_base = now_ns - 30 * day_ns;
    for i in 0..new_count {
        let mut e = create_event_at(
            "/test/doc.txt",
            [(i as u8).wrapping_add(100); 32],
            new_base + (i as i64) * 1_000_000,
        );
        store.add_secure_event(&mut e).expect("insert new event");
    }

    (old_base, new_base)
}

#[test]
fn test_needs_archival_below_threshold() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    assert!(!store.needs_archival().unwrap());
}

#[test]
fn test_archive_no_old_events() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    // Insert only recent events.
    let now_ns = chrono::Utc::now().timestamp_nanos_safe();
    for i in 0..5 {
        let mut e = create_event_at("/test/file.txt", [i + 1; 32], now_ns + i as i64 * 1_000_000);
        store.add_secure_event(&mut e).unwrap();
    }

    let result = store.archive_old_events(&db_path, Some(90)).unwrap();
    assert!(result.is_none(), "No events should qualify for archival");
}

#[test]
fn test_archive_moves_old_events() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    populate_store_with_old_and_new(&mut store, 10, 5);

    let result = store.archive_old_events(&db_path, Some(90)).unwrap();
    assert!(result.is_some());
    let r = result.unwrap();

    assert_eq!(r.events_archived, 10);
    assert!(r.archive_path.exists());

    // Active DB should only have the 5 new events.
    let remaining = store.get_events_for_file("/test/doc.txt").unwrap();
    assert_eq!(remaining.len(), 5);
}

#[test]
fn test_archive_preserves_hmac_integrity() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    populate_store_with_old_and_new(&mut store, 10, 5);

    let result = store.archive_old_events(&db_path, Some(90)).unwrap().unwrap();

    // Query the archive and verify HMAC integrity holds.
    let now_ns = chrono::Utc::now().timestamp_nanos_safe();
    let events = SecureStore::query_archive(
        &result.archive_path,
        &test_hmac_key(),
        "/test/doc.txt",
        0,
        now_ns,
    )
    .unwrap();

    assert_eq!(events.len(), 10);
}

#[test]
fn test_archive_hmac_tamper_detected() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    populate_store_with_old_and_new(&mut store, 5, 3);

    let result = store.archive_old_events(&db_path, Some(90)).unwrap().unwrap();

    // Query with wrong HMAC key should fail.
    let wrong_key = zeroize::Zeroizing::new(vec![0xFFu8; 32]);
    let now_ns = chrono::Utc::now().timestamp_nanos_safe();
    let err = SecureStore::query_archive(
        &result.archive_path,
        &wrong_key,
        "/test/doc.txt",
        0,
        now_ns,
    );

    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("HMAC mismatch"));
}

#[test]
fn test_archive_chain_continuity() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    populate_store_with_old_and_new(&mut store, 10, 5);

    // Get the last old event's hash before archiving.
    let all_events_before = store.get_events_for_file("/test/doc.txt").unwrap();
    let last_old_hash = all_events_before[9].event_hash;
    let first_new_prev_hash = all_events_before[10].previous_hash;
    assert_eq!(last_old_hash, first_new_prev_hash);

    let result = store.archive_old_events(&db_path, Some(90)).unwrap().unwrap();

    // Chain link hash should be the last archived event's hash.
    assert_eq!(result.chain_link_hash, last_old_hash);

    // The first remaining event's previous_hash should still point to the archive's last hash.
    let remaining = store.get_events_for_file("/test/doc.txt").unwrap();
    assert_eq!(remaining[0].previous_hash, result.chain_link_hash);

    // Verify chain link.
    assert!(store.verify_archive_chain_link(&result.archive_path).unwrap());
}

#[test]
fn test_archive_active_db_integrity_after() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    populate_store_with_old_and_new(&mut store, 8, 4);

    store.archive_old_events(&db_path, Some(90)).unwrap();
    drop(store);

    // Re-open and verify integrity passes.
    let store = SecureStore::open(&db_path, test_hmac_key()).unwrap();
    let events = store.get_events_for_file("/test/doc.txt").unwrap();
    assert_eq!(events.len(), 4);
}

#[test]
fn test_query_spanning_both_dbs() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    let (old_base, new_base) = populate_store_with_old_and_new(&mut store, 10, 5);

    store.archive_old_events(&db_path, Some(90)).unwrap();

    // Query spanning the full range should return all 15 events.
    let all = store.query_spanning(&db_path, "/test/doc.txt", 0, i64::MAX).unwrap();
    assert_eq!(all.len(), 15);

    // Query only old range should return 10 from archive.
    let old_only = store
        .query_spanning(&db_path, "/test/doc.txt", old_base, old_base + 20_000_000)
        .unwrap();
    assert_eq!(old_only.len(), 10);

    // Query only new range should return 5 from active.
    let new_only = store
        .query_spanning(&db_path, "/test/doc.txt", new_base, new_base + 20_000_000)
        .unwrap();
    assert_eq!(new_only.len(), 5);
}

#[test]
fn test_list_archives() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    populate_store_with_old_and_new(&mut store, 5, 3);
    store.archive_old_events(&db_path, Some(90)).unwrap();

    let archives = SecureStore::list_archives(&db_path).unwrap();
    assert_eq!(archives.len(), 1);
    assert!(archives[0]
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("events_archive_"));
}

#[test]
fn test_archive_zero_age_days_rejected() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    let result = store.archive_old_events(&db_path, Some(0));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("must be > 0"));
}

#[test]
fn test_archive_duplicate_same_day_rejected() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    populate_store_with_old_and_new(&mut store, 10, 5);
    store.archive_old_events(&db_path, Some(90)).unwrap();

    // Add more old events and try again same day.
    let now_ns = chrono::Utc::now().timestamp_nanos_safe();
    let day_ns = 86400i64 * 1_000_000_000;
    let old_ts = now_ns - 100 * day_ns;
    for i in 0..3u8 {
        let mut e = create_event_at("/test/doc.txt", [200 + i; 32], old_ts + i as i64 * 1_000_000);
        store.add_secure_event(&mut e).unwrap();
    }

    let result = store.archive_old_events(&db_path, Some(90));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already exists"));
}

#[test]
fn test_archive_read_only_permission() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    populate_store_with_old_and_new(&mut store, 5, 3);
    let result = store.archive_old_events(&db_path, Some(90)).unwrap().unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&result.archive_path).unwrap().permissions();
        let mode = perms.mode() & 0o777;
        assert_eq!(mode, 0o444, "Archive should be read-only");
    }
}

#[test]
fn test_archive_hash_chain_in_archive_valid() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    populate_store_with_old_and_new(&mut store, 10, 5);
    let result = store.archive_old_events(&db_path, Some(90)).unwrap().unwrap();

    // Open archive and verify internal chain continuity.
    let now_ns = chrono::Utc::now().timestamp_nanos_safe();
    let events = SecureStore::query_archive(
        &result.archive_path,
        &test_hmac_key(),
        "/test/doc.txt",
        0,
        now_ns,
    )
    .unwrap();

    // First event should have zero previous_hash (genesis).
    assert_eq!(events[0].previous_hash, [0u8; 32]);

    // Each subsequent event's previous_hash should match the prior event's event_hash.
    for i in 1..events.len() {
        assert_eq!(
            events[i].previous_hash, events[i - 1].event_hash,
            "Chain break at archive event index {i}"
        );
    }
}

#[test]
fn test_query_spanning_empty_archive() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    let now_ns = chrono::Utc::now().timestamp_nanos_safe();
    for i in 0..5u8 {
        let mut e = create_event_at("/test/file.txt", [i + 1; 32], now_ns + i as i64 * 1_000_000);
        store.add_secure_event(&mut e).unwrap();
    }

    // No archives exist, spanning query should still work.
    let events = store.query_spanning(&db_path, "/test/file.txt", 0, i64::MAX).unwrap();
    assert_eq!(events.len(), 5);
}

#[test]
fn test_multiple_files_across_archive_boundary() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let mut store = SecureStore::open(&db_path, test_hmac_key()).unwrap();

    let now_ns = chrono::Utc::now().timestamp_nanos_safe();
    let day_ns = 86400i64 * 1_000_000_000;

    // Old events for two files.
    let old_ts = now_ns - 120 * day_ns;
    for i in 0..5u8 {
        let mut e = create_event_at("/test/a.txt", [i + 1; 32], old_ts + i as i64 * 1_000_000);
        store.add_secure_event(&mut e).unwrap();
    }
    for i in 0..3u8 {
        let mut e = create_event_at(
            "/test/b.txt",
            [i + 50; 32],
            old_ts + (i as i64 + 10) * 1_000_000,
        );
        store.add_secure_event(&mut e).unwrap();
    }

    // New events.
    let new_ts = now_ns - 10 * day_ns;
    for i in 0..2u8 {
        let mut e = create_event_at("/test/a.txt", [i + 200; 32], new_ts + i as i64 * 1_000_000);
        store.add_secure_event(&mut e).unwrap();
    }

    store.archive_old_events(&db_path, Some(90)).unwrap();

    // Query spanning for file a: 5 old + 2 new = 7.
    let a_events = store.query_spanning(&db_path, "/test/a.txt", 0, i64::MAX).unwrap();
    assert_eq!(a_events.len(), 7);

    // Query spanning for file b: 3 old + 0 new = 3.
    let b_events = store.query_spanning(&db_path, "/test/b.txt", 0, i64::MAX).unwrap();
    assert_eq!(b_events.len(), 3);

    // Active DB should only have the 2 new events for file a.
    let active_a = store.get_events_for_file("/test/a.txt").unwrap();
    assert_eq!(active_a.len(), 2);
    let active_b = store.get_events_for_file("/test/b.txt").unwrap();
    assert_eq!(active_b.len(), 0);
}
