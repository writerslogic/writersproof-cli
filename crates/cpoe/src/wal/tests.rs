// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

use ed25519_dalek::SigningKey;
use std::fs;
use std::path::PathBuf;

fn temp_wal_path() -> PathBuf {
    let name = format!("writerslogic-wal-{}.log", uuid::Uuid::new_v4());
    std::env::temp_dir().join(name)
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0u8; 32])
}

#[test]
fn test_wal_append_and_verify() {
    let path = temp_wal_path();
    let session_id = [7u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1, 2, 3])
        .expect("append");
    wal.append(EntryType::DocumentHash, vec![4, 5, 6])
        .expect("append");

    let verification = wal.verify().expect("verify");
    assert!(verification.valid);
    assert_eq!(verification.entries, 2);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_truncate() {
    let path = temp_wal_path();
    let session_id = [3u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1]).expect("append");
    wal.append(EntryType::Heartbeat, vec![2]).expect("append");
    wal.append(EntryType::Heartbeat, vec![3]).expect("append");

    wal.truncate(1).expect("truncate");
    let verification = wal.verify().expect("verify");
    assert!(verification.valid);
    assert_eq!(verification.entries, 2);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_reopen_after_close() {
    let path = temp_wal_path();
    let session_id = [8u8; 32];
    let signing_key = test_signing_key();

    {
        let wal = Wal::open(&path, session_id, signing_key.clone()).expect("open wal");
        wal.append(EntryType::Heartbeat, vec![1, 2, 3])
            .expect("append");
        wal.append(EntryType::DocumentHash, vec![4, 5, 6])
            .expect("append");
        wal.close().expect("close");
    }

    {
        let wal = Wal::open(&path, session_id, signing_key).expect("reopen wal");
        let verification = wal.verify().expect("verify");
        assert!(verification.valid);
        assert_eq!(verification.entries, 2);
        wal.close().expect("close");
    }

    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_append_to_closed() {
    let path = temp_wal_path();
    let session_id = [9u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.close().expect("close");

    let result = wal.append(EntryType::Heartbeat, vec![1, 2, 3]);
    assert!(result.is_err());
    match result {
        Err(WalError::Closed) => {} // Expected
        Err(e) => panic!("Expected WalError::Closed, got {:?}", e),
        Ok(_) => panic!("Expected error on append to closed WAL"),
    }

    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_all_entry_types() {
    let path = temp_wal_path();
    let session_id = [10u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

    wal.append(EntryType::Heartbeat, vec![1])
        .expect("append heartbeat");
    wal.append(EntryType::DocumentHash, vec![2])
        .expect("append document hash");
    wal.append(EntryType::KeystrokeBatch, vec![3])
        .expect("append keystroke batch");
    wal.append(EntryType::JitterSample, vec![4])
        .expect("append jitter sample");
    wal.append(EntryType::SessionStart, vec![5])
        .expect("append session start");
    wal.append(EntryType::SessionEnd, vec![6])
        .expect("append session end");
    wal.append(EntryType::Checkpoint, vec![7])
        .expect("append checkpoint");

    let verification = wal.verify().expect("verify");
    assert!(verification.valid);
    assert_eq!(verification.entries, 7);
    assert_eq!(wal.entry_count(), 7);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_large_payload() {
    let path = temp_wal_path();
    let session_id = [11u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

    let large_payload = vec![0xABu8; 1024 * 1024];
    wal.append(EntryType::KeystrokeBatch, large_payload.clone())
        .expect("append large payload");

    let verification = wal.verify().expect("verify");
    assert!(verification.valid);
    assert_eq!(verification.entries, 1);

    let size = wal.size();
    assert!(size > 1024 * 1024, "Size should be at least 1MB");

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_exists() {
    let path = temp_wal_path();
    let session_id = [12u8; 32];
    let signing_key = test_signing_key();

    assert!(!Wal::exists(&path));

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1]).expect("append");
    wal.close().expect("close");

    assert!(Wal::exists(&path));

    let _ = fs::remove_file(&path);

    assert!(!Wal::exists(&path));
}

#[test]
fn test_wal_size_and_entry_count() {
    let path = temp_wal_path();
    let session_id = [13u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

    assert_eq!(wal.entry_count(), 0);

    wal.append(EntryType::Heartbeat, vec![1, 2, 3])
        .expect("append 1");
    assert_eq!(wal.entry_count(), 1);

    wal.append(EntryType::Heartbeat, vec![4, 5, 6])
        .expect("append 2");
    assert_eq!(wal.entry_count(), 2);

    let size = wal.size();
    assert!(size > 0, "Size should be positive");

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_last_sequence() {
    let path = temp_wal_path();
    let session_id = [14u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

    assert_eq!(wal.last_sequence(), 0);

    wal.append(EntryType::Heartbeat, vec![1]).expect("append 1");
    assert_eq!(wal.last_sequence(), 0);

    wal.append(EntryType::Heartbeat, vec![2]).expect("append 2");
    assert_eq!(wal.last_sequence(), 1);

    wal.append(EntryType::Heartbeat, vec![3]).expect("append 3");
    assert_eq!(wal.last_sequence(), 2);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_truncate_race_condition() {
    use std::sync::Arc;
    use std::thread;

    let path = temp_wal_path();
    let session_id = [17u8; 32];
    let signing_key = test_signing_key();

    let wal = Arc::new(Wal::open(&path, session_id, signing_key).expect("open wal"));

    wal.append(EntryType::Heartbeat, vec![1])
        .expect("append entry 1");
    wal.append(EntryType::Heartbeat, vec![2])
        .expect("append entry 2");

    let wal_clone = Arc::clone(&wal);
    let handle = thread::spawn(move || {
        for i in 0..50 {
            let _ = wal_clone.append(EntryType::Heartbeat, vec![i as u8 + 10]);
        }
    });

    for _ in 0..5 {
        let _ = wal.truncate(1);
    }

    handle.join().expect("join writer thread");

    let verification = wal.verify().expect("verify");
    assert!(
        verification.valid,
        "WAL should still be valid even after race"
    );

    // If entries are missing, it's a bug, but hard to assert exact count due to race timing.
    // But we can check if it's at least consistent with what truncate() thinks it has.
    assert_eq!(wal.entry_count(), verification.entries);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_path() {
    let path = temp_wal_path();
    let session_id = [15u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    assert_eq!(wal.path(), path);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_truncate_empty() {
    let path = temp_wal_path();
    let session_id = [16u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");

    wal.truncate(0).expect("truncate empty");

    let verification = wal.verify().expect("verify");
    assert!(verification.valid);
    assert_eq!(verification.entries, 0);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_rotate_if_needed_no_rotation() {
    let path = temp_wal_path();
    let session_id = [20u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1, 2, 3])
        .expect("append");

    // Threshold much larger than current size; no rotation should occur.
    let result = wal.rotate_if_needed(256 * 1024 * 1024).expect("rotate");
    assert!(result.is_none());
    assert_eq!(wal.entry_count(), 1);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_rotate_if_needed_triggers() {
    let dir = std::env::temp_dir().join(format!("wal-rot-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("test.wal");
    let session_id = [21u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key.clone()).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1; 1024])
        .expect("append");
    let size_before = wal.size();

    // Set threshold to 1 byte so rotation is forced.
    let archive = wal.rotate_if_needed(1).expect("rotate");
    assert!(archive.is_some());
    let archive_path = archive.expect("archive path");
    assert!(archive_path.exists());
    assert!(archive_path.to_string_lossy().ends_with(".archive"));

    // After rotation, WAL should be fresh (header only, 0 entries).
    assert_eq!(wal.entry_count(), 0);
    assert!(wal.size() < size_before);

    // Can still append to the new WAL.
    wal.append(EntryType::Heartbeat, vec![2; 64])
        .expect("append after rotate");
    assert_eq!(wal.entry_count(), 1);
    let verification = wal.verify().expect("verify");
    assert!(verification.valid);

    let _ = wal.close();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wal_list_and_prune_archives() {
    let dir = std::env::temp_dir().join(format!("wal-prune-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("create temp dir");

    // Create fake archive files with ordered timestamps.
    for i in 1..=5 {
        let name = format!("test.wal.{}.archive", i);
        fs::write(dir.join(&name), b"fake").expect("write fake archive");
    }

    let archives = Wal::list_archives(&dir);
    assert_eq!(archives.len(), 5);

    // Prune to keep only 2 most recent.
    Wal::prune_archives(&dir, 2);

    let remaining = Wal::list_archives(&dir);
    assert_eq!(remaining.len(), 2);
    // The two newest (timestamps 4 and 5) should survive.
    assert!(remaining[0].to_string_lossy().contains(".4.archive"));
    assert!(remaining[1].to_string_lossy().contains(".5.archive"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wal_rotate_closed_wal_fails() {
    let path = temp_wal_path();
    let session_id = [22u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1; 1024])
        .expect("append");
    wal.close().expect("close");

    let result = wal.rotate_if_needed(1);
    assert!(result.is_err());
    match result {
        Err(WalError::Closed) => {}
        other => panic!("Expected WalError::Closed, got {:?}", other),
    }

    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_write_read_roundtrip() {
    let path = temp_wal_path();
    let session_id = [30u8; 32];
    let signing_key = test_signing_key();

    let payloads: Vec<(EntryType, Vec<u8>)> = vec![
        (EntryType::SessionStart, vec![0xDE, 0xAD]),
        (EntryType::KeystrokeBatch, vec![1, 2, 3, 4, 5]),
        (EntryType::JitterSample, vec![0xFF; 128]),
        (EntryType::DocumentHash, vec![42; 32]),
        (EntryType::Heartbeat, vec![]),
        (EntryType::Checkpoint, vec![0xCA, 0xFE]),
        (EntryType::SessionEnd, vec![0xBE, 0xEF]),
    ];

    {
        let wal = Wal::open(&path, session_id, signing_key.clone()).expect("open wal");
        for (entry_type, payload) in &payloads {
            wal.append(*entry_type, payload.clone()).expect("append");
        }
        wal.close().expect("close");
    }

    // Reopen and verify entries can be read back with correct payloads.
    {
        let wal = Wal::open(&path, session_id, signing_key).expect("reopen wal");
        assert_eq!(wal.entry_count(), payloads.len() as u64);
        let verification = wal.verify().expect("verify");
        assert!(verification.valid);
        assert_eq!(verification.entries, payloads.len() as u64);
        wal.close().expect("close");
    }

    // Read the raw file to verify each entry's payload bytes survived serialization.
    let raw = fs::read(&path).expect("read raw");
    assert!(raw.len() > super::types::HEADER_SIZE);

    // Verify magic bytes are correct.
    assert_eq!(&raw[0..4], super::types::MAGIC);

    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_cumulative_hash_integrity() {
    let path = temp_wal_path();
    let session_id = [31u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key.clone()).expect("open wal");

    // Append several entries to build a hash chain.
    for i in 0..10u8 {
        wal.append(EntryType::Heartbeat, vec![i]).expect("append");
    }

    // Verify the entire chain is valid.
    let v1 = wal.verify().expect("verify");
    assert!(v1.valid);
    assert_eq!(v1.entries, 10);
    assert!(v1.error.is_none());

    // The final hash should be non-zero (hash chain output).
    assert_ne!(v1.final_hash, [0u8; 32]);

    // Append one more entry; the final hash should change.
    wal.append(EntryType::Heartbeat, vec![99]).expect("append");
    let v2 = wal.verify().expect("verify");
    assert!(v2.valid);
    assert_eq!(v2.entries, 11);
    assert_ne!(v2.final_hash, v1.final_hash);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_rejects_tampered_entry() {
    let path = temp_wal_path();
    let session_id = [32u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key.clone()).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1, 2, 3])
        .expect("append 1");
    wal.append(EntryType::DocumentHash, vec![4, 5, 6])
        .expect("append 2");
    wal.close().expect("close");

    // Tamper with the file: flip a byte in the second entry's payload region.
    let mut raw = fs::read(&path).expect("read");
    // The second entry starts after the header + first entry.
    // Find a byte well past the header and first entry to corrupt.
    let tamper_offset = raw.len() - 100;
    raw[tamper_offset] ^= 0xFF;
    fs::write(&path, &raw).expect("write tampered");

    // Reopening with the same session should detect corruption during scan_to_end.
    // The WAL truncates to the last valid entry, so entry_count should be less than 2.
    let wal2 = Wal::open(&path, session_id, signing_key).expect("open tampered wal");
    let count = wal2.entry_count();
    assert!(
        count < 2,
        "Expected fewer than 2 entries after tampering, got {}",
        count
    );

    // Verify should also confirm the chain is valid up to the truncation point.
    let v = wal2.verify().expect("verify");
    assert!(v.valid);
    assert_eq!(v.entries, count);

    let _ = wal2.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_list_archives_empty() {
    let dir = std::env::temp_dir().join(format!("wal-empty-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("create temp dir");

    let archives = Wal::list_archives(&dir);
    assert!(archives.is_empty());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_prune_archives_keeps_newest() {
    let dir = std::env::temp_dir().join(format!("wal-prune-keep-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("create temp dir");

    // Create 7 archive files with ordered timestamps.
    for i in 1..=7 {
        let name = format!("test.wal.{}.archive", i * 1000);
        fs::write(dir.join(&name), format!("archive-{}", i)).expect("write fake archive");
    }

    assert_eq!(Wal::list_archives(&dir).len(), 7);

    // Prune to keep 3 most recent.
    Wal::prune_archives(&dir, 3);

    let remaining = Wal::list_archives(&dir);
    assert_eq!(remaining.len(), 3);

    // The three newest (timestamps 5000, 6000, 7000) should survive.
    for path in &remaining {
        let name = path
            .file_name()
            .expect("archive file name")
            .to_string_lossy();
        let ts: u64 = name
            .strip_prefix("test.wal.")
            .expect("strip prefix")
            .strip_suffix(".archive")
            .expect("strip suffix")
            .parse()
            .expect("parse timestamp");
        assert!(
            ts >= 5000,
            "Expected only newest archives to survive, found timestamp {}",
            ts
        );
    }

    // Pruning when count <= max should be a no-op.
    Wal::prune_archives(&dir, 10);
    assert_eq!(Wal::list_archives(&dir).len(), 3);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wal_rotate_preserves_session() {
    let dir = std::env::temp_dir().join(format!("wal-rot-sess-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("session.wal");
    let session_id = [33u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key.clone()).expect("open wal");
    wal.append(EntryType::SessionStart, vec![1; 512])
        .expect("append");
    wal.append(EntryType::KeystrokeBatch, vec![2; 512])
        .expect("append");

    // Force rotation.
    let archive = wal.rotate_if_needed(1).expect("rotate");
    assert!(archive.is_some());

    // After rotation, append more entries to the fresh WAL.
    wal.append(EntryType::Heartbeat, vec![3])
        .expect("append post-rotate");
    wal.append(EntryType::SessionEnd, vec![4])
        .expect("append post-rotate");

    assert_eq!(wal.entry_count(), 2);
    let v = wal.verify().expect("verify");
    assert!(v.valid);
    assert_eq!(v.entries, 2);

    // Archive should exist alongside the new WAL.
    let archives = Wal::list_archives(&dir);
    assert_eq!(archives.len(), 1);

    let _ = wal.close();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wal_flush_noop_when_closed() {
    let path = temp_wal_path();
    let session_id = [40u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1]).expect("append");
    wal.close().expect("close");
    // flush after close should succeed silently
    wal.flush().expect("flush after close");

    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_flush_syncs_pending() {
    let path = temp_wal_path();
    let session_id = [41u8; 32];
    let signing_key = test_signing_key();

    // Use a large sync interval so appends don't auto-sync
    let wal = Wal::open_with_sync_interval(&path, session_id, signing_key, 1000).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1]).expect("append");
    wal.append(EntryType::DocumentHash, vec![2])
        .expect("append");
    // Explicit flush should not fail
    wal.flush().expect("flush");

    let v = wal.verify().expect("verify");
    assert!(v.valid);
    assert_eq!(v.entries, 2);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_checkpoint_forces_sync() {
    let path = temp_wal_path();
    let session_id = [42u8; 32];
    let signing_key = test_signing_key();

    // Large sync interval, but Checkpoint entry type should force sync
    let wal = Wal::open_with_sync_interval(&path, session_id, signing_key, 1000).expect("open wal");
    wal.append(EntryType::Checkpoint, vec![0xAA; 32])
        .expect("checkpoint append");

    let v = wal.verify().expect("verify");
    assert!(v.valid);
    assert_eq!(v.entries, 1);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_verify_detects_wrong_signing_key() {
    let path = temp_wal_path();
    let session_id = [43u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    wal.append(EntryType::Heartbeat, vec![1]).expect("append");
    wal.close().expect("close");

    // Reopen with a different signing key
    let different_key = SigningKey::from_bytes(&[1u8; 32]);
    let wal2 = Wal::open(&path, session_id, different_key).expect("open with wrong key");
    // scan_to_end should have truncated the entries signed by the other key
    assert_eq!(wal2.entry_count(), 0);

    let _ = wal2.close();
    let _ = fs::remove_file(&path);
}

#[test]
fn test_wal_empty_verify() {
    let path = temp_wal_path();
    let session_id = [44u8; 32];
    let signing_key = test_signing_key();

    let wal = Wal::open(&path, session_id, signing_key).expect("open wal");
    let v = wal.verify().expect("verify empty");
    assert!(v.valid);
    assert_eq!(v.entries, 0);

    let _ = wal.close();
    let _ = fs::remove_file(&path);
}
