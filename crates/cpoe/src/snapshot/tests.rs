// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42u8; 32])
}

fn open_test_store(dir: &TempDir) -> SnapshotStore {
    let db_path = dir.path().join("snapshots.db");
    SnapshotStore::open(&db_path, &test_signing_key()).expect("open snapshot store")
}

// --- Store basics ---

#[test]
fn open_and_reopen() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("snapshots.db");
    {
        let _store = SnapshotStore::open(&db_path, &test_signing_key()).unwrap();
    }
    let _store = SnapshotStore::open(&db_path, &test_signing_key()).unwrap();
}

#[test]
fn save_and_get_roundtrip() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    let text = "The quick brown fox jumps over the lazy dog.";
    let id = store.save("/test/doc.txt", text, false).unwrap();

    let retrieved = store.get(id).unwrap();
    assert_eq!(retrieved, text);
}

#[test]
fn save_empty_document() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    let id = store.save("/test/empty.txt", "", false).unwrap();
    let retrieved = store.get(id).unwrap();
    assert_eq!(retrieved, "");
}

#[test]
fn save_large_document() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    let text = "word ".repeat(100_000); // ~500KB
    let id = store.save("/test/large.txt", &text, false).unwrap();
    let retrieved = store.get(id).unwrap();
    assert_eq!(retrieved, text);
}

// --- Encrypted at rest ---

#[test]
fn blob_is_encrypted_at_rest() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    let text = "This is sensitive content that must be encrypted at rest.";
    store.save("/test/secret.txt", text, false).unwrap();

    // Read the raw encrypted_data from the blob table
    let encrypted: Vec<u8> = store
        .conn
        .query_row(
            "SELECT encrypted_data FROM snapshot_blobs LIMIT 1",
            [],
            |row: &rusqlite::Row| row.get(0),
        )
        .unwrap();

    // The raw blob must not contain the plaintext
    let plaintext_bytes = text.as_bytes();
    assert_ne!(encrypted, plaintext_bytes);
    // Check that plaintext substring doesn't appear in encrypted data
    assert!(
        !encrypted
            .windows(plaintext_bytes.len())
            .any(|w| w == plaintext_bytes),
        "plaintext found in encrypted blob"
    );
}

#[test]
fn encrypt_rejects_mismatched_hash() {
    let key = [0x42u8; 32];
    let plaintext = b"hello world";
    let wrong_hash = [0xFFu8; 32]; // doesn't match SHA-256("hello world")
    let result = crypto::encrypt_blob(&key, &wrong_hash, plaintext);
    assert!(result.is_err(), "should reject mismatched content hash");
    assert!(
        result.unwrap_err().contains("content hash does not match"),
        "error should mention hash mismatch"
    );
}

#[test]
fn wrong_key_cannot_decrypt() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("snapshots.db");

    let key1 = SigningKey::from_bytes(&[0x42u8; 32]);
    let key2 = SigningKey::from_bytes(&[0x99u8; 32]);

    let id = {
        let mut store = SnapshotStore::open(&db_path, &key1).unwrap();
        store.save("/test/doc.txt", "secret text", false).unwrap()
    };

    let store2 = SnapshotStore::open(&db_path, &key2).unwrap();
    let result = store2.get(id);
    assert!(result.is_err(), "decryption with wrong key should fail");
}

// --- Content-addressable dedup ---

#[test]
fn dedup_identical_content() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    let text = "duplicate content";
    let id1 = store.save("/test/doc.txt", text, false).unwrap();
    let id2 = store.save("/test/doc.txt", text, false).unwrap();

    // Two meta entries, one blob
    assert_ne!(id1, id2);

    let blob_count: i64 = store
        .conn
        .query_row("SELECT COUNT(*) FROM snapshot_blobs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(blob_count, 1);

    let meta_count: i64 = store
        .conn
        .query_row("SELECT COUNT(*) FROM snapshot_meta", [], |row| row.get(0))
        .unwrap();
    assert_eq!(meta_count, 2);
}

#[test]
fn different_content_creates_different_blobs() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    store.save("/test/doc.txt", "version one", false).unwrap();
    store.save("/test/doc.txt", "version two", false).unwrap();

    let blob_count: i64 = store
        .conn
        .query_row("SELECT COUNT(*) FROM snapshot_blobs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(blob_count, 2);
}

// --- Word count ---

#[test]
fn word_count_tracked() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    store.save("/test/doc.txt", "one two three", false).unwrap();
    let entries = store.list("/test/doc.txt").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].word_count, 3);
}

#[test]
fn word_count_delta_computed() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    store.save("/test/doc.txt", "one two three", false).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    store
        .save("/test/doc.txt", "one two three four five", false)
        .unwrap();

    let entries = store.list("/test/doc.txt").unwrap();
    // Newest first
    assert_eq!(entries[0].word_count, 5);
    assert_eq!(entries[0].word_count_delta, 2); // 5 - 3
    assert_eq!(entries[1].word_count, 3);
    assert_eq!(entries[1].word_count_delta, 3); // first snapshot delta = word_count
}

// --- Session grouping ---

#[test]
fn single_session_group() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    store.save("/test/doc.txt", "v1", false).unwrap();
    store.save("/test/doc.txt", "v2", false).unwrap();
    store.save("/test/doc.txt", "v3", false).unwrap();

    let entries = store.list("/test/doc.txt").unwrap();
    for e in &entries {
        assert_eq!(e.session_group, 0, "all within same session");
    }
}

#[test]
fn session_boundary_on_time_gap() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    // Insert with manual timestamps to simulate a 30+ min gap
    let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let gap_ns: i64 = 31 * 60 * 1_000_000_000; // 31 minutes

    insert_with_timestamp(&mut store, "/test/doc.txt", "session1-a", now_ns);
    insert_with_timestamp(
        &mut store,
        "/test/doc.txt",
        "session1-b",
        now_ns + 1_000_000_000,
    );
    insert_with_timestamp(&mut store, "/test/doc.txt", "session2-a", now_ns + gap_ns);
    insert_with_timestamp(
        &mut store,
        "/test/doc.txt",
        "session2-b",
        now_ns + gap_ns + 1_000_000_000,
    );

    let entries = store.list("/test/doc.txt").unwrap();
    assert_eq!(entries.len(), 4);

    // Entries are newest-first, so session2 comes first
    assert_eq!(entries[0].session_group, 1);
    assert_eq!(entries[1].session_group, 1);
    assert_eq!(entries[2].session_group, 0);
    assert_eq!(entries[3].session_group, 0);
}

fn insert_with_timestamp(store: &mut SnapshotStore, path: &str, text: &str, ts_ns: i64) {
    let plaintext_bytes = text.as_bytes();
    let content_hash: [u8; 32] = Sha256::digest(plaintext_bytes).into();
    let word_count = text.split_whitespace().count() as i32;

    let blob_exists: bool = store
        .conn
        .query_row(
            "SELECT 1 FROM snapshot_blobs WHERE content_hash = ?",
            rusqlite::params![&content_hash[..]],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if !blob_exists {
        let encrypted =
            crypto::encrypt_blob(&store.signing_key_bytes, &content_hash, plaintext_bytes).unwrap();
        store
            .conn
            .execute(
                "INSERT INTO snapshot_blobs (content_hash, encrypted_data, original_size, compressed_size)
                 VALUES (?, ?, ?, ?)",
                rusqlite::params![
                    &content_hash[..],
                    &encrypted,
                    plaintext_bytes.len() as i64,
                    encrypted.len() as i64,
                ],
            )
            .unwrap();
    }

    store
        .conn
        .execute(
            "INSERT INTO snapshot_meta (document_path, content_hash, timestamp_ns, word_count, is_restore)
             VALUES (?, ?, ?, ?, 0)",
            rusqlite::params![path, &content_hash[..], ts_ns, word_count],
        )
        .unwrap();
}

// --- Draft markers ---

#[test]
fn mark_and_clear_draft() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    let id = store.save("/test/doc.txt", "draft content", false).unwrap();
    store.mark_draft(id, "First Draft").unwrap();

    let entries = store.list("/test/doc.txt").unwrap();
    assert_eq!(entries[0].draft_label.as_deref(), Some("First Draft"));

    store.mark_draft(id, "").unwrap();
    let entries = store.list("/test/doc.txt").unwrap();
    assert!(entries[0].draft_label.is_none());
}

#[test]
fn mark_draft_nonexistent_snapshot() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(&dir);
    let result = store.mark_draft(9999, "Nope");
    assert!(result.is_err());
}

// --- Restore ---

#[test]
fn restore_saves_current_then_returns_old() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    let id_v1 = store.save("/test/doc.txt", "original", false).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    store.save("/test/doc.txt", "modified", false).unwrap();

    let restored = store.restore("/test/doc.txt", id_v1, "modified").unwrap();
    assert_eq!(restored, "original");

    // Should now have 4 meta entries: v1, v2, pre-restore save of "modified", restore of "original"
    let entries = store.list("/test/doc.txt").unwrap();
    assert_eq!(entries.len(), 4);
    assert!(
        entries[0].is_restore,
        "newest entry should be marked as restore"
    );
}

#[test]
fn restore_is_never_lossy() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    store.save("/test/doc.txt", "v1", false).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let id_v1 = store.list("/test/doc.txt").unwrap()[0].id;
    store
        .save("/test/doc.txt", "v2-will-be-saved", false)
        .unwrap();

    store
        .restore("/test/doc.txt", id_v1, "current-before-restore")
        .unwrap();

    // "current-before-restore" must be retrievable
    let entries = store.list("/test/doc.txt").unwrap();
    let all_texts: Vec<String> = entries.iter().map(|e| store.get(e.id).unwrap()).collect();
    assert!(
        all_texts.contains(&"current-before-restore".to_string()),
        "pre-restore state must be preserved"
    );
}

#[test]
fn restore_atomic_meta_count() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    let id = store.save("/test/doc.txt", "original", false).unwrap();
    store.restore("/test/doc.txt", id, "current").unwrap();

    // restore creates exactly 2 new meta entries (pre-save + restore marker)
    let entries = store.list("/test/doc.txt").unwrap();
    assert_eq!(entries.len(), 3); // original + pre-save + restore marker
    assert!(entries[0].is_restore);
    assert!(!entries[1].is_restore);
    assert!(!entries[2].is_restore);
}

// --- Diff ---

#[test]
fn diff_identical_documents() {
    let ops = word_diff("hello world", "hello world");
    assert!(ops.iter().all(|op| op.tag == DiffTag::Equal));
}

#[test]
fn diff_empty_to_content() {
    let ops = word_diff("", "hello world");
    assert!(ops.iter().all(|op| op.tag == DiffTag::Insert));
    let joined: String = ops.iter().map(|op| op.text.as_str()).collect();
    assert_eq!(joined, "hello world");
}

#[test]
fn diff_content_to_empty() {
    let ops = word_diff("hello world", "");
    assert!(ops.iter().all(|op| op.tag == DiffTag::Delete));
}

#[test]
fn diff_both_empty() {
    let ops = word_diff("", "");
    assert!(ops.is_empty());
}

#[test]
fn diff_word_level_changes() {
    let ops = word_diff("The quick brown fox", "The slow brown fox");
    let inserts: Vec<&str> = ops
        .iter()
        .filter(|op| op.tag == DiffTag::Insert)
        .map(|op| op.text.as_str())
        .collect();
    let deletes: Vec<&str> = ops
        .iter()
        .filter(|op| op.tag == DiffTag::Delete)
        .map(|op| op.text.as_str())
        .collect();
    assert!(deletes.iter().any(|t| t.contains("quick")));
    assert!(inserts.iter().any(|t| t.contains("slow")));
}

#[test]
fn diff_additions_at_end() {
    let ops = word_diff("one two", "one two three four");
    let inserts: String = ops
        .iter()
        .filter(|op| op.tag == DiffTag::Insert)
        .map(|op| op.text.as_str())
        .collect();
    assert!(inserts.contains("three"));
    assert!(inserts.contains("four"));
}

#[test]
fn diff_deletions_at_start() {
    let ops = word_diff("alpha beta gamma", "gamma");
    let deletes: String = ops
        .iter()
        .filter(|op| op.tag == DiffTag::Delete)
        .map(|op| op.text.as_str())
        .collect();
    assert!(deletes.contains("alpha"));
    assert!(deletes.contains("beta"));
}

// --- Storage size ---

#[test]
fn storage_size_tracks_blobs() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    let info = store.storage_size().unwrap();
    assert_eq!(info.total_bytes, 0);
    assert!(!info.over_threshold);

    store.save("/test/doc.txt", "some content", false).unwrap();
    let info = store.storage_size().unwrap();
    assert!(info.total_bytes > 0);
}

// --- Cross-document isolation ---

#[test]
fn list_filters_by_document() {
    let dir = TempDir::new().unwrap();
    let mut store = open_test_store(&dir);

    store.save("/test/a.txt", "content a", false).unwrap();
    store.save("/test/b.txt", "content b", false).unwrap();

    let list_a = store.list("/test/a.txt").unwrap();
    let list_b = store.list("/test/b.txt").unwrap();
    assert_eq!(list_a.len(), 1);
    assert_eq!(list_b.len(), 1);
    assert_ne!(list_a[0].id, list_b[0].id);
}

#[test]
fn get_nonexistent_snapshot() {
    let dir = TempDir::new().unwrap();
    let store = open_test_store(&dir);
    assert!(store.get(9999).is_err());
}

#[test]
fn lock_prevents_concurrent_open() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("locked_snap.db");
    let _store1 = SnapshotStore::open(&db_path, &test_signing_key()).unwrap();

    let result = SnapshotStore::open(&db_path, &test_signing_key());
    assert!(result.is_err());
    let msg = result.unwrap_err();
    assert!(
        msg.contains("locked by another process"),
        "expected lock error, got: {msg}"
    );
}

#[test]
fn lock_released_on_drop() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("relock_snap.db");
    let store = SnapshotStore::open(&db_path, &test_signing_key()).unwrap();
    drop(store);
    let _store2 = SnapshotStore::open(&db_path, &test_signing_key()).unwrap();
}
