// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial
#![cfg(feature = "ffi")]

//! Demo-flow integration tests.
//!
//! Simulates the exact user journey:
//! init -> checkpoint -> edit -> checkpoint -> export -> verify history
//!
//! Run: `cargo test --test demo_flow_integration --features ffi`

use std::io::Write;
use std::sync::Mutex;

// Serialize all tests since they share CPOE_DATA_DIR env var
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn setup() -> (tempfile::TempDir, std::sync::MutexGuard<'static, ()>) {
    let guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().expect("tempdir");
    std::env::set_var("CPOE_DATA_DIR", dir.path());
    std::env::set_var("CPOE_NO_KEYCHAIN", "1");
    (dir, guard)
}

fn create_doc(dir: &tempfile::TempDir, name: &str, content: &str) -> String {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create doc");
    f.write_all(content.as_bytes()).expect("write");
    path.to_string_lossy().to_string()
}

fn modify_doc(path: &str, content: &str) {
    let mut f = std::fs::File::create(path).expect("modify");
    f.write_all(content.as_bytes()).expect("write");
}

// ============================================================
// 1. Engine initialization creates signing key and database
// ============================================================

#[test]
fn t01_engine_init() {
    let (dir, _g) = setup();
    let r = cpoe_engine::ffi::system::ffi_init();
    assert!(r.success, "init failed: {:?}", r.error_message);
    assert!(dir.path().join("signing_key").exists(), "no signing_key");
    assert!(dir.path().join("events.db").exists(), "no events.db");
}

// ============================================================
// 2. Status reports initialized=true after init
// ============================================================

#[test]
fn t02_status_initialized() {
    let (_dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let s = cpoe_engine::ffi::system::ffi_get_status();
    assert!(s.initialized, "not initialized");
    assert_eq!(s.tracked_file_count, 0);
    assert_eq!(s.total_checkpoints, 0);
    assert!(s.error_message.is_none(), "error: {:?}", s.error_message);
}

// ============================================================
// 3. Checkpoint a document
// ============================================================

#[test]
fn t03_create_checkpoint() {
    let (dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let doc = create_doc(&dir, "essay.txt", "My essay content.");
    let r = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc, "Initial".into());
    assert!(r.success, "checkpoint failed: {:?}", r.error_message);
    let s = cpoe_engine::ffi::system::ffi_get_status();
    assert_eq!(s.tracked_file_count, 1);
    assert_eq!(s.total_checkpoints, 1);
}

// ============================================================
// 4. Multiple checkpoints with edits
// ============================================================

#[test]
fn t04_multi_checkpoint() {
    let (dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let doc = create_doc(&dir, "paper.txt", "v1");

    for i in 1..=5 {
        modify_doc(&doc, &format!("Version {i} with more text."));
        let r = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("v{i}"),
        );
        assert!(r.success, "cp{i} failed: {:?}", r.error_message);
    }

    let s = cpoe_engine::ffi::system::ffi_get_status();
    assert_eq!(s.total_checkpoints, 5);
}

// ============================================================
// 5. Export evidence as JSON
// ============================================================

#[test]
fn t05_export_json() {
    let (dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let doc = create_doc(&dir, "article.txt", "Content.");

    for i in 1..=3 {
        modify_doc(&doc, &format!("Article v{i}."));
        assert!(
            cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
                doc.clone(),
                format!("v{i}")
            )
            .success
        );
    }

    let out = dir
        .path()
        .join("evidence.json")
        .to_string_lossy()
        .to_string();
    let r = cpoe_engine::ffi::evidence_export::ffi_export_evidence(doc, "core".into(), out.clone());
    assert!(r.success, "export failed: {:?}", r.error_message);

    let data = std::fs::read(&out).expect("read evidence");
    assert!(data.len() > 50, "evidence too small: {} bytes", data.len());
    // Export always produces CBOR (even with .json extension); verify it's valid CBOR
    assert!(
        data[0] >= 0x80 || data[0] == 0xd9,
        "doesn't look like CBOR: 0x{:02x}",
        data[0]
    );
}

// ============================================================
// 6. Export evidence as CPoE (CBOR)
// ============================================================

#[test]
fn t06_export_cpoe() {
    let (dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let doc = create_doc(&dir, "report.txt", "Report.");

    for i in 1..=2 {
        modify_doc(&doc, &format!("Report v{i}."));
        assert!(
            cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
                doc.clone(),
                format!("v{i}")
            )
            .success
        );
    }

    let out = dir
        .path()
        .join("evidence.cpoe")
        .to_string_lossy()
        .to_string();
    let r = cpoe_engine::ffi::evidence_export::ffi_export_evidence(doc, "core".into(), out.clone());
    assert!(r.success, "CPoE export failed: {:?}", r.error_message);

    let data = std::fs::read(&out).expect("read cpoe");
    assert!(data.len() > 50, "CPoE too small");
}

// ============================================================
// 7. History lists tracked documents
// ============================================================

#[test]
fn t07_history() {
    let (dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);

    let doc1 = create_doc(&dir, "doc1.txt", "Doc 1.");
    let doc2 = create_doc(&dir, "doc2.txt", "Doc 2.");
    assert!(
        cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc1.clone(), "cp".into())
            .success
    );
    assert!(
        cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc2.clone(), "cp".into())
            .success
    );

    let files = cpoe_engine::ffi::system::ffi_list_tracked_files();
    let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
    // Paths are canonicalized in the store; compare against canonical paths
    let canon1 = std::fs::canonicalize(&doc1).unwrap_or_else(|_| doc1.clone().into());
    let canon2 = std::fs::canonicalize(&doc2).unwrap_or_else(|_| doc2.clone().into());
    let c1 = canon1.to_string_lossy();
    let c2 = canon2.to_string_lossy();
    assert!(
        paths.contains(&c1.as_ref()),
        "doc1 missing from history. Have: {:?}",
        paths
    );
    assert!(
        paths.contains(&c2.as_ref()),
        "doc2 missing from history. Have: {:?}",
        paths
    );
}

// ============================================================
// 8. Checkpoint log shows entries in order
// ============================================================

#[test]
fn t08_log_ordering() {
    let (dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let doc = create_doc(&dir, "log.txt", "Start.");

    for i in 1..=3 {
        modify_doc(&doc, &format!("Edit {i}."));
        assert!(
            cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
                doc.clone(),
                format!("e{i}")
            )
            .success
        );
    }

    let log = cpoe_engine::ffi::system::ffi_get_log(doc);
    assert_eq!(log.len(), 3, "expected 3 log entries");
    for (i, entry) in log.iter().enumerate() {
        assert_eq!(entry.ordinal, i as u64, "ordinal mismatch at {i}");
        assert!(entry.timestamp_ns > 0);
        assert!(!entry.content_hash.is_empty());
    }
}

// ============================================================
// 9. Re-init preserves existing data
// ============================================================

#[test]
fn t09_reinit_preserves_data() {
    let (dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let doc = create_doc(&dir, "persist.txt", "Data.");
    assert!(cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc, "cp".into()).success);

    // Re-init
    let r = cpoe_engine::ffi::system::ffi_init();
    assert!(r.success, "re-init failed: {:?}", r.error_message);
    let s = cpoe_engine::ffi::system::ffi_get_status();
    assert_eq!(s.total_checkpoints, 1, "checkpoint lost on re-init");
}

// ============================================================
// 10. HMAC recovery after cache reset
// ============================================================

#[test]
fn t10_hmac_recovery() {
    let (dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let doc = create_doc(&dir, "recover.txt", "Data.");
    assert!(cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc, "cp".into()).success);

    // Simulate keychain state change
    cpoe_engine::identity::SecureStorage::reset_hmac_cache();

    let r = cpoe_engine::ffi::system::ffi_init();
    assert!(r.success, "recovery failed: {:?}", r.error_message);
    assert!(cpoe_engine::ffi::system::ffi_get_status().initialized);
}

// ============================================================
// 11. Nonexistent file rejected
// ============================================================

#[test]
fn t11_bad_path_rejected() {
    let (_dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let r = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        "/no/such/file.txt".into(),
        "x".into(),
    );
    assert!(!r.success, "should reject nonexistent file");
}

// ============================================================
// 12. Empty file gets checkpoint
// ============================================================

#[test]
fn t12_empty_file() {
    let (dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let doc = create_doc(&dir, "empty.txt", "");
    let r = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc, "empty".into());
    assert!(r.success, "empty file failed: {:?}", r.error_message);
}

// ============================================================
// 13. SWF calibration
// ============================================================

#[test]
fn t13_calibration() {
    let (_dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let cal = cpoe_engine::ffi::forensics::ffi_calibrate_swf();
    assert!(cal.success, "calibration failed: {:?}", cal.error_message);
    assert!(cal.iterations_per_second > 0, "SWF iters should be > 0");
}

// ============================================================
// 14. Dashboard metrics
// ============================================================

#[test]
fn t14_dashboard() {
    let (dir, _g) = setup();
    assert!(cpoe_engine::ffi::system::ffi_init().success);
    let doc = create_doc(&dir, "dash.txt", "Content.");
    assert!(cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc, "cp".into()).success);
    let m = cpoe_engine::ffi::system::ffi_get_dashboard_metrics();
    assert!(m.total_checkpoints >= 1);
    assert!(m.total_files >= 1);
}
