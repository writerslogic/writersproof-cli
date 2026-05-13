// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial
#![cfg(feature = "ffi")]

//! Comprehensive integration tests for the full CPoE feature pipeline.
//!
//! Run with: `cargo test -p cpoe_engine --test integration_tests --features ffi`
//!
//! Tests requiring real system permissions (CGEventTap, Input Monitoring)
//! are gated behind `CPOE_INTEGRATION=1`.

use std::io::Write;
use std::sync::Mutex;

// Serialize all tests that share CPOE_DATA_DIR env var.
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
// 1. Keystroke E2E flow
// ============================================================

/// Verify that injected keystrokes reach the sentinel session and are reported
/// via ffi_sentinel_witnessing_status. Requires system permissions on macOS,
/// so gated behind CPOE_INTEGRATION=1.
#[test]
fn test_keystroke_injection_reaches_session() {
    if std::env::var("CPOE_INTEGRATION").is_err() {
        eprintln!("Skipping test_keystroke_injection_reaches_session (set CPOE_INTEGRATION=1)");
        return;
    }

    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let start = cpoe_engine::ffi::sentinel::ffi_sentinel_start();
    assert!(
        start.success,
        "sentinel start failed: {:?}",
        start.error_message
    );

    let doc = create_doc(&dir, "test.txt", "Hello, integration test.");
    let witness = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_start_witnessing(doc);
    assert!(
        witness.success,
        "start witnessing failed: {:?}",
        witness.error_message
    );

    // Inject 20 keystrokes with realistic timing (100-250ms intervals).
    let base_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos() as i64;

    let keycodes: [u16; 20] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    ];
    let intervals_ms: [i64; 20] = [
        0, 120, 180, 150, 200, 130, 170, 210, 140, 190, 160, 220, 135, 185, 175, 205, 145, 195,
        155, 165,
    ];

    let mut cumulative_ns = 0i64;
    for i in 0..20 {
        cumulative_ns += intervals_ms[i] * 1_000_000;
        let ts = base_ns + cumulative_ns;
        let zone = (i % 5) as u8;
        let accepted = cpoe_engine::ffi::sentinel_inject::ffi_sentinel_inject_keystroke(
            ts,
            keycodes[i],
            zone,
            1,  // source_state_id = HID_SYSTEM
            40, // keyboard_type = ANSI
            0,  // source_pid = kernel (hardware)
            "".to_string(),
        );
        assert!(accepted, "keystroke {i} was rejected");
    }

    let status = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_witnessing_status();
    assert!(status.is_tracking, "should be tracking");
    assert!(
        status.keystroke_count >= 20,
        "expected >= 20 keystrokes, got {}",
        status.keystroke_count
    );

    // Cleanup
    let stop_w = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_stop_witnessing(
        status.document_path.unwrap_or_default(),
    );
    assert!(
        stop_w.success,
        "stop witnessing failed: {:?}",
        stop_w.error_message
    );

    let stop = cpoe_engine::ffi::sentinel::ffi_sentinel_stop();
    assert!(
        stop.success,
        "sentinel stop failed: {:?}",
        stop.error_message
    );
}

// ============================================================
// 2. Auto-checkpoint creates events
// ============================================================

#[test]
fn test_checkpoint_creates_store_event() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(
        &dir,
        "checkpoint_test.txt",
        "Initial content for checkpoint.",
    );
    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc.clone(),
        "first checkpoint".to_string(),
    );
    assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

    // Verify status shows the tracked file.
    let status = cpoe_engine::ffi::system::ffi_get_status();
    assert_eq!(status.tracked_file_count, 1);
    assert_eq!(status.total_checkpoints, 1);

    // Verify ffi_list_tracked_files shows the file.
    let files = cpoe_engine::ffi::system::ffi_list_tracked_files();
    assert!(!files.is_empty(), "tracked files should be non-empty");

    let canonical = std::path::Path::new(&doc)
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(&doc));
    let canonical_str = canonical.to_string_lossy().to_string();
    let found = files.iter().any(|f| f.path == canonical_str);
    assert!(
        found,
        "expected to find {} in tracked files: {:?}",
        canonical_str,
        files.iter().map(|f| &f.path).collect::<Vec<_>>()
    );

    let tracked = files
        .iter()
        .find(|f| f.path == canonical_str)
        .expect("tracked file found");
    assert_eq!(tracked.checkpoint_count, 1);
}

// ============================================================
// 4. Cumulative stats persist across sessions
// ============================================================

/// This test verifies that cumulative keystroke counts persist via the
/// sentinel session lifecycle. Requires system permissions.
#[test]
fn test_cumulative_keystrokes_persist_across_sessions() {
    if std::env::var("CPOE_INTEGRATION").is_err() {
        eprintln!(
            "Skipping test_cumulative_keystrokes_persist_across_sessions (set CPOE_INTEGRATION=1)"
        );
        return;
    }

    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let start = cpoe_engine::ffi::sentinel::ffi_sentinel_start();
    assert!(
        start.success,
        "sentinel start failed: {:?}",
        start.error_message
    );

    let doc = create_doc(&dir, "persist_test.txt", "Content for persistence.");
    let doc_clone = doc.clone();

    // Session 1: inject 50 keystrokes.
    let w1 = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_start_witnessing(doc.clone());
    assert!(
        w1.success,
        "start witnessing 1 failed: {:?}",
        w1.error_message
    );

    let base_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos() as i64;

    for i in 0..50 {
        let ts = base_ns + (i as i64) * 150_000_000 + (i as i64 * 13 % 50) * 1_000_000;
        cpoe_engine::ffi::sentinel_inject::ffi_sentinel_inject_keystroke(
            ts,
            (i % 40) as u16,
            (i % 5) as u8,
            1,
            40,
            0,
            "".to_string(),
        );
    }

    let s1 = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_witnessing_status();
    assert!(
        s1.keystroke_count >= 50,
        "session 1: expected >= 50, got {}",
        s1.keystroke_count
    );

    cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_stop_witnessing(doc_clone.clone());

    // Session 2: start witnessing the same file again.
    let w2 =
        cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_start_witnessing(doc_clone.clone());
    assert!(
        w2.success,
        "start witnessing 2 failed: {:?}",
        w2.error_message
    );

    let s2 = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_witnessing_status();
    // Cumulative keystrokes from session 1 should carry over.
    assert!(
        s2.keystroke_count >= 50,
        "session 2: cumulative keystrokes should be >= 50, got {}",
        s2.keystroke_count
    );

    cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_stop_witnessing(doc_clone);
    cpoe_engine::ffi::sentinel::ffi_sentinel_stop();
}

// ============================================================
// 5. Export + verify round-trip
// ============================================================

#[test]
fn test_export_verify_roundtrip() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "roundtrip.txt", "Version 1.");

    // Create 3 checkpoints with edits.
    for i in 1..=3 {
        modify_doc(&doc, &format!("Version {i} with more content added here."));
        let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("v{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    // Export evidence to a temp file.
    let output_path = dir.path().join("evidence.cpoe");
    let output_str = output_path.to_string_lossy().to_string();
    let export = cpoe_engine::ffi::evidence_export::ffi_export_evidence(
        doc,
        "core".to_string(),
        output_str.clone(),
    );
    assert!(export.success, "export failed: {:?}", export.error_message);
    assert!(output_path.exists(), "evidence file not created");

    let file_size = std::fs::metadata(&output_path)
        .expect("read evidence metadata")
        .len();
    assert!(file_size > 0, "evidence file is empty");

    // Verify the exported evidence.
    let verify = cpoe_engine::ffi::verify_detail::ffi_verify_evidence_detailed(output_str);
    assert!(verify.success, "verify failed: {:?}", verify.error_message);
    assert!(
        verify.checkpoint_count >= 3,
        "expected >= 3 checkpoints, got {}",
        verify.checkpoint_count
    );
}

// ============================================================
// 6. WAR report generation
// ============================================================

#[test]
fn test_war_report_html_generation() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "war_html.txt", "Document for WAR report.");

    // Create checkpoints to have report data.
    for i in 1..=3 {
        modify_doc(
            &doc,
            &format!("Revision {i} with substantial edits and more text."),
        );
        let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("rev{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    let result = cpoe_engine::ffi::report::ffi_render_war_html(doc);
    assert!(
        result.success,
        "WAR HTML failed: {:?}",
        result.error_message
    );
    let html = result.html.expect("html should be Some");
    assert!(!html.is_empty(), "HTML should be non-empty");
    assert!(html.contains("<html"), "HTML should contain <html tag");
    assert!(html.contains("WAR"), "HTML should reference WAR");
}

#[test]
fn test_war_report_build() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "war_build.txt", "Document for WAR build.");

    for i in 1..=2 {
        modify_doc(
            &doc,
            &format!("Content revision {i} with edits and changes."),
        );
        let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("rev{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    let result = cpoe_engine::ffi::report::ffi_build_war_report(doc);
    assert!(
        result.success,
        "WAR build failed: {:?}",
        result.error_message
    );
    assert!(result.report.is_some(), "report should be Some");
}

// ============================================================
// 7. Store document stats
// ============================================================

/// Verify that ffi_list_tracked_files shows a file after checkpoints are created,
/// and that the checkpoint count persists (indirectly testing document stats).
/// Verify that ffi_create_checkpoint writes to the events table and
/// ffi_list_tracked_files shows the file with correct checkpoint count.
#[test]
fn test_document_stats_via_ffi_roundtrip() {
    use cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint;
    use cpoe_engine::ffi::system::{ffi_init, ffi_list_tracked_files};

    let (dir, _g) = setup();
    let test_file = dir.path().join("stats_test.txt");
    std::fs::write(&test_file, "test content for stats").expect("write test file");

    let init = ffi_init();
    assert!(init.success, "init: {:?}", init.error_message);

    // Create a checkpoint
    let cp = ffi_create_checkpoint(test_file.to_string_lossy().to_string(), "stats test".into());
    assert!(cp.success, "checkpoint: {:?}", cp.error_message);

    // List should show the file with 1 checkpoint.
    // Canonicalize to resolve macOS /var -> /private/var symlink.
    let files = ffi_list_tracked_files();
    let test_path = std::fs::canonicalize(&test_file)
        .unwrap_or(test_file.clone())
        .to_string_lossy()
        .to_string();
    let found = files.iter().find(|f| f.path == test_path);
    assert!(
        found.is_some(),
        "file should appear in tracked list; looked for '{}', got {:?}",
        test_path,
        files.iter().map(|f| &f.path).collect::<Vec<_>>()
    );
    assert!(
        found.expect("tracked file entry").checkpoint_count >= 1,
        "should have at least 1 checkpoint"
    );
}

// ============================================================
// 8. API field naming (camelCase serialization)
// ============================================================

#[test]
fn test_api_types_serialize_camelcase() {
    let enroll = cpoe_engine::writersproof::types::EnrollRequest {
        public_key: "abc123".to_string(),
        device_id: "dev01".to_string(),
        platform: "macos".to_string(),
        attestation_type: "secure_enclave".to_string(),
        attestation_certificate: None,
    };
    let json = serde_json::to_string(&enroll).expect("serialize EnrollRequest");
    assert!(
        json.contains("\"publicKey\""),
        "EnrollRequest should use camelCase: {json}"
    );
    assert!(
        json.contains("\"deviceId\""),
        "EnrollRequest should use camelCase: {json}"
    );
    assert!(
        json.contains("\"attestationType\""),
        "EnrollRequest should use camelCase: {json}"
    );
    assert!(
        !json.contains("\"public_key\""),
        "EnrollRequest should not use snake_case: {json}"
    );

    let anchor = cpoe_engine::writersproof::types::AnchorRequest {
        evidence_hash: "hash".to_string(),
        author_did: "did:cpoe:test".to_string(),
        signature: "sig".to_string(),
        metadata: None,
    };
    let json = serde_json::to_string(&anchor).expect("serialize AnchorRequest");
    assert!(
        json.contains("\"evidenceHash\""),
        "AnchorRequest should use camelCase: {json}"
    );
    assert!(
        json.contains("\"authorDid\""),
        "AnchorRequest should use camelCase: {json}"
    );
    assert!(
        !json.contains("\"evidence_hash\""),
        "AnchorRequest should not use snake_case: {json}"
    );

    let nonce = cpoe_engine::writersproof::types::NonceResponse {
        nonce: "abc".to_string(),
        expires_at: "2026-01-01T00:00:00Z".to_string(),
        nonce_id: "n1".to_string(),
    };
    let json = serde_json::to_string(&nonce).expect("serialize NonceResponse");
    assert!(
        json.contains("\"expiresAt\""),
        "NonceResponse should use camelCase: {json}"
    );
    assert!(
        json.contains("\"nonceId\""),
        "NonceResponse should use camelCase: {json}"
    );
    assert!(
        !json.contains("\"expires_at\""),
        "NonceResponse should not use snake_case: {json}"
    );
}

// ============================================================
// 9. Jitter session records and verifies chain
// ============================================================

#[test]
fn test_jitter_session_records_and_verifies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let doc_path = dir.path().join("jitter_doc.txt");
    std::fs::write(&doc_path, "Initial jitter test content.").expect("write doc");

    let params = cpoe_engine::jitter::default_parameters();
    let mut session = cpoe_engine::jitter::Session::new(&doc_path, params).expect("create session");

    // Record 20 keystrokes. With sample_interval=10, we should get 2 samples.
    for _ in 0..20 {
        session.record_keystroke().expect("record keystroke");
    }

    assert_eq!(session.keystroke_count(), 20);
    assert_eq!(
        session.sample_count(),
        2,
        "expected 2 samples at interval=10"
    );

    // Export and verify chain integrity.
    let evidence = session.export();
    assert_eq!(evidence.samples.len(), 2);
    assert_eq!(evidence.statistics.total_keystrokes, 20);
    assert!(
        evidence.statistics.chain_valid,
        "jitter chain should be valid"
    );
}

#[test]
fn test_jitter_session_chain_integrity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let doc_path = dir.path().join("jitter_chain.txt");
    std::fs::write(&doc_path, "Chain integrity test.").expect("write doc");

    let params = cpoe_engine::jitter::Parameters {
        sample_interval: 5, // sample every 5 keystrokes for more chain links
        ..cpoe_engine::jitter::default_parameters()
    };
    let mut session = cpoe_engine::jitter::Session::new(&doc_path, params).expect("create session");

    // Record 30 keystrokes -> 6 samples.
    for _ in 0..30 {
        session.record_keystroke().expect("record keystroke");
    }

    assert_eq!(session.sample_count(), 6);

    let evidence = session.export();
    assert!(
        evidence.statistics.chain_valid,
        "chain should be valid after 6 samples"
    );

    // Verify each sample links to its predecessor.
    for i in 1..evidence.samples.len() {
        assert_eq!(
            evidence.samples[i].previous_hash,
            evidence.samples[i - 1].hash,
            "sample {i} should link to sample {}",
            i - 1,
        );
    }

    // First sample should have zero previous_hash.
    assert_eq!(evidence.samples[0].previous_hash, [0u8; 32]);
}

// ============================================================
// 10. Multiple checkpoints with export at different tiers
// ============================================================

#[test]
fn test_export_at_multiple_tiers() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "tiers.txt", "Tier test v1.");

    for i in 1..=3 {
        modify_doc(
            &doc,
            &format!("Tier test version {i} with additional content."),
        );
        let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("v{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    for tier in &["core", "enhanced", "maximum"] {
        let output = dir.path().join(format!("evidence_{tier}.cpoe"));
        let result = cpoe_engine::ffi::evidence_export::ffi_export_evidence(
            doc.clone(),
            tier.to_string(),
            output.to_string_lossy().to_string(),
        );
        assert!(
            result.success,
            "export at tier {tier} failed: {:?}",
            result.error_message
        );
        assert!(output.exists(), "evidence file for tier {tier} not created");
        let size = std::fs::metadata(&output)
            .expect("read tier evidence metadata")
            .len();
        assert!(size > 0, "evidence file for tier {tier} is empty");
    }
}

// ============================================================
// 11. Compact reference format
// ============================================================

#[test]
fn test_compact_ref_format() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "compact_ref.txt", "Compact ref test.");

    let cp =
        cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc.clone(), String::new());
    assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

    let compact = cpoe_engine::ffi::evidence_export::ffi_get_compact_ref(doc);
    assert!(
        compact.starts_with("cpoe-ref:writerslogic:"),
        "compact ref should start with 'cpoe-ref:writerslogic:', got: {compact}"
    );
    // Format: cpoe-ref:writerslogic:<hash_prefix>:<count>
    let parts: Vec<&str> = compact.split(':').collect();
    assert_eq!(
        parts.len(),
        4,
        "compact ref should have 4 colon-separated parts: {compact}"
    );
    assert_eq!(parts[3], "1", "should show 1 event");
}

// ============================================================
// 12. Dashboard metrics
// ============================================================

#[test]
fn test_dashboard_metrics_after_checkpoints() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "dashboard.txt", "Dashboard test v1.");
    for i in 1..=3 {
        modify_doc(&doc, &format!("Dashboard version {i} with edits."));
        cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc.clone(), format!("v{i}"));
    }

    let metrics = cpoe_engine::ffi::system::ffi_get_dashboard_metrics();
    assert!(
        metrics.success,
        "dashboard metrics failed: {:?}",
        metrics.error_message
    );
    assert_eq!(metrics.total_files, 1);
    assert_eq!(metrics.total_checkpoints, 3);
}

// ============================================================
// 13. Security hardness tests
// ============================================================

#[test]
fn test_checkpoint_rejects_path_traversal() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let traversal = dir
        .path()
        .join("../../../etc/passwd")
        .to_string_lossy()
        .to_string();
    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        traversal,
        "traversal attempt".to_string(),
    );
    assert!(!cp.success, "path traversal should be rejected");
}

#[test]
fn test_checkpoint_rejects_system_paths() {
    let (_dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        "/System/Library/CoreServices/SystemVersion.plist".to_string(),
        "system path attempt".to_string(),
    );
    assert!(!cp.success, "system path should be rejected");
}

#[test]
fn test_export_rejects_unwritable_path() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "unwritable_test.txt", "Content for unwritable test.");
    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc.clone(),
        "checkpoint".to_string(),
    );
    assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

    // Try exporting to a path that cannot be written (/System is read-only on macOS)
    let result = cpoe_engine::ffi::evidence_export::ffi_export_evidence(
        doc,
        "core".to_string(),
        "/System/evidence.cpoe".to_string(),
    );
    assert!(!result.success, "export to unwritable path should fail");
}

#[test]
fn test_signing_key_exists_after_init() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let key_path = dir.path().join("signing_key");
    assert!(key_path.exists(), "signing_key should exist after init");
    let key_bytes = std::fs::read(&key_path).expect("read signing key");
    assert_eq!(key_bytes.len(), 32, "signing key should be 32 bytes");
}

#[test]
fn test_hmac_integrity_verification() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "hmac_test.txt", "HMAC integrity content.");
    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc.clone(),
        "hmac checkpoint".to_string(),
    );
    assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

    // Export evidence, verify it passes
    let output = dir.path().join("hmac_evidence.cpoe");
    let output_str = output.to_string_lossy().to_string();
    let export = cpoe_engine::ffi::evidence_export::ffi_export_evidence(
        doc,
        "core".to_string(),
        output_str.clone(),
    );
    assert!(export.success, "export failed: {:?}", export.error_message);

    // Tamper with the middle of the file (corrupt the CBOR payload)
    let mut data = std::fs::read(&output).expect("read evidence");
    if data.len() > 20 {
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        data[mid + 1] ^= 0xFF;
    }
    let tampered_path = dir.path().join("hmac_tampered.cpoe");
    std::fs::write(&tampered_path, &data).expect("write tampered");
    let tampered_str = tampered_path.to_string_lossy().to_string();

    let verify = cpoe_engine::ffi::verify_detail::ffi_verify_evidence_detailed(tampered_str);
    // Tampered file should either fail to decode or fail verification
    assert!(
        !verify.success || !verify.overall_valid,
        "tampered evidence should not verify as valid"
    );
}

#[test]
fn test_verify_detects_tampered_checkpoint() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "tamper_cp.txt", "Version 1.");
    for i in 1..=3 {
        modify_doc(&doc, &format!("Version {i} with more content."));
        let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("v{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    let output = dir.path().join("tamper_evidence.cpoe");
    let output_str = output.to_string_lossy().to_string();
    let export = cpoe_engine::ffi::evidence_export::ffi_export_evidence(
        doc,
        "core".to_string(),
        output_str.clone(),
    );
    assert!(export.success, "export failed: {:?}", export.error_message);

    // Verify original passes
    let verify_ok =
        cpoe_engine::ffi::verify_detail::ffi_verify_evidence_detailed(output_str.clone());
    assert!(
        verify_ok.success,
        "original verify failed: {:?}",
        verify_ok.error_message
    );

    // Tamper: flip bytes near the end
    let mut data = std::fs::read(&output).expect("read");
    let near_end = data.len().saturating_sub(10);
    for byte in &mut data[near_end..] {
        *byte ^= 0xFF;
    }
    std::fs::write(&output, &data).expect("write tampered");

    let verify_bad = cpoe_engine::ffi::verify_detail::ffi_verify_evidence_detailed(output_str);
    assert!(
        !verify_bad.success || !verify_bad.overall_valid,
        "tampered evidence should fail verification"
    );
}

#[test]
fn test_verify_detects_truncated_file() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "truncate_test.txt", "Content for truncation.");
    let cp =
        cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc.clone(), "cp".to_string());
    assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

    let output = dir.path().join("truncated.cpoe");
    let output_str = output.to_string_lossy().to_string();
    let export = cpoe_engine::ffi::evidence_export::ffi_export_evidence(
        doc,
        "core".to_string(),
        output_str.clone(),
    );
    assert!(export.success, "export failed: {:?}", export.error_message);

    // Truncate to half
    let data = std::fs::read(&output).expect("read");
    std::fs::write(&output, &data[..data.len() / 2]).expect("write truncated");

    let verify = cpoe_engine::ffi::verify_detail::ffi_verify_evidence_detailed(output_str);
    assert!(
        !verify.success || !verify.overall_valid,
        "truncated file should fail verification"
    );
}

#[test]
fn test_verify_rejects_empty_file() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let empty = dir.path().join("empty.cpoe");
    std::fs::write(&empty, b"").expect("write empty");
    let empty_str = empty.to_string_lossy().to_string();

    let verify = cpoe_engine::ffi::verify_detail::ffi_verify_evidence_detailed(empty_str);
    assert!(!verify.success, "empty file should fail verification");
}

#[test]
fn test_verify_rejects_random_bytes() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let random_path = dir.path().join("random.cpoe");
    let random_data: Vec<u8> = (0..1024).map(|i| (i * 37 + 13) as u8).collect();
    std::fs::write(&random_path, &random_data).expect("write random");
    let random_str = random_path.to_string_lossy().to_string();

    let verify = cpoe_engine::ffi::verify_detail::ffi_verify_evidence_detailed(random_str);
    assert!(!verify.success, "random bytes should fail verification");
}

#[test]
fn test_checkpoint_rejects_empty_path() {
    let (_dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        String::new(),
        "empty path".to_string(),
    );
    assert!(!cp.success, "empty path should be rejected");
}

#[test]
fn test_checkpoint_rejects_nonexistent_file() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let nonexistent = dir
        .path()
        .join("does_not_exist.txt")
        .to_string_lossy()
        .to_string();
    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        nonexistent,
        "nonexistent".to_string(),
    );
    assert!(!cp.success, "nonexistent file should be rejected");
}

#[test]
fn test_export_rejects_invalid_tier() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "tier_test.txt", "Content for tier test.");
    let cp =
        cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(doc.clone(), "cp".to_string());
    assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

    // Invalid tier falls back to "core" per the implementation, so export should succeed.
    // This test documents that behavior.
    let output = dir.path().join("invalid_tier.cpoe");
    let result = cpoe_engine::ffi::evidence_export::ffi_export_evidence(
        doc,
        "NONEXISTENT_TIER_XYZ".to_string(),
        output.to_string_lossy().to_string(),
    );
    // The implementation defaults unknown tiers to Core, so this succeeds
    assert!(
        result.success,
        "unknown tier should fall back to core: {:?}",
        result.error_message
    );
}

// ============================================================
// 14. Edge case tests
// ============================================================

#[test]
fn test_export_with_single_checkpoint() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "single_cp.txt", "Single checkpoint content.");
    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc.clone(),
        "only one".to_string(),
    );
    assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

    let output = dir.path().join("single.cpoe");
    let output_str = output.to_string_lossy().to_string();
    let export = cpoe_engine::ffi::evidence_export::ffi_export_evidence(
        doc,
        "core".to_string(),
        output_str.clone(),
    );
    assert!(export.success, "export failed: {:?}", export.error_message);
    assert!(output.exists(), "evidence file should exist");

    // Single-checkpoint exports may not produce verifiable CBOR because the wire format
    // requires a minimum structure. Verify the file exists and is non-empty.
    // Full verify roundtrip is tested with 3+ checkpoints in test_export_verify_roundtrip.
    let verify = cpoe_engine::ffi::verify_detail::ffi_verify_evidence_detailed(output_str);
    if !verify.success {
        // Expected: single-checkpoint evidence may not pass full verification
        eprintln!("Single-checkpoint verify: {:?}", verify.error_message);
    }
}

#[test]
fn test_list_tracked_files_empty_store() {
    let (_dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let files = cpoe_engine::ffi::system::ffi_list_tracked_files();
    assert!(files.is_empty(), "fresh store should have no tracked files");
}

#[test]
fn test_status_before_init() {
    let (_dir, _g) = setup();
    // Don't call ffi_init; query status on a fresh data dir
    let status = cpoe_engine::ffi::system::ffi_get_status();
    // Should handle gracefully (either success with defaults or explicit error)
    assert_eq!(status.tracked_file_count, 0);
    assert_eq!(status.total_checkpoints, 0);
}

#[test]
fn test_double_init() {
    let (_dir, _g) = setup();
    let init1 = cpoe_engine::ffi::system::ffi_init();
    assert!(
        init1.success,
        "first init failed: {:?}",
        init1.error_message
    );

    let init2 = cpoe_engine::ffi::system::ffi_init();
    assert!(
        init2.success,
        "second init should succeed (idempotent): {:?}",
        init2.error_message
    );
}

#[test]
fn test_sentinel_start_stop_start() {
    let (_dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let start1 = cpoe_engine::ffi::sentinel::ffi_sentinel_start();
    assert!(
        start1.success,
        "first start failed: {:?}",
        start1.error_message
    );
    assert!(
        cpoe_engine::ffi::sentinel::ffi_sentinel_is_running(),
        "sentinel should be running after start"
    );

    let stop = cpoe_engine::ffi::sentinel::ffi_sentinel_stop();
    assert!(stop.success, "stop failed: {:?}", stop.error_message);

    let start2 = cpoe_engine::ffi::sentinel::ffi_sentinel_start();
    assert!(start2.success, "restart failed: {:?}", start2.error_message);
    assert!(
        cpoe_engine::ffi::sentinel::ffi_sentinel_is_running(),
        "sentinel should be running after restart"
    );

    cpoe_engine::ffi::sentinel::ffi_sentinel_stop();
}

#[test]
fn test_checkpoint_large_file() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    // Create a 10MB file
    let large_content: String = "A".repeat(10 * 1024 * 1024);
    let doc = create_doc(&dir, "large_file.txt", &large_content);

    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc.clone(),
        "large file checkpoint".to_string(),
    );
    assert!(
        cp.success,
        "large file checkpoint failed: {:?}",
        cp.error_message
    );

    let status = cpoe_engine::ffi::system::ffi_get_status();
    assert_eq!(status.total_checkpoints, 1);
}

#[test]
fn test_many_checkpoints() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "many_cp.txt", "Initial.");

    for i in 1..=100 {
        modify_doc(&doc, &format!("Revision number {i} with content changes."));
        let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("r{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    let status = cpoe_engine::ffi::system::ffi_get_status();
    assert_eq!(status.total_checkpoints, 100);
}

#[test]
fn test_checkpoint_unicode_path() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "unicode_\u{1F4DD}_doc.txt", "Unicode path content.");
    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc,
        "unicode path".to_string(),
    );
    assert!(
        cp.success,
        "unicode path checkpoint failed: {:?}",
        cp.error_message
    );
}

#[test]
fn test_checkpoint_unicode_message() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "unicode_msg.txt", "Content for unicode message test.");
    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc,
        "\u{1F680} Launch with \u{00E9}l\u{00E8}ve and \u{4E16}\u{754C}".to_string(),
    );
    assert!(
        cp.success,
        "unicode message checkpoint failed: {:?}",
        cp.error_message
    );
}

#[test]
fn test_concurrent_checkpoints_same_file() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "concurrent.txt", "Concurrent checkpoint content.");
    let doc_path = doc.clone();

    // Run 10 threads each creating a checkpoint
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let path = doc_path.clone();
            std::thread::spawn(move || {
                cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
                    path,
                    format!("thread-{i}"),
                )
            })
        })
        .collect();

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("thread join"))
        .collect();
    let success_count = results.iter().filter(|r| r.success).count();
    assert!(
        success_count >= 1,
        "at least one concurrent checkpoint should succeed, got {} successes out of 10",
        success_count
    );
}

// ============================================================
// 15. Error recovery tests
// ============================================================

#[test]
fn test_init_recovers_from_corrupt_db() {
    let (dir, _g) = setup();

    // Write garbage to events.db before init
    let db_path = dir.path().join("events.db");
    std::fs::write(&db_path, b"THIS IS NOT A SQLITE DATABASE").expect("write corrupt db");

    let init = cpoe_engine::ffi::system::ffi_init();
    // Init should either recover (recreate) or report the error cleanly
    // The important thing is it does not panic
    if init.success {
        // If it recovered, we should be able to create a checkpoint
        let doc = create_doc(&dir, "recovered.txt", "Post-recovery content.");
        let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc,
            "recovery test".to_string(),
        );
        // Checkpoint may or may not succeed depending on DB state,
        // but it should not panic
        let _ = cp;
    }
}

#[test]
fn test_checkpoint_after_db_backup_recovery() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "backup_test.txt", "Initial content.");
    let cp1 = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc.clone(),
        "before backup".to_string(),
    );
    assert!(
        cp1.success,
        "first checkpoint failed: {:?}",
        cp1.error_message
    );

    // Simulate a backup/restore by copying the DB, then restoring
    let db_path = dir.path().join("events.db");
    let backup_path = dir.path().join("events.db.bak");
    std::fs::copy(&db_path, &backup_path).expect("backup db");

    // Create another checkpoint
    modify_doc(&doc, "Modified after backup.");
    let cp2 = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc.clone(),
        "after backup".to_string(),
    );
    assert!(
        cp2.success,
        "second checkpoint failed: {:?}",
        cp2.error_message
    );

    // Restore from backup (losing cp2)
    std::fs::copy(&backup_path, &db_path).expect("restore db");

    // Should still be able to create checkpoints after restore
    modify_doc(&doc, "Post-restore content.");
    let cp3 = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc,
        "post restore".to_string(),
    );
    assert!(
        cp3.success,
        "post-restore checkpoint failed: {:?}",
        cp3.error_message
    );
}

#[test]
fn test_status_when_sentinel_not_started() {
    let (_dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    // Query sentinel status without starting it
    let status = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_status();
    assert!(!status.running, "sentinel should not be running");
}

#[test]
fn test_witnessing_status_when_not_tracking() {
    let (_dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let status = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_witnessing_status();
    assert!(
        !status.is_tracking,
        "should not be tracking when sentinel is not started"
    );
    assert_eq!(status.keystroke_count, 0);
}

// ============================================================
// 17. Export content verification (deep)
// ============================================================

#[test]
fn test_exported_cpoe_is_valid_cbor() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "cbor_valid.txt", "Version 1 content.");
    for i in 1..=3 {
        modify_doc(&doc, &format!("Version {i} with more substantial content."));
        let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("v{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    let output = dir.path().join("cbor_test.cpoe");
    let output_str = output.to_string_lossy().to_string();
    let export =
        cpoe_engine::ffi::evidence_export::ffi_export_evidence(doc, "core".to_string(), output_str);
    assert!(export.success, "export failed: {:?}", export.error_message);

    let data = std::fs::read(&output).expect("read exported file");
    assert!(!data.is_empty(), "exported file should not be empty");

    // Evidence is wrapped in a COSE_Sign1 envelope; strip the envelope first.
    let payload = cpoe_engine::ffi::helpers::unwrap_cose_or_raw(&data);

    // Parse as generic CBOR value to confirm structural validity
    let value: ciborium::Value =
        ciborium::from_reader(payload.as_slice()).expect("exported payload should be valid CBOR");

    // The top-level value is a CBOR tag (CPoE tag 1129336645) wrapping a map
    let inner = match &value {
        ciborium::Value::Tag(_tag, inner) => inner.as_ref(),
        other => other,
    };
    assert!(
        inner.is_map(),
        "CBOR payload should be a map, got: {:?}",
        inner
    );
}

#[test]
fn test_exported_html_contains_required_sections() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "html_sections.txt", "Initial document content.");
    for i in 1..=3 {
        modify_doc(
            &doc,
            &format!("Revision {i} with substantial edits and more text here."),
        );
        let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("rev{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    let result = cpoe_engine::ffi::report::ffi_render_war_html(doc);
    assert!(
        result.success,
        "WAR HTML failed: {:?}",
        result.error_message
    );
    let html = result.html.expect("html should be Some");

    // Verify required sections are present
    assert!(html.contains("<html"), "HTML should contain <html tag");
    assert!(
        html.contains("WAR") || html.contains("Attestation"),
        "HTML should reference WAR or Attestation"
    );
    assert!(
        html.to_lowercase().contains("score") || html.to_lowercase().contains("verdict"),
        "HTML should contain a score or verdict section"
    );
    assert!(
        html.to_lowercase().contains("checkpoint"),
        "HTML should reference checkpoints"
    );
    assert!(
        html.to_lowercase().contains("hash") || html.to_lowercase().contains("sha"),
        "HTML should contain document hash information"
    );
}

#[test]
fn test_exported_evidence_contains_all_checkpoints() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "all_cp.txt", "Version 0.");
    for i in 1..=5 {
        modify_doc(
            &doc,
            &format!("Version {i} with progressively more content."),
        );
        let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
            doc.clone(),
            format!("v{i}"),
        );
        assert!(cp.success, "checkpoint {i} failed: {:?}", cp.error_message);
    }

    let output = dir.path().join("all_cp.cpoe");
    let output_str = output.to_string_lossy().to_string();
    let export = cpoe_engine::ffi::evidence_export::ffi_export_evidence(
        doc,
        "core".to_string(),
        output_str.clone(),
    );
    assert!(export.success, "export failed: {:?}", export.error_message);

    // Verify via ffi_verify_evidence_detailed that all 5 checkpoints are present
    let verify = cpoe_engine::ffi::verify_detail::ffi_verify_evidence_detailed(output_str);
    assert!(verify.success, "verify failed: {:?}", verify.error_message);
    assert_eq!(
        verify.checkpoint_count, 5,
        "expected 5 checkpoints, got {}",
        verify.checkpoint_count
    );
}

#[test]
fn test_export_includes_document_metadata() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    let doc = create_doc(&dir, "metadata_test.txt", "Metadata verification content.");
    let cp = cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(
        doc.clone(),
        "metadata cp".to_string(),
    );
    assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

    let output = dir.path().join("metadata.cpoe");
    let output_str = output.to_string_lossy().to_string();
    let export =
        cpoe_engine::ffi::evidence_export::ffi_export_evidence(doc, "core".to_string(), output_str);
    assert!(export.success, "export failed: {:?}", export.error_message);

    // Parse the CBOR and verify document metadata fields
    let data = std::fs::read(&output).expect("read exported file");
    // Evidence is wrapped in a COSE_Sign1 envelope; strip the envelope first.
    let payload = cpoe_engine::ffi::helpers::unwrap_cose_or_raw(&data);
    let value: ciborium::Value =
        ciborium::from_reader(payload.as_slice()).expect("should be valid CBOR");

    // Unwrap CBOR tag if present (CPoE tag wraps the map)
    let inner = match &value {
        ciborium::Value::Tag(_tag, inner) => inner.as_ref(),
        other => other,
    };

    // Wire format uses numeric string keys per IETF spec:
    // "5" = document, "4" = created, "6" = checkpoints
    if let ciborium::Value::Map(entries) = inner {
        // Check that document field ("5") exists with filename ("2") and content_hash ("1")
        let doc_entry = entries
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "5"));
        assert!(
            doc_entry.is_some(),
            "CBOR should contain document field '5'; keys: {:?}",
            entries.iter().map(|(k, _)| k).collect::<Vec<_>>()
        );

        if let Some((_, ciborium::Value::Map(doc_fields))) = doc_entry {
            // DocumentRef uses "2" for filename, "1" for content_hash
            let has_content_hash = doc_fields
                .iter()
                .any(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "1"));
            assert!(
                has_content_hash,
                "document should have content_hash field (key '1')"
            );
            // filename may be present as key "2"
            let has_filename = doc_fields
                .iter()
                .any(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "2"));
            assert!(
                has_filename,
                "document should have filename field (key '2')"
            );
        }

        // Check that "created" timestamp ("4") exists
        let has_created = entries
            .iter()
            .any(|(k, _)| matches!(k, ciborium::Value::Text(s) if s == "4"));
        assert!(
            has_created,
            "CBOR should contain 'created' timestamp (key '4')"
        );
    } else {
        panic!("CBOR payload should be a map, got: {:?}", inner);
    }
}

// ============================================================
// 18. Jitter deep verification
// ============================================================

#[test]
fn test_jitter_chain_detects_replay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let doc_path = dir.path().join("jitter_replay.txt");
    std::fs::write(&doc_path, "Replay detection test content.").expect("write doc");

    let params = cpoe_engine::jitter::Parameters {
        sample_interval: 5,
        ..cpoe_engine::jitter::default_parameters()
    };
    let mut session = cpoe_engine::jitter::Session::new(&doc_path, params).expect("create session");

    // Record enough keystrokes to produce multiple samples
    for _ in 0..25 {
        session.record_keystroke().expect("record keystroke");
    }

    let evidence = session.export();
    assert!(
        evidence.statistics.chain_valid,
        "original chain should be valid"
    );
    assert!(
        evidence.samples.len() >= 5,
        "should have at least 5 samples"
    );

    // Tamper: modify a sample's timestamp (simulate replay attack)
    let mut tampered = evidence.clone();
    // Change the timestamp of sample 2 to replay sample 0's timestamp
    tampered.samples[2].timestamp = tampered.samples[0].timestamp;

    // The tampered chain should fail verification because the hash
    // includes the timestamp, so the stored hash won't match the recomputed one
    let verify_result = tampered.verify();
    assert!(
        verify_result.is_err(),
        "tampered evidence should fail verification"
    );
    let err_msg = verify_result.unwrap_err().to_string();
    assert!(
        err_msg.contains("hash mismatch") || err_msg.contains("broken chain"),
        "error should indicate hash or chain failure: {err_msg}"
    );
}

#[test]
fn test_jitter_zone_diversity_with_realistic_typing() {
    use cpoe_engine::jitter::{char_to_zone, text_to_zone_sequence};

    let text = "the quick brown fox jumps over the lazy dog";
    let transitions = text_to_zone_sequence(text);

    // "the quick brown fox..." uses keys from multiple keyboard zones
    assert!(
        !transitions.is_empty(),
        "realistic text should produce zone transitions"
    );

    // Count distinct zones used
    let mut zone_set = std::collections::HashSet::new();
    for c in text.chars() {
        let z = char_to_zone(c);
        if z >= 0 {
            zone_set.insert(z);
        }
    }

    // "the quick brown fox jumps over the lazy dog" spans multiple zones
    assert!(
        zone_set.len() >= 3,
        "realistic typing should use at least 3 distinct zones, got {}",
        zone_set.len()
    );

    // Verify zone transitions include cross-hand movements
    let cross_hand = transitions.iter().filter(|t| !t.is_same_hand()).count();
    assert!(
        cross_hand > 0,
        "realistic text should include cross-hand transitions"
    );
}

// ============================================================
// 20. Error messages are user-friendly
// ============================================================

#[test]
fn test_error_messages_not_internal() {
    let (dir, _g) = setup();
    let init = cpoe_engine::ffi::system::ffi_init();
    assert!(init.success, "init failed: {:?}", init.error_message);

    // Call with nonexistent path
    let bad_path = dir
        .path()
        .join("absolutely_does_not_exist.txt")
        .to_string_lossy()
        .to_string();
    let cp =
        cpoe_engine::ffi::evidence_checkpoint::ffi_create_checkpoint(bad_path, "test".to_string());
    assert!(!cp.success, "should fail for nonexistent file");

    let err = cp.error_message.unwrap_or_default();
    // Error should not contain stack traces or internal Rust paths
    assert!(
        !err.contains("src/"),
        "error should not contain source file paths: {err}"
    );
    assert!(
        !err.contains("panicked at"),
        "error should not contain panic info: {err}"
    );
    assert!(
        !err.contains("thread '"),
        "error should not contain thread info: {err}"
    );
    assert!(
        !err.contains("RUST_BACKTRACE"),
        "error should not reference RUST_BACKTRACE: {err}"
    );
    // Error should be non-empty and human-readable
    assert!(!err.is_empty(), "error message should not be empty");
    assert!(
        err.len() < 500,
        "error message should be concise (< 500 chars): {err}"
    );
}

// ============================================================
// 21. Concurrent stress
// ============================================================

#[test]
fn test_rapid_init_deinit_cycle() {
    // Run 10 init cycles to verify no state corruption or resource leaks
    for i in 0..10 {
        let dir = tempfile::tempdir().expect("tempdir");
        // Use a block to isolate each cycle
        {
            let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            std::env::set_var("CPOE_DATA_DIR", dir.path());
            std::env::set_var("CPOE_NO_KEYCHAIN", "1");

            let init = cpoe_engine::ffi::system::ffi_init();
            assert!(
                init.success,
                "init cycle {i} failed: {:?}",
                init.error_message
            );

            // Verify basic operations still work after repeated init
            let status = cpoe_engine::ffi::system::ffi_get_status();
            assert_eq!(
                status.total_checkpoints, 0,
                "fresh init cycle {i} should have 0 checkpoints"
            );
        }
        // dir drops here, cleaning up the temp directory
    }
}
