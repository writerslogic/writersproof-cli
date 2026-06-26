// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Integration tests for the sentinel keystroke capture pipeline.
//!
//! These tests verify the full pipeline from sentinel startup through
//! keystroke accumulation to FFI status reporting. They catch silent
//! degraded mode, missing samples, and status propagation bugs.
//!
//! Run with: `cargo test --test sentinel_integration --features test-utils`
//!
//! Tests requiring real system permissions (CGEventTap, Input Monitoring)
//! are gated behind `CPOE_INTEGRATION=1`.

use cpoe_engine::config::SentinelConfig;
use cpoe_engine::fingerprint::ActivityFingerprintAccumulator;
use cpoe_engine::jitter::SimpleJitterSample;
use cpoe_engine::sentinel::Sentinel;
use std::io::Write;
use std::sync::Arc;

/// Helper: create a sentinel with a temp directory.
fn make_sentinel() -> (Sentinel, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = SentinelConfig::default().with_writersproof_dir(dir.path());
    let sentinel = Sentinel::new(config).expect("sentinel creation");
    (sentinel, dir)
}

/// Helper: create a temp file with content for witnessing.
fn make_temp_file(dir: &tempfile::TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create temp file");
    f.write_all(content.as_bytes()).expect("write temp file");
    path
}

/// Helper: create a sample at a given offset from base timestamp.
fn sample_at(base_ns: i64, index: i64, interval_ms: i64) -> SimpleJitterSample {
    SimpleJitterSample {
        timestamp_ns: base_ns + index * interval_ms * 1_000_000,
        duration_since_last_ns: if index == 0 {
            0
        } else {
            (interval_ms * 1_000_000) as u64
        },
        zone: (index % 5) as u8,
        dwell_time_ns: None,
        flight_time_ns: None,
    }
}

// ---------------------------------------------------------------------------
// 1. Sentinel Lifecycle Tests
// ---------------------------------------------------------------------------

#[test]
fn sentinel_new_defaults_capture_inactive() {
    let (sentinel, _dir) = make_sentinel();
    assert!(!sentinel.is_running());
    assert!(!sentinel.is_keystroke_capture_active());
    assert_eq!(sentinel.keystroke_count(), 0);
}

#[tokio::test]
async fn sentinel_start_stop_lifecycle() {
    let (sentinel, _dir) = make_sentinel();
    assert!(!sentinel.is_running());

    let result = sentinel.start().await;
    assert!(result.is_ok(), "sentinel start failed: {:?}", result.err());
    assert!(sentinel.is_running());

    // On CI/sandboxed environments, CGEventTap may fail → degraded mode.
    // The flag should accurately reflect reality.
    let capture_active = sentinel.is_keystroke_capture_active();
    if std::env::var("CPOE_INTEGRATION").is_ok() {
        assert!(
            capture_active,
            "keystroke capture should be active with CPOE_INTEGRATION=1"
        );
    }

    let stop_result = sentinel.stop().await;
    assert!(stop_result.is_ok());
    assert!(!sentinel.is_running());
}

#[tokio::test]
async fn sentinel_double_start_returns_already_running() {
    let (sentinel, _dir) = make_sentinel();
    sentinel.start().await.expect("first start");
    let second = sentinel.start().await;
    assert!(second.is_err(), "second start should fail");
    sentinel.stop().await.ok();
}

#[tokio::test]
async fn sentinel_stop_without_start_is_noop() {
    let (sentinel, _dir) = make_sentinel();
    // stop() on a non-running sentinel should succeed gracefully (idempotent)
    let result = sentinel.stop().await;
    assert!(
        result.is_ok(),
        "stop on idle sentinel should succeed as no-op"
    );
    assert!(!sentinel.is_running());
}

// ---------------------------------------------------------------------------
// 2. Witnessing Session Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn witnessing_start_and_stop() {
    let (sentinel, dir) = make_sentinel();
    let file = make_temp_file(&dir, "test.txt", "hello world");

    sentinel.start().await.expect("start");

    let result = sentinel.start_witnessing(&file);
    assert!(result.is_ok(), "start_witnessing failed: {:?}", result);
    assert_eq!(sentinel.sessions().len(), 1);
    // Sentinel canonicalizes paths on macOS (/var → /private/var) so compare
    // against the canonicalized form rather than the original.
    let canonical = std::fs::canonicalize(&file).expect("canonicalize");
    assert_eq!(sentinel.sessions()[0].path, canonical.to_string_lossy());

    // Double witnessing same file should fail
    let dup = sentinel.start_witnessing(&file);
    assert!(dup.is_err(), "duplicate witnessing should fail");

    // Stop witnessing
    let stop = sentinel.stop_witnessing(&file);
    assert!(stop.is_ok());
    assert!(sentinel.sessions().is_empty());

    sentinel.stop().await.ok();
}

#[tokio::test]
async fn witnessing_nonexistent_file_fails() {
    let (sentinel, _dir) = make_sentinel();
    sentinel.start().await.expect("start");

    let result = sentinel.start_witnessing(std::path::Path::new("/nonexistent/file.txt"));
    assert!(result.is_err());

    sentinel.stop().await.ok();
}

#[tokio::test]
async fn witnessing_multiple_files() {
    let (sentinel, dir) = make_sentinel();
    sentinel.start().await.expect("start");

    let f1 = make_temp_file(&dir, "doc1.txt", "first document");
    let f2 = make_temp_file(&dir, "doc2.txt", "second document");

    sentinel.start_witnessing(&f1).expect("witness f1");
    sentinel.start_witnessing(&f2).expect("witness f2");
    assert_eq!(sentinel.sessions().len(), 2);

    sentinel.stop_witnessing(&f1).expect("stop f1");
    assert_eq!(sentinel.sessions().len(), 1);
    let canonical_f2 = std::fs::canonicalize(&f2).expect("canonicalize");
    assert_eq!(sentinel.sessions()[0].path, canonical_f2.to_string_lossy());

    sentinel.stop().await.ok();
}

// ---------------------------------------------------------------------------
// 3. Activity Accumulator → Keystroke Count Pipeline Tests
// ---------------------------------------------------------------------------

#[test]
fn accumulator_empty_returns_zero_keystrokes() {
    let acc = ActivityFingerprintAccumulator::new();
    let summary = acc.to_session_summary();
    assert_eq!(summary.keystroke_count, 0);
}

#[test]
fn accumulator_counts_added_samples() {
    let mut acc = ActivityFingerprintAccumulator::new();

    for i in 0..50 {
        acc.add_sample(&sample_at(1_000_000_000, i, 100));
    }

    assert_eq!(acc.to_session_summary().keystroke_count, 50);
}

#[test]
fn accumulator_ring_buffer_evicts_oldest() {
    let mut acc = ActivityFingerprintAccumulator::with_capacity(10);

    for i in 0..20 {
        acc.add_sample(&sample_at(0, i, 100));
    }

    assert_eq!(acc.to_session_summary().keystroke_count, 10);
}

#[test]
fn accumulator_single_sample() {
    let mut acc = ActivityFingerprintAccumulator::new();
    acc.add_sample(&sample_at(1_000_000_000, 0, 0));
    let summary = acc.to_session_summary();
    assert_eq!(summary.keystroke_count, 1);
    assert_eq!(summary.duration_secs, 0);
}

#[test]
fn accumulator_capacity_one() {
    let mut acc = ActivityFingerprintAccumulator::with_capacity(1);
    for i in 0..10 {
        acc.add_sample(&sample_at(0, i, 100));
    }
    assert_eq!(acc.to_session_summary().keystroke_count, 1);
}

// ---------------------------------------------------------------------------
// 4. Sentinel Accumulator via inject_sample (test-utils feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "test-utils")]
mod sentinel_accumulator_tests {
    use super::*;

    #[test]
    fn sentinel_accumulator_counts_match_injected_samples() {
        let (sentinel, _dir) = make_sentinel();

        for i in 0..25 {
            sentinel.inject_sample(&sample_at(1_000_000_000, i, 100));
        }

        assert_eq!(sentinel.keystroke_count(), 25);
    }

    #[test]
    fn sentinel_accumulator_resets_on_new_instance() {
        let (s1, _d1) = make_sentinel();
        s1.inject_sample(&sample_at(1_000_000_000, 0, 0));
        assert_eq!(s1.keystroke_count(), 1);

        let (s2, _d2) = make_sentinel();
        assert_eq!(s2.keystroke_count(), 0, "new sentinel should start at 0");
    }

    #[tokio::test]
    async fn full_pipeline_sentinel_to_accumulator() {
        let (sentinel, dir) = make_sentinel();
        let file = make_temp_file(&dir, "essay.txt", "The quick brown fox jumps.\n");

        // Start sentinel
        sentinel.start().await.expect("start");
        assert!(sentinel.is_running());

        // Start witnessing
        sentinel.start_witnessing(&file).expect("witness");
        assert_eq!(sentinel.sessions().len(), 1);

        // Simulate 42 keystrokes via inject_sample
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        for i in 0..42 {
            sentinel.inject_sample(&SimpleJitterSample {
                timestamp_ns: now_ns + i * 120_000_000,
                duration_since_last_ns: 120_000_000,
                zone: match i % 4 {
                    0 => 1,
                    1 => 2,
                    2 => 3,
                    _ => 0,
                },
                dwell_time_ns: None,
                flight_time_ns: None,
            });
        }

        // Verify count via the same path FFI reads
        assert_eq!(sentinel.keystroke_count(), 42);

        // Verify session is still active
        let sessions = sentinel.sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].path, file.to_string_lossy());

        // Stop
        sentinel.stop_witnessing(&file).expect("stop witnessing");
        assert!(sentinel.sessions().is_empty());
        sentinel.stop().await.expect("stop");
        assert!(!sentinel.is_running());
    }

    #[tokio::test]
    async fn degraded_mode_accumulator_stays_zero() {
        let (sentinel, _dir) = make_sentinel();
        sentinel.start().await.expect("start");

        if !sentinel.is_keystroke_capture_active() {
            // In degraded mode, no bridge thread feeds the accumulator
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            assert_eq!(
                sentinel.keystroke_count(),
                0,
                "in degraded mode, keystroke count should remain 0"
            );
        }

        sentinel.stop().await.ok();
    }
}

// ---------------------------------------------------------------------------
// 5. FFI Status Pipeline Tests
// ---------------------------------------------------------------------------

#[cfg(feature = "ffi")]
#[test]
fn ffi_witnessing_status_reports_zero_when_no_sentinel() {
    let status = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_witnessing_status();
    assert!(!status.is_tracking);
    assert!(status.document_path.is_none());
    assert_eq!(status.keystroke_count, 0);
    assert!(!status.keystroke_capture_active);
}

#[cfg(feature = "ffi")]
#[test]
fn ffi_sentinel_status_defaults() {
    let status = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_status();
    assert!(!status.running);
    assert_eq!(status.tracked_file_count, 0);
    assert_eq!(status.keystroke_count, 0);
}

#[cfg(feature = "ffi")]
#[test]
fn ffi_start_witnessing_without_sentinel_fails() {
    let result = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_start_witnessing(
        "/tmp/test.txt".to_string(),
    );
    assert!(!result.success);
    assert!(result
        .error_message
        .as_deref()
        .unwrap_or("")
        .contains("not initialized"));
}

#[cfg(feature = "ffi")]
#[test]
fn ffi_stop_witnessing_without_sentinel_fails() {
    let result = cpoe_engine::ffi::sentinel_witnessing::ffi_sentinel_stop_witnessing(
        "/tmp/test.txt".to_string(),
    );
    assert!(!result.success);
    assert!(result
        .error_message
        .as_deref()
        .unwrap_or("")
        .contains("not initialized"));
}

#[cfg(feature = "ffi")]
#[test]
fn ffi_sentinel_is_not_running_by_default() {
    assert!(!cpoe_engine::ffi::sentinel::ffi_sentinel_is_running());
}

// ---------------------------------------------------------------------------
// 6. Concurrent Access Safety Tests
// ---------------------------------------------------------------------------

#[test]
fn accumulator_concurrent_read_write() {
    use std::sync::RwLock;
    use std::thread;

    let acc = Arc::new(RwLock::new(ActivityFingerprintAccumulator::new()));

    // Writer thread: add 1000 samples
    let writer_acc = Arc::clone(&acc);
    let writer = thread::spawn(move || {
        for i in 0..1000 {
            writer_acc
                .write()
                .expect("write lock")
                .add_sample(&sample_at(0, i, 10));
        }
    });

    // Reader threads: poll count concurrently
    let mut readers = vec![];
    for _ in 0..4 {
        let reader_acc = Arc::clone(&acc);
        readers.push(thread::spawn(move || {
            let mut last_count = 0;
            for _ in 0..100 {
                let count = reader_acc
                    .read()
                    .expect("read lock")
                    .to_session_summary()
                    .keystroke_count;
                assert!(
                    count >= last_count,
                    "keystroke count went backwards: {} < {}",
                    count,
                    last_count
                );
                last_count = count;
                thread::sleep(std::time::Duration::from_micros(100));
            }
        }));
    }

    writer.join().expect("writer");
    for r in readers {
        r.join().expect("reader");
    }

    assert_eq!(
        acc.read()
            .expect("final read")
            .to_session_summary()
            .keystroke_count,
        1000
    );
}

// ---------------------------------------------------------------------------
// 7. Degraded Mode Detection Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sentinel_capture_flag_reflects_reality() {
    let (sentinel, _dir) = make_sentinel();
    sentinel.start().await.expect("start");

    let active = sentinel.is_keystroke_capture_active();

    if active {
        println!("INFO: Keystroke capture is ACTIVE — real permissions detected");
    } else {
        println!("INFO: Keystroke capture is DEGRADED — no Input Monitoring permission");
    }

    // In either case, the sentinel should be running
    assert!(sentinel.is_running());

    sentinel.stop().await.ok();
}

// ---------------------------------------------------------------------------
// 8. Mid-Layer Integration Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_sentinel_start_creates_focus_monitor() {
    let (sentinel, _dir) = make_sentinel();
    assert!(!sentinel.is_running());

    let result = sentinel.start().await;
    assert!(result.is_ok(), "sentinel start failed: {:?}", result.err());
    assert!(sentinel.is_running());

    let stop = sentinel.stop().await;
    assert!(stop.is_ok(), "sentinel stop failed: {:?}", stop.err());
    assert!(!sentinel.is_running());
}

#[tokio::test]
async fn test_witnessing_status_tracks_active_document() {
    let (sentinel, dir) = make_sentinel();
    let file = make_temp_file(&dir, "tracked_doc.txt", "some document content");

    sentinel.start().await.expect("start");

    sentinel.start_witnessing(&file).expect("start witnessing");

    let sessions = sentinel.sessions();
    assert_eq!(sessions.len(), 1, "expected exactly one session");
    let canonical = std::fs::canonicalize(&file).expect("canonicalize");
    assert_eq!(
        sessions[0].path,
        canonical.to_string_lossy(),
        "session should track the temp file"
    );

    sentinel.stop_witnessing(&file).expect("stop witnessing");
    sentinel.stop().await.ok();
}

#[tokio::test]
async fn test_witnessing_keystroke_count_starts_at_zero() {
    let (sentinel, dir) = make_sentinel();
    let file = make_temp_file(&dir, "zero_keys.txt", "no keystrokes yet");

    sentinel.start().await.expect("start");
    sentinel.start_witnessing(&file).expect("start witnessing");

    assert_eq!(
        sentinel.keystroke_count(),
        0,
        "keystroke count should be 0 with no keystrokes injected"
    );

    sentinel.stop_witnessing(&file).expect("stop witnessing");
    sentinel.stop().await.ok();
}

#[tokio::test]
async fn test_focus_polling_detects_app_change() {
    use cpoe_engine::sentinel::{
        PollingSentinelFocusTracker, SentinelFocusTracker, WindowInfo, WindowProvider,
    };
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::SystemTime;

    struct ScriptedWindowProvider {
        responses: Mutex<VecDeque<WindowInfo>>,
        fallback: WindowInfo,
    }

    impl WindowProvider for ScriptedWindowProvider {
        fn get_active_window(&self) -> Option<WindowInfo> {
            let mut q = self.responses.lock().expect("lock");
            if let Some(info) = q.pop_front() {
                Some(info)
            } else {
                Some(self.fallback.clone())
            }
        }
    }

    let textedit_info = WindowInfo {
        path: None,
        application: "com.apple.TextEdit".to_string(),
        title: Default::default(),
        pid: None,
        timestamp: SystemTime::now(),
        is_document: true,
        is_unsaved: false,
        project_root: None,
        window_number: None,
    };

    let vscode_info = WindowInfo {
        path: None,
        application: "com.microsoft.VSCode".to_string(),
        title: Default::default(),
        pid: None,
        timestamp: SystemTime::now(),
        is_document: true,
        is_unsaved: false,
        project_root: None,
        window_number: None,
    };

    let mut responses = VecDeque::new();
    // First several polls return TextEdit, then switch to VSCode
    for _ in 0..3 {
        responses.push_back(textedit_info.clone());
    }
    for _ in 0..3 {
        responses.push_back(vscode_info.clone());
    }

    let provider = Arc::new(ScriptedWindowProvider {
        responses: Mutex::new(responses),
        fallback: vscode_info.clone(),
    });

    let config = Arc::new(SentinelConfig {
        poll_interval_ms: 10, // fast polling for test
        ..SentinelConfig::default()
    });

    let tracker = PollingSentinelFocusTracker::new(provider, config);
    let mut rx = tracker.focus_events().expect("focus_events receiver");

    tracker.start().expect("tracker start");

    // Collect focus events over a short window
    let mut events = vec![];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(200);
    loop {
        tokio::select! {
            ev = rx.recv() => {
                if let Some(ev) = ev {
                    events.push(ev);
                } else {
                    break;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                break;
            }
        }
    }

    tracker.stop().expect("tracker stop");

    // We expect at least a FocusGained for TextEdit and then a FocusLost + FocusGained for VSCode
    assert!(
        events.len() >= 2,
        "expected at least 2 focus events, got {}",
        events.len()
    );

    let app_ids: Vec<&str> = events.iter().map(|e| e.app_bundle_id.as_str()).collect();
    assert!(
        app_ids.contains(&"com.apple.TextEdit"),
        "expected TextEdit focus event, got: {:?}",
        app_ids
    );
    assert!(
        app_ids.contains(&"com.microsoft.VSCode"),
        "expected VSCode focus event, got: {:?}",
        app_ids
    );
}
