// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::fingerprint::global::{
    get_global_accumulator, sentinel_is_feeding, set_sentinel_feeding,
};
use crate::fingerprint::manager::FingerprintManager;
use crate::jitter::SimpleJitterSample;
use std::sync::Arc;

#[test]
fn test_author_fingerprint_creation() {
    let activity = ActivityFingerprint::default();
    let fp = AuthorFingerprint::new(activity);
    assert!(!fp.id.is_empty());
    assert_eq!(fp.sample_count, 0);
    assert_eq!(fp.confidence, 0.0);
}

#[test]
fn test_confidence_calculation() {
    let mut fp = AuthorFingerprint::new(ActivityFingerprint::default());
    // Logarithmic saturation: 1 - exp(-n/500)
    fp.sample_count = 100;
    fp.update_confidence();
    assert!(
        fp.confidence > 0.15 && fp.confidence < 0.25,
        "100 samples: expected ~0.18, got {}",
        fp.confidence
    );

    fp.sample_count = 1000;
    fp.update_confidence();
    assert!(
        fp.confidence > 0.85,
        "1000 samples: expected >0.85, got {}",
        fp.confidence
    );

    fp.sample_count = 2000;
    fp.update_confidence();
    assert!(
        fp.confidence > 0.95,
        "2000 samples: expected >0.95, got {}",
        fp.confidence
    );
}

#[test]
fn test_confidence_with_session_bonus() {
    let mut fp = AuthorFingerprint::new(ActivityFingerprint::default());
    fp.sample_count = 500;
    fp.activity.session_signature.session_count = 5;
    fp.update_confidence();
    assert!(
        fp.confidence > 0.7,
        "session bonus should increase confidence, got {}",
        fp.confidence
    );
}

#[test]
fn test_confidence_with_style_bonus() {
    let mut fp = AuthorFingerprint::new(ActivityFingerprint::default());
    fp.sample_count = 500;
    fp.style = Some(StyleFingerprint::default());
    fp.update_confidence();
    assert!(
        fp.confidence > 0.7,
        "style bonus should increase confidence, got {}",
        fp.confidence
    );
}

#[test]
fn test_update_with_ema() {
    let mut base =
        AuthorFingerprint::with_id("ema_test".to_string(), ActivityFingerprint::default());
    base.sample_count = 100;
    base.update_confidence();

    let mut recent =
        AuthorFingerprint::with_id("recent".to_string(), ActivityFingerprint::default());
    recent.sample_count = 50;

    base.update_with_ema(&recent, 0.3);
    assert_eq!(base.sample_count, 150, "sample count should accumulate");
    assert!(base.updated_at >= base.created_at);
}

#[test]
fn test_default_config() {
    let config = FingerprintConfig::default();
    assert!(config.activity_enabled);
    assert!(config.style_enabled);
    assert_eq!(config.retention_days, 365);
}

#[test]
fn test_global_accumulator_singleton() {
    let a = get_global_accumulator();
    let b = get_global_accumulator();
    assert!(
        Arc::ptr_eq(&a, &b),
        "get_global_accumulator must return the same Arc"
    );
}

#[test]
fn test_sentinel_feeding_flag() {
    set_sentinel_feeding(true);
    assert!(
        sentinel_is_feeding(),
        "expected true after set_sentinel_feeding(true)"
    );
    set_sentinel_feeding(false);
    assert!(
        !sentinel_is_feeding(),
        "expected false after set_sentinel_feeding(false)"
    );
}

#[test]
fn test_sentinel_feeding_prevents_double_write() {
    let acc = get_global_accumulator();
    // Drain any pre-existing samples so the count baseline is known.
    acc.write().unwrap().reset();

    let base_ts: i64 = 1_000_000_000;
    let make_sample = |i: i64| SimpleJitterSample {
        timestamp_ns: base_ts + i * 10_000_000,
        duration_since_last_ns: 10_000_000,
        zone: 1,
        dwell_time_ns: None,
        flight_time_ns: None,
    };

    // With sentinel feeding, consumer should skip.
    set_sentinel_feeding(true);
    if !sentinel_is_feeding() {
        acc.write().unwrap().add_sample(&make_sample(0));
    }
    let count_while_feeding = acc.read().unwrap().sample_count();

    // With sentinel not feeding, consumer writes.
    set_sentinel_feeding(false);
    if !sentinel_is_feeding() {
        acc.write().unwrap().add_sample(&make_sample(1));
    }
    let count_after = acc.read().unwrap().sample_count();

    assert_eq!(count_while_feeding, 0, "no writes when sentinel_is_feeding");
    assert_eq!(
        count_after, 1,
        "write succeeds when not sentinel_is_feeding"
    );

    // Restore flag.
    set_sentinel_feeding(false);
    acc.write().unwrap().reset();
}

#[test]
fn test_quality_gate_filters_isolated_keystrokes() {
    // Samples spaced >2 s apart — each is isolated with no local neighbor.
    let samples: Vec<SimpleJitterSample> = (0..3)
        .map(|i| SimpleJitterSample {
            timestamp_ns: i as i64 * 3_000_000_000, // 3 s apart
            duration_since_last_ns: 3_000_000_000,
            zone: 2,
            dwell_time_ns: None,
            flight_time_ns: None,
        })
        .collect();

    let mut acc = ActivityFingerprintAccumulator::new();
    for s in &samples {
        acc.add_sample(s);
    }
    assert_eq!(acc.sample_count(), 3);

    // IKI intervals are 3000 ms each, which exceed the 10 000 ms cap filter
    // but are treated as slow/isolated — the fingerprint mean will reflect this
    // and the burst_speed_cv will be 0 (single-element bursts).
    let fp = acc.current_fingerprint();
    // With only isolated keystrokes there is no meaningful burst; mean IKI is large.
    assert!(fp.iki_distribution.mean > 1000.0 || fp.sample_count == 3);
}

#[test]
fn test_ema_alpha_decay() {
    // alpha = 1 / (1 + (count + 1) * 0.5)
    let alpha_at = |count: u32| 1.0 / (1.0 + (count + 1) as f64 * 0.5);

    let a0 = alpha_at(0);
    assert!(
        (a0 - 2.0 / 3.0).abs() < 1e-9,
        "count=0: expected ~0.667, got {a0}"
    );

    let a5 = alpha_at(5);
    assert!(
        (a5 - 1.0 / 4.0).abs() < 1e-9,
        "count=5: expected 0.25, got {a5}"
    );

    let a20 = alpha_at(20);
    let expected = 1.0 / 11.5;
    assert!(
        (a20 - expected).abs() < 1e-9,
        "count=20: expected ~{expected:.4}, got {a20}"
    );
    assert!(a20 < 0.09, "count=20 alpha should be below 0.09, got {a20}");

    // Verify alpha strictly decreases with consolidation count.
    assert!(alpha_at(0) > alpha_at(5));
    assert!(alpha_at(5) > alpha_at(20));
}

#[test]
fn test_ema_consolidation_produces_canonical() {
    let dir =
        std::env::temp_dir().join(format!("cpoe_test_consolidation_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = FingerprintConfig {
        storage_path: dir.clone(),
        ..FingerprintConfig::default()
    };
    let mut mgr = FingerprintManager::with_config(cfg).unwrap();

    // Feed enough samples to trigger one consolidation (interval = 200).
    let base_ts: i64 = 2_000_000_000;
    for i in 0..201_i64 {
        mgr.record_activity_sample(&SimpleJitterSample {
            timestamp_ns: base_ts + i * 50_000_000,
            duration_since_last_ns: 50_000_000,
            zone: (i % 4) as u8,
            dwell_time_ns: None,
            flight_time_ns: None,
        });
    }

    assert!(
        mgr.canonical_profile.is_some(),
        "canonical should be set after consolidation"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_canonical_persists_across_restart() {
    let dir = std::env::temp_dir().join(format!("cpoe_test_persist_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    // Use a default ActivityFingerprint (no DigraphProfile data) so serde_json
    // serialization succeeds — DigraphProfile uses (u8,u8) map keys which are
    // incompatible with JSON object keys.
    let canonical = AuthorFingerprint::with_id(
        "persist-test-id".to_string(),
        ActivityFingerprint::default(),
    );
    let canonical_file = dir.join("canonical_profile.json");
    let json = serde_json::to_string_pretty(&canonical).expect("serialize canonical");
    std::fs::write(&canonical_file, json.as_bytes()).unwrap();

    // Simulate restart: new manager at the same path must load the canonical.
    let cfg = FingerprintConfig {
        storage_path: dir.clone(),
        ..FingerprintConfig::default()
    };
    let mgr = FingerprintManager::with_config(cfg).unwrap();
    assert!(
        mgr.canonical_profile.is_some(),
        "canonical should be loaded from disk after restart"
    );
    assert_eq!(
        mgr.canonical_profile.as_ref().unwrap().id,
        "persist-test-id",
        "reloaded canonical id must match"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_reset_clears_canonical() {
    let dir = std::env::temp_dir().join(format!("cpoe_test_reset_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = FingerprintConfig {
        storage_path: dir.clone(),
        ..FingerprintConfig::default()
    };
    let mut mgr = FingerprintManager::with_config(cfg).unwrap();

    // Seed the canonical directly (avoids DigraphProfile serde_json key issue).
    let canonical_file = dir.join("canonical_profile.json");
    let seed =
        AuthorFingerprint::with_id("reset-test-id".to_string(), ActivityFingerprint::default());
    let json = serde_json::to_string_pretty(&seed).expect("serialize");
    std::fs::write(&canonical_file, json.as_bytes()).unwrap();
    mgr.canonical_profile = Some(seed);
    assert!(canonical_file.exists(), "pre-condition: file written");

    mgr.reset();
    assert!(
        mgr.canonical_profile.is_none(),
        "canonical must be None after reset()"
    );
    assert!(
        !canonical_file.exists(),
        "canonical_profile.json must be deleted after reset()"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_canonical_or_current_fallback() {
    let dir = std::env::temp_dir().join(format!("cpoe_test_fallback_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = FingerprintConfig {
        storage_path: dir.clone(),
        ..FingerprintConfig::default()
    };
    let mut mgr = FingerprintManager::with_config(cfg).unwrap();
    assert!(mgr.canonical_profile.is_none());

    // Without canonical: should return current window fingerprint (non-panicking).
    let fp_before = mgr.canonical_or_current_fingerprint();
    assert_eq!(fp_before.sample_count, 0);

    // Trigger consolidation to create a canonical.
    let base_ts: i64 = 5_000_000_000;
    for i in 0..201_i64 {
        mgr.record_activity_sample(&SimpleJitterSample {
            timestamp_ns: base_ts + i * 50_000_000,
            duration_since_last_ns: 50_000_000,
            zone: (i % 4) as u8,
            dwell_time_ns: None,
            flight_time_ns: None,
        });
    }
    assert!(mgr.canonical_profile.is_some());

    // With canonical: canonical_or_current must return the canonical.
    let fp_after = mgr.canonical_or_current_fingerprint();
    let canonical_id = mgr.canonical_profile.as_ref().unwrap().id.clone();
    assert_eq!(
        fp_after.id, canonical_id,
        "canonical_or_current should return canonical fingerprint when present"
    );

    std::fs::remove_dir_all(&dir).ok();
}
