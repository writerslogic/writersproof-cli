// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

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
    assert!(!config.style_enabled);
    assert_eq!(config.retention_days, 365);
}
