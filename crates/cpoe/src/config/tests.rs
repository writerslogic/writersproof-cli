// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial
#![allow(clippy::field_reassign_with_default)]

use super::*;
use tempfile::tempdir;

#[test]
fn test_config_defaults() {
    let dir = tempdir().unwrap();
    let config = CpoeConfig::default_with_dir(dir.path());

    assert_eq!(config.data_dir, dir.path());
    assert_eq!(config.retention_days, 30);
    assert!(config.vdf.iterations_per_second > 0);
    assert!(config.sentinel.allowed_apps.is_empty());
    assert!(config.sentinel.track_unknown_apps);
    assert!(!config.sentinel.excluded_paths.is_empty());
    assert!(!config.sentinel.allowed_extensions.is_empty());
}

#[test]
fn test_config_persistence() {
    let dir = tempdir().unwrap();
    let config = CpoeConfig::default_with_dir(dir.path());
    config.persist().expect("persist failed");

    let loaded = CpoeConfig::load_or_default(dir.path()).expect("load failed");
    assert_eq!(loaded.data_dir, config.data_dir);
    assert_eq!(
        loaded.vdf.iterations_per_second,
        config.vdf.iterations_per_second
    );
}

#[test]
fn test_validate_defaults_pass() {
    let config = SentinelConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_zero_checkpoint_interval() {
    let mut config = SentinelConfig::default();
    config.checkpoint_interval_secs = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_validate_idle_less_than_checkpoint() {
    let mut config = SentinelConfig::default();
    config.idle_timeout_secs = 10;
    config.checkpoint_interval_secs = 60;
    assert!(config.validate().is_err());
}

#[test]
fn test_validate_zero_poll_interval() {
    let mut config = SentinelConfig::default();
    config.poll_interval_ms = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_sentinel_app_blocking() {
    let config = SentinelConfig::default();
    assert!(config.is_app_allowed("com.apple.TextEdit", "TextEdit"));
    assert!(!config.is_app_allowed("com.apple.finder", "Finder"));
    assert!(config.is_app_allowed("com.unknown.App", "Unknown"));
}
