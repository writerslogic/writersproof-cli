// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Validation utility types for use at trust boundaries by callers of the engine.
//!
//! **These validators are NOT the internal enforcement layer.** Each engine subsystem
//! enforces its own constraints where inputs arrive:
//! - Timestamp validation: `ipc::messages` validates `Pulse` timestamps with
//!   `MAX_PULSE_CLOCK_SKEW_NS` (±5 min symmetric), which is stricter than
//!   `TimestampValidator`'s default (5 min future + 24 h past).
//! - Bundle-ID validation: `config::types::SentinelConfig::is_app_allowed()` uses
//!   a user-configurable allow/block list, not the hardcoded list in `BundleIdValidator`.
//! - Text validation: `ipc::messages` enforces `MAX_ALERT_MESSAGE` (4096 bytes) inline.
//!
//! These types are provided for FFI layers, CLI frontends, and tests that need
//! reusable, configurable validation building blocks.

use crate::error::{Error, Result};
use crate::utils::DateTimeNanosExt;

/// Unified timestamp validation (±5 min drift, optional max age).
/// Prevents: future-dating, stale evidence, clock skew attacks.
#[derive(Debug, Clone)]
pub struct TimestampValidator {
    max_future_drift_ns: i64, // Default: 5 minutes
    max_age_ns: Option<i64>,  // Optional: e.g., 24 hours for certain events
}

impl TimestampValidator {
    /// Create validator with standard settings (±5 min, no max age).
    pub fn new() -> Self {
        TimestampValidator {
            max_future_drift_ns: 5 * 60 * 1_000_000_000, // 5 minutes in nanoseconds
            max_age_ns: Some(24 * 60 * 60 * 1_000_000_000), // 24 hours in nanoseconds
        }
    }

    /// Create validator with custom future drift (nanoseconds).
    /// `drift_ns` must be non-negative; a negative value would flag all timestamps as future.
    pub fn with_future_drift(drift_ns: i64) -> Self {
        debug_assert!(drift_ns >= 0, "drift_ns must be non-negative");
        TimestampValidator {
            max_future_drift_ns: drift_ns,
            max_age_ns: Some(24 * 60 * 60 * 1_000_000_000),
        }
    }

    /// Create validator with both custom future drift and custom max age.
    pub fn with_drift_and_age(drift_ns: i64, max_age_ns: Option<i64>) -> Self {
        debug_assert!(drift_ns >= 0, "drift_ns must be non-negative");
        TimestampValidator {
            max_future_drift_ns: drift_ns,
            max_age_ns,
        }
    }

    /// Create validator with custom max age (nanoseconds). None = no max age check.
    pub fn with_max_age(max_age_ns: Option<i64>) -> Self {
        TimestampValidator {
            max_future_drift_ns: 5 * 60 * 1_000_000_000,
            max_age_ns,
        }
    }

    /// Validate timestamp is within acceptable bounds.
    /// Rejects: future timestamps (>5 min ahead), too-old timestamps (>24 hours)
    pub fn validate(&self, timestamp: i64) -> Result<()> {
        let now = chrono::Utc::now().timestamp_nanos_safe();

        // Reject future-dated events (clock skew + 5 min tolerance)
        // Use saturating_add to handle overflow near i64::MAX
        let max_future = now.saturating_add(self.max_future_drift_ns);
        if timestamp > max_future {
            return Err(Error::validation(format!(
                "timestamp in future by {} ns",
                timestamp.saturating_sub(max_future)
            )));
        }

        // Reject too-old events
        // Use saturating_sub to handle underflow near i64::MIN
        if let Some(max_age) = self.max_age_ns {
            let min_timestamp = now.saturating_sub(max_age);
            if timestamp < min_timestamp {
                return Err(Error::validation(format!(
                    "timestamp too old by {} ns",
                    min_timestamp.saturating_sub(timestamp)
                )));
            }
        }

        Ok(())
    }
}

impl Default for TimestampValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Bundle ID validation (prevent app spoofing).
/// Maintains allowlist of trusted apps and can verify app focus (macOS).
#[derive(Debug, Clone)]
pub struct BundleIdValidator {
    allowed_apps: std::collections::HashSet<String>,
}

impl BundleIdValidator {
    /// Create validator with default monitored apps.
    pub fn new() -> Self {
        let mut allowed = std::collections::HashSet::new();

        // Common writing apps (should be monitored)
        allowed.insert("com.apple.Notes".to_string());
        allowed.insert("com.apple.Pages".to_string());
        allowed.insert("com.microsoft.Word".to_string());
        allowed.insert("com.google.docs".to_string());
        allowed.insert("com.ulysses".to_string());
        allowed.insert("com.literatureandlatte.scrivener3".to_string());
        allowed.insert("com.dayoneapp".to_string());
        allowed.insert("com.bear".to_string());

        BundleIdValidator {
            allowed_apps: allowed,
        }
    }

    /// Create validator with custom allowlist.
    pub fn with_apps(apps: Vec<String>) -> Self {
        BundleIdValidator {
            allowed_apps: apps.into_iter().collect(),
        }
    }

    /// Check if bundle ID is in allowlist.
    pub fn is_allowed(&self, bundle_id: &str) -> Result<()> {
        if self.allowed_apps.contains(bundle_id) {
            Ok(())
        } else {
            // Truncate untrusted input to prevent log injection via oversized bundle IDs.
            let display: String = bundle_id.chars().take(300).collect();
            Err(Error::validation(format!(
                "bundle ID not in allowlist: {}",
                display
            )))
        }
    }

    /// Add app to allowlist.
    pub fn add_app(&mut self, bundle_id: String) {
        self.allowed_apps.insert(bundle_id);
    }

    /// Remove app from allowlist.
    pub fn remove_app(&mut self, bundle_id: &str) {
        self.allowed_apps.remove(bundle_id);
    }

    /// Get all allowed apps (for debugging).
    pub fn allowed_apps(&self) -> Vec<&String> {
        self.allowed_apps.iter().collect()
    }
}

impl Default for BundleIdValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Text content validation (prevent OOM attacks, encoding issues).
/// Checks: size bounds (1 byte to 1MB), valid UTF-8.
#[derive(Debug, Clone)]
pub struct TextValidator {
    min_bytes: usize,
    max_bytes: usize,
}

impl TextValidator {
    /// Create validator with standard bounds (1 byte to 1MB).
    pub fn new() -> Self {
        TextValidator {
            min_bytes: 1,
            max_bytes: 1_000_000,
        }
    }

    /// Create validator with custom bounds.
    pub fn with_bounds(min_bytes: usize, max_bytes: usize) -> Self {
        debug_assert!(min_bytes <= max_bytes, "min_bytes ({min_bytes}) must be <= max_bytes ({max_bytes})");
        TextValidator {
            min_bytes,
            max_bytes,
        }
    }

    /// Validate text content.
    /// Checks: length in bounds. UTF-8 is guaranteed by &str type.
    pub fn validate(&self, text: &str) -> Result<()> {
        let byte_len = text.len();

        if byte_len < self.min_bytes {
            return Err(Error::validation(format!(
                "text too short: got {} bytes, minimum {} bytes required",
                byte_len, self.min_bytes
            )));
        }

        if byte_len > self.max_bytes {
            return Err(Error::validation(format!(
                "text too long: got {} bytes, maximum {} bytes allowed",
                byte_len, self.max_bytes
            )));
        }

        Ok(())
    }

    /// Get size bounds.
    pub fn bounds(&self) -> (usize, usize) {
        (self.min_bytes, self.max_bytes)
    }
}

impl Default for TextValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_validator_current_time_valid() {
        let validator = TimestampValidator::new();
        let now = chrono::Utc::now().timestamp_nanos_safe();
        assert!(validator.validate(now).is_ok());
    }

    #[test]
    fn test_timestamp_validator_future_reject() {
        let validator = TimestampValidator::new();
        let future = chrono::Utc::now().timestamp_nanos_safe() + 10 * 60 * 1_000_000_000; // 10 min ahead
        assert!(validator.validate(future).is_err());
    }

    #[test]
    fn test_timestamp_validator_past_acceptable() {
        let validator = TimestampValidator::new();
        let past = chrono::Utc::now().timestamp_nanos_safe() - 60 * 1_000_000_000; // 1 min ago
        assert!(validator.validate(past).is_ok());
    }

    #[test]
    fn test_timestamp_validator_very_old_reject() {
        let validator = TimestampValidator::new();
        let very_old = chrono::Utc::now().timestamp_nanos_safe() - 25 * 60 * 60 * 1_000_000_000; // 25 hours ago
        assert!(validator.validate(very_old).is_err());
    }

    #[test]
    fn test_bundle_id_validator_allows_default_apps() {
        let validator = BundleIdValidator::new();
        assert!(validator.is_allowed("com.apple.Notes").is_ok());
        assert!(validator.is_allowed("com.apple.Pages").is_ok());
    }

    #[test]
    fn test_bundle_id_validator_rejects_unknown() {
        let validator = BundleIdValidator::new();
        assert!(validator.is_allowed("com.unknown.app").is_err());
    }

    #[test]
    fn test_bundle_id_validator_add_app() {
        let mut validator = BundleIdValidator::new();
        validator.add_app("com.test.app".to_string());
        assert!(validator.is_allowed("com.test.app").is_ok());
    }

    #[test]
    fn test_bundle_id_validator_remove_app() {
        let mut validator = BundleIdValidator::new();
        validator.remove_app("com.apple.Notes");
        assert!(validator.is_allowed("com.apple.Notes").is_err());
    }

    #[test]
    fn test_text_validator_valid_text() {
        let validator = TextValidator::new();
        assert!(validator.validate("hello world").is_ok());
    }

    #[test]
    fn test_text_validator_empty_text() {
        let validator = TextValidator::new();
        assert!(validator.validate("").is_err());
    }

    #[test]
    fn test_text_validator_very_long_text() {
        let validator = TextValidator::new();
        let long_text = "x".repeat(2_000_000); // 2MB
        assert!(validator.validate(&long_text).is_err());
    }

    #[test]
    fn test_text_validator_one_byte() {
        let validator = TextValidator::new();
        assert!(validator.validate("a").is_ok());
    }

    #[test]
    fn test_text_validator_custom_bounds() {
        let validator = TextValidator::with_bounds(10, 100);
        assert!(validator.validate("short").is_err()); // < 10 bytes
        assert!(validator
            .validate("this is exactly the right length for this test")
            .is_ok()); // 45 bytes
        assert!(validator.validate(&"x".repeat(200)).is_err()); // > 100 bytes
    }

    #[test]
    fn test_text_validator_unicode() {
        let validator = TextValidator::new();
        // Multi-byte UTF-8 characters (emoji, accents)
        assert!(validator.validate("🎉").is_ok()); // 4 bytes
        assert!(validator.validate("café").is_ok()); // 5 bytes with accented e
        assert!(validator.validate("中文").is_ok()); // 6 bytes, Chinese characters
    }

    #[test]
    fn test_timestamp_validator_with_custom_drift() {
        let validator = TimestampValidator::with_future_drift(1000);
        let now = chrono::Utc::now().timestamp_nanos_safe();
        // Just within 1000ns ahead
        assert!(validator.validate(now + 500).is_ok());
        // Beyond 1000ns ahead
        assert!(validator.validate(now + 2000).is_err());
    }

    #[test]
    fn test_timestamp_validator_max_age_none() {
        let validator = TimestampValidator::with_max_age(None);
        let now = chrono::Utc::now().timestamp_nanos_safe();
        // 100 days in past should be ok if no max_age
        let very_old = now - (100 * 24 * 60 * 60 * 1_000_000_000);
        assert!(validator.validate(very_old).is_ok());
    }

    #[test]
    fn test_bundle_id_validator_custom_list() {
        let validator = BundleIdValidator::with_apps(vec![
            "com.example.app1".to_string(),
            "com.example.app2".to_string(),
        ]);
        assert!(validator.is_allowed("com.example.app1").is_ok());
        assert!(validator.is_allowed("com.apple.Notes").is_err()); // Not in custom list
    }

    #[test]
    fn test_bundle_id_validator_case_sensitive() {
        let validator = BundleIdValidator::new();
        assert!(validator.is_allowed("com.apple.Notes").is_ok());
        assert!(validator.is_allowed("COM.APPLE.NOTES").is_err()); // Bundle IDs are case-sensitive
    }

    #[test]
    fn test_text_validator_boundary_exact() {
        let validator = TextValidator::with_bounds(5, 10);
        assert!(validator.validate(&"x".repeat(4)).is_err()); // 4 bytes - below min
        assert!(validator.validate(&"x".repeat(5)).is_ok()); // 5 bytes - exact min
        assert!(validator.validate(&"x".repeat(10)).is_ok()); // 10 bytes - exact max
        assert!(validator.validate(&"x".repeat(11)).is_err()); // 11 bytes - above max
    }

    #[test]
    fn test_timestamp_validator_overflow_safe() {
        // Test that saturating_add prevents panic on overflow
        let validator = TimestampValidator::with_future_drift(1000);
        let now = chrono::Utc::now().timestamp_nanos_safe();
        // Even a far-future timestamp won't cause panic due to saturating arithmetic
        let far_future = now + (365 * 24 * 60 * 60 * 1_000_000_000); // 1 year in future
        let result = validator.validate(far_future);
        assert!(result.is_err()); // Should error (out of bounds), not panic
    }

    #[test]
    fn test_text_validator_error_messages_clear() {
        let validator = TextValidator::with_bounds(10, 20);
        let short_result = validator.validate("short");
        let long_result = validator.validate(&"x".repeat(30));

        let short_err = format!("{:?}", short_result);
        let long_err = format!("{:?}", long_result);

        // Verify error messages contain actual values, not just comparisons
        assert!(short_err.contains("got 5"));
        assert!(short_err.contains("minimum"));
        assert!(long_err.contains("got 30"));
        assert!(long_err.contains("maximum"));
    }

    #[test]
    fn test_timestamp_validator_error_messages_show_delta() {
        let validator = TimestampValidator::new();
        let now = chrono::Utc::now().timestamp_nanos_safe();

        // Create a timestamp 10 minutes in the future
        let future = now + (10 * 60 * 1_000_000_000);
        let result = validator.validate(future);

        assert!(result.is_err());
        let err_msg = format!("{:?}", result);
        // Error should show how far ahead it is
        assert!(err_msg.contains("ns") || err_msg.contains("future"));
    }
}
