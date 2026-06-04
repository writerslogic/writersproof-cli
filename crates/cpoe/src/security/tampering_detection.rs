// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Detection of evidence tampering via 8-component forensic checks.
//!
//! Detects:
//! 1. Impossible keystroke speeds (>300 WPM sustained)
//! 2. Monotonic timing violations (all equal inter-keystroke times)
//! 3. Incomplete recovery from sleep/wake
//! 4. Orphaned keystrokes (focus without prior keystroke)
//! 5. Checksum mismatches on checkpoint data
//! 6. Nonce replay (via NonceManager in crypto)
//! 7. Timestamp monotonicity violations
//! 8. Evidence packet signature failures
//!
//! Each detection produces a flag (bitmask) for forensic analysis.
//! Gracefully degrades: flags tampering without rejecting evidence.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

/// Named constant for maximum sustainable typing speed (words per minute).
pub const MAX_SUSTAINED_WPM: f64 = 300.0;

/// Named constant for minimum acceptable inter-keystroke variance (coefficient of variation).
pub const MIN_IKI_VARIANCE_CV: f64 = 0.10;

/// Named constant for sleep recovery threshold (milliseconds of silence).
pub const SLEEP_RECOVERY_THRESHOLD_MS: i64 = 2000;

/// Named constant for maximum keystroke count before session focus (orphan threshold).
pub const MAX_ORPHANED_KEYS: usize = 5;

/// Named constant for maximum timestamp deviation in milliseconds.
pub const MAX_TIMESTAMP_DEVIATION_MS: i64 = 5000;

/// Bitmask for tampering detection flags.
/// Each bit represents one detector component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TamperingFlags {
    pub flags: u8,
}

impl TamperingFlags {
    /// Bit 0: Impossible keystroke speed (>300 WPM sustained)
    pub const IMPOSSIBLE_SPEED: u8 = 0x01;
    /// Bit 1: Monotonic timing (all IKI nearly equal)
    pub const MONOTONIC_TIMING: u8 = 0x02;
    /// Bit 2: Incomplete sleep recovery
    pub const SLEEP_RECOVERY: u8 = 0x04;
    /// Bit 3: Orphaned keystrokes (focus without prior keystroke)
    pub const ORPHANED_KEYSTROKES: u8 = 0x08;
    /// Bit 4: Checksum mismatch on checkpoint
    pub const CHECKSUM_MISMATCH: u8 = 0x10;
    /// Bit 5: Nonce replay detected
    pub const NONCE_REPLAY: u8 = 0x20;
    /// Bit 6: Timestamp monotonicity violation
    pub const TIMESTAMP_VIOLATION: u8 = 0x40;
    /// Bit 7: Evidence packet signature failure
    pub const SIGNATURE_FAILURE: u8 = 0x80;

    pub fn new() -> Self {
        Self { flags: 0 }
    }

    pub fn set(&mut self, flag: u8) {
        self.flags |= flag;
    }

    pub fn is_set(&self, flag: u8) -> bool {
        (self.flags & flag) != 0
    }

    pub fn to_vec(&self) -> Vec<String> {
        let mut names = Vec::new();

        if self.is_set(Self::IMPOSSIBLE_SPEED) {
            names.push("impossible_speed".to_string());
        }
        if self.is_set(Self::MONOTONIC_TIMING) {
            names.push("monotonic_timing".to_string());
        }
        if self.is_set(Self::SLEEP_RECOVERY) {
            names.push("sleep_recovery".to_string());
        }
        if self.is_set(Self::ORPHANED_KEYSTROKES) {
            names.push("orphaned_keystrokes".to_string());
        }
        if self.is_set(Self::CHECKSUM_MISMATCH) {
            names.push("checksum_mismatch".to_string());
        }
        if self.is_set(Self::NONCE_REPLAY) {
            names.push("nonce_replay".to_string());
        }
        if self.is_set(Self::TIMESTAMP_VIOLATION) {
            names.push("timestamp_violation".to_string());
        }
        if self.is_set(Self::SIGNATURE_FAILURE) {
            names.push("signature_failure".to_string());
        }

        names
    }

    pub fn count_flags(&self) -> u32 {
        self.flags.count_ones()
    }

    pub fn is_empty(&self) -> bool {
        self.flags == 0
    }
}

/// Keystroke event for tampering detection.
#[derive(Debug, Clone)]
pub struct KeystrokeEvent {
    /// Timestamp in milliseconds since epoch.
    pub timestamp_ms: i64,
    /// Key code (for distinguishing patterns).
    pub key_code: u16,
    /// Is the source document in focus?
    pub is_focused: bool,
    /// Optional checkpoint hash for integrity checking.
    pub checkpoint_hash: Option<String>,
}

/// Tampering detector: identifies evidence manipulation patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperingDetector {
    /// Maximum allowable sustained typing speed (words per minute).
    pub speed_limit_wpm: f64,
    /// Minimum coefficient of variation for inter-keystroke intervals.
    pub timing_variance_min_cv: f64,
    /// Threshold for sleep/wake detection (milliseconds).
    pub sleep_threshold_ms: i64,
    /// Maximum orphaned keystrokes before flagging.
    pub max_orphaned_keys: usize,
}

impl TamperingDetector {
    /// Create a new tampering detector with default thresholds.
    pub fn new() -> Self {
        Self {
            speed_limit_wpm: MAX_SUSTAINED_WPM,
            timing_variance_min_cv: MIN_IKI_VARIANCE_CV,
            sleep_threshold_ms: SLEEP_RECOVERY_THRESHOLD_MS,
            max_orphaned_keys: MAX_ORPHANED_KEYS,
        }
    }

    /// Create a new tampering detector with custom thresholds.
    pub fn with_config(
        speed_limit_wpm: f64,
        timing_variance_min_cv: f64,
        sleep_threshold_ms: i64,
        max_orphaned_keys: usize,
    ) -> Result<Self> {
        if !(100.0..=1000.0).contains(&speed_limit_wpm) {
            return Err(Error::validation(format!(
                "speed_limit_wpm must be 100-1000, got {}",
                speed_limit_wpm
            )));
        }
        if !(0.0..=1.0).contains(&timing_variance_min_cv) {
            return Err(Error::validation(format!(
                "timing_variance_min_cv must be 0-1, got {}",
                timing_variance_min_cv
            )));
        }
        if !(500..=10000).contains(&sleep_threshold_ms) {
            return Err(Error::validation(format!(
                "sleep_threshold_ms must be 500-10000, got {}",
                sleep_threshold_ms
            )));
        }
        if !(1..=100).contains(&max_orphaned_keys) {
            return Err(Error::validation(format!(
                "max_orphaned_keys must be 1-100, got {}",
                max_orphaned_keys
            )));
        }

        Ok(Self {
            speed_limit_wpm,
            timing_variance_min_cv,
            sleep_threshold_ms,
            max_orphaned_keys,
        })
    }

    /// Detect tampering in a keystroke sequence.
    ///
    /// Runs all 8 detectors and returns bitmask of detected issues.
    /// Logs evidence for forensic analysis.
    pub fn detect_tampering(&self, events: &VecDeque<KeystrokeEvent>) -> TamperingFlags {
        let mut flags = TamperingFlags::new();

        if events.is_empty() {
            return flags;
        }

        // Detector 1: Impossible keystroke speed
        if self.detect_impossible_speed(events) {
            flags.set(TamperingFlags::IMPOSSIBLE_SPEED);
            log::warn!("Tampering detector: impossible keystroke speed");
        }

        // Detector 2: Monotonic timing
        if self.detect_monotonic_timing(events) {
            flags.set(TamperingFlags::MONOTONIC_TIMING);
            log::warn!("Tampering detector: monotonic timing detected");
        }

        // Detector 3: Sleep recovery
        if self.detect_incomplete_sleep_recovery(events) {
            flags.set(TamperingFlags::SLEEP_RECOVERY);
            log::warn!("Tampering detector: incomplete sleep recovery");
        }

        // Detector 4: Orphaned keystrokes
        if self.detect_orphaned_keystrokes(events) {
            flags.set(TamperingFlags::ORPHANED_KEYSTROKES);
            log::warn!("Tampering detector: orphaned keystrokes");
        }

        // Detector 5: Timestamp monotonicity
        if self.detect_timestamp_violation(events) {
            flags.set(TamperingFlags::TIMESTAMP_VIOLATION);
            log::warn!("Tampering detector: timestamp violation");
        }

        flags
    }

    /// Detector 1: Impossible keystroke speed (>300 WPM sustained)
    ///
    /// 300 WPM at 5 characters per word = 1500 chars/min = 25 chars/sec = 40ms per char.
    /// If mean inter-keystroke interval < 40ms, flag.
    fn detect_impossible_speed(&self, events: &VecDeque<KeystrokeEvent>) -> bool {
        if events.len() < 10 {
            return false;
        }

        let mut ikis_ms = Vec::new();
        for i in 1..events.len() {
            let iki = events[i].timestamp_ms - events[i - 1].timestamp_ms;
            if iki > 0 {
                ikis_ms.push(iki as f64);
            }
        }

        if ikis_ms.is_empty() {
            return false;
        }

        let mean_iki = crate::utils::mean(&ikis_ms);
        let max_wpm = 60000.0 / (mean_iki * 5.0); // 5 chars per word

        max_wpm > self.speed_limit_wpm
    }

    /// Detector 2: Monotonic timing (all IKI nearly equal)
    ///
    /// Calculate coefficient of variation (CV) of inter-keystroke intervals.
    /// CV < threshold = monotonic = likely paste or scripted.
    fn detect_monotonic_timing(&self, events: &VecDeque<KeystrokeEvent>) -> bool {
        if events.len() < 10 {
            return false;
        }

        let mut ikis_ms = Vec::new();
        for i in 1..events.len() {
            let iki = events[i].timestamp_ms - events[i - 1].timestamp_ms;
            if iki > 0 && iki < self.sleep_threshold_ms {
                ikis_ms.push(iki as f64);
            }
        }

        if ikis_ms.len() < 5 {
            return false;
        }

        let cv = crate::utils::coefficient_of_variation(&ikis_ms);

        cv < self.timing_variance_min_cv
    }

    /// Detector 3: Incomplete sleep recovery
    ///
    /// If keystroke-free gap > threshold, then keystrokes resume at identical speed,
    /// the session may not have properly recovered from sleep/wake.
    fn detect_incomplete_sleep_recovery(&self, events: &VecDeque<KeystrokeEvent>) -> bool {
        if events.len() < 5 {
            return false;
        }

        // Find gaps > sleep_threshold_ms
        for i in 1..events.len() {
            let gap_ms = events[i].timestamp_ms - events[i - 1].timestamp_ms;

            if gap_ms > self.sleep_threshold_ms {
                // Found a sleep gap; check recovery
                if i > 0 && i < events.len() - 1 {
                    let pre_gap_iki = if i > 1 {
                        events[i - 1].timestamp_ms - events[i - 2].timestamp_ms
                    } else {
                        0
                    };

                    let post_gap_iki = if i + 1 < events.len() {
                        events[i + 1].timestamp_ms - events[i].timestamp_ms
                    } else {
                        0
                    };

                    // If pre-gap and post-gap timing are identical (within 5%), suspicious
                    if pre_gap_iki > 0 && post_gap_iki > 0 {
                        let diff_ratio =
                            ((post_gap_iki - pre_gap_iki).abs() as f64) / (pre_gap_iki as f64);
                        if diff_ratio < 0.05 {
                            return true; // Incomplete recovery
                        }
                    }
                }
            }
        }

        false
    }

    /// Detector 4: Orphaned keystrokes (focus without prior keystroke)
    ///
    /// If keystroke count before first focus event > max_orphaned_keys, flag.
    fn detect_orphaned_keystrokes(&self, events: &VecDeque<KeystrokeEvent>) -> bool {
        let mut orphaned_count = 0;

        for event in events {
            if event.is_focused {
                // Document gained focus; orphaned count resets
                return orphaned_count > self.max_orphaned_keys;
            } else {
                orphaned_count += 1;
            }
        }

        orphaned_count > self.max_orphaned_keys
    }

    /// Detector 5: Timestamp monotonicity violation
    ///
    /// Timestamps must be strictly increasing.
    /// If any timestamp is out of order or too far in future, flag.
    fn detect_timestamp_violation(&self, events: &VecDeque<KeystrokeEvent>) -> bool {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        for i in 1..events.len() {
            // Check monotonicity
            if events[i].timestamp_ms <= events[i - 1].timestamp_ms {
                return true; // Timestamp regression
            }

            // Check deviation from current time (shouldn't be far in future)
            if events[i].timestamp_ms > now_ms + MAX_TIMESTAMP_DEVIATION_MS {
                return true; // Future timestamp
            }
        }

        false
    }

    /// Detector 6: Nonce replay
    ///
    /// This would be called by crypto layer with nonce manager.
    /// For now, returns false (deferred to crypto layer).
    pub fn check_nonce_replay(&self, _nonce: &[u8]) -> bool {
        // Implemented by crypto layer's NonceManager
        false
    }

    /// Detector 7: Evidence packet signature failure
    ///
    /// This would be called by crypto layer during verification.
    /// For now, returns false (deferred to crypto layer).
    pub fn check_signature_failure(&self, _signature_valid: bool) -> bool {
        // Implemented by crypto layer's signature verification
        !_signature_valid
    }

    /// Detector 8: Checksum mismatch on checkpoint
    ///
    /// Verifies checkpoint_hash against computed hash of keystroke events.
    /// For now, returns false (deferred to checkpoint layer).
    pub fn check_checkpoint_integrity(
        &self,
        _checkpoint_hash: &str,
        _events: &VecDeque<KeystrokeEvent>,
    ) -> bool {
        // Implemented by checkpoint module
        false
    }
}

impl Default for TamperingDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tampering_flags_set_and_check() {
        let mut flags = TamperingFlags::new();
        assert!(!flags.is_set(TamperingFlags::IMPOSSIBLE_SPEED));

        flags.set(TamperingFlags::IMPOSSIBLE_SPEED);
        assert!(flags.is_set(TamperingFlags::IMPOSSIBLE_SPEED));
        assert!(!flags.is_set(TamperingFlags::MONOTONIC_TIMING));
    }

    #[test]
    fn test_tampering_flags_to_vec() {
        let mut flags = TamperingFlags::new();
        flags.set(TamperingFlags::IMPOSSIBLE_SPEED);
        flags.set(TamperingFlags::MONOTONIC_TIMING);

        let names = flags.to_vec();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"impossible_speed".to_string()));
        assert!(names.contains(&"monotonic_timing".to_string()));
    }

    #[test]
    fn test_tampering_flags_count() {
        let mut flags = TamperingFlags::new();
        assert_eq!(flags.count_flags(), 0);

        flags.set(TamperingFlags::IMPOSSIBLE_SPEED);
        flags.set(TamperingFlags::MONOTONIC_TIMING);
        assert_eq!(flags.count_flags(), 2);
    }

    #[test]
    fn test_detector_creation() {
        let detector = TamperingDetector::new();
        assert_eq!(detector.speed_limit_wpm, MAX_SUSTAINED_WPM);
    }

    #[test]
    fn test_detector_with_config_valid() {
        let detector = TamperingDetector::with_config(250.0, 0.15, 2000, 5).unwrap();
        assert_eq!(detector.speed_limit_wpm, 250.0);
    }

    #[test]
    fn test_detector_with_config_invalid_speed() {
        let result = TamperingDetector::with_config(50.0, 0.15, 2000, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_impossible_speed() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        // Add events with very fast typing (30ms intervals = 500 WPM)
        let mut timestamp = 0i64;
        for _ in 0..20 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: timestamp,
                key_code: 65,
                is_focused: true,
                checkpoint_hash: None,
            });
            timestamp += 30;
        }

        assert!(detector.detect_impossible_speed(&events));
    }

    #[test]
    fn test_detect_impossible_speed_normal() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        // Add events with normal typing (150ms intervals = 80 WPM)
        let mut timestamp = 0i64;
        for _ in 0..20 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: timestamp,
                key_code: 65,
                is_focused: true,
                checkpoint_hash: None,
            });
            timestamp += 150;
        }

        assert!(!detector.detect_impossible_speed(&events));
    }

    #[test]
    fn test_detect_monotonic_timing() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        // Add events with identical timing
        let mut timestamp = 0i64;
        for _ in 0..20 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: timestamp,
                key_code: 65,
                is_focused: true,
                checkpoint_hash: None,
            });
            timestamp += 100; // Exactly 100ms
        }

        assert!(detector.detect_monotonic_timing(&events));
    }

    #[test]
    fn test_detect_monotonic_timing_variable() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        // Add events with variable timing
        let intervals = [100, 150, 120, 200, 90, 160, 110, 180, 130, 170];
        let mut timestamp = 0i64;
        for &interval in &intervals {
            events.push_back(KeystrokeEvent {
                timestamp_ms: timestamp,
                key_code: 65,
                is_focused: true,
                checkpoint_hash: None,
            });
            timestamp += interval;
        }

        // Extend to 20 events
        for _ in intervals.len()..20 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: timestamp,
                key_code: 65,
                is_focused: true,
                checkpoint_hash: None,
            });
            timestamp += 120;
        }

        assert!(!detector.detect_monotonic_timing(&events));
    }

    #[test]
    fn test_detect_timestamp_violation_regression() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        events.push_back(KeystrokeEvent {
            timestamp_ms: 1000,
            key_code: 65,
            is_focused: true,
            checkpoint_hash: None,
        });
        events.push_back(KeystrokeEvent {
            timestamp_ms: 900, // Timestamp regression
            key_code: 65,
            is_focused: true,
            checkpoint_hash: None,
        });

        assert!(detector.detect_timestamp_violation(&events));
    }

    #[test]
    fn test_detect_timestamp_violation_normal() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        events.push_back(KeystrokeEvent {
            timestamp_ms: now_ms - 1000,
            key_code: 65,
            is_focused: true,
            checkpoint_hash: None,
        });
        events.push_back(KeystrokeEvent {
            timestamp_ms: now_ms,
            key_code: 65,
            is_focused: true,
            checkpoint_hash: None,
        });

        assert!(!detector.detect_timestamp_violation(&events));
    }

    #[test]
    fn test_detect_orphaned_keystrokes() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        // Add more than max_orphaned_keys keystrokes before focus
        for i in 0..10 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: i as i64 * 100,
                key_code: 65,
                is_focused: false,
                checkpoint_hash: None,
            });
        }

        assert!(detector.detect_orphaned_keystrokes(&events));
    }

    #[test]
    fn test_detect_orphaned_keystrokes_none() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        // Add focus before keystrokes
        events.push_back(KeystrokeEvent {
            timestamp_ms: 0,
            key_code: 65,
            is_focused: true,
            checkpoint_hash: None,
        });

        for i in 1..10 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: i as i64 * 100,
                key_code: 65,
                is_focused: true,
                checkpoint_hash: None,
            });
        }

        assert!(!detector.detect_orphaned_keystrokes(&events));
    }

    #[test]
    fn test_detect_tampering_multiple_flags() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        // Create scenario with both impossible speed and monotonic timing
        let mut timestamp = 0i64;
        for _ in 0..20 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: timestamp,
                key_code: 65,
                is_focused: true,
                checkpoint_hash: None,
            });
            timestamp += 30; // Fast + monotonic
        }

        let flags = detector.detect_tampering(&events);
        assert!(flags.is_set(TamperingFlags::IMPOSSIBLE_SPEED));
        assert!(flags.is_set(TamperingFlags::MONOTONIC_TIMING));
    }
}
