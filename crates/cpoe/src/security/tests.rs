// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Integration tests for security hardening modules.

#[cfg(test)]
mod integration_tests {
    use crate::security::{
        EntropyAssessment, EntropyValidator, KeystrokeEvent, KeystrokeSample, TamperingDetector,
        TamperingFlags,
    };
    use std::collections::VecDeque;

    #[test]
    fn test_entropy_validator_integration() {
        let validator = EntropyValidator::new();
        let mut samples = VecDeque::new();

        // Create a realistic keystroke sequence with normal variation
        let mut timestamp = 0i64;
        let intervals = [
            120, 145, 130, 160, 125, 150, 135, 155, 140, 150, 130, 145, 125, 160, 140,
        ];

        for &interval in &intervals {
            samples.push_back(KeystrokeSample {
                timestamp_ns: timestamp,
                key_code: 65,
                is_burst: true,
            });
            timestamp += interval * 1_000_000; // Convert to nanos
        }

        let (entropy, assessment) = validator.measure_entropy(&samples);
        assert!(entropy > 0.0);
        assert!(!matches!(assessment, EntropyAssessment::InsufficientData));
    }

    #[test]
    fn test_tampering_detector_clean_input() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Create normal keystroke sequence
        for i in 0..20 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: now_ms - 5000 + i * 130,
                key_code: 65,
                is_focused: true,
                checkpoint_hash: None,
            });
        }

        let flags = detector.detect_tampering(&events);
        assert!(flags.is_empty());
    }

    #[test]
    fn test_tampering_detector_detects_multiple_issues() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Create keystroke sequence with impossible speed and monotonic timing
        for i in 0..20 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: now_ms - 5000 + i * 30, // Very fast: 30ms intervals
                key_code: 65,
                is_focused: true,
                checkpoint_hash: None,
            });
        }

        let flags = detector.detect_tampering(&events);
        assert!(flags.is_set(TamperingFlags::IMPOSSIBLE_SPEED));
        assert!(flags.is_set(TamperingFlags::MONOTONIC_TIMING));
        assert!(flags.count_flags() >= 2);
    }

    #[test]
    fn test_tampering_flags_serialization() {
        let mut flags = TamperingFlags::new();
        flags.set(TamperingFlags::IMPOSSIBLE_SPEED);
        flags.set(TamperingFlags::TIMESTAMP_VIOLATION);

        let names = flags.to_vec();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"impossible_speed".to_string()));
        assert!(names.contains(&"timestamp_violation".to_string()));
    }

    #[test]
    fn test_entropy_assessment_thresholds() {
        let validator = EntropyValidator::new();

        // Test with monotonic timing (should be critical)
        let mut samples = VecDeque::new();
        let mut timestamp = 0i64;
        for _ in 0..30 {
            samples.push_back(KeystrokeSample {
                timestamp_ns: timestamp,
                key_code: 65,
                is_burst: true,
            });
            timestamp += 100_000_000; // Exactly 100ms
        }

        let (_entropy, assessment) = validator.measure_entropy(&samples);
        assert_eq!(assessment, EntropyAssessment::Critical);
    }

    #[test]
    fn test_orphaned_keystroke_detection() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Add many keystrokes before focus (orphaned)
        for i in 0..10 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: now_ms - 5000 + i * 100,
                key_code: 65,
                is_focused: false, // Not focused
                checkpoint_hash: None,
            });
        }

        let flags = detector.detect_tampering(&events);
        assert!(flags.is_set(TamperingFlags::ORPHANED_KEYSTROKES));
    }

    #[test]
    fn test_sleep_recovery_detection() {
        let detector = TamperingDetector::new();
        let mut events = VecDeque::new();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Keystrokes before sleep
        let mut timestamp = now_ms - 5000;
        for _i in 0..5 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: timestamp,
                key_code: 65,
                is_focused: true,
                checkpoint_hash: None,
            });
            timestamp += 120;
        }

        // Large gap (sleep)
        timestamp += 3000;

        // Keystrokes after sleep with identical timing (suspicious)
        for _i in 0..5 {
            events.push_back(KeystrokeEvent {
                timestamp_ms: timestamp,
                key_code: 65,
                is_focused: true,
                checkpoint_hash: None,
            });
            timestamp += 120; // Same spacing as before
        }

        let flags = detector.detect_tampering(&events);
        assert!(flags.is_set(TamperingFlags::SLEEP_RECOVERY));
    }

    #[test]
    fn test_entropy_low_entropy_pattern_detection() {
        let validator = EntropyValidator::new();
        let mut samples = VecDeque::new();

        // Create uniform timing (all 100ms)
        let mut timestamp = 0i64;
        for _ in 0..20 {
            samples.push_back(KeystrokeSample {
                timestamp_ns: timestamp,
                key_code: 65,
                is_burst: true,
            });
            timestamp += 100_000_000;
        }

        let patterns = validator.detect_low_entropy_patterns(&samples);
        assert!(!patterns.is_empty());
        assert!(patterns.contains(&"monotonic_timing".to_string()));
    }

    #[test]
    fn test_detector_with_custom_config() {
        let detector = TamperingDetector::with_config(250.0, 0.12, 1500, 3).unwrap();
        assert_eq!(detector.speed_limit_wpm, 250.0);
        assert_eq!(detector.max_orphaned_keys, 3);

        // Should error on invalid config
        let result = TamperingDetector::with_config(50.0, 0.15, 2000, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_with_custom_config() {
        let validator = EntropyValidator::with_config(2.0, 75).unwrap();
        assert_eq!(validator.min_entropy_bits, 2.0);
        assert_eq!(validator.sample_window, 75);

        // Should error on invalid config
        let result = EntropyValidator::with_config(15.0, 100);
        assert!(result.is_err());
    }
}
