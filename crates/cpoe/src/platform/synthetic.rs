// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Statistical synthetic event detection (cross-platform).
//!
//! Detects automated/injected keystrokes via:
//! - Coefficient of Variation (CV) -- robotic timing (CV < 0.15)
//! - Inter-Key Interval (IKI) -- superhuman speed (< 35ms)
//! - Timing pattern repetition -- replay attacks

use super::{KeystrokeEvent, RejectionReasons, SyntheticStats};
use std::collections::VecDeque;

const MIN_HUMAN_CV: f64 = 0.15;
const EXTREME_ROBOTIC_CV: f64 = 0.05;
const MIN_HUMAN_IKI_MS: f64 = 35.0;
const ANALYSIS_WINDOW_SIZE: usize = 50;
const MIN_SAMPLES_FOR_ANALYSIS: usize = 10;
const MAX_PATTERN_REPETITION_RATIO: f64 = 0.8;

#[derive(Debug)]
/// Sliding-window anomaly detector for synthetic keystroke detection.
pub struct StatisticalAnomalyDetector {
    iki_window: VecDeque<f64>,
    /// Learned once half the window fills
    baseline_mean: Option<f64>,
    baseline_std: Option<f64>,
    last_timestamp_ns: Option<i64>,
    stats: SyntheticStats,
    rejection_reasons: RejectionReasons,
}

impl StatisticalAnomalyDetector {
    pub fn new() -> Self {
        Self {
            iki_window: VecDeque::with_capacity(ANALYSIS_WINDOW_SIZE),
            baseline_mean: None,
            baseline_std: None,
            last_timestamp_ns: None,
            stats: SyntheticStats::default(),
            rejection_reasons: RejectionReasons::default(),
        }
    }

    pub fn analyze(&mut self, event: &KeystrokeEvent) -> StatisticalResult {
        self.stats.total_events += 1;

        let iki_ms = if let Some(last_ts) = self.last_timestamp_ns {
            let delta_ns = event.timestamp_ns - last_ts;
            if delta_ns <= 0 {
                // Clock went backwards or duplicate timestamp; keep the last
                // known-good reference and discard this event.
                return StatisticalResult::Insufficient;
            }
            crate::utils::ns_to_ms(delta_ns)
        } else {
            self.last_timestamp_ns = Some(event.timestamp_ns);
            return StatisticalResult::Insufficient;
        };

        self.last_timestamp_ns = Some(event.timestamp_ns);

        if self.iki_window.len() >= ANALYSIS_WINDOW_SIZE {
            self.iki_window.pop_front();
        }
        self.iki_window.push_back(iki_ms);

        if self.iki_window.len() < MIN_SAMPLES_FOR_ANALYSIS {
            return StatisticalResult::Insufficient;
        }

        let mut flags = AnomalyFlags::default();

        if iki_ms < MIN_HUMAN_IKI_MS {
            flags.superhuman_speed = true;
            self.rejection_reasons.statistical_superhuman += 1;
        }

        let (mean, std) = self.compute_mean_std();
        let cv = if mean > 0.0 { std / mean } else { 0.0 };

        if self.baseline_mean.is_none() && self.iki_window.len() >= ANALYSIS_WINDOW_SIZE / 2 {
            self.baseline_mean = Some(mean);
            self.baseline_std = Some(std);
        }

        if cv < MIN_HUMAN_CV {
            flags.robotic_timing = true;
            if cv < EXTREME_ROBOTIC_CV {
                flags.extreme_robotic_timing = true;
            }
            self.rejection_reasons.statistical_robotic += 1;
        }

        if self.detect_replay_pattern() {
            flags.replay_pattern = true;
            self.rejection_reasons.statistical_replay += 1;
        }

        if flags.has_critical_anomaly() {
            self.stats.rejected_synthetic += 1;
            StatisticalResult::Synthetic(flags)
        } else if flags.has_any_anomaly() {
            self.stats.suspicious_accepted += 1;
            StatisticalResult::Suspicious(flags)
        } else {
            self.stats.verified_hardware += 1;
            StatisticalResult::Normal
        }
    }

    fn compute_mean_std(&self) -> (f64, f64) {
        if self.iki_window.len() < 2 {
            return (0.0, 0.0);
        }

        let ikis: Vec<f64> = self.iki_window.iter().copied().collect();
        let (mean, variance) = crate::utils::stats::mean_and_sample_variance(&ikis);
        let std = variance.sqrt();
        let std = if std.is_finite() { std } else { 0.0 };

        (mean, std)
    }

    fn detect_replay_pattern(&self) -> bool {
        if self.iki_window.len() < 20 {
            return false;
        }

        let ikis: Vec<f64> = self.iki_window.iter().copied().collect();
        let tolerance_ms = 2.0;

        for pattern_len in 5..=10 {
            if ikis.len() < pattern_len * 2 {
                continue;
            }

            let pattern = &ikis[..pattern_len];
            let mut matches = 0;
            let mut checks = 0;

            for i in (pattern_len..ikis.len()).step_by(pattern_len) {
                if i + pattern_len > ikis.len() {
                    break;
                }

                checks += 1;
                let candidate = &ikis[i..i + pattern_len];

                if pattern
                    .iter()
                    .zip(candidate.iter())
                    .all(|(a, b)| (a - b).abs() < tolerance_ms)
                {
                    matches += 1;
                }
            }

            if checks > 0 && (matches as f64 / checks as f64) >= MAX_PATTERN_REPETITION_RATIO {
                return true;
            }
        }

        false
    }

    pub fn stats(&self) -> &SyntheticStats {
        &self.stats
    }

    pub fn rejection_reasons(&self) -> &RejectionReasons {
        &self.rejection_reasons
    }

    pub fn reset(&mut self) {
        self.iki_window.clear();
        self.baseline_mean = None;
        self.baseline_std = None;
        self.last_timestamp_ns = None;
        self.stats = SyntheticStats::default();
        self.rejection_reasons = RejectionReasons::default();
    }

    pub fn current_cv(&self) -> Option<f64> {
        if self.iki_window.len() < MIN_SAMPLES_FOR_ANALYSIS {
            return None;
        }
        let (mean, std) = self.compute_mean_std();
        if mean > 0.0 {
            Some(std / mean)
        } else {
            None
        }
    }

    pub fn mean_iki_ms(&self) -> Option<f64> {
        if self.iki_window.is_empty() {
            None
        } else {
            let sum: f64 = self.iki_window.iter().sum();
            Some(sum / self.iki_window.len() as f64)
        }
    }
}

impl Default for StatisticalAnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of statistical analysis.
#[derive(Debug, Clone)]
pub enum StatisticalResult {
    Insufficient,
    Normal,
    Suspicious(AnomalyFlags),
    Synthetic(AnomalyFlags),
}

impl StatisticalResult {
    pub fn is_accepted(&self) -> bool {
        matches!(
            self,
            Self::Insufficient | Self::Normal | Self::Suspicious(_)
        )
    }

    pub fn is_synthetic(&self) -> bool {
        matches!(self, Self::Synthetic(_))
    }
}

/// Flags indicating detected anomalies.
#[derive(Debug, Clone, Default)]
pub struct AnomalyFlags {
    /// IKI < 35ms
    pub superhuman_speed: bool,
    /// CV < 0.15
    pub robotic_timing: bool,
    /// CV < 0.05 (extreme machine precision)
    pub extreme_robotic_timing: bool,
    pub replay_pattern: bool,
}

impl AnomalyFlags {
    pub fn has_critical_anomaly(&self) -> bool {
        self.superhuman_speed
            || self.extreme_robotic_timing
            || (self.robotic_timing && self.replay_pattern)
    }

    pub fn has_any_anomaly(&self) -> bool {
        self.superhuman_speed || self.robotic_timing || self.replay_pattern
    }
}

#[derive(Debug)]
/// Combines platform-level verification with statistical anomaly detection.
pub struct SyntheticDetector {
    statistical: StatisticalAnomalyDetector,
    strict_mode: bool,
}

impl SyntheticDetector {
    pub fn new() -> Self {
        Self {
            statistical: StatisticalAnomalyDetector::new(),
            strict_mode: true,
        }
    }

    /// Classify an event using both `event.is_hardware` and statistical analysis.
    pub fn analyze(&mut self, event: &KeystrokeEvent) -> DetectionResult {
        let platform_result = if event.is_hardware {
            PlatformResult::Hardware
        } else {
            PlatformResult::Synthetic
        };

        let statistical_result = self.statistical.analyze(event);

        match (&platform_result, &statistical_result) {
            (PlatformResult::Hardware, StatisticalResult::Normal) => DetectionResult::Verified,
            (PlatformResult::Hardware, StatisticalResult::Insufficient) => {
                DetectionResult::Verified
            }

            (PlatformResult::Synthetic, _) => DetectionResult::Synthetic {
                reason: SyntheticReason::PlatformDetected,
            },

            (_, StatisticalResult::Synthetic(flags)) => {
                if self.strict_mode {
                    DetectionResult::Synthetic {
                        reason: if flags.superhuman_speed {
                            SyntheticReason::SuperhumanSpeed
                        } else if flags.robotic_timing {
                            SyntheticReason::RoboticTiming
                        } else {
                            SyntheticReason::ReplayPattern
                        },
                    }
                } else {
                    DetectionResult::Suspicious {
                        flags: flags.clone(),
                    }
                }
            }

            (_, StatisticalResult::Suspicious(flags)) => DetectionResult::Suspicious {
                flags: flags.clone(),
            },
        }
    }

    pub fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    pub fn get_strict_mode(&self) -> bool {
        self.strict_mode
    }

    pub fn stats(&self) -> SyntheticStats {
        let mut stats = self.statistical.stats().clone();
        stats.rejection_reasons = self.statistical.rejection_reasons().clone();
        stats
    }

    pub fn reset(&mut self) {
        self.statistical.reset();
    }
}

impl Default for SyntheticDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
enum PlatformResult {
    Hardware,
    Synthetic,
}

#[derive(Debug, Clone)]
pub enum DetectionResult {
    Verified,
    Suspicious { flags: AnomalyFlags },
    Synthetic { reason: SyntheticReason },
}

impl DetectionResult {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Verified | Self::Suspicious { .. })
    }
}

#[derive(Debug, Clone)]
pub enum SyntheticReason {
    /// Platform API flagged as synthetic (CGEventTap, evdev, etc.)
    PlatformDetected,
    SuperhumanSpeed,
    RoboticTiming,
    ReplayPattern,
}

#[derive(Debug)]
/// Long-term typing rhythm analyzer (fatigue detection, WPM estimation).
pub struct TypingRhythmAnalyzer {
    /// IKI samples bucketed by hour (24 bins)
    hourly_ikis: [Vec<f64>; 24],
    session_ikis: Vec<f64>,
    total_keystrokes: u64,
}

impl TypingRhythmAnalyzer {
    pub fn new() -> Self {
        Self {
            hourly_ikis: Default::default(),
            session_ikis: Vec::new(),
            total_keystrokes: 0,
        }
    }

    const MAX_SESSION_IKIS: usize = 100_000;
    const MAX_HOURLY_IKIS: usize = 50_000;

    pub fn add_sample(&mut self, iki_ms: f64, hour: u8) {
        self.total_keystrokes += 1;
        if self.session_ikis.len() < Self::MAX_SESSION_IKIS {
            self.session_ikis.push(iki_ms);
        }
        if hour < 24 && self.hourly_ikis[hour as usize].len() < Self::MAX_HOURLY_IKIS {
            self.hourly_ikis[hour as usize].push(iki_ms);
        }
    }

    pub fn compute_wpm(&self) -> Option<f64> {
        if self.session_ikis.is_empty() {
            return None;
        }

        let mean_iki_ms = crate::utils::mean(&self.session_ikis);
        if mean_iki_ms <= 0.0 {
            return None;
        }

        // 60000ms / mean_iki / 5 chars per word
        Some(12000.0 / mean_iki_ms)
    }

    /// Fractional speed change: positive = fatigue (slowing), negative = warming up.
    pub fn fatigue_indicator(&self) -> Option<f64> {
        if self.session_ikis.len() < 100 {
            return None;
        }

        let first_quarter_len = self.session_ikis.len() / 4;
        let last_quarter_start = self.session_ikis.len() - first_quarter_len;

        let first_mean: f64 =
            self.session_ikis[..first_quarter_len].iter().sum::<f64>() / first_quarter_len as f64;
        let last_mean: f64 =
            self.session_ikis[last_quarter_start..].iter().sum::<f64>() / first_quarter_len as f64;

        if first_mean <= 0.0 {
            return None;
        }

        Some((last_mean - first_mean) / first_mean)
    }

    pub fn reset_session(&mut self) {
        self.session_ikis.clear();
    }
}

impl Default for TypingRhythmAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::KeyEventType;

    fn make_event(timestamp_ns: i64, keycode: u16, is_hardware: bool) -> KeystrokeEvent {
        KeystrokeEvent {
            timestamp_ns,
            keycode,
            zone: 0,
            event_type: KeyEventType::Down,
            char_value: None,
            composed_text: None,
            is_hardware,
            device_id: None,
            transport_type: None,
            target_pid: 0,
        }
    }

    #[test]
    fn test_insufficient_data() {
        let mut detector = StatisticalAnomalyDetector::new();

        let result = detector.analyze(&make_event(1_000_000_000, 0x04, true));
        assert!(matches!(result, StatisticalResult::Insufficient));

        let result = detector.analyze(&make_event(1_100_000_000, 0x05, true));
        assert!(matches!(result, StatisticalResult::Insufficient));
    }

    #[test]
    fn test_normal_typing() {
        let mut detector = StatisticalAnomalyDetector::new();

        let base = 0i64;
        let ikis = [120, 180, 150, 200, 170, 130, 190, 160, 220, 140, 180, 150];

        let mut ts = base;
        for iki in &ikis {
            ts += *iki * 1_000_000;
            let result = detector.analyze(&make_event(ts, 0x04, true));
            if detector.iki_window.len() >= MIN_SAMPLES_FOR_ANALYSIS {
                assert!(
                    matches!(result, StatisticalResult::Normal),
                    "Expected Normal, got {:?}",
                    result
                );
            }
        }
    }

    #[test]
    fn test_robotic_timing() {
        let mut detector = StatisticalAnomalyDetector::new();

        // Regular intervals (100ms +/- 1ms) should trigger low CV
        let mut ts = 0i64;
        for i in 0..20 {
            ts += if i % 2 == 0 { 99_000_000 } else { 101_000_000 };
            let _ = detector.analyze(&make_event(ts, 0x04, true));
        }

        let cv = detector.current_cv();
        assert!(cv.is_some());
        assert!(cv.unwrap() < MIN_HUMAN_CV, "CV should be below threshold");
    }

    #[test]
    fn test_superhuman_speed() {
        let mut detector = StatisticalAnomalyDetector::new();

        let mut ts = 0i64;
        for _ in 0..15 {
            ts += 150_000_000; // 150ms normal baseline
            let _ = detector.analyze(&make_event(ts, 0x04, true));
        }

        ts += 5_000_000; // 5ms superhuman keystroke
        let result = detector.analyze(&make_event(ts, 0x04, true));

        assert!(
            matches!(
                result,
                StatisticalResult::Suspicious(_) | StatisticalResult::Synthetic(_)
            ),
            "Expected suspicious or synthetic for 5ms IKI"
        );
    }

    #[test]
    fn test_combined_detector() {
        let mut detector = SyntheticDetector::new();
        detector.set_strict_mode(false);

        let result = detector.analyze(&make_event(100_000_000, 0x04, true));
        assert!(result.is_accepted());

        let result = detector.analyze(&make_event(200_000_000, 0x04, false));
        assert!(!result.is_accepted());
    }

    #[test]
    fn test_typing_rhythm_wpm() {
        let mut analyzer = TypingRhythmAnalyzer::new();

        for _ in 0..100 {
            analyzer.add_sample(200.0, 12);
        }

        let wpm = analyzer.compute_wpm().unwrap();
        assert!((wpm - 60.0).abs() < 1.0); // 12000 / 200 = 60 WPM
    }
}
