// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Generate unforgeable behavioral fingerprints from typing patterns

use crate::analysis::stats;
use crate::forensics::constants::{BURST_THRESHOLD_MS, PAUSE_THRESHOLD_MS};
use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};

const MAX_PAUSE_FILTER_MS: f64 = 5000.0;
const PARAGRAPH_PAUSE_MS: f64 = PAUSE_THRESHOLD_MS;
const BURST_SEPARATOR_MS: f64 = 500.0;
const BURST_INTERVAL_MS: f64 = BURST_THRESHOLD_MS;
const CV_FORGERY_THRESHOLD: f64 = 0.2;
const SKEWNESS_FORGERY_THRESHOLD: f64 = 0.2;
const MICRO_PAUSE_MIN_MS: f64 = 150.0;
const MICRO_PAUSE_MAX_MS: f64 = 500.0;
const MICRO_PAUSE_RATIO_THRESHOLD: f64 = 0.05;
const IMPOSSIBLY_FAST_MS: f64 = 20.0;
const SUSPICIOUS_FAST_PERCENT: usize = 10;
const MIN_FATIGUE_SAMPLES: usize = 40;
const FATIGUE_SLOWDOWN_RATIO: f64 = 1.05;
const FORGERY_CONFIDENCE_PER_FLAG: f64 = 0.3;
const MAX_FINGERPRINT_SAMPLES: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFingerprint {
    pub keystroke_interval_mean: f64,
    pub keystroke_interval_std: f64,
    pub keystroke_interval_skewness: f64,
    pub keystroke_interval_kurtosis: f64,

    pub interval_buckets: Vec<f64>,

    pub sentence_pause_mean: f64,
    pub paragraph_pause_mean: f64,
    pub thinking_pause_frequency: f64,

    pub burst_length_mean: f64,
    pub burst_speed_variance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeryAnalysis {
    pub is_suspicious: bool,
    pub confidence: f64,
    pub flags: Vec<ForgeryFlag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForgeryFlag {
    TooRegular { cv: f64 },
    WrongSkewness { skewness: f64 },
    MissingMicroPauses,
    SuperhumanSpeed { count: usize },
    NoFatiguePattern,
}

impl std::fmt::Display for ForgeryFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooRegular { cv } => write!(f, "Too Regular (CV: {cv:.3})"),
            Self::WrongSkewness { skewness } => write!(f, "Wrong Skewness ({skewness:.3})"),
            Self::MissingMicroPauses => write!(f, "Missing Micro-Pauses"),
            Self::SuperhumanSpeed { count } => write!(f, "Superhuman Speed ({count} bursts)"),
            Self::NoFatiguePattern => write!(f, "No Fatigue Pattern"),
        }
    }
}

fn interval_ms(a: &SimpleJitterSample, b: &SimpleJitterSample) -> f64 {
    crate::utils::ns_to_ms(b.timestamp_ns.saturating_sub(a.timestamp_ns))
}

impl BehavioralFingerprint {
    pub fn from_samples(samples: &[SimpleJitterSample]) -> Self {
        if samples.len() < 2 {
            return Self::default();
        }
        let samples = if samples.len() > MAX_FINGERPRINT_SAMPLES {
            &samples[..MAX_FINGERPRINT_SAMPLES]
        } else {
            samples
        };

        let mut intervals = Vec::with_capacity(samples.len().saturating_sub(1));
        let bucket_edges: &[f64] = &[0.0, 50.0, 100.0, 150.0, 200.0, 300.0, 500.0, 1000.0, 2000.0];
        let mut interval_buckets = vec![0.0f64; bucket_edges.len()];

        // Global stats (Welford)
        let mut welford_count = 0usize;
        let mut welford_mean = 0.0;
        let mut welford_m2 = 0.0;

        // Pauses
        let mut sentence_sum = 0.0;
        let mut sentence_count = 0usize;
        let mut para_sum = 0.0;
        let mut para_count = 0usize;

        // Burst speed variance (Welford)
        let mut burst_speed_count = 0usize;
        let mut burst_speed_mean = 0.0;
        let mut burst_speed_m2 = 0.0;

        // Burst length (Zero-allocation)
        let mut current_burst_len = 0usize;
        let mut total_burst_len = 0usize;
        let mut total_bursts = 0usize;

        // Single monolithic scan
        for w in samples.windows(2) {
            let iv = interval_ms(&w[0], &w[1]);

            // Burst length logic spans all intervals (including > MAX_PAUSE_FILTER_MS)
            if iv > BURST_SEPARATOR_MS {
                if current_burst_len > 0 {
                    total_burst_len += current_burst_len;
                    total_bursts += 1;
                }
                current_burst_len = 0;
            } else {
                current_burst_len += 1;
            }

            // Filtered metric logic
            if iv > 0.0 && iv < MAX_PAUSE_FILTER_MS {
                intervals.push(iv);

                // 1. Global Mean & Variance
                welford_count += 1;
                let delta = iv - welford_mean;
                welford_mean += delta / welford_count as f64;
                let delta2 = iv - welford_mean;
                welford_m2 += delta * delta2;

                // 2. Pause Means
                if iv > BURST_SEPARATOR_MS {
                    sentence_sum += iv;
                    sentence_count += 1;
                }
                if iv > PARAGRAPH_PAUSE_MS {
                    para_sum += iv;
                    para_count += 1;
                }

                // 3. Burst Speed Variance
                if iv < BURST_INTERVAL_MS {
                    burst_speed_count += 1;
                    let b_delta = iv - burst_speed_mean;
                    burst_speed_mean += b_delta / burst_speed_count as f64;
                    let b_delta2 = iv - burst_speed_mean;
                    burst_speed_m2 += b_delta * b_delta2;
                }

                // 4. Bucketing
                let idx = bucket_edges.partition_point(|&x| x <= iv).saturating_sub(1);
                interval_buckets[idx] += 1.0;
            }
        }

        // Close out any trailing burst length
        if current_burst_len > 0 {
            total_burst_len += current_burst_len;
            total_bursts += 1;
        }

        if intervals.is_empty() {
            return Self::default();
        }

        // Finalize metrics
        let std = if welford_count > 1 {
            (welford_m2 / (welford_count - 1) as f64).sqrt()
        } else {
            0.0
        };

        let skewness = stats::skewness(&intervals, welford_mean, std);
        let kurtosis = stats::kurtosis(&intervals, welford_mean, std);

        let thinking_freq = para_count as f64 / samples.len() as f64;
        let total = intervals.len() as f64;

        if total > 0.0 {
            for b in &mut interval_buckets {
                *b /= total;
            }
        }

        let sentence_pause_mean = if sentence_count > 0 {
            sentence_sum / sentence_count as f64
        } else {
            0.0
        };
        let paragraph_pause_mean = if para_count > 0 {
            para_sum / para_count as f64
        } else {
            0.0
        };

        let burst_speed_variance = if burst_speed_count >= 2 {
            let v = burst_speed_m2 / (burst_speed_count - 1) as f64;
            if v.is_finite() {
                v
            } else {
                0.0
            }
        } else {
            0.0
        };

        let burst_length_mean = if total_bursts > 0 {
            total_burst_len as f64 / total_bursts as f64
        } else {
            0.0
        };

        Self {
            keystroke_interval_mean: welford_mean,
            keystroke_interval_std: std,
            keystroke_interval_skewness: skewness,
            keystroke_interval_kurtosis: kurtosis,
            interval_buckets,
            sentence_pause_mean,
            paragraph_pause_mean,
            thinking_pause_frequency: thinking_freq,
            burst_length_mean,
            burst_speed_variance,
        }
    }

    pub fn detect_forgery(samples: &[SimpleJitterSample]) -> ForgeryAnalysis {
        if samples.len() < 10 {
            return ForgeryAnalysis {
                is_suspicious: false,
                confidence: 0.0,
                flags: vec![],
            };
        }
        let samples = if samples.len() > MAX_FINGERPRINT_SAMPLES {
            &samples[..MAX_FINGERPRINT_SAMPLES]
        } else {
            samples
        };

        let mut intervals = Vec::with_capacity(samples.len().saturating_sub(1));
        let mut flags = Vec::new();

        let mut micro_pauses = 0usize;
        let mut impossibly_fast = 0usize;
        let mut welford_count = 0usize;
        let mut welford_mean = 0.0;
        let mut welford_m2 = 0.0;

        for w in samples.windows(2) {
            let iv = interval_ms(&w[0], &w[1]);

            if iv > 0.0 && iv < MAX_PAUSE_FILTER_MS {
                intervals.push(iv);

                // Fuse micro pause and speed checks
                if iv > MICRO_PAUSE_MIN_MS && iv < MICRO_PAUSE_MAX_MS {
                    micro_pauses += 1;
                }
                if iv < IMPOSSIBLY_FAST_MS {
                    impossibly_fast += 1;
                }

                // Global mean & variance
                welford_count += 1;
                let delta = iv - welford_mean;
                welford_mean += delta / welford_count as f64;
                let delta2 = iv - welford_mean;
                welford_m2 += delta * delta2;
            }
        }

        if intervals.is_empty() {
            return ForgeryAnalysis {
                is_suspicious: false,
                confidence: 0.0,
                flags: vec![],
            };
        }

        let std = if welford_count > 1 {
            (welford_m2 / (welford_count - 1) as f64).sqrt()
        } else {
            0.0
        };

        if welford_mean > 0.0 {
            let cv = std / welford_mean;
            if cv.is_finite() && cv < CV_FORGERY_THRESHOLD {
                flags.push(ForgeryFlag::TooRegular { cv });
            }
        }

        let skewness = stats::skewness(&intervals, welford_mean, std);
        if skewness < SKEWNESS_FORGERY_THRESHOLD {
            flags.push(ForgeryFlag::WrongSkewness { skewness });
        }

        if (micro_pauses as f64 / intervals.len() as f64) < MICRO_PAUSE_RATIO_THRESHOLD {
            flags.push(ForgeryFlag::MissingMicroPauses);
        }

        if impossibly_fast * SUSPICIOUS_FAST_PERCENT > intervals.len() {
            flags.push(ForgeryFlag::SuperhumanSpeed {
                count: impossibly_fast,
            });
        }

        // Fatigue pattern analysis directly operates on the single allocated interval slice
        if intervals.len() >= MIN_FATIGUE_SAMPLES {
            let quarter = intervals.len() / 4;
            let first_mean = crate::utils::stats::mean(&intervals[..quarter]);
            let last_mean = crate::utils::stats::mean(&intervals[intervals.len() - quarter..]);

            if first_mean > 0.0 && last_mean <= first_mean * FATIGUE_SLOWDOWN_RATIO {
                flags.push(ForgeryFlag::NoFatiguePattern);
            }
        }

        ForgeryAnalysis {
            is_suspicious: !flags.is_empty(),
            confidence: (flags.len() as f64 * FORGERY_CONFIDENCE_PER_FLAG).min(1.0),
            flags,
        }
    }
}

/// Result of comparing a session fingerprint against a stored identity baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineComparison {
    /// Mahalanobis distance from the stored baseline. Lower = more similar.
    pub mahalanobis_distance: f64,
    /// True when the distance exceeds the anomaly threshold (3.0).
    pub is_anomalous: bool,
}

const MAHALANOBIS_ANOMALY_THRESHOLD: f64 = 3.0;

impl BehavioralFingerprint {
    /// Compare this fingerprint against a stored baseline using a simplified
    /// Mahalanobis distance over the five most stable biometric dimensions.
    ///
    /// Returns `None` when the baseline has zero standard deviation on any
    /// dimension (insufficient training data). The caller should persist the
    /// returned comparison result alongside the evidence packet.
    pub fn compare_to_baseline(&self, baseline: &BehavioralFingerprint) -> Option<BaselineComparison> {
        // Feature vector: [mean_iki, std_iki, burst_length_mean, sentence_pause_mean, thinking_freq]
        let current = [
            self.keystroke_interval_mean,
            self.keystroke_interval_std,
            self.burst_length_mean,
            self.sentence_pause_mean,
            self.thinking_pause_frequency,
        ];
        let base = [
            baseline.keystroke_interval_mean,
            baseline.keystroke_interval_std,
            baseline.burst_length_mean,
            baseline.sentence_pause_mean,
            baseline.thinking_pause_frequency,
        ];
        // Use baseline std as the diagonal covariance estimate.
        // std_iki serves as a proxy for per-dimension spread for all dimensions
        // except itself, which uses a fixed 5% relative spread.
        let spread = [
            baseline.keystroke_interval_std.max(1.0),
            (baseline.keystroke_interval_std * 0.25).max(1.0),
            (baseline.burst_length_mean * 0.3).max(0.1),
            (baseline.sentence_pause_mean * 0.3).max(1.0),
            0.02_f64.max(baseline.thinking_pause_frequency * 0.5),
        ];

        if spread.iter().any(|&s| s < f64::EPSILON) {
            return None;
        }

        let dist_sq: f64 = current
            .iter()
            .zip(base.iter())
            .zip(spread.iter())
            .map(|((c, b), s)| ((c - b) / s).powi(2))
            .sum();

        let mahalanobis_distance = dist_sq.sqrt();
        Some(BaselineComparison {
            mahalanobis_distance,
            is_anomalous: mahalanobis_distance > MAHALANOBIS_ANOMALY_THRESHOLD,
        })
    }
}

impl Default for BehavioralFingerprint {
    fn default() -> Self {
        Self {
            keystroke_interval_mean: 0.0,
            keystroke_interval_std: 0.0,
            keystroke_interval_skewness: 0.0,
            keystroke_interval_kurtosis: 0.0,
            interval_buckets: vec![],
            sentence_pause_mean: 0.0,
            paragraph_pause_mean: 0.0,
            thinking_pause_frequency: 0.0,
            burst_length_mean: 0.0,
            burst_speed_variance: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_samples(intervals_ms: &[u64]) -> Vec<SimpleJitterSample> {
        let mut samples = Vec::new();
        let mut current_ns = 1_000_000_000u64;

        samples.push(SimpleJitterSample {
            timestamp_ns: current_ns as i64,
            duration_since_last_ns: 0,
            zone: 1,
            ..Default::default()
        });

        for &interval in intervals_ms {
            let duration_ns = interval * 1_000_000;
            current_ns += duration_ns;
            samples.push(SimpleJitterSample {
                timestamp_ns: current_ns as i64,
                duration_since_last_ns: duration_ns,
                zone: 1,
                ..Default::default()
            });
        }
        samples
    }

    #[test]
    fn test_fingerprint_from_insufficient_samples() {
        let samples = mock_samples(&[]);
        let fp = BehavioralFingerprint::from_samples(&samples);
        assert_eq!(fp.keystroke_interval_mean, 0.0);
    }

    #[test]
    fn test_fingerprint_human_like() {
        let intervals = vec![200, 250, 180, 220, 400, 210, 190, 230, 220, 200];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert!(fp.keystroke_interval_mean > 200.0 && fp.keystroke_interval_mean < 300.0);
        assert!(fp.keystroke_interval_std > 0.0);
        assert!(fp.keystroke_interval_skewness > 0.0);
    }

    #[test]
    fn test_fingerprint_interval_buckets() {
        let intervals = vec![30, 80, 120, 180, 250, 400, 700, 1500, 3000, 150];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert_eq!(fp.interval_buckets.len(), 9);
        let sum: f64 = fp.interval_buckets.iter().sum();
        assert!((sum - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_fingerprint_pause_means() {
        let intervals = vec![100, 150, 120, 800, 100, 130, 2500, 100, 3000, 150];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert!(fp.sentence_pause_mean > 500.0);
        assert!(fp.paragraph_pause_mean > 2000.0);
    }

    #[test]
    fn test_fingerprint_burst_speed_variance() {
        let intervals = vec![80, 120, 150, 90, 110, 130, 170, 500, 100, 140];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert!(fp.burst_speed_variance > 0.0);
    }

    #[test]
    fn test_detect_forgery_robotic() {
        let intervals = vec![200; 20];
        let samples = mock_samples(&intervals);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);

        assert!(analysis.is_suspicious);
        assert!(analysis
            .flags
            .iter()
            .any(|f| matches!(f, ForgeryFlag::TooRegular { .. })));
    }

    #[test]
    fn test_detect_forgery_human_plausible() {
        let intervals = vec![
            180, 220, 190, 450, 210, 170, 230, 200, 190, 210, 500, 180, 220, 200, 190,
        ];
        let samples = mock_samples(&intervals);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);

        assert!(!analysis.is_suspicious);
    }

    #[test]
    fn test_detect_forgery_superhuman() {
        let mut intervals = vec![200; 15];
        intervals.extend(vec![10, 5, 10, 5, 10]); // Robotic/Superhuman burst
        let samples = mock_samples(&intervals);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);

        assert!(analysis.is_suspicious);
        assert!(analysis
            .flags
            .iter()
            .any(|f| matches!(f, ForgeryFlag::SuperhumanSpeed { .. })));
    }

    #[test]
    fn test_fingerprint_single_sample_returns_default() {
        let samples = mock_samples(&[]);
        assert_eq!(samples.len(), 1); // only the initial sample
        let fp = BehavioralFingerprint::from_samples(&samples);
        assert_eq!(fp.keystroke_interval_mean, 0.0);
        assert_eq!(fp.burst_length_mean, 0.0);
    }

    #[test]
    fn test_detect_forgery_too_few_samples() {
        let samples = mock_samples(&[200, 180, 220]);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);
        // < 10 samples -> not suspicious, no flags
        assert!(!analysis.is_suspicious);
        assert!(analysis.flags.is_empty());
        assert!((analysis.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fingerprint_thinking_pause_frequency() {
        // Include several paragraph-level pauses (> 2000ms)
        let intervals = vec![150, 180, 2500, 160, 170, 3000, 140, 190, 200, 2100];
        let samples = mock_samples(&intervals);
        let fp = BehavioralFingerprint::from_samples(&samples);

        assert!(
            fp.thinking_pause_frequency > 0.0,
            "Should detect thinking pauses, got {}",
            fp.thinking_pause_frequency
        );
    }

    #[test]
    fn test_detect_forgery_no_fatigue_pattern() {
        // 50 perfectly uniform intervals -> should flag NoFatiguePattern
        let intervals = vec![200; 50];
        let samples = mock_samples(&intervals);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);

        assert!(analysis.is_suspicious);
        assert!(analysis
            .flags
            .iter()
            .any(|f| matches!(f, ForgeryFlag::NoFatiguePattern)));
    }

    #[test]
    fn test_compare_to_baseline_similar() {
        let intervals_a = vec![200, 220, 190, 210, 230, 200, 210, 195, 205, 215];
        let intervals_b = vec![202, 218, 192, 208, 228, 203, 212, 197, 207, 213];
        let a = BehavioralFingerprint::from_samples(&mock_samples(&intervals_a));
        let b = BehavioralFingerprint::from_samples(&mock_samples(&intervals_b));
        let result = a.compare_to_baseline(&b);
        if let Some(cmp) = result {
            assert!(!cmp.is_anomalous, "Similar fingerprints should not be anomalous");
        }
    }

    #[test]
    fn test_compare_to_baseline_divergent() {
        let intervals_a = vec![200, 220, 190, 210, 230, 200, 210, 195, 205, 215];
        let intervals_b = vec![600, 620, 590, 610, 630, 600, 610, 595, 605, 615];
        let a = BehavioralFingerprint::from_samples(&mock_samples(&intervals_a));
        let b = BehavioralFingerprint::from_samples(&mock_samples(&intervals_b));
        let result = a.compare_to_baseline(&b);
        if let Some(cmp) = result {
            assert!(cmp.mahalanobis_distance > 0.0);
        }
    }

    #[test]
    fn test_compare_to_self_is_zero_distance() {
        let intervals = vec![200, 220, 190, 210, 230, 200, 210, 195, 205, 215];
        let fp = BehavioralFingerprint::from_samples(&mock_samples(&intervals));
        let result = fp.compare_to_baseline(&fp);
        if let Some(cmp) = result {
            assert!(cmp.mahalanobis_distance < f64::EPSILON);
            assert!(!cmp.is_anomalous);
        }
    }

    #[test]
    fn test_forgery_confidence_caps_at_one() {
        // Trigger as many flags as possible -> confidence should max at 1.0
        let mut intervals = vec![200; 50]; // uniform -> TooRegular, WrongSkewness, NoFatiguePattern, MissingMicroPauses
                                           // Add superhuman speeds
        for interval in &mut intervals[..10] {
            *interval = 5;
        }
        let samples = mock_samples(&intervals);
        let analysis = BehavioralFingerprint::detect_forgery(&samples);

        assert!(analysis.confidence <= 1.0);
    }
}
