// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Session-level typing characteristics, circadian patterns, and per-dimension confidence.

use serde::{Deserialize, Serialize};

/// IKI threshold for burst detection (ms)
const BURST_IKI_THRESHOLD_MS: f64 = 200.0;
/// IKI threshold for pause detection (ms)
const PAUSE_IKI_THRESHOLD_MS: f64 = 500.0;

/// Typing activity distribution by hour of day (0-23).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircadianPattern {
    pub hourly_activity: [f64; 24],
    pub total_samples: u64,
}

impl Default for CircadianPattern {
    fn default() -> Self {
        Self {
            hourly_activity: [0.0; 24],
            total_samples: 0,
        }
    }
}

impl CircadianPattern {
    /// Record a keystroke at the given hour (0-23).
    pub fn record(&mut self, hour: u8) {
        if hour < 24 {
            self.hourly_activity[hour as usize] += 1.0;
            self.total_samples += 1;
        }
    }

    /// Normalize to sum to 1.0.
    pub fn normalize(&mut self) {
        let total: f64 = self.hourly_activity.iter().sum();
        if total > 0.0 {
            for h in &mut self.hourly_activity {
                *h /= total;
            }
        }
    }

    /// Additive merge (re-normalize after merging).
    pub fn merge(&mut self, other: &CircadianPattern) {
        for i in 0..24 {
            self.hourly_activity[i] += other.hourly_activity[i];
        }
        self.total_samples += other.total_samples;
    }
}

/// Session-level typing characteristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSignature {
    pub mean_session_duration: f64,
    /// Keystrokes per minute
    pub mean_typing_speed: f64,
    /// Speed decay over session duration
    pub fatigue_coefficient: f64,
    pub session_count: u32,
    /// Fraction of time spent in bursts (<200ms IKI) vs pauses (>500ms)
    #[serde(default)]
    pub burst_pause_ratio: f64,
    /// Average number of consecutive keystrokes with IKI < 200ms
    #[serde(default)]
    pub mean_burst_length: f64,
}

impl Default for SessionSignature {
    fn default() -> Self {
        Self {
            mean_session_duration: 0.0,
            mean_typing_speed: 0.0,
            fatigue_coefficient: 0.0,
            session_count: 0,
            burst_pause_ratio: 0.0,
            mean_burst_length: 0.0,
        }
    }
}

impl SessionSignature {
    /// Compute burst/pause metrics from IKI intervals.
    pub fn compute_burst_metrics(&mut self, intervals: &[f64]) {
        if intervals.is_empty() {
            return;
        }
        let mut burst_count = 0.0f64;
        let mut pause_count = 0.0f64;
        let mut burst_lengths = Vec::new();
        let mut current_burst = 0usize;

        for &iki in intervals {
            if !iki.is_finite() {
                continue;
            }
            if iki < BURST_IKI_THRESHOLD_MS {
                burst_count += 1.0;
                current_burst += 1;
            } else {
                if current_burst > 0 {
                    burst_lengths.push(current_burst as f64);
                    current_burst = 0;
                }
                if iki > PAUSE_IKI_THRESHOLD_MS {
                    pause_count += 1.0;
                }
            }
        }
        if current_burst > 0 {
            burst_lengths.push(current_burst as f64);
        }

        let total = burst_count + pause_count;
        self.burst_pause_ratio = if total > 0.0 {
            burst_count / total
        } else {
            0.0
        };
        self.mean_burst_length = if !burst_lengths.is_empty() {
            burst_lengths.iter().sum::<f64>() / burst_lengths.len() as f64
        } else {
            0.0
        };
    }

    /// Weighted merge by session count.
    pub fn merge(&mut self, other: &SessionSignature) {
        let total = self.session_count + other.session_count;
        if total == 0 {
            return;
        }
        let self_w = self.session_count as f64 / total as f64;
        let other_w = other.session_count as f64 / total as f64;

        self.mean_session_duration =
            self.mean_session_duration * self_w + other.mean_session_duration * other_w;
        self.mean_typing_speed =
            self.mean_typing_speed * self_w + other.mean_typing_speed * other_w;
        self.fatigue_coefficient =
            self.fatigue_coefficient * self_w + other.fatigue_coefficient * other_w;
        self.burst_pause_ratio =
            self.burst_pause_ratio * self_w + other.burst_pause_ratio * other_w;
        self.mean_burst_length =
            self.mean_burst_length * self_w + other.mean_burst_length * other_w;
        self.session_count = total;
    }
}

/// Per-dimension confidence scores, each saturating at a feature-specific
/// sample count that reflects how many samples are needed for stability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionConfidence {
    pub iki: f64,
    pub zone: f64,
    pub pause: f64,
    pub dwell: f64,
    pub flight: f64,
    pub digraph: f64,
    pub hurst: f64,
    pub circadian: f64,
}

impl Default for DimensionConfidence {
    fn default() -> Self {
        Self {
            iki: 0.0,
            zone: 0.0,
            pause: 0.0,
            dwell: 0.0,
            flight: 0.0,
            digraph: 0.0,
            hurst: 0.0,
            circadian: 0.0,
        }
    }
}

impl DimensionConfidence {
    const IKI_SAT: f64 = 200.0;
    const ZONE_SAT: f64 = 300.0;
    const PAUSE_SAT: f64 = 500.0;
    const DWELL_SAT: f64 = 200.0;
    const FLIGHT_SAT: f64 = 200.0;
    const DIGRAPH_SAT: f64 = 1000.0;
    const HURST_SAT: f64 = 500.0;
    const CIRCADIAN_SAT: f64 = 5000.0;

    /// Compute per-dimension confidence from sample count and data availability.
    pub fn from_sample_count(
        sample_count: u64,
        has_dwell: bool,
        has_flight: bool,
        has_hurst: bool,
        circadian_samples: u64,
    ) -> Self {
        let n = sample_count as f64;
        Self {
            iki: (n / Self::IKI_SAT).min(1.0),
            zone: (n / Self::ZONE_SAT).min(1.0),
            pause: (n / Self::PAUSE_SAT).min(1.0),
            dwell: if has_dwell {
                (n / Self::DWELL_SAT).min(1.0)
            } else {
                0.0
            },
            flight: if has_flight {
                (n / Self::FLIGHT_SAT).min(1.0)
            } else {
                0.0
            },
            digraph: (n / Self::DIGRAPH_SAT).min(1.0),
            hurst: if has_hurst {
                (n / Self::HURST_SAT).min(1.0)
            } else {
                0.0
            },
            circadian: (circadian_samples as f64 / Self::CIRCADIAN_SAT).min(1.0),
        }
    }

    /// Weighted average across all dimensions (circadian at half weight).
    pub fn overall(&self) -> f64 {
        let weights = [0.25, 0.15, 0.10, 0.10, 0.10, 0.15, 0.05, 0.05];
        let values = [
            self.iki,
            self.zone,
            self.pause,
            self.dwell,
            self.flight,
            self.digraph,
            self.hurst,
            self.circadian,
        ];
        values
            .iter()
            .zip(weights.iter())
            .map(|(v, w)| v * w)
            .sum::<f64>()
            / weights.iter().sum::<f64>()
    }
}
