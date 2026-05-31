// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::jitter::SimpleJitterSample;

const BIOLOGICAL_LOWER_BOUND_NS: f64 = 5_000_000.0; // 5ms debounce threshold
const BIOLOGICAL_UPPER_BOUND_NS: f64 = 2_500_000_000.0; // 2.5s max cognitive delay

/// Higher-order biometric profile from keystroke cadence analysis.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BiometricProfile {
    pub mean: f64,
    pub variance: f64,
    pub skewness: f64,
    pub kurtosis: f64,
    pub consistency_score: f64,
}

/// Analyzer for biological typing cadence regularity.
#[derive(Debug)]
pub struct BiologicalCadence;

impl BiologicalCadence {
    /// Score cadence regularity from jitter samples (0.0 = erratic, 1.0 = steady).
    pub fn analyze(samples: &[SimpleJitterSample]) -> f64 {
        if samples.len() < 2 {
            return 0.0;
        }

        let mut sum = 0.0;
        let mut count = 0.0;
        for sample in samples {
            let v = sample.duration_since_last_ns as f64;
            if v > 0.0 {
                sum += v;
                count += 1.0;
            }
        }

        if count == 0.0 {
            return 0.0;
        }

        let mean = sum / count;
        let mut variance = 0.0;
        for sample in samples {
            let v = sample.duration_since_last_ns as f64;
            if v > 0.0 {
                let diff = v - mean;
                variance += diff * diff;
            }
        }
        variance /= count;
        let stddev = variance.max(0.0).sqrt();
        let cv = if mean > 0.0 { stddev / mean } else { 0.0 };

        // Lower coefficient of variation indicates steadier cadence (closer to 1.0).
        let score = 1.0 / (1.0 + cv);
        crate::utils::Probability::clamp(score).get()
    }

    /// Single-pass 4th-order moment extraction for advanced bot detection.
    ///
    /// Evaluates Mean, Variance, Skewness, and Kurtosis simultaneously to
    /// detect synthetic bots mimicking human variance patterns.
    pub fn analyze_advanced(samples: &[SimpleJitterSample]) -> Option<BiometricProfile> {
        if samples.len() < 4 {
            return None;
        }

        let mut n: f64 = 0.0;
        let mut mean = 0.0f64;
        let mut m2 = 0.0f64;
        let mut m3 = 0.0f64;
        let mut m4 = 0.0f64;

        for sample in samples {
            let x = sample.duration_since_last_ns as f64;
            if x < BIOLOGICAL_LOWER_BOUND_NS || x > BIOLOGICAL_UPPER_BOUND_NS {
                continue;
            }

            let n1 = n;
            n += 1.0;
            let delta = x - mean;
            let delta_n = delta / n;
            let delta_n2 = delta_n * delta_n;
            let term1 = delta * delta_n * n1;

            mean += delta_n;
            m4 += term1 * delta_n2 * (n * n - 3.0 * n + 3.0) + 6.0 * delta_n2 * m2
                - 4.0 * delta_n * m3;
            m3 += term1 * delta_n * (n - 2.0) - 3.0 * delta_n * m2;
            m2 += term1;
        }

        if n < 4.0 {
            return None;
        }

        let variance = m2 / (n - 1.0);
        let stddev = variance.max(0.0).sqrt();

        if stddev < f64::EPSILON {
            return Some(BiometricProfile {
                mean,
                variance: 0.0,
                skewness: 0.0,
                kurtosis: 0.0,
                consistency_score: 0.0,
            });
        }

        let skewness = (n.sqrt() * m3) / m2.powf(1.5);
        let kurtosis = (n * m4) / (m2 * m2) - 3.0;

        let cv = stddev / mean;
        let asymmetry_penalty = if skewness.abs() < 0.2 { 0.5 } else { 1.0 };
        let flat_distribution_penalty = if kurtosis < -1.0 { 0.4 } else { 1.0 };

        let raw_score = 1.0 / (1.0 + cv);
        let final_score = raw_score * asymmetry_penalty * flat_distribution_penalty;

        Some(BiometricProfile {
            mean,
            variance,
            skewness,
            kurtosis,
            consistency_score: crate::utils::Probability::clamp(final_score).get(),
        })
    }
}
