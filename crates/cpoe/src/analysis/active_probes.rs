// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Active probe mechanisms for behavioral verification.
//! RFC draft-condrey-rats-pop-01 §5.5: Galton invariant and reflex gate probes.

use serde::{Deserialize, Serialize};

const PERTURBATION_THRESHOLD_FRACTION: f64 = 0.3;
const MIN_GALTON_SAMPLES: usize = 20;
const MIN_PERTURBATION_COUNT: usize = 3;
const RECOVERY_WINDOW_SIZE: usize = 10;
const MIN_RECOVERY_SAMPLES: usize = 3;
const DEFAULT_DECAY_RATE: f64 = 0.5;
const MIN_DEVIATION_FLOOR: f64 = 0.001;
const MAX_DECAY_RATE: f64 = 2.0;
const MIN_STIMULUS_RESPONSES: usize = 5;
const MIN_AUTOCORRELATION_SAMPLES: usize = 3;

/// Comprehensive error type for Active Probe analyses
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActiveProbeError {
    #[error("Insufficient samples for Galton analysis: found {found}, minimum {required}")]
    InsufficientGaltonSamples { found: usize, required: usize },
    #[error("Insufficient perturbations detected: found {found}, minimum {required}")]
    InsufficientPerturbations { found: usize, required: usize },
    #[error("Could not calculate absorption rates")]
    CalculateAbsorptionFailed,
    #[error("Insufficient stimulus responses: found {found}, minimum {required}")]
    InsufficientStimulusResponses { found: usize, required: usize },
}

// --- Math Helpers ---

// --- Galton Invariant ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaltonInvariantResult {
    pub absorption_coefficient: f64,
    pub time_constant_ms: f64,
    pub asymmetry_factor: f64,
    pub std_error: f64,
    pub is_valid: bool,
    pub perturbation_count: usize,
}

impl GaltonInvariantResult {
    pub const MIN_VALID_ALPHA: f64 = 0.3;
    pub const MAX_VALID_ALPHA: f64 = 0.8;

    /// Checks if the absorption coefficient falls within a biologically plausible range.
    pub fn is_biologically_plausible(&self) -> bool {
        (Self::MIN_VALID_ALPHA..=Self::MAX_VALID_ALPHA).contains(&self.absorption_coefficient)
    }
}

#[derive(Debug, Clone)]
pub struct ProbeSample {
    pub timestamp_ns: i64,
    pub interval_ms: f64,
    pub is_perturbed: bool,
    pub is_stimulus_response: bool,
}

/// Analyzes probe samples to verify the Galton Invariant.
pub fn analyze_galton_invariant(
    samples: &[ProbeSample],
    baseline_interval_ms: f64,
) -> Result<GaltonInvariantResult, ActiveProbeError> {
    if samples.len() < MIN_GALTON_SAMPLES {
        return Err(ActiveProbeError::InsufficientGaltonSamples {
            found: samples.len(),
            required: MIN_GALTON_SAMPLES,
        });
    }

    if samples.iter().any(|s| !s.interval_ms.is_finite()) {
        return Err(ActiveProbeError::InsufficientGaltonSamples {
            found: 0,
            required: MIN_GALTON_SAMPLES,
        });
    }

    let threshold = baseline_interval_ms * PERTURBATION_THRESHOLD_FRACTION;

    // Identify perturbations
    let perturbations: Vec<(usize, f64)> = samples
        .iter()
        .enumerate()
        .filter_map(|(i, sample)| {
            let deviation = sample.interval_ms - baseline_interval_ms;
            if deviation.abs() > threshold || sample.is_perturbed {
                Some((i, deviation))
            } else {
                None
            }
        })
        .collect();

    if perturbations.len() < MIN_PERTURBATION_COUNT {
        return Err(ActiveProbeError::InsufficientPerturbations {
            found: perturbations.len(),
            required: MIN_PERTURBATION_COUNT,
        });
    }

    let mut absorption_rates = Vec::with_capacity(perturbations.len());
    let mut acceleration_recoveries = Vec::with_capacity(perturbations.len());
    let mut deceleration_recoveries = Vec::with_capacity(perturbations.len());

    for &(pert_idx, deviation) in &perturbations {
        let end_idx = samples.len().min(pert_idx + RECOVERY_WINDOW_SIZE + 1);
        let recovery_len = end_idx.saturating_sub(pert_idx + 1);

        // Zero-allocation inner loop via lazy iterator mapping
        if recovery_len >= MIN_RECOVERY_SAMPLES {
            let recovery_iter = samples[pert_idx + 1..end_idx]
                .iter()
                .map(|s| s.interval_ms - baseline_interval_ms);

            let decay_rate = estimate_decay_rate(recovery_iter);
            absorption_rates.push(decay_rate);

            if deviation > 0.0 {
                deceleration_recoveries.push(decay_rate);
            } else {
                acceleration_recoveries.push(decay_rate);
            }
        }
    }

    if absorption_rates.is_empty() {
        return Err(ActiveProbeError::CalculateAbsorptionFailed);
    }

    let absorption_coefficient = crate::utils::stats::mean(&absorption_rates);

    let time_constant_ms = if absorption_coefficient > 0.0 {
        baseline_interval_ms / absorption_coefficient
    } else {
        f64::INFINITY
    };

    let accel_mean = if !acceleration_recoveries.is_empty() {
        crate::utils::stats::mean(&acceleration_recoveries)
    } else {
        absorption_coefficient
    };

    let decel_mean = if !deceleration_recoveries.is_empty() {
        crate::utils::stats::mean(&deceleration_recoveries)
    } else {
        absorption_coefficient
    };

    let asymmetry_factor = if accel_mean > 0.0 {
        decel_mean / accel_mean
    } else {
        1.0
    };

    let n = absorption_rates.len();
    let std_error = if n <= 1 {
        0.0
    } else {
        let (_, sample_variance) = crate::utils::stats::mean_and_sample_variance(&absorption_rates);
        (sample_variance / n as f64).sqrt()
    };

    let is_valid = (GaltonInvariantResult::MIN_VALID_ALPHA
        ..=GaltonInvariantResult::MAX_VALID_ALPHA)
        .contains(&absorption_coefficient);

    Ok(GaltonInvariantResult {
        absorption_coefficient,
        time_constant_ms,
        asymmetry_factor,
        std_error,
        is_valid,
        perturbation_count: perturbations.len(),
    })
}

/// Calculates the exponential decay rate using an iterator, entirely preventing heap allocations.
fn estimate_decay_rate(mut deviations: impl Iterator<Item = f64>) -> f64 {
    let first_dev = match deviations.next() {
        Some(dev) => dev,
        None => return DEFAULT_DECAY_RATE,
    };

    // Exponential decay fit: ln(y/y0) = -α * t
    let y0 = first_dev.abs().max(MIN_DEVIATION_FLOOR);
    let mut sum_rate = 0.0;
    let mut count = 0;

    // Enumerate acts as time `t` starting at 1 since we already consumed the 0th item
    for (i, dev) in deviations.enumerate() {
        let y = dev.abs().max(MIN_DEVIATION_FLOOR);
        let t = (i + 1) as f64;
        let rate = -(y / y0).ln() / t;

        if rate.is_finite() && rate > 0.0 {
            sum_rate += rate;
            count += 1;
        }
    }

    if count > 0 {
        (sum_rate / count as f64).clamp(0.0, MAX_DECAY_RATE)
    } else {
        DEFAULT_DECAY_RATE
    }
}

// --- Reflex Gate ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflexGateResult {
    pub min_latency_ms: f64,
    pub mean_latency_ms: f64,
    pub std_latency_ms: f64,
    pub coefficient_of_variation: f64,
    pub sequential_dependency: f64,
    pub is_valid: bool,
    pub response_count: usize,
}

impl ReflexGateResult {
    pub const MIN_PHYSIOLOGICAL_LATENCY_MS: f64 = 100.0;
    pub const MIN_VALID_CV: f64 = 0.15;
    pub const MAX_VALID_CV: f64 = 0.40;

    /// Checks if latency and variation fall within biologically plausible limits.
    pub fn is_biologically_plausible(&self) -> bool {
        self.min_latency_ms >= Self::MIN_PHYSIOLOGICAL_LATENCY_MS
            && (Self::MIN_VALID_CV..=Self::MAX_VALID_CV).contains(&self.coefficient_of_variation)
    }

    /// Evaluates if responses demonstrate impossibly fast reflex times.
    pub fn has_superhuman_responses(&self) -> bool {
        self.min_latency_ms < Self::MIN_PHYSIOLOGICAL_LATENCY_MS
    }
}

/// Analyzes reflex responses for timing physiological validity.
pub fn analyze_reflex_gate(samples: &[ProbeSample]) -> Result<ReflexGateResult, ActiveProbeError> {
    let responses: Vec<f64> = samples
        .iter()
        .filter(|s| s.is_stimulus_response)
        .map(|s| s.interval_ms)
        .collect();

    let n = responses.len();
    if n < MIN_STIMULUS_RESPONSES {
        return Err(ActiveProbeError::InsufficientStimulusResponses {
            found: n,
            required: MIN_STIMULUS_RESPONSES,
        });
    }

    let min_latency_ms = responses
        .iter()
        .copied()
        .reduce(f64::min)
        .unwrap_or(f64::INFINITY);
    let (mean_latency_ms, variance) = crate::utils::stats::mean_and_variance(&responses);
    let std_latency_ms = variance.sqrt();

    let coefficient_of_variation = if mean_latency_ms > 0.0 {
        std_latency_ms / mean_latency_ms
    } else {
        0.0
    };

    let sequential_dependency = if n >= MIN_AUTOCORRELATION_SAMPLES {
        compute_lag1_autocorrelation(&responses, mean_latency_ms)
    } else {
        0.0
    };

    let is_valid = min_latency_ms >= ReflexGateResult::MIN_PHYSIOLOGICAL_LATENCY_MS
        && (ReflexGateResult::MIN_VALID_CV..=ReflexGateResult::MAX_VALID_CV)
            .contains(&coefficient_of_variation);

    Ok(ReflexGateResult {
        min_latency_ms,
        mean_latency_ms,
        std_latency_ms,
        coefficient_of_variation,
        sequential_dependency,
        is_valid,
        response_count: n,
    })
}

fn compute_lag1_autocorrelation(data: &[f64], mean: f64) -> f64 {
    if data.len() < MIN_AUTOCORRELATION_SAMPLES {
        return 0.0;
    }

    // Windows naturally processes adjacent pairs efficiently without offset index checking
    let numerator: f64 = data.windows(2).map(|w| (w[0] - mean) * (w[1] - mean)).sum();

    let denominator: f64 = data.iter().map(|&x| (x - mean).powi(2)).sum();

    if denominator > 0.0 {
        numerator / denominator
    } else {
        0.0
    }
}

// --- Combined Results ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProbeResults {
    pub galton: Option<GaltonInvariantResult>,
    pub reflex: Option<ReflexGateResult>,
    pub combined_score: f64,
    pub all_valid: bool,
}

impl ActiveProbeResults {
    /// Merges Galton and Reflex results into a unified score.
    pub fn combine(
        galton: Option<GaltonInvariantResult>,
        reflex: Option<ReflexGateResult>,
    ) -> Self {
        let mut score_count = 0;
        let mut valid_count = 0;

        if let Some(ref g) = galton {
            score_count += 1;
            if g.is_valid {
                valid_count += 1;
            }
        }

        if let Some(ref r) = reflex {
            score_count += 1;
            if r.is_valid {
                valid_count += 1;
            }
        }

        Self {
            galton,
            reflex,
            combined_score: if score_count > 0 {
                valid_count as f64 / score_count as f64
            } else {
                0.0
            },
            all_valid: valid_count > 0 && valid_count == score_count,
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn create_rhythmic_samples(
        base_interval: f64,
        perturbations: &[(usize, f64)],
    ) -> Vec<ProbeSample> {
        let mut samples = Vec::new();
        let mut timestamp = 0i64;

        for i in 0..50 {
            let mut interval = base_interval;

            for &(pert_idx, deviation) in perturbations {
                if i == pert_idx {
                    interval += deviation;
                } else if i > pert_idx && i < pert_idx + 5 {
                    let decay = deviation * (0.5_f64).powi((i - pert_idx) as i32);
                    interval += decay;
                }
            }

            timestamp += (interval * 1_000_000.0) as i64;
            samples.push(ProbeSample {
                timestamp_ns: timestamp,
                interval_ms: interval,
                is_perturbed: perturbations.iter().any(|&(idx, _)| idx == i),
                is_stimulus_response: false,
            });
        }

        samples
    }

    #[test]
    fn test_galton_invariant_basic() {
        let samples = create_rhythmic_samples(200.0, &[(10, 100.0), (25, -80.0), (40, 60.0)]);

        let result = analyze_galton_invariant(&samples, 200.0).unwrap();

        assert!(result.perturbation_count >= 3);
        assert!(result.absorption_coefficient > 0.0);
    }

    #[test]
    fn test_galton_insufficient_data() {
        let samples: Vec<ProbeSample> = (0..5)
            .map(|i| ProbeSample {
                timestamp_ns: i * 200_000_000,
                interval_ms: 200.0,
                is_perturbed: false,
                is_stimulus_response: false,
            })
            .collect();

        let result = analyze_galton_invariant(&samples, 200.0);
        assert!(matches!(
            result,
            Err(ActiveProbeError::InsufficientGaltonSamples { .. })
        ));
    }

    #[test]
    fn test_reflex_gate_basic() {
        let latencies = [150.0, 180.0, 165.0, 200.0, 175.0, 190.0, 160.0];
        let samples: Vec<ProbeSample> = latencies
            .iter()
            .enumerate()
            .map(|(i, &lat)| ProbeSample {
                timestamp_ns: i as i64 * 1_000_000_000,
                interval_ms: lat,
                is_perturbed: false,
                is_stimulus_response: true,
            })
            .collect();

        let result = analyze_reflex_gate(&samples).unwrap();

        assert_eq!(result.response_count, 7);
        assert!(result.min_latency_ms >= 150.0);
        assert!(result.mean_latency_ms > 150.0 && result.mean_latency_ms < 200.0);
    }

    #[test]
    fn test_reflex_gate_superhuman() {
        let latencies = [50.0, 60.0, 55.0, 70.0, 45.0];
        let samples: Vec<ProbeSample> = latencies
            .iter()
            .enumerate()
            .map(|(i, &lat)| ProbeSample {
                timestamp_ns: i as i64 * 1_000_000_000,
                interval_ms: lat,
                is_perturbed: false,
                is_stimulus_response: true,
            })
            .collect();

        let result = analyze_reflex_gate(&samples).unwrap();

        assert!(result.has_superhuman_responses());
        assert!(!result.is_valid);
    }

    #[test]
    fn test_combined_results() {
        let galton = GaltonInvariantResult {
            absorption_coefficient: 0.5,
            time_constant_ms: 400.0,
            asymmetry_factor: 1.1,
            std_error: 0.05,
            is_valid: true,
            perturbation_count: 5,
        };

        let reflex = ReflexGateResult {
            min_latency_ms: 120.0,
            mean_latency_ms: 180.0,
            std_latency_ms: 40.0,
            coefficient_of_variation: 0.22,
            sequential_dependency: 0.3,
            is_valid: true,
            response_count: 10,
        };

        let combined = ActiveProbeResults::combine(Some(galton), Some(reflex));

        assert!(combined.all_valid);
        assert!((combined.combined_score - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_lag1_autocorrelation() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let mean = crate::utils::stats::mean(&data);
        let corr = compute_lag1_autocorrelation(&data, mean);
        assert!(
            corr > 0.0,
            "Linear series should have positive autocorrelation, got {}",
            corr
        );

        let data2 = vec![1.0, -1.0, 1.0, -1.0, 1.0];
        let mean2 = crate::utils::stats::mean(&data2);
        let corr2 = compute_lag1_autocorrelation(&data2, mean2);
        assert!(
            corr2 < 0.0,
            "Alternating series should have negative autocorrelation, got {}",
            corr2
        );
    }
}
