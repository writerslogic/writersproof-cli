// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use authorproof_protocol::rfc::biology::{
    AnomalyFlag, AnomalyType, BiologyInvariantClaim, BiologyMeasurements, BiologyScoringParameters,
    ErrorTopology, PinkNoiseAnalysis,
};
use authorproof_protocol::rfc::jitter_binding::{
    ActiveProbes, GaltonInvariant, LabyrinthStructure, ReflexGate,
};

const GALTON_BASELINE_ABSORPTION: f64 = 0.55;
const ROBOTIC_CV_THRESHOLD: f64 = 0.15;

impl From<&crate::analysis::pink_noise::PinkNoiseAnalysis> for PinkNoiseAnalysis {
    #[inline(always)]
    fn from(analysis: &crate::analysis::pink_noise::PinkNoiseAnalysis) -> Self {
        Self {
            spectral_slope: analysis.spectral_slope,
            r_squared: analysis.r_squared,
            low_freq_power: 1.0,
            high_freq_power: if analysis.spectral_slope.is_finite() {
                10f64.powf(-analysis.spectral_slope)
            } else {
                0.0
            },
            within_human_range: analysis.is_valid,
        }
    }
}

impl From<&crate::analysis::error_topology::ErrorTopology> for ErrorTopology {
    #[inline(always)]
    fn from(topology: &crate::analysis::error_topology::ErrorTopology) -> Self {
        Self {
            gap_ratio: topology.gap_correlation,
            error_clustering: topology.error_hurst,
            adjacent_key_score: topology.adjacency_correlation,
            score: topology.score,
            passed: topology.is_valid,
        }
    }
}

pub trait BiologyInvariantClaimExt {
    fn from_analysis(
        measurements: BiologyMeasurements,
        hurst: Option<&crate::analysis::hurst::HurstAnalysis>,
        pink_noise: Option<&crate::analysis::pink_noise::PinkNoiseAnalysis>,
        error_topology: Option<&crate::analysis::error_topology::ErrorTopology>,
    ) -> BiologyInvariantClaim;
}

impl BiologyInvariantClaimExt for BiologyInvariantClaim {
    #[inline]
    fn from_analysis(
        measurements: BiologyMeasurements,
        hurst: Option<&crate::analysis::hurst::HurstAnalysis>,
        pink_noise: Option<&crate::analysis::pink_noise::PinkNoiseAnalysis>,
        error_topology: Option<&crate::analysis::error_topology::ErrorTopology>,
    ) -> BiologyInvariantClaim {
        let mut claim = Self::new(measurements, BiologyScoringParameters::default());

        if let Some(h) = hurst {
            claim.hurst_exponent = Some(h.exponent);
            if h.is_white_noise() {
                claim.add_anomaly(AnomalyFlag {
                    anomaly_type: AnomalyType::WhiteNoiseHurst,
                    description: format!(
                        "Hurst {:.3}: stochastic white noise detected",
                        h.exponent
                    ),
                    severity: 3,
                    timestamp_ms: None,
                });
            } else if h.is_suspiciously_predictable() {
                claim.add_anomaly(AnomalyFlag {
                    anomaly_type: AnomalyType::PredictableHurst,
                    description: format!(
                        "Hurst {:.3}: mechanical predictability detected",
                        h.exponent
                    ),
                    severity: 3,
                    timestamp_ms: None,
                });
            }
        }

        if let Some(pn) = pink_noise {
            claim.pink_noise = Some(pn.into());
            if !pn.is_biologically_plausible() {
                claim.add_anomaly(AnomalyFlag {
                    anomaly_type: AnomalyType::SpectralAnomaly,
                    description: format!(
                        "Spectral slope {:.3} is non-biological",
                        pn.spectral_slope
                    ),
                    severity: 2,
                    timestamp_ms: None,
                });
            }
        }

        if let Some(et) = error_topology {
            claim.error_topology = Some(et.into());
            if !et.is_valid {
                claim.add_anomaly(AnomalyFlag {
                    anomaly_type: AnomalyType::ErrorTopologyFail,
                    description: format!("Error topology score {:.3} rejected", et.score),
                    severity: 2,
                    timestamp_ms: None,
                });
            }
        }

        if claim.measurements.coefficient_of_variation < ROBOTIC_CV_THRESHOLD {
            claim.add_anomaly(AnomalyFlag {
                anomaly_type: AnomalyType::RoboticCadence,
                description: format!(
                    "CV {:.3} indicates automated input",
                    claim.measurements.coefficient_of_variation
                ),
                severity: 3,
                timestamp_ms: None,
            });
        }

        claim.compute_score();
        claim
    }
}

impl From<&crate::analysis::active_probes::GaltonInvariantResult> for GaltonInvariant {
    #[inline(always)]
    fn from(result: &crate::analysis::active_probes::GaltonInvariantResult) -> Self {
        let abs_coeff = result.absorption_coefficient;
        Self {
            absorption_coefficient: abs_coeff,
            stimulus_count: result.perturbation_count as u32,
            expected_absorption: GALTON_BASELINE_ABSORPTION,
            z_score: if result.std_error > f64::EPSILON && result.std_error.is_finite() {
                (abs_coeff - GALTON_BASELINE_ABSORPTION) / result.std_error
            } else {
                0.0
            },
            passed: result.is_valid,
        }
    }
}

impl From<&crate::analysis::active_probes::ReflexGateResult> for ReflexGate {
    #[inline(always)]
    fn from(result: &crate::analysis::active_probes::ReflexGateResult) -> Self {
        let m = result.mean_latency_ms;
        let s = result.std_latency_ms;
        let s_128 = 1.2815 * s;
        let s_067 = 0.6745 * s;

        Self {
            mean_latency_ms: m,
            std_dev_ms: s,
            event_count: result.response_count as u32,
            percentiles: [
                (m - s_128).max(0.0),
                (m - s_067).max(0.0),
                m.max(0.0),
                (m + s_067).max(0.0),
                (m + s_128).max(0.0),
            ],
            passed: result.is_valid,
        }
    }
}

impl From<&crate::analysis::active_probes::ActiveProbeResults> for ActiveProbes {
    #[inline(always)]
    fn from(results: &crate::analysis::active_probes::ActiveProbeResults) -> Self {
        Self {
            galton_invariant: results.galton.as_ref().map(Into::into),
            reflex_gate: results.reflex.as_ref().map(Into::into),
        }
    }
}

impl From<&crate::analysis::labyrinth::LabyrinthAnalysis> for LabyrinthStructure {
    #[inline(always)]
    fn from(analysis: &crate::analysis::labyrinth::LabyrinthAnalysis) -> Self {
        Self {
            embedding_dimension: analysis.embedding_dimension as u8,
            time_delay: analysis.optimal_delay as u16,
            attractor_points: Vec::new(),
            betti_numbers: vec![
                analysis.betti_numbers[0] as u32,
                analysis.betti_numbers[1] as u32,
                analysis.betti_numbers[2] as u32,
            ],
            lyapunov_exponent: None,
            correlation_dimension: analysis.correlation_dimension,
        }
    }
}
