// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::types::{
    AppraisalPolicy, EvidenceMetrics, FactorType, ThresholdType, TrustComputation, TrustPolicyError,
};
use crate::error::{Error, Result};

/// CoV below this is suspiciously regular (robotic).
const COV_LOW_THRESHOLD: f32 = 0.1;

/// CoV above this is the upper end of typical human variation.
const COV_HIGH_THRESHOLD: f32 = 0.6;

/// Checkpoint count at which the score saturates to 1.0.
const CHECKPOINT_SATURATION_COUNT: f32 = 20.0;

/// Factors scoring below this are counted as caveats.
const CAVEAT_SCORE_THRESHOLD: f32 = 0.5;

/// Score weight for below-low-CoV range (robotic).
const COV_BELOW_LOW_WEIGHT: f32 = 0.3;
/// Score weight for normal CoV range.
const COV_NORMAL_WEIGHT: f32 = 0.7;
/// CoV overflow penalty band width.
const COV_OVERFLOW_BAND: f32 = 0.4;
/// Maximum penalty fraction applied in CoV overflow.
const COV_OVERFLOW_PENALTY: f32 = 0.2;

/// Attestation score for tier 4 (hardware-backed, Secure Enclave / TPM).
const ATTESTATION_TIER4_SCORE: f32 = 1.0;
/// Attestation score for tier 3 (platform attestation).
const ATTESTATION_TIER3_SCORE: f32 = 0.85;
/// Attestation score for tier 2 (software-only, key-backed).
const ATTESTATION_TIER2_SCORE: f32 = 0.5;
/// Attestation score for tier 1 (self-attested, no hardware proof).
const ATTESTATION_TIER1_SCORE: f32 = 0.2;

impl AppraisalPolicy {
    /// Compute the aggregate trust score from all factors.
    pub fn compute_score(&self) -> f32 {
        if self.factors.is_empty() {
            return 0.0;
        }

        match self.computation_model {
            TrustComputation::WeightedAverage => {
                let total_weight: f32 = self.factors.iter().map(|f| f.weight).sum();
                if total_weight == 0.0 || !total_weight.is_finite() {
                    return 0.0;
                }
                let weighted_sum: f32 = self
                    .factors
                    .iter()
                    .map(|f| {
                        let w = if f.weight.is_finite() { f.weight } else { 0.0 };
                        let s = if f.normalized_score.is_finite() {
                            f.normalized_score
                        } else {
                            0.0
                        };
                        w * s
                    })
                    .sum();
                weighted_sum / total_weight
            }
            TrustComputation::MinimumOfFactors => {
                let min = self
                    .factors
                    .iter()
                    .map(|f| f.normalized_score)
                    .fold(f32::INFINITY, f32::min);
                if min.is_finite() {
                    min
                } else {
                    0.0
                }
            }
            TrustComputation::GeometricMean => {
                if self.factors.is_empty() {
                    return 0.0;
                }
                let product: f32 = self
                    .factors
                    .iter()
                    .map(|f| {
                        if f.normalized_score.is_finite() {
                            f.normalized_score.max(0.0)
                        } else {
                            0.0
                        }
                    })
                    .product();
                product.powf(1.0 / self.factors.len() as f32)
            }
            // CustomFormula requires an external implementation registered by the
            // caller via `evaluate()`. Direct callers must not bypass `evaluate()`,
            // which enforces this contract. Returning 0.0 here prevents silent
            // score inflation if `compute_score()` is called directly on a
            // CustomFormula policy (all callers in practice go through `evaluate()`
            // which returns Err before reaching here).
            TrustComputation::CustomFormula => 0.0,
        }
    }

    /// Validate that all factor-name references in thresholds exist in the factors list.
    pub fn validate(&self) -> Result<()> {
        for f in &self.factors {
            if !f.weight.is_finite() || f.weight < 0.0 {
                return Err(Error::validation(format!(
                    "factor '{}' has invalid weight: {}",
                    f.factor_name, f.weight
                )));
            }
            if !f.normalized_score.is_finite() {
                return Err(Error::validation(format!(
                    "factor '{}' has non-finite score: {}",
                    f.factor_name, f.normalized_score
                )));
            }
        }
        for t in &self.thresholds {
            match t.threshold_type {
                ThresholdType::MinimumFactor | ThresholdType::RequiredFactor => {
                    if !self
                        .factors
                        .iter()
                        .any(|f| f.factor_name == t.threshold_name)
                    {
                        return Err(Error::validation(format!(
                            "threshold '{}' references unknown factor name",
                            t.threshold_name
                        )));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Return `true` if all thresholds are met.
    pub fn check_thresholds(&self) -> bool {
        self.thresholds.iter().all(|t| t.met)
    }

    /// Collect references to all thresholds that were not met.
    pub fn failed_thresholds(&self) -> Vec<&super::types::TrustThreshold> {
        self.thresholds.iter().filter(|t| !t.met).collect()
    }

    /// Score all factors against `metrics` and evaluate thresholds.
    /// Returns a new policy instance with populated scores.
    ///
    /// # Errors
    /// Returns [`Error::TrustPolicy`] with [`TrustPolicyError::CustomFormulaUnavailable`]
    /// when `computation_model` is `CustomFormula`. There is no silent fallback to an
    /// alternative strategy; the caller must surface this as a `policy_evaluation_failed`
    /// evidence tag rather than treating the result as a valid evaluation.
    pub fn evaluate(&self, metrics: &EvidenceMetrics) -> Result<Self> {
        if self.computation_model == TrustComputation::CustomFormula {
            return Err(Error::TrustPolicy(
                TrustPolicyError::CustomFormulaUnavailable {
                    policy_uri: self.policy_uri.clone(),
                    reason: "no external formula implementation is registered for this \
                         evaluation context"
                        .to_string(),
                },
            ));
        }
        self.validate()?;
        let mut policy = self.clone();

        for factor in &mut policy.factors {
            let (observed, normalized) = match factor.factor_type {
                FactorType::ChainIntegrity => {
                    let score = if metrics.chain_verified { 1.0 } else { 0.0 };
                    (score, score)
                }
                FactorType::TypingRateConsistency => {
                    let cov = metrics.checkpoint_interval_cov;
                    let score = if !cov.is_finite() || cov <= 0.0 {
                        0.0
                    } else if cov < COV_LOW_THRESHOLD {
                        cov / COV_LOW_THRESHOLD * COV_BELOW_LOW_WEIGHT
                    } else if cov <= COV_HIGH_THRESHOLD {
                        COV_BELOW_LOW_WEIGHT
                            + (cov - COV_LOW_THRESHOLD) / (COV_HIGH_THRESHOLD - COV_LOW_THRESHOLD)
                                * COV_NORMAL_WEIGHT
                    } else {
                        (1.0 - (cov - COV_HIGH_THRESHOLD).min(COV_OVERFLOW_BAND)
                            / COV_OVERFLOW_BAND
                            * COV_OVERFLOW_PENALTY)
                            .max(0.0)
                    };
                    (cov, score)
                }
                FactorType::MonotonicRatio => (
                    metrics.monotonic_growth_ratio,
                    metrics.monotonic_growth_ratio,
                ),
                FactorType::EditEntropy => (metrics.behavioral_entropy, metrics.behavioral_entropy),
                FactorType::HardwareAttestation => {
                    let score = match metrics.attestation_tier_level {
                        4 => ATTESTATION_TIER4_SCORE,
                        3 => ATTESTATION_TIER3_SCORE,
                        2 => ATTESTATION_TIER2_SCORE,
                        1 => ATTESTATION_TIER1_SCORE,
                        _ => 0.0,
                    };
                    (metrics.attestation_tier_level as f32, score)
                }
                FactorType::CheckpointCount => {
                    let count = metrics.checkpoint_count as f32;
                    let score = (count / CHECKPOINT_SATURATION_COUNT).min(1.0);
                    (count, score)
                }
                _ => (factor.observed_value, factor.normalized_score),
            };

            factor.observed_value = observed;
            factor.normalized_score =
                crate::utils::Probability::clamp(normalized as f64).get() as f32;
            factor.contribution = factor.weight * factor.normalized_score;
        }

        let overall_score = policy.compute_score();

        for threshold in &mut policy.thresholds {
            match threshold.threshold_type {
                ThresholdType::MinimumScore => {
                    threshold.met = overall_score >= threshold.required_value;
                    if !threshold.met {
                        threshold.failure_reason = Some(format!(
                            "Overall score {:.2} < required {:.2}",
                            overall_score, threshold.required_value
                        ));
                    }
                }
                ThresholdType::MinimumFactor => {
                    let met = policy.factors.iter().any(|f| {
                        f.factor_name == threshold.threshold_name
                            && f.normalized_score >= threshold.required_value
                    });
                    threshold.met = met;
                    if !met {
                        threshold.failure_reason = Some(format!(
                            "Factor '{}' does not meet minimum score of {:.2}",
                            threshold.threshold_name, threshold.required_value
                        ));
                    }
                }
                ThresholdType::RequiredFactor => {
                    let met = policy.factors.iter().any(|f| {
                        f.factor_name == threshold.threshold_name && f.normalized_score > 0.0
                    });
                    threshold.met = met;
                    if !met {
                        threshold.failure_reason = Some(format!(
                            "Required factor '{}' not present or scored zero",
                            threshold.threshold_name
                        ));
                    }
                }
                ThresholdType::MaximumCaveats => {
                    let caveat_count = policy
                        .factors
                        .iter()
                        .filter(|f| f.normalized_score < CAVEAT_SCORE_THRESHOLD)
                        .count() as f32;
                    threshold.met = caveat_count <= threshold.required_value;
                    if !threshold.met {
                        threshold.failure_reason = Some(format!(
                            "{} caveats exceed maximum of {}",
                            caveat_count, threshold.required_value
                        ));
                    }
                }
            }
        }

        Ok(policy)
    }
}
