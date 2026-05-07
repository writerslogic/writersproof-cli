// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

#[test]
fn test_weighted_average() {
    let policy = AppraisalPolicy::new("test", "1.0")
        .with_computation(TrustComputation::WeightedAverage)
        .add_factor(TrustFactor::new(
            "f1",
            FactorType::VdfDuration,
            0.5,
            1.0,
            1.0,
        ))
        .add_factor(TrustFactor::new(
            "f2",
            FactorType::JitterEntropy,
            0.5,
            0.5,
            0.5,
        ));

    let score = policy.compute_score();
    // (0.5 * 1.0 + 0.5 * 0.5) / 1.0 = 0.75
    assert!((score - 0.75).abs() < 0.001);
}

#[test]
fn test_minimum_of_factors() {
    let policy = AppraisalPolicy::new("test", "1.0")
        .with_computation(TrustComputation::MinimumOfFactors)
        .add_factor(TrustFactor::new(
            "f1",
            FactorType::VdfDuration,
            0.5,
            1.0,
            0.9,
        ))
        .add_factor(TrustFactor::new(
            "f2",
            FactorType::JitterEntropy,
            0.5,
            0.5,
            0.3,
        ));

    let score = policy.compute_score();
    assert!((score - 0.3).abs() < 0.001);
}

#[test]
fn test_geometric_mean() {
    let policy = AppraisalPolicy::new("test", "1.0")
        .with_computation(TrustComputation::GeometricMean)
        .add_factor(TrustFactor::new(
            "f1",
            FactorType::VdfDuration,
            0.5,
            1.0,
            1.0,
        ))
        .add_factor(TrustFactor::new(
            "f2",
            FactorType::JitterEntropy,
            0.5,
            0.5,
            0.5,
        ));

    let score = policy.compute_score();
    // sqrt(1.0 * 0.5) = 0.707
    assert!((score - 0.707).abs() < 0.01);
}

#[test]
fn test_threshold_checking() {
    let policy = AppraisalPolicy::new("test", "1.0")
        .add_threshold(TrustThreshold::new(
            "t1",
            ThresholdType::MinimumScore,
            0.5,
            true,
        ))
        .add_threshold(TrustThreshold::new(
            "t2",
            ThresholdType::MinimumScore,
            0.9,
            false,
        ));

    assert!(!policy.check_thresholds());
    assert_eq!(policy.failed_thresholds().len(), 1);
}

#[test]
fn test_predefined_profiles() {
    let basic = profiles::basic();
    assert_eq!(basic.policy_uri, "urn:ietf:params:pop:policy:basic");

    let academic = profiles::academic();
    assert_eq!(
        academic.computation_model,
        TrustComputation::WeightedAverage
    );

    let legal = profiles::legal();
    assert_eq!(legal.computation_model, TrustComputation::MinimumOfFactors);
}

#[test]
fn test_serialization() {
    let policy = AppraisalPolicy::new("urn:test:policy", "1.0.0").add_factor(TrustFactor::new(
        "test",
        FactorType::ChainIntegrity,
        1.0,
        1.0,
        1.0,
    ));

    let json = serde_json::to_string(&policy).unwrap();
    let parsed: AppraisalPolicy = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.policy_uri, "urn:test:policy");
}

#[test]
fn test_evaluate_basic_policy() {
    let policy = profiles::basic();
    let metrics = EvidenceMetrics {
        checkpoint_interval_cov: 0.4,
        monotonic_growth_ratio: 0.95,
        behavioral_entropy: 0.7,
        attestation_tier_level: 3,
        chain_verified: true,
        checkpoint_count: 10,
    };

    let evaluated = policy.evaluate(&metrics).unwrap();
    let score = evaluated.compute_score();
    assert!(score > 0.5, "Expected score > 0.5, got {}", score);

    let chain = evaluated
        .factors
        .iter()
        .find(|f| f.factor_type == FactorType::ChainIntegrity)
        .unwrap();
    assert!((chain.normalized_score - 1.0).abs() < 0.001);
}

#[test]
fn test_evaluate_broken_chain() {
    let policy = profiles::basic();
    let metrics = EvidenceMetrics {
        chain_verified: false,
        ..Default::default()
    };

    let evaluated = policy.evaluate(&metrics).unwrap();
    let chain = evaluated
        .factors
        .iter()
        .find(|f| f.factor_type == FactorType::ChainIntegrity)
        .unwrap();
    assert!((chain.normalized_score - 0.0).abs() < 0.001);
}

#[test]
fn test_evaluate_threshold_checking() {
    let policy = AppraisalPolicy::new("test", "1.0")
        .with_computation(TrustComputation::WeightedAverage)
        .add_factor(TrustFactor::new(
            "chain-integrity",
            FactorType::ChainIntegrity,
            1.0,
            0.0,
            0.0,
        ))
        .add_threshold(TrustThreshold::new(
            "minimum-overall",
            ThresholdType::MinimumScore,
            0.5,
            false,
        ));

    let metrics = EvidenceMetrics {
        chain_verified: true,
        ..Default::default()
    };

    let evaluated = policy.evaluate(&metrics).unwrap();
    assert!(evaluated.check_thresholds());

    let metrics_bad = EvidenceMetrics {
        chain_verified: false,
        ..Default::default()
    };
    let evaluated_bad = policy.evaluate(&metrics_bad).unwrap();
    assert!(!evaluated_bad.check_thresholds());
}

/// H-060: CustomFormula must never silently fall back to a built-in scoring strategy.
/// evaluate() must return Err so the caller can surface a policy_evaluation_failed tag.
#[test]
fn test_custom_formula_evaluate_returns_error() {
    let policy = AppraisalPolicy::new("urn:test:custom", "1.0")
        .with_computation(TrustComputation::CustomFormula)
        .add_factor(TrustFactor::new(
            "f1",
            FactorType::ChainIntegrity,
            1.0,
            1.0,
            1.0,
        ));

    let metrics = EvidenceMetrics {
        chain_verified: true,
        ..Default::default()
    };

    let result = policy.evaluate(&metrics);
    assert!(
        result.is_err(),
        "CustomFormula evaluate() must return Err, not a fallback score"
    );

    let err = result.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("custom formula unavailable"),
        "error message should identify unavailable custom formula, got: {err_str}"
    );
}

/// H-060: The policy_evaluation_failed field serialises into the evidence representation
/// so verifiers see an explicit failure tag rather than a successful evaluation.
#[test]
fn test_custom_formula_policy_evaluation_failed_tag() {
    let policy = AppraisalPolicy::new("urn:test:custom", "1.0")
        .with_computation(TrustComputation::CustomFormula);

    let metrics = EvidenceMetrics::default();
    let err = policy.evaluate(&metrics).unwrap_err();

    // Caller's responsibility: stamp the failure reason onto a policy copy for the
    // evidence packet before serialisation.
    let mut tagged = policy.clone();
    tagged.policy_evaluation_failed = Some(err.to_string());

    let json = serde_json::to_string(&tagged).expect("serialize tagged policy");
    assert!(
        json.contains("policy_evaluation_failed"),
        "serialised evidence must carry policy_evaluation_failed field"
    );
    assert!(
        tagged.policy_evaluation_failed.is_some(),
        "policy_evaluation_failed must be Some after stamping"
    );
}
