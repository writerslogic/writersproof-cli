// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from trust policy evaluation.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TrustPolicyError {
    /// The policy specifies `CustomFormula` computation, which requires an external
    /// implementation identified by the policy URI. No such implementation is
    /// registered for this evaluation context. The evaluation did NOT fall back to
    /// an alternative scoring strategy; callers must treat this as a failed evaluation
    /// and surface it to the verifier as a `policy_evaluation_failed` evidence tag.
    #[error("custom formula unavailable for policy '{policy_uri}': {reason}")]
    CustomFormulaUnavailable { policy_uri: String, reason: String },

    /// The policy evaluation failed for a reason unrelated to formula availability.
    #[error("policy evaluation failed: {reason}")]
    EvaluationFailed { reason: String },
}

/// Algorithm used to combine trust factor scores into an aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustComputation {
    /// Sum of (factor * weight), normalized by total weight.
    WeightedAverage,
    /// Score limited by the lowest individual factor.
    MinimumOfFactors,
    /// Nth-root of the product of all factor scores.
    GeometricMean,
    /// Delegated to external implementation identified by `policy_uri`.
    CustomFormula,
}

/// Category of evidence factor used in trust scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorType {
    /// Cumulative verifiable delay function duration.
    VdfDuration,
    /// Number of checkpoints in the evidence chain.
    CheckpointCount,
    /// Entropy from hardware jitter measurements.
    JitterEntropy,
    /// Cryptographic integrity of the checkpoint chain.
    ChainIntegrity,
    /// Depth of document revision history.
    RevisionDepth,

    /// Fraction of presence challenges passed.
    PresenceRate,
    /// Average response time to presence challenges.
    PresenceResponseTime,

    /// Hardware-backed attestation (TPM/Secure Enclave).
    HardwareAttestation,
    /// Calibration attestation from a trusted authority.
    CalibrationAttestation,

    /// Shannon entropy of editing patterns.
    EditEntropy,
    /// Fraction of checkpoints with monotonic character growth.
    MonotonicRatio,
    /// Coefficient of variation in typing rate.
    TypingRateConsistency,

    /// Transparency log anchor confirmation.
    AnchorConfirmation,
    /// Number of anchored transparency log entries.
    AnchorCount,

    /// Number of collaborator cross-attestations.
    CollaboratorAttestations,
    /// Consistency of individual contributions in collaborative work.
    ContributionConsistency,
}

/// Kind of threshold gate applied during policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdType {
    /// Overall aggregate score must meet or exceed this value.
    MinimumScore,
    /// At least one factor must meet or exceed this value.
    MinimumFactor,
    /// A named factor must be present and score above zero.
    RequiredFactor,
    /// Number of factors below the caveat threshold must not exceed this.
    MaximumCaveats,
}

/// Supporting evidence attached to a scored trust factor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorEvidence {
    /// Value before normalization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_value: Option<f32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_value: Option<f32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computation_notes: Option<String>,

    /// (start_ordinal, end_ordinal) inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_range: Option<(u32, u32)>,
}

/// Weighted trust factor with observed value, normalized score, and contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFactor {
    pub factor_name: String,
    pub factor_type: FactorType,
    pub weight: f32,
    pub observed_value: f32,
    /// 0.0..1.0
    pub normalized_score: f32,
    /// weight * normalized_score
    pub contribution: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<FactorEvidence>,
}

impl TrustFactor {
    /// Create a factor with pre-computed weight and normalized score.
    pub fn new(
        name: impl Into<String>,
        factor_type: FactorType,
        weight: f32,
        observed: f32,
        normalized: f32,
    ) -> Self {
        Self {
            factor_name: name.into(),
            factor_type,
            weight,
            observed_value: observed,
            normalized_score: normalized,
            contribution: weight * normalized,
            evidence: None,
        }
    }

    /// Attach supporting evidence to this factor (builder pattern).
    pub fn with_evidence(mut self, evidence: FactorEvidence) -> Self {
        self.evidence = Some(evidence);
        self
    }
}

/// Gate condition that must be satisfied for the policy to pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustThreshold {
    pub threshold_name: String,
    pub threshold_type: ThresholdType,
    pub required_value: f32,
    pub met: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

impl TrustThreshold {
    /// Create a threshold with the given type and required value.
    pub fn new(
        name: impl Into<String>,
        threshold_type: ThresholdType,
        required: f32,
        met: bool,
    ) -> Self {
        Self {
            threshold_name: name.into(),
            threshold_type,
            required_value: required,
            met,
            failure_reason: None,
        }
    }

    /// Attach a failure reason string (builder pattern).
    pub fn with_failure_reason(mut self, reason: impl Into<String>) -> Self {
        self.failure_reason = Some(reason.into());
        self
    }
}

/// Optional descriptive metadata attached to a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_authority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_effective_date: Option<DateTime<Utc>>,
    /// e.g. "academic", "legal"
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applicable_domains: Vec<String>,
}

/// Complete trust appraisal policy with factors, thresholds, and scoring model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppraisalPolicy {
    /// e.g. `urn:ietf:params:pop:policy:basic`
    pub policy_uri: String,
    pub policy_version: String,
    pub computation_model: TrustComputation,
    pub factors: Vec<TrustFactor>,
    /// All must be satisfied for the policy to pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thresholds: Vec<TrustThreshold>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PolicyMetadata>,
    /// Set when evaluation was attempted but failed (e.g. CustomFormula unavailable).
    /// Verifiers must treat a non-None value as a `policy_evaluation_failed` evidence
    /// tag; the policy result does NOT represent a successful evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_evaluation_failed: Option<String>,
}

impl AppraisalPolicy {
    /// Create an empty policy with the given URI and version.
    pub fn new(uri: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            policy_uri: uri.into(),
            policy_version: version.into(),
            computation_model: TrustComputation::WeightedAverage,
            factors: Vec::new(),
            thresholds: Vec::new(),
            metadata: None,
            policy_evaluation_failed: None,
        }
    }

    pub fn with_computation(mut self, model: TrustComputation) -> Self {
        self.computation_model = model;
        self
    }

    /// Append a trust factor (builder pattern).
    pub fn add_factor(mut self, factor: TrustFactor) -> Self {
        self.factors.push(factor);
        self
    }

    /// Append a threshold gate (builder pattern).
    pub fn add_threshold(mut self, threshold: TrustThreshold) -> Self {
        self.thresholds.push(threshold);
        self
    }

    /// Attach descriptive metadata (builder pattern).
    pub fn with_metadata(mut self, metadata: PolicyMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Metrics extracted from evidence for trust evaluation.
#[derive(Debug, Clone, Default)]
pub struct EvidenceMetrics {
    /// Checkpoint interval CoV (std/mean); higher = more natural timing
    pub checkpoint_interval_cov: f32,
    /// Fraction of checkpoints with monotonic character-count growth (0.0..1.0)
    pub monotonic_growth_ratio: f32,
    /// Typing-pattern entropy (0.0..1.0)
    pub behavioral_entropy: f32,
    /// 1=SoftwareOnly, 2=AttestedSoftware, 3=HardwareBound, 4=HardwareHardened
    pub attestation_tier_level: u32,
    pub chain_verified: bool,
    pub checkpoint_count: u32,
}
