// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Forensic authorship analysis: edit topology, keystroke cadence, and profile correlation.
//!
//! # Boundary with `analysis/`
//!
//! - **forensics/** = Domain-specific orchestration, scoring, and verdict logic
//!   for authorship evidence. Calls into `analysis/` for reusable algorithms.
//! - **analysis/** = Pure statistical algorithms (Hurst exponent, Lyapunov,
//!   SNR, perplexity, etc.) that are domain-agnostic and could be used outside
//!   forensics.
//!
//! The dependency is one-directional: `forensics -> analysis`.

mod advanced_metrics;
pub(crate) mod analysis;
mod assessment;
mod cadence;
pub mod cognitive_accumulator;
pub mod constants;
pub mod cognitive_load;
pub mod composition_mode;
mod comparison;
mod correlation;
pub mod cross_modal;
pub mod dictation;
mod engine;
pub mod error;
pub mod error_ecology;
pub mod event_validation;
pub mod forgery_cost;
pub mod likelihood_model;
pub mod provenance_metrics;
mod report;
pub mod revision_topology;
pub(crate) mod scoring;
mod topology;
pub mod types;
mod velocity;
pub mod writing_mode;

pub use advanced_metrics::{
    analyze_fatigue_trajectory, analyze_repair_locality, compute_clc_metrics,
};
pub use analysis::*;
pub use assessment::*;
pub use cadence::*;
pub use comparison::*;
pub use correlation::*;
pub use cross_modal::{
    analyze_cross_modal, CrossModalCheck, CrossModalInput, CrossModalResult, CrossModalVerdict,
};
pub use engine::*;
pub use error::*;
pub use event_validation::{
    validate_keystroke_event, EventValidationFlags, EventValidationResult, EventValidationState,
};
pub use forgery_cost::{
    estimate_forgery_cost, ComponentCost, ForgeryCostEstimate, ForgeryCostInput,
    ForgeryResistanceTier,
};
pub use provenance_metrics::{ProvenanceMetrics, SourceSessionInfo};
pub use report::*;
pub use scoring::{
    apply_segment_velocity_penalty, cadence_score_from_samples, compute_focus_penalty,
    evidence_maturity, session_forensic_score,
};
pub use topology::*;
pub use types::{
    AnalysisKind, AnalysisStatus, ForensicGateVerdict, JitterQuality, TypingMetrics, *,
};
pub use velocity::*;
pub use writing_mode::{
    classify_writing_mode, enrich_writing_mode, EnhancedSignals, RevisionPattern, WritingMode,
    WritingModeAnalysis,
};

pub use cognitive_load::{analyze_cognitive_load, CognitiveLoadMetrics, CognitiveMode};
pub use composition_mode::{
    analyze_composition_mode, CompositionMode, CompositionModeDistribution,
    CompositionModeMetrics,
};
pub use error_ecology::{
    analyze_error_ecology, assess_transcription_suspicion, ErrorEcologyMetrics,
    TranscriptionSuspicion,
};
pub use likelihood_model::{
    analyze_likelihood_model, analyze_likelihood_model_with_priors, GaussianParams,
    LikelihoodModelMetrics, LikelihoodPriors,
};
pub use revision_topology::{
    analyze_revision_topology, RevisionGraphMetrics, RevisionTopologyMetrics,
    RevisionTypeDistribution,
};

/// Minimum event count for full residency credit in process scoring.
pub(crate) const MIN_EVENTS_FOR_RESIDENCY: usize = 5;
/// Residency weight in composite process score.
pub(crate) const PROCESS_SCORE_WEIGHT_RESIDENCY: f64 = 0.3;
/// Sequence weight in composite process score.
pub(crate) const PROCESS_SCORE_WEIGHT_SEQUENCE: f64 = 0.3;
/// Behavioral weight in composite process score.
pub(crate) const PROCESS_SCORE_WEIGHT_BEHAVIORAL: f64 = 0.4;
/// Composite score at or above which the process meets threshold.
pub(crate) const PROCESS_SCORE_PASS_THRESHOLD: f64 = 0.9;

#[cfg(test)]
mod tests;
