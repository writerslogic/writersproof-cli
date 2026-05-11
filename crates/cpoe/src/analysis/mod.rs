// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Reusable statistical analysis algorithms.
//!
//! These are domain-agnostic: Hurst exponent, Lyapunov, SNR, perplexity,
//! labyrinth (attractor reconstruction), etc. Used by `forensics/` for
//! authorship analysis but could apply to any time-series data.

pub mod active_probes;
pub mod behavioral_fingerprint;
pub mod content_detector;
pub mod error_topology;
pub mod histogram;
pub mod hurst;
pub mod iki_compression;
pub mod labyrinth;
pub mod language_model;
pub mod lyapunov;
pub mod perplexity;
pub mod pink_noise;
pub mod snr;
pub(crate) mod stats;

pub use active_probes::{
    analyze_galton_invariant, analyze_reflex_gate, ActiveProbeError, ActiveProbeResults,
    GaltonInvariantResult, ProbeSample, ReflexGateResult,
};
pub use behavioral_fingerprint::{BehavioralFingerprint, ForgeryAnalysis, ForgeryFlag};
pub use content_detector::{
    ContentAnalysis, ContentDetector, ContextType, KeystrokeMetrics, PatternMatcher, ProseStyle,
};
pub use error_topology::{
    analyze_error_topology, ErrorDistribution, ErrorTopology, ErrorTopologyError, EventType,
    TopologyEvent,
};
pub use hurst::{
    compute_hurst_dfa, compute_hurst_rs, HurstAnalysis, HurstError, HurstInterpretation,
};
pub use iki_compression::{analyze_iki_compression, IkiCompressionAnalysis, IkiCompressionError};
pub use labyrinth::{analyze_labyrinth, LabyrinthAnalysis, LabyrinthError, LabyrinthParams};
pub use language_model::{LanguageClassifier, TfidfModel};
pub use lyapunov::{analyze_lyapunov, LyapunovAnalysis, LyapunovError};
pub use perplexity::PerplexityModel;
pub use pink_noise::{
    analyze_pink_noise, generate_pink_noise, NoiseType, PinkNoiseAnalysis, PinkNoiseError,
};
pub use snr::{analyze_snr, SnrAnalysis, SnrError};
