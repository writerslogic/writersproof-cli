// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Per-Window Generative Likelihood Model.
//!
//! Replaces rule-based penalty scoring with a proper log-likelihood ratio
//! framework. For each sliding window of keystrokes, computes:
//!
//!   LLR = log P(features | cognitive) - log P(features | transcriptive)
//!
//! Positive LLR = cognitive evidence. Negative = transcriptive evidence.
//! Per-window scores enable temporal resolution (detecting mode transitions)
//! and natural feature correlation handling.
//!
//! Distributional assumptions:
//! - IKI: log-normal (different μ,σ for each mode)
//! - Pause frequency: Poisson (different λ)
//! - Correction rate: Beta (different α,β)
//! - Burst speed CV: Gaussian (different μ,σ)

use serde::{Deserialize, Serialize};

use crate::analysis::BehavioralFingerprint;
use crate::jitter::SimpleJitterSample;

use super::constants::{BURST_THRESHOLD_NS, CORRECTION_ZONE, PAUSE_THRESHOLD_NS};

// ---------------------------------------------------------------------------
// Bayesian calibration
// ---------------------------------------------------------------------------

/// Normal-Normal conjugate prior for log-IKI parameters.
///
/// Uses precision-weighted updates: the more consistent a user's historical
/// typing (small σ = high precision), the less a single unusual session
/// sways their baseline. O(1) per checkpoint, numerically stable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaussianParams {
    pub mu: f64,
    pub sigma: f64,
    pub count: usize,
}

impl GaussianParams {
    pub fn new(mu: f64, sigma: f64) -> Self {
        Self { mu, sigma, count: 0 }
    }

    /// Bayesian update using new session data (precision-weighted).
    pub fn update(&mut self, session_mu: f64, session_sigma: f64, session_count: usize) {
        if session_count == 0 || session_sigma <= 0.0 || !session_mu.is_finite() {
            return;
        }

        let prior_precision = 1.0 / (self.sigma * self.sigma);
        let data_precision = session_count as f64 / (session_sigma * session_sigma);
        let new_precision = prior_precision + data_precision;

        self.mu = (prior_precision * self.mu + data_precision * session_mu) / new_precision;
        self.sigma = (1.0 / new_precision).sqrt();
        self.count += session_count;
    }
}

/// User-calibrated priors for the likelihood model.
///
/// Cognitive IKI parameters are personalized from the user's `BehavioralFingerprint`
/// when mature. Transcriptive parameters remain hardcoded population defaults
/// since we cannot calibrate to how a user fakes typing.
#[derive(Debug, Clone)]
pub struct LikelihoodPriors {
    pub cognitive_iki_mu: f64,
    pub cognitive_iki_sigma: f64,
}

/// Minimum sessions before using personalized priors (matches FingerprintMaturity::Advisory).
const MIN_SESSIONS_FOR_PRIORS: usize = 500;

impl LikelihoodPriors {
    /// Bootstrap from population defaults, overlaying user fingerprint if mature.
    ///
    /// The fingerprint stores `keystroke_interval_mean/std` in raw nanoseconds;
    /// we convert to log-space here.
    pub fn from_fingerprint(fp: Option<&BehavioralFingerprint>) -> Self {
        match fp {
            Some(f)
                if f.keystroke_interval_mean > 0.0
                    && f.keystroke_interval_std > 0.0
                    && f.interval_buckets.len() >= MIN_SESSIONS_FOR_PRIORS =>
            {
                // Convert from nanosecond space to log-space.
                let log_mu = f.keystroke_interval_mean.ln();
                // Approximate log-space sigma via delta method: σ_log ≈ σ / μ
                let log_sigma =
                    (f.keystroke_interval_std / f.keystroke_interval_mean).max(0.1);
                Self {
                    cognitive_iki_mu: log_mu,
                    cognitive_iki_sigma: log_sigma,
                }
            }
            _ => Self::population_defaults(),
        }
    }

    /// Population-level defaults (used when fingerprint is immature).
    pub fn population_defaults() -> Self {
        Self {
            cognitive_iki_mu: cognitive_params::IKI_MU,
            cognitive_iki_sigma: cognitive_params::IKI_SIGMA,
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Window size in samples.
const WINDOW_SIZE: usize = 200;

/// Window overlap in samples.
const WINDOW_OVERLAP: usize = 100;

/// Minimum samples for any analysis.
const MIN_SAMPLES: usize = 30;


// ---------------------------------------------------------------------------
// Distributional parameters
// ---------------------------------------------------------------------------

/// Log-normal IKI parameters: (mu, sigma) in log-nanoseconds.
/// Fitted from empirical typing data.
mod cognitive_params {
    /// Log-normal IKI: mean of log(IKI_ns). ~150ms typical → log(150_000_000) ≈ 18.8
    pub const IKI_MU: f64 = 18.8;
    /// Higher variance: cognitive writers have variable timing.
    pub const IKI_SIGMA: f64 = 1.2;
    /// Pause rate: ~15% of intervals are pauses.
    pub const PAUSE_RATE: f64 = 0.15;
    /// Correction rate: ~7% of keystrokes.
    pub const CORRECTION_RATE: f64 = 0.07;
    /// Burst speed CV: higher variation within bursts.
    pub const BURST_CV_MU: f64 = 0.35;
    pub const BURST_CV_SIGMA: f64 = 0.12;
    /// Post-pause CV: variable recovery.
    pub const POST_PAUSE_CV_MU: f64 = 0.35;
    pub const POST_PAUSE_CV_SIGMA: f64 = 0.10;
}

mod transcriptive_params {
    /// Log-normal IKI: slightly lower mean (faster, steady pace).
    pub const IKI_MU: f64 = 18.5;
    /// Lower variance: more uniform timing.
    pub const IKI_SIGMA: f64 = 0.5;
    /// Fewer pauses.
    pub const PAUSE_RATE: f64 = 0.03;
    /// Very few corrections.
    pub const CORRECTION_RATE: f64 = 0.01;
    /// Low burst speed variation.
    pub const BURST_CV_MU: f64 = 0.10;
    pub const BURST_CV_SIGMA: f64 = 0.05;
    /// Low post-pause variation.
    pub const POST_PAUSE_CV_MU: f64 = 0.10;
    pub const POST_PAUSE_CV_SIGMA: f64 = 0.05;
}

// ---------------------------------------------------------------------------
// Log-likelihood functions
// ---------------------------------------------------------------------------

/// Log-probability density of x under a Gaussian(mu, sigma).
fn log_gaussian_pdf(x: f64, mu: f64, sigma: f64) -> f64 {
    if sigma <= 0.0 || !x.is_finite() {
        return -50.0; // Sentinel for degenerate cases.
    }
    let z = (x - mu) / sigma;
    -0.5 * z * z - sigma.ln() - 0.5 * std::f64::consts::TAU.ln()
}

/// Log-probability of observing k successes in n trials with rate p.
/// Includes the binomial coefficient ln(C(n,k)) = lnΓ(n+1) - lnΓ(k+1) - lnΓ(n-k+1)
/// so the likelihood scales correctly across different window sizes.
fn log_binomial_approx(k: usize, n: usize, p: f64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let p = p.clamp(0.001, 0.999);
    let k_f = k.min(n) as f64;
    let n_f = n as f64;
    let ln_coeff = statrs::function::gamma::ln_gamma(n_f + 1.0)
        - statrs::function::gamma::ln_gamma(k_f + 1.0)
        - statrs::function::gamma::ln_gamma(n_f - k_f + 1.0);
    ln_coeff + k_f * p.ln() + (n_f - k_f) * (1.0 - p).ln()
}

/// Extract features from a window of jitter samples.
struct WindowFeatures {
    /// Mean log(IKI) for non-pause intervals.
    mean_log_iki: f64,
    /// Std dev of log(IKI) for non-pause intervals.
    std_log_iki: f64,
    /// Fraction of intervals that are pauses (>2s).
    pause_rate: f64,
    /// Fraction of keystrokes that are corrections (zone 0xFF).
    correction_rate: f64,
    /// CV of typing speed within bursts.
    burst_speed_cv: f64,
    /// CV of first keystrokes after pauses.
    post_pause_cv: f64,
    /// Number of samples in this window.
    sample_count: usize,
}

/// Extract features from a window of samples.
fn extract_window_features(samples: &[SimpleJitterSample]) -> WindowFeatures {
    let n = samples.len();
    if n < 5 {
        return WindowFeatures {
            mean_log_iki: 0.0,
            std_log_iki: 0.0,
            pause_rate: 0.0,
            correction_rate: 0.0,
            burst_speed_cv: 0.0,
            post_pause_cv: 0.0,
            sample_count: n,
        };
    }

    // Log-IKI statistics (excluding pauses).
    let log_ikis: Vec<f64> = samples
        .iter()
        .filter(|s| s.duration_since_last_ns > 0 && s.duration_since_last_ns < PAUSE_THRESHOLD_NS)
        .map(|s| (s.duration_since_last_ns as f64).ln())
        .collect();

    let (mean_log_iki, std_log_iki) = if log_ikis.len() >= 2 {
        crate::utils::stats::mean_and_sample_std_dev(&log_ikis)
    } else {
        (18.5, 0.5)
    };

    // Pause rate.
    let pause_count = samples
        .iter()
        .filter(|s| s.duration_since_last_ns >= PAUSE_THRESHOLD_NS)
        .count();
    let pause_rate = pause_count as f64 / n as f64;

    // Correction rate.
    let correction_count = samples.iter().filter(|s| s.zone == CORRECTION_ZONE).count();
    let correction_rate = correction_count as f64 / n as f64;

    // Burst speed CV: CV of IKIs within bursts.
    let mut burst_cvs = Vec::new();
    let mut burst_ikis = Vec::new();
    for s in samples {
        if s.duration_since_last_ns > 0 && s.duration_since_last_ns < BURST_THRESHOLD_NS {
            burst_ikis.push(s.duration_since_last_ns as f64);
        } else {
            if burst_ikis.len() >= 3 {
                let cv = crate::utils::stats::coefficient_of_variation(&burst_ikis);
                if cv > 0.0 {
                    burst_cvs.push(cv);
                }
            }
            burst_ikis.clear();
        }
    }
    if burst_ikis.len() >= 3 {
        let cv = crate::utils::stats::coefficient_of_variation(&burst_ikis);
        if cv > 0.0 {
            burst_cvs.push(cv);
        }
    }
    let burst_speed_cv = if burst_cvs.is_empty() {
        0.2 // Neutral default.
    } else {
        burst_cvs.iter().sum::<f64>() / burst_cvs.len() as f64
    };

    // Post-pause CV: CV of first 3 keystrokes after each pause.
    let mut post_pause_ikis = Vec::new();
    let mut after_pause = 0usize;
    for s in samples {
        if s.duration_since_last_ns >= PAUSE_THRESHOLD_NS {
            after_pause = 3;
        } else if after_pause > 0 && s.duration_since_last_ns > 0 {
            post_pause_ikis.push(s.duration_since_last_ns as f64);
            after_pause -= 1;
        }
    }
    let post_pause_cv = if post_pause_ikis.len() >= 3 {
        let cv = crate::utils::stats::coefficient_of_variation(&post_pause_ikis);
        if cv > 0.0 { cv } else { 0.2 }
    } else {
        0.2
    };

    WindowFeatures {
        mean_log_iki,
        std_log_iki,
        pause_rate,
        correction_rate,
        burst_speed_cv,
        post_pause_cv,
        sample_count: n,
    }
}

/// Compute log-likelihood of features under the cognitive model.
fn log_likelihood_cognitive(f: &WindowFeatures, priors: &LikelihoodPriors) -> f64 {
    let mut ll = 0.0;

    // IKI distribution fit (personalized when fingerprint is mature).
    ll += log_gaussian_pdf(f.mean_log_iki, priors.cognitive_iki_mu, priors.cognitive_iki_sigma);
    // Reward higher IKI variance (cognitive writers vary more).
    ll += log_gaussian_pdf(
        f.std_log_iki,
        priors.cognitive_iki_sigma,
        0.4,
    );

    // Pause rate.
    ll += log_binomial_approx(
        (f.pause_rate * f.sample_count as f64) as usize,
        f.sample_count,
        cognitive_params::PAUSE_RATE,
    );

    // Correction rate.
    ll += log_binomial_approx(
        (f.correction_rate * f.sample_count as f64) as usize,
        f.sample_count,
        cognitive_params::CORRECTION_RATE,
    );

    // Burst speed CV.
    ll += log_gaussian_pdf(
        f.burst_speed_cv,
        cognitive_params::BURST_CV_MU,
        cognitive_params::BURST_CV_SIGMA,
    );

    // Post-pause CV.
    ll += log_gaussian_pdf(
        f.post_pause_cv,
        cognitive_params::POST_PAUSE_CV_MU,
        cognitive_params::POST_PAUSE_CV_SIGMA,
    );

    ll
}

/// Compute log-likelihood of features under the transcriptive model.
fn log_likelihood_transcriptive(f: &WindowFeatures) -> f64 {
    let mut ll = 0.0;

    ll += log_gaussian_pdf(
        f.mean_log_iki,
        transcriptive_params::IKI_MU,
        transcriptive_params::IKI_SIGMA,
    );
    ll += log_gaussian_pdf(
        f.std_log_iki,
        transcriptive_params::IKI_SIGMA,
        0.2,
    );

    ll += log_binomial_approx(
        (f.pause_rate * f.sample_count as f64) as usize,
        f.sample_count,
        transcriptive_params::PAUSE_RATE,
    );

    ll += log_binomial_approx(
        (f.correction_rate * f.sample_count as f64) as usize,
        f.sample_count,
        transcriptive_params::CORRECTION_RATE,
    );

    ll += log_gaussian_pdf(
        f.burst_speed_cv,
        transcriptive_params::BURST_CV_MU,
        transcriptive_params::BURST_CV_SIGMA,
    );

    ll += log_gaussian_pdf(
        f.post_pause_cv,
        transcriptive_params::POST_PAUSE_CV_MU,
        transcriptive_params::POST_PAUSE_CV_SIGMA,
    );

    ll
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Per-window log-likelihood ratio result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowLLR {
    /// Window start index in the sample stream.
    pub start_idx: usize,
    /// Window end index.
    pub end_idx: usize,
    /// Log-likelihood ratio: positive = cognitive, negative = transcriptive.
    pub llr: f64,
    /// Posterior probability of cognitive mode (sigmoid of LLR).
    pub p_cognitive: f64,
}

/// Session-level likelihood model metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LikelihoodModelMetrics {
    /// Session-level log-likelihood ratio (sum of per-window LLRs).
    pub session_llr: f64,

    /// Session-level posterior probability of cognitive writing.
    pub session_p_cognitive: f64,

    /// Number of windows analyzed.
    pub window_count: usize,

    /// Number of windows classified as cognitive (LLR > 0).
    pub cognitive_window_count: usize,

    /// Number of windows classified as transcriptive (LLR < 0).
    pub transcriptive_window_count: usize,

    /// Mean LLR across windows.
    pub mean_window_llr: f64,

    /// Standard deviation of per-window LLRs (higher = mixed session).
    pub llr_std_dev: f64,

    /// Minimum per-window LLR (most transcriptive window).
    pub min_window_llr: f64,

    /// Maximum per-window LLR (most cognitive window).
    pub max_window_llr: f64,

    /// Composite score: 0.0 = transcriptive, 1.0 = cognitive.
    /// Derived from session posterior probability.
    pub composite_score: f64,

    /// Per-window timeline: (seconds_from_start, p_cognitive) pairs.
    /// Enables timestamped sparkline rendering of cognitive mode transitions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub window_timeline: Vec<(f64, f64)>,
}

/// Compute per-window log-likelihood ratios using the given priors.
pub fn compute_window_llrs_with_priors(
    samples: &[SimpleJitterSample],
    priors: &LikelihoodPriors,
) -> Vec<WindowLLR> {
    if samples.len() < MIN_SAMPLES {
        return Vec::new();
    }

    let step = if samples.len() > WINDOW_SIZE {
        WINDOW_SIZE - WINDOW_OVERLAP
    } else {
        samples.len()
    };

    let mut results = Vec::new();
    let mut start = 0;

    while start < samples.len() {
        let end = (start + WINDOW_SIZE).min(samples.len());
        if end - start < MIN_SAMPLES {
            break;
        }

        let features = extract_window_features(&samples[start..end]);
        let ll_cog = log_likelihood_cognitive(&features, priors);
        let ll_trans = log_likelihood_transcriptive(&features);
        let llr = ll_cog - ll_trans;

        let p_cognitive = 1.0 / (1.0 + (-llr.clamp(-700.0, 700.0)).exp());

        results.push(WindowLLR {
            start_idx: start,
            end_idx: end,
            llr,
            p_cognitive,
        });

        start += step;
        if step == 0 {
            break;
        }
    }

    results
}

/// Compute per-window LLRs using population defaults.
pub fn compute_window_llrs(samples: &[SimpleJitterSample]) -> Vec<WindowLLR> {
    compute_window_llrs_with_priors(samples, &LikelihoodPriors::population_defaults())
}

/// Analyze the full session with personalized priors from the user's fingerprint.
pub fn analyze_likelihood_model_with_priors(
    samples: &[SimpleJitterSample],
    fingerprint: Option<&BehavioralFingerprint>,
) -> Option<LikelihoodModelMetrics> {
    let priors = LikelihoodPriors::from_fingerprint(fingerprint);
    analyze_likelihood_model_inner(samples, &priors)
}

/// Analyze the full session using population defaults.
pub fn analyze_likelihood_model(samples: &[SimpleJitterSample]) -> Option<LikelihoodModelMetrics> {
    analyze_likelihood_model_inner(samples, &LikelihoodPriors::population_defaults())
}

fn analyze_likelihood_model_inner(
    samples: &[SimpleJitterSample],
    priors: &LikelihoodPriors,
) -> Option<LikelihoodModelMetrics> {
    if samples.len() < MIN_SAMPLES {
        return None;
    }

    let windows = compute_window_llrs_with_priors(samples, priors);
    if windows.is_empty() {
        return None;
    }

    let window_count = windows.len();
    let cognitive_windows = windows.iter().filter(|w| w.llr > 0.0).count();
    let transcriptive_windows = windows.iter().filter(|w| w.llr < 0.0).count();

    let session_llr: f64 = windows.iter().map(|w| w.llr).sum();
    let mean_llr = session_llr / window_count as f64;

    let llr_variance = if window_count >= 2 {
        windows
            .iter()
            .map(|w| (w.llr - mean_llr).powi(2))
            .sum::<f64>()
            / (window_count - 1) as f64
    } else {
        0.0
    };
    let llr_std_dev = llr_variance.sqrt();

    let min_llr = windows
        .iter()
        .map(|w| w.llr)
        .fold(f64::MAX, f64::min);
    let max_llr = windows
        .iter()
        .map(|w| w.llr)
        .fold(f64::MIN, f64::max);

    // Session posterior: sigmoid of mean LLR (not sum, to be scale-independent).
    let session_p_cognitive = 1.0 / (1.0 + (-mean_llr).exp());

    // Build timestamped timeline: (seconds_from_start, p_cognitive).
    let session_start_ns = samples.first().map(|s| s.timestamp_ns).unwrap_or(0);
    let window_timeline: Vec<(f64, f64)> = windows
        .iter()
        .map(|w| {
            let mid_idx = (w.start_idx + w.end_idx) / 2;
            let mid_ns = samples
                .get(mid_idx)
                .map(|s| s.timestamp_ns)
                .unwrap_or(session_start_ns);
            let secs = (mid_ns - session_start_ns) as f64 / 1_000_000_000.0;
            (secs, w.p_cognitive)
        })
        .collect();

    Some(LikelihoodModelMetrics {
        session_llr,
        session_p_cognitive,
        window_count,
        cognitive_window_count: cognitive_windows,
        transcriptive_window_count: transcriptive_windows,
        mean_window_llr: mean_llr,
        llr_std_dev,
        min_window_llr: min_llr,
        max_window_llr: max_llr,
        composite_score: session_p_cognitive,
        window_timeline,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cognitive_samples(n: usize) -> Vec<SimpleJitterSample> {
        let mut ts = 0i64;
        (0..n)
            .map(|i| {
                // Variable IKI with pauses, corrections, and bursts.
                let iki_ns = if i % 15 == 0 {
                    3_000_000_000u64 // Deep pause every 15 keystrokes.
                } else if i % 7 == 0 {
                    800_000_000 // Thinking pause.
                } else {
                    // Variable burst typing: 80-300ms.
                    let base = 150_000_000u64;
                    let variation = ((i * 37 + 13) % 220) as u64 * 1_000_000;
                    base + variation
                };
                ts += iki_ns as i64;
                let zone = if i % 12 == 0 { 0xFF } else { (i % 8) as u8 };
                SimpleJitterSample {
                    timestamp_ns: ts,
                    duration_since_last_ns: iki_ns,
                    zone,
                    ..Default::default()
                }
            })
            .collect()
    }

    fn make_transcriptive_samples(n: usize) -> Vec<SimpleJitterSample> {
        let mut ts = 0i64;
        (0..n)
            .map(|i| {
                // Uniform IKI: ~120ms with very low variation.
                let iki_ns = 120_000_000u64 + ((i * 3) % 10) as u64 * 1_000_000;
                ts += iki_ns as i64;
                let zone = (i % 8) as u8; // No corrections.
                SimpleJitterSample {
                    timestamp_ns: ts,
                    duration_since_last_ns: iki_ns,
                    zone,
                    ..Default::default()
                }
            })
            .collect()
    }

    #[test]
    fn test_log_gaussian_pdf() {
        let p = log_gaussian_pdf(0.0, 0.0, 1.0);
        // Standard normal at 0: -0.5 * ln(2π) ≈ -0.9189
        assert!((p + 0.9189).abs() < 0.01, "log_gaussian at mean: {}", p);
    }

    #[test]
    fn test_insufficient_samples() {
        let samples = make_cognitive_samples(10);
        assert!(analyze_likelihood_model(&samples).is_none());
    }

    #[test]
    fn test_cognitive_session_positive_llr() {
        let samples = make_cognitive_samples(250);
        let result = analyze_likelihood_model(&samples).unwrap();
        assert!(
            result.session_llr > 0.0,
            "cognitive samples should yield positive session LLR: {}",
            result.session_llr
        );
        assert!(
            result.session_p_cognitive > 0.5,
            "cognitive posterior should be >0.5: {}",
            result.session_p_cognitive
        );
    }

    #[test]
    fn test_transcriptive_session_negative_llr() {
        let samples = make_transcriptive_samples(250);
        let result = analyze_likelihood_model(&samples).unwrap();
        assert!(
            result.session_llr < 0.0,
            "transcriptive samples should yield negative session LLR: {}",
            result.session_llr
        );
        assert!(
            result.session_p_cognitive < 0.5,
            "transcriptive posterior should be <0.5: {}",
            result.session_p_cognitive
        );
    }

    #[test]
    fn test_window_count() {
        let samples = make_cognitive_samples(500);
        let windows = compute_window_llrs(&samples);
        // 500 samples with window=200, step=100: windows at 0, 100, 200, 300
        assert!(windows.len() >= 3, "expected >=3 windows, got {}", windows.len());
    }

    #[test]
    fn test_composite_score_range() {
        let samples = make_cognitive_samples(100);
        let result = analyze_likelihood_model(&samples).unwrap();
        assert!(result.composite_score >= 0.0 && result.composite_score <= 1.0);
    }

    #[test]
    fn test_mixed_session_high_variance() {
        // First half cognitive, second half transcriptive.
        let mut samples = make_cognitive_samples(150);
        samples.extend(make_transcriptive_samples(150));
        // Fix timestamps to be monotonic.
        let mut ts = 0i64;
        for s in &mut samples {
            ts += s.duration_since_last_ns as i64;
            s.timestamp_ns = ts;
        }

        let result = analyze_likelihood_model(&samples).unwrap();
        // Should have both cognitive and transcriptive windows.
        assert!(
            result.cognitive_window_count > 0 && result.transcriptive_window_count > 0,
            "mixed session should have both types: cog={}, trans={}",
            result.cognitive_window_count,
            result.transcriptive_window_count
        );
        // LLR std dev should be higher than a pure session.
        assert!(result.llr_std_dev > 0.0);
    }
}
