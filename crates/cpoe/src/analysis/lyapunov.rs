// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Largest Lyapunov exponent estimation via Rosenstein's method.
//!
//! A positive exponent indicates chaotic dynamics (human-like).
//! An exponent ≤ 0 indicates periodic/robotic behavior.
//! An anomalously high exponent indicates random noise (no deterministic structure).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Comprehensive error type for Lyapunov analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LyapunovError {
    InsufficientDataPoints { found: usize, required: usize },
    InsufficientEmbeddingLength { found: usize, required: usize },
    InsufficientIterations,
    NonFiniteValues,
}

impl fmt::Display for LyapunovError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientDataPoints { found, required } => write!(
                f,
                "Insufficient data points: found {}, minimum {} required",
                found, required
            ),
            Self::InsufficientEmbeddingLength { found, required } => write!(
                f,
                "Embedding length too short after delay: found {}, minimum {} required",
                found, required
            ),
            Self::InsufficientIterations => write!(f, "Insufficient iterations for regression"),
            Self::NonFiniteValues => write!(f, "Input contains non-finite values"),
        }
    }
}

impl std::error::Error for LyapunovError {}

/// Minimum data points for Lyapunov analysis.
const MIN_DATA_POINTS: usize = 100;

/// Cap input to avoid O(N²) nearest-neighbor search in phase space.
const MAX_DATA_POINTS: usize = 1000;

/// Embedding dimension for phase-space reconstruction.
const EMBED_DIM: usize = 5;

/// Time delay for embedding.
const EMBED_DELAY: usize = 2;

/// Minimum temporal separation to avoid correlated neighbors.
const MEAN_PERIOD_MULTIPLIER: usize = 10;

/// Exponent below this is periodic/robotic.
const PERIODIC_THRESHOLD: f64 = 0.0;

/// Exponent above this is random noise (no deterministic structure).
const NOISE_THRESHOLD: f64 = 2.0;

/// Result of Lyapunov exponent analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LyapunovAnalysis {
    /// Largest Lyapunov exponent (bits/sample).
    pub exponent: f64,
    /// Whether the result is flagged as anomalous.
    pub flagged: bool,
    /// Confidence in the estimate (0.0-1.0).
    pub confidence: f64,
}

use super::stats::{linear_regression_y_only, sq_dist};

/// Estimate the largest Lyapunov exponent using Rosenstein's method.
///
/// Rosenstein, Collins & De Luca (1993), "A practical method for
/// calculating largest Lyapunov exponents from small data sets."
pub fn analyze_lyapunov(iki_intervals_ns: &[f64]) -> Result<LyapunovAnalysis, LyapunovError> {
    if iki_intervals_ns.len() < MIN_DATA_POINTS {
        return Err(LyapunovError::InsufficientDataPoints {
            found: iki_intervals_ns.len(),
            required: MIN_DATA_POINTS,
        });
    }

    // Truncate to cap O(N²) nearest-neighbor search at ~1M comparisons
    let data = if iki_intervals_ns.len() > MAX_DATA_POINTS {
        &iki_intervals_ns[iki_intervals_ns.len() - MAX_DATA_POINTS..]
    } else {
        iki_intervals_ns
    };

    if crate::utils::require_all_finite(data, "lyapunov").is_err() {
        return Err(LyapunovError::NonFiniteValues);
    }

    // Normalize data
    let (mean, std_dev) = crate::utils::stats::mean_and_std_dev(data);

    if std_dev < 1e-10 {
        // Zero variance → perfectly periodic → flagged
        return Ok(LyapunovAnalysis {
            exponent: f64::NEG_INFINITY,
            flagged: true,
            confidence: 1.0,
        });
    }

    let normalized: Vec<f64> = data.iter().map(|&x| (x - mean) / std_dev).collect();

    // Construct delay embedding (Flattened for cache locality)
    let embed_len = normalized
        .len()
        .saturating_sub((EMBED_DIM - 1) * EMBED_DELAY);

    if embed_len < 20 {
        return Err(LyapunovError::InsufficientEmbeddingLength {
            found: embed_len,
            required: 20,
        });
    }

    let mut embedding = Vec::with_capacity(embed_len * EMBED_DIM);
    for i in 0..embed_len {
        for d in 0..EMBED_DIM {
            embedding.push(normalized[i + d * EMBED_DELAY]);
        }
    }

    let get_point = |idx: usize| -> &[f64] { &embedding[idx * EMBED_DIM..(idx + 1) * EMBED_DIM] };

    let min_sep = MEAN_PERIOD_MULTIPLIER;
    let max_iter = embed_len / 4;
    if max_iter < 5 {
        return Err(LyapunovError::InsufficientIterations);
    }

    // For each point, find nearest neighbor with temporal separation
    let mut divergence_sum = vec![0.0f64; max_iter];
    let mut divergence_count = vec![0usize; max_iter];

    for i in 0..embed_len {
        let mut min_dist = f64::INFINITY;
        let mut nn_idx = 0;
        let p_i = get_point(i);

        for j in 0..embed_len {
            let temporal_sep = i.abs_diff(j);
            if temporal_sep < min_sep {
                continue;
            }

            let dist = sq_dist(p_i, get_point(j)).sqrt();

            if dist < min_dist && dist > 0.0 {
                min_dist = dist;
                nn_idx = j;
            }
        }

        if min_dist.is_infinite() {
            continue;
        }

        // Track divergence over time
        for k in 0..max_iter {
            let i_k = i + k;
            let j_k = nn_idx + k;
            if i_k < embed_len && j_k < embed_len {
                let sq_dist_k = sq_dist(get_point(i_k), get_point(j_k));

                if sq_dist_k > 0.0 {
                    divergence_sum[k] += sq_dist_k.ln();
                    divergence_count[k] += 1;
                }
            }
        }
    }

    // Average log divergence curve
    let log_divergence: Vec<f64> = divergence_sum
        .iter()
        .zip(divergence_count.iter())
        .filter_map(|(&sum, &count)| {
            if count > 0 {
                Some(sum / count as f64)
            } else {
                None
            }
        })
        .collect();

    if log_divergence.len() < 5 {
        return Err(LyapunovError::InsufficientIterations);
    }

    // Estimate slope of the linear region (first quarter)
    let fit_len = (log_divergence.len() / 4).max(5).min(log_divergence.len());
    let (slope, _) = linear_regression_y_only(&log_divergence[..fit_len]);

    // Correct for using ln(sq_dist) instead of ln(dist): ln(d²) = 2*ln(d), so divide slope by 2
    let exponent = slope / 2.0;

    let confidence = (data.len() as f64 / 500.0).min(1.0);
    let flagged = exponent <= PERIODIC_THRESHOLD || exponent > NOISE_THRESHOLD;

    Ok(LyapunovAnalysis {
        exponent,
        flagged,
        confidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lyapunov_insufficient_data() {
        let data: Vec<f64> = (0..50).map(|i| i as f64).collect();
        assert!(matches!(
            analyze_lyapunov(&data),
            Err(LyapunovError::InsufficientDataPoints { .. })
        ));
    }

    #[test]
    fn test_lyapunov_periodic_data() {
        let data: Vec<f64> = (0..300)
            .map(|i| (i as f64 * 0.1).sin() * 100_000_000.0 + 150_000_000.0)
            .collect();
        let result = analyze_lyapunov(&data).unwrap();
        assert!(
            result.exponent <= 0.5,
            "Periodic data should have low exponent, got {}",
            result.exponent
        );
    }

    #[test]
    fn test_lyapunov_chaotic_data() {
        let mut data = Vec::new();
        let mut x = 0.1;
        for _ in 0..300 {
            x = 3.9 * x * (1.0 - x);
            data.push(x * 200_000_000.0 + 50_000_000.0);
        }
        let result = analyze_lyapunov(&data).unwrap();
        assert!(
            result.exponent > 0.0,
            "Chaotic data should have positive exponent, got {}",
            result.exponent
        );
    }

    #[test]
    fn test_lyapunov_constant_data() {
        let data = vec![100_000_000.0; 200];
        let result = analyze_lyapunov(&data).unwrap();
        assert!(result.flagged, "Constant data should be flagged");
    }
}
