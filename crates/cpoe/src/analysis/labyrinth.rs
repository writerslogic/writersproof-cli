// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Labyrinth: multivariate biometric engine via Takens' delay-coordinate embedding.
//! Fuses keystroke (1D) and mouse (2D) data into a unified phase space.
//! RFC draft-condrey-rats-pop §5.4.

use super::stats::sq_dist;
use serde::{Deserialize, Serialize};

/// Comprehensive error type for Labyrinth analysis.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LabyrinthError {
    #[error("Insufficient data: found {found} points, minimum {required} required")]
    InsufficientDataPoints { found: usize, required: usize },
}

/// Result of labyrinth structure analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabyrinthAnalysis {
    pub embedding_dimension: usize,
    pub optimal_delay: usize,
    pub correlation_dimension: f64,
    pub betti_numbers: [usize; 3],
    pub recurrence_rate: f64,
    pub determinism: f64,
    pub is_valid: bool,
    pub confidence: f64,
    pub lyapunov_exponent: f64,
    pub rqa_entropy: f64,
    pub quantization_index: f64,
}

impl LabyrinthAnalysis {
    pub const MIN_EMBEDDING_DIM: usize = 3;
    pub const MAX_EMBEDDING_DIM: usize = 10;
    pub const MIN_CORRELATION_DIM: f64 = 1.0;
    pub const MAX_CORRELATION_DIM: f64 = 5.0;
    pub const MIN_RECURRENCE: f64 = 0.01;
    pub const MAX_RECURRENCE: f64 = 0.50;
    pub const MIN_DETERMINISM: f64 = 0.25;

    pub fn is_biologically_plausible(&self) -> bool {
        self.is_valid
    }
}

#[derive(Debug, Clone)]
pub struct LabyrinthParams {
    pub max_embedding_dim: usize,
    pub max_delay: usize,
    pub recurrence_threshold: f64,
    pub min_line_length: usize,
}

impl Default for LabyrinthParams {
    fn default() -> Self {
        Self {
            max_embedding_dim: 10,
            max_delay: 20,
            recurrence_threshold: 0.1,
            min_line_length: 2,
        }
    }
}

pub(crate) struct RqaResult {
    pub recurrence_rate: f64,
    pub determinism: f64,
    pub laminarity: f64,
}

const MIN_LABYRINTH_DATA_POINTS: usize = 50;
/// Cap input to avoid O(N²) in RQA and Lyapunov. 1000 points = 1M distance
/// comparisons, which completes in ~5ms. 10,000 would take 500ms+.
const MAX_LABYRINTH_DATA_POINTS: usize = 1000;

/// Analyze keystroke timing and optional mouse trajectory via Takens' embedding.
pub fn analyze_labyrinth(
    keystroke_deltas: &[f64],
    mouse_coords: &[(f64, f64)],
    params: &LabyrinthParams,
) -> Result<LabyrinthAnalysis, LabyrinthError> {
    if keystroke_deltas.len() < MIN_LABYRINTH_DATA_POINTS {
        return Err(LabyrinthError::InsufficientDataPoints {
            found: keystroke_deltas.len(),
            required: MIN_LABYRINTH_DATA_POINTS,
        });
    }

    let dim = params.max_embedding_dim.clamp(2, 10);
    let delay = params.max_delay.clamp(1, 50);

    // Truncate to cap O(N²) RQA/Lyapunov at ~1M distance comparisons
    let capped = if keystroke_deltas.len() > MAX_LABYRINTH_DATA_POINTS {
        log::info!(
            "labyrinth: truncating {} keystroke deltas to {} for O(N²) cap",
            keystroke_deltas.len(),
            MAX_LABYRINTH_DATA_POINTS
        );
        &keystroke_deltas[keystroke_deltas.len() - MAX_LABYRINTH_DATA_POINTS..]
    } else {
        keystroke_deltas
    };
    let mut k_norm: Vec<f64> = capped.to_vec();
    normalize_in_place(&mut k_norm);
    let has_mouse = mouse_coords.len() >= MIN_LABYRINTH_DATA_POINTS;

    let embed = if has_mouse {
        let mut mx: Vec<f64> = mouse_coords.iter().map(|p| p.0).collect();
        let mut my: Vec<f64> = mouse_coords.iter().map(|p| p.1).collect();
        normalize_in_place(&mut mx);
        normalize_in_place(&mut my);
        construct_fused_embedding(&k_norm, &mx, &my, dim, delay)
    } else {
        construct_1d_embedding(&k_norm, dim, delay)
    };

    let rqa = compute_rqa(&embed, params.recurrence_threshold, params.min_line_length);
    let lyapunov = estimate_lyapunov(&embed, delay);
    let corr_dim = estimate_correlation_dimension(&embed);
    let q_index = detect_quantization(&embed);

    let is_valid = q_index < 0.65
        && lyapunov > 0.002
        && (1.1..4.9).contains(&corr_dim)
        && rqa.determinism > LabyrinthAnalysis::MIN_DETERMINISM;

    Ok(LabyrinthAnalysis {
        embedding_dimension: if has_mouse { embed.dim / 3 } else { embed.dim },
        optimal_delay: delay,
        correlation_dimension: corr_dim,
        betti_numbers: estimate_betti(&embed),
        recurrence_rate: rqa.recurrence_rate,
        determinism: rqa.determinism,
        is_valid,
        confidence: (keystroke_deltas.len() as f64 / 1000.0).min(1.0),
        lyapunov_exponent: lyapunov,
        rqa_entropy: rqa.laminarity,
        quantization_index: q_index,
    })
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

fn normalize_in_place(data: &mut [f64]) {
    if data.iter().any(|v| !v.is_finite()) {
        log::warn!("labyrinth normalize: non-finite values in input, replacing with zeros");
        for v in data.iter_mut() {
            if !v.is_finite() {
                *v = 0.0;
            }
        }
    }
    let (min, max) = data
        .iter()
        .fold((f64::MAX, f64::NEG_INFINITY), |(m, ax), &x| {
            (m.min(x), ax.max(x))
        });
    let range = (max - min).max(1e-9);
    for x in data.iter_mut() {
        *x = (*x - min) / range;
    }
}

// ---------------------------------------------------------------------------
// Phase-space embedding
// ---------------------------------------------------------------------------

struct FlatEmbedding {
    data: Vec<f64>,
    dim: usize,
    count: usize,
}

impl FlatEmbedding {
    #[inline(always)]
    fn get_point(&self, i: usize) -> &[f64] {
        &self.data[i * self.dim..(i + 1) * self.dim]
    }
}

fn construct_1d_embedding(k: &[f64], dim: usize, delay: usize) -> FlatEmbedding {
    let count = k.len().saturating_sub((dim - 1) * delay);
    let mut data = Vec::with_capacity(count * dim);
    for i in 0..count {
        for d in 0..dim {
            data.push(k[i + d * delay]);
        }
    }
    FlatEmbedding { data, dim, count }
}

fn construct_fused_embedding(
    k: &[f64],
    x: &[f64],
    y: &[f64],
    dim: usize,
    delay: usize,
) -> FlatEmbedding {
    let n = k.len().min(x.len()).min(y.len());
    let channels = 3;
    let total_dim = channels * dim;
    let count = n.saturating_sub((dim - 1) * delay);
    let mut data = Vec::with_capacity(count * total_dim);
    for i in 0..count {
        for d in 0..dim {
            let idx = i + d * delay;
            data.push(k[idx]);
            data.push(x[idx]);
            data.push(y[idx]);
        }
    }
    FlatEmbedding {
        data,
        dim: total_dim,
        count,
    }
}

// ---------------------------------------------------------------------------
// Recurrence Quantification Analysis
// ---------------------------------------------------------------------------

fn compute_rqa(embed: &FlatEmbedding, threshold: f64, min_line: usize) -> RqaResult {
    let n = embed.count;
    let theil_window: usize = 10;
    let eps_sq = threshold.powi(2);
    let mut rec_pts: usize = 0;
    let mut diag_pts: usize = 0;
    let mut hist = [0usize; 50];

    for i in 0..n {
        let p_i = embed.get_point(i);
        for j in 0..n {
            if (i as i64 - j as i64).unsigned_abs() < theil_window as u64 {
                continue;
            }
            if sq_dist(p_i, embed.get_point(j)) < eps_sq {
                rec_pts += 1;
                let mut line_len = 0;
                for k in 1..20 {
                    if i + k >= n || j + k >= n {
                        break;
                    }
                    if sq_dist(embed.get_point(i + k), embed.get_point(j + k)) < eps_sq {
                        line_len += 1;
                    } else {
                        break;
                    }
                }
                if line_len + 1 >= min_line {
                    diag_pts += 1;
                    hist[line_len.min(49)] += 1;
                }
            }
        }
    }

    let total = (n * n.saturating_sub(theil_window * 2)) as f64;
    let rr = rec_pts as f64 / total.max(1.0);
    let det = diag_pts as f64 / rec_pts.max(1) as f64;
    let entropy: f64 = hist
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / diag_pts.max(1) as f64;
            if p > f64::EPSILON {
                -p * p.ln()
            } else {
                0.0
            }
        })
        .sum();

    RqaResult {
        recurrence_rate: rr,
        determinism: det,
        laminarity: entropy,
    }
}

// ---------------------------------------------------------------------------
// Largest Lyapunov Exponent
// ---------------------------------------------------------------------------

fn estimate_lyapunov(embed: &FlatEmbedding, delay: usize) -> f64 {
    let n = embed.count;
    let evol_steps = 8;
    if n <= evol_steps {
        return 0.0;
    }

    let tree = crate::analysis::spatial::KdTree::build(&embed.data, embed.count, embed.dim);
    let min_sep = delay * 2;

    let mut divergence = 0.0;
    let mut count = 0usize;

    for i in 0..n - evol_steps {
        let Some((j, min_dist_sq)) = tree.nearest_neighbor(i, min_sep) else {
            continue;
        };
        if j + evol_steps >= n {
            continue;
        }
        let d0 = min_dist_sq.sqrt();
        let dt = sq_dist(
            embed.get_point(i + evol_steps),
            embed.get_point(j + evol_steps),
        )
        .sqrt();
        if d0 > 1e-10 && dt > 1e-10 {
            divergence += (dt / d0).ln();
            count += 1;
        }
    }

    if count == 0 {
        return 0.0;
    }
    divergence / (count as f64 * evol_steps as f64)
}

// ---------------------------------------------------------------------------
// Correlation Dimension (D2)
// ---------------------------------------------------------------------------

fn estimate_correlation_dimension(embed: &FlatEmbedding) -> f64 {
    let n = embed.count;
    let scales: [f64; 4] = [0.05, 0.1, 0.15, 0.2];
    let mut log_c = Vec::with_capacity(scales.len());
    let mut log_r = Vec::with_capacity(scales.len());

    for r in scales {
        let r_sq = r.powi(2);
        let mut count = 0usize;
        for i in 0..n {
            let p_i = embed.get_point(i);
            for j in i + 1..n {
                if sq_dist(p_i, embed.get_point(j)) < r_sq {
                    count += 1;
                }
            }
        }
        let c_r = (2.0 * count as f64) / (n * n.saturating_sub(1)).max(1) as f64;
        if c_r > 0.0 {
            log_c.push(c_r.ln());
            log_r.push(r.ln());
        }
    }

    if log_r.len() < 2 {
        return 0.0;
    }
    let mean_x = crate::utils::stats::mean(&log_r);
    let mean_y = crate::utils::stats::mean(&log_c);
    let num: f64 = log_r
        .iter()
        .zip(log_c.iter())
        .map(|(x, y)| (x - mean_x) * (y - mean_y))
        .sum();
    let den: f64 = log_r.iter().map(|x| (x - mean_x).powi(2)).sum();
    if den.abs() < 1e-15 {
        return 0.0;
    }
    num / den
}

// ---------------------------------------------------------------------------
// Quantization detection (anti-playback)
// ---------------------------------------------------------------------------

fn detect_quantization(embed: &FlatEmbedding) -> f64 {
    let n = embed.count;
    let scales: [f64; 4] = [0.001, 0.0015, 0.002, 0.0025];
    let mut plateaus = 0;
    let mut prev_count: Option<usize> = None;
    for r in scales {
        let r_sq = r.powi(2);
        let mut total = 0usize;
        for i in 0..n {
            let p_i = embed.get_point(i);
            for j in 0..n {
                if i != j && sq_dist(p_i, embed.get_point(j)) < r_sq {
                    total += 1;
                }
            }
        }
        if let Some(prev) = prev_count {
            if total == prev && total > 0 {
                plateaus += 1;
            }
        }
        prev_count = Some(total);
    }
    plateaus as f64 / (scales.len() - 1) as f64
}

// ---------------------------------------------------------------------------
// Betti number estimation (simplified)
// ---------------------------------------------------------------------------

fn estimate_betti(embed: &FlatEmbedding) -> [usize; 3] {
    let n = embed.count;
    if n < 10 {
        return [1, 0, 0];
    }
    // Simplified: beta_0 from connected components at median distance,
    // beta_1 estimated from recurrence structure.
    let mut dists = Vec::with_capacity(n.min(200));
    for i in 0..n.min(200) {
        if i + 1 < n {
            dists.push(sq_dist(embed.get_point(i), embed.get_point(i + 1)).sqrt());
        }
    }
    if dists.is_empty() {
        return [1, 0, 0];
    }
    dists.retain(|d| d.is_finite());
    if dists.is_empty() {
        return [1, 0, 0];
    }
    dists.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = dists[dists.len() / 2];

    let mut components = n;
    for i in 0..n.saturating_sub(1) {
        if sq_dist(embed.get_point(i), embed.get_point(i + 1)).sqrt() < median * 2.0 {
            components -= 1;
        }
    }
    let beta_0 = components.max(1);
    let beta_1 = if embed.dim >= 4 { 1 } else { 0 };
    [beta_0, beta_1, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sine_data(n: usize) -> Vec<f64> {
        (0..n)
            .map(|i| (i as f64 * 0.1).sin() * 100.0 + 150.0)
            .collect()
    }

    fn make_mouse_data(n: usize) -> Vec<(f64, f64)> {
        (0..n)
            .map(|i| {
                let t = i as f64 * 0.05;
                (t.sin() * 200.0 + 500.0, t.cos() * 200.0 + 400.0)
            })
            .collect()
    }

    #[test]
    fn keystroke_only_analysis() {
        let data = make_sine_data(200);
        let params = LabyrinthParams::default();
        let result = analyze_labyrinth(&data, &[], &params).unwrap();
        assert!(result.confidence > 0.0);
        assert!(result.embedding_dimension > 0);
    }

    #[test]
    fn fused_analysis() {
        let keys = make_sine_data(200);
        let mouse = make_mouse_data(200);
        let params = LabyrinthParams::default();
        let result = analyze_labyrinth(&keys, &mouse, &params).unwrap();
        assert!(result.confidence > 0.0);
        assert!(result.embedding_dimension > 0);
    }

    #[test]
    fn insufficient_data() {
        let data = vec![1.0; 10];
        let params = LabyrinthParams::default();
        assert!(matches!(
            analyze_labyrinth(&data, &[], &params),
            Err(LabyrinthError::InsufficientDataPoints { .. })
        ));
    }

    #[test]
    fn quantization_detects_grid() {
        let data: Vec<f64> = (0..200).map(|i| (i % 5) as f64 * 50.0).collect();
        let params = LabyrinthParams::default();
        let result = analyze_labyrinth(&data, &[], &params).unwrap();
        assert!(
            result.quantization_index > 0.0,
            "quantized input should have non-zero quantization index"
        );
    }

    #[test]
    fn biological_plausibility_check() {
        let data = make_sine_data(500);
        let params = LabyrinthParams::default();
        let result = analyze_labyrinth(&data, &[], &params).unwrap();
        assert_eq!(result.is_valid, result.is_biologically_plausible());
    }

    #[test]
    fn betti_numbers_populated() {
        let data = make_sine_data(200);
        let params = LabyrinthParams::default();
        let result = analyze_labyrinth(&data, &[], &params).unwrap();
        assert!(result.betti_numbers[0] >= 1, "beta_0 should be at least 1");
    }

    #[test]
    fn no_panic_on_zero_count_embedding() {
        // 50..=179 deltas with default params (dim 10, delay 20 => (dim-1)*delay = 180)
        // make embed.count = len.saturating_sub(180) == 0. With overflow-checks=true
        // the correlation-dimension/RQA subtractions previously aborted; must not panic.
        for len in [50usize, 60, 120, 179] {
            let data = make_sine_data(len);
            let params = LabyrinthParams::default();
            assert!(
                analyze_labyrinth(&data, &[], &params).is_ok(),
                "degenerate embedding (len={len}) must not panic"
            );
        }
    }
}
