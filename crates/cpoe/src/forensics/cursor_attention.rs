// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Cursor attention and scroll behavior analysis for authorship evidence.
//!
//! Derives attention patterns from scroll events and cursor position statistics:
//!
//! - **Bidirectional scrolling**: writers re-read; transcriptionists scroll one way
//! - **Direction reversals**: frequent reversals = scanning/reviewing behavior
//! - **Scroll-edit correlation**: scrolling near keystrokes = re-reading before revising
//! - **Scroll-before-edit**: scrolls that precede keystrokes within 3s (strongest signal)
//! - **Scroll velocity uniformity**: human scroll velocity varies; synthetic is uniform
//! - **Position entropy**: dispersed attention vs. fixed-point transcription
//! - **Read-back frequency**: cursor moving toward document start
//! - **Dwell distribution**: where the cursor spends time (top/middle/bottom thirds)

use crate::sentinel::types::ScrollAttentionAccumulator;
use serde::{Deserialize, Serialize};

/// Minimum scroll events required for meaningful analysis.
const MIN_SCROLL_EVENTS: u64 = 5;
/// Minimum position samples for position-based metrics.
const MIN_POSITION_SAMPLES: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorAttentionMetrics {
    // --- scroll behavior ---
    /// Total scroll events in the session.
    pub scroll_event_count: u64,
    /// Ratio of bidirectional scrolling: min(up,down)/max(up,down).
    /// 0.0 = unidirectional, 1.0 = equal up/down.
    pub scroll_bidirectional_ratio: f64,
    /// Direction reversals per scroll event. Human scanning produces frequent
    /// reversals (>0.15); follow-along transcription produces near-zero.
    pub reversal_rate: f64,
    /// Fraction of scroll events that occur within 5s of a keystroke.
    pub scroll_edit_correlation: f64,
    /// Fraction of scroll events that precede a keystroke within 3s.
    /// The strongest single signal: re-reading before editing.
    pub scroll_before_edit_ratio: f64,
    /// Coefficient of variation of scroll delta magnitudes.
    /// Human scrolling has variable velocity (CV > 0.3); synthetic is uniform (CV < 0.1).
    pub scroll_velocity_cv: f64,

    // --- cursor position ---
    /// Shannon entropy of cursor Y-position histogram (10 bins).
    /// High = dispersed attention; low = fixed-point transcription.
    pub position_entropy: f64,
    /// Fraction of cursor movements going "upward" (toward document start).
    pub read_back_frequency: f64,
    /// Dwell distribution across screen thirds [top, middle, bottom] as fractions.
    pub dwell_distribution: [f64; 3],
    /// Gini coefficient of dwell distribution. 0 = uniform, 1 = concentrated.
    /// Writers show moderate Gini (0.2-0.5); transcriptionists show high (>0.6).
    pub dwell_gini: f64,

    // --- composite ---
    /// Composite attention score: 0.0 = transcriptive, 1.0 = cognitive/compositional.
    pub composite_score: f64,
}

pub fn analyze(acc: &ScrollAttentionAccumulator) -> Option<CursorAttentionMetrics> {
    if acc.total_scroll_events < MIN_SCROLL_EVENTS {
        return None;
    }

    let total = acc.total_scroll_events as f64;

    // Bidirectional ratio
    let up = acc.scroll_up_count as f64;
    let down = acc.scroll_down_count as f64;
    let max_dir = up.max(down);
    let scroll_bidirectional_ratio = if max_dir > 0.0 {
        up.min(down) / max_dir
    } else {
        0.0
    };

    // Reversal rate
    let reversal_rate = acc.direction_reversals as f64 / total;

    // Scroll-edit correlations
    let scroll_edit_correlation = (acc.scroll_near_edit_count as f64 / total).min(1.0);
    let scroll_before_edit_ratio = (acc.scroll_before_edit_count as f64 / total).min(1.0);

    // Scroll velocity CV (coefficient of variation) via Welford
    let scroll_velocity_cv = acc.scroll_velocity_cv();

    // Position metrics (may have insufficient data independently of scroll count)
    let has_position = acc.position_sample_count >= MIN_POSITION_SAMPLES;

    let position_entropy = if has_position {
        compute_bin_entropy(&acc.position_y_bins)
    } else {
        0.0
    };

    let read_back_frequency = if has_position {
        let total_moves = acc.cursor_move_up_count + acc.cursor_move_down_count;
        if total_moves > 0 {
            acc.cursor_move_up_count as f64 / total_moves as f64
        } else {
            0.0
        }
    } else {
        0.0
    };

    let (dwell_distribution, dwell_gini) = compute_dwell_metrics(&acc.dwell_thirds_ns);

    // Composite score: calibrated weights based on signal discrimination power.
    //
    // scroll_before_edit_ratio is the strongest single discriminator between
    // cognitive writing and transcription — weight it highest.
    // reversal_rate and scroll_velocity_cv are the next-most-discriminating.
    // bidirectional_ratio, position_entropy, and read_back are supporting signals.
    //
    // Weights sum to 1.0:
    //   scroll_before_edit:  0.25  (strongest: re-read then edit)
    //   reversal_rate:       0.20  (scanning behavior)
    //   scroll_velocity_cv:  0.15  (human variability)
    //   bidirectional_ratio: 0.15  (re-reading)
    //   position_entropy:    0.15  (dispersed attention)
    //   dwell_gini:          0.05  (where cursor lingers)
    //   read_back:           0.05  (backward movement)

    let max_entropy = 10.0_f64.log2(); // log2(10 bins) ≈ 3.32
    let entropy_norm = if has_position && max_entropy > 0.0 {
        (position_entropy / max_entropy).min(1.0)
    } else {
        0.5 // neutral when no data
    };

    // reversal_rate: clamp to [0, 1] — values above 0.4 are already strongly cognitive
    let reversal_norm = (reversal_rate / 0.4).min(1.0);

    // scroll_velocity_cv: human CV is typically 0.3-1.5; normalize so 0.5 → 0.5
    let velocity_cv_norm = (scroll_velocity_cv / 1.0).min(1.0);

    // dwell_gini inverted: low gini = dispersed = cognitive
    let gini_score = if has_position { 1.0 - dwell_gini } else { 0.5 };

    let composite_score = (0.25 * scroll_before_edit_ratio
        + 0.20 * reversal_norm
        + 0.15 * velocity_cv_norm
        + 0.15 * scroll_bidirectional_ratio
        + 0.15 * entropy_norm
        + 0.05 * gini_score
        + 0.05 * read_back_frequency)
        .clamp(0.0, 1.0);

    Some(CursorAttentionMetrics {
        scroll_event_count: acc.total_scroll_events,
        scroll_bidirectional_ratio,
        reversal_rate,
        scroll_edit_correlation,
        scroll_before_edit_ratio,
        scroll_velocity_cv,
        position_entropy,
        read_back_frequency,
        dwell_distribution,
        dwell_gini,
        composite_score,
    })
}

/// Shannon entropy from a pre-computed histogram.
fn compute_bin_entropy(bins: &[u64; 10]) -> f64 {
    let total: u64 = bins.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let t = total as f64;
    bins.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / t;
            -p * p.log2()
        })
        .sum()
}

/// Compute dwell distribution fractions and Gini coefficient from time-weighted thirds.
fn compute_dwell_metrics(thirds_ns: &[u64; 3]) -> ([f64; 3], f64) {
    let total: u64 = thirds_ns.iter().sum();
    if total == 0 {
        return ([0.0; 3], 0.0);
    }
    let t = total as f64;
    let dist = [
        thirds_ns[0] as f64 / t,
        thirds_ns[1] as f64 / t,
        thirds_ns[2] as f64 / t,
    ];

    // Gini coefficient for 3 values: G = (sum of |xi - xj|) / (2 * n * mean)
    let n = 3.0;
    let mean = 1.0 / n;
    let abs_diff_sum = (dist[0] - dist[1]).abs()
        + (dist[0] - dist[2]).abs()
        + (dist[1] - dist[2]).abs();
    let gini = if mean > 0.0 {
        (abs_diff_sum / (2.0 * n * mean)).min(1.0)
    } else {
        0.0
    };

    (dist, gini)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_acc() -> ScrollAttentionAccumulator {
        ScrollAttentionAccumulator::default()
    }

    fn add_scrolls(acc: &mut ScrollAttentionAccumulator, ups: u64, downs: u64, near: u64) {
        acc.scroll_up_count = ups;
        acc.scroll_down_count = downs;
        acc.total_scroll_events = ups + downs;
        acc.scroll_near_edit_count = near;
    }

    fn add_position_samples(acc: &mut ScrollAttentionAccumulator, ys: &[f64]) {
        for &y in ys {
            acc.record_position(y);
            acc.record_direction(y);
            acc.last_sample_y = y;
            acc.last_sample_ts_ns = 1; // nonzero so direction tracking activates
        }
    }

    #[test]
    fn too_few_scroll_events() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 2, 2, 0);
        assert!(analyze(&acc).is_none());
    }

    #[test]
    fn bidirectional_ratio_equal() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 10, 10, 5);
        let m = analyze(&acc).unwrap();
        assert!((m.scroll_bidirectional_ratio - 1.0).abs() < 0.01);
    }

    #[test]
    fn unidirectional_scroll() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 0, 20, 0);
        let m = analyze(&acc).unwrap();
        assert!(m.scroll_bidirectional_ratio < 0.01);
    }

    #[test]
    fn reversal_rate() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 5, 5, 0);
        acc.direction_reversals = 6;
        let m = analyze(&acc).unwrap();
        assert!((m.reversal_rate - 0.6).abs() < 0.01);
    }

    #[test]
    fn scroll_edit_correlation() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 5, 5, 8);
        let m = analyze(&acc).unwrap();
        assert!((m.scroll_edit_correlation - 0.8).abs() < 0.01);
    }

    #[test]
    fn scroll_before_edit() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 10, 10, 5);
        acc.scroll_before_edit_count = 12;
        let m = analyze(&acc).unwrap();
        assert!((m.scroll_before_edit_ratio - 0.6).abs() < 0.01);
    }

    #[test]
    fn scroll_velocity_cv_variable() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 5, 5, 0);
        for &m in &[1.0, 5.0, 2.0, 8.0, 3.0, 7.0, 1.0, 6.0, 4.0, 9.0] {
            acc.record_scroll_magnitude(m);
        }
        let m = analyze(&acc).unwrap();
        assert!(m.scroll_velocity_cv > 0.3, "human-like CV={}", m.scroll_velocity_cv);
    }

    #[test]
    fn scroll_velocity_cv_uniform() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 5, 5, 0);
        for _ in 0..10 {
            acc.record_scroll_magnitude(3.0);
        }
        let m = analyze(&acc).unwrap();
        assert!(m.scroll_velocity_cv < 0.05, "uniform CV={}", m.scroll_velocity_cv);
    }

    #[test]
    fn position_entropy_dispersed() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 5, 5, 0);
        let ys: Vec<f64> = (0..100).map(|i| i as f64 * 10.0).collect();
        add_position_samples(&mut acc, &ys);
        let m = analyze(&acc).unwrap();
        assert!(m.position_entropy > 2.0, "dispersed entropy={}", m.position_entropy);
    }

    #[test]
    fn position_entropy_clustered() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 5, 5, 0);
        // Nearly identical Y values — range < 1.0 → entropy 0
        let ys: Vec<f64> = (0..20).map(|_| 500.0).collect();
        add_position_samples(&mut acc, &ys);
        let m = analyze(&acc).unwrap();
        assert!(m.position_entropy < 0.01, "clustered entropy={}", m.position_entropy);
    }

    #[test]
    fn read_back_with_revision() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 10, 5, 0);
        let ys = vec![
            100.0, 200.0, 300.0, 400.0, 500.0,
            400.0, 300.0, 200.0,
            300.0, 400.0, 500.0, 600.0,
        ];
        add_position_samples(&mut acc, &ys);
        let m = analyze(&acc).unwrap();
        assert!(m.read_back_frequency > 0.2, "read_back={}", m.read_back_frequency);
    }

    #[test]
    fn dwell_distribution_uniform() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 5, 5, 0);
        acc.dwell_thirds_ns = [1000, 1000, 1000];
        add_position_samples(&mut acc, &(0..20).map(|i| i as f64 * 50.0).collect::<Vec<_>>());
        let m = analyze(&acc).unwrap();
        assert!(m.dwell_gini < 0.05, "uniform gini={}", m.dwell_gini);
        for &d in &m.dwell_distribution {
            assert!((d - 1.0 / 3.0).abs() < 0.01);
        }
    }

    #[test]
    fn dwell_distribution_concentrated() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 5, 5, 0);
        acc.dwell_thirds_ns = [0, 0, 3000];
        add_position_samples(&mut acc, &(0..20).map(|i| i as f64 * 50.0).collect::<Vec<_>>());
        let m = analyze(&acc).unwrap();
        assert!(m.dwell_gini > 0.5, "concentrated gini={}", m.dwell_gini);
    }

    #[test]
    fn composite_cognitive_pattern() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 15, 12, 20);
        acc.direction_reversals = 10;
        acc.scroll_before_edit_count = 15;
        for &m in &[1.0, 5.0, 2.0, 8.0, 3.0, 7.0, 1.0, 6.0, 4.0, 9.0,
                    2.0, 6.0, 3.0, 7.0, 4.0, 5.0, 1.0, 8.0, 3.0, 6.0,
                    2.0, 7.0, 4.0, 5.0, 3.0, 8.0, 1.0] {
            acc.record_scroll_magnitude(m);
        }
        let ys: Vec<f64> = (0..100).map(|i| i as f64 * 10.0).collect();
        add_position_samples(&mut acc, &ys);
        acc.dwell_thirds_ns = [800, 1200, 1000];
        let m = analyze(&acc).unwrap();
        assert!(m.composite_score > 0.5, "cognitive composite={}", m.composite_score);
    }

    #[test]
    fn composite_transcriptive_pattern() {
        let mut acc = make_acc();
        add_scrolls(&mut acc, 0, 10, 0);
        acc.direction_reversals = 0;
        acc.scroll_before_edit_count = 0;
        for _ in 0..10 {
            acc.record_scroll_magnitude(3.0);
        }
        // Clustered position
        let ys: Vec<f64> = (0..20).map(|_| 900.0).collect();
        add_position_samples(&mut acc, &ys);
        acc.dwell_thirds_ns = [0, 0, 3000];
        let m = analyze(&acc).unwrap();
        assert!(m.composite_score < 0.20, "transcriptive composite={}", m.composite_score);
    }

    #[test]
    fn bin_entropy_uniform_distribution() {
        let bins = [10, 10, 10, 10, 10, 10, 10, 10, 10, 10];
        let e = compute_bin_entropy(&bins);
        let max = 10.0_f64.log2();
        assert!((e - max).abs() < 0.01, "uniform entropy={} expected={}", e, max);
    }

    #[test]
    fn bin_entropy_single_bin() {
        let bins = [100, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let e = compute_bin_entropy(&bins);
        assert!(e < 0.01, "single-bin entropy={}", e);
    }

    #[test]
    fn gini_uniform() {
        let (_, gini) = compute_dwell_metrics(&[100, 100, 100]);
        assert!(gini < 0.01, "uniform gini={}", gini);
    }

    #[test]
    fn gini_concentrated() {
        let (_, gini) = compute_dwell_metrics(&[0, 0, 300]);
        assert!(gini > 0.6, "concentrated gini={}", gini);
    }
}
