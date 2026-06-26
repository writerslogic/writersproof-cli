// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Error topology analysis per RFC draft-condrey-rats-pop-01.
//!
//! Score = 0.4*rho_gap + 0.2*H + 0.4*adj_phys (threshold >= 0.75).
//!
//! Human error patterns show characteristic gap correlation (hesitation
//! before errors, quick correction after), long-range dependence in error
//! timing (Hurst), and physical key adjacency in mistyped characters.
//!
//! Note: the Hurst component uses a single-window R/S estimator
//! (`log(R/S)/log(n)`), which is less accurate than the full multi-window
//! R/S analysis in `analysis/hurst.rs`. Its weight is therefore reduced to
//! 0.2 to limit the impact of single-window estimation error on the composite
//! score. Consider wiring `analysis/hurst.rs` here for a future improvement.

use serde::{Deserialize, Serialize};

/// Comprehensive error type for Error Topology analysis.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorTopologyError {
    #[error("Insufficient events for error topology analysis: found {found}, minimum {required}")]
    InsufficientEvents { found: usize, required: usize },
}

/// Error topology analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorTopology {
    pub gap_correlation: f64,
    pub error_hurst: f64,
    pub adjacency_correlation: f64,
    pub score: f64,
    pub is_valid: bool,
    pub error_count: usize,
    pub error_rate: f64,
    pub error_distribution: ErrorDistribution,
}

/// Error type breakdown by timing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorDistribution {
    pub immediate_corrections: usize,
    pub delayed_corrections: usize,
    pub long_delayed_corrections: usize,
    pub burst_errors: usize,
    pub isolated_errors: usize,
}

/// Score version for stored/compared results. Bump when weights change so
/// callers can reject cross-version comparisons.
///
/// Version history:
///   1 — original weights: gap=0.4, hurst=0.4, adjacency=0.2
///   2 — hurst reduced 0.4→0.2 (single-window R/S less accurate than
///         multi-window); adjacency raised 0.2→0.4 to compensate
impl ErrorTopology {
    pub const VALIDITY_THRESHOLD: f64 = 0.75;
    pub const WEIGHT_GAP: f64 = 0.4;
    /// Reduced from 0.4 to 0.2 (version 1→2) because the single-window R/S
    /// estimator is less accurate than the multi-window analysis in
    /// `analysis/hurst.rs`. The freed weight is redistributed to
    /// adjacency_correlation.
    pub const WEIGHT_HURST: f64 = 0.2;
    pub const WEIGHT_ADJACENCY: f64 = 0.4;

    pub fn compute_score(
        gap_correlation: f64,
        error_hurst: f64,
        adjacency_correlation: f64,
    ) -> f64 {
        Self::WEIGHT_GAP * gap_correlation
            + Self::WEIGHT_HURST * error_hurst
            + Self::WEIGHT_ADJACENCY * adjacency_correlation
    }

    pub fn is_biologically_plausible(&self) -> bool {
        self.score >= Self::VALIDITY_THRESHOLD
    }

    pub fn is_error_rate_plausible(&self) -> bool {
        self.error_rate >= 1.0 && self.error_rate <= 10.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Normal,
    Correction,
    WordDelete,
    LineDelete,
}

#[derive(Debug, Clone)]
pub struct TopologyEvent {
    pub timestamp_ns: i64,
    pub event_type: EventType,
    pub key_code: Option<u16>,
    pub gap_ns: u64,
}

/// Analyze error topology from a sequence of events. Requires >= 20 events.
pub fn analyze_error_topology(
    events: &[TopologyEvent],
) -> Result<ErrorTopology, ErrorTopologyError> {
    if events.len() < 20 {
        return Err(ErrorTopologyError::InsufficientEvents {
            found: events.len(),
            required: 20,
        });
    }

    let error_indices: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            matches!(
                e.event_type,
                EventType::Correction | EventType::WordDelete | EventType::LineDelete
            )
        })
        .map(|(i, _)| i)
        .collect();

    let error_count = error_indices.len();
    let error_rate = (error_count as f64 / events.len() as f64) * 100.0;

    if error_count < 3 {
        return Ok(ErrorTopology {
            gap_correlation: 0.0,
            error_hurst: 0.5,
            adjacency_correlation: 0.0,
            score: 0.0,
            is_valid: false,
            error_count,
            error_rate,
            error_distribution: ErrorDistribution::default(),
        });
    }

    let gap_correlation = compute_gap_correlation(events, &error_indices);
    let error_hurst = compute_error_hurst(events, &error_indices).unwrap_or(0.5);
    let adjacency_correlation = compute_adjacency_correlation(events, &error_indices);

    let score = ErrorTopology::compute_score(gap_correlation, error_hurst, adjacency_correlation);
    let is_valid = score >= ErrorTopology::VALIDITY_THRESHOLD;
    let error_distribution = compute_error_distribution(events, &error_indices);

    Ok(ErrorTopology {
        gap_correlation,
        error_hurst,
        adjacency_correlation,
        score,
        is_valid,
        error_count,
        error_rate,
        error_distribution,
    })
}

fn compute_gap_correlation(events: &[TopologyEvent], error_indices: &[usize]) -> f64 {
    if error_indices.is_empty() || events.len() < 3 {
        return 0.0;
    }

    let mut pre_error_sum = 0.0;
    let mut pre_error_count = 0;

    let mut post_error_sum = 0.0;
    let mut post_error_count = 0;

    let mut normal_sum = 0.0;
    let mut normal_count = 0;

    let mut err_ptr = 0;
    let mut prev_was_error = false;

    // Zero-allocation, single-pass linear scan using two pointers
    for (i, event) in events.iter().enumerate() {
        let gap_ms = crate::utils::ns_to_ms(event.gap_ns as i64);

        let is_error = if err_ptr < error_indices.len() && error_indices[err_ptr] == i {
            err_ptr += 1;
            true
        } else {
            false
        };

        if is_error {
            pre_error_sum += gap_ms;
            pre_error_count += 1;
        } else if prev_was_error {
            post_error_sum += gap_ms;
            post_error_count += 1;
        } else {
            normal_sum += gap_ms;
            normal_count += 1;
        }

        prev_was_error = is_error;
    }

    if normal_count == 0 || pre_error_count == 0 {
        return 0.0;
    }

    let normal_mean = normal_sum / normal_count as f64;
    let pre_error_mean = pre_error_sum / pre_error_count as f64;

    let post_error_mean = if post_error_count > 0 {
        post_error_sum / post_error_count as f64
    } else {
        normal_mean
    };

    let pre_ratio = if normal_mean > 0.0 {
        (pre_error_mean / normal_mean).min(3.0)
    } else {
        1.0
    };

    let post_ratio = if normal_mean > 0.0 {
        (normal_mean / post_error_mean.max(1.0)).min(3.0)
    } else {
        1.0
    };

    ((pre_ratio - 1.0).max(0.0) * 0.5 + (post_ratio - 1.0).max(0.0) * 0.5).min(1.0)
}

fn compute_error_hurst(events: &[TopologyEvent], error_indices: &[usize]) -> Option<f64> {
    if error_indices.len() < 5 {
        return None;
    }

    // Pre-allocate to prevent dynamic heap resizing
    let mut intervals = Vec::with_capacity(error_indices.len().saturating_sub(1));
    for i in 1..error_indices.len() {
        let prev_idx = error_indices[i - 1];
        let curr_idx = error_indices[i];

        if curr_idx > prev_idx {
            let time_diff = events[curr_idx].timestamp_ns - events[prev_idx].timestamp_ns;
            if time_diff > 0 {
                intervals.push(time_diff as f64);
            }
        }
    }

    if intervals.len() < 4 {
        return None;
    }

    let n = intervals.len();
    let (mean, variance) = crate::utils::stats::mean_and_variance(&intervals);

    let mut cumsum = 0.0;
    let mut max_cumsum = f64::NEG_INFINITY;
    let mut min_cumsum = f64::INFINITY;

    for &x in &intervals {
        cumsum += x - mean;
        max_cumsum = max_cumsum.max(cumsum);
        min_cumsum = min_cumsum.min(cumsum);
    }

    let range = max_cumsum - min_cumsum;
    let std_dev = variance.sqrt();

    if std_dev > 0.0 && range > 0.0 {
        let rs = range / std_dev;
        // H ~ log(R/S) / log(n)
        let nf = n as f64;
        if nf.ln() < f64::EPSILON {
            Some(0.5)
        } else {
            Some(
                crate::utils::Probability::clamp(crate::utils::finite_or(rs.ln() / nf.ln(), 0.5))
                    .get(),
            )
        }
    } else {
        Some(0.5)
    }
}

fn compute_adjacency_correlation(events: &[TopologyEvent], error_indices: &[usize]) -> f64 {
    if error_indices.is_empty() {
        return 0.0;
    }

    let mut adjacent_errors = 0;
    let mut total_with_keys = 0;

    for &error_idx in error_indices {
        if error_idx > 0 {
            let prev_event = &events[error_idx - 1];
            let curr_event = &events[error_idx];

            if let (Some(prev_key), Some(curr_key)) = (prev_event.key_code, curr_event.key_code) {
                total_with_keys += 1;
                if are_keys_adjacent(prev_key, curr_key) {
                    adjacent_errors += 1;
                }
            }
        }
    }

    if total_with_keys > 0 {
        let adjacency_rate = adjacent_errors as f64 / total_with_keys as f64;

        // Plausible human range: 15-50%; outside suggests random or simulated
        if (0.15..=0.50).contains(&adjacency_rate) {
            1.0
        } else if adjacency_rate < 0.15 {
            adjacency_rate / 0.15
        } else {
            (1.0 - (adjacency_rate - 0.50) / 0.50).max(0.0)
        }
    } else {
        0.5
    }
}

fn are_keys_adjacent(key1: u16, key2: u16) -> bool {
    if let (Some((r1, c1)), Some((r2, c2))) = (key_to_position(key1), key_to_position(key2)) {
        let row_diff = r1.abs_diff(r2);
        let col_diff = c1.abs_diff(c2);

        row_diff <= 1 && col_diff <= 1 && (row_diff + col_diff) > 0
    } else {
        false
    }
}

fn key_to_position(key: u16) -> Option<(u8, u8)> {
    if key > 127 {
        return None;
    }
    match key as u8 as char {
        '1'..='9' => Some((0, (key - u16::from(b'1')) as u8)),
        '0' => Some((0, 9)),
        'q' | 'Q' => Some((1, 0)),
        'w' | 'W' => Some((1, 1)),
        'e' | 'E' => Some((1, 2)),
        'r' | 'R' => Some((1, 3)),
        't' | 'T' => Some((1, 4)),
        'y' | 'Y' => Some((1, 5)),
        'u' | 'U' => Some((1, 6)),
        'i' | 'I' => Some((1, 7)),
        'o' | 'O' => Some((1, 8)),
        'p' | 'P' => Some((1, 9)),
        'a' | 'A' => Some((2, 0)),
        's' | 'S' => Some((2, 1)),
        'd' | 'D' => Some((2, 2)),
        'f' | 'F' => Some((2, 3)),
        'g' | 'G' => Some((2, 4)),
        'h' | 'H' => Some((2, 5)),
        'j' | 'J' => Some((2, 6)),
        'k' | 'K' => Some((2, 7)),
        'l' | 'L' => Some((2, 8)),
        'z' | 'Z' => Some((3, 0)),
        'x' | 'X' => Some((3, 1)),
        'c' | 'C' => Some((3, 2)),
        'v' | 'V' => Some((3, 3)),
        'b' | 'B' => Some((3, 4)),
        'n' | 'N' => Some((3, 5)),
        'm' | 'M' => Some((3, 6)),
        _ => None,
    }
}

fn compute_error_distribution(
    events: &[TopologyEvent],
    error_indices: &[usize],
) -> ErrorDistribution {
    let mut dist = ErrorDistribution::default();
    let mut prev_timestamp = None;

    for &error_idx in error_indices {
        let event = &events[error_idx];
        let gap_ms = crate::utils::ns_to_ms(event.gap_ns as i64);

        if gap_ms < 500.0 {
            dist.immediate_corrections += 1;
        } else if gap_ms < 2000.0 {
            dist.delayed_corrections += 1;
        } else {
            dist.long_delayed_corrections += 1;
        }

        let is_burst = match prev_timestamp {
            Some(pt) => {
                let time_diff = event.timestamp_ns.saturating_sub(pt);
                // 1_000_000_000 ns == 1 second
                time_diff > 0 && time_diff < 1_000_000_000
            }
            None => false,
        };

        if is_burst {
            dist.burst_errors += 1;
        } else {
            dist.isolated_errors += 1;
        }

        prev_timestamp = Some(event.timestamp_ns);
    }

    dist
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_events(pattern: &[(i64, EventType, u64)]) -> Vec<TopologyEvent> {
        let mut events = Vec::new();
        let mut timestamp = 0i64;

        for &(gap_ms, event_type, _) in pattern {
            timestamp += gap_ms * 1_000_000;
            events.push(TopologyEvent {
                timestamp_ns: timestamp,
                event_type,
                key_code: None,
                gap_ns: (gap_ms * 1_000_000) as u64,
            });
        }

        events
    }

    #[test]
    fn test_error_topology_basic() {
        let pattern: Vec<(i64, EventType, u64)> = vec![
            (200, EventType::Normal, 0),
            (150, EventType::Normal, 0),
            (180, EventType::Normal, 0),
            (400, EventType::Correction, 0),
            (100, EventType::Normal, 0),
            (200, EventType::Normal, 0),
            (150, EventType::Normal, 0),
            (350, EventType::Correction, 0),
            (120, EventType::Normal, 0),
            (200, EventType::Normal, 0),
            (180, EventType::Normal, 0),
            (420, EventType::Correction, 0),
            (110, EventType::Normal, 0),
            (200, EventType::Normal, 0),
            (150, EventType::Normal, 0),
            (200, EventType::Normal, 0),
            (180, EventType::Normal, 0),
            (200, EventType::Normal, 0),
            (150, EventType::Normal, 0),
            (200, EventType::Normal, 0),
        ];

        let events = create_test_events(&pattern);
        let result = analyze_error_topology(&events).unwrap();

        assert_eq!(result.error_count, 3);
        assert!(result.error_rate > 0.0);
    }

    #[test]
    fn test_insufficient_events() {
        let pattern: Vec<(i64, EventType, u64)> =
            vec![(200, EventType::Normal, 0), (150, EventType::Normal, 0)];

        let events = create_test_events(&pattern);
        let result = analyze_error_topology(&events);

        assert!(matches!(
            result,
            Err(ErrorTopologyError::InsufficientEvents { .. })
        ));
    }

    #[test]
    fn test_score_calculation() {
        let score = ErrorTopology::compute_score(0.8, 0.7, 0.6);
        let expected = 0.4 * 0.8 + 0.2 * 0.7 + 0.4 * 0.6;
        assert!((score - expected).abs() < 0.001);
    }

    #[test]
    fn test_key_adjacency() {
        assert!(are_keys_adjacent('q' as u16, 'w' as u16));
        assert!(are_keys_adjacent('q' as u16, 'a' as u16));
        assert!(!are_keys_adjacent('q' as u16, 'z' as u16));
    }

    #[test]
    fn test_error_distribution() {
        let pattern: Vec<(i64, EventType, u64)> = vec![
            (200, EventType::Normal, 0),
            (100, EventType::Correction, 0),
            (200, EventType::Normal, 0),
            (800, EventType::Correction, 0),
            (200, EventType::Normal, 0),
            (3000, EventType::Correction, 0),
        ];
        let mut full_pattern = pattern.clone();
        for _ in 0..15 {
            full_pattern.push((200, EventType::Normal, 0));
        }

        let events = create_test_events(&full_pattern);
        let result = analyze_error_topology(&events).unwrap();

        assert_eq!(result.error_distribution.immediate_corrections, 1);
        assert_eq!(result.error_distribution.delayed_corrections, 1);
        assert_eq!(result.error_distribution.long_delayed_corrections, 1);
    }
}
