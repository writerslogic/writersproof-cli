// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Revision Topology and Semantic Delta analysis.
//!
//! Builds a revision graph from edit events and classifies revisions by type:
//!
//! - **Sub-word motor correction**: Backspace 1-3 chars within 800ms, retype similar.
//! - **Word substitution**: Delete and replace entire word within 2s (lexical selection).
//! - **Clause restructuring**: Delete >10 chars, pause >1s, type different content.
//! - **Positional insertion**: Navigate backward and insert without deleting.
//!
//! Graph metrics (branching factor, revisit depth, frontier distance) distinguish
//! cognitive writing (non-linear, revisiting DAG) from transcriptive (linear chain).

use serde::{Deserialize, Serialize};

use super::types::SortedEvents;
#[cfg(test)]
use super::types::EventData;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of position bins for the revision graph.
const POSITION_BINS: usize = 20;

/// Minimum events for meaningful topology analysis.
const MIN_EVENTS: usize = 20;

/// Maximum IKI (nanoseconds) for sub-word motor correction (800ms).
const MOTOR_CORRECTION_MAX_NS: i64 = 800_000_000;

/// Maximum deletion size (bytes) for sub-word motor correction.
const MOTOR_CORRECTION_MAX_BYTES: i32 = 4;

/// Maximum IKI for word substitution (2 seconds).
const WORD_SUBSTITUTION_MAX_NS: i64 = 2_000_000_000;

/// Minimum deletion size for clause restructuring.
const CLAUSE_RESTRUCTURING_MIN_DELETE: i32 = 10;

/// Minimum pause before clause restructuring (1 second).
const CLAUSE_RESTRUCTURING_PAUSE_NS: i64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Revision type classification
// ---------------------------------------------------------------------------

/// Classification of a single revision event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevisionType {
    /// Backspace 1-3 chars within 800ms: motor execution error recovery.
    SubWordMotor,
    /// Delete and replace word within 2s: lexical selection / synonym choice.
    WordSubstitution,
    /// Delete >10 chars, pause >1s, type different content: reformulation.
    ClauseRestructuring,
    /// Navigate backward, insert without deleting: elaboration.
    PositionalInsertion,
}

/// Distribution across the four revision types.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevisionTypeDistribution {
    /// Fraction of revisions that are sub-word motor corrections.
    pub sub_word_motor_pct: f64,
    /// Fraction that are word substitutions (lexical selection).
    pub word_substitution_pct: f64,
    /// Fraction that are clause restructuring (reformulation).
    pub clause_restructuring_pct: f64,
    /// Fraction that are positional insertions (elaboration).
    pub positional_insertion_pct: f64,
    /// Total number of classified revision events.
    pub total_revisions: usize,
}

// ---------------------------------------------------------------------------
// Revision graph
// ---------------------------------------------------------------------------

/// Metrics from the revision DAG.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevisionGraphMetrics {
    /// Mean branching factor: how many distinct regions are edited from a given position.
    /// Cognitive: >2. Transcriptive: ~1 (linear).
    pub mean_branching_factor: f64,

    /// Mean number of times each active region is re-edited.
    /// Cognitive: 2-4 revisits. Transcriptive: 0-1.
    pub mean_revisit_depth: f64,

    /// Mean distance between current edit position and the document frontier.
    /// Cognitive: 30-60% of document behind frontier. Transcriptive: >90%.
    pub mean_frontier_distance: f64,

    /// Number of distinct position bins that received edits.
    pub active_region_count: usize,
}

/// Build revision graph metrics from position bins.
fn build_revision_graph(sorted: SortedEvents<'_>) -> RevisionGraphMetrics {
    if sorted.len() < MIN_EVENTS {
        return RevisionGraphMetrics::default();
    }

    let max_file_size = sorted.iter().map(|e| e.file_size).max().unwrap_or(1).max(1) as f64;

    // Track which bins are edited and transitions between bins.
    // Bitmask pattern: POSITION_BINS is 20, so a u32 bitmask per source bin
    // records all unique targets in 80 bytes total with zero heap allocation.
    let mut bin_edit_counts = [0usize; POSITION_BINS];
    let mut transition_bitmask = [0u32; POSITION_BINS];
    let mut frontier_bin = 0usize;
    let mut frontier_distances = Vec::with_capacity(sorted.len());

    let mut prev_bin: Option<usize> = None;

    for event in sorted.iter() {
        let cursor_pos = if event.size_delta >= 0 {
            event.file_size as f64 / max_file_size
        } else {
            (event.file_size as f64 - event.size_delta.abs() as f64) / max_file_size
        };
        let bin = (cursor_pos * POSITION_BINS as f64)
            .floor()
            .clamp(0.0, (POSITION_BINS - 1) as f64) as usize;

        bin_edit_counts[bin] += 1;

        if event.size_delta > 0 && bin >= frontier_bin {
            frontier_bin = bin;
        }

        if frontier_bin > 0 {
            frontier_distances
                .push((frontier_bin as f64 - bin as f64) / frontier_bin.max(1) as f64);
        }

        if let Some(prev) = prev_bin {
            if prev != bin {
                transition_bitmask[prev] |= 1 << bin;
            }
        }
        prev_bin = Some(bin);
    }

    // Branching factor: mean number of distinct target bins per source bin.
    let active_bins: Vec<usize> = (0..POSITION_BINS)
        .filter(|&b| transition_bitmask[b] != 0)
        .collect();

    let mean_branching = if active_bins.is_empty() {
        1.0
    } else {
        let total_unique_targets: u32 = active_bins
            .iter()
            .map(|&b| transition_bitmask[b].count_ones())
            .sum();
        total_unique_targets as f64 / active_bins.len() as f64
    };

    // Revisit depth: mean edit count for bins that were edited.
    let active_region_count = bin_edit_counts.iter().filter(|&&c| c > 0).count();
    let mean_revisit = if active_region_count == 0 {
        0.0
    } else {
        let total_edits: usize = bin_edit_counts.iter().filter(|&&c| c > 0).sum();
        total_edits as f64 / active_region_count as f64
    };

    // Mean frontier distance.
    let mean_frontier_distance = if frontier_distances.is_empty() {
        0.0
    } else {
        frontier_distances.iter().sum::<f64>() / frontier_distances.len() as f64
    };

    RevisionGraphMetrics {
        mean_branching_factor: mean_branching,
        mean_revisit_depth: mean_revisit,
        mean_frontier_distance: mean_frontier_distance.clamp(0.0, 1.0),
        active_region_count,
    }
}

// ---------------------------------------------------------------------------
// Revision type classifier
// ---------------------------------------------------------------------------

/// Classify revision events from the edit stream.
fn classify_revisions(sorted: SortedEvents<'_>) -> RevisionTypeDistribution {
    if sorted.len() < MIN_EVENTS {
        return RevisionTypeDistribution::default();
    }

    let mut counts = [0usize; 4]; // motor, substitution, restructuring, insertion
    let max_file_size = sorted.iter().map(|e| e.file_size).max().unwrap_or(1).max(1) as f64;
    let mut frontier_pos = 0.0f64;

    for i in 0..sorted.len() {
        let event = &sorted[i];

        // Update frontier.
        if event.size_delta > 0 {
            let pos = event.file_size as f64 / max_file_size;
            if pos > frontier_pos {
                frontier_pos = pos;
            }
        }

        // Only classify deletion events followed by insertion (revision).
        if event.size_delta >= 0 {
            continue;
        }

        let del_bytes = event.size_delta.abs();
        let iki_ns = if i > 0 {
            event
                .timestamp_ns
                .saturating_sub(sorted[i - 1].timestamp_ns)
        } else {
            i64::MAX
        };

        // Check if followed by an insertion.
        let has_followup_insert = i + 1 < sorted.len() && sorted[i + 1].size_delta > 0;
        let followup_iki = if i + 1 < sorted.len() {
            sorted[i + 1]
                .timestamp_ns
                .saturating_sub(event.timestamp_ns)
        } else {
            i64::MAX
        };

        // Classify.
        if del_bytes <= MOTOR_CORRECTION_MAX_BYTES && iki_ns < MOTOR_CORRECTION_MAX_NS {
            counts[0] += 1; // SubWordMotor
        } else if del_bytes > CLAUSE_RESTRUCTURING_MIN_DELETE
            && followup_iki > CLAUSE_RESTRUCTURING_PAUSE_NS
            && has_followup_insert
        {
            counts[2] += 1; // ClauseRestructuring
        } else if has_followup_insert && followup_iki < WORD_SUBSTITUTION_MAX_NS {
            counts[1] += 1; // WordSubstitution
        }
    }

    // Positional insertions: insertions behind the frontier.
    for event in sorted.iter() {
        if event.size_delta > 0 && frontier_pos > 0.0 {
            let pos = event.file_size as f64 / max_file_size;
            if pos < frontier_pos * 0.8 {
                counts[3] += 1; // PositionalInsertion
            }
        }
    }

    let total = counts.iter().sum::<usize>();
    if total == 0 {
        return RevisionTypeDistribution::default();
    }

    let t = total as f64;
    RevisionTypeDistribution {
        sub_word_motor_pct: counts[0] as f64 / t,
        word_substitution_pct: counts[1] as f64 / t,
        clause_restructuring_pct: counts[2] as f64 / t,
        positional_insertion_pct: counts[3] as f64 / t,
        total_revisions: total,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Combined revision topology metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevisionTopologyMetrics {
    /// DAG structure metrics.
    pub graph: RevisionGraphMetrics,

    /// Revision type distribution.
    pub revision_types: RevisionTypeDistribution,

    /// Composite score: 0.0 = transcriptive, 1.0 = cognitive.
    /// Based on non-linearity of edits and prevalence of semantic revisions.
    pub composite_score: f64,
}

/// Analyze revision topology from edit events.
pub fn analyze_revision_topology(sorted: SortedEvents<'_>) -> Option<RevisionTopologyMetrics> {
    if sorted.len() < MIN_EVENTS {
        return None;
    }

    let graph = build_revision_graph(sorted);
    let revision_types = classify_revisions(sorted);

    // Composite score from graph metrics and revision type distribution.
    use crate::utils::stats::lerp_score;

    let branching_score = lerp_score(graph.mean_branching_factor, 1.0, 3.0);
    let revisit_score = lerp_score(graph.mean_revisit_depth, 1.0, 4.0);
    let frontier_score = lerp_score(graph.mean_frontier_distance, 0.0, 0.5);

    let semantic_ratio = revision_types.word_substitution_pct
        + revision_types.clause_restructuring_pct
        + revision_types.positional_insertion_pct;
    let semantic_score = lerp_score(semantic_ratio, 0.0, 0.6);

    const W_BRANCHING: f64 = 0.25;
    const W_REVISIT: f64 = 0.20;
    const W_FRONTIER: f64 = 0.25;
    const W_SEMANTIC: f64 = 0.30;
    let composite_score = W_BRANCHING * branching_score
        + W_REVISIT * revisit_score
        + W_FRONTIER * frontier_score
        + W_SEMANTIC * semantic_score;

    Some(RevisionTopologyMetrics {
        graph,
        revision_types,
        composite_score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_events(
        deltas: &[i32],
        timestamps_ms: Option<&[i64]>,
    ) -> Vec<EventData> {
        let mut file_size: i64 = 1000;
        deltas
            .iter()
            .enumerate()
            .map(|(i, &d)| {
                file_size = (file_size + d as i64).max(0);
                let ts = timestamps_ms
                    .map(|ts| ts[i] * 1_000_000)
                    .unwrap_or((i as i64 + 1) * 1_000_000_000);
                EventData {
                    id: i as i64,
                    timestamp_ns: ts,
                    file_size,
                    size_delta: d,
                    file_path: "test.txt".to_string(),
                }
            })
            .collect()
    }

    #[test]
    fn test_insufficient_data() {
        let events = make_events(&[10; 5], None);
        assert!(analyze_revision_topology(SortedEvents::new(&events)).is_none());
    }

    #[test]
    fn test_pure_append_linear() {
        let deltas: Vec<i32> = vec![10; 30];
        let events = make_events(&deltas, None);
        let result = analyze_revision_topology(SortedEvents::new(&events)).unwrap();

        // Pure append should have low branching and revisit depth.
        assert!(
            result.graph.mean_branching_factor <= 2.0,
            "pure append branching: {}",
            result.graph.mean_branching_factor
        );
        assert!(result.composite_score < 0.6, "pure append score: {}", result.composite_score);
    }

    #[test]
    fn test_revision_type_motor_correction() {
        // Small deletions with fast IKI = motor corrections.
        let deltas = [
            10, 10, 10, -2, 3, 10, 10, -1, 2, 10, 10, 10, -3, 4, 10, 10, 10, 10, 10, 10,
            10, 10, 10, 10,
        ];
        let timestamps: Vec<i64> = (0..deltas.len())
            .map(|i| (i as i64) * 300) // 300ms intervals — within motor correction window
            .collect();
        let events = make_events(&deltas, Some(&timestamps));
        let dist = classify_revisions(SortedEvents::new(&events));

        assert!(dist.total_revisions > 0);
        assert!(
            dist.sub_word_motor_pct > 0.0,
            "should detect motor corrections"
        );
    }

    #[test]
    fn test_revision_graph_with_backtracking() {
        // Simulate editing at different document positions (varying file sizes).
        let mut events = Vec::new();
        let mut file_size: i64 = 100;

        // Write forward.
        for i in 0..10 {
            file_size += 50;
            events.push(EventData {
                id: i,
                timestamp_ns: (i + 1) * 1_000_000_000,
                file_size,
                size_delta: 50,
                file_path: "test.txt".to_string(),
            });
        }

        // Jump back and edit near beginning (simulating cursor jump).
        for i in 10..15 {
            events.push(EventData {
                id: i as i64,
                timestamp_ns: (i as i64 + 1) * 1_000_000_000,
                file_size: 200, // Much lower than frontier (~600)
                size_delta: 5,
                file_path: "test.txt".to_string(),
            });
        }

        // Resume at frontier.
        for i in 15..25 {
            file_size += 30;
            events.push(EventData {
                id: i as i64,
                timestamp_ns: (i as i64 + 1) * 1_000_000_000,
                file_size,
                size_delta: 30,
                file_path: "test.txt".to_string(),
            });
        }

        let result = analyze_revision_topology(SortedEvents::new(&events)).unwrap();
        assert!(
            result.graph.mean_frontier_distance > 0.0,
            "backtracking should produce non-zero frontier distance"
        );
        assert!(result.graph.active_region_count > 1);
    }
}
