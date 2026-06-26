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

#[cfg(test)]
use super::types::EventData;
use super::types::SortedEvents;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of position bins for the revision graph.
const POSITION_BINS: usize = 20;

// Bitmask tracking requires POSITION_BINS to fit in a u32.
const _: () = assert!(POSITION_BINS <= 32, "POSITION_BINS must fit in u32 bitmask");

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
            (event.file_size as f64 - (event.size_delta as i64).unsigned_abs() as f64)
                / max_file_size
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
        crate::utils::mean(&frontier_distances)
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

        let del_bytes = (event.size_delta as i64).unsigned_abs() as i64;
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
        if del_bytes <= MOTOR_CORRECTION_MAX_BYTES as i64 && iki_ns < MOTOR_CORRECTION_MAX_NS {
            counts[0] += 1; // SubWordMotor
        } else if del_bytes > CLAUSE_RESTRUCTURING_MIN_DELETE as i64
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

    /// Detour ratio: sum(|cursor_jumps|) / total_chars_typed.
    /// Near-zero for retype; high (>0.3) for composition (Buschenhenke 2023).
    /// Calibrated against Crossley 2024 dataset (99% accuracy).
    pub detour_ratio: f64,

    /// Fraction of edits where cursor < leading edge (max cursor position).
    /// ~0% for retype; 15-40% for composition (Crossley 2024).
    pub leading_edge_divergence: f64,

    /// Shannon entropy of insertion positions (20-bin histogram).
    /// Low for retype (clustered at document end); high for composition.
    pub insertion_point_entropy: f64,
}

/// Compute detour ratio, leading-edge divergence, and insertion-point entropy
/// from the event stream.
///
/// - **Detour ratio** (Buschenhenke 2023): sum of *non-sequential* cursor
///   displacements normalized by total chars typed. Sequential advances
///   (cursor moves forward by exactly `size_delta`) are excluded; only
///   actual cursor repositioning counts.
/// - **Leading-edge divergence** (Crossley 2024): fraction of edits behind
///   the frontier.
/// - **Insertion-point entropy**: Shannon entropy of behind-edge insertion
///   positions only. Frontier-append insertions are excluded so transcription
///   (all-append) yields near-zero entropy while composition (scattered
///   behind-edge edits) yields high entropy.
fn compute_retype_metrics(sorted: SortedEvents<'_>) -> (f64, f64, f64) {
    let max_file_size = sorted.iter().map(|e| e.file_size).max().unwrap_or(1).max(1) as f64;

    let mut total_detour = 0.0f64;
    let mut total_chars_typed = 0i64;
    let mut leading_edge = 0.0f64;
    let mut behind_count = 0usize;
    let mut total_count = 0usize;
    let mut prev_cursor = 0.0f64;
    let mut prev_delta_norm = 0.0f64;
    let mut behind_edge_histogram = [0usize; POSITION_BINS];

    for event in sorted.iter() {
        let cursor = if event.size_delta >= 0 {
            (event.file_size as f64 - event.size_delta as f64) / max_file_size
        } else {
            event.file_size as f64 / max_file_size
        };
        let cursor = cursor.clamp(0.0, 1.0);

        // Detour: only count displacement beyond the expected sequential advance.
        // For an insertion of N bytes, the cursor is expected to advance by N/max.
        // Any additional displacement is a genuine cursor repositioning (detour).
        if total_count > 0 {
            let actual_displacement = cursor - prev_cursor;
            let expected_advance = prev_delta_norm;
            let detour = (actual_displacement - expected_advance).abs();
            // Threshold: ignore sub-character rounding noise.
            if detour > 1.0 / max_file_size {
                total_detour += detour;
            }
        }

        // Track chars typed (positive deltas only).
        if event.size_delta > 0 {
            total_chars_typed += event.size_delta as i64;
        }

        // Leading edge: track maximum cursor position from insertions.
        if event.size_delta > 0 {
            let end_pos = event.file_size as f64 / max_file_size;
            if end_pos > leading_edge {
                leading_edge = end_pos;
            }
        }

        // Leading-edge divergence: count edits behind the frontier.
        let is_behind = leading_edge > 0.0 && cursor < leading_edge * 0.95;
        if is_behind {
            behind_count += 1;
        }

        // Behind-edge insertion histogram (excludes frontier appends).
        if event.size_delta > 0 && is_behind {
            let bin = (cursor * POSITION_BINS as f64)
                .floor()
                .clamp(0.0, (POSITION_BINS - 1) as f64) as usize;
            behind_edge_histogram[bin] += 1;
        }

        total_count += 1;
        prev_cursor = cursor;
        prev_delta_norm = if event.size_delta > 0 {
            event.size_delta as f64 / max_file_size
        } else {
            0.0
        };
    }

    let detour_ratio = if total_chars_typed > 0 {
        total_detour / (total_chars_typed as f64 / max_file_size)
    } else {
        0.0
    };

    let leading_edge_divergence = if total_count > 0 {
        behind_count as f64 / total_count as f64
    } else {
        0.0
    };

    let insertion_point_entropy =
        crate::analysis::histogram::shannon_entropy_usize(&behind_edge_histogram);

    let detour_ratio = if detour_ratio.is_finite() {
        detour_ratio.max(0.0)
    } else {
        0.0
    };

    (
        detour_ratio,
        leading_edge_divergence.clamp(0.0, 1.0),
        insertion_point_entropy,
    )
}

/// Analyze revision topology from edit events.
pub fn analyze_revision_topology(sorted: SortedEvents<'_>) -> Option<RevisionTopologyMetrics> {
    if sorted.len() < MIN_EVENTS {
        return None;
    }

    let graph = build_revision_graph(sorted);
    let revision_types = classify_revisions(sorted);
    let (detour_ratio, leading_edge_divergence, insertion_point_entropy) =
        compute_retype_metrics(sorted);

    // Composite score: graph metrics + revision types + retype-defense metrics.
    // Weights recalibrated against Crossley 2024 (99% accuracy) and
    // Buschenhenke 2023 (detour ratio validated on 400+ sessions).
    use crate::utils::stats::lerp_score;

    let branching_score = lerp_score(graph.mean_branching_factor, 1.0, 3.0);
    let revisit_score = lerp_score(graph.mean_revisit_depth, 1.0, 4.0);
    let frontier_score = lerp_score(graph.mean_frontier_distance, 0.0, 0.5);

    let semantic_ratio = revision_types.word_substitution_pct
        + revision_types.clause_restructuring_pct
        + revision_types.positional_insertion_pct;
    let semantic_score = lerp_score(semantic_ratio, 0.0, 0.6);

    // Retype-defense scores (Crossley 2024 calibration).
    // Detour: transcription ≈0, composition 0.3-1.5+.
    let detour_score = lerp_score(detour_ratio, 0.0, 0.5);
    // LED: transcription ≈0%, composition 15-40%.
    let led_score = lerp_score(leading_edge_divergence, 0.0, 0.30);
    // Insertion entropy: max for 20 bins ≈ 4.32 bits.
    // Transcription clusters at end (< 1.5 bits), composition spreads (2.5-4.0).
    let entropy_score = lerp_score(insertion_point_entropy, 1.0, 3.5);

    // Old signal weights (50% budget, preserve existing DAG analysis).
    const W_BRANCHING: f64 = 0.12;
    const W_REVISIT: f64 = 0.10;
    const W_FRONTIER: f64 = 0.12;
    const W_SEMANTIC: f64 = 0.16;
    // Retype-defense weights (50% budget, AUC-proportional from Crossley 2024).
    // Proxy AUC: detour=0.947, LED=0.883, entropy=0.918.
    const W_DETOUR: f64 = 0.18;
    const W_LED: f64 = 0.15;
    const W_ENTROPY: f64 = 0.17;
    let composite_score = W_BRANCHING * branching_score
        + W_REVISIT * revisit_score
        + W_FRONTIER * frontier_score
        + W_SEMANTIC * semantic_score
        + W_DETOUR * detour_score
        + W_LED * led_score
        + W_ENTROPY * entropy_score;

    let composite_score = if composite_score.is_finite() {
        composite_score.clamp(0.0, 1.0)
    } else {
        0.0
    };

    Some(RevisionTopologyMetrics {
        graph,
        revision_types,
        composite_score,
        detour_ratio,
        leading_edge_divergence,
        insertion_point_entropy,
    })
}

// ---------------------------------------------------------------------------
// Entropy-triggered checkpoint verification
// ---------------------------------------------------------------------------

/// Result of verifying the entropy-triggered checkpoint schedule.
#[derive(Debug, Clone)]
pub struct CheckpointScheduleVerification {
    /// Number of expected trigger points found in the jitter chain replay.
    pub expected_checkpoints: usize,
    /// Number of actual checkpoints that matched expected trigger points
    /// (within `tolerance_ns` of the expected timestamp).
    pub matched_checkpoints: usize,
    /// Trigger timestamps that had no matching checkpoint.
    pub missing_triggers: Vec<i64>,
    /// Checkpoint timestamps that don't correspond to any trigger or deadline.
    pub unexpected_checkpoints: Vec<i64>,
}

impl CheckpointScheduleVerification {
    /// True if all expected triggers have matching checkpoints and no
    /// unexpected checkpoints exist.
    pub fn is_valid(&self) -> bool {
        self.missing_triggers.is_empty() && self.unexpected_checkpoints.is_empty()
    }
}

/// Replay the jitter hash chain and verify that checkpoints fired at the
/// correct entropy-triggered points.
///
/// `session_id`: the session identifier used to seed the hash chain.
/// `samples`: the full jitter sample sequence from the evidence packet.
/// `checkpoint_timestamps_ns`: sorted timestamps of actual checkpoints.
/// `tolerance_ns`: maximum allowed deviation between expected and actual
///   checkpoint timestamps (accounts for async scheduling delay).
pub fn verify_checkpoint_schedule(
    session_id: &str,
    samples: &[crate::jitter::SimpleJitterSample],
    checkpoint_timestamps_ns: &[i64],
    tolerance_ns: i64,
) -> CheckpointScheduleVerification {
    use crate::sentinel::types::{
        ENTROPY_CHECKPOINT_DST, ENTROPY_CHECKPOINT_MAX_NS, ENTROPY_CHECKPOINT_MIN_NS,
        ENTROPY_TRIGGER_THRESHOLD,
    };
    use sha2::{Digest, Sha256};

    // Replay the hash chain from the session seed.
    let mut state: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(ENTROPY_CHECKPOINT_DST);
        h.update(session_id.as_bytes());
        h.finalize().into()
    };

    let mut expected_triggers: Vec<i64> = Vec::new();
    let mut last_trigger_ns: i64 = if samples.is_empty() {
        0
    } else {
        samples[0].timestamp_ns
    };

    for sample in samples {
        // Advance the hash chain (mirrors sentinel/event_handlers.rs).
        let mut h = Sha256::new();
        h.update(state);
        h.update(sample.timestamp_ns.to_be_bytes());
        h.update(sample.duration_since_last_ns.to_be_bytes());
        h.update([sample.zone]);
        state = h.finalize().into();

        let elapsed_ns = sample.timestamp_ns.saturating_sub(last_trigger_ns);

        // Deadline trigger: MAX_INTERVAL exceeded.
        if elapsed_ns >= ENTROPY_CHECKPOINT_MAX_NS {
            expected_triggers.push(sample.timestamp_ns);
            last_trigger_ns = sample.timestamp_ns;
            continue;
        }

        // Entropy trigger: hash chain crossed threshold after MIN floor.
        if elapsed_ns >= ENTROPY_CHECKPOINT_MIN_NS {
            let trigger = u32::from_be_bytes(state[..4].try_into().unwrap());
            if trigger < ENTROPY_TRIGGER_THRESHOLD {
                expected_triggers.push(sample.timestamp_ns);
                last_trigger_ns = sample.timestamp_ns;
            }
        }
    }

    // Match expected triggers against actual checkpoints.
    let tolerance_ns = tolerance_ns.max(0);
    let mut actual_remaining: Vec<i64> = checkpoint_timestamps_ns.to_vec();
    let mut matched = 0usize;
    let mut missing = Vec::new();

    for &expected_ns in &expected_triggers {
        if let Some(pos) = actual_remaining
            .iter()
            .position(|&a| a.saturating_sub(expected_ns).unsigned_abs() <= tolerance_ns as u64)
        {
            actual_remaining.remove(pos);
            matched += 1;
        } else {
            missing.push(expected_ns);
        }
    }

    CheckpointScheduleVerification {
        expected_checkpoints: expected_triggers.len(),
        matched_checkpoints: matched,
        missing_triggers: missing,
        unexpected_checkpoints: actual_remaining,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_events(deltas: &[i32], timestamps_ms: Option<&[i64]>) -> Vec<EventData> {
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
        assert!(
            result.composite_score < 0.6,
            "pure append score: {}",
            result.composite_score
        );

        // Retype-defense metrics: pure append should show transcriptive pattern.
        assert!(
            result.leading_edge_divergence < 0.1,
            "pure append LED should be near zero: {}",
            result.leading_edge_divergence
        );
        assert!(
            result.insertion_point_entropy < 2.5,
            "pure append entropy should be low: {}",
            result.insertion_point_entropy
        );
    }

    #[test]
    fn test_revision_type_motor_correction() {
        // Small deletions with fast IKI = motor corrections.
        let deltas = [
            10, 10, 10, -2, 3, 10, 10, -1, 2, 10, 10, 10, -3, 4, 10, 10, 10, 10, 10, 10, 10, 10,
            10, 10,
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

        // Backtracking should produce non-zero retype-defense signals.
        assert!(
            result.leading_edge_divergence > 0.0,
            "backtracking should produce non-zero LED: {}",
            result.leading_edge_divergence
        );
        assert!(
            result.detour_ratio > 0.0,
            "backtracking should produce non-zero detour ratio: {}",
            result.detour_ratio
        );
    }

    #[test]
    fn test_retype_metrics_pure_retype_vs_composition() {
        // Simulate retype: monotonic append, no backtracking.
        let retype_deltas: Vec<i32> = vec![5; 40];
        let retype_events = make_events(&retype_deltas, None);
        let retype = analyze_revision_topology(SortedEvents::new(&retype_events)).unwrap();

        // Simulate composition: forward, jump back, edit, jump forward.
        let mut comp_events = Vec::new();
        let mut file_size: i64 = 100;
        for i in 0..15 {
            file_size += 20;
            comp_events.push(EventData {
                id: i,
                timestamp_ns: (i + 1) * 1_000_000_000,
                file_size,
                size_delta: 20,
                file_path: "test.txt".to_string(),
            });
        }
        // Jump back to near start and insert.
        for i in 15..25 {
            comp_events.push(EventData {
                id: i as i64,
                timestamp_ns: (i as i64 + 1) * 1_000_000_000,
                file_size: 150,
                size_delta: 10,
                file_path: "test.txt".to_string(),
            });
        }
        // Resume at frontier.
        file_size = 500;
        for i in 25..40 {
            file_size += 15;
            comp_events.push(EventData {
                id: i as i64,
                timestamp_ns: (i as i64 + 1) * 1_000_000_000,
                file_size,
                size_delta: 15,
                file_path: "test.txt".to_string(),
            });
        }
        let comp = analyze_revision_topology(SortedEvents::new(&comp_events)).unwrap();

        // Composition should dominate retype on all three metrics.
        assert!(
            comp.detour_ratio > retype.detour_ratio,
            "comp detour {} should exceed retype {}",
            comp.detour_ratio,
            retype.detour_ratio
        );
        assert!(
            comp.leading_edge_divergence > retype.leading_edge_divergence,
            "comp LED {} should exceed retype {}",
            comp.leading_edge_divergence,
            retype.leading_edge_divergence
        );
        assert!(
            comp.composite_score > retype.composite_score,
            "comp score {} should exceed retype {}",
            comp.composite_score,
            retype.composite_score
        );
    }

    #[test]
    fn test_verify_checkpoint_schedule_roundtrip() {
        use crate::sentinel::types::{
            ENTROPY_CHECKPOINT_DST, ENTROPY_CHECKPOINT_MIN_NS, ENTROPY_TRIGGER_THRESHOLD,
        };
        use sha2::{Digest, Sha256};

        let session_id = "test-session-entropy-001";

        // Generate 500 jitter samples at ~200ms intervals (5 KPS, ~100s of typing).
        let mut samples = Vec::new();
        for i in 0..500 {
            samples.push(crate::jitter::SimpleJitterSample {
                timestamp_ns: (i as i64 + 1) * 200_000_000, // 200ms apart
                duration_since_last_ns: if i == 0 { 0 } else { 200_000_000 },
                zone: (i % 5) as u8,
                dwell_time_ns: None,
                flight_time_ns: None,
            });
        }

        // Replay the hash chain to find expected trigger points (same as verifier).
        let mut state: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(ENTROPY_CHECKPOINT_DST);
            h.update(session_id.as_bytes());
            h.finalize().into()
        };

        let mut checkpoint_timestamps = Vec::new();
        let mut last_trigger_ns: i64 = samples[0].timestamp_ns;

        for sample in &samples {
            let mut h = Sha256::new();
            h.update(state);
            h.update(sample.timestamp_ns.to_be_bytes());
            h.update(sample.duration_since_last_ns.to_be_bytes());
            h.update([sample.zone]);
            state = h.finalize().into();

            let elapsed_ns = sample.timestamp_ns.saturating_sub(last_trigger_ns);
            if elapsed_ns >= ENTROPY_CHECKPOINT_MIN_NS {
                let trigger = u32::from_be_bytes(state[..4].try_into().unwrap());
                if trigger < ENTROPY_TRIGGER_THRESHOLD {
                    checkpoint_timestamps.push(sample.timestamp_ns);
                    last_trigger_ns = sample.timestamp_ns;
                }
            }
        }

        assert!(
            !checkpoint_timestamps.is_empty(),
            "500 samples at 5KPS should produce at least one entropy trigger"
        );

        // Verify: perfect match should produce valid result.
        let result = super::verify_checkpoint_schedule(
            session_id,
            &samples,
            &checkpoint_timestamps,
            0, // zero tolerance for exact match
        );
        assert!(
            result.is_valid(),
            "Perfect replay should verify: missing={:?} unexpected={:?}",
            result.missing_triggers,
            result.unexpected_checkpoints,
        );
        assert_eq!(result.expected_checkpoints, checkpoint_timestamps.len());
        assert_eq!(result.matched_checkpoints, checkpoint_timestamps.len());

        // Verify: missing a checkpoint should be detected.
        if checkpoint_timestamps.len() >= 2 {
            let mut incomplete = checkpoint_timestamps.clone();
            incomplete.remove(0);
            let result = super::verify_checkpoint_schedule(session_id, &samples, &incomplete, 0);
            assert_eq!(result.missing_triggers.len(), 1);
        }

        // Verify: extra checkpoint should be detected.
        let mut extra = checkpoint_timestamps.clone();
        extra.push(50_000_000_000); // fake checkpoint at 50s
        extra.sort();
        let result = super::verify_checkpoint_schedule(session_id, &samples, &extra, 0);
        assert_eq!(result.unexpected_checkpoints.len(), 1);
    }
}
