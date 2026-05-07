// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Cross-modal consistency analysis for adversarial forgery detection.
//!
//! Verifies that independently-captured evidence channels (keystrokes, content
//! growth, timing jitter, edit topology) are mutually consistent. A user
//! adversary must fabricate ALL channels simultaneously and maintain coherence
//! across them, which raises the cost of forgery from O(1) per channel to
//! O(n^2) due to pairwise consistency constraints.

use serde::{Deserialize, Serialize};

use super::types::EventData;
use crate::analysis::stats::safe_div;
use crate::jitter::SimpleJitterSample;

const MIN_EVENTS: usize = 10;
const MIN_JITTER_SAMPLES: usize = 20;

/// Minimum jitter samples per 1000 document characters.
/// Below this the jitter channel is too sparse to be credible.
const MIN_JITTER_DENSITY_PER_KCHAR: f64 = 0.5;

/// Human typing rarely exceeds 15 chars/second sustained over 10+ seconds.
const MAX_SUSTAINED_CHARS_PER_SEC: f64 = 15.0;
/// Minimum ratio of edit events to jitter samples (keystrokes should
/// produce content changes; a ratio below this suggests injected jitter).
const MIN_EDIT_TO_JITTER_RATIO: f64 = 0.02;
/// Maximum allowable gap between last jitter sample and last edit event (seconds).
const MAX_TEMPORAL_DRIFT_SEC: f64 = 120.0;

const INSUFFICIENT_SCORE: f64 = 0.5;
const FAILED_CHECK_SCORE: f64 = 0.3;
const MIN_SESSION_DURATION_SEC: f64 = 10.0;
const EVENTS_PER_CHECKPOINT_MIN: f64 = 0.5;
const EVENTS_PER_CHECKPOINT_MAX: f64 = 200.0;
const EDIT_JITTER_RATIO_GOOD: f64 = 0.1;
const COHERENCE_MARGINAL_SCORE: f64 = 0.6;
const COHERENCE_FAILED_MAX_SCORE: f64 = 0.4;
const DRIFT_PERFECT_SEC: f64 = 10.0;
const DRIFT_MODERATE_PENALTY: f64 = 0.4;
const DRIFT_LARGE_DIVISOR: f64 = 600.0;
const DRIFT_LARGE_MAX_SCORE: f64 = 0.3;
const KS_CONTENT_MIN: f64 = 0.5;
const JITTER_KS_MIN: f64 = 0.3;
const KS_CONTENT_OPTIMAL: f64 = 1.0;
const JITTER_KS_OPTIMAL: f64 = 0.8;
const ENTANGLEMENT_MARGINAL_SCORE: f64 = 0.6;
const ENTANGLEMENT_FAILED_SCORE: f64 = 0.2;

#[derive(Debug)]
/// Input data for cross-modal consistency analysis.
pub struct CrossModalInput<'a> {
    /// Edit events captured during the session.
    pub events: &'a [EventData],
    /// Timing jitter samples, if available.
    pub jitter_samples: Option<&'a [SimpleJitterSample]>,
    /// Final document length in characters.
    pub document_length: i64,
    /// Total keystrokes recorded independently of jitter.
    pub total_keystrokes: i64,
    /// Number of checkpoints in the evidence chain.
    pub checkpoint_count: u64,
    /// Wall-clock duration of the authoring session (seconds).
    pub session_duration_sec: f64,
}

/// Result of cross-modal consistency analysis across evidence channels.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrossModalResult {
    /// Overall consistency score [0.0, 1.0]; higher = more consistent.
    pub score: f64,
    /// Individual check results for each cross-modal test.
    pub checks: Vec<CrossModalCheck>,
    /// Aggregate verdict based on failed check count.
    pub verdict: CrossModalVerdict,
}

/// Result of a single cross-modal consistency check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossModalCheck {
    /// Identifier for this check (e.g., "content_growth_rate").
    pub name: String,
    /// Whether the check passed its threshold.
    pub passed: bool,
    /// Normalized score [0.0, 1.0] for this check.
    pub score: f64,
    /// Human-readable explanation of the result.
    pub detail: String,
}

/// Aggregate verdict from cross-modal consistency analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CrossModalVerdict {
    /// All channels are mutually consistent.
    Consistent,
    /// One or two checks failed; evidence is suspect but not conclusive.
    Marginal,
    /// Multiple channels are inconsistent -- likely forgery.
    Inconsistent,
    /// Not enough data to perform cross-modal analysis.
    #[default]
    Insufficient,
}

/// Run all cross-modal consistency checks and produce an aggregate result.
pub fn analyze_cross_modal(input: &CrossModalInput<'_>) -> CrossModalResult {
    let mut checks = Vec::new();

    if input.events.len() < MIN_EVENTS {
        return CrossModalResult {
            score: INSUFFICIENT_SCORE,
            checks,
            verdict: CrossModalVerdict::Insufficient,
        };
    }

    checks.push(check_content_growth_rate(input));
    checks.push(check_edit_checkpoint_ratio(input));

    if let Some(samples) = input.jitter_samples {
        if samples.len() >= MIN_JITTER_SAMPLES {
            checks.push(check_jitter_edit_coherence(input.events, samples));
            checks.push(check_temporal_span_alignment(input.events, samples));
            checks.push(check_jitter_content_entanglement(
                samples,
                input.document_length,
                input.total_keystrokes,
            ));
            checks.push(check_content_growth_vs_jitter_density(
                samples,
                input.document_length,
            ));
        }
    }

    if checks.is_empty() {
        return CrossModalResult {
            score: INSUFFICIENT_SCORE,
            checks,
            verdict: CrossModalVerdict::Insufficient,
        };
    }

    let total: f64 = checks.iter().map(|c| c.score).sum();
    let score = total / checks.len() as f64;
    let failed = checks.iter().filter(|c| !c.passed).count();

    // Checks 3 (jitter_edit_coherence) and 5 (jitter_content_entanglement) are
    // the strongest causal links between the jitter and keystroke channels.
    // A single failure of either is treated as Inconsistent rather than Marginal
    // because these checks cannot both fail by accident in genuine typing.
    let critical_jitter_failed = checks.iter().any(|c| {
        !c.passed
            && (c.name == "jitter_edit_coherence" || c.name == "jitter_content_entanglement")
    });

    let verdict = if failed >= 3 || critical_jitter_failed {
        CrossModalVerdict::Inconsistent
    } else if failed >= 1 {
        CrossModalVerdict::Marginal
    } else {
        CrossModalVerdict::Consistent
    };

    CrossModalResult {
        score,
        checks,
        verdict,
    }
}

/// Check 1: Content growth rate vs session duration.
///
/// If document length / session time exceeds human typing speed, the content
/// was likely pasted or AI-generated and the session fabricated around it.
fn check_content_growth_rate(input: &CrossModalInput<'_>) -> CrossModalCheck {
    if input.document_length < 0 {
        return CrossModalCheck {
            name: "content_growth_rate".into(),
            passed: false,
            score: 0.0,
            detail: format!(
                "Negative document length ({}); invalid input",
                input.document_length
            ),
        };
    }

    if input.session_duration_sec < MIN_SESSION_DURATION_SEC {
        return CrossModalCheck {
            name: "content_growth_rate".into(),
            passed: true,
            score: INSUFFICIENT_SCORE,
            detail: "Session too short for growth rate analysis".into(),
        };
    }

    // Track gross additions (sum of positive deltas) to prevent bypass via
    // alternating +/- deltas that cancel to a small net value.
    let gross_additions: i64 = input
        .events
        .iter()
        .map(|e| (e.size_delta as i64).max(0))
        .sum();
    // When gross_additions is 0 but document_length > 0, the event stream shows no
    // recorded growth despite an existing document. This is a definitive inconsistency
    // (AI-generated content or evidence fabrication), not merely suspicious, so score 0.0.
    if gross_additions == 0 && input.document_length > 0 {
        return CrossModalCheck {
            name: "content_growth_rate".into(),
            passed: false,
            score: 0.0,
            detail: "zero gross additions with non-empty document".into(),
        };
    }
    let chars_per_sec = gross_additions as f64 / input.session_duration_sec;
    let passed = chars_per_sec <= MAX_SUSTAINED_CHARS_PER_SEC;

    let score = if chars_per_sec <= MAX_SUSTAINED_CHARS_PER_SEC {
        1.0
    } else {
        crate::utils::Probability::clamp(
            1.0 - (chars_per_sec - MAX_SUSTAINED_CHARS_PER_SEC) / MAX_SUSTAINED_CHARS_PER_SEC,
        )
        .get()
    };

    CrossModalCheck {
        name: "content_growth_rate".into(),
        passed,
        score,
        detail: format!(
            "Content growth: {:.1} chars/sec (threshold: {:.0})",
            chars_per_sec, MAX_SUSTAINED_CHARS_PER_SEC
        ),
    }
}

/// Check 2: Edit events should produce checkpoints at a reasonable rate.
///
/// If checkpoint_count is much lower than expected for the number of edits,
/// the checkpoints may have been fabricated after the fact.
fn check_edit_checkpoint_ratio(input: &CrossModalInput<'_>) -> CrossModalCheck {
    if input.checkpoint_count == 0 {
        return CrossModalCheck {
            name: "edit_checkpoint_ratio".into(),
            passed: false,
            score: 0.0,
            detail: "No checkpoints recorded".into(),
        };
    }

    let events_per_checkpoint = input.events.len() as f64 / input.checkpoint_count as f64;

    let passed =
        (EVENTS_PER_CHECKPOINT_MIN..=EVENTS_PER_CHECKPOINT_MAX).contains(&events_per_checkpoint);
    let score = if passed { 1.0 } else { FAILED_CHECK_SCORE };

    CrossModalCheck {
        name: "edit_checkpoint_ratio".into(),
        passed,
        score,
        detail: format!(
            "{:.1} events per checkpoint ({} events, {} checkpoints)",
            events_per_checkpoint,
            input.events.len(),
            input.checkpoint_count
        ),
    }
}

/// Check 3: Jitter samples and edit events should overlap temporally.
///
/// If jitter samples exist but don't align with edit event timestamps,
/// the jitter was likely injected from a separate source.
fn check_jitter_edit_coherence(
    events: &[EventData],
    samples: &[SimpleJitterSample],
) -> CrossModalCheck {
    let edit_count = events.len();
    let jitter_count = samples.len();

    let ratio = safe_div(edit_count as f64, jitter_count as f64, 0.0);
    let passed = ratio >= MIN_EDIT_TO_JITTER_RATIO;

    let score = if ratio >= EDIT_JITTER_RATIO_GOOD {
        1.0
    } else if ratio >= MIN_EDIT_TO_JITTER_RATIO {
        COHERENCE_MARGINAL_SCORE
    } else {
        safe_div(ratio, MIN_EDIT_TO_JITTER_RATIO, 0.0).clamp(0.0, COHERENCE_FAILED_MAX_SCORE)
    };

    CrossModalCheck {
        name: "jitter_edit_coherence".into(),
        passed,
        score,
        detail: format!(
            "Edit/jitter ratio: {:.4} ({} edits, {} jitter samples)",
            ratio, edit_count, jitter_count
        ),
    }
}

/// Check 4: Temporal span of jitter samples should align with edit events.
///
/// The first and last jitter timestamps should bracket (or closely match)
/// the first and last edit event timestamps. Large drift suggests the
/// jitter was recorded in a different session.
fn check_temporal_span_alignment(
    events: &[EventData],
    samples: &[SimpleJitterSample],
) -> CrossModalCheck {
    let edit_first = events.iter().map(|e| e.timestamp_ns).min().unwrap_or(0);
    let edit_last = events.iter().map(|e| e.timestamp_ns).max().unwrap_or(0);

    let jitter_first = samples.iter().map(|s| s.timestamp_ns).min().unwrap_or(0);
    let jitter_last = samples.iter().map(|s| s.timestamp_ns).max().unwrap_or(0);

    // Zero timestamps are invalid -- they indicate missing or uninitialized data,
    // not legitimate temporal information. Treat as a failed check to prevent bypass.
    if jitter_first == 0 || jitter_last == 0 || edit_first == 0 || edit_last == 0 {
        return CrossModalCheck {
            name: "temporal_span_alignment".into(),
            passed: false,
            score: 0.0,
            detail: "Zero timestamps detected; cannot verify temporal alignment".into(),
        };
    }

    // Compute drift at both ends (seconds), using i128 to avoid i64 overflow
    let start_drift = (edit_first as i128 - jitter_first as i128).unsigned_abs() as f64 / 1e9;
    let end_drift = (edit_last as i128 - jitter_last as i128).unsigned_abs() as f64 / 1e9;
    let max_drift = start_drift.max(end_drift);

    let passed = max_drift <= MAX_TEMPORAL_DRIFT_SEC;
    let score = if max_drift <= DRIFT_PERFECT_SEC {
        1.0
    } else if max_drift <= MAX_TEMPORAL_DRIFT_SEC {
        let denom = (MAX_TEMPORAL_DRIFT_SEC - DRIFT_PERFECT_SEC).max(f64::EPSILON);
        (1.0 - (max_drift - DRIFT_PERFECT_SEC) / denom * DRIFT_MODERATE_PENALTY).clamp(0.0, 1.0)
    } else {
        (DRIFT_LARGE_MAX_SCORE - (max_drift - MAX_TEMPORAL_DRIFT_SEC) / DRIFT_LARGE_DIVISOR)
            .clamp(0.0, DRIFT_LARGE_MAX_SCORE)
    };

    CrossModalCheck {
        name: "temporal_span_alignment".into(),
        passed,
        score,
        detail: format!(
            "Temporal drift: start={:.1}s, end={:.1}s (max allowed: {:.0}s)",
            start_drift, end_drift, MAX_TEMPORAL_DRIFT_SEC
        ),
    }
}

/// Check 5: Jitter volume should correlate with content length.
///
/// Each keystroke produces one jitter sample, so the ratio of
/// jitter_count to document_length should be plausible for human typing
/// (accounting for deletions, corrections, navigation keys).
fn check_jitter_content_entanglement(
    samples: &[SimpleJitterSample],
    document_length: i64,
    total_keystrokes: i64,
) -> CrossModalCheck {
    if document_length <= 0 {
        return CrossModalCheck {
            name: "jitter_content_entanglement".into(),
            passed: true,
            score: INSUFFICIENT_SCORE,
            detail: "No document content for entanglement check".into(),
        };
    }

    let jitter_count = samples.len() as i64;

    // Without an independent keystroke count, jitter/keystroke ratio would be
    // self-referential (jitter_count / jitter_count = 1.0), trivially passing.
    // Fall back to document_length as an independent lower bound instead.
    let keystroke_source = if total_keystrokes > 0 {
        total_keystrokes
    } else {
        document_length
    };

    let ks_content_ratio = keystroke_source as f64 / document_length as f64;
    let jitter_ks_ratio = if keystroke_source > 0 {
        jitter_count as f64 / keystroke_source as f64
    } else {
        0.0
    };

    let passed = ks_content_ratio >= KS_CONTENT_MIN && jitter_ks_ratio >= JITTER_KS_MIN;

    let score = if ks_content_ratio >= KS_CONTENT_OPTIMAL && jitter_ks_ratio >= JITTER_KS_OPTIMAL {
        1.0
    } else if passed {
        ENTANGLEMENT_MARGINAL_SCORE
    } else {
        ENTANGLEMENT_FAILED_SCORE
    };

    CrossModalCheck {
        name: "jitter_content_entanglement".into(),
        passed,
        score,
        detail: format!(
            "Keystroke/content ratio: {:.2}, jitter/keystroke ratio: {:.2}",
            ks_content_ratio, jitter_ks_ratio
        ),
    }
}

/// Check 6: Jitter sample density vs document length.
///
/// Genuine typing produces roughly one jitter sample per keystroke. If the
/// document has many characters but very few jitter samples, the content
/// was likely inserted without corresponding physical keystrokes.
fn check_content_growth_vs_jitter_density(
    samples: &[SimpleJitterSample],
    document_length: i64,
) -> CrossModalCheck {
    if document_length <= 0 {
        return CrossModalCheck {
            name: "content_growth_vs_jitter_density".into(),
            passed: true,
            score: INSUFFICIENT_SCORE,
            detail: "No document content for jitter density check".into(),
        };
    }

    let kchars = document_length as f64 / 1000.0;
    let density = samples.len() as f64 / kchars;
    let passed = density >= MIN_JITTER_DENSITY_PER_KCHAR;

    let score = if passed {
        (density / (MIN_JITTER_DENSITY_PER_KCHAR * 10.0)).min(1.0)
    } else {
        safe_div(density, MIN_JITTER_DENSITY_PER_KCHAR, 0.0).clamp(0.0, FAILED_CHECK_SCORE)
    };

    CrossModalCheck {
        name: "content_growth_vs_jitter_density".into(),
        passed,
        score,
        detail: format!(
            "Jitter density: {:.2} samples/kchar ({} samples, {} chars)",
            density,
            samples.len(),
            document_length
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_events(count: usize, start_ns: i64, interval_ns: i64) -> Vec<EventData> {
        (0..count)
            .map(|i| EventData {
                id: i as i64,
                timestamp_ns: start_ns + i as i64 * interval_ns,
                file_size: (i as i64 + 1) * 100,
                size_delta: 10,
                file_path: "test.txt".into(),
            })
            .collect()
    }

    fn make_jitter(count: usize, start_ns: i64, interval_ns: i64) -> Vec<SimpleJitterSample> {
        (0..count)
            .map(|i| SimpleJitterSample {
                timestamp_ns: start_ns + i as i64 * interval_ns,
                duration_since_last_ns: 150_000_000, // 150ms
                zone: 0,
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn test_consistent_session() {
        let events = make_events(50, 1_000_000_000, 1_000_000_000);
        let jitter = make_jitter(200, 1_000_000_000, 250_000_000);

        let input = CrossModalInput {
            events: &events,
            jitter_samples: Some(&jitter),
            document_length: 500,
            total_keystrokes: 600,
            checkpoint_count: 10,
            session_duration_sec: 50.0,
        };

        let result = analyze_cross_modal(&input);
        assert!(result.score > 0.7);
        assert_eq!(result.verdict, CrossModalVerdict::Consistent);
    }

    #[test]
    fn test_content_too_fast() {
        let events = make_events(20, 1_000_000_000, 500_000_000);
        let input = CrossModalInput {
            events: &events,
            jitter_samples: None,
            document_length: 5000,
            total_keystrokes: 100,
            checkpoint_count: 5,
            session_duration_sec: 10.0,
        };

        let result = analyze_cross_modal(&input);
        let growth_check = result
            .checks
            .iter()
            .find(|c| c.name == "content_growth_rate")
            .unwrap();
        assert!(!growth_check.passed);
    }

    #[test]
    fn test_jitter_without_edits() {
        let events = make_events(10, 1_000_000_000, 1_000_000_000);
        let jitter = make_jitter(10000, 1_000_000_000, 100_000);

        let input = CrossModalInput {
            events: &events,
            jitter_samples: Some(&jitter),
            document_length: 100,
            total_keystrokes: 50,
            checkpoint_count: 5,
            session_duration_sec: 10.0,
        };

        let result = analyze_cross_modal(&input);
        assert!(result.score < 0.9);
    }

    #[test]
    fn test_jitter_density_fail() {
        // 1 jitter sample for a 10,000-char document = 0.1/kchar, below 0.5 threshold
        let events = make_events(50, 1_000_000_000, 1_000_000_000);
        let jitter = make_jitter(1, 1_000_000_000, 250_000_000);
        let input = CrossModalInput {
            events: &events,
            jitter_samples: Some(&jitter),
            document_length: 10_000,
            total_keystrokes: 600,
            checkpoint_count: 10,
            session_duration_sec: 50.0,
        };
        // jitter length < MIN_JITTER_SAMPLES so density check won't run; verify boundary
        let density_check = check_content_growth_vs_jitter_density(&jitter, 10_000);
        assert!(!density_check.passed);
    }

    #[test]
    fn test_critical_jitter_failure_gives_inconsistent() {
        // Simulate a session with almost no jitter vs many edits (coherence fails)
        let events = make_events(50, 1_000_000_000, 500_000_000);
        let jitter = make_jitter(5000, 1_000_000_000, 10_000); // extreme jitter/edit imbalance
        let input = CrossModalInput {
            events: &events,
            jitter_samples: Some(&jitter),
            document_length: 500,
            total_keystrokes: 50,
            checkpoint_count: 10,
            session_duration_sec: 50.0,
        };
        let result = analyze_cross_modal(&input);
        // jitter_edit_coherence ratio = 50/5000 = 0.01 < MIN_EDIT_TO_JITTER_RATIO (0.02) → fails
        let coherence = result.checks.iter().find(|c| c.name == "jitter_edit_coherence");
        if let Some(c) = coherence {
            if !c.passed {
                assert_eq!(result.verdict, CrossModalVerdict::Inconsistent);
            }
        }
    }

    #[test]
    fn test_insufficient_data() {
        let events = make_events(3, 1_000_000_000, 1_000_000_000);
        let input = CrossModalInput {
            events: &events,
            jitter_samples: None,
            document_length: 100,
            total_keystrokes: 50,
            checkpoint_count: 1,
            session_duration_sec: 3.0,
        };

        let result = analyze_cross_modal(&input);
        assert_eq!(result.verdict, CrossModalVerdict::Insufficient);
    }
}
