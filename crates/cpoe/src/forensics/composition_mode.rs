// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Composition Mode State Machine.
//!
//! Classifies writing sessions into five composition modes based on
//! event sequences (focus switches, paste events, edit density, timing):
//!
//! - **PureComposition**: Sustained in-editor focus, burst-pause-revise, no paste.
//! - **ReferenceAssisted**: Short focus-away (<10s), return, type without paste.
//! - **PasteDomesticate**: Paste → significant editing (>=20 keystrokes after paste).
//! - **PasteVeneer**: Paste → minimal editing (<=5 keystrokes after paste).
//! - **AiMediated**: Repeated (focus-to-AI 15-120s → return → paste → light edit) cycles.

use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::sentinel::types::PasteSource;
use crate::sentinel::types::{FocusSwitchRecord, PasteContentKind, PasteContext};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum events for composition mode analysis.
const MIN_EVENTS: usize = 10;

/// Maximum away duration for reference-checking (10 seconds).
const REFERENCE_MAX_AWAY_SEC: f64 = 10.0;

/// Minimum away duration for AI-mediated cycle (15 seconds).
const AI_MIN_AWAY_SEC: f64 = 15.0;

/// Maximum away duration for AI-mediated cycle (120 seconds).
const AI_MAX_AWAY_SEC: f64 = 120.0;

/// Minimum AI-mediated cycles to flag the pattern.
const AI_CYCLE_MIN_COUNT: usize = 2;

/// Window (nanoseconds) after regaining focus in which a paste counts as AI-mediated.
const AI_PASTE_WINDOW_NS: i64 = 30_000_000_000; // 30 seconds

/// Composite score weight for pure composition mode.
const SCORE_WEIGHT_PURE: f64 = 1.0;
/// Composite score weight for reference-assisted mode.
const SCORE_WEIGHT_REFERENCE: f64 = 0.8;
/// Composite score weight for paste-domesticate mode.
const SCORE_WEIGHT_DOMESTICATE: f64 = 0.5;
/// Composite score weight for paste-veneer mode.
const SCORE_WEIGHT_VENEER: f64 = 0.1;
/// Composite score weight for AI-mediated mode.
const SCORE_WEIGHT_AI: f64 = 0.0;

const PENALTY_STRUCTURED: f64 = 0.15;
const PENALTY_MEDIA: f64 = 0.20;
const PENALTY_MIXED: f64 = 0.30;

use super::constants::{AI_APP_PATTERNS, BROWSER_BUNDLE_IDS};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The five composition modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompositionMode {
    /// Original composition: sustained focus, no paste.
    PureComposition,
    /// Reference-checking: short focus-away, return, type without paste.
    ReferenceAssisted,
    /// Paste with significant editing (>=20 keystrokes after paste).
    PasteDomesticate,
    /// Paste with minimal editing (<=5 keystrokes after paste).
    PasteVeneer,
    /// AI-mediated: repeated focus-to-AI → return → paste cycles.
    AiMediated,
}

impl std::fmt::Display for CompositionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompositionMode::PureComposition => write!(f, "pure_composition"),
            CompositionMode::ReferenceAssisted => write!(f, "reference_assisted"),
            CompositionMode::PasteDomesticate => write!(f, "paste_domesticate"),
            CompositionMode::PasteVeneer => write!(f, "paste_veneer"),
            CompositionMode::AiMediated => write!(f, "ai_mediated"),
        }
    }
}

/// Per-mode probability from the state machine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompositionModeDistribution {
    /// Fraction of session time in pure composition.
    pub pure_composition: f64,
    /// Fraction in reference-assisted mode.
    pub reference_assisted: f64,
    /// Fraction in paste-and-domesticate mode.
    pub paste_domesticate: f64,
    /// Fraction in paste-and-veneer mode.
    pub paste_veneer: f64,
    /// Fraction in AI-mediated mode.
    pub ai_mediated: f64,
}

/// Breakdown of paste events by content kind.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PasteContentBreakdown {
    pub prose_count: usize,
    pub structured_data_count: usize,
    pub media_count: usize,
    pub formatting_only_count: usize,
    pub mixed_count: usize,
    pub total_chars_pasted: usize,
}

/// Complete composition mode analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompositionModeMetrics {
    /// Dominant mode for this session.
    pub dominant_mode: Option<CompositionMode>,
    /// Probability distribution over modes.
    pub distribution: CompositionModeDistribution,
    /// Number of AI-mediated cycles detected.
    pub ai_cycle_count: usize,
    /// Number of paste events analyzed.
    pub paste_event_count: usize,
    /// Number of focus switches analyzed.
    pub focus_switch_count: usize,
    /// Composite score: 0.0 = AI-mediated/paste-veneer, 1.0 = pure composition.
    pub composite_score: f64,
    /// Breakdown of paste events by content kind.
    pub paste_content_breakdown: PasteContentBreakdown,
}

// ---------------------------------------------------------------------------
// Classification logic
// ---------------------------------------------------------------------------

/// Classify a focus switch event.
fn classify_focus_switch(switch: &FocusSwitchRecord) -> FocusSwitchClass {
    // If the user never returned, treat as extended away (not a quick reference check).
    let away_sec = match switch
        .regained_at
        .and_then(|r| r.duration_since(switch.lost_at).ok())
        .map(|d| d.as_secs_f64())
    {
        Some(s) => s,
        None => return FocusSwitchClass::ExtendedAway,
    };

    let bid_lower = switch.target_bundle_id.to_lowercase();
    let app_lower = switch.target_app.to_lowercase();

    let is_ai = AI_APP_PATTERNS
        .iter()
        .any(|pat| bid_lower.contains(pat) || app_lower.contains(pat));

    let is_browser = BROWSER_BUNDLE_IDS
        .iter()
        .any(|b| bid_lower.eq_ignore_ascii_case(b));

    if is_ai && (AI_MIN_AWAY_SEC..=AI_MAX_AWAY_SEC).contains(&away_sec) {
        FocusSwitchClass::AiInteraction
    } else if (is_browser || is_ai) && away_sec >= AI_MIN_AWAY_SEC {
        FocusSwitchClass::PossibleAiInteraction
    } else if away_sec <= REFERENCE_MAX_AWAY_SEC {
        FocusSwitchClass::ReferenceCheck
    } else {
        FocusSwitchClass::ExtendedAway
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusSwitchClass {
    ReferenceCheck,
    AiInteraction,
    PossibleAiInteraction,
    ExtendedAway,
}

/// Returns `(PasteClass, penalty)` where penalty 0.0–1.0 is how much this
/// paste contributes to its penalty bucket (prose=1.0, tables/images reduced).
fn classify_paste(paste: &PasteContext) -> (PasteClass, f64) {
    if paste.content_kind == PasteContentKind::FormattingOnly {
        return (PasteClass::Domesticated, 0.0);
    }

    let domestication_threshold = if paste.paste_char_count > 0 {
        (paste.paste_char_count / 50).clamp(20, 200)
    } else {
        20
    };
    let class = if paste.keystroke_count_after_paste >= domestication_threshold {
        PasteClass::Domesticated
    } else if paste.keystroke_count_after_paste <= 5 {
        PasteClass::Veneer
    } else {
        PasteClass::Moderate
    };

    let penalty = match paste.content_kind {
        PasteContentKind::Prose => 1.0,
        PasteContentKind::StructuredData => PENALTY_STRUCTURED,
        PasteContentKind::Media => PENALTY_MEDIA,
        PasteContentKind::Mixed => PENALTY_MIXED,
        PasteContentKind::FormattingOnly => 0.0, // handled above
    };

    (class, penalty)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasteClass {
    Domesticated,
    Moderate,
    Veneer,
}

/// Detect AI-mediated cycles: focus-to-AI → return → paste in sequence.
///
/// Returns `(cycle_count, consumed_paste)` where `consumed_paste[i]` is true
/// if paste `i` was matched to a cycle and should not be double-counted.
fn count_ai_cycles(
    focus_switches: &[FocusSwitchRecord],
    paste_contexts: &[PasteContext],
) -> (usize, Vec<bool>) {
    let mut used_paste = vec![false; paste_contexts.len()];

    if focus_switches.is_empty() || paste_contexts.is_empty() {
        return (0, used_paste);
    }

    let mut cycles = 0usize;

    for switch in focus_switches {
        let class = classify_focus_switch(switch);
        if class != FocusSwitchClass::AiInteraction
            && class != FocusSwitchClass::PossibleAiInteraction
        {
            continue;
        }

        // Check if a paste occurred shortly after returning.
        let regained = match switch.regained_at {
            Some(r) => r,
            None => continue,
        };

        let regained_ns = match regained.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => match i64::try_from(d.as_nanos()) {
                Ok(ns) => ns,
                Err(_) => continue, // Overflow; timestamp too far in the future.
            },
            Err(_) => continue, // Pre-epoch timestamp; skip.
        };

        // Look for an unconsumed paste within 30s of regaining focus.
        let matched = paste_contexts.iter().enumerate().find(|(i, p)| {
            if used_paste[*i] {
                return false;
            }
            let delta_ns = p.paste_time.saturating_sub(regained_ns);
            (0..AI_PASTE_WINDOW_NS).contains(&delta_ns)
        });

        if let Some((i, _)) = matched {
            used_paste[i] = true;
            cycles += 1;
        }
    }

    (cycles, used_paste)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Analyze composition mode from focus switches and paste events.
///
/// `total_events` is the total number of edit events in the session.
pub fn analyze_composition_mode(
    focus_switches: &[FocusSwitchRecord],
    paste_contexts: &[PasteContext],
    total_events: usize,
) -> Option<CompositionModeMetrics> {
    if total_events < MIN_EVENTS {
        return None;
    }

    let (ai_cycles, ai_consumed_paste) = count_ai_cycles(focus_switches, paste_contexts);

    // Classify each focus switch.
    let mut reference_count = 0usize;

    for switch in focus_switches {
        if classify_focus_switch(switch) == FocusSwitchClass::ReferenceCheck {
            reference_count += 1;
        }
    }

    // Classify each paste event, skipping those already consumed by AI cycles.
    let mut domesticated_count = 0f64;
    let mut veneer_count = 0f64;
    let mut breakdown = PasteContentBreakdown::default();

    for (i, paste) in paste_contexts.iter().enumerate() {
        match paste.content_kind {
            PasteContentKind::Prose => breakdown.prose_count += 1,
            PasteContentKind::StructuredData => breakdown.structured_data_count += 1,
            PasteContentKind::Media => breakdown.media_count += 1,
            PasteContentKind::FormattingOnly => breakdown.formatting_only_count += 1,
            PasteContentKind::Mixed => breakdown.mixed_count += 1,
        }
        breakdown.total_chars_pasted += paste.paste_char_count;

        if ai_consumed_paste.get(i).copied().unwrap_or(false) {
            continue;
        }
        let (class, penalty) = classify_paste(paste);
        match class {
            PasteClass::Domesticated => domesticated_count += penalty,
            PasteClass::Veneer => veneer_count += penalty,
            PasteClass::Moderate => {}
        }
    }

    // Compute mode distribution.
    let total_signals = (focus_switches.len() + paste_contexts.len()).max(1) as f64;

    // Segments of behavior assigned to each mode.
    let ai_mediated_weight = if ai_cycles >= AI_CYCLE_MIN_COUNT {
        (ai_cycles as f64 * 2.0) / total_signals // Each cycle covers ~2 events.
    } else {
        0.0
    };
    let paste_veneer_weight = veneer_count / total_signals;
    let paste_domesticate_weight = domesticated_count / total_signals;
    let reference_weight = reference_count as f64 / total_signals;

    // Pure composition is what's left.
    let non_pure =
        ai_mediated_weight + paste_veneer_weight + paste_domesticate_weight + reference_weight;
    let pure_weight = (1.0 - non_pure).max(0.0);

    // Normalize to sum to 1.0.
    let total_weight = pure_weight
        + reference_weight
        + paste_domesticate_weight
        + paste_veneer_weight
        + ai_mediated_weight;

    let distribution = if total_weight.is_finite() && total_weight > 0.0 {
        CompositionModeDistribution {
            pure_composition: (pure_weight / total_weight).clamp(0.0, 1.0),
            reference_assisted: (reference_weight / total_weight).clamp(0.0, 1.0),
            paste_domesticate: (paste_domesticate_weight / total_weight).clamp(0.0, 1.0),
            paste_veneer: (paste_veneer_weight / total_weight).clamp(0.0, 1.0),
            ai_mediated: (ai_mediated_weight / total_weight).clamp(0.0, 1.0),
        }
    } else {
        CompositionModeDistribution {
            pure_composition: 1.0,
            ..Default::default()
        }
    };

    // Dominant mode.
    let modes = [
        (
            distribution.pure_composition,
            CompositionMode::PureComposition,
        ),
        (
            distribution.reference_assisted,
            CompositionMode::ReferenceAssisted,
        ),
        (
            distribution.paste_domesticate,
            CompositionMode::PasteDomesticate,
        ),
        (distribution.paste_veneer, CompositionMode::PasteVeneer),
        (distribution.ai_mediated, CompositionMode::AiMediated),
    ];
    let dominant_mode = modes
        .iter()
        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
        .map(|&(_, mode)| mode);

    // Composite score: 1.0 for pure composition, 0.0 for AI-mediated/veneer.
    let composite_score = (distribution.pure_composition * SCORE_WEIGHT_PURE
        + distribution.reference_assisted * SCORE_WEIGHT_REFERENCE
        + distribution.paste_domesticate * SCORE_WEIGHT_DOMESTICATE
        + distribution.paste_veneer * SCORE_WEIGHT_VENEER
        + distribution.ai_mediated * SCORE_WEIGHT_AI)
        .clamp(0.0, 1.0);

    Some(CompositionModeMetrics {
        dominant_mode,
        distribution,
        ai_cycle_count: ai_cycles,
        paste_event_count: paste_contexts.len(),
        focus_switch_count: focus_switches.len(),
        composite_score,
        paste_content_breakdown: breakdown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn make_focus_switch(away_sec: f64, bundle_id: &str, app_name: &str) -> FocusSwitchRecord {
        let lost_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let regained_at = Some(lost_at + Duration::from_secs_f64(away_sec));
        FocusSwitchRecord {
            lost_at,
            regained_at,
            target_app: app_name.to_string(),
            target_bundle_id: bundle_id.to_string(),
        }
    }

    fn make_paste(keystroke_count: usize, source: PasteSource) -> PasteContext {
        make_paste_with_kind(keystroke_count, source, PasteContentKind::Prose)
    }

    fn make_paste_with_kind(
        keystroke_count: usize,
        source: PasteSource,
        content_kind: PasteContentKind,
    ) -> PasteContext {
        PasteContext {
            paste_time: 1_000_000_000_000, // 1000s in ns
            context_window_end: 1_060_000_000_000,
            keystroke_count_after_paste: keystroke_count,
            source,
            content_kind,
            paste_char_count: 0,
        }
    }

    #[test]
    fn test_pure_composition() {
        let result = analyze_composition_mode(&[], &[], 50).unwrap();
        assert_eq!(result.dominant_mode, Some(CompositionMode::PureComposition));
        assert!((result.distribution.pure_composition - 1.0).abs() < f64::EPSILON);
        assert!((result.composite_score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_reference_assisted() {
        let switches = vec![
            make_focus_switch(3.0, "com.apple.safari", "Safari"),
            make_focus_switch(5.0, "com.apple.safari", "Safari"),
            make_focus_switch(8.0, "com.google.chrome", "Chrome"),
        ];
        let result = analyze_composition_mode(&switches, &[], 50).unwrap();
        assert!(result.distribution.reference_assisted > 0.0);
    }

    #[test]
    fn test_ai_mediated_detection() {
        let switches = vec![
            make_focus_switch(30.0, "com.openai.chatgpt", "ChatGPT"),
            make_focus_switch(45.0, "com.openai.chatgpt", "ChatGPT"),
            make_focus_switch(20.0, "com.openai.chatgpt", "ChatGPT"),
        ];
        // Paste events shortly after each return.
        let pastes = vec![
            PasteContext {
                paste_time: (SystemTime::UNIX_EPOCH + Duration::from_secs(1030))
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64
                    + 5_000_000_000, // 5s after regained
                context_window_end: 0,
                keystroke_count_after_paste: 3,
                source: PasteSource::External,
                content_kind: PasteContentKind::Prose,
                paste_char_count: 0,
            },
            PasteContext {
                paste_time: (SystemTime::UNIX_EPOCH + Duration::from_secs(1045))
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64
                    + 5_000_000_000,
                context_window_end: 0,
                keystroke_count_after_paste: 2,
                source: PasteSource::External,
                content_kind: PasteContentKind::Prose,
                paste_char_count: 0,
            },
        ];

        let result = analyze_composition_mode(&switches, &pastes, 50).unwrap();
        assert!(result.ai_cycle_count >= 1, "should detect AI cycles");
    }

    #[test]
    fn test_paste_veneer() {
        let pastes = vec![
            make_paste(2, PasteSource::External),
            make_paste(1, PasteSource::External),
        ];
        let result = analyze_composition_mode(&[], &pastes, 50).unwrap();
        assert!(result.distribution.paste_veneer > 0.0);
        assert!(result.composite_score < 0.5);
    }

    #[test]
    fn test_paste_domesticate() {
        let pastes = vec![
            make_paste(30, PasteSource::External),
            make_paste(25, PasteSource::OtherDocument),
        ];
        let result = analyze_composition_mode(&[], &pastes, 50).unwrap();
        assert!(result.distribution.paste_domesticate > 0.0);
    }

    #[test]
    fn test_insufficient_events() {
        assert!(analyze_composition_mode(&[], &[], 5).is_none());
    }

    #[test]
    fn test_unresolved_focus_not_reference() {
        // A focus switch with no regained_at should NOT count as reference-assisted.
        let switch = FocusSwitchRecord {
            lost_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1000),
            regained_at: None,
            target_app: "Safari".to_string(),
            target_bundle_id: "com.apple.safari".to_string(),
        };
        let result = analyze_composition_mode(&[switch], &[], 50).unwrap();
        assert!(
            result.distribution.reference_assisted == 0.0,
            "unresolved switch must not count as reference"
        );
    }

    #[test]
    fn test_paste_dedup_across_cycles() {
        // Two AI focus switches close together, one paste: should count 1 cycle, not 2.
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let switches = vec![
            FocusSwitchRecord {
                lost_at: base,
                regained_at: Some(base + Duration::from_secs(30)),
                target_app: "ChatGPT".to_string(),
                target_bundle_id: "com.openai.chatgpt".to_string(),
            },
            FocusSwitchRecord {
                lost_at: base + Duration::from_secs(35),
                regained_at: Some(base + Duration::from_secs(65)),
                target_app: "ChatGPT".to_string(),
                target_bundle_id: "com.openai.chatgpt".to_string(),
            },
        ];
        let paste_time = (base + Duration::from_secs(32))
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i64;
        let pastes = vec![PasteContext {
            paste_time,
            context_window_end: 0,
            keystroke_count_after_paste: 3,
            source: PasteSource::External,
            content_kind: PasteContentKind::Prose,
            paste_char_count: 0,
        }];
        let (cycles, consumed) = count_ai_cycles(&switches, &pastes);
        assert_eq!(cycles, 1, "one paste should match at most one cycle");
        assert!(consumed[0], "the matched paste should be marked consumed");
    }

    #[test]
    fn test_ai_paste_not_double_counted_as_veneer() {
        // Pastes consumed by AI cycles should not also count as veneer.
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let switches: Vec<_> = (0..3)
            .map(|i| {
                let offset = i as u64 * 100;
                FocusSwitchRecord {
                    lost_at: base + Duration::from_secs(offset),
                    regained_at: Some(base + Duration::from_secs(offset + 30)),
                    target_app: "ChatGPT".to_string(),
                    target_bundle_id: "com.openai.chatgpt".to_string(),
                }
            })
            .collect();
        // One veneer paste per cycle, timed to match each switch's return.
        let pastes: Vec<_> = (0..3)
            .map(|i| {
                let regained = base + Duration::from_secs(i as u64 * 100 + 30);
                let ns = regained
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64
                    + 2_000_000_000;
                PasteContext {
                    paste_time: ns,
                    context_window_end: 0,
                    keystroke_count_after_paste: 1, // veneer-level
                    source: PasteSource::External,
                    content_kind: PasteContentKind::Prose,
                    paste_char_count: 0,
                }
            })
            .collect();
        let result = analyze_composition_mode(&switches, &pastes, 50).unwrap();
        assert_eq!(
            result.distribution.paste_veneer, 0.0,
            "AI-consumed pastes must not also count as veneer"
        );
        assert!(result.ai_cycle_count >= 2);
    }

    #[test]
    fn test_composite_score_range() {
        let switches = vec![make_focus_switch(5.0, "com.apple.safari", "Safari")];
        let pastes = vec![make_paste(10, PasteSource::External)];
        let result = analyze_composition_mode(&switches, &pastes, 50).unwrap();
        assert!(result.composite_score >= 0.0 && result.composite_score <= 1.0);
    }

    #[test]
    fn test_structured_data_paste_higher_score_than_prose() {
        let prose_pastes = vec![
            make_paste(2, PasteSource::External),
            make_paste(1, PasteSource::External),
        ];
        let table_pastes = vec![
            make_paste_with_kind(2, PasteSource::External, PasteContentKind::StructuredData),
            make_paste_with_kind(1, PasteSource::External, PasteContentKind::StructuredData),
        ];
        let prose_result = analyze_composition_mode(&[], &prose_pastes, 50).unwrap();
        let table_result = analyze_composition_mode(&[], &table_pastes, 50).unwrap();
        assert!(
            table_result.composite_score > prose_result.composite_score,
            "table paste score ({}) must exceed prose paste score ({})",
            table_result.composite_score,
            prose_result.composite_score,
        );
    }

    #[test]
    fn test_media_paste_higher_score_than_prose() {
        let prose = vec![make_paste(2, PasteSource::External)];
        let media = vec![make_paste_with_kind(
            2,
            PasteSource::External,
            PasteContentKind::Media,
        )];
        let prose_result = analyze_composition_mode(&[], &prose, 50).unwrap();
        let media_result = analyze_composition_mode(&[], &media, 50).unwrap();
        assert!(
            media_result.composite_score > prose_result.composite_score,
            "media paste score ({}) must exceed prose paste score ({})",
            media_result.composite_score,
            prose_result.composite_score,
        );
    }

    #[test]
    fn test_formatting_only_no_penalty() {
        let pastes = vec![make_paste_with_kind(
            0,
            PasteSource::External,
            PasteContentKind::FormattingOnly,
        )];
        let result = analyze_composition_mode(&[], &pastes, 50).unwrap();
        // FormattingOnly paste with 0 keystrokes should still yield near-perfect score
        // because penalty=0.0 means it doesn't contribute to veneer/domesticate buckets.
        assert!(
            result.composite_score > 0.9,
            "formatting-only paste should not penalize: {}",
            result.composite_score,
        );
    }

    #[test]
    fn test_ai_mediated_overrides_content_kind() {
        // Even if the paste is structured data, AI-mediated detection should still fire.
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let switches: Vec<_> = (0..3)
            .map(|i| {
                let offset = i as u64 * 100;
                FocusSwitchRecord {
                    lost_at: base + Duration::from_secs(offset),
                    regained_at: Some(base + Duration::from_secs(offset + 30)),
                    target_app: "ChatGPT".to_string(),
                    target_bundle_id: "com.openai.chatgpt".to_string(),
                }
            })
            .collect();
        let pastes: Vec<_> = (0..3)
            .map(|i| {
                let regained = base + Duration::from_secs(i as u64 * 100 + 30);
                let ns = regained
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64
                    + 2_000_000_000;
                PasteContext {
                    paste_time: ns,
                    context_window_end: 0,
                    keystroke_count_after_paste: 1,
                    source: PasteSource::External,
                    content_kind: PasteContentKind::StructuredData,
                    paste_char_count: 0,
                }
            })
            .collect();
        let result = analyze_composition_mode(&switches, &pastes, 50).unwrap();
        assert!(
            result.ai_cycle_count >= 2,
            "AI cycles must still be detected for structured data pastes"
        );
    }

    #[test]
    fn test_paste_content_breakdown_tracked() {
        let pastes = vec![
            make_paste_with_kind(5, PasteSource::External, PasteContentKind::Prose),
            make_paste_with_kind(5, PasteSource::External, PasteContentKind::StructuredData),
            make_paste_with_kind(5, PasteSource::External, PasteContentKind::Media),
            make_paste_with_kind(5, PasteSource::External, PasteContentKind::FormattingOnly),
            make_paste_with_kind(5, PasteSource::External, PasteContentKind::Mixed),
        ];
        let result = analyze_composition_mode(&[], &pastes, 50).unwrap();
        let b = &result.paste_content_breakdown;
        assert_eq!(b.prose_count, 1);
        assert_eq!(b.structured_data_count, 1);
        assert_eq!(b.media_count, 1);
        assert_eq!(b.formatting_only_count, 1);
        assert_eq!(b.mixed_count, 1);
    }
}
