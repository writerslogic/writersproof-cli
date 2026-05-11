// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::load_events_for_path;
use crate::ffi::types::{catch_ffi_panic, try_ffi};
use crate::utils::finite_or;

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForensicBreakdown {
    pub success: bool,
    pub monotonic_append_ratio: f64,
    pub edit_entropy: f64,
    pub median_interval: f64,
    pub mean_iki_ms: f64,
    pub std_dev_iki_ms: f64,
    pub coefficient_of_variation: f64,
    pub burst_count: u32,
    pub pause_count: u32,
    pub mean_bps: f64,
    pub max_bps: f64,
    pub hurst_exponent: Option<f64>,
    pub assessment_score: f64,
    pub perplexity_score: f64,
    pub risk_level: String,
    pub protocol_verdict: String,
    pub anomaly_count: u32,
    pub anomalies: Vec<FfiAnomaly>,
    /// Writing mode: "cognitive", "transcriptive", "mixed", or "insufficient".
    pub writing_mode: String,
    /// Composite cognitive score (0.0 = transcriptive, 1.0 = cognitive).
    pub writing_mode_score: f64,
    /// Confidence in writing mode classification (0.0-1.0).
    pub writing_mode_confidence: f64,
    /// Number of burst->delete->burst revision cycles detected.
    pub revision_cycle_count: u32,
    /// Fraction of keystrokes that are backspace/delete.
    pub correction_ratio: f64,
    /// CV of typing speed within bursts.
    pub burst_speed_cv: f64,
    /// Pause depth distribution: [sentence_fraction, paragraph_fraction, deep_fraction].
    pub pause_depth_distribution: Vec<f64>,
    /// Joint signal consistency: 0.0 = consistent, >0.5 = possible spoofing.
    pub spoofing_indicator: f64,
    /// Sentence initiation delay ratio (cognitive: 8-30x, transcriptive: 2-4x).
    pub sentence_initiation_ratio: f64,
    /// Lexical retrieval delay correlation (cognitive: >0.25, transcriptive: ~0).
    pub lrd_correlation: f64,
    /// IKI distribution modality (cognitive: multi-modal >0.7, transcriptive: <0.3).
    pub iki_modality_score: f64,
    /// Deviation from personal writing baseline (0 = normal, >0.6 = anomalous).
    pub baseline_deviation: f64,
    /// Mean plausibility of dictation events (1.0 = fully plausible, <0.3 = likely forged).
    pub dictation_plausibility: f64,
    /// Fraction of content that was dictated (0.0 = all typed, 1.0 = all dictated).
    pub dictation_ratio: f64,
    /// Whether multiple speakers were detected in dictation segments.
    pub multi_speaker_detected: bool,
    /// Enhanced cognitive/transcriptive signal analysis (5 new dimensions).
    pub enhanced_signals: Option<FfiEnhancedSignals>,
    pub error_message: Option<String>,
}

/// Enhanced forensic signal metrics grouped by analysis dimension.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiEnhancedSignals {
    pub cognitive_load: Option<FfiCognitiveLoadSignals>,
    pub revision_topology: Option<FfiRevisionTopologySignals>,
    pub error_ecology: Option<FfiErrorEcologySignals>,
    pub likelihood_model: Option<FfiLikelihoodSignals>,
    pub composition_mode: Option<FfiCompositionModeSignals>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCognitiveLoadSignals {
    /// Composite score (0=transcriptive, 1=cognitive).
    pub score: f64,
    /// IKI-surprisal Spearman rho (cognitive: 0.3-0.6, transcriptive: ~0).
    pub iki_surprisal_rho: f64,
    /// Per-sentence velocity arc R² (cognitive: >0.3, transcriptive: <0.1).
    pub sentence_arc_r_squared: f64,
    /// Deep pauses at structural boundaries (cognitive: >0.6, transcriptive: <0.3).
    pub structural_pause_concentration: f64,
    /// Number of deep pauses analyzed.
    pub deep_pause_count: u32,
    /// Number of sentences analyzed.
    pub sentence_count: u32,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiRevisionTopologySignals {
    pub score: f64,
    /// DAG branching factor (cognitive: >2, transcriptive: ~1).
    pub branching_factor: f64,
    /// Mean region revisit depth (cognitive: 2-4, transcriptive: 0-1).
    pub revisit_depth: f64,
    /// Mean distance from edit position to frontier (cognitive: 0.3-0.6).
    pub frontier_distance: f64,
    /// Semantic revision ratio (substitution + restructuring + insertion).
    pub semantic_revision_ratio: f64,
    /// Total classified revision events.
    pub total_revisions: u32,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiErrorEcologySignals {
    pub score: f64,
    /// Rapid self-correction fraction (cognitive: >0.3).
    pub rapid_correction_pct: f64,
    /// Bulk correction fraction (transcriptive: >0.3).
    pub bulk_correction_pct: f64,
    /// False start fraction (cognitive: >0.15).
    pub false_start_pct: f64,
    /// Overall correction rate (corrections / total keystrokes).
    pub correction_rate: f64,
    /// Total correction events.
    pub total_corrections: u32,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiLikelihoodSignals {
    /// Session posterior P(cognitive).
    pub p_cognitive: f64,
    /// Mean per-window LLR.
    pub mean_llr: f64,
    /// LLR standard deviation (high = mixed session).
    pub llr_std_dev: f64,
    /// Fraction of windows classified as cognitive.
    pub cognitive_window_fraction: f64,
    /// Total windows analyzed.
    pub window_count: u32,
    /// Timestamped per-window cognitive probability timeline.
    /// Each point has a seconds-since-session-start and P(cognitive).
    pub timeline: Vec<FfiTimelinePoint>,
}

/// A single point on the cognitive probability timeline.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiTimelinePoint {
    /// Seconds since the start of the session.
    pub seconds_from_start: f64,
    /// Posterior P(cognitive) for this window.
    pub p_cognitive: f64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCompositionModeSignals {
    pub score: f64,
    /// Dominant mode: "pure_composition", "reference_assisted", "paste_domesticate",
    /// "paste_veneer", or "ai_mediated".
    pub dominant_mode: String,
    /// Number of AI-mediated cycles detected.
    pub ai_cycle_count: u32,
    /// Per-mode probability distribution.
    pub pure_composition_pct: f64,
    pub reference_assisted_pct: f64,
    pub paste_domesticate_pct: f64,
    pub paste_veneer_pct: f64,
    pub ai_mediated_pct: f64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiAnomaly {
    pub timestamp_epoch_ms: Option<i64>,
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
}

impl FfiForensicBreakdown {
    fn error(msg: String) -> Self {
        Self {
            success: false,
            monotonic_append_ratio: 0.0,
            edit_entropy: 0.0,
            median_interval: 0.0,
            mean_iki_ms: 0.0,
            std_dev_iki_ms: 0.0,
            coefficient_of_variation: 0.0,
            burst_count: 0,
            pause_count: 0,
            mean_bps: 0.0,
            max_bps: 0.0,
            hurst_exponent: None,
            assessment_score: 0.0,
            perplexity_score: 0.0,
            risk_level: "unknown".to_string(),
            protocol_verdict: "unknown".to_string(),
            anomaly_count: 0,
            anomalies: Vec::new(),
            writing_mode: "insufficient".to_string(),
            writing_mode_score: 0.0,
            writing_mode_confidence: 0.0,
            revision_cycle_count: 0,
            correction_ratio: 0.0,
            burst_speed_cv: 0.0,
            pause_depth_distribution: vec![0.0, 0.0, 0.0],
            spoofing_indicator: 0.0,
            sentence_initiation_ratio: 0.0,
            lrd_correlation: 0.0,
            iki_modality_score: 0.0,
            baseline_deviation: 0.0,
            dictation_plausibility: 0.0,
            dictation_ratio: 0.0,
            multi_speaker_detected: false,
            enhanced_signals: None,
            error_message: Some(msg),
        }
    }
}

crate::ffi::types::impl_ffi_err!(FfiForensicBreakdown);

/// Return a detailed forensic breakdown for a tracked file.
///
/// Runs both the authorship profile (anomaly detection) and the full forensic
/// metrics pipeline (cadence, velocity, behavioral fingerprint, etc.), returning
/// rich structured data suitable for native UI display.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_forensic_breakdown(path: String) -> FfiForensicBreakdown {
    catch_ffi_panic!(FfiForensicBreakdown::error("engine internal error".to_string()), {
    let (path, _store, events) = try_ffi!(load_events_for_path(&path), FfiForensicBreakdown);

    if events.is_empty() {
        return FfiForensicBreakdown::error("No events found for this file".to_string());
    }

    let profile = crate::forensics::ForensicEngine::evaluate_authorship(&path, &events);
    let (mut metrics, _regions) = crate::ffi::helpers::run_full_forensics(&events);

    // Enrich writing mode with cognitive layer from live session if available.
    if let Some(sentinel) = super::sentinel::get_sentinel() {
        for session in sentinel.sessions() {
            if session.path == path {
                if let Some(layer) = session.cognitive.analyze() {
                    if let Some(ref mut wm) = metrics.writing_mode {
                        wm.cognitive_layer = Some(layer);
                    }
                }
                break;
            }
        }
    }

    // Enrich with dictation scoring from live session if available.
    let mut dictation_plausibility = 0.0;
    let mut dictation_ratio = 0.0;
    let mut multi_speaker_detected = false;
    if let Some(sentinel) = super::sentinel::get_sentinel() {
        for session in sentinel.sessions() {
            if session.path == path && !session.dictation_events.is_empty() {
                let dict_words: u32 = session.dictation_events.iter().map(|e| e.word_count).sum();
                let typed_words = (session.cognitive.word_boundary_count() as u32).saturating_sub(dict_words);
                let segments = crate::forensics::dictation::cluster_speaker_segments(
                    &session.dictation_events,
                );
                let multi = segments.iter().any(|s| s.speaker_label > 0);
                let comp = crate::forensics::dictation::apply_dictation_adjustment(
                    metrics.assessment_score.get(),
                    &session.dictation_events,
                    typed_words,
                    multi,
                );
                dictation_plausibility = comp.dictated_score;
                dictation_ratio = comp.dictation_ratio;
                multi_speaker_detected = comp.multi_speaker_detected;
                break;
            }
        }
    }

    let protocol_verdict = metrics.map_to_protocol_verdict();

    let anomalies: Vec<FfiAnomaly> = profile
        .anomalies
        .iter()
        .map(|a| FfiAnomaly {
            timestamp_epoch_ms: a.timestamp.map(|t| t.timestamp_millis()),
            anomaly_type: a.anomaly_type.to_string(),
            description: a.description.clone(),
            severity: a.severity.to_string(),
        })
        .collect();

    let mean_iki_ms = finite_or(metrics.cadence.mean_iki_ns / 1_000_000.0, 0.0);
    let std_dev_iki_ms = finite_or(metrics.cadence.std_dev_iki_ns / 1_000_000.0, 0.0);
    let cv = finite_or(metrics.cadence.coefficient_of_variation, 0.0);

    FfiForensicBreakdown {
        success: true,
        monotonic_append_ratio: profile.metrics.monotonic_append_ratio.get(),
        edit_entropy: profile.metrics.edit_entropy,
        median_interval: profile.metrics.median_interval,
        mean_iki_ms,
        std_dev_iki_ms,
        coefficient_of_variation: cv,
        burst_count: u32::try_from(metrics.cadence.burst_count).unwrap_or(u32::MAX),
        pause_count: u32::try_from(metrics.cadence.pause_count).unwrap_or(u32::MAX),
        mean_bps: finite_or(metrics.velocity.mean_bps, 0.0),
        max_bps: finite_or(metrics.velocity.max_bps, 0.0),
        hurst_exponent: metrics.hurst_exponent.filter(|h| h.is_finite()),
        assessment_score: finite_or(metrics.assessment_score.get(), 0.0),
        perplexity_score: finite_or(metrics.perplexity_score, 0.0),
        risk_level: metrics.risk_level.to_string().to_lowercase(),
        protocol_verdict: format!("{:?}", protocol_verdict),
        anomaly_count: u32::try_from(profile.anomalies.len()).unwrap_or(u32::MAX),
        anomalies,
        writing_mode: metrics
            .writing_mode
            .as_ref()
            .map(|wm| wm.mode.to_string())
            .unwrap_or_else(|| "insufficient".to_string()),
        writing_mode_score: metrics
            .writing_mode
            .as_ref()
            .map(|wm| wm.cognitive_score)
            .unwrap_or(0.0),
        writing_mode_confidence: metrics
            .writing_mode
            .as_ref()
            .map(|wm| wm.confidence)
            .unwrap_or(0.0),
        revision_cycle_count: metrics
            .writing_mode
            .as_ref()
            .map(|wm| wm.revision_pattern.revision_cycle_count as u32)
            .unwrap_or(0),
        correction_ratio: metrics.cadence.correction_ratio.get(),
        burst_speed_cv: metrics.cadence.burst_speed_cv,
        pause_depth_distribution: metrics.cadence.pause_depth_distribution.to_vec(),
        spoofing_indicator: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| cl.spoofing_indicator)
            .unwrap_or(0.0),
        sentence_initiation_ratio: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| cl.sentence_initiation_ratio)
            .unwrap_or(0.0),
        lrd_correlation: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| cl.lrd_correlation)
            .unwrap_or(0.0),
        iki_modality_score: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| cl.iki_modality_score)
            .unwrap_or(0.0),
        baseline_deviation: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| cl.baseline_deviation)
            .unwrap_or(0.0),
        dictation_plausibility,
        dictation_ratio,
        multi_speaker_detected,
        enhanced_signals: build_enhanced_signals(&metrics, &path),
        error_message: None,
    }
    })
}

fn build_enhanced_signals(
    metrics: &crate::forensics::ForensicMetrics,
    path: &str,
) -> Option<FfiEnhancedSignals> {
    let has_any = metrics.cognitive_load.is_some()
        || metrics.revision_topology.is_some()
        || metrics.error_ecology.is_some()
        || metrics.likelihood_model.is_some()
        || metrics.composition_mode.is_some();
    if !has_any {
        return None;
    }

    let cognitive_load = metrics.cognitive_load.as_ref().map(|c| FfiCognitiveLoadSignals {
        score: c.composite_score,
        iki_surprisal_rho: c.iki_surprisal_rho,
        sentence_arc_r_squared: c.sentence_arc_r_squared,
        structural_pause_concentration: c.structural_pause_concentration,
        deep_pause_count: c.deep_pause_count as u32,
        sentence_count: c.sentence_count as u32,
    });

    let revision_topology =
        metrics
            .revision_topology
            .as_ref()
            .map(|r| FfiRevisionTopologySignals {
                score: r.composite_score,
                branching_factor: r.graph.mean_branching_factor,
                revisit_depth: r.graph.mean_revisit_depth,
                frontier_distance: r.graph.mean_frontier_distance,
                semantic_revision_ratio: r.revision_types.word_substitution_pct
                    + r.revision_types.clause_restructuring_pct
                    + r.revision_types.positional_insertion_pct,
                total_revisions: r.revision_types.total_revisions as u32,
            });

    let error_ecology = metrics.error_ecology.as_ref().map(|e| FfiErrorEcologySignals {
        score: e.composite_score,
        rapid_correction_pct: e.rapid_self_correction_pct,
        bulk_correction_pct: e.bulk_correction_pct,
        false_start_pct: e.false_start_pct,
        correction_rate: e.correction_rate,
        total_corrections: e.total_corrections as u32,
    });

    let likelihood_model = metrics.likelihood_model.as_ref().map(|lm| {
        FfiLikelihoodSignals {
            p_cognitive: lm.session_p_cognitive,
            mean_llr: lm.mean_window_llr,
            llr_std_dev: lm.llr_std_dev,
            cognitive_window_fraction: if lm.window_count > 0 {
                lm.cognitive_window_count as f64 / lm.window_count as f64
            } else {
                0.0
            },
            window_count: lm.window_count as u32,
            timeline: lm
                .window_timeline
                .iter()
                .map(|&(secs, p)| FfiTimelinePoint {
                    seconds_from_start: secs,
                    p_cognitive: p,
                })
                .collect(),
        }
    });

    // Populate composition mode from live sentinel session data.
    let composition_mode = metrics
        .composition_mode
        .as_ref()
        .map(build_composition_ffi)
        .or_else(|| {
            // Fall back to computing from sentinel if the pipeline didn't populate it.
            let sentinel = super::sentinel::get_sentinel()?;
            let sessions = sentinel.sessions();
            let session = sessions.iter().find(|s| s.path == path)?;
            let switches: Vec<_> = session.focus_switches.iter().cloned().collect();
            let pastes: Vec<_> = session
                .paste_context
                .iter()
                .cloned()
                .collect();
            let event_count = session.cognitive.keystroke_count();
            let cm = crate::forensics::composition_mode::analyze_composition_mode(
                &switches, &pastes, event_count,
            )?;
            Some(build_composition_ffi(&cm))
        });

    Some(FfiEnhancedSignals {
        cognitive_load,
        revision_topology,
        error_ecology,
        likelihood_model,
        composition_mode,
    })
}

fn build_composition_ffi(
    cm: &crate::forensics::composition_mode::CompositionModeMetrics,
) -> FfiCompositionModeSignals {
    FfiCompositionModeSignals {
        score: cm.composite_score,
        dominant_mode: cm
            .dominant_mode
            .map(|m| m.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        ai_cycle_count: cm.ai_cycle_count as u32,
        pure_composition_pct: cm.distribution.pure_composition,
        reference_assisted_pct: cm.distribution.reference_assisted,
        paste_domesticate_pct: cm.distribution.paste_domesticate,
        paste_veneer_pct: cm.distribution.paste_veneer,
        ai_mediated_pct: cm.distribution.ai_mediated,
    }
}

/// Lightweight live scores for dashboard polling.
///
/// Reads the last-computed metrics from the sentinel session cache
/// without re-running the forensics pipeline. O(1) cost, safe to call
/// at 1Hz from the UI refresh loop.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiLiveScores {
    pub success: bool,
    /// Writing mode: "cognitive", "transcriptive", "mixed", "insufficient".
    pub writing_mode: String,
    /// Composite cognitive score (0.0-1.0).
    pub cognitive_score: f64,
    /// Assessment score (0.0-1.0, higher = more human-like).
    pub assessment_score: f64,
    /// Risk level: "low", "medium", "high", "insufficient data".
    pub risk_level: String,
    /// Total keystrokes in the current session.
    pub keystroke_count: u32,
    /// Session duration in seconds.
    pub session_duration_sec: f64,
    /// Real-time cadence score (0.0-1.0).
    pub cadence_score: f64,
    /// Current composition mode (if available).
    pub composition_mode: String,
    pub error_message: Option<String>,
}

/// Fast live score polling for the dashboard.
///
/// Returns cached metrics from the sentinel session for the given path.
/// Does NOT re-run the forensics pipeline. Call `ffi_get_forensic_breakdown`
/// for full analysis.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_live_scores(path: String) -> FfiLiveScores {
    let sentinel = match super::sentinel::get_sentinel() {
        Some(s) => s,
        None => {
            return FfiLiveScores {
                success: false,
                writing_mode: "insufficient".into(),
                cognitive_score: 0.0,
                assessment_score: 0.0,
                risk_level: "insufficient data".into(),
                keystroke_count: 0,
                session_duration_sec: 0.0,
                cadence_score: 0.0,
                composition_mode: "unknown".into(),
                error_message: Some("Sentinel not running".into()),
            };
        }
    };

    let sessions = sentinel.sessions();
    let session = match sessions.iter().find(|s| s.path == path) {
        Some(s) => s,
        None => {
            return FfiLiveScores {
                success: false,
                writing_mode: "insufficient".into(),
                cognitive_score: 0.0,
                assessment_score: 0.0,
                risk_level: "insufficient data".into(),
                keystroke_count: 0,
                session_duration_sec: 0.0,
                cadence_score: 0.0,
                composition_mode: "unknown".into(),
                error_message: Some("No active session for this path".into()),
            };
        }
    };

    let keystroke_count = session.cognitive.keystroke_count() as u32;
    let duration = session
        .start_time
        .elapsed()
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    // Cadence score from live jitter samples.
    let cadence_score = crate::forensics::scoring::cadence_score_from_samples(
        &session.jitter_samples,
    );

    // Composition mode from cached focus/paste data.
    let switches: Vec<_> = session.focus_switches.iter().cloned().collect();
    let pastes: Vec<_> = session.paste_context.iter().cloned().collect();
    let comp_mode = crate::forensics::composition_mode::analyze_composition_mode(
        &switches,
        &pastes,
        keystroke_count as usize,
    );

    let (writing_mode, cognitive_score) = if keystroke_count < 20 {
        ("insufficient".to_string(), 0.0)
    } else if cadence_score > 0.7 {
        ("cognitive".to_string(), cadence_score)
    } else if cadence_score < 0.3 {
        ("transcriptive".to_string(), cadence_score)
    } else {
        ("mixed".to_string(), cadence_score)
    };

    let risk_level = if cadence_score >= 0.7 {
        "low"
    } else if cadence_score >= 0.4 {
        "medium"
    } else if keystroke_count < 10 {
        "insufficient data"
    } else {
        "high"
    };

    FfiLiveScores {
        success: true,
        writing_mode,
        cognitive_score,
        assessment_score: cadence_score,
        risk_level: risk_level.to_string(),
        keystroke_count,
        session_duration_sec: duration,
        cadence_score,
        composition_mode: comp_mode
            .and_then(|c| c.dominant_mode)
            .map(|m| m.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        error_message: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_scores_no_sentinel_returns_error() {
        // In test context, sentinel is never initialized.
        let result = ffi_get_live_scores("/tmp/nonexistent.txt".to_string());
        assert!(!result.success);
        assert_eq!(result.writing_mode, "insufficient");
        assert_eq!(result.risk_level, "insufficient data");
        assert_eq!(result.keystroke_count, 0);
        assert!(result.error_message.is_some());
        assert!(
            result.error_message.as_ref().unwrap().contains("Sentinel"),
            "Error should mention sentinel: {:?}",
            result.error_message,
        );
    }

    #[test]
    fn live_scores_default_numeric_fields_are_zero() {
        let result = ffi_get_live_scores("/tmp/no_session.txt".to_string());
        assert!(!result.success);
        assert_eq!(result.cognitive_score, 0.0);
        assert_eq!(result.assessment_score, 0.0);
        assert_eq!(result.session_duration_sec, 0.0);
        assert_eq!(result.cadence_score, 0.0);
        assert_eq!(result.composition_mode, "unknown");
    }
}
