// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Dimension scoring builders for WAR reports.
//!
//! Each dimension evaluates one axis of authorship evidence (temporal, edit,
//! continuity, coherence, behavioral, velocity) and optionally enhanced signal
//! dimensions when advanced analysis modules have produced results.

use crate::report::{
    compute_likelihood_ratio, DimensionDetail, DimensionScore, ProcessEvidence, ReportSession,
};
use crate::utils::finite_or;

use super::report::EventStats;

// ---------------------------------------------------------------------------
// Dimension scoring constants
// ---------------------------------------------------------------------------

// Temporal dimension
const TEMPORAL_BASE_FULL: u32 = 75;
const TEMPORAL_BASE_DENSE: u32 = 60;
const TEMPORAL_BASE_VDF_ONLY: u32 = 45;
const TEMPORAL_BASE_NONE: u32 = 30;
const TEMPORAL_HIGH_ITERATIONS: u64 = 1000;
const TEMPORAL_BONUS_HIGH: u32 = 10;
const TEMPORAL_BONUS_LOW: u32 = 5;
const TEMPORAL_CONFIDENCE_VDF: f64 = 0.90;
const TEMPORAL_CONFIDENCE_NO_VDF: f64 = 0.50;
const TEMPORAL_MIN_EVENTS: usize = 3;
const TEMPORAL_MIN_DURATION: f64 = 1.0;

// Edit dimension
const EDIT_TOPOLOGY_WEIGHT: f64 = 0.6;
const EDIT_REVISION_WEIGHT: f64 = 0.4;
const EDIT_RI_OPTIMAL_LOW: f64 = 0.05;
const EDIT_RI_OPTIMAL_HIGH: f64 = 0.65;
const EDIT_RI_SCORE_OPTIMAL: f64 = 0.8;
const EDIT_RI_SCORE_PRESENT: f64 = 0.5;
const EDIT_RI_SCORE_ABSENT: f64 = 0.3;
const EDIT_CONFIDENCE_SUFFICIENT: f64 = 0.80;
const EDIT_CONFIDENCE_SPARSE: f64 = 0.50;
const EDIT_MIN_EVENTS: usize = 5;

// Continuity dimension
const CONTINUITY_BASE_MULTI: u32 = 80;
const CONTINUITY_BASE_TWO: u32 = 70;
const CONTINUITY_BASE_SINGLE: u32 = 55;
const CONTINUITY_DURATION_BONUS_THRESHOLD: f64 = 5.0;
const CONTINUITY_DURATION_BONUS: u32 = 10;
const CONTINUITY_CONFIDENCE_MULTI: f64 = 0.85;
const CONTINUITY_CONFIDENCE_SINGLE: f64 = 0.60;
const CONTINUITY_MIN_MULTI_SESSIONS: usize = 3;

// Coherence dimension
const COHERENCE_PASTE_THRESHOLD_PCT: f64 = 30.0;
const COHERENCE_MIN_KEYSTROKES: u64 = 10;
const COHERENCE_BASE_CLEAN: u32 = 75;
const COHERENCE_BASE_PASTY: u32 = 50;
const COHERENCE_CR_OPTIMAL_LOW: f64 = 0.05;
const COHERENCE_CR_OPTIMAL_HIGH: f64 = 0.4;
const COHERENCE_CR_BONUS: u32 = 15;
const COHERENCE_CONFIDENCE: f64 = 0.75;

// Behavioral dimension
const BEHAVIORAL_CV_OPTIMAL_LOW: f64 = 0.2;
const BEHAVIORAL_CV_OPTIMAL_HIGH: f64 = 1.8;
const BEHAVIORAL_CV_MARGINAL: f64 = 0.1;
const BEHAVIORAL_CV_SCORE_OPTIMAL: f64 = 0.85;
const BEHAVIORAL_CV_SCORE_MARGINAL: f64 = 0.55;
const BEHAVIORAL_CV_SCORE_POOR: f64 = 0.25;
const BEHAVIORAL_CV_WEIGHT: f64 = 0.6;
const BEHAVIORAL_BIO_WEIGHT: f64 = 0.4;
const BEHAVIORAL_CONFIDENCE_DATA: f64 = 0.85;
const BEHAVIORAL_CONFIDENCE_NO_DATA: f64 = 0.55;

// Velocity dimension
const VELOCITY_HUMAN_LOW_BPS: f64 = 0.5;
const VELOCITY_HUMAN_HIGH_BPS: f64 = 20.0;
const VELOCITY_PLAUSIBLE_MAX_BPS: f64 = 50.0;
const VELOCITY_SCORE_OPTIMAL: f64 = 0.85;
const VELOCITY_SCORE_PLAUSIBLE: f64 = 0.60;
const VELOCITY_SCORE_NONE: f64 = 0.40;
const VELOCITY_SCORE_ANOMALOUS: f64 = 0.20;
const VELOCITY_CONFIDENCE_DATA: f64 = 0.80;
const VELOCITY_CONFIDENCE_SPARSE: f64 = 0.55;
const VELOCITY_MIN_EVENTS: usize = 3;

// Enhanced dimension thresholds
const ENHANCED_COGNITIVE_THRESHOLD: f64 = 0.7;
const ENHANCED_MIXED_THRESHOLD: f64 = 0.4;

fn score_color(s: u32) -> String {
    if s >= 80 {
        "#2e7d32".to_string()
    } else if s >= 60 {
        "#558b2f".to_string()
    } else if s >= 40 {
        "#f57f17".to_string()
    } else {
        "#b71c1c".to_string()
    }
}

fn dimension_interpretation(score: u32, high: &str, mid: &str, low: &str) -> String {
    if score >= 75 {
        high.into()
    } else if score >= 50 {
        mid.into()
    } else {
        low.into()
    }
}

fn make_dimension(
    name: &str,
    score: u32,
    confidence: f64,
    key_discriminator: String,
    interpretation: String,
) -> DimensionScore {
    DimensionScore {
        name: name.to_string(),
        score,
        lr: compute_likelihood_ratio(score),
        // log10() may return -inf for LR=0 or NaN for negative; .max(-2.0) clamps both.
        log_lr: compute_likelihood_ratio(score).log10().max(-2.0),
        confidence,
        key_discriminator: key_discriminator.clone(),
        color: score_color(score),
        analysis: vec![
            DimensionDetail {
                label: "Observation".into(),
                text: key_discriminator,
            },
            DimensionDetail {
                label: "Interpretation".into(),
                text: interpretation,
            },
        ],
    }
}

fn build_temporal_dimension(
    stats: &EventStats,
    event_count: usize,
) -> DimensionScore {
    let score: u32 = {
        let has_vdf = stats.total_iterations > 0;
        let dense_enough = event_count >= TEMPORAL_MIN_EVENTS;
        let long_enough = stats.total_min > TEMPORAL_MIN_DURATION;
        let base = if has_vdf && dense_enough && long_enough {
            TEMPORAL_BASE_FULL
        } else if has_vdf && dense_enough {
            TEMPORAL_BASE_DENSE
        } else if has_vdf {
            TEMPORAL_BASE_VDF_ONLY
        } else {
            TEMPORAL_BASE_NONE
        };
        base.saturating_add(if stats.total_iterations > TEMPORAL_HIGH_ITERATIONS {
            TEMPORAL_BONUS_HIGH
        } else {
            TEMPORAL_BONUS_LOW
        })
        .min(99)
    };
    let kd = format!(
        "{} checkpoints, {} VDF iterations",
        event_count, stats.total_iterations
    );
    make_dimension(
        "Temporal Proof Chain",
        score,
        if stats.total_iterations > 0 { TEMPORAL_CONFIDENCE_VDF } else { TEMPORAL_CONFIDENCE_NO_VDF },
        kd,
        dimension_interpretation(
            score,
            "Checkpoint density and VDF chain establish a credible minimum elapsed time consistent with organic composition.",
            "Chain is internally consistent but limited iterations reduce the provable elapsed-time bound.",
            "Insufficient checkpoints or VDF proof to establish minimum elapsed time with confidence.",
        ),
    )
}

fn build_edit_dimension(
    process: &ProcessEvidence,
    metrics: &crate::forensics::ForensicMetrics,
    event_count: usize,
) -> DimensionScore {
    let score: u32 = {
        let topo = finite_or(metrics.assessment_score.get(), 0.0);
        let ri = process
            .revision_intensity
            .filter(|v| v.is_finite())
            .unwrap_or(0.0);
        let ri_score = if ri > EDIT_RI_OPTIMAL_LOW && ri < EDIT_RI_OPTIMAL_HIGH {
            EDIT_RI_SCORE_OPTIMAL
        } else if ri > 0.0 {
            EDIT_RI_SCORE_PRESENT
        } else {
            EDIT_RI_SCORE_ABSENT
        };
        ((topo * EDIT_TOPOLOGY_WEIGHT + ri_score * EDIT_REVISION_WEIGHT) * 100.0)
            .clamp(0.0, 99.0) as u32
    };
    let kd = process
        .revision_intensity
        .filter(|v| v.is_finite())
        .map(|v| format!("{:.0}% revision rate", v * 100.0))
        .unwrap_or_else(|| "edit topology analyzed".to_string());
    make_dimension(
        "Edit Pattern Authenticity",
        score,
        if event_count >= EDIT_MIN_EVENTS { EDIT_CONFIDENCE_SUFFICIENT } else { EDIT_CONFIDENCE_SPARSE },
        kd,
        dimension_interpretation(
            score,
            "Revision patterns are consistent with iterative human composition including normal correction frequency and non-linear editing.",
            "Some revision activity detected; patterns are ambiguous between original composition and light editing.",
            "Low revision rate or anomalous editing patterns are inconsistent with typical human drafting behavior.",
        ),
    )
}

fn build_continuity_dimension(
    stats: &EventStats,
    sessions: &[ReportSession],
) -> DimensionScore {
    let score: u32 = {
        let session_count = sessions.len();
        let avg_duration = if session_count > 0 {
            stats.total_min / session_count as f64
        } else {
            stats.total_min
        };
        let base: u32 = if session_count >= CONTINUITY_MIN_MULTI_SESSIONS {
            CONTINUITY_BASE_MULTI
        } else if session_count == 2 {
            CONTINUITY_BASE_TWO
        } else {
            CONTINUITY_BASE_SINGLE
        };
        base.saturating_add(if avg_duration > CONTINUITY_DURATION_BONUS_THRESHOLD {
            CONTINUITY_DURATION_BONUS
        } else {
            0
        })
        .min(99)
    };
    let kd = format!(
        "{} session{}, {:.0} min total",
        sessions.len(),
        if sessions.len() == 1 { "" } else { "s" },
        stats.total_min
    );
    make_dimension(
        "Process Continuity",
        score,
        if sessions.len() >= 2 { CONTINUITY_CONFIDENCE_MULTI } else { CONTINUITY_CONFIDENCE_SINGLE },
        kd,
        dimension_interpretation(
            score,
            "Multiple distinct writing sessions demonstrate sustained engagement consistent with extended human composition.",
            "Session structure is present but limited; fewer sessions reduce confidence in sustained engagement.",
            "Single or very short session may indicate rapid entry rather than organic multi-session composition.",
        ),
    )
}

fn build_coherence_dimension(
    stats: &EventStats,
    metrics: &crate::forensics::ForensicMetrics,
) -> DimensionScore {
    let score: u32 = {
        let low_paste = stats
            .paste_ratio_pct
            .map(|p| p < COHERENCE_PASTE_THRESHOLD_PCT)
            .unwrap_or(true);
        let has_keystrokes = stats.keystroke_estimate > COHERENCE_MIN_KEYSTROKES;
        let cv = finite_or(metrics.cadence.correction_ratio.get(), 0.0);
        let base: u32 = if low_paste && has_keystrokes {
            COHERENCE_BASE_CLEAN
        } else {
            COHERENCE_BASE_PASTY
        };
        base.saturating_add(
            if cv > COHERENCE_CR_OPTIMAL_LOW && cv < COHERENCE_CR_OPTIMAL_HIGH {
                COHERENCE_CR_BONUS
            } else {
                0
            },
        )
        .min(99)
    };
    let kd = stats
        .paste_ratio_pct
        .map(|p| format!("{:.1}% paste ratio", p))
        .unwrap_or_else(|| format!("{} paste events", stats.paste_count));
    make_dimension(
        "Content-Process Coherence",
        score,
        COHERENCE_CONFIDENCE,
        kd,
        dimension_interpretation(
            score,
            "Content growth closely tracks keystroke activity with low paste ratio; process and content are well-aligned.",
            "Moderate alignment between content growth and editing activity; some paste operations detected.",
            "High paste ratio or poor keystroke-to-content alignment; process evidence is partially decoupled from content.",
        ),
    )
}

fn build_behavioral_dimension(
    metrics: &crate::forensics::ForensicMetrics,
) -> DimensionScore {
    let score: u32 = {
        let cv = if metrics.cadence.mean_iki_ns > 0.0
            && metrics.cadence.std_dev_iki_ns > 0.0
            && metrics.cadence.std_dev_iki_ns.is_finite()
            && metrics.cadence.mean_iki_ns.is_finite()
        {
            finite_or(metrics.cadence.std_dev_iki_ns / metrics.cadence.mean_iki_ns, 0.5)
        } else {
            finite_or(metrics.cadence.burst_speed_cv, 0.5)
        };
        let cv_score = if cv > BEHAVIORAL_CV_OPTIMAL_LOW && cv < BEHAVIORAL_CV_OPTIMAL_HIGH {
            BEHAVIORAL_CV_SCORE_OPTIMAL
        } else if cv > BEHAVIORAL_CV_MARGINAL {
            BEHAVIORAL_CV_SCORE_MARGINAL
        } else {
            BEHAVIORAL_CV_SCORE_POOR
        };
        let biological = finite_or(metrics.biological_cadence_score.get(), 0.5);
        ((cv_score * BEHAVIORAL_CV_WEIGHT + biological * BEHAVIORAL_BIO_WEIGHT) * 100.0)
            .clamp(0.0, 99.0) as u32
    };
    let kd = format!(
        "burst CV: {:.2}, correction rate: {:.1}%",
        finite_or(metrics.cadence.burst_speed_cv, 0.0),
        finite_or(metrics.cadence.correction_ratio.get(), 0.0) * 100.0
    );
    make_dimension(
        "Behavioral Signature",
        score,
        if metrics.cadence.mean_iki_ns > 0.0 { BEHAVIORAL_CONFIDENCE_DATA } else { BEHAVIORAL_CONFIDENCE_NO_DATA },
        kd,
        dimension_interpretation(
            score,
            "Inter-keystroke interval variability falls within human norms; cadence is consistent with biological typing.",
            "Typing cadence shows some variability but the pattern is ambiguous; limited IKI data reduces certainty.",
            "Keystroke cadence is atypical; may indicate automated input or transcription from an external source.",
        ),
    )
}

fn build_velocity_dimension(
    metrics: &crate::forensics::ForensicMetrics,
    event_count: usize,
) -> DimensionScore {
    let score: u32 = {
        let mbps = finite_or(metrics.velocity.mean_bps, 0.0);
        let v_score = if mbps > VELOCITY_HUMAN_LOW_BPS && mbps < VELOCITY_HUMAN_HIGH_BPS {
            VELOCITY_SCORE_OPTIMAL
        } else if mbps > 0.0 && mbps < VELOCITY_PLAUSIBLE_MAX_BPS {
            VELOCITY_SCORE_PLAUSIBLE
        } else if mbps == 0.0 {
            VELOCITY_SCORE_NONE
        } else {
            VELOCITY_SCORE_ANOMALOUS
        };
        (v_score * 100.0) as u32
    };
    let kd = format!(
        "{:.1} bytes/sec mean velocity",
        finite_or(metrics.velocity.mean_bps, 0.0)
    );
    make_dimension(
        "Writing Velocity",
        score,
        if event_count >= VELOCITY_MIN_EVENTS { VELOCITY_CONFIDENCE_DATA } else { VELOCITY_CONFIDENCE_SPARSE },
        kd,
        dimension_interpretation(
            score,
            "Mean content production rate falls within human prose writing norms (0.5\u{2013}15 B/s).",
            "Content production velocity is plausible but falls outside the core human prose range.",
            "Content production rate is inconsistent with natural human writing; may indicate batch insertion.",
        ),
    )
}

fn build_enhanced_dimension(
    name: &str,
    composite_score: f64,
    key_discriminator: &str,
) -> DimensionScore {
    let score = (composite_score * 100.0).round().clamp(0.0, 100.0) as u32;
    let interpretation = if composite_score >= ENHANCED_COGNITIVE_THRESHOLD {
        "Consistent with cognitive authorship"
    } else if composite_score >= ENHANCED_MIXED_THRESHOLD {
        "Mixed signals; ambiguous"
    } else {
        "Consistent with transcriptive or synthetic patterns"
    };
    make_dimension(name, score, composite_score, key_discriminator.to_string(), interpretation.to_string())
}

/// Assemble all dimension scores from event stats, process evidence, forensic
/// metrics, and detected sessions. Returns the core 6 dimensions plus any
/// enhanced signal dimensions produced by advanced analysis modules.
pub(crate) fn build_dimensions(
    stats: &EventStats,
    process: &ProcessEvidence,
    metrics: &crate::forensics::ForensicMetrics,
    sessions: &[ReportSession],
) -> Vec<DimensionScore> {
    let event_count = process.swf_checkpoints.unwrap_or(0) as usize;
    let mut dims = vec![
        build_temporal_dimension(stats, event_count),
        build_edit_dimension(process, metrics, event_count),
        build_continuity_dimension(stats, sessions),
        build_coherence_dimension(stats, metrics),
        build_behavioral_dimension(metrics),
        build_velocity_dimension(metrics, event_count),
    ];

    // Enhanced signal dimensions (populated when new analysis modules ran).
    if let Some(ref cl) = metrics.cognitive_load {
        dims.push(build_enhanced_dimension(
            "Cognitive Load",
            cl.composite_score,
            &format!("IKI-surprisal rho={:.2}", cl.iki_surprisal_rho),
        ));
    }
    if let Some(ref rt) = metrics.revision_topology {
        dims.push(build_enhanced_dimension(
            "Revision Topology",
            rt.composite_score,
            &format!("branching={:.1}", rt.graph.mean_branching_factor),
        ));
    }
    if let Some(ref ee) = metrics.error_ecology {
        dims.push(build_enhanced_dimension(
            "Error Ecology",
            ee.composite_score,
            &format!("rapid={:.0}%", ee.rapid_self_correction_pct * 100.0),
        ));
    }
    if let Some(ref lm) = metrics.likelihood_model {
        dims.push(build_enhanced_dimension(
            "Likelihood Model",
            lm.session_p_cognitive,
            &format!("LLR={:.1}", lm.mean_window_llr),
        ));
    }
    if let Some(ref cm) = metrics.composition_mode {
        dims.push(build_enhanced_dimension(
            "Composition Mode",
            cm.composite_score,
            &cm.dominant_mode
                .map(|m| m.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        ));
    }

    dims
}
