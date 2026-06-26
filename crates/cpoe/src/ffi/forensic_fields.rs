// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::report::ForensicBreakdown;
use crate::utils::finite_or;

/// Build the common forensic breakdown fields from an authorship profile
/// and forensic metrics. Used by both the WAR report builder and the
/// FFI forensic breakdown builder to avoid duplicating extraction logic.
pub(crate) fn build_forensic_breakdown(
    profile: &crate::forensics::AuthorshipProfile,
    metrics: &crate::forensics::ForensicMetrics,
) -> ForensicBreakdown {
    let c = &metrics.cadence;
    let mean_iki = finite_or(c.mean_iki_ns / 1_000_000.0, 0.0);
    let cv = if mean_iki > 0.0 && c.std_dev_iki_ns.is_finite() && c.mean_iki_ns.is_finite() {
        finite_or(c.std_dev_iki_ns / c.mean_iki_ns, 0.0)
    } else {
        0.0
    };
    ForensicBreakdown {
        writing_mode: profile.writing_mode().to_string(),
        cognitive_score: finite_or(metrics.assessment_score.get(), 0.0),
        writing_mode_confidence: metrics
            .writing_mode
            .as_ref()
            .map(|wm| finite_or(wm.confidence, 0.0))
            .unwrap_or_else(|| if profile.event_count > 20 { 0.8 } else { 0.3 }),
        revision_cycle_count: metrics
            .writing_mode
            .as_ref()
            .map(|wm| u32::try_from(wm.revision_pattern.revision_cycle_count).unwrap_or(u32::MAX))
            .unwrap_or(0),
        hurst_exponent: metrics.hurst_exponent.filter(|v| v.is_finite()),
        assessment_score: finite_or(metrics.assessment_score.get(), 0.0),
        risk_level: profile.risk_level().to_string(),
        mean_iki_ms: mean_iki,
        coefficient_of_variation: finite_or(cv, 0.0),
        burst_count: u32::try_from(c.burst_count).unwrap_or(u32::MAX),
        pause_count: u32::try_from(c.pause_count).unwrap_or(u32::MAX),
        correction_ratio: finite_or(c.correction_ratio.get(), 0.0),
        burst_speed_cv: finite_or(c.burst_speed_cv, 0.0),
        pause_depth: c.pause_depth_distribution,
        mean_bps: finite_or(metrics.velocity.mean_bps, 0.0),
        max_bps: finite_or(metrics.velocity.max_bps, 0.0),
        biological_cadence_score: finite_or(metrics.biological_cadence_score.get(), 0.0),
        steg_confidence: finite_or(metrics.steg_confidence.get(), 0.0),
        thinking_pause_ratio: metrics
            .writing_mode
            .as_ref()
            .map(|wm| finite_or(wm.thinking_pause_ratio, 0.0))
            .unwrap_or(0.0),
        timing_entropy: finite_or(profile.metrics.timing_entropy, 0.0),
        pause_entropy: finite_or(profile.metrics.pause_entropy, 0.0),
        snr_db: metrics
            .snr
            .as_ref()
            .map(|s| s.snr_db)
            .filter(|v| v.is_finite()),
        snr_flagged: metrics.snr.as_ref().is_some_and(|s| s.flagged),
        lyapunov_exponent: metrics
            .lyapunov
            .as_ref()
            .map(|l| l.exponent)
            .filter(|v| v.is_finite()),
        lyapunov_flagged: metrics.lyapunov.as_ref().is_some_and(|l| l.flagged),
        iki_compression_ratio: metrics
            .iki_compression
            .as_ref()
            .map(|i| i.ratio)
            .filter(|v| v.is_finite()),
        iki_compression_flagged: metrics.iki_compression.as_ref().is_some_and(|i| i.flagged),
        forgery_difficulty: metrics
            .forgery_cost
            .as_ref()
            .map(|f| f.overall_difficulty)
            .filter(|v| v.is_finite()),
        forgery_tier: metrics.forgery_cost.as_ref().map(|f| f.tier.to_string()),
        forgery_time_sec: metrics
            .forgery_cost
            .as_ref()
            .map(|f| f.estimated_forge_time_sec)
            .filter(|v| v.is_finite()),
        fatigue_warmup_pct: metrics
            .fatigue_trajectory
            .as_ref()
            .map(|f| f.warmup_fraction)
            .filter(|v| v.is_finite()),
        fatigue_plateau_pct: metrics
            .fatigue_trajectory
            .as_ref()
            .map(|f| f.plateau_fraction)
            .filter(|v| v.is_finite()),
        fatigue_pct: metrics
            .fatigue_trajectory
            .as_ref()
            .map(|f| f.fatigue_fraction)
            .filter(|v| v.is_finite()),
        fatigue_slope: metrics
            .fatigue_trajectory
            .as_ref()
            .map(|f| f.fatigue_slope_iki_per_kstroke)
            .filter(|v| v.is_finite()),
        cross_modal_score: metrics
            .cross_modal
            .as_ref()
            .map(|cm| cm.score)
            .filter(|v| v.is_finite()),
        cross_modal_verdict: metrics
            .cross_modal
            .as_ref()
            .map(|cm| cm.verdict.to_string()),
        transcription_suspicious: metrics
            .transcription_suspicion
            .as_ref()
            .is_some_and(|t| t.is_suspicious),
        repair_recent_pct: metrics
            .repair_locality
            .as_ref()
            .map(|r| r.recent_repair_pct)
            .filter(|v| v.is_finite()),
        repair_distant_pct: metrics
            .repair_locality
            .as_ref()
            .map(|r| r.distant_repair_pct)
            .filter(|v| v.is_finite()),
        cognitive_load_score: metrics
            .cognitive_load
            .as_ref()
            .map(|cl| cl.composite_score)
            .filter(|v| v.is_finite()),
        revision_topology_score: metrics
            .revision_topology
            .as_ref()
            .map(|rt| rt.composite_score)
            .filter(|v| v.is_finite()),
        detour_ratio: metrics
            .revision_topology
            .as_ref()
            .map(|rt| rt.detour_ratio)
            .filter(|v| v.is_finite()),
        leading_edge_divergence: metrics
            .revision_topology
            .as_ref()
            .map(|rt| rt.leading_edge_divergence)
            .filter(|v| v.is_finite()),
        insertion_point_entropy: metrics
            .revision_topology
            .as_ref()
            .map(|rt| rt.insertion_point_entropy)
            .filter(|v| v.is_finite()),
        error_ecology_score: metrics
            .error_ecology
            .as_ref()
            .map(|ee| ee.composite_score)
            .filter(|v| v.is_finite()),
        likelihood_p_cognitive: metrics
            .likelihood_model
            .as_ref()
            .map(|lm| lm.session_p_cognitive)
            .filter(|v| v.is_finite()),
        composition_mode: metrics
            .composition_mode
            .as_ref()
            .and_then(|cm| cm.dominant_mode.map(|m| m.to_string())),
        labyrinth_determinism: metrics
            .labyrinth
            .as_ref()
            .filter(|l| l.is_valid)
            .map(|l| l.determinism)
            .filter(|v| v.is_finite()),
        labyrinth_recurrence: metrics
            .labyrinth
            .as_ref()
            .filter(|l| l.is_valid)
            .map(|l| l.recurrence_rate)
            .filter(|v| v.is_finite()),
        active_probes_score: metrics
            .active_probes
            .as_ref()
            .map(|ap| ap.combined_score)
            .filter(|v| v.is_finite()),
        error_topology_score: metrics
            .error_topology
            .as_ref()
            .map(|et| et.score)
            .filter(|v| v.is_finite()),
        spectral_slope: metrics
            .spectral_analysis
            .as_ref()
            .map(|pn| pn.spectral_slope)
            .filter(|v| v.is_finite()),
        spectral_noise_type: metrics
            .spectral_analysis
            .as_ref()
            .map(|pn| format!("{:?}", pn.noise_type)),
        baseline_deviation: metrics
            .baseline_comparison
            .as_ref()
            .map(|bc| bc.mahalanobis_distance)
            .filter(|v| v.is_finite()),
        ai_fluency_flag: metrics.ai_fluency_flag,
    }
}
