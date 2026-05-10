// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::Result;
use std::path::PathBuf;

use crate::cli::ForensicsAction;
use crate::output::OutputMode;
use crate::util::{check_ffi_result, path_str};

pub(crate) fn cmd_forensics(action: ForensicsAction, out: &OutputMode) -> Result<()> {
    match action {
        ForensicsAction::Breakdown { path } => cmd_forensics_breakdown(&path, out),
        ForensicsAction::Score { path } => cmd_forensics_score(&path, out),
        ForensicsAction::Provenance { path } => cmd_forensics_provenance(&path, out),
    }
}

fn cmd_forensics_breakdown(path: &PathBuf, out: &OutputMode) -> Result<()> {
    let path_str = path_str(path);
    let result = cpoe::ffi::forensics_detail::ffi_get_forensic_breakdown(path_str);

    check_ffi_result(result.success, &result.error_message)?;

    if out.json {
        println!(
            "{}",
            serde_json::json!({
                "monotonic_append_ratio": result.monotonic_append_ratio,
                "edit_entropy": result.edit_entropy,
                "median_interval": result.median_interval,
                "mean_iki_ms": result.mean_iki_ms,
                "std_dev_iki_ms": result.std_dev_iki_ms,
                "coefficient_of_variation": result.coefficient_of_variation,
                "burst_count": result.burst_count,
                "pause_count": result.pause_count,
                "mean_bps": result.mean_bps,
                "max_bps": result.max_bps,
                "hurst_exponent": result.hurst_exponent,
                "assessment_score": result.assessment_score,
                "perplexity_score": result.perplexity_score,
                "risk_level": result.risk_level,
                "protocol_verdict": result.protocol_verdict,
                "anomaly_count": result.anomaly_count,
                "writing_mode": result.writing_mode,
                "writing_mode_score": result.writing_mode_score,
                "writing_mode_confidence": result.writing_mode_confidence,
                "revision_cycle_count": result.revision_cycle_count,
                "correction_ratio": result.correction_ratio,
                "burst_speed_cv": result.burst_speed_cv,
                "spoofing_indicator": result.spoofing_indicator,
                "sentence_initiation_ratio": result.sentence_initiation_ratio,
                "lrd_correlation": result.lrd_correlation,
                "iki_modality_score": result.iki_modality_score,
                "baseline_deviation": result.baseline_deviation,
                "dictation_plausibility": result.dictation_plausibility,
                "dictation_ratio": result.dictation_ratio,
                "multi_speaker_detected": result.multi_speaker_detected,
            })
        );
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("=== Forensic Breakdown ===");
    println!();
    println!("Verdict:          {}", result.protocol_verdict);
    println!("Risk Level:       {}", result.risk_level);
    println!("Assessment Score: {:.2}", result.assessment_score);
    println!("Writing Mode:     {} ({:.0}% confidence)",
        result.writing_mode, result.writing_mode_confidence * 100.0);
    println!();
    println!("--- Timing ---");
    println!("Mean IKI:         {:.1} ms", result.mean_iki_ms);
    println!("Std Dev IKI:      {:.1} ms", result.std_dev_iki_ms);
    println!("Median Interval:  {:.1} ms", result.median_interval);
    println!("Coeff of Var:     {:.3}", result.coefficient_of_variation);
    println!();
    println!("--- Structure ---");
    println!("Bursts:           {}", result.burst_count);
    println!("Pauses:           {}", result.pause_count);
    println!("Mean BPS:         {:.2}", result.mean_bps);
    println!("Max BPS:          {:.2}", result.max_bps);
    println!("Edit Entropy:     {:.3}", result.edit_entropy);
    println!("Append Ratio:     {:.3}", result.monotonic_append_ratio);
    println!();
    println!("--- Behavioral ---");
    println!("Revision Cycles:  {}", result.revision_cycle_count);
    println!("Correction Ratio: {:.3}", result.correction_ratio);
    println!("Spoofing Score:   {:.3}", result.spoofing_indicator);
    println!("Baseline Dev:     {:.3}", result.baseline_deviation);
    println!("Anomalies:        {}", result.anomaly_count);

    if result.dictation_ratio > 0.0 {
        println!();
        println!("--- Dictation ---");
        println!("Dictation Ratio:  {:.1}%", result.dictation_ratio * 100.0);
        println!("Plausibility:     {:.2}", result.dictation_plausibility);
        println!("Multi-Speaker:    {}", result.multi_speaker_detected);
    }

    if !result.anomalies.is_empty() {
        println!();
        println!("--- Anomalies ---");
        for anomaly in &result.anomalies {
            println!("  [{}] {}: {}", anomaly.severity, anomaly.anomaly_type, anomaly.description);
        }
    }

    Ok(())
}

fn cmd_forensics_score(path: &PathBuf, out: &OutputMode) -> Result<()> {
    let path_str = path_str(path);
    let result = cpoe::ffi::forensics::ffi_compute_process_score(path_str);

    check_ffi_result(result.success, &result.error_message)?;

    if out.json {
        println!(
            "{}",
            serde_json::json!({
                "residency": result.residency,
                "sequence": result.sequence,
                "behavioral": result.behavioral,
                "composite": result.composite,
                "meets_threshold": result.meets_threshold,
            })
        );
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("=== Process Score ===");
    println!();
    println!("Residency:  {:.3}", result.residency);
    println!("Sequence:   {:.3}", result.sequence);
    println!("Behavioral: {:.3}", result.behavioral);
    println!("Composite:  {:.3}", result.composite);
    println!();
    println!(
        "Threshold:  {}",
        if result.meets_threshold {
            "PASS"
        } else {
            "FAIL"
        }
    );

    Ok(())
}

fn cmd_forensics_provenance(path: &PathBuf, out: &OutputMode) -> Result<()> {
    let path_str = path_str(path);
    let result = cpoe::ffi::forensics::ffi_get_provenance_metrics_for_document(path_str);

    check_ffi_result(result.success, &result.error_message)?;

    if out.json {
        let sources: Vec<serde_json::Value> = result
            .source_sessions
            .iter()
            .map(|s| {
                serde_json::json!({
                    "session_id": s.session_id,
                    "app_bundle_id": s.app_bundle_id,
                    "fragment_count": s.fragment_count,
                    "verified": s.verified,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "total_fragments": result.total_fragments,
                "original_composition_pct": result.original_composition_pct,
                "sourced_unknown_pct": result.sourced_unknown_pct,
                "sourced_verified_pct": result.sourced_verified_pct,
                "chain_depth": result.chain_depth,
                "source_trustworthiness": result.source_trustworthiness,
                "authenticity_score": result.authenticity_score,
                "source_sessions": sources,
            })
        );
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("=== Provenance Metrics ===");
    println!();
    println!("Total Fragments:      {}", result.total_fragments);
    println!(
        "Original Composition: {:.1}%",
        result.original_composition_pct * 100.0
    );
    println!(
        "Sourced (verified):   {:.1}%",
        result.sourced_verified_pct * 100.0
    );
    println!(
        "Sourced (unknown):    {:.1}%",
        result.sourced_unknown_pct * 100.0
    );
    println!("Chain Depth:          {}", result.chain_depth);
    println!(
        "Source Trust:         {:.2}",
        result.source_trustworthiness
    );
    println!("Authenticity Score:   {:.2}", result.authenticity_score);

    if !result.source_sessions.is_empty() {
        println!();
        println!("--- Source Sessions ---");
        for s in &result.source_sessions {
            let verified = if s.verified { "verified" } else { "unverified" };
            println!(
                "  {} ({}) — {} fragments [{}]",
                s.session_id, s.app_bundle_id, s.fragment_count, verified
            );
        }
    }

    Ok(())
}
