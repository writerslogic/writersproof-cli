// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use std::path::Path;

use crate::output::OutputMode;
use crate::util::{check_ffi_result, path_str};

pub(crate) fn cmd_report(path: &Path, format: &str, out: &OutputMode) -> Result<()> {
    let path_str = path_str(path);

    match format {
        "html" => cmd_report_html(&path_str, out),
        "json" => cmd_report_json(&path_str, out),
        other => Err(anyhow!(
            "Unsupported report format: '{}'. Use 'html' or 'json'.",
            other
        )),
    }
}

fn cmd_report_html(path: &str, out: &OutputMode) -> Result<()> {
    let result = cpoe::ffi::report::ffi_render_war_html(path.to_string());

    check_ffi_result(result.success, &result.error_message)?;

    let html = result.html.unwrap_or_default();

    if out.quiet {
        return Ok(());
    }
    if out.json {
        println!("{}", serde_json::json!({ "html": html }));
    } else {
        print!("{}", html);
    }

    Ok(())
}

fn cmd_report_json(path: &str, out: &OutputMode) -> Result<()> {
    let result = cpoe::ffi::report::ffi_build_war_report(path.to_string());

    check_ffi_result(result.success, &result.error_message)?;

    let report = result
        .report
        .ok_or_else(|| anyhow!("Report was empty"))?;

    if out.quiet {
        return Ok(());
    }
    if out.json {
        println!(
            "{}",
            serde_json::json!({
                "report_id": report.report_id,
                "algorithm_version": report.algorithm_version,
                "generated_at_epoch_ms": report.generated_at_epoch_ms,
                "schema_version": report.schema_version,
                "score": report.score,
                "verdict": report.verdict,
                "verdict_description": report.verdict_description,
                "likelihood_ratio": report.likelihood_ratio,
                "enfsi_tier": report.enfsi_tier,
                "document_hash": report.document_hash,
                "session_count": report.session_count,
                "total_duration_min": report.total_duration_min,
                "revision_events": report.revision_events,
                "device_attestation": report.device_attestation,
            })
        );
        return Ok(());
    }

    println!("=== WAR Report ===");
    println!();
    println!("Report ID:    {}", report.report_id);
    println!("Score:        {}/100", report.score);
    println!("Verdict:      {}", report.verdict);
    println!("Description:  {}", report.verdict_description);
    println!("ENFSI Tier:   {}", report.enfsi_tier);
    println!();
    println!("Document Hash:     {}", report.document_hash);
    println!("Sessions:          {}", report.session_count);
    println!("Duration:          {:.1} min", report.total_duration_min);
    println!("Revision Events:   {}", report.revision_events);
    println!("Device Attestation:{}", report.device_attestation);
    println!("Likelihood Ratio:  {:.2}", report.likelihood_ratio);

    if !report.flags.is_empty() {
        println!();
        println!("--- Flags ---");
        for flag in &report.flags {
            println!("  [{}] {}: {}", flag.category, flag.flag, flag.detail);
        }
    }

    Ok(())
}
