// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

mod css;
mod helpers;
mod sections;

use super::types::*;
use std::fmt::Write;

/// Render a self-contained HTML report from a `WarReport`.
pub fn render_html(r: &WarReport) -> String {
    let mut html = String::new();
    html.reserve(48_000);
    // String::write_fmt is infallible; the expect documents that invariant.
    render_html_inner(&mut html, r).expect("infallible: String::Write");
    html
}

fn render_html_inner(html: &mut String, r: &WarReport) -> std::fmt::Result {
    css::write_head(html, r)?;

    // Document title
    sections::write_header(html, r)?;

    // Formal examination metadata block
    sections::write_examination_metadata(html, r)?;

    // Executive summary (plain-English for non-technical readers)
    sections::write_executive_summary(html, r)?;

    // Declaration of findings (score, verdict, LR, ENFSI)
    sections::write_verdict(html, r)?;

    let sufficient = r.evidence_is_sufficient();

    if !sufficient {
        // Short report: explain why the methodology cannot issue a finding,
        // show what was captured and what thresholds are needed.
        write_insufficient_notice(html, r)?;

        // Still show: chain of evidence, scope/limitations, verification, glossary
        sections::write_chain_of_custody(html, r)?;
        sections::write_scope(html, r)?;
        sections::write_verification_instructions(html)?;
        sections::write_glossary(html)?;
        sections::write_footer(html, r)?;
        return write!(html, "</div></body></html>");
    }

    sections::write_enfsi_scale(html, r)?;
    sections::write_lr_interpretation(html, r)?;
    sections::write_key_findings(html, r)?;

    // Methodology with explicit hypotheses
    sections::write_methodology(html, r)?;

    // Chain of evidence
    sections::write_chain_of_custody(html, r)?;

    // Content provenance breakdown
    sections::write_provenance_breakdown(html, r)?;

    // Author declaration
    sections::write_declaration_summary(html, r)?;

    // Key hierarchy
    sections::write_key_hierarchy(html, r)?;

    // Category scores + writing flow
    sections::write_category_scores(html, r)?;

    // Process evidence (exhibits A-F, dynamic notes)
    sections::write_process_evidence(html, r)?;

    // Forensic breakdown
    sections::write_forensic_breakdown(html, r)?;

    // Edit topology
    sections::write_edit_topology(html, r)?;

    // Session timeline
    sections::write_session_timeline(html, r)?;

    // Activity contexts
    sections::write_activity_contexts(html, r)?;

    // Hardware attestation
    sections::write_hardware_attestation(html, r)?;

    // Detailed dimension analysis
    sections::write_dimension_analysis(html, r)?;

    // Per-dimension LR table
    sections::write_dimension_lr_table(html, r)?;

    // Checkpoint chain
    sections::write_checkpoint_chain(html, r)?;

    // Forgery resistance
    sections::write_forgery_resistance(html, r)?;

    // Analysis flags
    sections::write_flags(html, r)?;

    // Anomaly details
    sections::write_anomalies_detail(html, r)?;

    // Scope, limitations, admissibility
    sections::write_scope(html, r)?;

    // Analyzed text
    sections::write_analyzed_text(html, r)?;

    // Verification instructions
    sections::write_verification_instructions(html)?;

    // Glossary
    sections::write_glossary(html)?;

    // Verifiable Credential
    sections::write_verifiable_credential(html, r)?;

    // Embedded evidence (self-verifying artifact)
    sections::write_embedded_evidence(html, r)?;

    // Court-grade legal sections (only for sufficient evidence)
    sections::write_certification(html, r)?;
    sections::write_fre_certification(html, r)?;
    sections::write_references(html, r)?;

    // Certification
    sections::write_footer(html, r)?;

    write!(html, "</div></body></html>")
}

fn write_insufficient_notice(html: &mut String, r: &WarReport) -> std::fmt::Result {
    use helpers::html_escape;

    let gaps = r.sufficiency_gaps();
    let duration_sec = (r.total_duration_min * 60.0) as u64;
    let keystrokes = r.process.total_keystrokes.unwrap_or(0);
    let checkpoints = r.checkpoints.len();
    let words = r.document_words.unwrap_or(0);

    write!(html,
        r#"<div class="info-box" style="border-left:4px solid #757575;margin:24px 0;padding:16px 20px">
<h2 style="margin:0 0 8px;color:#757575">Examination Withheld</h2>
<p>The captured evidence does not meet the validated minimum thresholds required for
evaluative reporting under this methodology. <strong>No likelihood ratio, ENFSI verbal
equivalence, or forensic score is issued.</strong></p>
<h3 style="margin:16px 0 8px">Evidence Captured</h3>
<table class="data">
<thead><tr><th>Metric</th><th>Captured</th><th>Required</th><th>Status</th></tr></thead>
<tbody>
<tr><td>Keystrokes</td><td>{keystrokes}</td><td>{min_ks}</td><td>{ks_status}</td></tr>
<tr><td>Duration</td><td>{duration_sec}s</td><td>{min_dur}s</td><td>{dur_status}</td></tr>
<tr><td>Checkpoints</td><td>{checkpoints}</td><td>{min_cp}</td><td>{cp_status}</td></tr>
<tr><td>Words</td><td>{words}</td><td>{min_words}</td><td>{words_status}</td></tr>
</tbody>
</table>
<p style="margin:12px 0 0;color:#666;font-size:13px">Continue writing to accumulate sufficient
evidence. The report will issue an evaluative finding once all thresholds are met.</p>
</div>"#,
        keystrokes = keystrokes,
        min_ks = crate::report::MIN_REPORT_KEYSTROKES,
        ks_status = if keystrokes >= crate::report::MIN_REPORT_KEYSTROKES {
            "&#10003; Met"
        } else {
            "&#10007; Below threshold"
        },
        duration_sec = duration_sec,
        min_dur = crate::report::MIN_REPORT_DURATION_SEC as u64,
        dur_status = if (r.total_duration_min * 60.0) >= crate::report::MIN_REPORT_DURATION_SEC {
            "&#10003; Met"
        } else {
            "&#10007; Below threshold"
        },
        checkpoints = checkpoints,
        min_cp = crate::report::MIN_REPORT_CHECKPOINTS,
        cp_status = if checkpoints >= crate::report::MIN_REPORT_CHECKPOINTS {
            "&#10003; Met"
        } else {
            "&#10007; Below threshold"
        },
        words = words,
        min_words = crate::report::MIN_REPORT_WORDS,
        words_status = if words >= crate::report::MIN_REPORT_WORDS {
            "&#10003; Met"
        } else {
            "&#10007; Below threshold"
        },
    )?;

    if !gaps.is_empty() {
        for lim in &r.limitations {
            if lim.contains("Evidence below validated thresholds") {
                write!(html, "<p style=\"color:#666;font-size:12px\"><em>{}</em></p>",
                    html_escape(lim))?;
                break;
            }
        }
    }

    Ok(())
}
