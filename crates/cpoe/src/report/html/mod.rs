// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

pub(crate) mod charts;
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

    // ── PART 1: VISUAL SUMMARY (intended to be read) ──
    // Charts and visual evidence — the primary way humans consume this report.
    write_visual_overview(html, r)?;

    sections::write_enfsi_scale(html, r)?;
    sections::write_lr_interpretation(html, r)?;
    sections::write_key_findings(html, r)?;

    // ── PART 2: BEHAVIORAL ANALYSIS (intended to be read) ──
    // Dimension scores, category breakdowns, writing flow — the analytical core.
    sections::write_dimension_analysis(html, r)?;
    sections::write_category_scores(html, r)?;
    sections::write_forensic_breakdown(html, r)?;
    sections::write_session_timeline(html, r)?;
    sections::write_edit_topology(html, r)?;
    sections::write_activity_contexts(html, r)?;

    // ── PART 3: EVIDENCE CHAIN (intended to be read) ──
    // Provenance, process evidence, chain of custody.
    sections::write_provenance_breakdown(html, r)?;
    sections::write_process_evidence(html, r)?;
    sections::write_chain_of_custody(html, r)?;
    sections::write_declaration_summary(html, r)?;
    sections::write_hardware_attestation(html, r)?;
    sections::write_forgery_resistance(html, r)?;

    // ── PART 4: METHODOLOGY & SCOPE ──
    sections::write_methodology(html, r)?;
    sections::write_scope(html, r)?;
    sections::write_flags(html, r)?;
    sections::write_anomalies_detail(html, r)?;

    // ── PART 5: REFERENCE DATA (for legal/technical use, not casual reading) ──
    writeln!(html, r#"<div class="reference-appendix">"#)?;
    writeln!(html, r#"<h2>Reference Appendix</h2>"#)?;
    writeln!(html, r#"<p class="chart-caption">The following sections contain raw technical data provided for legal verification and reproducibility. The visual charts and analysis above are the intended reading material.</p>"#)?;
    sections::write_dimension_lr_table(html, r)?;
    sections::write_checkpoint_chain(html, r)?;
    sections::write_key_hierarchy(html, r)?;
    sections::write_analyzed_text(html, r)?;
    sections::write_verification_instructions(html)?;
    sections::write_glossary(html)?;
    sections::write_verifiable_credential(html, r)?;
    sections::write_embedded_evidence(html, r)?;
    writeln!(html, "</div>")?;

    // ── LEGAL CERTIFICATIONS ──
    sections::write_certification(html, r)?;
    sections::write_fre_certification(html, r)?;
    sections::write_references(html, r)?;
    sections::write_footer(html, r)?;

    write!(html, "</div></body></html>")
}

/// Visual overview section with SVG charts — placed early in the report
/// so human readers see the visual summary before the detailed tables.
fn write_visual_overview(html: &mut String, r: &WarReport) -> std::fmt::Result {
    writeln!(html, r#"<h2>Visual Overview</h2>"#)?;

    // Writing flow intensity chart
    let flow_svg = charts::writing_flow_chart(&r.writing_flow);
    if !flow_svg.is_empty() {
        writeln!(html, r#"<h3>Writing Rhythm</h3>"#)?;
        writeln!(html, r#"<p class="chart-caption">Typing intensity over time. Peaks indicate active composition; valleys indicate pauses for thought or revision.</p>"#)?;
        writeln!(html, "{flow_svg}")?;
    }

    // Dimension score bar chart
    let dim_svg = charts::dimension_bar_chart(&r.dimensions);
    if !dim_svg.is_empty() {
        writeln!(html, r#"<h3>Analysis Dimensions</h3>"#)?;
        writeln!(html, r#"<p class="chart-caption">Per-dimension assessment scores. Green (&ge;70) indicates strong human authorship signals; amber (40&ndash;69) is mixed; red (&lt;40) is suspicious.</p>"#)?;
        writeln!(html, "{dim_svg}")?;
    }

    // Checkpoint velocity chart
    let cp_svg = charts::checkpoint_velocity_chart(&r.checkpoints);
    if !cp_svg.is_empty() {
        writeln!(html, r#"<h3>Document Growth</h3>"#)?;
        writeln!(html, r#"<p class="chart-caption">Document size at each checkpoint. Steady growth with revision dips is characteristic of human composition.</p>"#)?;
        writeln!(html, "{cp_svg}")?;
    }

    if flow_svg.is_empty() && dim_svg.is_empty() && cp_svg.is_empty() {
        writeln!(html, r#"<p>Insufficient data for visual charts. See detailed tables below.</p>"#)?;
    }

    Ok(())
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
