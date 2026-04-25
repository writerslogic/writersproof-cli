// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers::*;
use crate::report::types::*;
use crate::utils::finite_or;
use std::fmt::{self, Write};

const TMPL_METHODOLOGY: &str = include_str!("templates/methodology.html");
const TMPL_GLOSSARY: &str = include_str!("templates/glossary.html");
const TMPL_SCOPE: &str = include_str!("templates/scope.html");
const TMPL_VERIFICATION: &str = include_str!("templates/verification.html");

const REPORT_TITLE: &str = "Forensic Authorship Examination Report";
const SEC_DECLARATION: &str = "Declaration of Findings";
const SEC_METHODOLOGY: &str = "Methodology";
const SEC_CHAIN: &str = "Chain of Evidence";
const SEC_PROCESS: &str = "Findings: Process Evidence";
const SEC_TIMELINE: &str = "Session Timeline";
const SEC_DIMENSIONS: &str = "Detailed Dimension Analysis";
const SEC_STATISTICS: &str = "Statistical Analysis: Per-Dimension Likelihood Ratios";
const SEC_CHECKPOINTS: &str = "Checkpoint Chain Integrity";
const SEC_FORGERY: &str = "Forgery Resistance Assessment";
const SEC_FLAGS: &str = "Analysis Flags";
const SEC_SCOPE: &str = "Scope, Limitations, and Admissibility";
const SEC_TEXT: &str = "Analyzed Text";
const SEC_VERIFY: &str = "Independent Verification";
const SEC_GLOSSARY: &str = "Glossary of Terms";

fn section_heading(html: &mut String, number: u32, title: &str) -> fmt::Result {
    write!(
        html,
        r#"<h2><span class="section-number">{}.</span> {}</h2>"#,
        number, title
    )
}

/// Validate a CSS color value to prevent XSS injection via style attributes.
fn sanitize_css_color(color: &str) -> &str {
    let bytes = color.as_bytes();
    let valid = bytes.first() == Some(&b'#')
        && matches!(bytes.len(), 4 | 5 | 7 | 9)
        && bytes[1..].iter().all(|b| b.is_ascii_hexdigit());
    if valid {
        color
    } else {
        "#4a4a4a"
    }
}

// ---------------------------------------------------------------------------
// Document Header
// ---------------------------------------------------------------------------

pub(super) fn write_header(html: &mut String, r: &WarReport) -> fmt::Result {
    let sample = if r.is_sample {
        r#"<span class="sample-badge">SAMPLE</span>"#
    } else {
        ""
    };
    write!(
        html,
        r#"<h1>{title}{sample}</h1>
<p class="subtitle">
  Report {id} &ensp;|&ensp; Algorithm {alg} &ensp;|&ensp;
  Issued {ts} &ensp;|&ensp; Schema {schema}
</p>
"#,
        title = REPORT_TITLE,
        id = html_escape(&r.report_id),
        alg = html_escape(&r.algorithm_version),
        ts = r.generated_at.format("%B %-d, %Y at %H:%M:%S UTC"),
        schema = html_escape(&r.schema_version),
    )
}

// ---------------------------------------------------------------------------
// Examination Metadata
// ---------------------------------------------------------------------------

pub(super) fn write_examination_metadata(html: &mut String, r: &WarReport) -> fmt::Result {
    let doc_hash_short = if r.document_hash.len() > 16 {
        format!(
            "{}...{}",
            &r.document_hash[..8],
            &r.document_hash[r.document_hash.len().saturating_sub(8)..],
        )
    } else {
        r.document_hash.clone()
    };
    write!(
        html,
        r#"<div class="exam-meta">
<div><span class="meta-label">Report Reference</span><span class="meta-value">{id}</span></div>
<div><span class="meta-label">Date of Report</span><span class="meta-value">{date}</span></div>
<div><span class="meta-label">Examination System</span><span class="meta-value">CPoE Forensic Engine {alg}</span></div>
<div><span class="meta-label">Document Fingerprint</span><span class="meta-value"><code>{hash}</code></span></div>
<div><span class="meta-label">Evidence Sessions</span><span class="meta-value">{sessions} session{s_plural}, {dur:.0} min total</span></div>
<div><span class="meta-label">Reporting Standard</span><span class="meta-value">ENFSI Guideline for Evaluative Reporting (2015)</span></div>
</div>
"#,
        id = html_escape(&r.report_id),
        date = r.generated_at.format("%B %-d, %Y"),
        alg = html_escape(&r.algorithm_version),
        hash = html_escape(&doc_hash_short),
        sessions = r.session_count,
        s_plural = if r.session_count == 1 { "" } else { "s" },
        dur = r.total_duration_min,
    )
}

// ---------------------------------------------------------------------------
// Executive Summary
// ---------------------------------------------------------------------------

pub(super) fn write_executive_summary(html: &mut String, r: &WarReport) -> fmt::Result {
    let strength = match r.enfsi_tier {
        EnfsiTier::VeryStrong => "very strongly supports",
        EnfsiTier::Strong => "strongly supports",
        EnfsiTier::ModeratelyStrong => "moderately supports",
        EnfsiTier::Moderate => "provides moderate support for",
        EnfsiTier::Weak => "provides limited support for",
        EnfsiTier::Against => "does not support",
        EnfsiTier::Inconclusive => "is inconclusive regarding",
    };

    let human_flags = r
        .flags
        .iter()
        .filter(|f| f.signal == FlagSignal::Human)
        .count();
    let synthetic_flags = r
        .flags
        .iter()
        .filter(|f| f.signal == FlagSignal::Synthetic)
        .count();

    let duration_desc = if r.total_duration_min < 1.0 {
        "less than one minute".to_string()
    } else if r.total_duration_min < 60.0 {
        format!("approximately {:.0} minutes", r.total_duration_min)
    } else {
        let hours = r.total_duration_min / 60.0;
        format!("approximately {:.1} hours", hours)
    };

    let keystrokes_desc = r
        .process
        .total_keystrokes
        .map(|k| format!(", with {} keystrokes captured", format_number(k)))
        .unwrap_or_default();

    let checkpoint_desc = if r.checkpoints.is_empty() {
        String::new()
    } else {
        format!(
            " {} cryptographic checkpoints were recorded and verified.",
            r.checkpoints.len()
        )
    };

    let flag_desc = if synthetic_flags > 0 {
        format!(
            " The analysis identified {} behavioral indicator{} consistent with human authorship \
             and {} indicator{} of potential synthetic generation.",
            human_flags,
            if human_flags == 1 { "" } else { "s" },
            synthetic_flags,
            if synthetic_flags == 1 { "" } else { "s" },
        )
    } else if human_flags > 0 {
        format!(
            " The analysis identified {} behavioral indicator{} consistent with human authorship \
             and no indicators of synthetic generation.",
            human_flags,
            if human_flags == 1 { "" } else { "s" },
        )
    } else {
        String::new()
    };

    write!(
        html,
        r#"<div class="executive-summary">
<p>Based on forensic examination of the submitted document, the evidence {strength} the proposition that the text was composed through a human writing process. The document was produced across {sessions} writing session{s_plural} spanning {duration}{keystrokes}.{checkpoints}{flags}</p>
</div>
"#,
        sessions = r.session_count,
        s_plural = if r.session_count == 1 { "" } else { "s" },
        duration = duration_desc,
        keystrokes = keystrokes_desc,
        checkpoints = checkpoint_desc,
        flags = flag_desc,
    )
}

// ---------------------------------------------------------------------------
// Declaration of Findings
// ---------------------------------------------------------------------------

pub(super) fn write_verdict(html: &mut String, r: &WarReport) -> fmt::Result {
    let color = sanitize_css_color(r.verdict.css_color());
    let lr_display = format_lr(r.likelihood_ratio);
    section_heading(html, 1, SEC_DECLARATION)?;
    write!(
        html,
        r#"<div class="declaration" style="border-color:{color}">
  <div class="declaration-header">Examiner's Determination</div>
  <div class="declaration-body">
    <div class="declaration-score" style="color:{color}">{score}<small>of 100</small></div>
    <div class="declaration-text">
      <div class="verdict-label" style="color:{color}">{label}</div>
      <p>{desc}</p>
    </div>
    <div class="declaration-lr">
      <div class="lr-value">{lr}</div>
      <div class="lr-label">Likelihood Ratio</div>
      <div class="lr-tier">{tier}</div>
    </div>
  </div>
</div>
"#,
        score = r.score,
        label = r.verdict.label(),
        desc = html_escape(&r.verdict_description),
        lr = lr_display,
        tier = r.enfsi_tier.label(),
    )
}

pub(super) fn write_enfsi_scale(html: &mut String, r: &WarReport) -> fmt::Result {
    let tiers = [
        ("enfsi-against", "&lt;1 Against", EnfsiTier::Against),
        ("enfsi-weak", "1\u{2013}10 Weak", EnfsiTier::Weak),
        (
            "enfsi-moderate",
            "10\u{2013}100 Moderate",
            EnfsiTier::Moderate,
        ),
        (
            "enfsi-modstrong",
            "10\u{00b2}\u{2013}10\u{00b3} Mod. Strong",
            EnfsiTier::ModeratelyStrong,
        ),
        (
            "enfsi-strong",
            "10\u{00b3}\u{2013}10\u{2074} Strong",
            EnfsiTier::Strong,
        ),
        (
            "enfsi-vstrong",
            "\u{2265}10\u{2074} Very Strong",
            EnfsiTier::VeryStrong,
        ),
    ];
    write!(
        html,
        r#"<p class="enfsi-label">ENFSI Verbal Equivalence Scale (per ENFSI Guideline for Evaluative Reporting, 2015):</p>
<div class="enfsi-scale">"#
    )?;
    for (class, label, tier) in &tiers {
        let active = if *tier == r.enfsi_tier {
            " enfsi-active"
        } else {
            ""
        };
        write!(html, r#"<span class="{class}{active}">{label}</span>"#)?;
    }
    writeln!(html, "</div>")
}

pub(super) fn write_lr_interpretation(html: &mut String, r: &WarReport) -> fmt::Result {
    let lr = r.likelihood_ratio;
    if !lr.is_finite() || lr <= 0.0 {
        return Ok(());
    }

    let interpretation = if lr >= 1.0 {
        format!(
            "The observed behavioral evidence is approximately <strong>{}</strong> times more \
             probable under the hypothesis that the document was composed through a human writing \
             process (H\u{2081}) than under the hypothesis that it was generated or substantially \
             produced by automated means (H\u{2082}). On the ENFSI verbal equivalence scale, \
             this constitutes <strong>{}</strong> the proposition of human authorship.",
            format_lr(lr),
            r.enfsi_tier.label().to_lowercase(),
        )
    } else {
        format!(
            "The observed behavioral evidence is approximately <strong>{:.2}</strong> times as \
             probable under the hypothesis of human authorship (H\u{2081}) as under the \
             alternative (H\u{2082}). An LR below 1.0 means the evidence favors the alternative \
             hypothesis. On the ENFSI scale, this constitutes evidence <strong>against</strong> \
             the proposition of human authorship.",
            lr,
        )
    };

    write!(
        html,
        r#"<div class="lr-interpretation"><strong>Interpretation:</strong> {interpretation}</div>"#,
    )
}

pub(super) fn write_key_findings(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(html, r#"<ol class="key-findings">"#)?;

    // Duration and session count
    write!(
        html,
        "<li><strong>Writing duration:</strong> {} session{}, {:.0} minutes of active composition, \
         {} revision events recorded.</li>",
        r.session_count,
        if r.session_count == 1 { "" } else { "s" },
        r.total_duration_min,
        format_number(r.revision_events),
    )?;

    // Keystroke capture
    if let Some(ks) = r.process.total_keystrokes {
        write!(
            html,
            "<li><strong>Keystroke capture:</strong> {} keystrokes recorded with timing data.",
            format_number(ks),
        )?;
        if let Some(cv) = r.process.iki_cv {
            write!(
                html,
                " Inter-keystroke interval CV of {:.2} {}.",
                cv,
                if cv > 0.3 {
                    "indicates variable, human-like typing rhythm"
                } else if cv > 0.15 {
                    "is within normal range for focused typing"
                } else {
                    "is unusually uniform and may warrant further review"
                },
            )?;
        }
        write!(html, "</li>")?;
    }

    // Checkpoints
    if !r.checkpoints.is_empty() {
        let verified = if r.process.swf_chain_verified {
            "integrity verified"
        } else {
            "integrity unverified"
        };
        write!(
            html,
            "<li><strong>Cryptographic checkpoints:</strong> {} checkpoints in tamper-evident chain, {}.",
            r.checkpoints.len(),
            verified,
        )?;
        if let Some(hrs) = r.process.swf_backdating_hours {
            write!(
                html,
                " Backdating cost: ~{:.0} hours sequential computation.",
                hrs,
            )?;
        }
        write!(html, "</li>")?;
    }

    // Paste ratio
    if let Some(pr) = r.process.paste_ratio_pct {
        let assessment = if pr < 5.0 {
            "minimal paste activity, consistent with original composition"
        } else if pr < 20.0 {
            "moderate paste activity, within normal editing range"
        } else if pr < 50.0 {
            "elevated paste activity; may include quoted material or self-editing"
        } else {
            "high paste ratio; document may contain substantial externally-sourced content"
        };
        write!(
            html,
            "<li><strong>Paste analysis:</strong> {:.1}% of text entered via paste ({}).</li>",
            pr, assessment,
        )?;
    }

    // Dimension concordance
    if !r.dimensions.is_empty() {
        let below = r.dimensions.iter().filter(|d| d.score < 40).count();
        if below == 0 {
            write!(
                html,
                "<li><strong>Dimension concordance:</strong> All {} analytical dimensions support \
                 the composite determination. No contradictory signals detected.</li>",
                r.dimensions.len(),
            )?;
        } else {
            write!(
                html,
                "<li><strong>Dimension concordance:</strong> {} of {} dimensions scored below \
                 threshold, indicating potential anomalies in those areas.</li>",
                below,
                r.dimensions.len(),
            )?;
        }
    }

    writeln!(html, "</ol>")
}

// ---------------------------------------------------------------------------
// Methodology (with explicit hypotheses)
// ---------------------------------------------------------------------------

pub(super) fn write_methodology(html: &mut String, r: &WarReport) -> fmt::Result {
    section_heading(html, 2, SEC_METHODOLOGY)?;
    html.push_str(TMPL_METHODOLOGY);

    if let Some(ref m) = r.methodology {
        write!(
            html,
            r#"<div class="methodology-grid">
<div class="methodology-card"><h4>LR Computation</h4><p>{}</p></div>
<div class="methodology-card"><h4>Confidence Interval</h4><p>{}</p></div>
<div class="methodology-card"><h4>Calibration</h4><p>{}</p></div>
</div>"#,
            html_escape(&m.lr_computation),
            html_escape(&m.confidence_interval),
            html_escape(&m.calibration),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Chain of Evidence
// ---------------------------------------------------------------------------

pub(super) fn write_chain_of_custody(html: &mut String, r: &WarReport) -> fmt::Result {
    section_heading(html, 3, SEC_CHAIN)?;
    write!(
        html,
        r#"<p>The following identifiers establish the provenance and integrity of the evidence examined in this report. The document hash can be independently computed from the original file to confirm it matches the evidence record.</p>
<div class="info-box"><table>"#
    )?;

    row(html, "Document Hash (SHA-256)", &r.document_hash)?;
    row(html, "Signing Key Fingerprint", &r.signing_key_fingerprint)?;
    if let Some(ref did) = r.author_did {
        row(html, "Author DID", did)?;
    }

    let mut doc_len = String::new();
    if let Some(w) = r.document_words {
        write!(doc_len, "{} words", format_number(w))?;
    }
    if let Some(c) = r.document_chars {
        if !doc_len.is_empty() {
            doc_len.push_str("  |  ");
        }
        write!(doc_len, "{} characters", format_number(c))?;
    }
    if let Some(s) = r.document_sentences {
        if !doc_len.is_empty() {
            doc_len.push_str("  |  ");
        }
        write!(doc_len, "{} sentences", format_number(s))?;
    }
    if !doc_len.is_empty() {
        row(html, "Document Metrics", &doc_len)?;
    }

    let bundle = format!(
        "{} | {} session{} | {:.0} min total | {} revision events",
        r.evidence_bundle_version,
        r.session_count,
        if r.session_count == 1 { "" } else { "s" },
        r.total_duration_min,
        format_number(r.revision_events),
    );
    row(html, "Evidence Bundle", &bundle)?;
    row(html, "Device Attestation", &r.device_attestation)?;

    writeln!(html, "</table></div>")
}

// ---------------------------------------------------------------------------
// Content Provenance
// ---------------------------------------------------------------------------

pub(super) fn write_provenance_breakdown(html: &mut String, r: &WarReport) -> fmt::Result {
    let prov = match r.provenance_breakdown {
        Some(ref p) => p,
        None => return Ok(()),
    };

    write!(
        html,
        r#"<h3>Content Provenance</h3>
<p>Breakdown of content origin based on {} text fragment{} analyzed.</p>
<div class="info-box"><table>"#,
        prov.total_fragments,
        if prov.total_fragments == 1 { "" } else { "s" },
    )?;

    row(
        html,
        "Original Composition",
        &format!("{:.1}%", prov.original_composition_pct),
    )?;
    row(
        html,
        "Sourced (Verified)",
        &format!("{:.1}%", prov.sourced_verified_pct),
    )?;
    row(
        html,
        "Sourced (Unverified)",
        &format!("{:.1}%", prov.sourced_unknown_pct),
    )?;
    row(
        html,
        "Source Trust",
        &format!("{:.2}", prov.source_trustworthiness),
    )?;
    row(
        html,
        "Authenticity Score",
        &format!("{:.2}", prov.authenticity_score),
    )?;
    row(
        html,
        "Provenance Chain Depth",
        &format!("{}", prov.chain_depth),
    )?;

    writeln!(html, "</table></div>")?;

    if !prov.sources.is_empty() {
        write!(
            html,
            r#"<h4>Source Sessions</h4>
<div class="info-box"><table>
<tr><th>Session</th><th>App</th><th>Fragments</th><th>Verified</th></tr>"#
        )?;
        for src in &prov.sources {
            write!(
                html,
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(
                    src.session_id
                        .get(..16)
                        .unwrap_or(&src.session_id)
                ),
                html_escape(
                    src.app_bundle_id.as_deref().unwrap_or("unknown")
                ),
                src.fragment_count,
                if src.verified { "Yes" } else { "No" },
            )?;
        }
        writeln!(html, "</table></div>")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Category Scores + Writing Flow
// ---------------------------------------------------------------------------

pub(super) fn write_category_scores(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.dimensions.is_empty() {
        return Ok(());
    }
    write!(
        html,
        r#"<div class="category-scores"><div class="score-bars"><h3>Dimension Scores</h3>"#
    )?;
    for d in &r.dimensions {
        write!(
            html,
            r#"<div class="score-bar-row">
<span class="score-bar-label" style="color:{color}">{name}</span>
<div class="score-bar-track"><div class="score-bar-fill" style="width:{score}%;background:{color}"></div></div>
<span class="score-bar-value">{score}</span>
</div>"#,
            name = html_escape(&d.name),
            score = d.score.min(100),
            color = sanitize_css_color(&d.color),
        )?;
    }
    write_category_composite_note(html, r)?;
    write!(html, "</div>")?;

    if !r.writing_flow.is_empty() {
        write_writing_flow(html, r)?;
    }

    writeln!(html, "</div>")
}

fn write_category_composite_note(html: &mut String, r: &WarReport) -> fmt::Result {
    let all_pass = r.dimensions.iter().all(|d| d.score >= 60);
    let contradicts = r.dimensions.iter().any(|d| d.score < 40);
    if contradicts {
        write!(
            html,
            r#"<p class="composite-note">Note: One or more dimensions scored below the acceptance threshold, indicating potential anomalies requiring further examination.</p>"#,
        )
    } else if all_pass {
        write!(
            html,
            r#"<p class="composite-note">All dimensions exceed the minimum threshold of 60. No dimension contradicts the composite determination.</p>"#
        )
    } else {
        Ok(())
    }
}

fn write_writing_flow(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<div><h3>Writing Flow (Fig. 1)</h3><div class="flow-chart">"#
    )?;
    let max_intensity = r
        .writing_flow
        .iter()
        .map(|p| p.intensity)
        .fold(0.0_f64, f64::max)
        .max(0.01);
    for point in &r.writing_flow {
        let pct = (point.intensity / max_intensity * 100.0).min(100.0);
        let color = match point.phase.as_str() {
            "drafting" => "#3d7a4a",
            "revising" => "#2c5282",
            "polish" => "#5b3c8b",
            "pause" => "#d8d8d5",
            _ => "#6b6b6b",
        };
        write!(
            html,
            r#"<div class="flow-bar" style="height:{pct:.0}%;background:{color}"></div>"#
        )?;
    }
    write!(html, "</div>")?;
    if let (Some(first), Some(last)) = (r.writing_flow.first(), r.writing_flow.last()) {
        write!(
            html,
            r#"<div class="flow-labels"><span>{:.0}:00</span><span style="color:#3d7a4a">Drafting</span><span style="color:#d8d8d5">Pause</span><span style="color:#2c5282">Revising</span><span style="color:#5b3c8b">Polish</span><span>{:.0}:{:02.0}</span></div>"#,
            first.offset_min,
            last.offset_min as u64,
            ((last.offset_min % 1.0) * 60.0) as u64,
        )?;
    }
    write!(
        html,
        r#"<p class="flow-caption">Fig. 1: Keystroke intensity over time. Irregular cadence with natural pauses is characteristic of human cognitive processing; automated input typically produces uniform intensity without semantic-boundary pauses.</p>"#
    )?;
    write!(html, "</div>")
}

// ---------------------------------------------------------------------------
// Process Evidence (dynamic notes based on actual values)
// ---------------------------------------------------------------------------

pub(super) fn write_process_evidence(html: &mut String, r: &WarReport) -> fmt::Result {
    let p = &r.process;
    section_heading(html, 4, SEC_PROCESS)?;
    write!(
        html,
        r#"<p>The following metrics were captured by the CPoE proof daemon during the writing process. Each metric is derived from real-time behavioral observation and is cryptographically bound to the checkpoint chain (see Section 8).</p>
<div class="evidence-grid">"#
    )?;

    write_evidence_revision_intensity(html, p)?;
    write_evidence_pause_distribution(html, p)?;
    write_evidence_paste_ratio(html, p)?;
    write_evidence_keystroke_dynamics(html, p)?;
    write_evidence_deletion_patterns(html, p)?;
    write_evidence_swf(html, p)?;

    writeln!(html, "</div>")
}

fn write_evidence_revision_intensity(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit A: Revision Intensity</h4>"#
    )?;
    if let Some(ri) = p.revision_intensity {
        write!(
            html,
            r#"<div class="metric">{:.2} edits/sentence</div>"#,
            ri
        )?;
        let note = if ri > 2.0 {
            "Heavy revision activity; consistent with careful drafting and self-editing."
        } else if ri > 0.5 {
            "Moderate revision activity; within the expected range for natural composition."
        } else if ri > 0.1 {
            "Light revision activity; may indicate fluent single-pass writing or dictation."
        } else {
            "Minimal revision detected; atypical for multi-paragraph human composition."
        };
        write!(html, r#"<div class="note">{note}</div>"#)?;
    }
    if let Some(ref bl) = p.revision_baseline {
        write!(
            html,
            r#"<div class="note">Baseline: {}</div>"#,
            html_escape(bl)
        )?;
    }
    write!(html, "</div>")
}

fn write_evidence_pause_distribution(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit B: Pause Distribution</h4>"#
    )?;
    if let Some(med) = p.pause_median_sec {
        write!(html, r#"<div class="metric">Median: {:.1}s"#, med)?;
        if let Some(p95) = p.pause_p95_sec {
            write!(html, " | P95: {:.1}s", p95)?;
        }
        if let Some(max) = p.pause_max_sec {
            write!(html, " | Max: {:.0}s", max)?;
        }
        write!(html, "</div>")?;
        let note = if med > 0.5 && med < 5.0 {
            "Median pause duration falls within the range reported in published studies of human \
             composition (0.5-5.0s), consistent with cognitive planning between clauses."
        } else if med <= 0.5 {
            "Median pause duration is short; may indicate rapid transcription, dictation, \
             or highly rehearsed content."
        } else {
            "Median pause duration is long; may indicate deliberate composition, \
             research-interleaved writing, or multi-tasking."
        };
        write!(html, r#"<div class="note">{note}</div>"#)?;
    }
    write!(html, "</div>")
}

fn write_evidence_paste_ratio(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit C: Paste Analysis</h4>"#
    )?;
    if let Some(pr) = p.paste_ratio_pct {
        write!(html, r#"<div class="metric">{:.1}% of total text"#, pr)?;
        if let Some(ops) = p.paste_operations {
            write!(html, " ({} operations)", ops)?;
        }
        write!(html, "</div>")?;
        let note = if pr < 5.0 {
            "Minimal paste activity. Virtually all text was entered keystroke-by-keystroke, \
             strongly indicative of original composition."
        } else if pr < 20.0 {
            "Moderate paste activity, within the normal range for authors who self-edit \
             by cutting and rearranging their own text."
        } else if pr < 50.0 {
            "Elevated paste ratio. May include quoted material, references, or \
             restructuring of previously-typed content."
        } else {
            "High paste ratio. A substantial portion of the document was entered via paste. \
             This may indicate external sourcing and warrants further investigation."
        };
        write!(html, r#"<div class="note">{note}</div>"#)?;
    }
    if let Some(max) = p.paste_max_chars {
        write!(
            html,
            r#"<div class="note">Largest single paste: {} characters.</div>"#,
            format_number(max)
        )?;
    }
    write!(html, "</div>")
}

fn write_evidence_keystroke_dynamics(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit D: Keystroke Dynamics</h4>"#
    )?;
    if let Some(cv) = p.iki_cv {
        write!(html, r#"<div class="metric">IKI CV: {:.2}"#, cv)?;
        if let Some(bg) = p.bigram_consistency {
            write!(html, " | Bigram consistency: {:.2}", bg)?;
        }
        write!(html, "</div>")?;
        let note = if cv > 0.4 {
            "High inter-keystroke interval variability indicates natural, human-like typing \
             rhythm with variable cognitive load throughout the session."
        } else if cv > 0.2 {
            "Moderate IKI variability, within the normal range for focused human typing. \
             Behavioral fingerprint is consistent with single-author composition."
        } else if cv > 0.1 {
            "Low IKI variability. Typing rhythm is unusually regular, though still within \
             the range observed for skilled touch-typists on familiar material."
        } else {
            "Very low IKI variability. The typing rhythm is highly uniform, which is atypical \
             for human composition and more consistent with automated or replayed input."
        };
        write!(html, r#"<div class="note">{note}</div>"#)?;
    }
    if let Some(ks) = p.total_keystrokes {
        write!(
            html,
            r#"<div class="note">{} total keystrokes captured.</div>"#,
            format_number(ks)
        )?;
    }
    write!(html, "</div>")
}

fn write_evidence_deletion_patterns(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit E: Deletion Patterns</h4>"#
    )?;
    if let Some(ds) = p.deletion_sequences {
        write!(
            html,
            r#"<div class="metric">{} sequences"#,
            format_number(ds)
        )?;
        if let Some(avg) = p.avg_deletion_length {
            write!(html, " | Avg {:.1} chars", avg)?;
        }
        if let Some(sd) = p.select_delete_ops {
            write!(html, " | {} select-delete ops", sd)?;
        }
        write!(html, "</div>")?;
        let note = if let Some(avg) = p.avg_deletion_length {
            if avg < 3.0 {
                "Short deletion sequences (1-3 characters) indicate real-time typo correction, \
                 a hallmark of keystroke-level human composition."
            } else if avg < 10.0 {
                "Mixed short and medium deletions suggest both typo correction and \
                 word/phrase-level revision during composition."
            } else {
                "Long average deletion length may indicate structural revision or \
                 paragraph-level rewriting."
            }
        } else {
            "Deletion sequences detected, indicating iterative refinement during composition."
        };
        write!(html, r#"<div class="note">{note}</div>"#)?;
    }
    write!(html, "</div>")
}

fn write_evidence_swf(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit F: Verifiable Delay Functions</h4>"#
    )?;
    if let Some(count) = p.swf_checkpoints {
        write!(
            html,
            r#"<div class="metric">{} checkpoints"#,
            format_number(count)
        )?;
        if let Some(avg) = p.swf_avg_compute_ms {
            write!(html, " | {:.0}ms avg compute", avg)?;
        }
        let verified = if p.swf_chain_verified {
            "Verified"
        } else {
            "Unverified"
        };
        write!(html, " | Chain: {}", verified)?;
        write!(html, "</div>")?;
    }
    if let Some(hrs) = p.swf_backdating_hours {
        write!(
            html,
            r#"<div class="note">Each checkpoint contains a VDF proof that required real wall-clock time to compute. \
            Fabricating this evidence chain after the fact would require approximately {:.0} hours of sequential computation, \
            making backdating computationally infeasible for practical purposes.</div>"#,
            hrs
        )?;
    } else {
        write!(
            html,
            r#"<div class="note">VDF checkpoints provide cryptographic proof that writing occurred over real elapsed time. \
            The sequential nature of VDF computation prevents after-the-fact fabrication.</div>"#
        )?;
    }
    write!(html, "</div>")
}

// ---------------------------------------------------------------------------
// Session Timeline
// ---------------------------------------------------------------------------

pub(super) fn write_session_timeline(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.sessions.is_empty() {
        return Ok(());
    }
    section_heading(html, 5, SEC_TIMELINE)?;
    writeln!(
        html,
        r#"<p>The document was composed across {} session{}, totaling approximately {:.0} minutes of active writing time.</p>"#,
        r.session_count,
        if r.session_count == 1 { "" } else { "s" },
        r.total_duration_min,
    )?;
    for s in &r.sessions {
        write!(
            html,
            r#"<div class="session-box">
<h4>Session {idx} &mdash; {dur:.0} min</h4>
<p>{start} &ensp;|&ensp; {events} events &ensp;|&ensp; {summary}</p>
</div>
"#,
            idx = s.index,
            dur = s.duration_min,
            start = s.start.format("%B %-d, %Y %H:%M UTC"),
            events = s.event_count,
            summary = html_escape(&s.summary),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Dimension Analysis
// ---------------------------------------------------------------------------

pub(super) fn write_dimension_analysis(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.dimensions.is_empty() {
        return Ok(());
    }
    section_heading(html, 6, SEC_DIMENSIONS)?;
    writeln!(
        html,
        r#"<p>Each analytical dimension is evaluated independently against both H\u{{2081}} and H\u{{2082}}. \
The per-dimension scores and likelihood ratios below contribute to the composite determination in Section 1.</p>"#
    )?;
    for d in &r.dimensions {
        if d.analysis.is_empty() {
            continue;
        }
        write!(
            html,
            r#"<div class="dimension-card">
<h3 style="color:{color}">{name}</h3>
<div class="dimension-badge" style="background:{color}">{score}</div>
"#,
            name = html_escape(&d.name),
            score = d.score,
            color = sanitize_css_color(&d.color),
        )?;
        for detail in &d.analysis {
            write!(
                html,
                r#"<p class="dimension-detail"><strong>{}:</strong> {}</p>"#,
                html_escape(&detail.label),
                html_escape(&detail.text),
            )?;
        }
        writeln!(html, "</div>")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Statistical Analysis (LR table)
// ---------------------------------------------------------------------------

pub(super) fn write_dimension_lr_table(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.dimensions.is_empty() {
        return Ok(());
    }
    section_heading(html, 7, SEC_STATISTICS)?;
    writeln!(
        html,
        r#"<p>The likelihood ratio (LR) quantifies the evidential weight of each dimension. An LR greater than 1 supports H\u{{2081}} \
(human authorship); an LR less than 1 supports H\u{{2082}} (automated generation). The log<sub>10</sub>(LR) is provided \
for comparison with published forensic scales. See the Glossary (Section 15) for term definitions.</p>"#
    )?;
    write!(
        html,
        r#"<table class="data"><thead><tr><th>Dimension</th><th>Score</th><th>LR</th><th>Log<sub>10</sub> LR</th><th>Confidence</th><th>Key Discriminator</th></tr></thead><tbody>"#
    )?;
    for d in &r.dimensions {
        let conf_pct = (d.confidence * 100.0).min(100.0);
        write!(
            html,
            r#"<tr><td style="color:{color};font-weight:600">{name}</td><td>{score}</td><td>{lr}</td><td>{log_lr:.2}</td><td><div class="confidence-bar" style="width:{conf_pct:.0}px;background:{color}"></div></td><td>{disc}</td></tr>"#,
            name = html_escape(&d.name),
            score = d.score,
            lr = format_lr(d.lr),
            log_lr = d.log_lr,
            conf_pct = conf_pct,
            color = sanitize_css_color(&d.color),
            disc = html_escape(&d.key_discriminator),
        )?;
    }
    let combined_log = if r.likelihood_ratio > 0.0 {
        r.likelihood_ratio.log10()
    } else {
        0.0
    };
    write!(
        html,
        r#"</tbody><tfoot><tr style="font-weight:700;border-top:2px solid var(--rule)"><td>Combined</td><td>{score}</td><td>{lr}</td><td>{log_lr:.2}</td><td><div class="confidence-bar" style="width:{conf_pct:.0}px;background:#1a4d2e"></div></td><td>All dimensions concordant</td></tr></tfoot>"#,
        score = r.score,
        lr = format_lr(r.likelihood_ratio),
        log_lr = combined_log,
        conf_pct = (r.score as f64).min(100.0),
    )?;
    writeln!(html, "</table>")
}

// ---------------------------------------------------------------------------
// Checkpoint Chain Integrity
// ---------------------------------------------------------------------------

pub(super) fn write_checkpoint_chain(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.checkpoints.is_empty() {
        return Ok(());
    }
    section_heading(html, 8, SEC_CHECKPOINTS)?;
    writeln!(
        html,
        r#"<p>Each checkpoint records a cryptographic hash of the document state at a point in time. The chain is linked by including \
the previous checkpoint's hash in each successive entry, forming a tamper-evident log. Any modification to a checkpoint \
invalidates all subsequent entries, making undetected alteration computationally infeasible.</p>"#
    )?;
    write!(
        html,
        r#"<table class="data"><thead><tr><th>#</th><th>Timestamp</th><th>Content Hash (SHA-256)</th><th>Size</th><th>VDF Iterations</th><th>Elapsed</th></tr></thead><tbody>"#
    )?;
    for cp in &r.checkpoints {
        let hash_short = if cp.content_hash.len() > 16 {
            format!(
                "{}...{}",
                cp.content_hash.get(..8).unwrap_or(&cp.content_hash),
                cp.content_hash
                    .get(cp.content_hash.len().saturating_sub(8)..)
                    .unwrap_or(&cp.content_hash),
            )
        } else {
            cp.content_hash.clone()
        };
        let vdf = cp
            .vdf_iterations
            .map(format_number)
            .unwrap_or_else(|| "\u{2014}".into());
        let elapsed = cp
            .elapsed_ms
            .map(|ms| format!("{:.1}s", ms as f64 / 1000.0))
            .unwrap_or_else(|| "\u{2014}".into());
        write!(
            html,
            "<tr><td>{ord}</td><td>{ts}</td><td><code>{hash}</code></td><td>{size}</td><td>{vdf}</td><td>{elapsed}</td></tr>",
            ord = cp.ordinal,
            ts = cp.timestamp.format("%H:%M:%S UTC"),
            hash = hash_short,
            size = format_bytes(cp.content_size),
        )?;
    }
    writeln!(html, "</tbody></table>")
}

// ---------------------------------------------------------------------------
// Forgery Resistance
// ---------------------------------------------------------------------------

pub(super) fn write_forgery_resistance(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.forgery.components.is_empty() {
        return Ok(());
    }
    section_heading(html, 9, SEC_FORGERY)?;
    writeln!(
        html,
        r#"<p>The following analysis estimates the computational cost an adversary would incur to fabricate evidence equivalent to \
that presented in this report. Higher costs indicate stronger resistance to forgery.</p>"#
    )?;
    write!(html, r#"<div class="info-box"><table>"#)?;
    row(html, "Resistance Tier", &r.forgery.tier)?;
    let forge_time = format_duration_human(r.forgery.estimated_forge_time_sec);
    row(html, "Estimated Forge Time", &forge_time)?;
    if let Some(ref weak) = r.forgery.weakest_link {
        row(html, "Weakest Component", weak)?;
    }
    writeln!(html, "</table></div>")?;

    write!(
        html,
        r#"<table class="data"><thead><tr><th>Component</th><th>Present</th><th>CPU Cost</th><th>Explanation</th></tr></thead><tbody>"#
    )?;
    for c in &r.forgery.components {
        let present = if c.present {
            r#"<span style="color:var(--accent)">&#10003; Yes</span>"#
        } else {
            r#"<span style="color:var(--alert)">&#10007; No</span>"#
        };
        let cost = if c.cost_cpu_sec.is_infinite() {
            "Computationally infeasible".to_string()
        } else {
            format_duration_human(c.cost_cpu_sec)
        };
        write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&c.name),
            present,
            cost,
            html_escape(&c.explanation),
        )?;
    }
    writeln!(html, "</tbody></table>")
}

// ---------------------------------------------------------------------------
// Analysis Flags
// ---------------------------------------------------------------------------

pub(super) fn write_flags(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.flags.is_empty() {
        return Ok(());
    }
    let pos = r
        .flags
        .iter()
        .filter(|f| f.signal == FlagSignal::Human)
        .count();
    let neg = r
        .flags
        .iter()
        .filter(|f| f.signal == FlagSignal::Synthetic)
        .count();
    write!(
        html,
        r#"<h2><span class="section-number">10.</span> {} ({} human, {} synthetic)</h2>"#,
        SEC_FLAGS, pos, neg
    )?;
    writeln!(
        html,
        r#"<p>The following behavioral signals were detected during analysis. Human indicators corroborate H\u{{2081}}; \
synthetic indicators, if present, corroborate H\u{{2082}} and may warrant further investigation.</p>"#
    )?;
    write!(
        html,
        r#"<table class="data"><thead><tr><th>Category</th><th>Finding</th><th>Detail</th><th>Signal</th></tr></thead><tbody>"#
    )?;
    for f in &r.flags {
        let class = match f.signal {
            FlagSignal::Human => "flag-human",
            FlagSignal::Synthetic => "flag-synthetic",
            FlagSignal::Neutral => "flag-neutral",
        };
        let icon = match f.signal {
            FlagSignal::Human => "&#10003;",
            FlagSignal::Synthetic => "&#10007;",
            FlagSignal::Neutral => "&mdash;",
        };
        write!(
            html,
            r#"<tr><td>{cat}</td><td>{flag}</td><td>{detail}</td><td class="{class}">{icon} {label}</td></tr>"#,
            cat = html_escape(&f.category),
            flag = html_escape(&f.flag),
            detail = html_escape(&f.detail),
            label = f.signal.label(),
        )?;
    }
    writeln!(html, "</tbody></table>")
}

// ---------------------------------------------------------------------------
// Scope, Limitations, Admissibility
// ---------------------------------------------------------------------------

pub(super) fn write_scope(html: &mut String, r: &WarReport) -> fmt::Result {
    section_heading(html, 11, SEC_SCOPE)?;
    html.push_str(TMPL_SCOPE);

    if !r.limitations.is_empty() {
        write!(
            html,
            r#"<h3>Additional Limitations Specific to This Examination:</h3><ul>"#
        )?;
        for lim in &r.limitations {
            write!(html, "<li>{}</li>", html_escape(lim))?;
        }
        writeln!(html, "</ul>")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Analyzed Text
// ---------------------------------------------------------------------------

pub(super) fn write_analyzed_text(html: &mut String, r: &WarReport) -> fmt::Result {
    if let Some(ref text) = r.analyzed_text {
        section_heading(html, 12, SEC_TEXT)?;
        write!(
            html,
            r#"<p>The following text was submitted for examination. Its SHA-256 hash has been verified against the chain-of-evidence record in Section 3.</p>
<div class="analyzed-text">{}</div>
"#,
            html_escape(text)
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verification Instructions
// ---------------------------------------------------------------------------

pub(super) fn write_verification_instructions(html: &mut String) -> fmt::Result {
    section_heading(html, 13, SEC_VERIFY)?;
    html.push_str(TMPL_VERIFICATION);
    Ok(())
}

// ---------------------------------------------------------------------------
// Glossary
// ---------------------------------------------------------------------------

pub(super) fn write_glossary(html: &mut String) -> fmt::Result {
    section_heading(html, 14, SEC_GLOSSARY)?;
    html.push_str(TMPL_GLOSSARY);
    Ok(())
}

// ---------------------------------------------------------------------------
// Embedded Evidence (self-verifying artifact)
// ---------------------------------------------------------------------------

pub(super) fn write_embedded_evidence(html: &mut String, r: &WarReport) -> fmt::Result {
    if let Some(ref b64) = r.evidence_cbor_b64 {
        writeln!(
            html,
            r#"<script type="application/vnd.writerslogic.cpoe+cbor">{}</script>"#,
            html_escape(b64),
        )?;
    }
    if let Some(ref vc_json) = r.verifiable_credential_json {
        writeln!(
            html,
            r#"<script type="application/ld+json">{}</script>"#,
            html_escape(vc_json),
        )?;
    }
    Ok(())
}

pub(super) fn write_verifiable_credential(html: &mut String, r: &WarReport) -> fmt::Result {
    let vc_json = match r.verifiable_credential_json {
        Some(ref j) => j,
        None => return Ok(()),
    };

    // Parse the VC to extract structured fields for display.
    let vc: serde_json::Value = match serde_json::from_str(vc_json) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    html.push_str(r#"<div class="info-box" style="margin-top:16px">"#);
    html.push_str(r#"<h3 style="margin:0 0 8px">W3C Verifiable Credential 2.0</h3>"#);
    html.push_str(
        "<p style=\"font-size:var(--size-detail);margin:0 0 8px\">\
         This report includes a signed W3C Verifiable Credential that can be \
         independently verified using any VC 2.0 compliant verifier.</p>",
    );

    // Credential identity table
    html.push_str(r#"<table class="data-table" style="margin:8px 0">"#);
    if let Some(issuer) = vc["issuer"].as_str() {
        write!(
            html,
            "<tr><td style=\"font-weight:600;width:180px\">Issuer</td>\
             <td><code>{}</code></td></tr>",
            html_escape(issuer)
        )?;
    }
    if let Some(subject_id) = vc["credentialSubject"]["id"].as_str() {
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Subject (Author DID)</td>\
             <td><code>{}</code></td></tr>",
            html_escape(subject_id)
        )?;
    }
    if let Some(valid_from) = vc["validFrom"].as_str() {
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Valid From</td>\
             <td>{}</td></tr>",
            html_escape(valid_from)
        )?;
    }
    if let Some(status) = vc["credentialSubject"]["processAttestation"]["status"].as_str() {
        let badge_color = match status {
            "affirming" => "#3d7a4a",
            "warning" => "#b45309",
            "contraindicated" => "#b71c1c",
            _ => "#666",
        };
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Attestation Status</td>\
             <td><span style=\"background:{};color:#fff;padding:2px 8px;\
             border-radius:2px;font-size:10px;font-weight:700;\
             text-transform:uppercase\">{}</span></td></tr>",
            badge_color,
            html_escape(status)
        )?;
    }
    if let Some(tier) = vc["credentialSubject"]["processAttestation"]["attestationTier"].as_str() {
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Attestation Tier</td>\
             <td>{}</td></tr>",
            html_escape(tier)
        )?;
    }
    if let Some(dur) = vc["credentialSubject"]["processAttestation"]["chainDuration"].as_str() {
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Chain Duration</td>\
             <td>{}</td></tr>",
            html_escape(dur)
        )?;
    }
    if let Some(doc_ref) = vc["credentialSubject"]["processAttestation"]["documentRef"].as_str() {
        let short = if doc_ref.len() > 16 {
            format!("{}...{}", &doc_ref[..8], &doc_ref[doc_ref.len() - 8..])
        } else {
            doc_ref.to_string()
        };
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Document Reference</td>\
             <td><code>{}</code></td></tr>",
            html_escape(&short)
        )?;
    }

    // Proof info
    if let Some(proof) = vc.get("proof") {
        if let Some(suite) = proof["cryptosuite"].as_str() {
            write!(
                html,
                "<tr><td style=\"font-weight:600\">Proof Type</td>\
                 <td>DataIntegrityProof ({}) \
                 <span style=\"color:#3d7a4a;font-weight:700\">&#x2713; Signed</span></td></tr>",
                html_escape(suite)
            )?;
        }
        if let Some(vm) = proof["verificationMethod"].as_str() {
            write!(
                html,
                "<tr><td style=\"font-weight:600\">Verification Method</td>\
                 <td><code style=\"font-size:10px\">{}</code></td></tr>",
                html_escape(vm)
            )?;
        }
    }
    html.push_str("</table>");

    // Trust vector visualization if present
    if let Some(tv) = vc["credentialSubject"]["processAttestation"]["trustVector"].as_object() {
        html.push_str(r#"<h4 style="margin:12px 0 6px;font-size:12px">AR4SI Trust Vector</h4>"#);
        html.push_str(r#"<div class="metric-grid">"#);
        for (key, val) in tv {
            let v = val.as_i64().unwrap_or(0);
            let (label, color) = match v as i8 {
                2 => ("Affirming", "#3d7a4a"),
                32 => ("Warning", "#b45309"),
                96 => ("Contraindicated", "#b71c1c"),
                _ => ("None", "#999"),
            };
            let mut display_key = String::with_capacity(key.len());
            let mut capitalize_next = true;
            for ch in key.chars() {
                if ch == '_' || ch == ' ' {
                    display_key.push(' ');
                    capitalize_next = true;
                } else if capitalize_next {
                    display_key.extend(ch.to_uppercase());
                    capitalize_next = false;
                } else {
                    display_key.push(ch);
                }
            }
            write!(
                html,
                r#"<div class="metric-card"><div class="metric-label">{}</div><div class="metric-value" style="color:{}">{}</div></div>"#,
                html_escape(&display_key),
                color,
                label,
            )?;
        }
        html.push_str("</div>");
    }

    // Collapsible raw JSON
    html.push_str(
        r#"<details style="margin-top:10px"><summary style="cursor:pointer;font-weight:600;font-size:12px">Raw Credential JSON-LD</summary>"#,
    );
    write!(
        html,
        r#"<pre style="font-size:10px;max-height:300px;overflow:auto;background:var(--bg-card);padding:10px;border:1px solid var(--border);margin-top:6px">{}</pre>"#,
        html_escape(vc_json),
    )?;
    html.push_str("</details></div>");
    Ok(())
}

// ---------------------------------------------------------------------------
// Forensic Breakdown
// ---------------------------------------------------------------------------

pub(super) fn write_forensic_breakdown(html: &mut String, r: &WarReport) -> fmt::Result {
    let fm = match r.forensic_metrics {
        Some(ref m) => m,
        None => return Ok(()),
    };

    write!(html, r#"<h3>Forensic Breakdown</h3>"#)?;

    // Writing mode badge
    let badge_color = match fm.writing_mode.as_str() {
        "cognitive" => "#3d7a4a",
        "transcriptive" => "#b45309",
        _ => "#2c5282",
    };
    write!(
        html,
        r#"<p><strong>Writing Mode:</strong> <span style="display:inline-block;background:{color};color:#fff;font-family:var(--sans);font-size:10px;font-weight:700;padding:2px 8px;border-radius:2px;letter-spacing:0.5px;text-transform:uppercase">{mode}</span> <span style="color:var(--text-muted);font-size:12px">(confidence: {conf:.0}%)</span></p>"#,
        color = badge_color,
        mode = html_escape(&fm.writing_mode),
        conf = finite_or(fm.writing_mode_confidence * 100.0, 0.0),
    )?;

    // Cognitive score gauge
    let cog_pct = finite_or(fm.cognitive_score * 100.0, 0.0).clamp(0.0, 100.0);
    let cog_color = if cog_pct >= 60.0 {
        "#3d7a4a"
    } else if cog_pct >= 30.0 {
        "#b45309"
    } else {
        "#b71c1c"
    };
    write!(
        html,
        r#"<p style="font-size:12px;margin-bottom:2px"><strong>Cognitive Score:</strong> {cog:.0}/100</p>
<div class="writing-gauge"><div class="writing-gauge-fill" style="width:{cog:.0}%;background:{color}"></div></div>"#,
        cog = cog_pct,
        color = cog_color,
    )?;

    // Cadence metrics grid
    write!(html, r#"<div class="metric-grid">"#)?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Mean IKI</div><div class="metric-value">{:.0} ms</div></div>"#,
        finite_or(fm.mean_iki_ms, 0.0),
    )?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Coefficient of Variation</div><div class="metric-value">{:.3}</div></div>"#,
        finite_or(fm.coefficient_of_variation, 0.0),
    )?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Burst Count</div><div class="metric-value">{}</div></div>"#,
        fm.burst_count,
    )?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Pause Count</div><div class="metric-value">{}</div></div>"#,
        fm.pause_count,
    )?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Correction Ratio</div><div class="metric-value">{:.3}</div></div>"#,
        finite_or(fm.correction_ratio, 0.0),
    )?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Burst Speed CV</div><div class="metric-value">{:.3}</div></div>"#,
        finite_or(fm.burst_speed_cv, 0.0),
    )?;
    write!(html, r#"</div>"#)?;

    // Hurst exponent
    if let Some(h) = fm.hurst_exponent.filter(|v| v.is_finite()) {
        let interp = if h < 0.5 {
            "anti-persistent (mean-reverting)"
        } else if h < 0.6 {
            "approximately random"
        } else if h < 0.8 {
            "long-range dependent (human-like)"
        } else {
            "highly persistent (deterministic)"
        };
        write!(
            html,
            r#"<p style="font-size:12.5px;margin:8px 0"><strong>Hurst Exponent:</strong> {:.3} ({interp})</p>"#,
            h,
        )?;
    }

    // Pause depth stacked bar
    let d = &fm.pause_depth;
    let total = d[0] + d[1] + d[2];
    if total > 0.0 {
        let s_pct = d[0] / total * 100.0;
        let p_pct = d[1] / total * 100.0;
        let t_pct = d[2] / total * 100.0;
        write!(
            html,
            r#"<p style="font-size:12.5px;margin:8px 0 2px"><strong>Pause Depth Distribution:</strong></p>
<div class="pause-depth-bar">
<div class="pause-depth-seg" style="width:{s:.1}%;background:#b45309" title="Sentence: {s:.1}%"></div>
<div class="pause-depth-seg" style="width:{p:.1}%;background:#2c5282" title="Paragraph: {p:.1}%"></div>
<div class="pause-depth-seg" style="width:{t:.1}%;background:#5b3c8b" title="Deep thought: {t:.1}%"></div>
</div>
<p style="font-size:11px;color:var(--text-muted)"><span style="color:#b45309">Sentence {s:.0}%</span> | <span style="color:#2c5282">Paragraph {p:.0}%</span> | <span style="color:#5b3c8b">Deep thought {t:.0}%</span></p>"#,
            s = s_pct,
            p = p_pct,
            t = t_pct,
        )?;
    }

    // Assessment + risk + throughput
    let risk_color = match fm.risk_level.as_str() {
        "Low" => "#3d7a4a",
        "Medium" => "#b45309",
        _ => "#b71c1c",
    };
    write!(
        html,
        r#"<p style="font-size:12.5px;margin:8px 0"><strong>Assessment:</strong> {score:.0}/100 | <strong>Risk:</strong> <span style="color:{color};font-weight:600">{risk}</span> | <strong>Revision Cycles:</strong> {rev}</p>
<p style="font-size:12.5px;margin:4px 0"><strong>Throughput:</strong> {mean:.1} mean BPS, {max:.1} max BPS</p>"#,
        score = finite_or(fm.assessment_score * 100.0, 0.0),
        color = risk_color,
        risk = html_escape(&fm.risk_level),
        rev = fm.revision_cycle_count,
        mean = finite_or(fm.mean_bps, 0.0),
        max = finite_or(fm.max_bps, 0.0),
    )
}

// ---------------------------------------------------------------------------
// Edit Topology
// ---------------------------------------------------------------------------

pub(super) fn write_edit_topology(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.edit_topology.is_empty() {
        return Ok(());
    }

    write!(html, r#"<h3>Edit Topology</h3>"#)?;

    // Accumulate edits into 20 bins
    let mut bins_ins = [0i64; 20];
    let mut bins_del = [0i64; 20];
    for region in &r.edit_topology {
        let start_bin = ((region.start_pct / 100.0 * 20.0).floor() as usize).min(19);
        let end_bin = ((region.end_pct / 100.0 * 20.0).ceil() as usize).min(20);
        for b in start_bin..end_bin {
            if region.delta_sign > 0 {
                bins_ins[b] += region.byte_count.unsigned_abs() as i64;
            } else if region.delta_sign < 0 {
                bins_del[b] += region.byte_count.unsigned_abs() as i64;
            }
        }
    }

    let max_val = bins_ins
        .iter()
        .chain(bins_del.iter())
        .copied()
        .max()
        .unwrap_or(1)
        .max(1);

    write!(html, r#"<div class="topology-bar">"#)?;
    for i in 0..20 {
        let ins = bins_ins[i];
        let del = bins_del[i];
        let dominant = if ins >= del { ins } else { del };
        let opacity = (dominant as f64 / max_val as f64 * 0.9 + 0.1).min(1.0);
        let color = if ins >= del { "#3d7a4a" } else { "#b71c1c" };
        write!(
            html,
            r#"<div class="topology-segment" style="flex:1;background:{color};opacity:{op:.2}"></div>"#,
            color = color,
            op = opacity,
        )?;
    }
    write!(html, "</div>")?;
    write!(
        html,
        r#"<p style="font-size:11px;color:var(--text-muted)">{} edit regions across the document. <span style="color:#3d7a4a">Green = insertions</span>, <span style="color:#b71c1c">red = deletions</span>.</p>"#,
        r.edit_topology.len(),
    )
}

// ---------------------------------------------------------------------------
// Activity Contexts
// ---------------------------------------------------------------------------

pub(super) fn write_activity_contexts(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.activity_contexts.is_empty() {
        return Ok(());
    }

    write!(html, r#"<h3>Activity Contexts</h3>"#)?;

    let total_min: f64 = r.activity_contexts.iter().map(|a| a.duration_min).sum();
    if total_min <= 0.0 {
        return Ok(());
    }

    // Timeline bar
    write!(html, r#"<div class="context-timeline">"#)?;
    for ctx in &r.activity_contexts {
        let pct = ctx.duration_min / total_min * 100.0;
        let color = match ctx.period_type.as_str() {
            "focused" => "#3d7a4a",
            "break" => "#999",
            "research" => "#2c5282",
            "revision" => "#e65100",
            "assisted" => "#7b1fa2",
            "external" => "#b71c1c",
            "idle" => "#ddd",
            _ => "#6b6b6b",
        };
        write!(
            html,
            r#"<div class="context-segment" style="flex:{pct:.2};background:{color}"></div>"#,
        )?;
    }
    write!(html, "</div>")?;

    // Legend
    let types = [
        ("focused", "#3d7a4a"),
        ("break", "#999"),
        ("research", "#2c5282"),
        ("revision", "#e65100"),
        ("assisted", "#7b1fa2"),
        ("external", "#b71c1c"),
        ("idle", "#ddd"),
    ];
    write!(html, r#"<div class="context-legend">"#)?;
    for (label, color) in &types {
        let present = r.activity_contexts.iter().any(|a| a.period_type == *label);
        if present {
            write!(
                html,
                r#"<span class="context-legend-item"><span class="context-legend-swatch" style="background:{color}"></span>{label}</span>"#,
            )?;
        }
    }
    write!(html, "</div>")?;

    // Summary table
    write!(
        html,
        r#"<table class="data" style="margin-top:10px"><thead><tr><th>Type</th><th>Duration</th><th>Percentage</th></tr></thead><tbody>"#,
    )?;
    // Aggregate by type
    let mut agg: Vec<(String, f64)> = Vec::new();
    for ctx in &r.activity_contexts {
        if let Some(entry) = agg.iter_mut().find(|(t, _)| *t == ctx.period_type) {
            entry.1 += ctx.duration_min;
        } else {
            agg.push((ctx.period_type.clone(), ctx.duration_min));
        }
    }
    for (ptype, dur) in &agg {
        let pct = dur / total_min * 100.0;
        write!(
            html,
            "<tr><td>{}</td><td>{:.1} min</td><td>{:.1}%</td></tr>",
            html_escape(ptype),
            dur,
            pct,
        )?;
    }
    writeln!(html, "</tbody></table>")
}

// ---------------------------------------------------------------------------
// Author Declaration
// ---------------------------------------------------------------------------

pub(super) fn write_declaration_summary(html: &mut String, r: &WarReport) -> fmt::Result {
    let decl = match r.declaration_summary {
        Some(ref d) => d,
        None => return Ok(()),
    };

    write!(html, r#"<h3>Author Declaration</h3>"#)?;

    // Statement blockquote
    write!(
        html,
        r#"<div class="declaration-quote">{}</div>"#,
        html_escape(&decl.statement),
    )?;

    // Title
    write!(
        html,
        r#"<p style="font-size:12.5px"><strong>Document Title:</strong> {}</p>"#,
        html_escape(&decl.title),
    )?;

    // AI tools
    if !decl.ai_tools.is_empty() {
        write!(
            html,
            r#"<p style="font-size:12.5px"><strong>AI Tools Declared:</strong> "#
        )?;
        for (i, tool) in decl.ai_tools.iter().enumerate() {
            if i > 0 {
                html.push(' ');
            }
            write!(
                html,
                r#"<span style="display:inline-block;background:var(--navy-muted);font-family:var(--sans);font-size:10px;padding:2px 6px;border-radius:2px">{}</span>"#,
                html_escape(tool),
            )?;
        }
        write!(html, "</p>")?;
    }

    // Input modalities
    if !decl.input_modalities.is_empty() {
        let modalities: Vec<String> = decl
            .input_modalities
            .iter()
            .map(|m| html_escape(m))
            .collect();
        write!(
            html,
            r#"<p style="font-size:12.5px"><strong>Input Modalities:</strong> {}</p>"#,
            modalities.join(", "),
        )?;
    }

    // Collaborators and signature
    let sig_icon = if decl.signature_valid {
        r#"<span style="color:#3d7a4a">&#10003; Valid</span>"#
    } else {
        r#"<span style="color:#b71c1c">&#10007; Invalid</span>"#
    };
    write!(
        html,
        r#"<p style="font-size:12.5px"><strong>Collaborators:</strong> {} | <strong>Signature:</strong> {} | <strong>Declared:</strong> {}</p>"#,
        decl.collaborator_count,
        sig_icon,
        decl.created_at.format("%B %-d, %Y %H:%M UTC"),
    )
}

// ---------------------------------------------------------------------------
// Key Hierarchy
// ---------------------------------------------------------------------------

pub(super) fn write_key_hierarchy(html: &mut String, r: &WarReport) -> fmt::Result {
    let kh = match r.key_hierarchy_summary {
        Some(ref k) => k,
        None => return Ok(()),
    };

    write!(html, r#"<h3>Key Hierarchy</h3>"#)?;
    write!(html, r#"<div class="info-box"><table>"#)?;

    let master_short = if kh.master_fingerprint.len() > 16 {
        format!(
            "{}...{}",
            &kh.master_fingerprint[..8],
            &kh.master_fingerprint[kh.master_fingerprint.len().saturating_sub(8)..],
        )
    } else {
        kh.master_fingerprint.clone()
    };
    row(html, "Master Fingerprint", &master_short)?;

    let dev_short = if kh.device_id.len() > 16 {
        format!(
            "{}...{}",
            &kh.device_id[..8],
            &kh.device_id[kh.device_id.len().saturating_sub(8)..],
        )
    } else {
        kh.device_id.clone()
    };
    row(html, "Device ID", &dev_short)?;

    let sess_short = if kh.session_id.len() > 16 {
        format!(
            "{}...{}",
            &kh.session_id[..8],
            &kh.session_id[kh.session_id.len().saturating_sub(8)..],
        )
    } else {
        kh.session_id.clone()
    };
    row(html, "Session ID", &sess_short)?;
    row(html, "Ratchet Count", &kh.ratchet_count.to_string())?;
    row(
        html,
        "Checkpoint Signatures",
        &kh.checkpoint_signatures.to_string(),
    )?;
    row(
        html,
        "Session Started",
        &kh.session_started
            .format("%B %-d, %Y %H:%M UTC")
            .to_string(),
    )?;

    writeln!(html, "</table></div>")
}

// ---------------------------------------------------------------------------
// Hardware Attestation (physical context + beacon)
// ---------------------------------------------------------------------------

pub(super) fn write_hardware_attestation(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.physical_context.is_none() && r.beacon_info.is_none() {
        return Ok(());
    }

    write!(html, r#"<h3>Hardware Attestation</h3>"#)?;

    if let Some(ref pc) = r.physical_context {
        write!(html, r#"<div class="info-box"><table>"#)?;
        row(
            html,
            "Clock Skew",
            &format!("{} ns", format_number(pc.clock_skew_ns)),
        )?;
        row(html, "Thermal Proxy", &pc.thermal_proxy.to_string())?;
        let puf_short = if pc.silicon_puf_hash.len() > 16 {
            format!(
                "{}...{}",
                &pc.silicon_puf_hash[..8],
                &pc.silicon_puf_hash[pc.silicon_puf_hash.len().saturating_sub(8)..],
            )
        } else {
            pc.silicon_puf_hash.clone()
        };
        row(html, "Silicon PUF Hash", &puf_short)?;
        row(
            html,
            "IO Latency",
            &format!("{} ns", format_number(pc.io_latency_ns)),
        )?;
        writeln!(html, "</table></div>")?;
    }

    if let Some(ref bi) = r.beacon_info {
        write!(
            html,
            r#"<p style="font-size:12.5px;margin:8px 0"><strong>Temporal Beacons:</strong></p>"#,
        )?;
        write!(html, r#"<div class="info-box"><table>"#)?;
        row(html, "drand Round", &format_number(bi.drand_round))?;
        row(
            html,
            "NIST Pulse Index",
            &format_number(bi.nist_pulse_index),
        )?;
        row(html, "Fetched At", &html_escape(&bi.fetched_at))?;
        if let Some(ref kid) = bi.wp_key_id {
            row(html, "WP Key ID", &html_escape(kid))?;
        }
        writeln!(html, "</table></div>")?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Anomalies Detail
// ---------------------------------------------------------------------------

pub(super) fn write_anomalies_detail(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.anomalies.is_empty() {
        return Ok(());
    }

    write!(html, r#"<h3>Anomaly Details</h3>"#)?;
    write!(
        html,
        r#"<table class="data"><thead><tr><th>Severity</th><th>Type</th><th>Description</th></tr></thead><tbody>"#,
    )?;
    for a in &r.anomalies {
        let sev_class = match a.severity.as_str() {
            "Alert" => "severity-alert",
            "Warning" => "severity-warning",
            _ => "severity-info",
        };
        write!(
            html,
            r#"<tr><td class="{cls}">{sev}</td><td>{typ}</td><td>{desc}</td></tr>"#,
            cls = sev_class,
            sev = html_escape(&a.severity),
            typ = html_escape(&a.anomaly_type),
            desc = html_escape(&a.description),
        )?;
    }
    writeln!(html, "</tbody></table>")
}

// ---------------------------------------------------------------------------
// Certification (footer)
// ---------------------------------------------------------------------------

pub(super) fn write_footer(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<div class="report-footer">
<p class="certification">This report was generated by an automated forensic examination system using standardized, reproducible methodology. Applying the same algorithm version to the same evidence will produce identical results. This report documents process analysis only; it does not constitute legal advice, and the determination herein should be evaluated alongside all other available evidence by the trier of fact.</p>
<p>Forensic Authorship Examination Report &ensp;|&ensp; {id} &ensp;|&ensp; Algorithm {alg} &ensp;|&ensp; Schema {schema}<br>
&copy; {year} WritersLogic, LLC. All rights reserved. CPoE Protocol per draft-condrey-rats-pop.</p>
</div>
"#,
        id = html_escape(&r.report_id),
        alg = html_escape(&r.algorithm_version),
        schema = html_escape(&r.schema_version),
        year = r.generated_at.format("%Y"),
    )
}
