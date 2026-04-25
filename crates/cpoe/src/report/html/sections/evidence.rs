// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

pub(in crate::report::html) fn write_methodology(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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

pub(in crate::report::html) fn write_chain_of_custody(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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

pub(in crate::report::html) fn write_provenance_breakdown(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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
                html_escape(src.session_id.get(..16).unwrap_or(&src.session_id)),
                html_escape(src.app_bundle_id.as_deref().unwrap_or("unknown")),
                src.fragment_count,
                if src.verified { "Yes" } else { "No" },
            )?;
        }
        writeln!(html, "</table></div>")?;
    }

    Ok(())
}

pub(in crate::report::html) fn write_category_scores(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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

pub(in crate::report::html) fn write_process_evidence(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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
