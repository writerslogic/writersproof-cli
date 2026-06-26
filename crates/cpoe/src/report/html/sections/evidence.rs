// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

pub(in crate::report::html) fn write_methodology(
    html: &mut String,
    sc: &mut SectionCounter,
    r: &WarReport,
) -> fmt::Result {
    section_heading(html, sc, SEC_METHODOLOGY)?;
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
    sc: &mut SectionCounter,
    r: &WarReport,
) -> fmt::Result {
    section_heading(html, sc, SEC_CHAIN)?;
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
        if r.total_duration_min.is_finite() {
            r.total_duration_min
        } else {
            0.0
        },
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

    let fin = |v: f64| if v.is_finite() { v } else { 0.0 };
    row(
        html,
        "Original Composition",
        &format!("{:.1}%", fin(prov.original_composition_pct)),
    )?;
    row(
        html,
        "Sourced (Verified)",
        &format!("{:.1}%", fin(prov.sourced_verified_pct)),
    )?;
    row(
        html,
        "Sourced (Unverified)",
        &format!("{:.1}%", fin(prov.sourced_unknown_pct)),
    )?;
    row(
        html,
        "Source Trust",
        &format!("{:.2}", fin(prov.source_trustworthiness)),
    )?;
    row(
        html,
        "Authenticity Score",
        &format!("{:.2}", fin(prov.authenticity_score)),
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

pub(in crate::report::html) fn write_process_evidence(
    html: &mut String,
    sc: &mut SectionCounter,
    r: &WarReport,
) -> fmt::Result {
    let p = &r.process;
    section_heading(html, sc, SEC_PROCESS)?;
    write!(
        html,
        r#"<p>The following metrics were captured by the CPoE proof daemon during the writing process. Each metric is derived from real-time behavioral observation and is cryptographically bound to the checkpoint chain (see the Checkpoint Chain Integrity section).</p>
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
    if p.revision_intensity.is_none() {
        return Ok(());
    }
    write!(
        html,
        r#"<div class="evidence-card"><h4><span class="exhibit-badge">A</span> Revision Intensity</h4>"#
    )?;
    if let Some(ri) = p.revision_intensity.filter(|v| v.is_finite()) {
        let pct = (ri * 100.0).min(100.0);
        write!(
            html,
            r#"<div class="metric">{pct:.0}% of content revised</div>
<div class="forgery-bar"><div class="forgery-fill" style="width:{pct:.0}%;background:var(--accent)"></div></div>"#,
        )?;
        let note = if ri > 0.65 {
            "Heavy revision activity; consistent with careful drafting and extensive self-editing."
        } else if ri > 0.30 {
            "Moderate revision activity; within the expected range for natural composition."
        } else if ri > 0.05 {
            "Light revision activity; may indicate fluent single-pass writing or dictation."
        } else {
            "Minimal revision detected. Most content was entered as a forward-only append, which is atypical for multi-paragraph human composition but may occur in short or highly rehearsed text."
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
    if p.pause_median_sec.filter(|v| v.is_finite()).is_none() {
        return Ok(());
    }
    write!(
        html,
        r#"<div class="evidence-card"><h4><span class="exhibit-badge">B</span> Pause Distribution</h4>"#
    )?;
    if let Some(med) = p.pause_median_sec.filter(|v| v.is_finite()) {
        write!(html, r#"<div class="metric">Median: {:.1}s"#, med)?;
        if let Some(p90) = p.pause_p90_sec.filter(|v| v.is_finite()) {
            write!(html, " | P90: {:.1}s", p90)?;
        }
        if let Some(max) = p.pause_max_sec.filter(|v| v.is_finite()) {
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
    if p.paste_ratio_pct.is_none() && p.paste_operations.is_none() {
        return Ok(());
    }
    write!(
        html,
        r#"<div class="evidence-card"><h4><span class="exhibit-badge">C</span> Paste Analysis</h4>"#
    )?;
    if let Some(pr) = p.paste_ratio_pct.filter(|v| v.is_finite()) {
        let paste_color = if pr < 20.0 {
            "var(--accent)"
        } else if pr < 50.0 {
            "var(--caution)"
        } else {
            "var(--alert)"
        };
        write!(html, r#"<div class="metric">{:.1}% of total text"#, pr)?;
        if let Some(ops) = p.paste_operations {
            write!(html, " ({} operations)", ops)?;
        }
        write!(
            html,
            r#"</div>
<div class="forgery-bar"><div class="forgery-fill" style="width:{pct:.0}%;background:{color}"></div></div>"#,
            pct = pr.min(100.0),
            color = paste_color,
        )?;
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
    if p.iki_cv.is_none() && p.total_keystrokes.is_none() {
        return Ok(());
    }
    write!(
        html,
        r#"<div class="evidence-card"><h4><span class="exhibit-badge">D</span> Keystroke Dynamics</h4>"#
    )?;
    if let Some(cv) = p.iki_cv.filter(|v| v.is_finite()) {
        let cv_color = if cv > 0.3 {
            "var(--accent)"
        } else if cv > 0.15 {
            "var(--caution)"
        } else {
            "var(--alert)"
        };
        let cv_pct = (cv * 100.0).min(100.0);
        write!(html, r#"<div class="metric">IKI CV: {:.2}"#, cv)?;
        if let Some(bg) = p.bigram_consistency.filter(|v| v.is_finite()) {
            write!(html, " | Bigram consistency: {:.2}", bg)?;
        }
        write!(
            html,
            r#"</div>
<div class="forgery-bar"><div class="forgery-fill" style="width:{cv_pct:.0}%;background:{cv_color}"></div></div>"#
        )?;
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
    if p.deletion_sequences.is_none() {
        return Ok(());
    }
    write!(
        html,
        r#"<div class="evidence-card"><h4><span class="exhibit-badge">E</span> Deletion Patterns</h4>"#
    )?;
    if let Some(ds) = p.deletion_sequences {
        write!(
            html,
            r#"<div class="metric">{} sequences"#,
            format_number(ds)
        )?;
        if let Some(avg) = p.avg_deletion_length.filter(|v| v.is_finite()) {
            write!(html, " | Avg {:.1} chars", avg)?;
        }
        if let Some(sd) = p.select_delete_ops {
            write!(html, " | {} select-delete ops", sd)?;
        }
        write!(html, "</div>")?;
        let note = if let Some(avg) = p.avg_deletion_length.filter(|v| v.is_finite()) {
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
    if p.swf_checkpoints.is_none() {
        return Ok(());
    }
    write!(
        html,
        r#"<div class="evidence-card"><h4><span class="exhibit-badge">F</span> Verifiable Delay Functions</h4>"#
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
    if let Some(hrs) = p.swf_backdating_hours.filter(|v| v.is_finite()) {
        write!(
            html,
            r#"<div class="note">Each checkpoint contains a PoSME timing proof that required real wall-clock time to compute. 
            Fabricating this evidence chain after the fact would require approximately {:.0} hours of sequential computation, 
            making backdating computationally infeasible for practical purposes.</div>"#,
            hrs
        )?;
    } else {
        write!(
            html,
            r#"<div class="note">PoSME checkpoints provide cryptographic proof that writing occurred over real elapsed time. 
            The sequential nature of PoSME computation prevents after-the-fact fabrication.</div>"#
        )?;
    }
    write!(html, "</div>")
}
