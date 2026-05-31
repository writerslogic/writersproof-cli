// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

pub(in crate::report::html) fn write_session_timeline(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    if r.sessions.is_empty() {
        return Ok(());
    }
    section_heading(html, 5, SEC_TIMELINE)?;
    writeln!(
        html,
        r#"<p>The document was composed across {} session{}, totaling approximately {:.0} minutes of active writing time.</p>"#,
        r.session_count,
        if r.session_count == 1 { "" } else { "s" },
        if r.total_duration_min.is_finite() { r.total_duration_min } else { 0.0 },
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

pub(in crate::report::html) fn write_dimension_analysis(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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

pub(in crate::report::html) fn write_dimension_lr_table(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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
        let conf_pct = if d.confidence.is_finite() { (d.confidence * 100.0).min(100.0) } else { 0.0 };
        let log_lr = if d.log_lr.is_finite() { format!("{:.2}", d.log_lr) } else { "N/A".to_string() };
        write!(
            html,
            r#"<tr><td style="color:{color};font-weight:600">{name}</td><td>{score}</td><td>{lr}</td><td>{log_lr}</td><td><div class="confidence-bar" style="width:{conf_pct:.0}px;background:{color}"></div></td><td>{disc}</td></tr>"#,
            name = html_escape(&d.name),
            score = d.score,
            lr = format_lr(d.lr),
            log_lr = log_lr,
            conf_pct = conf_pct,
            color = sanitize_css_color(&d.color),
            disc = html_escape(&d.key_discriminator),
        )?;
    }
    let combined_log = if r.likelihood_ratio.is_finite() && r.likelihood_ratio > 0.0 {
        format!("{:.2}", r.likelihood_ratio.log10())
    } else {
        "N/A".to_string()
    };
    write!(
        html,
        r#"</tbody><tfoot><tr style="font-weight:700;border-top:2px solid var(--rule)"><td>Combined</td><td>{score}</td><td>{lr}</td><td>{log_lr}</td><td><div class="confidence-bar" style="width:{conf_pct:.0}px;background:#1a4d2e"></div></td><td>All dimensions concordant</td></tr></tfoot>"#,
        score = r.score,
        lr = format_lr(r.likelihood_ratio),
        log_lr = combined_log,
        conf_pct = (r.score as f64).min(100.0),
    )?;
    writeln!(html, "</table>")
}

pub(in crate::report::html) fn write_checkpoint_chain(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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
            hash = html_escape(&hash_short),
            size = format_bytes(cp.content_size),
        )?;
    }
    writeln!(html, "</tbody></table>")
}

pub(in crate::report::html) fn write_forgery_resistance(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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
        let cost = format_duration_human(c.cost_cpu_sec);
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

pub(in crate::report::html) fn write_flags(html: &mut String, r: &WarReport) -> fmt::Result {
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

pub(in crate::report::html) fn write_scope(html: &mut String, r: &WarReport) -> fmt::Result {
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

pub(in crate::report::html) fn write_analyzed_text(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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

pub(in crate::report::html) fn write_verification_instructions(
    html: &mut String,
) -> fmt::Result {
    section_heading(html, 13, SEC_VERIFY)?;
    html.push_str(TMPL_VERIFICATION);
    Ok(())
}

pub(in crate::report::html) fn write_glossary(html: &mut String) -> fmt::Result {
    section_heading(html, 14, SEC_GLOSSARY)?;
    html.push_str(TMPL_GLOSSARY);
    Ok(())
}
