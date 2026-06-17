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
        let dur = if s.duration_min.is_finite() { s.duration_min } else { 0.0 };
        let dur_pct = (dur / r.total_duration_min.max(1.0) * 100.0).min(100.0);
        write!(
            html,
            r#"<div class="session-box">
<h4>Session {idx}</h4>
<div class="metric-grid">
<div class="metric-card"><span class="metric-label">Started</span><span class="metric-value">{start}</span></div>
<div class="metric-card"><span class="metric-label">Duration</span><span class="metric-value">{dur:.0} min</span></div>
<div class="metric-card"><span class="metric-label">Events</span><span class="metric-value">{events}</span></div>
</div>
<div class="forgery-bar" style="margin:6px 0 4px"><div class="forgery-fill" style="width:{dur_pct:.0}%;background:var(--navy)"></div></div>
<p style="font-size:12px;color:var(--text-muted)">{summary}</p>
</div>
"#,
            idx = s.index,
            start = s.start.format("%b %-d, %Y %H:%M"),
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
    let dim_count = r.dimensions.iter().filter(|d| !d.analysis.is_empty()).count();
    let min_score = r.dimensions.iter().map(|d| d.score).min().unwrap_or(0);
    write!(
        html,
        r#"<h2><span class="section-number">6.</span> {title} <span class="section-metric">{count} dimensions, lowest {min}</span></h2>"#,
        title = SEC_DIMENSIONS,
        count = dim_count,
        min = min_score,
    )?;
    writeln!(
        html,
        r#"<p>Each analytical dimension is evaluated independently against both H\u{{2081}} and H\u{{2082}}. \
The per-dimension scores and likelihood ratios below contribute to the composite determination in Section 1.</p>"#
    )?;
    for d in &r.dimensions {
        if d.analysis.is_empty() {
            continue;
        }
        let color = sanitize_css_color(&d.color);
        let circumference = 2.0 * std::f64::consts::PI * 14.0; // r=14
        let offset = circumference * (1.0 - d.score as f64 / 100.0);
        write!(
            html,
            r#"<div class="dimension-card">
<h3 style="color:{color}">{name}</h3>
<svg class="dimension-badge" width="36" height="36" viewBox="0 0 36 36" style="position:absolute;top:14px;right:18px">
<circle cx="18" cy="18" r="14" fill="none" stroke="var(--border-light)" stroke-width="3"/>
<circle cx="18" cy="18" r="14" fill="none" stroke="{color}" stroke-width="3" stroke-dasharray="{circ:.1}" stroke-dashoffset="{offset:.1}" stroke-linecap="round" transform="rotate(-90 18 18)"/>
<text x="18" y="22" text-anchor="middle" font-family="var(--sans)" font-size="11" font-weight="700" fill="{color}">{score}</text>
</svg>
"#,
            name = html_escape(&d.name),
            score = d.score,
            circ = circumference,
        )?;
        if !d.key_discriminator.is_empty() {
            write!(
                html,
                r#"<p class="dimension-detail" style="font-style:italic;color:var(--navy-light)"><strong>Key signal:</strong> {}</p>"#,
                html_escape(&d.key_discriminator),
            )?;
        }
        if d.lr.is_finite() && d.lr > 0.0 {
            write!(
                html,
                r#"<p class="dimension-detail"><strong>LR:</strong> {} (log&#8321;&#8320; = {:.2})</p>"#,
                format_lr(d.lr),
                d.log_lr,
            )?;
        }
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
    write!(
        html,
        r#"<h2><span class="section-number">7.</span> {title} <span class="section-metric">LR = {lr}</span></h2>"#,
        title = SEC_STATISTICS,
        lr = format_lr(r.likelihood_ratio),
    )?;
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
    let total_elapsed: f64 = r.checkpoints.iter()
        .filter_map(|cp| cp.elapsed_ms)
        .sum::<u64>() as f64 / 1000.0;
    write!(
        html,
        r#"<h2><span class="section-number">8.</span> {title} <span class="section-metric">{count} checkpoints, {elapsed:.0}s total</span></h2>"#,
        title = SEC_CHECKPOINTS,
        count = r.checkpoints.len(),
        elapsed = total_elapsed,
    )?;
    writeln!(
        html,
        r#"<p>Each checkpoint records a cryptographic hash of the document state at a point in time. The chain is linked by including \
the previous checkpoint's hash in each successive entry, forming a tamper-evident log.</p>"#
    )?;
    write!(html, r#"<div class="checkpoint-timeline">"#)?;
    let mut prev_ts = None;
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
        let vdf_badge = cp
            .vdf_iterations
            .filter(|&v| v > 0)
            .map(|v| format!(r#"<span class="cp-badge">{} iterations</span>"#, format_number(v)))
            .unwrap_or_default();
        let elapsed_label = match (prev_ts, Some(cp.timestamp)) {
            (Some(prev), Some(cur)) => {
                let delta = cur.signed_duration_since(prev);
                let secs = delta.num_seconds().unsigned_abs();
                if secs < 60 { format!("{}s", secs) }
                else if secs < 3600 { format!("{}m {}s", secs / 60, secs % 60) }
                else { format!("{}h {}m", secs / 3600, (secs % 3600) / 60) }
            }
            _ => String::new(),
        };
        write!(
            html,
            r#"<div class="checkpoint-node"><span class="cp-time">#{ord} {ts}</span> <span class="cp-hash" title="{full_hash}">{hash}</span> {size}{vdf}{elapsed}</div>"#,
            ord = cp.ordinal,
            ts = cp.timestamp.format("%H:%M:%S"),
            hash = html_escape(&hash_short),
            full_hash = html_escape(&cp.content_hash),
            size = format_bytes(cp.content_size),
            vdf = vdf_badge,
            elapsed = if elapsed_label.is_empty() { String::new() } else { format!(r#" <span class="cp-meta">+{elapsed_label}</span>"#) },
        )?;
        prev_ts = Some(cp.timestamp);
    }
    writeln!(html, "</div>")
}

pub(in crate::report::html) fn write_forgery_resistance(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    if r.forgery.components.is_empty() {
        return Ok(());
    }
    let forge_time = format_duration_human(r.forgery.estimated_forge_time_sec);
    write!(
        html,
        r#"<h2><span class="section-number">9.</span> {title} <span class="section-metric">{tier}, {time} to forge</span></h2>"#,
        title = SEC_FORGERY,
        tier = html_escape(&r.forgery.tier),
        time = forge_time,
    )?;

    // Stacked cost bar showing relative contribution of each component.
    let total_cost: f64 = r.forgery.components.iter()
        .map(|c| if c.cost_cpu_sec.is_finite() { c.cost_cpu_sec } else { 0.0 })
        .sum::<f64>().max(1.0);
    let bar_colors = ["#1a4d2e", "#2c5282", "#5b3c8b", "#8b6914", "#3d7a4a", "#b45309", "#6b6b6b", "#8b1a1a"];
    write!(html, r#"<div style="display:flex;height:18px;border:1px solid var(--border);margin:12px 0;overflow:hidden">"#)?;
    for (i, c) in r.forgery.components.iter().enumerate() {
        let cost = if c.cost_cpu_sec.is_finite() { c.cost_cpu_sec } else { 0.0 };
        let pct = (cost / total_cost * 100.0).max(0.5);
        let bg = bar_colors.get(i % bar_colors.len()).unwrap_or(&"#6b6b6b");
        let opacity = if c.present { "1" } else { "0.3" };
        write!(html, r#"<div style="width:{pct:.1}%;background:{bg};opacity:{opacity}" title="{name}: {cost_h}"></div>"#,
            name = html_escape(&c.name),
            cost_h = format_duration_human(c.cost_cpu_sec),
        )?;
    }
    write!(html, "</div>")?;

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
        r#"<h2><span class="section-number">10.</span> {} <span class="section-metric">{} human, {} synthetic</span></h2>"#,
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
