// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

pub(in crate::report::html) fn write_verdict(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    let color = sanitize_css_color(r.verdict.css_color());
    section_heading(html, 1, SEC_DECLARATION)?;

    if r.verdict == Verdict::InsufficientData {
        return write!(
            html,
            r#"<div class="declaration" style="border-color:{color}">
  <div class="declaration-header">Examiner's Determination</div>
  <div class="declaration-body">
    <div class="declaration-text" style="flex:1">
      <div class="verdict-label" style="color:{color}">{label}</div>
      <p>{desc}</p>
    </div>
  </div>
</div>
"#,
            label = r.verdict.label(),
            desc = html_escape(&r.verdict_description),
        );
    }

    let lr_display = format_lr(r.likelihood_ratio);
    // SVG semicircle gauge: score 0-100 maps to 0-180 degrees on the arc.
    let score_clamped = (r.score as f64).clamp(0.0, 100.0);
    let angle = score_clamped * 1.8; // 0-180 degrees
    let cx = 50.0;
    let cy = 50.0;
    let radius = 40.0;
    // Arc sweeps from left (10,50) clockwise. At 0 degrees end=(10,50), at 180 end=(90,50).
    let end_x = cx - radius * angle.to_radians().cos();
    let end_y = cy - radius * angle.to_radians().sin();
    let large_arc = if angle > 90.0 { 1 } else { 0 };
    // Arc from left (10,50) sweeping clockwise to (end_x, end_y)
    let gauge_svg = format!(
        r#"<svg viewBox="0 0 100 55" width="88" height="48" style="flex-shrink:0">
<path d="M10,50 A40,40 0 0,1 90,50" fill="none" stroke="{border}" stroke-width="7" stroke-linecap="round"/>
<path d="M10,50 A40,40 0 {large_arc},1 {ex:.1},{ey:.1}" fill="none" stroke="{color}" stroke-width="7" stroke-linecap="round"/>
<text x="50" y="48" text-anchor="middle" font-family="var(--sans)" font-size="18" font-weight="800" fill="{color}">{score}</text>
<text x="50" y="12" text-anchor="middle" font-family="var(--sans)" font-size="7" fill="{muted}" letter-spacing="0.5">OF 100</text>
</svg>"#,
        border = "var(--border-light)",
        color = color,
        score = r.score,
        ex = end_x,
        ey = end_y,
        muted = "var(--text-muted)",
    );
    write!(
        html,
        r#"<div class="declaration" style="border-color:{color}">
  <div class="declaration-header">Examiner's Determination</div>
  <div class="declaration-body">
    {gauge}
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
        gauge = gauge_svg,
        label = r.verdict.label(),
        desc = html_escape(&r.verdict_description),
        lr = lr_display,
        tier = r.enfsi_tier.label(),
    )
}

pub(in crate::report::html) fn write_enfsi_scale(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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

pub(in crate::report::html) fn write_lr_interpretation(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    if r.verdict == Verdict::InsufficientData {
        return Ok(());
    }
    let lr = r.likelihood_ratio;
    if !lr.is_finite() || lr <= 0.0 {
        return Ok(());
    }

    let interpretation = if lr >= 1.0 {
        format!(
            "The observed behavioral evidence is approximately <strong>{}</strong> times more \
             probable under the hypothesis that the document was composed through a human writing \
             process (H\u{2081}) than under the hypothesis that it was produced by automated or \
             non-compositional means (H\u{2082}). On the ENFSI verbal equivalence scale, \
             this constitutes <strong>{}</strong> the proposition of human authorship.",
            format_lr(lr),
            r.enfsi_tier.label().to_lowercase(),
        )
    } else {
        let inverse = 1.0 / lr;
        format!(
            "The observed behavioral evidence is approximately <strong>{}</strong> times more \
             probable under H\u{2082} than under H\u{2081}. This means the captured process \
             patterns are more consistent with non-compositional input (transcription, paste, or \
             automated generation) than with real-time human composition. This is not proof of \
             automated generation; it indicates the behavioral signals captured during this session \
             did not exhibit the variability and revision patterns typically observed in human \
             drafting. Short sessions, minimal editing, or unfamiliar input methods can produce \
             this result even for genuinely human-authored text.",
            format_lr(inverse),
        )
    };

    // Log-scale LR bar: maps log10(LR) from -2..+5 onto a horizontal bar.
    let log_lr = if lr > 0.0 { lr.log10() } else { -2.0 };
    let bar_pct = ((log_lr + 2.0) / 7.0 * 100.0).clamp(2.0, 98.0); // -2..+5 range
    let bar_color = if log_lr >= 4.0 { "var(--accent)" }
        else if log_lr >= 2.0 { "#3d7a4a" }
        else if log_lr >= 1.0 { "var(--caution)" }
        else { "var(--alert)" };
    write!(
        html,
        r#"<div class="lr-interpretation">
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
<svg viewBox="0 0 300 24" width="300" height="24" style="flex-shrink:0">
<rect x="0" y="8" width="300" height="8" rx="4" fill="var(--border-light)"/>
<rect x="0" y="8" width="{bar_w:.0}" height="8" rx="4" fill="{bar_color}"/>
<circle cx="{bar_w:.0}" cy="12" r="6" fill="{bar_color}" stroke="var(--bg)" stroke-width="2"/>
<text x="0" y="6" font-family="var(--sans)" font-size="7" fill="var(--text-muted)">&lt;1</text>
<text x="86" y="6" font-family="var(--sans)" font-size="7" fill="var(--text-muted)">10</text>
<text x="172" y="6" font-family="var(--sans)" font-size="7" fill="var(--text-muted)">10&#xB3;</text>
<text x="290" y="6" font-family="var(--sans)" font-size="7" fill="var(--text-muted)" text-anchor="end">10&#x2075;</text>
</svg>
<span style="font-family:var(--sans);font-weight:700;font-size:13px;color:{bar_color}">log\u{{2081}}\u{{2080}} = {log_lr:.1}</span>
</div>
<strong>Interpretation:</strong> {interpretation}</div>"#,
        bar_w = bar_pct * 3.0, // 300px width
    )
}

pub(in crate::report::html) fn write_key_findings(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    write!(
        html,
        r#"<div class="finding-card finding-human"><strong>Writing duration:</strong> {} session{}, {:.0} minutes of active composition, \
         {} revision events recorded.</div>"#,
        r.session_count,
        if r.session_count == 1 { "" } else { "s" },
        if r.total_duration_min.is_finite() { r.total_duration_min } else { 0.0 },
        format_number(r.revision_events),
    )?;

    if let Some(ks) = r.process.total_keystrokes {
        let cv_class = r.process.iki_cv.filter(|v| v.is_finite()).map(|cv| {
            if cv < 0.15 { "finding-synthetic" } else { "finding-human" }
        }).unwrap_or("finding-human");
        write!(
            html,
            r#"<div class="finding-card {cv_class}"><strong>Keystroke capture:</strong> {} keystrokes recorded with timing data."#,
            format_number(ks),
        )?;
        if let Some(cv) = r.process.iki_cv.filter(|v| v.is_finite()) {
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
        write!(html, "</div>")?;
    }

    if !r.checkpoints.is_empty() {
        let verified = if r.process.swf_chain_verified {
            "integrity verified"
        } else {
            "integrity unverified"
        };
        write!(
            html,
            r#"<div class="finding-card finding-human"><strong>Cryptographic checkpoints:</strong> {} checkpoints in tamper-evident chain, {}."#,
            r.checkpoints.len(),
            verified,
        )?;
        if let Some(hrs) = r.process.swf_backdating_hours {
            if hrs > 8760.0 {
                write!(
                    html,
                    " An adversary attempting to fabricate this chain would need over {:.0} years of sequential computation.",
                    hrs / 8760.0,
                )?;
            } else if hrs > 24.0 {
                write!(
                    html,
                    " Fabricating this chain would require approximately {:.0} days of sequential computation.",
                    hrs / 24.0,
                )?;
            } else if hrs > 1.0 {
                write!(
                    html,
                    " Fabricating this chain would require approximately {:.0} hours of sequential computation.",
                    hrs,
                )?;
            }
        }
        write!(html, "</div>")?;
    }

    if let Some(pr) = r.process.paste_ratio_pct.filter(|v| v.is_finite()) {
        let paste_class = if pr < 20.0 { "finding-human" } else if pr < 50.0 { "finding-neutral" } else { "finding-synthetic" };
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
            r#"<div class="finding-card {paste_class}"><strong>Paste analysis:</strong> {:.1}% of text entered via paste ({}).</div>"#,
            pr, assessment,
        )?;
    }

    if !r.dimensions.is_empty() {
        let not_evaluated = r.dimensions.iter().filter(|d| d.score == 0).count();
        let anomalous = r.dimensions.iter().filter(|d| d.score > 0 && d.score < 40).count();
        let evaluated = r.dimensions.len() - not_evaluated;
        let dim_class = if anomalous > 0 { "finding-synthetic" } else { "finding-human" };
        if anomalous == 0 && not_evaluated == 0 {
            write!(
                html,
                r#"<div class="finding-card {dim_class}"><strong>Dimension concordance:</strong> All {} analytical dimensions support the composite determination. No contradictory signals detected.</div>"#,
                r.dimensions.len(),
            )?;
        } else if anomalous > 0 {
            write!(
                html,
                r#"<div class="finding-card {dim_class}"><strong>Dimension concordance:</strong> {} of {} evaluated dimensions scored below threshold, indicating potential anomalies in those areas.{}</div>"#,
                anomalous,
                evaluated,
                if not_evaluated > 0 {
                    format!(" {} dimension{} had insufficient data for evaluation.",
                        not_evaluated, if not_evaluated == 1 { "" } else { "s" })
                } else {
                    String::new()
                },
            )?;
        } else if not_evaluated > 0 {
            write!(
                html,
                r#"<div class="finding-card {dim_class}"><strong>Dimension concordance:</strong> {} of {} dimensions evaluated; {} dimension{} had insufficient data. No contradictory signals in evaluated dimensions.</div>"#,
                evaluated,
                r.dimensions.len(),
                not_evaluated,
                if not_evaluated == 1 { "" } else { "s" },
            )?;
        }
    }

    Ok(())
}
