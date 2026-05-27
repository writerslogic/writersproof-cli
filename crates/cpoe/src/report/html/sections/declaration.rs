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

    write!(
        html,
        r#"<div class="lr-interpretation"><strong>Interpretation:</strong> {interpretation}</div>"#,
    )
}

pub(in crate::report::html) fn write_key_findings(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    write!(html, r#"<ol class="key-findings">"#)?;

    write!(
        html,
        "<li><strong>Writing duration:</strong> {} session{}, {:.0} minutes of active composition, \
         {} revision events recorded.</li>",
        r.session_count,
        if r.session_count == 1 { "" } else { "s" },
        if r.total_duration_min.is_finite() { r.total_duration_min } else { 0.0 },
        format_number(r.revision_events),
    )?;

    if let Some(ks) = r.process.total_keystrokes {
        write!(
            html,
            "<li><strong>Keystroke capture:</strong> {} keystrokes recorded with timing data.",
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
        write!(html, "</li>")?;
    }

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
        write!(html, "</li>")?;
    }

    if let Some(pr) = r.process.paste_ratio_pct.filter(|v| v.is_finite()) {
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

    if !r.dimensions.is_empty() {
        let not_evaluated = r.dimensions.iter().filter(|d| d.score == 0).count();
        let anomalous = r.dimensions.iter().filter(|d| d.score > 0 && d.score < 40).count();
        let evaluated = r.dimensions.len() - not_evaluated;
        if anomalous == 0 && not_evaluated == 0 {
            write!(
                html,
                "<li><strong>Dimension concordance:</strong> All {} analytical dimensions support \
                 the composite determination. No contradictory signals detected.</li>",
                r.dimensions.len(),
            )?;
        } else if anomalous > 0 {
            write!(
                html,
                "<li><strong>Dimension concordance:</strong> {} of {} evaluated dimensions scored below \
                 threshold, indicating potential anomalies in those areas.{}</li>",
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
                "<li><strong>Dimension concordance:</strong> {} of {} dimensions evaluated; \
                 {} dimension{} had insufficient data. No contradictory signals in evaluated dimensions.</li>",
                evaluated,
                r.dimensions.len(),
                not_evaluated,
                if not_evaluated == 1 { "" } else { "s" },
            )?;
        }
    }

    writeln!(html, "</ol>")
}
