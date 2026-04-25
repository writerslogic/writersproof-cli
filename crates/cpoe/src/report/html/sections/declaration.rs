// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

pub(in crate::report::html) fn write_verdict(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
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
        r.total_duration_min,
        format_number(r.revision_events),
    )?;

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
