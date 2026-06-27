// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::report::types::*;

pub fn draw_page2(layer: &PdfLayerReference, r: &WarReport, fonts: &PdfFonts, footer: &str) {
    let mut y = PAGE_TOP;

    // ── 5. Session Timeline ──
    if !r.sessions.is_empty() {
        text(
            layer,
            "5. Session Timeline",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 7.0;

        for s in &r.sessions {
            if y < 20.0 {
                break;
            }
            // White card with thin border
            fill_rect(layer, MARGIN_LEFT, y - 4.0, CONTENT_WIDTH, 12.0, WHITE);
            stroke_rect(
                layer,
                MARGIN_LEFT,
                y - 4.0,
                CONTENT_WIDTH,
                12.0,
                BORDER_THICKNESS,
                BORDER_COLOR,
            );
            // Green left accent border (2mm wide)
            fill_rect(layer, MARGIN_LEFT, y - 4.0, 2.0, 12.0, (0.18, 0.49, 0.20));

            text(
                layer,
                &format!("Session {} — {:.0} min", s.index, s.duration_min),
                8.0,
                MARGIN_LEFT + 6.0,
                y + 3.0,
                &fonts.bold,
                BLACK,
            );
            text(
                layer,
                &s.summary,
                6.0,
                MARGIN_LEFT + 6.0,
                y - 1.5,
                &fonts.regular,
                GRAY,
            );
            y -= 16.0;
        }
    }
    y -= 7.0;

    // ── 6. Process Evidence ──
    text(
        layer,
        "6. Process Evidence",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 7.0;

    let p = &r.process;
    let evidence_items: Vec<(&str, String)> = vec![
        (
            "Revision Intensity",
            p.revision_intensity
                .map(|v| format!("{:.0}% non-append edits", v * 100.0))
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Pause Distribution",
            p.pause_median_sec
                .map(|v| {
                    let mut s = format!("Median: {:.1}s", v);
                    if let Some(p90) = p.pause_p90_sec {
                        s.push_str(&format!(" | P90: {:.1}s", p90));
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Paste Ratio",
            p.paste_ratio_pct
                .map(|v| format!("{:.1}% of total text", v))
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Keystroke Dynamics",
            p.iki_cv
                .map(|v| {
                    let mut s = format!("IKI CV: {:.2}", v);
                    if let Some(bg) = p.bigram_consistency {
                        s.push_str(&format!(" | Bigram: {:.2}", bg));
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Deletion Patterns",
            p.deletion_sequences
                .map(|v| {
                    let mut s = format!("{} sequences", v);
                    if let Some(avg) = p.avg_deletion_length {
                        s.push_str(&format!(" | Avg: {:.1} chars", avg));
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Time Proofs",
            p.swf_checkpoints
                .map(|v| {
                    let mut s = format!("{} SWF checkpoints", v);
                    if p.swf_chain_verified {
                        s.push_str(" | Chain: verified");
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
    ];

    let col_w = CONTENT_WIDTH / 2.0;
    for (i, (label, value)) in evidence_items.iter().enumerate() {
        let col = i % 2;
        let row = i / 2;
        let ex = MARGIN_LEFT + col as f32 * (col_w + 2.0);
        let ey = y - row as f32 * 16.0;

        // White card with thin border
        fill_rect(layer, ex, ey - 5.0, col_w - 2.0, 14.0, WHITE);
        stroke_rect(
            layer,
            ex,
            ey - 5.0,
            col_w - 2.0,
            14.0,
            BORDER_THICKNESS,
            BORDER_COLOR,
        );
        text(layer, label, 7.0, ex + 4.0, ey + 4.0, &fonts.bold, BLACK);
        text(layer, value, 6.5, ex + 4.0, ey - 0.5, &fonts.regular, GRAY);
    }
    y -= (evidence_items.len() as f32 / 2.0).ceil() * 16.0 + 7.0;

    // ── 7. Analysis Flags ──
    if !r.flags.is_empty() {
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
        text(
            layer,
            &format!("7. Analysis Flags ({} positive, {} negative)", pos, neg),
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 6.0;

        // Table header
        text(
            layer,
            "CATEGORY",
            5.5,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            GRAY,
        );
        text(layer, "FLAG", 5.5, MARGIN_LEFT + 30.0, y, &fonts.bold, GRAY);
        text(
            layer,
            "SIGNAL",
            5.5,
            MARGIN_LEFT + 130.0,
            y,
            &fonts.bold,
            GRAY,
        );
        y -= 4.0;

        for (row_idx, f) in r.flags.iter().enumerate() {
            if y < 18.0 {
                break;
            }
            // Alternating row backgrounds
            if row_idx % 2 == 0 {
                fill_rect(layer, MARGIN_LEFT, y - 2.0, CONTENT_WIDTH, 5.0, ALT_ROW);
            }

            let signal_color = match f.signal {
                FlagSignal::Human => (0.18_f32, 0.49, 0.20),
                FlagSignal::Synthetic => (0.78, 0.16, 0.16),
                FlagSignal::Neutral => (0.62, 0.62, 0.62),
            };
            let icon = match f.signal {
                FlagSignal::Human => "✓",
                FlagSignal::Synthetic => "✗",
                FlagSignal::Neutral => "—",
            };

            let category_display = if f.category.chars().count() > 40 {
                let truncated: String = f.category.chars().take(40).collect();
                format!("{truncated}...")
            } else {
                f.category.clone()
            };
            let flag_display = if f.flag.chars().count() > 60 {
                let truncated: String = f.flag.chars().take(60).collect();
                format!("{truncated}...")
            } else {
                f.flag.clone()
            };
            text(
                layer,
                &category_display,
                6.5,
                MARGIN_LEFT + 2.0,
                y,
                &fonts.regular,
                BLACK,
            );
            text(
                layer,
                &flag_display,
                6.5,
                MARGIN_LEFT + 30.0,
                y,
                &fonts.regular,
                BLACK,
            );
            text(
                layer,
                &format!("{} {}", icon, f.signal.label()),
                6.5,
                MARGIN_LEFT + 130.0,
                y,
                &fonts.bold,
                signal_color,
            );
            y -= 5.0;
        }
    }

    // ── 8. Forgery Resistance ──
    if y > 60.0 && !r.forgery.tier.is_empty() {
        y -= 7.0;
        text(
            layer,
            "8. Forgery Resistance",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 6.0;

        let tier_color = match r.forgery.tier.as_str() {
            "Very High" | "High" => (0.18_f32, 0.49, 0.20),
            "Moderate" => (0.96, 0.50, 0.09),
            _ => (0.78, 0.16, 0.16),
        };

        // Tier badge + estimated time
        fill_rect(layer, MARGIN_LEFT, y - 1.5, 28.0, 6.5, tier_color);
        text(
            layer,
            &r.forgery.tier,
            6.0,
            MARGIN_LEFT + 1.5,
            y,
            &fonts.bold,
            WHITE,
        );
        let forge_secs = r.forgery.estimated_forge_time_sec;
        let forge_label = if !forge_secs.is_finite() || forge_secs >= 1e30 {
            "Infeasible".to_string()
        } else if forge_secs >= 3.156e16 {
            let years = forge_secs / 3.156e7;
            let exp = years.log10().floor() as i32;
            format!("~10^{} years", exp)
        } else if forge_secs >= 3.156e7 {
            format!("{:.0} years", forge_secs / 3.156e7)
        } else if forge_secs >= 86400.0 {
            format!("{:.0} days", forge_secs / 86400.0)
        } else if forge_secs >= 3600.0 {
            format!("{:.0} hours", forge_secs / 3600.0)
        } else if forge_secs >= 60.0 {
            format!("{:.0} min", forge_secs / 60.0)
        } else {
            format!("{:.0}s", forge_secs)
        };
        text(
            layer,
            &forge_label,
            7.0,
            MARGIN_LEFT + 32.0,
            y,
            &fonts.regular,
            BLACK,
        );
        if let Some(ref wl) = r.forgery.weakest_link {
            text(
                layer,
                &format!("Weakest link: {}", wl),
                6.0,
                MARGIN_LEFT + 90.0,
                y,
                &fonts.regular,
                GRAY,
            );
        }
        y -= 8.0;

        // Component rows (present first, then absent)
        let comp_w = CONTENT_WIDTH / 2.0 - 1.0;
        let mut sorted_comps: Vec<_> = r.forgery.components.iter().collect();
        sorted_comps.sort_by_key(|c| std::cmp::Reverse(c.present));
        for (i, comp) in sorted_comps.iter().enumerate() {
            if y < 20.0 {
                break;
            }
            let cx = MARGIN_LEFT + (i % 2) as f32 * (comp_w + 2.0);
            let cy = y - (i / 2) as f32 * 11.0;
            fill_rect(layer, cx, cy - 4.0, comp_w, 10.0, WHITE);
            stroke_rect(
                layer,
                cx,
                cy - 4.0,
                comp_w,
                10.0,
                BORDER_THICKNESS,
                BORDER_COLOR,
            );
            let present_color = if comp.present {
                (0.18_f32, 0.49, 0.20)
            } else {
                (0.62, 0.62, 0.62)
            };
            let icon = if comp.present { "✓" } else { "○" };
            text(layer, icon, 7.0, cx + 2.0, cy, &fonts.bold, present_color);
            let name_display: String = comp.name.chars().take(22).collect();
            text(
                layer,
                &name_display,
                6.0,
                cx + 7.0,
                cy + 1.0,
                &fonts.bold,
                BLACK,
            );
            let cost_label = if !comp.cost_cpu_sec.is_finite() || comp.cost_cpu_sec >= 1e30 {
                "Infeasible".to_string()
            } else if comp.cost_cpu_sec >= 3.156e7 {
                let years = comp.cost_cpu_sec / 3.156e7;
                let exp = years.log10().floor() as i32;
                if exp > 3 {
                    format!("~10^{} yr CPU", exp)
                } else {
                    format!("{:.0} yr CPU", years)
                }
            } else if comp.cost_cpu_sec >= 3600.0 {
                format!("{:.0}h CPU", comp.cost_cpu_sec / 3600.0)
            } else {
                format!("{:.0}s CPU", comp.cost_cpu_sec)
            };
            text(
                layer,
                &cost_label,
                5.5,
                cx + 7.0,
                cy - 4.0,
                &fonts.regular,
                GRAY,
            );
        }
    }

    // Footer
    text(layer, footer, 5.0, MARGIN_LEFT, 10.0, &fonts.regular, GRAY);
}
