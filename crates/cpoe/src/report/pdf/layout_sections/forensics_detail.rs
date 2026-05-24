// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::report::types::*;
use crate::utils::finite_or;

pub fn draw_forensics_page(
    layer: &PdfLayerReference,
    report: &WarReport,
    fonts: &PdfFonts,
    footer: &str,
) {
    let mut y = PAGE_TOP;

    // ── Page Title ──
    text(
        layer,
        "Forensic Analysis Details",
        12.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 10.0;

    // ── Writing Mode Section ──
    if let Some(ref fm) = report.forensic_metrics {
        text(
            layer,
            "Writing Mode",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 7.0;

        // Writing mode badge
        // writing_mode is stored lowercase ("cognitive", "transcriptive", "mixed", "insufficient")
        let mode_color = match fm.writing_mode.as_str() {
            "cognitive" => (0.18, 0.49, 0.20),
            "transcriptive" => (0.78, 0.16, 0.16),
            _ => (0.96, 0.50, 0.09), // Mixed / insufficient / unknown
        };
        fill_rect(layer, MARGIN_LEFT, y - 1.5, 30.0, 7.0, mode_color);
        text(
            layer,
            &fm.writing_mode,
            7.0,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            WHITE,
        );

        // Risk level badge
        // risk_level is stored lowercase ("low", "high", "undetermined")
        let risk_color = match fm.risk_level.as_str() {
            "low" => (0.18, 0.49, 0.20),
            "medium" => (0.96, 0.50, 0.09),
            _ => (0.78, 0.16, 0.16), // High / Critical / undetermined
        };
        fill_rect(layer, MARGIN_LEFT + 34.0, y - 1.5, 24.0, 7.0, risk_color);
        text(
            layer,
            &format!("Risk: {}", fm.risk_level),
            6.0,
            MARGIN_LEFT + 36.0,
            y,
            &fonts.bold,
            WHITE,
        );
        y -= 10.0;

        // Cognitive score bar
        let cog_f = if fm.cognitive_score.is_finite() {
            fm.cognitive_score
        } else {
            0.0
        };
        let cog_score = (cog_f * 100.0).round().clamp(0.0, 100.0) as u32;
        super::super::charts::draw_score_bar(
            layer,
            &fonts.regular,
            &fonts.bold,
            "Cognitive",
            cog_score,
            (0.13, 0.59, 0.95),
            MARGIN_LEFT + 2.0,
            y,
            100.0,
        );
        y -= 8.0;

        // Revision cycle count and Hurst exponent
        text(
            layer,
            &format!("Revision Cycles: {}", fm.revision_cycle_count),
            7.0,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.regular,
            BLACK,
        );
        if let Some(hurst) = fm.hurst_exponent.filter(|v| v.is_finite()) {
            text(
                layer,
                &format!("Hurst Exponent: {:.3}", hurst),
                7.0,
                MARGIN_LEFT + 60.0,
                y,
                &fonts.regular,
                BLACK,
            );
        }
        y -= 12.0;

        // ── Cadence Metrics (2x3 grid of cards) ──
        text(
            layer,
            "Cadence Metrics",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 7.0;

        let metrics: [(&str, String); 6] = [
            (
                "Mean IKI (ms)",
                format!("{:.1}", finite_or(fm.mean_iki_ms, 0.0)),
            ),
            (
                "CV",
                format!("{:.3}", finite_or(fm.coefficient_of_variation, 0.0)),
            ),
            ("Burst Count", format!("{}", fm.burst_count)),
            ("Pause Count", format!("{}", fm.pause_count)),
            (
                "Correction Ratio",
                format!("{:.3}", finite_or(fm.correction_ratio, 0.0)),
            ),
            (
                "Burst Speed CV",
                format!("{:.3}", finite_or(fm.burst_speed_cv, 0.0)),
            ),
        ];

        let card_w = (CONTENT_WIDTH - 4.0) / 3.0;
        let card_h = 14.0;
        for (i, (label, value)) in metrics.iter().enumerate() {
            let col = i % 3;
            let row = i / 3;
            let cx = MARGIN_LEFT + col as f32 * (card_w + 2.0);
            let cy = y - row as f32 * (card_h + 2.0);

            draw_card(layer, cx, cy - card_h, card_w, card_h);
            text(layer, label, 6.0, cx + 3.0, cy - 3.0, &fonts.bold, GRAY);
            text(layer, value, 9.0, cx + 3.0, cy - 9.0, &fonts.bold, BLACK);
        }
        y -= 2.0 * (card_h + 2.0) + 7.0;

        // ── Enhanced Signal Scores ──
        let has_enhanced = fm.cognitive_load_score.is_some()
            || fm.revision_topology_score.is_some()
            || fm.detour_ratio.is_some();
        if has_enhanced && y > 60.0 {
            text(layer, "Enhanced Signal Scores", 10.0, MARGIN_LEFT, y, &fonts.bold, BLACK);
            y -= 7.0;

            let mut signal_cards: Vec<(&str, String)> = Vec::new();
            if let Some(s) = fm.cognitive_load_score {
                signal_cards.push(("Cognitive Load", format!("{:.0}%", s * 100.0)));
            }
            if let Some(s) = fm.revision_topology_score {
                signal_cards.push(("Revision Topology", format!("{:.0}%", s * 100.0)));
            }
            if let Some(d) = fm.detour_ratio {
                signal_cards.push(("Detour Ratio", format!("{:.3}", d)));
            }
            if let Some(l) = fm.leading_edge_divergence {
                signal_cards.push(("Leading-Edge Div.", format!("{:.1}%", l * 100.0)));
            }
            if let Some(e) = fm.insertion_point_entropy {
                signal_cards.push(("Insertion Entropy", format!("{:.2} bits", e)));
            }
            if let Some(s) = fm.error_ecology_score {
                signal_cards.push(("Error Ecology", format!("{:.0}%", s * 100.0)));
            }
            if let Some(p) = fm.likelihood_p_cognitive {
                signal_cards.push(("P(Cognitive)", format!("{:.0}%", p * 100.0)));
            }

            let sig_card_w = (CONTENT_WIDTH - 4.0) / 3.0;
            let sig_card_h = 14.0;
            for (i, (label, value)) in signal_cards.iter().enumerate() {
                let col = i % 3;
                let row = i / 3;
                let cx = MARGIN_LEFT + col as f32 * (sig_card_w + 2.0);
                let cy = y - row as f32 * (sig_card_h + 2.0);
                draw_card(layer, cx, cy - sig_card_h, sig_card_w, sig_card_h);
                text(layer, label, 6.0, cx + 3.0, cy - 3.0, &fonts.bold, GRAY);
                text(layer, value, 9.0, cx + 3.0, cy - 9.0, &fonts.bold, BLACK);
            }
            let rows = signal_cards.len().div_ceil(3);
            y -= rows as f32 * (sig_card_h + 2.0) + 7.0;
        }
    }

    // ── Edit Topology ──
    if !report.edit_topology.is_empty() && y > 40.0 {
        text(
            layer,
            "Edit Distribution Across Document",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 4.0;

        super::super::charts::draw_topology_bar(
            layer,
            &report.edit_topology,
            MARGIN_LEFT,
            y - 10.0,
            CONTENT_WIDTH,
            10.0,
        );
        y -= 14.0;
        text(
            layer,
            "Green = insertions, Red = deletions, Gray = no edits",
            5.5,
            MARGIN_LEFT,
            y,
            &fonts.regular,
            GRAY,
        );
        y -= 10.0;
    }

    // ── Activity Context Timeline ──
    if !report.activity_contexts.is_empty() && y > 30.0 {
        text(
            layer,
            "Activity Timeline",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 4.0;

        super::super::charts::draw_context_timeline(
            layer,
            &report.activity_contexts,
            MARGIN_LEFT,
            y - 8.0,
            CONTENT_WIDTH,
            8.0,
        );
        y -= 12.0;
        text(
            layer,
            "Green=focused  Gray=break  Blue=research  Orange=revision",
            5.5,
            MARGIN_LEFT,
            y,
            &fonts.regular,
            GRAY,
        );
        y -= 10.0;
    }

    // ── Anomalies Table ──
    if !report.anomalies.is_empty() && y > 30.0 {
        text(
            layer,
            &format!("Anomalies ({})", report.anomalies.len()),
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
            "SEVERITY",
            5.5,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            GRAY,
        );
        text(layer, "TYPE", 5.5, MARGIN_LEFT + 28.0, y, &fonts.bold, GRAY);
        text(
            layer,
            "DESCRIPTION",
            5.5,
            MARGIN_LEFT + 60.0,
            y,
            &fonts.bold,
            GRAY,
        );
        y -= 4.0;

        for (row_idx, anomaly) in report.anomalies.iter().enumerate() {
            if y < 18.0 {
                break;
            }
            if row_idx % 2 == 0 {
                fill_rect(layer, MARGIN_LEFT, y - 2.0, CONTENT_WIDTH, 5.0, ALT_ROW);
            }

            let sev_color = match anomaly.severity.as_str() {
                "Alert" => (0.78_f32, 0.16, 0.16),
                "Warning" => (0.90, 0.45, 0.00),
                _ => (0.13, 0.47, 0.78), // Info / other
            };
            text(
                layer,
                &anomaly.severity,
                6.5,
                MARGIN_LEFT + 2.0,
                y,
                &fonts.bold,
                sev_color,
            );

            let type_display = if anomaly.anomaly_type.len() > 20 {
                let t: String = anomaly.anomaly_type.chars().take(20).collect();
                format!("{t}...")
            } else {
                anomaly.anomaly_type.clone()
            };
            text(
                layer,
                &type_display,
                6.5,
                MARGIN_LEFT + 28.0,
                y,
                &fonts.regular,
                BLACK,
            );

            let desc_display = if anomaly.description.len() > 65 {
                let d: String = anomaly.description.chars().take(65).collect();
                format!("{d}...")
            } else {
                anomaly.description.clone()
            };
            text(
                layer,
                &desc_display,
                6.0,
                MARGIN_LEFT + 60.0,
                y,
                &fonts.regular,
                BLACK,
            );

            y -= 5.0;
        }
    }

    // ── Footer ──
    text(layer, footer, 5.0, MARGIN_LEFT, 10.0, &fonts.regular, GRAY);
}
