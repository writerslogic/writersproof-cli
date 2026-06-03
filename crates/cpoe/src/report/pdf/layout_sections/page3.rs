// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::report::types::*;

pub fn draw_page3(layer: &PdfLayerReference, r: &WarReport, fonts: &PdfFonts, footer: &str) {
    let mut y = PAGE_TOP;

    // ── 9. Scope & Limitations ──
    text(
        layer,
        "9. Scope and Limitations",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 7.0;

    let supports = [
        "Evidence of human cognitive constraint patterns",
        "Stylometric consistency with natural authorship",
        "Documented methodology for dispute review",
        "Reproducible analysis (same text + algorithm = same results)",
    ];
    text(
        layer,
        "What This Report Supports:",
        7.0,
        MARGIN_LEFT + 2.0,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 4.0;
    for item in &supports {
        text(
            layer,
            &format!("• {}", item),
            6.0,
            MARGIN_LEFT + 4.0,
            y,
            &fonts.regular,
            BLACK,
        );
        y -= 4.0;
    }
    y -= 2.0;

    let does_not = [
        "Named author identity (requires additional evidence)",
        "AI was not used at any point in the process",
        "Text has not been edited, paraphrased, or translated",
        "Definitive attribution beyond reasonable doubt",
    ];
    text(
        layer,
        "What This Report Does NOT Prove:",
        7.0,
        MARGIN_LEFT + 2.0,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 4.0;
    for item in &does_not {
        text(
            layer,
            &format!("• {}", item),
            6.0,
            MARGIN_LEFT + 4.0,
            y,
            &fonts.regular,
            BLACK,
        );
        y -= 4.0;
    }
    y -= 7.0;

    // ── 10. Verification Instructions ──
    text(
        layer,
        "10. Independent Verification",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 8.0;

    let box_h = 28.0;
    let half_w = CONTENT_WIDTH / 2.0 - 2.0;

    // Offline box: white with border
    fill_rect(layer, MARGIN_LEFT, y - 24.0, half_w, box_h, WHITE);
    stroke_rect(
        layer,
        MARGIN_LEFT,
        y - 24.0,
        half_w,
        box_h,
        BORDER_THICKNESS,
        BORDER_COLOR,
    );
    text(
        layer,
        "OFFLINE VERIFICATION",
        7.0,
        MARGIN_LEFT + 5.0,
        y,
        &fonts.bold,
        BLACK,
    );
    text(
        layer,
        "Extract WAR seal from PDF → verify Ed25519",
        5.5,
        MARGIN_LEFT + 5.0,
        y - 5.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "signature → verify enrollment cert chain",
        5.5,
        MARGIN_LEFT + 5.0,
        y - 9.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "Run: writersproof-cli verify <file.pdf>",
        6.0,
        MARGIN_LEFT + 5.0,
        y - 17.0,
        &fonts.mono,
        BLACK,
    );

    // Online box: white with border
    let ox = MARGIN_LEFT + CONTENT_WIDTH / 2.0 + 2.0;
    fill_rect(layer, ox, y - 24.0, half_w, box_h, WHITE);
    stroke_rect(
        layer,
        ox,
        y - 24.0,
        half_w,
        box_h,
        BORDER_THICKNESS,
        BORDER_COLOR,
    );
    text(
        layer,
        "ONLINE VERIFICATION",
        7.0,
        ox + 5.0,
        y,
        &fonts.bold,
        BLACK,
    );
    text(
        layer,
        "All offline checks + transparency log",
        5.5,
        ox + 5.0,
        y - 5.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "anchor + certificate revocation check",
        5.5,
        ox + 5.0,
        y - 9.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "Scan QR or visit writersproof.com/verify",
        6.0,
        ox + 5.0,
        y - 17.0,
        &fonts.mono,
        BLACK,
    );
    y -= 34.0;

    // ── Additional Limitations ──
    if !r.limitations.is_empty() {
        text(
            layer,
            "Additional Limitations:",
            7.0,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 4.0;
        for lim in &r.limitations {
            text(
                layer,
                &format!("• {}", lim),
                6.0,
                MARGIN_LEFT + 4.0,
                y,
                &fonts.regular,
                BLACK,
            );
            y -= 4.0;
        }
    }
    y -= 7.0;

    // ── 11. Analyzed Text (if available) ──
    if let Some(ref analyzed) = r.analyzed_text {
        text(
            layer,
            "11. Analyzed Text",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 3.0;
        text(
            layer,
            "Document hash verified against chain of custody record.",
            5.5,
            MARGIN_LEFT,
            y,
            &fonts.regular,
            GRAY,
        );
        y -= 5.0;

        // White box with thin border
        fill_rect(layer, MARGIN_LEFT, y - 60.0, CONTENT_WIDTH, 62.0, WHITE);
        stroke_rect(
            layer,
            MARGIN_LEFT,
            y - 60.0,
            CONTENT_WIDTH,
            62.0,
            BORDER_THICKNESS,
            BORDER_COLOR,
        );

        // Word-wrap the text into the box
        let mut ty = y - 3.0;
        for line in wrap_text_lines(analyzed, 100) {
            text(
                layer,
                &line,
                6.5,
                MARGIN_LEFT + 5.0,
                ty,
                &fonts.regular,
                BLACK,
            );
            ty -= 4.0;
            if ty < y - 58.0 {
                text(
                    layer,
                    "[continued...]",
                    5.5,
                    MARGIN_LEFT + 5.0,
                    ty,
                    &fonts.regular,
                    GRAY,
                );
                break;
            }
        }
    }

    // ── VERIFICATION BLOCK ──
    // Visually distinct bordered block as the human-readable trust anchor.
    let vb_h = 42.0;
    let vb_y = 22.0;
    // Dark border
    stroke_rect(
        layer,
        MARGIN_LEFT,
        vb_y,
        CONTENT_WIDTH,
        vb_h,
        0.8,
        (0.13, 0.13, 0.13),
    );
    // Light inner background
    fill_rect(
        layer,
        MARGIN_LEFT + 0.4,
        vb_y + 0.4,
        CONTENT_WIDTH - 0.8,
        vb_h - 0.8,
        (0.97, 0.97, 0.99),
    );

    let mut vy = vb_y + vb_h - 4.0;
    text(
        layer,
        "VERIFICATION",
        9.0,
        MARGIN_LEFT + 4.0,
        vy,
        &fonts.bold,
        BLACK,
    );
    vy -= 5.5;

    let lr_str = if r.likelihood_ratio >= 100.0 {
        format!("{:.0}", r.likelihood_ratio)
    } else {
        format!("{:.1}", r.likelihood_ratio)
    };
    let vb_rows: Vec<(&str, String)> = vec![
        ("Report ID:", r.report_id.clone()),
        ("Document Hash (SHA-256):", r.document_hash.clone()),
        (
            "Evidence Hash:",
            r.evidence_hash.clone().unwrap_or_else(|| "N/A".to_string()),
        ),
        ("Signing Key:", r.signing_key_fingerprint.clone()),
        (
            "Assessment:",
            format!("{}/100 | LR {} | {}", r.score, lr_str, r.enfsi_tier.label()),
        ),
        (
            "Generated:",
            r.generated_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        ),
        ("Verify:", "https://writersproof.com/verify".to_string()),
    ];
    for (label, value) in &vb_rows {
        text(layer, label, 5.5, MARGIN_LEFT + 4.0, vy, &fonts.bold, BLACK);
        // Truncate long hashes for display
        let display = if value.len() > 72 {
            format!(
                "{}...{}",
                value.get(..32).unwrap_or(value),
                value.get(value.len().saturating_sub(8)..).unwrap_or(value),
            )
        } else {
            value.clone()
        };
        text(
            layer,
            &display,
            5.0,
            MARGIN_LEFT + 40.0,
            vy,
            &fonts.mono,
            (0.20, 0.20, 0.20),
        );
        vy -= 4.5;
    }

    // ── Disclaimer / Footer ──
    text(
        layer,
        "This report documents process analysis only. It does not constitute legal advice or definitive proof of authorship.",
        5.0,
        MARGIN_LEFT,
        15.0,
        &fonts.regular,
        GRAY,
    );
    text(layer, footer, 5.0, MARGIN_LEFT, 10.0, &fonts.regular, GRAY);
}
