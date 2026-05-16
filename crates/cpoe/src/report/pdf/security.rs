// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Anti-forgery security features for PDF reports.
//!
//! All visual security features are seeded from a signature-dependent value
//! (`sign("cpoe-security-v1" || H3)`), making them cryptographically bound
//! to the evidence packet. A forger cannot reproduce them without the
//! signing key.

use printpdf::*;

/// Draw a guilloché border pattern around the page.
///
/// The pattern is a parametric spirograph curve whose parameters are
/// derived from `seed` — a 64-byte Ed25519 signature that only the
/// key holder can produce. Different evidence packets produce visually
/// distinct patterns.
pub fn draw_guilloche_border(layer: &PdfLayerReference, seed: &[u8; 64]) {
    // Extract pattern parameters from the seed bytes.
    // Using different byte ranges for different parameters ensures
    // each parameter varies independently.
    let r1 = 8.0 + (seed[0] as f64 / 255.0) * 4.0; // outer radius: 8-12mm
    let r2 = 2.0 + (seed[1] as f64 / 255.0) * 3.0; // inner radius: 2-5mm
    let d = 1.0 + (seed[2] as f64 / 255.0) * 2.0; // pen distance: 1-3mm
    let phase = (seed[3] as f64 / 255.0) * std::f64::consts::TAU;
    let num_loops = 200 + (seed[4] as usize % 100); // 200-300 points per side

    // Color derived from seed bytes 8-10, very faint (~3-5% opacity equivalent)
    let r = 0.95 + (seed[8] as f32 / 255.0) * 0.03;
    let g = 0.95 + (seed[9] as f32 / 255.0) * 0.03;
    let b = 0.95 + (seed[10] as f32 / 255.0) * 0.03;

    let color = Color::Rgb(Rgb::new(r, g, b, None));
    let line_width = 0.15; // very fine line — degrades when photocopied

    // Page dimensions (A4)
    let page_w = 210.0_f64;
    let page_h = 297.0_f64;
    let margin = 8.0_f64;

    // Draw guilloché along each edge
    for edge in 0..4 {
        let points: Vec<(Point, bool)> = (0..num_loops)
            .map(|i| {
                let t = (i as f64 / num_loops as f64) * std::f64::consts::TAU * 6.0 + phase;

                // Spirograph: x = (R-r)*cos(t) + d*cos((R-r)/r * t)
                let gx = (r1 - r2) * t.cos() + d * ((r1 - r2) / r2 * t).cos();
                let gy = (r1 - r2) * t.sin() - d * ((r1 - r2) / r2 * t).sin();

                // Map to edge position
                let frac = i as f64 / num_loops as f64;
                let (px, py) = match edge {
                    0 => (margin + frac * (page_w - 2.0 * margin), margin + gy * 0.5),
                    1 => (
                        page_w - margin + gx * 0.5,
                        margin + frac * (page_h - 2.0 * margin),
                    ),
                    2 => (
                        page_w - margin - frac * (page_w - 2.0 * margin),
                        page_h - margin + gy * 0.5,
                    ),
                    _ => (
                        margin + gx * 0.5,
                        page_h - margin - frac * (page_h - 2.0 * margin),
                    ),
                };

                (Point::new(Mm(px as f32), Mm(py as f32)), i == 0)
            })
            .collect();

        let line = Line {
            points,
            is_closed: false,
        };

        layer.set_outline_color(color.clone());
        layer.set_outline_thickness(line_width);
        layer.add_line(line);
    }

    // Corner rosettes — small circular patterns at each corner
    for corner in 0..4 {
        let (cx, cy) = match corner {
            0 => (margin + 4.0, margin + 4.0),
            1 => (page_w - margin - 4.0, margin + 4.0),
            2 => (page_w - margin - 4.0, page_h - margin - 4.0),
            _ => (margin + 4.0, page_h - margin - 4.0),
        };

        let rosette_points: Vec<(Point, bool)> = (0..120)
            .map(|i| {
                let t = (i as f64 / 120.0) * std::f64::consts::TAU * 4.0;
                let corner_seed = seed[(16 + corner * 4) as usize] as f64 / 255.0;
                let rr = 2.0 + corner_seed * 1.5;
                let x = cx + rr * (t.cos() + (t * 3.0).cos() * 0.3);
                let y = cy + rr * (t.sin() + (t * 3.0).sin() * 0.3);
                (Point::new(Mm(x as f32), Mm(y as f32)), i == 0)
            })
            .collect();

        let rosette = Line {
            points: rosette_points,
            is_closed: true,
        };

        layer.set_outline_color(color.clone());
        layer.set_outline_thickness(0.1);
        layer.add_line(rosette);
    }
}

/// Draw microtext along a horizontal line.
///
/// At normal zoom, the text appears as a decorative rule line.
/// Under magnification, it reads as repeated text containing the report ID
/// and document hash — providing a visual authenticity marker.
pub fn draw_microtext(
    layer: &PdfLayerReference,
    font: &IndirectFontRef,
    y_mm: f32,
    text: &str,
    page_width_mm: f32,
) {
    if text.is_empty() {
        return;
    }
    let font_size = 1.5_f32; // 1.5pt — appears as a thin line at normal zoom
    let margin = 15.0_f32;
    let repeat_width = text.len() as f32 * 0.5; // approximate char width at 1.5pt
    let available = page_width_mm - 2.0 * margin;
    let repeats = (available / repeat_width).ceil() as usize;

    let repeats = repeats.max(1);
    const SEPARATOR: &str = " · ";
    let mut full_text =
        String::with_capacity(text.len() * repeats + SEPARATOR.len() * repeats.saturating_sub(1));
    for i in 0..repeats {
        if i > 0 {
            full_text.push_str(SEPARATOR);
        }
        full_text.push_str(text);
    }

    // Truncate to fit
    let max_chars = (available / 0.5) as usize;
    let display: String = full_text.chars().take(max_chars).collect();

    layer.use_text(&display, font_size, Mm(margin), Mm(y_mm), font);
}
