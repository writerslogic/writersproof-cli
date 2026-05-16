// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Chart rendering for PDF reports.
//!
//! Draws writing flow visualizations and score bars as PDF vector graphics.

use crate::report::types::*;
use printpdf::*;

/// Draw the writing flow chart as a bar chart.
///
/// Each bar represents a time slice with height proportional to keystroke
/// intensity and color indicating the phase (drafting/revising/polishing/pause).
pub fn draw_flow_chart(
    layer: &PdfLayerReference,
    flow: &[FlowDataPoint],
    x_mm: f32,
    y_mm: f32,
    width_mm: f32,
    height_mm: f32,
) {
    if flow.is_empty() {
        return;
    }

    // Background
    let bg = Color::Rgb(Rgb::new(0.98, 0.98, 0.98, None));
    let bg_rect = Rect::new(
        Mm(x_mm),
        Mm(y_mm),
        Mm(x_mm + width_mm),
        Mm(y_mm + height_mm),
    );
    layer.set_fill_color(bg);
    layer.add_rect(bg_rect);

    let max_intensity = flow
        .iter()
        .map(|p| p.intensity)
        .fold(0.0_f64, f64::max)
        .max(0.01);

    let bar_width = width_mm / flow.len() as f32;

    for (i, point) in flow.iter().enumerate() {
        let pct = (point.intensity / max_intensity).min(1.0) as f32;
        let bar_height = pct * height_mm;
        let bx = x_mm + i as f32 * bar_width;

        let color = match point.phase.as_str() {
            "drafting" => Color::Rgb(Rgb::new(0.298, 0.686, 0.314, None)), // green
            "revising" => Color::Rgb(Rgb::new(0.129, 0.588, 0.953, None)), // blue
            "polish" => Color::Rgb(Rgb::new(0.612, 0.153, 0.691, None)),   // purple
            "pause" => Color::Rgb(Rgb::new(0.878, 0.878, 0.878, None)),    // gray
            _ => Color::Rgb(Rgb::new(0.471, 0.565, 0.612, None)),          // blue-gray
        };

        let bar = Rect::new(Mm(bx), Mm(y_mm), Mm(bx + bar_width), Mm(y_mm + bar_height));
        layer.set_fill_color(color);
        layer.add_rect(bar);
    }
}

/// Draw a horizontal score bar with label.
#[allow(clippy::too_many_arguments)]
pub fn draw_score_bar(
    layer: &PdfLayerReference,
    font: &IndirectFontRef,
    font_bold: &IndirectFontRef,
    label: &str,
    score: u32,
    color: (f32, f32, f32),
    x_mm: f32,
    y_mm: f32,
    bar_width_mm: f32,
) {
    // Label
    layer.set_fill_color(Color::Rgb(Rgb::new(color.0, color.1, color.2, None)));
    layer.use_text(label, 9.0, Mm(x_mm), Mm(y_mm), font_bold);

    // Track background
    let track_x = x_mm + 42.0;
    let track_h = 5.0_f32;
    let bg = Color::Rgb(Rgb::new(0.93, 0.93, 0.93, None));
    let track = Rect::new(
        Mm(track_x),
        Mm(y_mm - 1.0),
        Mm(track_x + bar_width_mm),
        Mm(y_mm + track_h - 1.0),
    );
    layer.set_fill_color(bg);
    layer.add_rect(track);

    // Fill
    let fill_width = (score as f32 / 100.0) * bar_width_mm;
    let fill = Rect::new(
        Mm(track_x),
        Mm(y_mm - 1.0),
        Mm(track_x + fill_width),
        Mm(y_mm + track_h - 1.0),
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(color.0, color.1, color.2, None)));
    layer.add_rect(fill);

    // Score text
    layer.set_fill_color(Color::Rgb(Rgb::new(0.13, 0.13, 0.13, None)));
    layer.use_text(
        score.to_string(),
        9.0,
        Mm(track_x + bar_width_mm + 3.0),
        Mm(y_mm),
        font,
    );
}

/// Draw an edit topology bar showing spatial edit distribution across a document.
///
/// Bins the edit regions into 20 segments (0-100% of document position).
/// Insertions are green, deletions are red, and segments with no edits are light gray.
pub fn draw_topology_bar(
    layer: &PdfLayerReference,
    regions: &[EditRegion],
    x: f32,
    y: f32,
    width: f32,
    height: f32,
) {
    const NUM_BINS: usize = 20;
    let mut bins = [0_i64; NUM_BINS];

    for region in regions {
        let start_bin = ((region.start_pct / 100.0) * NUM_BINS as f64)
            .floor()
            .clamp(0.0, (NUM_BINS - 1) as f64) as usize;
        let end_bin = ((region.end_pct / 100.0) * NUM_BINS as f64)
            .ceil()
            .clamp(0.0, NUM_BINS as f64) as usize;
        for bin in &mut bins[start_bin..end_bin.min(NUM_BINS)] {
            *bin += region.byte_count;
        }
    }

    let bin_w = width / NUM_BINS as f32;
    for (i, &net) in bins.iter().enumerate() {
        let bx = x + i as f32 * bin_w;
        let color = if net > 0 {
            Color::Rgb(Rgb::new(0.235, 0.478, 0.290, None)) // green - insertions
        } else if net < 0 {
            Color::Rgb(Rgb::new(0.780, 0.160, 0.160, None)) // red - deletions
        } else {
            Color::Rgb(Rgb::new(0.910, 0.910, 0.910, None)) // light gray - no edits
        };
        layer.set_fill_color(color);
        layer.add_rect(Rect::new(
            Mm(bx),
            Mm(y),
            Mm(bx + bin_w - 0.3),
            Mm(y + height),
        ));
    }
}

/// Draw a context timeline showing activity periods as proportionally-sized colored bars.
///
/// Colors by period type: focused=green, break=gray, research=blue,
/// revision=orange, idle=light gray.
pub fn draw_context_timeline(
    layer: &PdfLayerReference,
    contexts: &[ActivityContext],
    x: f32,
    y: f32,
    width: f32,
    height: f32,
) {
    if contexts.is_empty() {
        return;
    }

    let total_min: f64 = contexts.iter().map(|c| c.duration_min).sum();
    if total_min <= 0.0 {
        return;
    }

    let mut cx = x;
    for ctx in contexts {
        let frac = (ctx.duration_min / total_min) as f32;
        let seg_w = frac * width;
        if seg_w < 0.2 {
            cx += seg_w;
            continue;
        }
        let color = match ctx.period_type.as_str() {
            "focused" => Color::Rgb(Rgb::new(0.235, 0.478, 0.290, None)),
            "break" => Color::Rgb(Rgb::new(0.600, 0.600, 0.600, None)),
            "research" => Color::Rgb(Rgb::new(0.173, 0.322, 0.510, None)),
            "revision" => Color::Rgb(Rgb::new(0.902, 0.320, 0.000, None)),
            _ => Color::Rgb(Rgb::new(0.867, 0.867, 0.867, None)), // idle/unknown
        };
        layer.set_fill_color(color);
        layer.add_rect(Rect::new(Mm(cx), Mm(y), Mm(cx + seg_w), Mm(y + height)));
        cx += seg_w;
    }
}
