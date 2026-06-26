// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Inline SVG chart generators for HTML forensic reports.
//!
//! Each function returns a self-contained `<svg>` string. No external JS or CSS.
//! All charts use the same color palette as the CSS theme.

use std::fmt::Write;

const WIDTH: f64 = 720.0;
const HEIGHT: f64 = 200.0;
const PAD_L: f64 = 55.0;
const PAD_R: f64 = 15.0;
const PAD_T: f64 = 20.0;
const PAD_B: f64 = 30.0;
const PLOT_W: f64 = WIDTH - PAD_L - PAD_R;
const PLOT_H: f64 = HEIGHT - PAD_T - PAD_B;

const COLOR_PRIMARY: &str = "#3b82f6";
const COLOR_SUCCESS: &str = "#22c55e";
const COLOR_WARNING: &str = "#f59e0b";
const COLOR_ERROR: &str = "#ef4444";
const COLOR_GRID: &str = "#e5e7eb";
const COLOR_TEXT: &str = "#6b7280";
const COLOR_AREA: &str = "rgba(59,130,246,0.12)";

/// Writing flow intensity chart — multi-phase area plot over time.
///
/// Shows the rhythm and intensity of writing across the session with
/// color-coded phases (composing, editing, idle).
pub fn writing_flow_chart(flow: &[super::super::types::FlowDataPoint]) -> String {
    if flow.len() < 2 {
        return String::new();
    }
    let mut svg = String::with_capacity(4096);
    let _ = write_writing_flow(&mut svg, flow);
    svg
}

fn write_writing_flow(
    svg: &mut String,
    flow: &[super::super::types::FlowDataPoint],
) -> std::fmt::Result {
    let max_int = flow
        .iter()
        .map(|p| {
            if p.intensity.is_finite() {
                p.intensity
            } else {
                0.0
            }
        })
        .fold(0.01f64, f64::max);
    let max_min = flow
        .iter()
        .map(|p| {
            if p.offset_min.is_finite() {
                p.offset_min
            } else {
                0.0
            }
        })
        .fold(0.0f64, f64::max);

    let h = HEIGHT + 20.0; // extra room for legend
    write!(
        svg,
        r#"<svg viewBox="0 0 {WIDTH} {h}" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:{WIDTH}px;height:auto;font-family:-apple-system,BlinkMacSystemFont,sans-serif">"#,
    )?;

    // Grid
    for i in 0..=4 {
        let y = PAD_T + PLOT_H * (1.0 - i as f64 / 4.0);
        write!(
            svg,
            r#"<line x1="{PAD_L}" y1="{y}" x2="{}" y2="{y}" stroke="{COLOR_GRID}" stroke-width="0.5"/>"#,
            PAD_L + PLOT_W,
        )?;
    }

    // Phase-colored bars (like a spectrogram)
    let bar_w = if flow.len() > 1 {
        (PLOT_W / flow.len() as f64).max(1.0)
    } else {
        PLOT_W
    };

    for (i, pt) in flow.iter().enumerate() {
        let intensity = if pt.intensity.is_finite() {
            pt.intensity
        } else {
            0.0
        };
        let pct = intensity / max_int;
        let bar_h = (PLOT_H * pct).max(0.5);
        let x = PAD_L + i as f64 * bar_w;
        let y = PAD_T + PLOT_H - bar_h;
        let color = phase_color(&pt.phase);
        write!(
            svg,
            r#"<rect x="{x:.1}" y="{y:.1}" width="{:.1}" height="{bar_h:.1}" fill="{color}" opacity="0.85"/>"#,
            bar_w.max(0.8),
        )?;
    }

    // Smoothed envelope line over the bars
    if flow.len() >= 3 {
        let x_scale = if max_min > 0.0 {
            PLOT_W / max_min
        } else {
            PLOT_W / flow.len() as f64
        };
        let mut line = String::with_capacity(flow.len() * 16);
        for (i, pt) in flow.iter().enumerate() {
            let intensity = if pt.intensity.is_finite() {
                pt.intensity
            } else {
                0.0
            };
            let x = PAD_L
                + if max_min > 0.0 {
                    pt.offset_min * x_scale
                } else {
                    i as f64 * bar_w + bar_w / 2.0
                };
            let y = (PAD_T + PLOT_H - PLOT_H * intensity / max_int).clamp(PAD_T, PAD_T + PLOT_H);
            if i == 0 {
                write!(line, "M{x:.1},{y:.1}")?;
            } else {
                write!(line, " L{x:.1},{y:.1}")?;
            }
        }
        write!(
            svg,
            r#"<path d="{line}" fill="none" stroke="rgba(0,0,0,0.3)" stroke-width="1" stroke-linejoin="round"/>"#,
        )?;
    }

    // X-axis time labels
    let tick_count = 5.min(flow.len());
    if tick_count > 0 && max_min > 0.0 {
        let x_scale = PLOT_W / max_min;
        for i in 0..=tick_count {
            let min = max_min * i as f64 / tick_count as f64;
            let x = PAD_L + min * x_scale;
            write!(
                svg,
                r#"<text x="{x:.1}" y="{}" text-anchor="middle" font-size="9" fill="{COLOR_TEXT}">{min:.0}m</text>"#,
                PAD_T + PLOT_H + 14.0,
            )?;
        }
    }

    // Legend
    let legend_y = PAD_T + PLOT_H + 28.0;
    for (i, (label, color)) in [
        ("Drafting", "#3d7a4a"),
        ("Revising", "#2c5282"),
        ("Polish", "#5b3c8b"),
        ("Pause", "#d8d8d5"),
    ]
    .iter()
    .enumerate()
    {
        let lx = PAD_L + i as f64 * 120.0;
        write!(
            svg,
            r#"<rect x="{lx}" y="{}" width="10" height="10" rx="2" fill="{color}"/>"#,
            legend_y - 8.0,
        )?;
        write!(
            svg,
            r#"<text x="{}" y="{legend_y}" font-size="10" fill="{COLOR_TEXT}">{label}</text>"#,
            lx + 14.0,
        )?;
    }

    write!(svg, "</svg>")
}

fn phase_color(phase: &str) -> &'static str {
    match phase {
        "drafting" => "#3d7a4a",
        "revising" => "#2c5282",
        "polish" => "#5b3c8b",
        "pause" => "#d8d8d5",
        _ => "#6b6b6b",
    }
}

/// Dimension score bar chart — horizontal bars for each analysis dimension.
pub fn dimension_bar_chart(dims: &[super::super::types::DimensionScore]) -> String {
    if dims.is_empty() {
        return String::new();
    }
    let mut svg = String::with_capacity(4096);
    let _ = write_dimension_bars(&mut svg, dims);
    svg
}

fn write_dimension_bars(
    svg: &mut String,
    dims: &[super::super::types::DimensionScore],
) -> std::fmt::Result {
    let bar_h = 22.0f64;
    let gap = 6.0f64;
    let label_w = 140.0f64;
    let bar_area_w = WIDTH - label_w - PAD_R - 50.0;
    let total_h = PAD_T + (bar_h + gap) * dims.len() as f64 + PAD_B;

    write!(
        svg,
        r#"<svg viewBox="0 0 {WIDTH} {total_h}" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:{WIDTH}px;height:auto;font-family:-apple-system,BlinkMacSystemFont,sans-serif">"#,
    )?;

    for (i, d) in dims.iter().enumerate() {
        let y = PAD_T + (bar_h + gap) * i as f64;
        let score = (d.score as f64).clamp(0.0, 100.0);
        let bar_w = bar_area_w * score / 100.0;
        let color = if score >= 70.0 {
            COLOR_SUCCESS
        } else if score >= 40.0 {
            COLOR_WARNING
        } else {
            COLOR_ERROR
        };

        // Label
        write!(
            svg,
            r#"<text x="{}" y="{}" text-anchor="end" font-size="11" fill="{COLOR_TEXT}" dominant-baseline="middle">{}</text>"#,
            label_w - 8.0,
            y + bar_h / 2.0,
            super::helpers::html_escape(&d.name),
        )?;
        // Background track
        write!(
            svg,
            r#"<rect x="{label_w}" y="{y}" width="{bar_area_w}" height="{bar_h}" rx="4" fill="{COLOR_GRID}" opacity="0.5"/>"#,
        )?;
        // Score bar
        if bar_w > 0.5 {
            write!(
                svg,
                r#"<rect x="{label_w}" y="{y}" width="{bar_w:.1}" height="{bar_h}" rx="4" fill="{color}"/>"#,
            )?;
        }
        // Score inside bar (if wide enough) or outside
        if bar_w > 35.0 {
            write!(
                svg,
                r#"<text x="{}" y="{}" font-size="11" font-weight="600" fill="white" dominant-baseline="middle" text-anchor="end">{}</text>"#,
                label_w + bar_w - 6.0,
                y + bar_h / 2.0,
                d.score,
            )?;
        } else {
            write!(
                svg,
                r#"<text x="{}" y="{}" font-size="11" font-weight="600" fill="{color}" dominant-baseline="middle">{}</text>"#,
                label_w + bar_area_w + 8.0,
                y + bar_h / 2.0,
                d.score,
            )?;
        }
    }

    // Threshold line at 70 (human authorship threshold)
    let threshold_x = label_w + bar_area_w * 70.0 / 100.0;
    write!(
        svg,
        r#"<line x1="{threshold_x:.1}" y1="{}" x2="{threshold_x:.1}" y2="{}" stroke="{COLOR_SUCCESS}" stroke-width="1" stroke-dasharray="4,3" opacity="0.6"/>"#,
        PAD_T - 4.0,
        total_h - PAD_B + 4.0,
    )?;
    write!(
        svg,
        r#"<text x="{threshold_x:.1}" y="{}" text-anchor="middle" font-size="8" fill="{COLOR_SUCCESS}">70</text>"#,
        total_h - PAD_B + 14.0,
    )?;

    write!(svg, "</svg>")
}

/// Checkpoint velocity sparkline — document size progression over checkpoints.
pub fn checkpoint_velocity_chart(checkpoints: &[super::super::types::ReportCheckpoint]) -> String {
    if checkpoints.len() < 2 {
        return String::new();
    }
    let mut svg = String::with_capacity(2048);
    let _ = write_checkpoint_velocity(&mut svg, checkpoints);
    svg
}

fn write_checkpoint_velocity(
    svg: &mut String,
    checkpoints: &[super::super::types::ReportCheckpoint],
) -> std::fmt::Result {
    let max_size = checkpoints
        .iter()
        .map(|c| c.content_size)
        .max()
        .unwrap_or(1)
        .max(1) as f64;
    let n = checkpoints.len();

    write!(
        svg,
        r#"<svg viewBox="0 0 {WIDTH} 140" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:{WIDTH}px;height:auto;font-family:-apple-system,BlinkMacSystemFont,sans-serif">"#,
    )?;

    let plot_h = 100.0;
    let x_step = PLOT_W / (n - 1).max(1) as f64;

    // Area + line
    let mut area = String::with_capacity(n * 20);
    let mut line = String::with_capacity(n * 20);
    for (i, cp) in checkpoints.iter().enumerate() {
        let x = PAD_L + i as f64 * x_step;
        let y = PAD_T + plot_h * (1.0 - cp.content_size as f64 / max_size);
        if i == 0 {
            write!(area, "M{x:.1},{:.1} L{x:.1},{y:.1}", PAD_T + plot_h)?;
            write!(line, "M{x:.1},{y:.1}")?;
        } else {
            write!(area, " L{x:.1},{y:.1}")?;
            write!(line, " L{x:.1},{y:.1}")?;
        }
    }
    if let Some(last_x) = checkpoints.last().map(|_| PAD_L + (n - 1) as f64 * x_step) {
        write!(area, " L{last_x:.1},{:.1}Z", PAD_T + plot_h)?;
    }

    write!(
        svg,
        r#"<path d="{area}" fill="{COLOR_AREA}" stroke="none"/>"#
    )?;
    write!(
        svg,
        r#"<path d="{line}" fill="none" stroke="{COLOR_PRIMARY}" stroke-width="1.5"/>"#,
    )?;

    // Dots at each checkpoint
    for (i, cp) in checkpoints.iter().enumerate() {
        let x = PAD_L + i as f64 * x_step;
        let y = PAD_T + plot_h * (1.0 - cp.content_size as f64 / max_size);
        write!(
            svg,
            r#"<circle cx="{x:.1}" cy="{y:.1}" r="3" fill="{COLOR_PRIMARY}" stroke="white" stroke-width="1"/>"#,
        )?;
    }

    // Y axis label
    write!(
        svg,
        r#"<text x="{}" y="{}" text-anchor="end" font-size="9" fill="{COLOR_TEXT}">{:.0} KB</text>"#,
        PAD_L - 6.0,
        PAD_T + 4.0,
        max_size / 1024.0,
    )?;
    write!(
        svg,
        r#"<text x="{}" y="{}" text-anchor="end" font-size="9" fill="{COLOR_TEXT}">0</text>"#,
        PAD_L - 6.0,
        PAD_T + plot_h + 4.0,
    )?;

    // X axis label
    write!(
        svg,
        r#"<text x="{}" y="135" text-anchor="middle" font-size="9" fill="{COLOR_TEXT}">Checkpoint Sequence</text>"#,
        PAD_L + PLOT_W / 2.0,
    )?;

    write!(svg, "</svg>")
}
