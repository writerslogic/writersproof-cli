// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Report generation for forensic analysis.

use chrono::Duration as ChronoDuration;

use super::assessment::ENTROPY_NORMALIZATION;
use super::types::{AuthorshipProfile, Severity};

/// Generate a human-readable forensic report.
pub fn generate_report(profile: &AuthorshipProfile) -> String {
    let mut report = String::new();

    report.push_str(&"=".repeat(72));
    report.push('\n');
    report.push_str("                    FORENSIC AUTHORSHIP ANALYSIS\n");
    report.push_str(&"=".repeat(72));
    report.push_str("\n\n");

    if !profile.file_path.is_empty() {
        report.push_str(&format!("File:           {}\n", profile.file_path));
    }
    report.push_str(&format!("Events:         {}\n", profile.event_count));
    report.push_str(&format!("Sessions:       {}\n", profile.session_count));
    report.push_str(&format!(
        "Time Span:      {}\n",
        format_duration(profile.time_span)
    ));
    if profile.first_event.timestamp() != 0 {
        report.push_str(&format!(
            "First Event:    {}\n",
            profile.first_event.format("%Y-%m-%dT%H:%M:%S%z")
        ));
        report.push_str(&format!(
            "Last Event:     {}\n",
            profile.last_event.format("%Y-%m-%dT%H:%M:%S%z")
        ));
    }
    report.push('\n');

    report.push_str(&"-".repeat(72));
    report.push_str("\nPRIMARY METRICS\n");
    report.push_str(&"-".repeat(72));
    report.push_str("\n\n");

    let m = &profile.metrics;

    report.push_str(&format!(
        "Monotonic Append Ratio:   {:.3}  {}\n",
        m.monotonic_append_ratio,
        format_metric_bar(m.monotonic_append_ratio.get(), 0.0, 1.0, 20)
    ));
    report.push_str(&format!(
        "  -> {}\n\n",
        interpret_monotonic_append(m.monotonic_append_ratio.get())
    ));

    let max_entropy = ENTROPY_NORMALIZATION;
    report.push_str(&format!(
        "Edit Entropy:             {:.3}  {}\n",
        m.edit_entropy,
        format_metric_bar(m.edit_entropy, 0.0, max_entropy, 20)
    ));
    report.push_str(&format!(
        "  -> {}\n\n",
        interpret_edit_entropy(m.edit_entropy)
    ));

    report.push_str(&format!(
        "Median Interval:          {:.2} sec\n",
        m.median_interval
    ));
    report.push_str(&format!(
        "  -> {}\n\n",
        interpret_median_interval(m.median_interval)
    ));

    report.push_str(&format!(
        "Positive/Negative Ratio:  {:.3}  {}\n",
        m.positive_negative_ratio,
        format_metric_bar(m.positive_negative_ratio.get(), 0.0, 1.0, 20)
    ));
    report.push_str(&format!(
        "  -> {}\n\n",
        interpret_pos_neg_ratio(m.positive_negative_ratio.get())
    ));

    report.push_str(&format!(
        "Deletion Clustering:      {:.3}\n",
        m.deletion_clustering
    ));
    report.push_str(&format!(
        "  -> {}\n\n",
        interpret_deletion_clustering(m.deletion_clustering)
    ));

    if !profile.anomalies.is_empty() {
        report.push_str(&"-".repeat(72));
        report.push_str("\nANOMALIES DETECTED\n");
        report.push_str(&"-".repeat(72));
        report.push_str("\n\n");

        for (i, a) in profile.anomalies.iter().enumerate() {
            let severity_marker = match a.severity {
                Severity::Alert => "!!!",
                Severity::Warning => " ! ",
                Severity::Info => " i ",
            };
            report.push_str(&format!(
                "{}. [{}] {}: {}\n",
                i + 1,
                severity_marker,
                a.anomaly_type,
                a.description
            ));
            if let Some(ts) = a.timestamp {
                report.push_str(&format!("   At: {}\n", ts.format("%Y-%m-%dT%H:%M:%S%z")));
            }
            if let Some(ctx) = &a.context {
                report.push_str(&format!("   Context: {}\n", ctx));
            }
        }
        report.push('\n');
    }

    report.push_str(&"=".repeat(72));
    report.push_str(&format!("\nASSESSMENT: {}\n", profile.assessment));
    report.push_str(&"=".repeat(72));
    report.push('\n');

    report
}

/// Format a `ChronoDuration` as "X days, Y hours" etc.
fn format_duration(d: ChronoDuration) -> String {
    crate::utils::format_duration_verbose(d.num_seconds())
}

/// Render an ASCII bar `[####----]` for a metric value.
fn format_metric_bar(value: f64, min: f64, max: f64, width: usize) -> String {
    if width == 0 || max <= min {
        return "-".repeat(width);
    }

    let normalized = crate::utils::stats::lerp_score(value, min, max);
    let filled = (normalized * width as f64) as usize;
    let filled = filled.min(width);

    format!("[{}{}]", "#".repeat(filled), "-".repeat(width - filled))
}

fn interpret_monotonic_append(ratio: f64) -> &'static str {
    if ratio > 0.90 {
        "Very high: Nearly all edits at end of document (AI-like pattern)"
    } else if ratio > 0.70 {
        "High: Most edits at end of document"
    } else if ratio > 0.40 {
        "Moderate: Mixed editing patterns (typical human behavior)"
    } else {
        "Low: Distributed editing throughout document"
    }
}

fn interpret_edit_entropy(entropy: f64) -> &'static str {
    if entropy < 1.0 {
        "Very low: Highly concentrated editing (suspicious)"
    } else if entropy < 2.0 {
        "Low: Somewhat focused editing patterns"
    } else if entropy < 3.0 {
        "Moderate: Typical editing distribution"
    } else {
        "High: Well-distributed editing (normal revision behavior)"
    }
}

fn interpret_median_interval(interval: f64) -> &'static str {
    if interval < 1.0 {
        "Very fast: Sub-second editing pace (automated?)"
    } else if interval < 5.0 {
        "Fast: Rapid editing pace"
    } else if interval < 30.0 {
        "Moderate: Typical typing/thinking pace"
    } else if interval < 300.0 {
        "Slow: Thoughtful/deliberate editing"
    } else {
        "Very slow: Extended pauses between edits"
    }
}

fn interpret_pos_neg_ratio(ratio: f64) -> &'static str {
    if ratio > 0.95 {
        "Almost all insertions: No revision behavior (suspicious)"
    } else if ratio > 0.80 {
        "Mostly insertions: Limited revision"
    } else if ratio > 0.60 {
        "Balanced toward insertions: Typical drafting pattern"
    } else if ratio > 0.40 {
        "Balanced: Active revision behavior"
    } else {
        "Mostly deletions: Heavy revision/editing mode"
    }
}

fn interpret_deletion_clustering(coef: f64) -> &'static str {
    if coef == 0.0 {
        "No deletions or insufficient data"
    } else if coef < 0.5 {
        "Highly clustered: Systematic revision passes (human-like)"
    } else if coef < 0.8 {
        "Moderately clustered: Natural editing pattern"
    } else if coef < 1.2 {
        "Scattered: Random deletion distribution (suspicious)"
    } else {
        "Very scattered: Possibly artificial deletion pattern"
    }
}
