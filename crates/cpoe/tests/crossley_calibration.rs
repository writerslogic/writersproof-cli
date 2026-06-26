// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Empirical calibration of retype-defense metrics against the Crossley 2024
//! transcription detection dataset (Zenodo 12729864).
//!
//! Two data sources:
//!
//! 1. **Raw transcribed keystroke logs** (50 sample files): parsed into
//!    `EventData`, then run through `compute_retype_metrics` for exact
//!    `detour_ratio`, `leading_edge_divergence`, and `insertion_point_entropy`.
//!
//! 2. **Aggregate CSVs** (499 authentic + 499 transcribed): proxy metrics
//!    computed from Inputlog-derived features available for both conditions.
//!    Proxy AUC gives relative discrimination power for weight calibration.
//!
//! Reference:
//!   Crossley, S. A., Tian, Y., Holmes, L., Morris, W., & Choi, J. S. (2024).
//!   Plagiarism Detection Using Keystroke Logs.
//!   Proc. 17th International Conference on Educational Data Mining (EDM).

use std::path::Path;

use cpoe_engine::forensics::revision_topology::analyze_revision_topology;
use cpoe_engine::forensics::types::{EventData, SortedEvents};

// ---------------------------------------------------------------------------
// CSV field indices (0-based) in the Crossley aggregate CSVs
// ---------------------------------------------------------------------------

const COL_CHARS_PRODUCED: usize = 3;
const COL_TOTAL_STROKES: usize = 129;
const COL_NUM_DELETIONS: usize = 134;
const COL_MEAN_DELETION_LEN: usize = 138;
const COL_NUM_INSERTIONS: usize = 142;
const COL_MEAN_INSERTION_LEN: usize = 146;
const COL_PRODUCT_PROCESS_RATIO: usize = 157;

// ---------------------------------------------------------------------------
// Crossley raw log → EventData conversion
// ---------------------------------------------------------------------------

/// Parse a single Crossley raw keystroke log CSV into `EventData` records.
///
/// Crossley format (CSV with quoted fields):
///   row_num, DownEventID, UpEventID, DownTime(ms), UpTime(ms), ActionTime,
///   DownEvent, UpEvent, Cursorposition, WordCount, TextChange, Activity
///
/// We map:
///   - `timestamp_ns` ← DownTime * 1_000_000
///   - `file_size`    ← Cursorposition (tracks leading edge)
///   - `size_delta`   ← +1 for Input, -1 for Remove/Cut, 0 for Nonproduction
fn parse_crossley_raw(path: &Path) -> Vec<EventData> {
    let content = std::fs::read_to_string(path).expect("read crossley CSV");
    let mut events = Vec::new();
    let mut max_cursor: i64 = 0;

    for (idx, line) in content.lines().skip(1).enumerate() {
        let fields: Vec<&str> = parse_csv_line(line);
        if fields.len() < 12 {
            continue;
        }

        let down_time_ms: i64 = match fields[3].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let cursor_pos: i64 = match fields[8].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let activity = fields[11].trim();

        let size_delta = match activity {
            "Input" => 1i32,
            "Remove/Cut" => -1,
            _ => continue, // Skip Nonproduction for topology analysis
        };

        if cursor_pos > max_cursor {
            max_cursor = cursor_pos;
        }

        // file_size tracks the document length as cursor advances.
        // For Input: file_size = max of (cursor_pos, previous max).
        // For Remove/Cut: file_size = current max (deletion shrinks doc).
        let file_size = if size_delta > 0 {
            cursor_pos.max(max_cursor)
        } else {
            max_cursor
        };

        events.push(EventData {
            id: idx as i64,
            timestamp_ns: down_time_ms * 1_000_000,
            file_size,
            size_delta,
            file_path: path.to_string_lossy().to_string(),
        });
    }

    events
}

/// Simple CSV field parser that handles quoted fields.
fn parse_csv_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let bytes = line.as_bytes();

    for i in 0..bytes.len() {
        match bytes[i] {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                let field = &line[start..i];
                fields.push(field.trim_matches('"'));
                start = i + 1;
            }
            _ => {}
        }
    }
    // Last field
    if start <= line.len() {
        fields.push(line[start..].trim_matches('"'));
    }
    fields
}

// ---------------------------------------------------------------------------
// Aggregate CSV proxy metrics
// ---------------------------------------------------------------------------

struct ProxyMetrics {
    /// Proxy for detour_ratio: revision intensity normalized by document size.
    /// `(num_insertions * mean_insertion_len + num_deletions * mean_deletion_len) / chars_produced`
    detour_proxy: f64,
    /// Proxy for leading_edge_divergence: fraction of events that are insertions.
    /// `num_insertions / total_strokes`
    led_proxy: f64,
    /// Proxy for insertion_point_entropy: `1 - product_process_ratio`.
    /// More revision → lower PPR → higher proxy.
    entropy_proxy: f64,
}

fn parse_aggregate_csv(path: &Path) -> Vec<ProxyMetrics> {
    let content = std::fs::read_to_string(path).expect("read aggregate CSV");
    let mut results = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() <= COL_PRODUCT_PROCESS_RATIO {
            continue;
        }

        let total_strokes: f64 = fields[COL_TOTAL_STROKES].parse().unwrap_or(0.0);
        let num_insertions: f64 = fields[COL_NUM_INSERTIONS].parse().unwrap_or(0.0);
        let mean_ins_len: f64 = fields[COL_MEAN_INSERTION_LEN].parse().unwrap_or(0.0);
        let num_deletions: f64 = fields[COL_NUM_DELETIONS].parse().unwrap_or(0.0);
        let mean_del_len: f64 = fields[COL_MEAN_DELETION_LEN].parse().unwrap_or(0.0);
        let chars_produced: f64 = fields[COL_CHARS_PRODUCED].parse().unwrap_or(1.0);
        let ppr: f64 = fields[COL_PRODUCT_PROCESS_RATIO].parse().unwrap_or(1.0);

        if total_strokes < 20.0 || chars_produced < 20.0 {
            continue;
        }

        let detour_proxy = (num_insertions * mean_ins_len + num_deletions * mean_del_len)
            / chars_produced.max(1.0);

        let led_proxy = num_insertions / total_strokes.max(1.0);

        let entropy_proxy = (1.0 - ppr).max(0.0);

        results.push(ProxyMetrics {
            detour_proxy,
            led_proxy,
            entropy_proxy,
        });
    }

    results
}

// ---------------------------------------------------------------------------
// AUC computation (Wilcoxon-Mann-Whitney)
// ---------------------------------------------------------------------------

/// Compute AUC = P(positive > negative) using the Wilcoxon-Mann-Whitney U statistic.
/// `positives` = authentic (should score higher), `negatives` = transcribed.
fn wilcoxon_auc(positives: &[f64], negatives: &[f64]) -> f64 {
    if positives.is_empty() || negatives.is_empty() {
        return 0.5;
    }

    let mut concordant: u64 = 0;
    let mut tied: u64 = 0;

    for &p in positives {
        for &n in negatives {
            if p > n {
                concordant += 1;
            } else if (p - n).abs() < f64::EPSILON {
                tied += 1;
            }
        }
    }

    let total = positives.len() as f64 * negatives.len() as f64;
    (concordant as f64 + 0.5 * tied as f64) / total
}

fn mean(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    vals.iter().sum::<f64>() / vals.len() as f64
}

fn std_dev(vals: &[f64]) -> f64 {
    if vals.len() < 2 {
        return 0.0;
    }
    let m = mean(vals);
    let var = vals.iter().map(|&x| (x - m).powi(2)).sum::<f64>() / (vals.len() - 1) as f64;
    var.sqrt()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn crossley_exact_metrics_on_transcribed_logs() {
    let raw_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/crossley/raw_transcribed");
    if !raw_dir.exists() {
        eprintln!(
            "SKIP: Crossley raw transcribed data not found at {:?}",
            raw_dir
        );
        return;
    }

    let mut detour_ratios = Vec::new();
    let mut leds = Vec::new();
    let mut entropies = Vec::new();
    let mut composite_scores = Vec::new();
    let mut file_count = 0;

    for entry in std::fs::read_dir(&raw_dir).expect("read raw dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("csv") {
            continue;
        }

        let events = parse_crossley_raw(&path);
        if events.len() < 20 {
            continue;
        }

        // Sort by timestamp (should already be sorted, but defensive).
        let mut sorted_events = events;
        sorted_events.sort_by_key(|e| e.timestamp_ns);

        let sorted = SortedEvents::new(&sorted_events);
        if let Some(metrics) = analyze_revision_topology(sorted) {
            detour_ratios.push(metrics.detour_ratio);
            leds.push(metrics.leading_edge_divergence);
            entropies.push(metrics.insertion_point_entropy);
            composite_scores.push(metrics.composite_score);
            file_count += 1;
        }
    }

    assert!(
        file_count >= 10,
        "Need at least 10 transcribed samples, got {}",
        file_count
    );

    println!(
        "\n=== Crossley Exact Metrics: Transcribed (N={}) ===",
        file_count
    );
    println!(
        "  detour_ratio:           mean={:.4} sd={:.4}",
        mean(&detour_ratios),
        std_dev(&detour_ratios)
    );
    println!(
        "  leading_edge_divergence: mean={:.4} sd={:.4}",
        mean(&leds),
        std_dev(&leds)
    );
    println!(
        "  insertion_point_entropy:  mean={:.4} sd={:.4}",
        mean(&entropies),
        std_dev(&entropies)
    );
    println!(
        "  composite_score:          mean={:.4} sd={:.4}",
        mean(&composite_scores),
        std_dev(&composite_scores)
    );

    // Transcribed essays should show low detour and LED.
    let mean_detour = mean(&detour_ratios);
    let mean_led = mean(&leds);
    assert!(
        mean_detour < 0.15,
        "Transcribed detour_ratio should be low, got {:.4}",
        mean_detour
    );
    assert!(
        mean_led < 0.15,
        "Transcribed LED should be low, got {:.4}",
        mean_led
    );
}

#[test]
fn crossley_proxy_auc_calibration() {
    let data_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/crossley");
    let authentic_path = data_dir.join("keystroke_analytics_original_essays_anon.csv");
    let transcribed_path = data_dir.join("keystroke_analytics_transcribed_essays_anon.csv");

    if !authentic_path.exists() || !transcribed_path.exists() {
        eprintln!("SKIP: Crossley aggregate CSVs not found");
        return;
    }

    let authentic = parse_aggregate_csv(&authentic_path);
    let transcribed = parse_aggregate_csv(&transcribed_path);

    assert!(
        authentic.len() >= 400,
        "Expected ~499 authentic samples, got {}",
        authentic.len()
    );
    assert!(
        transcribed.len() >= 400,
        "Expected ~499 transcribed samples, got {}",
        transcribed.len()
    );

    // Extract per-metric vectors.
    let auth_detour: Vec<f64> = authentic.iter().map(|m| m.detour_proxy).collect();
    let auth_led: Vec<f64> = authentic.iter().map(|m| m.led_proxy).collect();
    let auth_entropy: Vec<f64> = authentic.iter().map(|m| m.entropy_proxy).collect();

    let trans_detour: Vec<f64> = transcribed.iter().map(|m| m.detour_proxy).collect();
    let trans_led: Vec<f64> = transcribed.iter().map(|m| m.led_proxy).collect();
    let trans_entropy: Vec<f64> = transcribed.iter().map(|m| m.entropy_proxy).collect();

    // AUC: P(authentic > transcribed) — higher AUC = better discrimination.
    let auc_detour = wilcoxon_auc(&auth_detour, &trans_detour);
    let auc_led = wilcoxon_auc(&auth_led, &trans_led);
    let auc_entropy = wilcoxon_auc(&auth_entropy, &trans_entropy);

    println!(
        "\n=== Crossley Proxy AUC (N_auth={}, N_trans={}) ===",
        authentic.len(),
        transcribed.len()
    );
    println!("  detour_proxy  AUC: {:.4}", auc_detour);
    println!("  led_proxy     AUC: {:.4}", auc_led);
    println!("  entropy_proxy AUC: {:.4}", auc_entropy);

    println!("\n--- Distribution stats ---");
    println!(
        "  detour_proxy:  auth mean={:.4} sd={:.4}  |  trans mean={:.4} sd={:.4}",
        mean(&auth_detour),
        std_dev(&auth_detour),
        mean(&trans_detour),
        std_dev(&trans_detour)
    );
    println!(
        "  led_proxy:     auth mean={:.4} sd={:.4}  |  trans mean={:.4} sd={:.4}",
        mean(&auth_led),
        std_dev(&auth_led),
        mean(&trans_led),
        std_dev(&trans_led)
    );
    println!(
        "  entropy_proxy: auth mean={:.4} sd={:.4}  |  trans mean={:.4} sd={:.4}",
        mean(&auth_entropy),
        std_dev(&auth_entropy),
        mean(&trans_entropy),
        std_dev(&trans_entropy)
    );

    // Compute optimal weights proportional to AUC excess over chance (0.5).
    let excess_detour = (auc_detour - 0.5).max(0.0);
    let excess_led = (auc_led - 0.5).max(0.0);
    let excess_entropy = (auc_entropy - 0.5).max(0.0);
    let total_excess = excess_detour + excess_led + excess_entropy;

    if total_excess > 0.0 {
        let w_detour = excess_detour / total_excess;
        let w_led = excess_led / total_excess;
        let w_entropy = excess_entropy / total_excess;

        println!("\n--- AUC-proportional weights (new signal budget = 0.50) ---");
        println!(
            "  W_DETOUR:  {:.3} → composite weight {:.3}",
            w_detour,
            w_detour * 0.50
        );
        println!(
            "  W_LED:     {:.3} → composite weight {:.3}",
            w_led,
            w_led * 0.50
        );
        println!(
            "  W_ENTROPY: {:.3} → composite weight {:.3}",
            w_entropy,
            w_entropy * 0.50
        );
        println!("\n  Recommended constants for revision_topology.rs:");
        println!("    const W_DETOUR: f64 = {:.2};", w_detour * 0.50);
        println!("    const W_LED: f64 = {:.2};", w_led * 0.50);
        println!("    const W_ENTROPY: f64 = {:.2};", w_entropy * 0.50);
    }

    // All three metrics should discriminate above chance.
    assert!(
        auc_detour > 0.55,
        "detour proxy AUC should be >0.55, got {:.4}",
        auc_detour
    );
    assert!(
        auc_led > 0.55,
        "LED proxy AUC should be >0.55, got {:.4}",
        auc_led
    );
    assert!(
        auc_entropy > 0.55,
        "entropy proxy AUC should be >0.55, got {:.4}",
        auc_entropy
    );
}
