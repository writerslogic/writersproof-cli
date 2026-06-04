// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::DateTime;

use crate::output::OutputMode;
use crate::util::{ensure_dirs, load_vdf_params, open_secure_store};

/// Format a nanosecond timestamp, returning "invalid timestamp" for out-of-range values.
/// Valid range: year 2000 (946684800s) to year 2100 (4102444800s).
fn format_timestamp_nanos(ns: i64, fmt: &str) -> String {
    const MIN_NS: i64 = 946_684_800_000_000_000;
    const MAX_NS: i64 = 4_102_444_800_000_000_000;
    if (MIN_NS..=MAX_NS).contains(&ns) {
        DateTime::from_timestamp_nanos(ns).format(fmt).to_string()
    } else {
        "invalid timestamp".to_string()
    }
}

/// Format a nanosecond timestamp as RFC 3339, returning "invalid timestamp" for out-of-range.
fn format_timestamp_nanos_rfc3339(ns: i64) -> String {
    const MIN_NS: i64 = 946_684_800_000_000_000;
    const MAX_NS: i64 = 4_102_444_800_000_000_000;
    if (MIN_NS..=MAX_NS).contains(&ns) {
        DateTime::from_timestamp_nanos(ns).to_rfc3339()
    } else {
        "invalid timestamp".to_string()
    }
}

pub(crate) fn cmd_log(file_path: &PathBuf, out: &OutputMode) -> Result<()> {
    let abs_path = fs::canonicalize(file_path).context("resolve path")?;
    let path_str = abs_path.to_string_lossy().into_owned();
    let db = open_secure_store()?;
    let events = db.get_events_for_file(&path_str)?;

    let config = ensure_dirs()?;
    let vdf_params = load_vdf_params(&config);
    let vdf_calibrated = vdf_params.iterations_per_second > 0;

    if out.json {
        let checkpoints: Vec<serde_json::Value> = events
            .iter()
            .enumerate()
            .map(|(i, ev)| {
                let ts = format_timestamp_nanos_rfc3339(ev.timestamp_ns);
                let mut cp = serde_json::json!({
                    "index": i + 1,
                    "timestamp": ts,
                    "content_hash": hex::encode(ev.content_hash),
                    "event_hash": hex::encode(ev.event_hash),
                    "file_size": ev.file_size,
                    "size_delta": ev.size_delta,
                    "vdf_iterations": ev.vdf_iterations,
                });
                if vdf_calibrated && ev.vdf_iterations > 0 {
                    let elapsed =
                        ev.vdf_iterations as f64 / vdf_params.iterations_per_second as f64;
                    cp["vdf_elapsed_secs"] = serde_json::json!(elapsed);
                }
                if let Some(ref note) = ev.context_note {
                    if !note.is_empty() {
                        cp["message"] = serde_json::json!(note);
                    }
                }
                if let Some(ref ctx) = ev.context_type {
                    cp["context_type"] = serde_json::json!(ctx);
                }
                cp
            })
            .collect();

        let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
        let mut result = serde_json::json!({
            "document": path_str,
            "checkpoint_count": events.len(),
            "vdf_calibrated": vdf_calibrated,
            "total_vdf_iterations": total_iterations,
            "checkpoints": checkpoints,
        });
        if vdf_calibrated && total_iterations > 0 {
            result["total_vdf_time_secs"] = serde_json::json!(
                total_iterations as f64 / vdf_params.iterations_per_second as f64
            );
        }
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    if events.is_empty() {
        if !out.quiet {
            println!("No checkpoints found for this file.");
        }
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();

    println!(
        "=== Checkpoint History: {} ===",
        file_path.file_name().unwrap_or_default().to_string_lossy()
    );
    println!("Document: {}", path_str);
    println!("Checkpoints: {}", events.len());
    if vdf_calibrated {
        let total_vdf_time = Duration::from_secs_f64(
            total_iterations as f64 / vdf_params.iterations_per_second as f64,
        );
        println!("Total VDF time: {:.0?}", total_vdf_time);
    } else {
        println!("Total VDF time: (uncalibrated - run 'cpoe calibrate')");
    }
    println!();

    for (i, ev) in events.iter().enumerate() {
        let ts = format_timestamp_nanos(ev.timestamp_ns, "%Y-%m-%d %H:%M:%S");
        println!("[{}] {}", i + 1, ts);
        println!("    Hash: {}", hex::encode(ev.content_hash));
        print!("    Size: {} bytes", ev.file_size);
        if ev.size_delta != 0 {
            if ev.size_delta > 0 {
                print!(" (+{})", ev.size_delta);
            } else {
                print!(" ({})", ev.size_delta);
            }
        }
        println!();
        if ev.vdf_iterations > 0 && vdf_calibrated {
            let elapsed_secs = ev.vdf_iterations as f64 / vdf_params.iterations_per_second as f64;
            let elapsed_dur = Duration::from_secs_f64(elapsed_secs);
            println!("    VDF:  >= {:.0?}", elapsed_dur);
        }
        if let Some(ref note) = ev.context_note {
            if !note.is_empty() {
                println!("    Msg:  {}", note);
            }
        } else if let Some(ref ctx) = ev.context_type {
            if !ctx.is_empty() && ctx != "manual" && ctx != "auto" {
                println!("    Msg:  {}", ctx);
            }
        }
        println!();
    }

    Ok(())
}

pub(crate) fn cmd_log_smart(file: Option<PathBuf>, out: &OutputMode) -> Result<()> {
    match file {
        Some(f) => cmd_log(&f, out),
        None => {
            if out.verbose() {
                println!("No file specified. Showing all tracked documents:");
                println!();
            }
            cmd_list_documents(out)
        }
    }
}

fn cmd_list_documents(out: &OutputMode) -> Result<()> {
    let db = open_secure_store()?;
    let files = db.list_files()?;

    if out.json {
        let docs: Vec<serde_json::Value> = files
            .iter()
            .map(|(path, ts, count)| {
                serde_json::json!({
                    "path": path,
                    "last_checkpoint": format_timestamp_nanos_rfc3339(*ts),
                    "checkpoint_count": count,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "documents": docs,
                "total": files.len(),
            }))?
        );
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    if files.is_empty() {
        println!("No tracked documents.");
        return Ok(());
    }

    println!("Tracked documents:");
    for (path, last_ts, count) in &files {
        let ts = format_timestamp_nanos(*last_ts, "%Y-%m-%d %H:%M");
        println!("  {} ({} checkpoints, last: {})", path, count, ts);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- format_timestamp_nanos ---

    #[test]
    fn test_timestamp_nanos_valid_date() {
        // 2024-01-01 00:00:00 UTC = 1704067200s = 1704067200_000_000_000 ns
        let ns = 1_704_067_200_000_000_000i64;
        let result = format_timestamp_nanos(ns, "%Y-%m-%d");
        assert_eq!(result, "2024-01-01", "should format known date correctly");
    }

    #[test]
    fn test_timestamp_nanos_year_2000_boundary() {
        // Year 2000 boundary: 946684800s = MIN_NS
        let min_ns = 946_684_800_000_000_000i64;
        let result = format_timestamp_nanos(min_ns, "%Y");
        assert_eq!(result, "2000", "year 2000 boundary should be valid");
    }

    #[test]
    fn test_timestamp_nanos_year_2100_boundary() {
        // Year 2100 boundary: 4102444800s = 2100-01-01 00:00:00 UTC
        let max_ns = 4_102_444_800_000_000_000i64;
        let result = format_timestamp_nanos(max_ns, "%Y");
        assert_eq!(result, "2100", "year 2100 (MAX boundary) should be valid");
    }

    #[test]
    fn test_timestamp_nanos_below_range_returns_invalid() {
        let too_early = 946_684_799_999_999_999i64; // 1 ns before year 2000
        let result = format_timestamp_nanos(too_early, "%Y");
        assert_eq!(
            result, "invalid timestamp",
            "timestamp before year 2000 should return 'invalid timestamp'"
        );
    }

    #[test]
    fn test_timestamp_nanos_above_range_returns_invalid() {
        let too_late = 4_102_444_800_000_000_001i64; // 1 ns after year 2100
        let result = format_timestamp_nanos(too_late, "%Y");
        assert_eq!(
            result, "invalid timestamp",
            "timestamp after year 2100 should return 'invalid timestamp'"
        );
    }

    #[test]
    fn test_timestamp_nanos_zero_returns_invalid() {
        assert_eq!(
            format_timestamp_nanos(0, "%Y"),
            "invalid timestamp",
            "timestamp 0 (epoch) should be out of range"
        );
    }

    #[test]
    fn test_timestamp_nanos_negative_returns_invalid() {
        assert_eq!(
            format_timestamp_nanos(-1, "%Y"),
            "invalid timestamp",
            "negative timestamp should be invalid"
        );
    }

    // --- format_timestamp_nanos_rfc3339 ---

    #[test]
    fn test_timestamp_rfc3339_valid() {
        let ns = 1_704_067_200_000_000_000i64;
        let result = format_timestamp_nanos_rfc3339(ns);
        assert!(
            result.contains("2024-01-01"),
            "RFC 3339 should contain date, got: {result}"
        );
        assert!(
            result.contains('T'),
            "RFC 3339 format should contain 'T' separator, got: {result}"
        );
    }

    #[test]
    fn test_timestamp_rfc3339_out_of_range() {
        assert_eq!(
            format_timestamp_nanos_rfc3339(0),
            "invalid timestamp",
            "RFC 3339 should return 'invalid timestamp' for out-of-range"
        );
    }

    #[test]
    fn test_timestamp_rfc3339_boundary_consistency() {
        // Boundary values should give same valid/invalid behavior
        let min = 946_684_800_000_000_000i64;
        let max = 4_102_444_800_000_000_000i64;
        assert_ne!(
            format_timestamp_nanos_rfc3339(min),
            "invalid timestamp",
            "MIN boundary should be valid"
        );
        assert_ne!(
            format_timestamp_nanos_rfc3339(max),
            "invalid timestamp",
            "MAX boundary should be valid"
        );
        assert_eq!(
            format_timestamp_nanos_rfc3339(min - 1),
            "invalid timestamp",
            "below MIN should be invalid"
        );
        assert_eq!(
            format_timestamp_nanos_rfc3339(max + 1),
            "invalid timestamp",
            "above MAX should be invalid"
        );
    }
}
