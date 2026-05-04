// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Smoke-test CLI for the CPoE forensic transcription pipeline.
//!
//! Reads a small JSON payload describing a synthetic typing session from
//! stdin or a file path, runs the engine's transcription detector, and
//! prints a human-readable summary to stdout.
//!
//! Run with:
//!   cargo run -p cpoe --example transcription_check -- path/to/sample.json
//!   cargo run -p cpoe --example transcription_check -- - < sample.json

use std::collections::HashMap;
use std::io::{self, Read};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::DateTime;
use serde::Deserialize;

use cpoe_engine::forensics::{
    analyze_forensics, analyze_forensics_with_full_focus, build_transcription_data,
    AnalysisContext, EventData, ForensicMetrics, TranscriptionSegment,
};
use cpoe_engine::sentinel::types::FocusSwitchRecord;

/// Top-level JSON shape accepted by the example.
#[derive(Debug, Deserialize)]
struct InputPayload {
    events: Vec<EventData>,
    #[serde(default)]
    focus_switches: Vec<FocusSwitchInput>,
}

/// Wire-friendly stand-in for [`FocusSwitchRecord`].
///
/// `FocusSwitchRecord` does not implement `serde` because its `SystemTime`
/// fields don't have a stable cross-platform serialization. The example
/// accepts ns-since-UNIX-epoch integers and converts them manually.
#[derive(Debug, Deserialize)]
struct FocusSwitchInput {
    /// Nanoseconds since UNIX epoch when focus was lost.
    lost_at_ns: u64,
    /// Nanoseconds since UNIX epoch when focus was regained (optional).
    #[serde(default)]
    regained_at_ns: Option<u64>,
    #[serde(default)]
    target_app: String,
    #[serde(default)]
    target_bundle_id: String,
}

impl FocusSwitchInput {
    fn into_record(self) -> FocusSwitchRecord {
        FocusSwitchRecord {
            lost_at: ns_to_system_time(self.lost_at_ns),
            regained_at: self.regained_at_ns.map(ns_to_system_time),
            target_app: self.target_app,
            target_bundle_id: self.target_bundle_id,
        }
    }
}

fn ns_to_system_time(ns: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(ns)
}

fn print_usage_to_stderr() {
    eprintln!(
        "usage: transcription_check <PATH|->\n\n  \
         PATH  read JSON payload from this file\n  \
         -     read JSON payload from stdin\n\n\
         JSON shape:\n  \
         {{\n    \"events\": [ {{ id, timestamp_ns, file_size, size_delta, file_path }} ],\n    \
         \"focus_switches\": [ {{ lost_at_ns, regained_at_ns, target_app, target_bundle_id }} ]\n  \
         }}"
    );
}

fn read_input(arg: &str) -> io::Result<String> {
    if arg == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(arg)
    }
}

/// Format a timestamp as ISO-8601, falling back to raw ns for the sentinel
/// zero value used when an event index couldn't be resolved.
fn fmt_timestamp(ns: i64) -> String {
    if ns == 0 {
        return "0 ns".to_string();
    }
    DateTime::from_timestamp_nanos(ns).to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

fn run_pipeline(payload: InputPayload) -> ForensicMetrics {
    let regions: HashMap<i64, Vec<cpoe_engine::forensics::RegionData>> = HashMap::new();

    if payload.focus_switches.is_empty() {
        analyze_forensics(&payload.events, &regions, None, None, None)
    } else {
        let switches: Vec<FocusSwitchRecord> = payload
            .focus_switches
            .into_iter()
            .map(FocusSwitchInput::into_record)
            .collect();
        analyze_forensics_with_full_focus(
            &payload.events,
            &regions,
            None,
            None,
            None,
            &AnalysisContext::default(),
            None,
            &switches,
        )
    }
}

fn print_summary(metrics: &ForensicMetrics, event_count: usize, final_char_count: usize) {
    println!("=== CPoE Transcription Smoke Test ===");
    println!("analyzed_events: {}", event_count);
    println!("final_char_count: {}", final_char_count);

    match metrics.transcription.as_ref() {
        Some(t) => {
            println!("transcription_pattern: {}", t.is_transcription);
            println!("session_linearity_score: {:.3}", t.linearity_score);
            println!("revision_density: {:.3}", t.revision_density);
            println!("nonlinearity_index: {:.3}", t.nonlinearity_index);
            println!("focus_correlation: {:.3}", t.focus_correlation);
            println!("avg_burst_length: {:.3}", t.avg_burst_length);
            println!("explanation: {}", t.explanation);
        }
        None => {
            println!("transcription_pattern: <unavailable>");
            println!("session_linearity_score: <unavailable>");
            println!("(detector not invoked — likely too few events with non-zero size_delta)");
        }
    }

    let segs: &[TranscriptionSegment] = &metrics.transcription_segments;
    println!("transcription_segments: {}", segs.len());
    for (idx, seg) in segs.iter().enumerate() {
        println!(
            "  [{}] events {}..{}  [{} -> {}]  linearity={:.3}\n      {}",
            idx,
            seg.event_start_index,
            seg.event_end_index,
            fmt_timestamp(seg.event_start_timestamp_ns),
            fmt_timestamp(seg.event_end_timestamp_ns),
            seg.linearity_score,
            seg.detail,
        );
    }
}

fn main() -> ExitCode {
    let arg = match std::env::args().nth(1) {
        Some(a) => a,
        None => {
            print_usage_to_stderr();
            return ExitCode::FAILURE;
        }
    };

    let raw = match read_input(&arg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to read input '{}': {}", arg, e);
            return ExitCode::FAILURE;
        }
    };

    let payload: InputPayload = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to parse JSON: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let event_count = payload.events.len();
    let final_char_count = build_transcription_data(&payload.events, None).final_char_count;
    let metrics = run_pipeline(payload);
    print_summary(&metrics, event_count, final_char_count);

    ExitCode::SUCCESS
}
