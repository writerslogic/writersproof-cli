// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Multi-phase verification pipeline: forensic analysis on packet behavioral data.

use std::collections::HashMap;

use crate::evidence::Packet;
use crate::forensics::{
    analyze_forensics_ext, per_checkpoint_flags, AnalysisContext, EventData, ForensicMetrics,
    PerCheckpointResult, RegionData, SortedEvents, PER_CHECKPOINT_SUSPICIOUS_THRESHOLD,
};
use crate::jitter::SimpleJitterSample;

/// Run forensic analysis on packet behavioral data (Phases 2+3).
pub(super) fn run_forensics(
    packet: &Packet,
    warnings: &mut Vec<String>,
) -> (Option<ForensicMetrics>, Option<PerCheckpointResult>) {
    // Extract events from behavioral evidence
    let events: Vec<EventData> = if let Some(ref behavioral) = packet.behavioral {
        behavioral
            .edit_topology
            .iter()
            .enumerate()
            .map(|(i, _region)| EventData {
                id: i as i64,
                timestamp_ns: 0,
                file_size: packet.document.final_size as i64,
                size_delta: 0,
                file_path: packet.document.path.clone(),
            })
            .collect()
    } else {
        Vec::new()
    };

    // Prefer per-keystroke typing_samples (zone, dwell, flight) when available;
    // fall back to converting cryptographic jitter::Sample (timing only, no zone data).
    let jitter_samples: Vec<SimpleJitterSample> = if let Some(ref ks) = packet.keystroke {
        if !ks.typing_samples.is_empty() {
            ks.typing_samples.clone()
        } else {
            let mut simple = Vec::with_capacity(ks.samples.len());
            let mut prev_ns: Option<i64> = None;
            for s in &ks.samples {
                let ts_ns = s.timestamp.timestamp_nanos_opt().unwrap_or_else(|| {
                    log::warn!("timestamp_nanos_opt overflow for sample; falling back to 0");
                    0
                });
                let duration = if let Some(prev) = prev_ns {
                    (ts_ns - prev).max(0) as u64
                } else {
                    0
                };
                simple.push(SimpleJitterSample {
                    timestamp_ns: ts_ns,
                    duration_since_last_ns: duration,
                    zone: 0,
                    dwell_time_ns: None,
                    flight_time_ns: None,
                });
                prev_ns = Some(ts_ns);
            }
            simple
        }
    } else {
        Vec::new()
    };

    // Empty regions HashMap is intentional; region-based analysis requires document
    // structure data not available in third-party verification.
    let regions: HashMap<i64, Vec<RegionData>> = HashMap::new();

    let context = AnalysisContext {
        document_length: packet.document.final_size as i64,
        total_keystrokes: packet
            .keystroke
            .as_ref()
            .map(|k| k.total_keystrokes as i64)
            .unwrap_or(0),
        checkpoint_count: packet.checkpoints.len() as u64,
        attestation_tier: None,
        vdf_merkle_root: None,
        cross_window_matches: Vec::new(),
        baseline_fingerprint: None,
    };

    let has_data = !jitter_samples.is_empty() || !events.is_empty();
    if !has_data {
        warnings.push("No behavioral/keystroke data available for forensic analysis".to_string());
        return (None, None);
    }

    // Skip forensic analysis when all events have synthetic zero timestamps —
    // they carry no meaningful timing information and produce misleading results.
    let all_zero_timestamps = !events.is_empty() && events.iter().all(|e| e.timestamp_ns == 0);
    if all_zero_timestamps && jitter_samples.is_empty() {
        warnings.push(
            "All events have timestamp_ns=0 (synthetic); skipping forensic analysis".to_string(),
        );
        return (None, None);
    }
    if all_zero_timestamps && !jitter_samples.is_empty() {
        warnings.push(
            "Forensic analysis used jitter samples only; edit topology timestamps were all zero."
                .to_string(),
        );
    }

    // Sort once: analyze_forensics_ext detects the pre-sorted input via its
    // is_sorted fast-path, and per_checkpoint_flags reuses the same sort.
    let mut sorted_events = events;
    sorted_events.sort_unstable_by_key(|e| e.timestamp_ns);

    let forensics = analyze_forensics_ext(
        &sorted_events,
        &regions,
        if jitter_samples.is_empty() {
            None
        } else {
            Some(&jitter_samples)
        },
        None, // perplexity model not available in verify context
        None, // document text not available
        &context,
    );

    // Per-checkpoint analysis — only valid when events have real timestamps.
    // Events derived from behavioral edit_topology have timestamp_ns: 0, which
    // would bucket all events into the first checkpoint interval and produce
    // meaningless results. Only run when keystroke data provides real timestamps.
    let events_have_timestamps = sorted_events.iter().any(|e| e.timestamp_ns > 0);
    let per_cp = if packet.checkpoints.len() >= 2 && events_have_timestamps {
        let result = per_checkpoint_flags(SortedEvents::new(&sorted_events), &packet.checkpoints);
        if result.suspicious {
            warnings.push(format!(
                "Per-checkpoint analysis: {:.0}% of checkpoints flagged (threshold: {:.0}%)",
                result.pct_flagged.get() * 100.0,
                PER_CHECKPOINT_SUSPICIOUS_THRESHOLD * 100.0,
            ));
        }
        Some(result)
    } else {
        None
    };

    (Some(forensics), per_cp)
}
