// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::types::catch_ffi_panic;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCheckpointDetail {
    pub ordinal: u64,
    pub timestamp_epoch_ms: i64,
    pub content_hash: String,
    pub previous_hash: String,
    pub checkpoint_hash: String,
    pub content_size: u64,
    pub size_delta: i32,
    pub vdf_iterations: u64,
    pub has_jitter_binding: bool,
    pub has_tpm_binding: bool,
    pub context_type: Option<String>,
    pub context_note: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiChainSummary {
    pub success: bool,
    pub document_path: String,
    pub checkpoint_count: u32,
    pub first_commit_epoch_ms: Option<i64>,
    pub last_commit_epoch_ms: Option<i64>,
    pub total_elapsed_sec: f64,
    pub final_content_hash: Option<String>,
    pub chain_valid: Option<bool>,
    pub checkpoints: Vec<FfiCheckpointDetail>,
    /// "Legacy" (WAR/1.0) or "Entangled" (WAR/1.1).
    pub entanglement_mode: String,
    pub error_message: Option<String>,
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_checkpoint_chain(path: String) -> FfiChainSummary {
    catch_ffi_panic!(FfiChainSummary {
        success: false,
        document_path: String::new(),
        checkpoint_count: 0,
        first_commit_epoch_ms: None,
        last_commit_epoch_ms: None,
        total_elapsed_sec: 0.0,
        final_content_hash: None,
        chain_valid: None,
        checkpoints: vec![],
        entanglement_mode: "Legacy".into(),
        error_message: Some("engine internal error".to_string()),
    }, {
    log::debug!("ffi_get_checkpoint_chain: path={}", path);
    let err = |msg: String| FfiChainSummary {
        success: false,
        document_path: path.clone(),
        checkpoint_count: 0,
        first_commit_epoch_ms: None,
        last_commit_epoch_ms: None,
        total_elapsed_sec: 0.0,
        final_content_hash: None,
        chain_valid: None,
        checkpoints: vec![],
        entanglement_mode: "Legacy".into(),
        error_message: Some(msg),
    };

    let (canonical, _store, events) = match crate::ffi::helpers::load_events_for_path(&path) {
        Ok(v) => v,
        Err(e) => return err(e),
    };

    if events.is_empty() {
        return err("No checkpoints found for this document".to_string());
    }

    let checkpoint_count = u32::try_from(events.len()).unwrap_or(u32::MAX);
    let first_ts_ms = events.first().map(|e| e.timestamp_ns / 1_000_000);
    let last_ts_ms = events.last().map(|e| e.timestamp_ns / 1_000_000);

    let total_elapsed_sec = match (first_ts_ms, last_ts_ms) {
        (Some(f), Some(l)) => ((l - f).max(0) as f64) / 1000.0,
        _ => 0.0,
    };

    let final_content_hash = events.last().map(|e| hex::encode(e.content_hash));

    let mut chain_valid = true;
    let mut checkpoints = Vec::with_capacity(events.len());

    for (i, ev) in events.iter().enumerate() {
        if i > 0 {
            let prev = &events[i - 1];
            if ev.previous_hash != prev.event_hash {
                chain_valid = false;
            }
        }

        let has_jitter = ev.vdf_input.is_some() && ev.vdf_iterations > 0;
        let has_tpm = ev.hardware_counter.is_some();

        checkpoints.push(FfiCheckpointDetail {
            ordinal: i as u64,
            timestamp_epoch_ms: ev.timestamp_ns / 1_000_000,
            content_hash: hex::encode(ev.content_hash),
            previous_hash: hex::encode(ev.previous_hash),
            checkpoint_hash: hex::encode(ev.event_hash),
            content_size: ev.file_size.max(0) as u64,
            size_delta: ev.size_delta,
            vdf_iterations: ev.vdf_iterations,
            has_jitter_binding: has_jitter,
            has_tpm_binding: has_tpm,
            context_type: ev.context_type.clone(),
            context_note: ev.context_note.clone(),
        });
    }

    // Entangled if any checkpoint has both VDF iterations and jitter input binding.
    let is_entangled = events
        .iter()
        .any(|e| e.vdf_iterations > 0 && e.vdf_input.is_some());

    FfiChainSummary {
        success: true,
        document_path: canonical,
        checkpoint_count,
        first_commit_epoch_ms: first_ts_ms,
        last_commit_epoch_ms: last_ts_ms,
        total_elapsed_sec,
        final_content_hash,
        chain_valid: Some(chain_valid),
        checkpoints,
        entanglement_mode: if is_entangled { "Entangled" } else { "Legacy" }.into(),
        error_message: None,
    }
    })
}
