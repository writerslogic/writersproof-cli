// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use chrono::Utc;
use cpoe::jitter::Session as JitterSession;
use cpoe::vdf;
use cpoe::SecureEvent;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use subtle::ConstantTimeEq;

use crate::util::MAX_FILE_SIZE;

use super::types::TrackTarget;

/// Outcome of an auto-checkpoint attempt.
pub(super) enum CheckpointResult {
    Created,
    AlreadyUpToDate,
    EmptyFile,
    TooLarge,
}

pub(super) fn auto_checkpoint_file(
    file_path: &Path,
    db: &mut cpoe::SecureStore,
    vdf_params: &vdf::Parameters,
    device_id: &[u8; 16],
    machine_id: &str,
) -> Result<CheckpointResult> {
    let abs_path_str = file_path.to_string_lossy().into_owned();
    let file_len = fs::metadata(file_path)?.len();
    if file_len > MAX_FILE_SIZE {
        return Ok(CheckpointResult::TooLarge);
    }
    let content = fs::read(file_path)?;
    if content.is_empty() {
        return Ok(CheckpointResult::EmptyFile);
    }
    let content_hash: [u8; 32] = Sha256::digest(&content).into();
    let file_size = content.len() as i64;
    let events = db.get_events_for_file(&abs_path_str)?;

    if let Some(last) = events.last() {
        if bool::from(last.content_hash.ct_eq(&content_hash)) {
            return Ok(CheckpointResult::AlreadyUpToDate);
        }
    }

    let (vdf_input, size_delta): ([u8; 32], i32) = if let Some(last) = events.last() {
        let delta = file_size - last.file_size;
        if delta < i32::MIN as i64 || delta > i32::MAX as i64 {
            eprintln!("Warning: size delta clamped to i32 range");
        }
        let delta = delta.clamp(i32::MIN as i64, i32::MAX as i64);
        (last.event_hash, delta as i32)
    } else {
        (
            content_hash,
            file_size.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
        )
    };

    let vdf_proof = vdf::compute(vdf_input, Duration::from_millis(500), *vdf_params)
        .map_err(|e| anyhow!("VDF failed: {}", e))?;

    let mut event = SecureEvent {
        id: None,
        device_id: *device_id,
        machine_id: machine_id.to_string(),
        timestamp_ns: Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| Utc::now().timestamp_millis().saturating_mul(1_000_000)),
        file_path: abs_path_str,
        content_hash,
        file_size,
        size_delta,
        previous_hash: [0u8; 32],
        event_hash: [0u8; 32],
        context_type: Some("auto".to_string()),
        context_note: None,
        vdf_input: Some(vdf_input),
        vdf_output: Some(vdf_proof.output),
        vdf_iterations: vdf_proof.iterations,
        forensic_score: 1.0,
        is_paste: false,
        hardware_counter: None,
        input_method: None,
        lamport_signature: None,
        lamport_pubkey_fingerprint: None,
        challenge_nonce: None,
        hw_cosign_signature: None,
        hw_cosign_pubkey: None,
        hw_cosign_salt_commitment: None,
        hw_cosign_chain_index: None,
        hw_cosign_entangled_hash: None,
        hw_cosign_entropy_digest: None,
        hw_cosign_entropy_bytes: None,
        posme_proof: None,
        semantic_summary: None,
    };

    db.add_secure_event(&mut event)?;
    Ok(CheckpointResult::Created)
}

pub(super) fn setup_keystroke_capture(
    session: &Arc<Mutex<JitterSession>>,
) -> (
    Option<Box<dyn cpoe::platform::KeystrokeCapture>>,
    Option<std::thread::JoinHandle<()>>,
) {
    let perms = cpoe::platform::check_permissions();
    if !perms.all_granted {
        println!("Requesting input monitoring permissions...");
        let updated = cpoe::platform::request_permissions();
        if !updated.all_granted {
            eprintln!("Warning: Permissions not granted. Keystroke capture disabled.");
            eprintln!("Grant access in System Settings > Privacy & Security > Input Monitoring.");
            eprintln!("File checkpoints will still be created on save.");
            eprintln!();
        }
    }

    if !cpoe::platform::has_required_permissions() {
        return (None, None);
    }

    match cpoe::platform::create_keystroke_capture() {
        Ok(mut capture) => match capture.start() {
            Ok(rx) => {
                let session_clone = Arc::clone(session);
                let handle = std::thread::spawn(move || {
                    const MAX_PANICS: u32 = 5;
                    let mut panic_count: u32 = 0;
                    while let Ok(_event) = rx.recv() {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let mut s = session_clone.lock().unwrap_or_else(|e| {
                                eprintln!("Warning: mutex poisoned, recovering: {}", e);
                                e.into_inner()
                            });
                            if let Err(e) = s.record_keystroke() {
                                eprintln!("Warning: keystroke recording failed: {}", e);
                            }
                        }));
                        if let Err(panic_val) = result {
                            panic_count += 1;
                            let msg = panic_val
                                .downcast_ref::<&str>()
                                .copied()
                                .or_else(|| panic_val.downcast_ref::<String>().map(|s| s.as_str()))
                                .unwrap_or("unknown panic");
                            eprintln!("Warning: keystroke processing panicked ({panic_count}/{MAX_PANICS}): {msg}");
                            if panic_count >= MAX_PANICS {
                                eprintln!("Error: keystroke thread exceeded panic limit ({MAX_PANICS}), exiting");
                                break;
                            }
                        }
                    }
                });
                println!("Keystroke capture: active");
                (Some(capture), Some(handle))
            }
            Err(e) => {
                eprintln!("Warning: Could not start keystroke capture: {}", e);
                (None, None)
            }
        },
        Err(e) => {
            eprintln!("Warning: Could not initialize keystroke capture: {}", e);
            (None, None)
        }
    }
}

pub(super) fn finalize_session(
    capture_box: &mut Option<Box<dyn cpoe::platform::KeystrokeCapture>>,
    keystroke_handle: Option<std::thread::JoinHandle<()>>,
    session: &Arc<Mutex<JitterSession>>,
    session_path: &Path,
    current_file: &Path,
    checkpoint_counts: &HashMap<PathBuf, u32>,
    target: &TrackTarget,
) -> Result<()> {
    if let Some(ref mut capture) = capture_box {
        if let Err(e) = capture.stop() {
            eprintln!("Warning: Keystroke capture stop failed: {e}");
        }
    }
    if let Some(handle) = keystroke_handle {
        if let Err(panic_val) = handle.join() {
            let msg = panic_val
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| panic_val.downcast_ref::<String>().map(|s| s.as_str()))
                .unwrap_or("unknown panic");
            eprintln!("Warning: Keystroke capture thread panicked: {msg}");
        }
    }

    let (duration, keystroke_count, sample_count) = {
        let mut s = session.lock().unwrap_or_else(|e| {
            eprintln!("Warning: mutex poisoned, recovering: {}", e);
            e.into_inner()
        });
        s.end();
        s.save(session_path)
            .map_err(|e| anyhow!("Error saving session: {}", e))?;
        (s.duration(), s.keystroke_count(), s.sample_count())
    };

    let _ = fs::remove_file(current_file);
    let total_checkpoints: u32 = checkpoint_counts.values().sum();

    println!();
    println!("=== Session Complete ===");
    println!("Duration: {:?}", duration);
    println!("Keystrokes: {}", keystroke_count);
    println!("Jitter samples: {}", sample_count);
    println!("Checkpoints: {}", total_checkpoints);

    if !target.is_single_file() && checkpoint_counts.len() > 1 {
        println!("Files:");
        let mut sorted: Vec<_> = checkpoint_counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (path, count) in sorted {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            println!("  {}: {} checkpoints", name, count);
        }
    }

    if duration.as_secs() > 0 && keystroke_count > 0 {
        let rate = keystroke_count as f64 / (duration.as_secs_f64() / 60.0);
        println!("Typing rate: {:.0} keystrokes/min", rate);
    }

    println!();
    println!(
        "Export evidence with: cpoe export {}",
        target.root().display()
    );

    Ok(())
}
