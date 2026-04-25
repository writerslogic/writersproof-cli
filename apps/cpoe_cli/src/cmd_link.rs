// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use cpoe::vdf;
use cpoe::SecureEvent;

use crate::output::OutputMode;
use crate::util::{
    ensure_dirs, get_device_id, get_machine_id, load_vdf_params, open_secure_store, MAX_FILE_SIZE,
};

pub(crate) fn cmd_link(
    source: &PathBuf,
    export: &PathBuf,
    message: Option<String>,
    out: &OutputMode,
) -> Result<()> {
    if !source.exists() {
        return Err(anyhow!("Source file not found: {}", source.display()));
    }
    if !export.exists() {
        return Err(anyhow!("Export file not found: {}", export.display()));
    }

    let abs_source =
        fs::canonicalize(source).map_err(|e| anyhow!("resolve {}: {}", source.display(), e))?;
    let abs_export =
        fs::canonicalize(export).map_err(|e| anyhow!("resolve {}: {}", export.display(), e))?;
    let source_str = abs_source.to_string_lossy().into_owned();

    let mut db = open_secure_store()?;
    let events = db.get_events_for_file(&source_str)?;
    if events.is_empty() {
        return Err(anyhow!(
            "No evidence chain for source: {}\n\n\
             Track the source file first with 'cpoe {}'",
            source.display(),
            source.display()
        ));
    }

    // Hash the export file (read once, then check size to avoid TOCTOU)
    let export_content =
        fs::read(&abs_export).map_err(|e| anyhow!("read {}: {}", abs_export.display(), e))?;
    if export_content.len() as u64 > MAX_FILE_SIZE {
        return Err(anyhow!(
            "Export file is too large ({:.0} MB). Maximum: {} MB.",
            export_content.len() as f64 / 1_000_000.0,
            MAX_FILE_SIZE / 1_000_000
        ));
    }
    let export_hash: [u8; 32] = Sha256::digest(&export_content).into();
    let export_name = abs_export.file_name().unwrap_or_default().to_string_lossy();

    // Build structured context note
    let note = message.unwrap_or_else(|| {
        format!(
            "Derived from {}",
            abs_source.file_name().unwrap_or_default().to_string_lossy()
        )
    });
    let context_note = format!(
        "export_hash={};export_path={};{}",
        hex::encode(export_hash),
        abs_export.to_string_lossy(),
        note
    );

    // Read source content for the checkpoint
    let source_content =
        fs::read(&abs_source).map_err(|e| anyhow!("read {}: {}", abs_source.display(), e))?;
    let content_hash: [u8; 32] = Sha256::digest(&source_content).into();
    let file_size = source_content.len() as i64;

    let last = events
        .last()
        .ok_or_else(|| anyhow!("No events found for source"))?;
    let size_delta = (file_size - last.file_size).clamp(i32::MIN as i64, i32::MAX as i64) as i32;
    let vdf_input = last.event_hash;

    let config = ensure_dirs()?;
    let vdf_params = load_vdf_params(&config);
    let vdf_proof = vdf::compute(vdf_input, Duration::from_secs(1), vdf_params)
        .map_err(|e| anyhow!("VDF computation failed: {}", e))?;

    let mut event = SecureEvent {
        id: None,
        device_id: get_device_id()?,
        machine_id: get_machine_id(),
        timestamp_ns: Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| Utc::now().timestamp_millis().saturating_mul(1_000_000)),
        file_path: source_str.clone(),
        content_hash,
        file_size,
        size_delta,
        previous_hash: [0u8; 32],
        event_hash: [0u8; 32],
        context_type: Some("derivative".to_string()),
        context_note: Some(context_note),
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
    };

    db.add_secure_event(&mut event)
        .map_err(|e| anyhow!("save link event: {}", e))?;

    if out.json {
        println!(
            "{}",
            serde_json::json!({
                "linked": true,
                "source": source_str,
                "export": abs_export.to_string_lossy(),
                "export_hash": hex::encode(export_hash),
                "event_hash": hex::encode(event.event_hash),
            })
        );
    } else if !out.quiet {
        println!("Linked export to evidence chain.");
        println!(
            "  Source:      {}",
            abs_source.file_name().unwrap_or_default().to_string_lossy()
        );
        println!("  Export:      {}", export_name);
        println!("  Export hash: {}...", hex::encode(&export_hash[..8]));
        println!("  Event hash:  {}...", hex::encode(&event.event_hash[..8]));
    }

    Ok(())
}
