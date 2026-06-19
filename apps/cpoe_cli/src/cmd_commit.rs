// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use cpoe::vdf;
use cpoe::SecureEvent;

use crate::output::OutputMode;
use crate::util::{
    ensure_dirs, get_device_id, get_machine_id, load_vdf_params, open_secure_store,
    writersproof_dir, BLOCKED_EXTENSIONS, LARGE_FILE_WARNING_THRESHOLD, MAX_FILE_SIZE,
};

pub(crate) async fn cmd_commit(
    file_path: &Path,
    message: Option<String>,
    out: &OutputMode,
) -> Result<()> {
    let file_path_owned = file_path.to_path_buf();

    // Phase 1: file I/O, hashing, and DB read (all blocking)
    #[allow(clippy::type_complexity)]
    let (
        abs_path_str,
        content_hash,
        content_len,
        file_size,
        size_delta,
        vdf_input,
        mut db,
        vdf_params,
        device_id,
        machine_id,
    ): (
        String,
        [u8; 32],
        usize,
        i64,
        i32,
        [u8; 32],
        _,
        _,
        [u8; 16],
        String,
    ) = tokio::task::spawn_blocking(move || -> Result<_> {
        if !file_path_owned.exists() {
            return Err(anyhow!("File not found: {}", file_path_owned.display()));
        }
        let abs_path = fs::canonicalize(&file_path_owned)
            .map_err(|e| anyhow!("resolve {}: {}", file_path_owned.display(), e))?;
        let abs_path_str = abs_path.to_string_lossy().into_owned();

        if let Some(ext) = abs_path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            if BLOCKED_EXTENSIONS.contains(&ext_lower.as_str()) {
                return Err(anyhow!(
                    "File type '.{}' is not a supported text document.",
                    ext_lower
                ));
            }
        }

        let content = fs::read(&abs_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                anyhow!("Permission denied: {}", abs_path.display())
            } else {
                anyhow!("read {}: {}", abs_path.display(), e)
            }
        })?;
        if content.len() as u64 > MAX_FILE_SIZE {
            return Err(anyhow!(
                "File is too large ({:.0} MB).\n\n\
                 CPoE is designed for text documents, not binary files.\n\
                 Maximum file size: {} MB",
                content.len() as f64 / 1_000_000.0,
                MAX_FILE_SIZE / 1_000_000
            ));
        }

        let db = open_secure_store()?;
        let content_hash: [u8; 32] = Sha256::digest(&content).into();
        let content_len = content.len();
        let file_size = content_len as i64;

        let events = db.get_events_for_file(&abs_path_str)?;
        let last_event = events.last();

        let (vdf_input, size_delta): ([u8; 32], i32) = if let Some(last) = last_event {
            let delta = (file_size - last.file_size).clamp(i32::MIN as i64, i32::MAX as i64);
            (last.event_hash, delta as i32)
        } else {
            (
                content_hash,
                file_size.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
            )
        };

        let config = ensure_dirs()?;
        let vdf_params = load_vdf_params(&config);
        let device_id = get_device_id()?;
        let machine_id = get_machine_id();

        Ok((
            abs_path_str,
            content_hash,
            content_len,
            file_size,
            size_delta,
            vdf_input,
            db,
            vdf_params,
            device_id,
            machine_id,
        ))
    })
    .await
    .context("pre-VDF I/O task")??;

    if content_len as u64 > LARGE_FILE_WARNING_THRESHOLD && !out.quiet {
        eprintln!(
            "Warning: Large file ({:.0} MB). Checkpoint may take longer than usual.",
            content_len as f64 / 1_000_000.0
        );
    }
    if content_len == 0 {
        eprintln!("Warning: File is empty. Checkpoint will record a zero-byte snapshot.");
    }

    if !out.quiet && !out.json {
        print!("Computing checkpoint...");
        io::stdout().flush()?;
    }

    let start = std::time::Instant::now();
    let vdf_proof = vdf::compute_async(vdf_input, Duration::from_secs(1), vdf_params)
        .await
        .map_err(|e| anyhow!("VDF computation failed: {}", e))?;
    let elapsed = start.elapsed();

    // Phase 2: DB write (blocking)
    let message_for_closure = message.clone();
    let (event_hash, count) = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut event = SecureEvent {
            id: None,
            device_id,
            machine_id,
            timestamp_ns: {
                const MIN_VALID_NS: i64 = 946_684_800 * 1_000_000_000; // year 2000
                const MAX_VALID_NS: i64 = 4_102_444_800 * 1_000_000_000; // year 2100
                let ts = Utc::now()
                    .timestamp_nanos_opt()
                    .unwrap_or_else(|| Utc::now().timestamp_millis().saturating_mul(1_000_000));
                if !(MIN_VALID_NS..=MAX_VALID_NS).contains(&ts) {
                    Utc::now().timestamp() * 1_000_000_000
                } else {
                    ts
                }
            },
            file_path: abs_path_str,
            content_hash,
            file_size,
            size_delta,
            previous_hash: [0u8; 32],
            event_hash: [0u8; 32],
            context_type: Some("manual".to_string()),
            context_note: message_for_closure,
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

        db.add_secure_event(&mut event).context("save checkpoint")?;
        let events = db.get_events_for_file(&event.file_path)?;
        Ok((event.event_hash, events.len()))
    })
    .await
    .context("DB write task")??;

    if out.json {
        println!(
            "{}",
            serde_json::json!({
                "checkpoint": count,
                "content_hash": hex::encode(content_hash),
                "event_hash": hex::encode(event_hash),
                "file_size": file_size,
                "size_delta": size_delta,
                "vdf_iterations": vdf_proof.iterations,
                "elapsed_secs": elapsed.as_secs_f64(),
                "message": message,
            })
        );
    } else if !out.quiet {
        println!(" done ({:.2?})", elapsed);
        println!();
        println!("Checkpoint #{} created", count);
        println!("  Content hash: {}...", hex::encode(&content_hash[..8]));
        println!("  Event hash:   {}...", hex::encode(&event_hash[..8]));
        println!(
            "  VDF proves:   >= {:?} elapsed",
            vdf_proof.min_elapsed_time(vdf_params)
        );
        if let Some(msg) = &message {
            println!("  Message:      {}", msg);
        }
        if count < 3 {
            println!();
            println!(
                "Note: Export requires at least 3 checkpoints (currently {}).",
                count
            );
        }
    }

    Ok(())
}

pub(crate) async fn cmd_commit_smart(
    file: Option<PathBuf>,
    message: Option<String>,
    anchor: bool,
    out: &OutputMode,
) -> Result<()> {
    let dir = writersproof_dir()?;

    if !crate::smart_defaults::is_initialized(&dir) {
        if !out.quiet {
            println!("CPoE is not initialized.");
        }
        if !out.json && crate::smart_defaults::ask_confirmation("Initialize now?", true)? {
            crate::cmd_init::cmd_init()?;
            println!();
        } else {
            return Err(anyhow!("CPoE is not initialized. Run 'cpoe init' first."));
        }
    }

    let config = ensure_dirs()?;
    if !out.quiet {
        crate::smart_defaults::ensure_vdf_calibrated_with_warning(config.vdf.iterations_per_second);
    }

    let file_path = match file {
        Some(f) => {
            let path_str = f.to_string_lossy();
            if path_str == "." || path_str == "./" {
                select_file_for_commit()?
            } else {
                f
            }
        }
        None => select_file_for_commit()?,
    };

    let msg = message.or_else(|| Some(crate::smart_defaults::default_commit_message()));

    cmd_commit(&file_path, msg, out).await?;

    if anchor {
        cmd_anchor(&file_path).await?;
    }

    Ok(())
}

async fn cmd_anchor(file_path: &Path) -> Result<()> {
    use cpoe::writersproof::{AnchorMetadata, AnchorRequest, WritersProofClient};

    let file_path_owned = file_path.to_path_buf();
    let (evidence_hash, signature, did, api_key) =
        tokio::task::spawn_blocking(move || -> Result<_> {
            let abs_path = fs::canonicalize(&file_path_owned)?;
            let abs_path_str = abs_path.to_string_lossy().into_owned();

            let db = open_secure_store()?;
            let events = db.get_events_for_file(&abs_path_str)?;
            let latest = events
                .last()
                .ok_or_else(|| anyhow!("No events found for anchoring"))?;

            let evidence_hash = hex::encode(latest.event_hash);

            let config = ensure_dirs()?;
            let dir = &config.data_dir;
            let signing_key = crate::util::load_signing_key(dir)?;
            let signature = {
                use ed25519_dalek::Signer;
                hex::encode(signing_key.sign(latest.event_hash.as_slice()).to_bytes())
            };
            let did = crate::util::load_did(dir).map_err(|e| {
                anyhow!("Cannot anchor without identity. Run 'cpoe init' first: {e}")
            })?;

            let api_key = crate::util::load_api_key(dir)?;
            Ok((evidence_hash, signature, did, api_key))
        })
        .await
        .context("anchor I/O task")??;

    let client = WritersProofClient::new("https://api.writersproof.com")?.with_jwt(api_key.into());

    print!("Anchoring to transparency log...");
    io::stdout().flush()?;

    let resp = tokio::time::timeout(
        Duration::from_secs(30),
        client.anchor(AnchorRequest {
            evidence_hash,
            author_did: did,
            signature,
            metadata: Some(AnchorMetadata {
                document_name: file_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned()),
                tier: Some("anchored".into()),
            }),
        }),
    )
    .await
    .map_err(|_| anyhow!("Anchor request timed out after 30s"))??;

    println!(" done");
    println!("  Anchor ID: {}", resp.anchor_id);
    println!("  Timestamp: {}", resp.timestamp);
    println!("  Log index: {}", resp.log_index);
    println!(
        "  Verify at: https://writerslogic.com/verify/{}",
        resp.anchor_id
    );

    Ok(())
}

fn select_file_for_commit() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;

    if let Ok(db) = open_secure_store() {
        let tracked = db.list_files().unwrap_or_default();
        let cwd_str = cwd.to_string_lossy();
        let tracked_in_cwd: Vec<PathBuf> = tracked
            .iter()
            .filter(|(path, _, _)| path.starts_with(cwd_str.as_ref()))
            .map(|(path, _, _)| PathBuf::from(path))
            .collect();

        if tracked_in_cwd.len() == 1 {
            let file = &tracked_in_cwd[0];
            println!(
                "Using tracked file: {}",
                file.file_name().unwrap_or_default().to_string_lossy()
            );
            return Ok(file.clone());
        } else if !tracked_in_cwd.is_empty() {
            println!("Multiple tracked files found:");
            if let Some(selected) =
                crate::smart_defaults::select_file_from_list(&tracked_in_cwd, "")?
            {
                return Ok(selected);
            }
        }
    }

    let recent = crate::smart_defaults::get_recently_modified_files(&cwd, 10);
    if recent.is_empty() {
        return Err(anyhow!(
            "No files found in current directory.\n\n\
             Specify a file: cpoe commit <file>"
        ));
    }

    println!("Select a file to checkpoint:");
    match crate::smart_defaults::select_file_from_list(&recent, "")? {
        Some(f) => Ok(f),
        None => Err(anyhow!("No file selected.")),
    }
}
