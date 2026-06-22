// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use chrono::DateTime;
use cpoe::tpm;
use cpoe::vdf::params::calibrate;
use cpoe::{derive_hmac_key, SecureStore};
use std::fs;
use std::time::Duration;
use zeroize::Zeroizing;

use cpoe::config::CpoeConfig;

use crate::output::OutputMode;
use crate::util::{ensure_dirs, open_secure_store, writersproof_dir};

pub(crate) fn cmd_calibrate() -> Result<()> {
    println!("Calibrating VDF performance...");
    println!("This measures your CPU's SHA-256 hashing speed.");
    println!();

    let calibrated_params =
        calibrate(Duration::from_secs(2)).map_err(|e| anyhow!("Calibration failed: {}", e))?;

    println!(
        "Iterations per second: {}",
        calibrated_params.iterations_per_second
    );
    println!(
        "Min iterations (0.1s): {}",
        calibrated_params.min_iterations
    );
    println!(
        "Max iterations (1hr):  {}",
        calibrated_params.max_iterations
    );
    println!();

    let mut config = ensure_dirs()?;
    config.vdf.iterations_per_second = calibrated_params.iterations_per_second;
    config.vdf.min_iterations = calibrated_params.min_iterations;
    config.vdf.max_iterations = calibrated_params.max_iterations;
    config.persist()?;

    println!("Calibration saved.");

    Ok(())
}

pub(crate) fn cmd_status(out: &OutputMode) -> Result<()> {
    let config = ensure_dirs()?;
    let dir = &config.data_dir;

    let pub_key_hex = fs::read(dir.join("signing_key.pub"))
        .ok()
        .filter(|k| k.len() >= 8)
        .map(|k| hex::encode(&k[..8]));

    let identity_fingerprint = fs::read_to_string(dir.join("identity.json"))
        .ok()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
        .and_then(|v| {
            v.get("fingerprint")
                .and_then(|f| f.as_str())
                .map(String::from)
        });

    let db_path = dir.join("events.db");
    let (db_status, tracked_files) = if db_path.exists() {
        let hmac_key = if let Ok(Some(key)) = cpoe::identity::SecureStorage::load_hmac_key() {
            Some(Zeroizing::new(key.to_vec()))
        } else {
            let signing_key_path = dir.join("signing_key");
            if signing_key_path.exists() {
                fs::read(&signing_key_path)
                    .ok()
                    .map(Zeroizing::new)
                    .filter(|k| k.len() >= 32)
                    .map(|k| derive_hmac_key(&k[..32]))
            } else {
                None
            }
        };

        if let Some(hmac_key) = hmac_key {
            match SecureStore::open(&db_path, hmac_key.clone()) {
                Ok(store) => {
                    let files = store.list_files().unwrap_or_else(|e| {
                        eprintln!("Warning: list_files: {}", e);
                        vec![]
                    });
                    ("verified".to_string(), files)
                }
                Err(e) => (format!("error: {}", e), vec![]),
            }
        } else {
            ("error: key not found".to_string(), vec![])
        }
    } else {
        ("not found".to_string(), vec![])
    };

    let chains_dir = dir.join("chains");
    let chain_count = fs::read_dir(&chains_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "json")
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or_else(|e| {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "Warning: Cannot read chains directory {:?}: {}",
                    chains_dir, e
                );
            }
            0
        });

    let presence_active = dir.join("sessions").join("current.json").exists();
    let tracking_active = dir.join("tracking").join("current_session.json").exists();

    // NOTE: catch_unwind only catches Rust panics; FFI panics (e.g. from TPM
    // libraries) will abort the process regardless. This is a best-effort guard.
    // AssertUnwindSafe is acceptable here because we discard all captured state
    // on panic and only use the returned values on the success path.
    let (tpm_status, tpm_details) =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let provider = tpm::detect_provider();
            let caps = provider.capabilities();
            (provider.device_id().to_string(), caps)
        })) {
            Ok((device_id, caps)) => {
                if caps.hardware_backed {
                    (
                        "hardware-backed".to_string(),
                        Some(serde_json::json!({
                            "device_id": device_id,
                            "supports_pcrs": caps.supports_pcrs,
                            "supports_sealing": caps.supports_sealing,
                            "supports_attestation": caps.supports_attestation,
                            "monotonic_counter": caps.monotonic_counter,
                            "secure_clock": caps.secure_clock,
                        })),
                    )
                } else {
                    ("software".to_string(), None)
                }
            }
            Err(_) => ("detection_failed".to_string(), None),
        };

    if out.json {
        let files_json: Vec<serde_json::Value> = tracked_files
            .iter()
            .map(|(path, ts, count)| {
                serde_json::json!({
                    "path": path,
                    "last_checkpoint": DateTime::from_timestamp_nanos(*ts).to_rfc3339(),
                    "checkpoint_count": count,
                })
            })
            .collect();

        let status = serde_json::json!({
            "data_dir": dir.display().to_string(),
            "public_key": pub_key_hex,
            "identity_fingerprint": identity_fingerprint,
            "vdf_iterations_per_second": config.vdf.iterations_per_second,
            "database": {
                "status": db_status,
                "tracked_documents": files_json.len(),
                "documents": files_json,
            },
            "sessions": {
                "chains": chain_count,
                "presence_active": presence_active,
                "tracking_active": tracking_active,
            },
            "hardware": {
                "tpm": tpm_status,
                "details": tpm_details,
            },
        });
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("=== CPoE Status ===");
    println!();
    println!("Data directory: {}", dir.display());
    if let Some(ref key) = pub_key_hex {
        println!("Public key: {}...", key);
    }
    if let Some(ref fp) = identity_fingerprint {
        println!("Master Identity: {}", fp);
    }
    println!("VDF iterations/sec: {}", config.vdf.iterations_per_second);

    println!();
    println!("=== Secure Database ===");
    if db_status == "verified" {
        println!("Database: Verified");
        println!();
        println!("Tracked documents: {}", tracked_files.len());
        for (path, last_ts, count) in tracked_files.iter().take(10) {
            let ts = DateTime::from_timestamp_nanos(*last_ts);
            println!(
                "  {} ({} checkpoints, last: {})",
                path,
                count,
                ts.format("%Y-%m-%d %H:%M")
            );
        }
        if tracked_files.len() > 10 {
            println!("  ... and {} more", tracked_files.len() - 10);
        }
    } else if db_status.starts_with("error") {
        if db_status.contains("Permission denied") {
            eprintln!("Error: Permission denied reading CPoE data.");
            eprintln!("Check permissions on ~/.writersproof/");
        } else {
            println!("Database: ERROR ({})", db_status);
        }
    } else {
        println!("Database: not found");
        println!("  Run 'cpoe init' to get started.");
    }

    println!();
    println!("=== Sessions ===");
    println!("JSON chains: {}", chain_count);
    println!(
        "Presence session: {}",
        if presence_active { "ACTIVE" } else { "none" }
    );
    println!(
        "Tracking session: {}",
        if tracking_active { "ACTIVE" } else { "none" }
    );

    println!();
    println!("=== Hardware ===");
    match tpm_status.as_str() {
        "hardware-backed" => {
            println!("TPM: Hardware");
            if let Some(details) = tpm_details {
                if let Some(id) = details.get("device_id").and_then(|v| v.as_str()) {
                    println!("  Device ID: {}", id);
                }
                for field in &[
                    "supports_pcrs",
                    "supports_sealing",
                    "supports_attestation",
                    "monotonic_counter",
                    "secure_clock",
                ] {
                    if let Some(val) = details.get(field) {
                        println!(
                            "  {}: {}",
                            field.replace('_', " ").replace("supports ", "Supports "),
                            val
                        );
                    }
                }
            }
        }
        "software" => println!("TPM: Software"),
        _ => {
            println!("TPM: Failed");
            println!("  Using software provider");
        }
    }

    Ok(())
}

pub(crate) fn show_quick_status(out: &OutputMode) -> Result<()> {
    let dir = writersproof_dir()?;
    let config = CpoeConfig::load_or_default(&dir)?;

    let tracked_files = if dir.join("signing_key").exists() {
        match open_secure_store() {
            Ok(db) => db.list_files().unwrap_or_default(),
            Err(_) => vec![],
        }
    } else {
        vec![]
    };

    if out.json {
        let initialized = crate::smart_defaults::is_initialized(&dir);
        let calibrated = crate::smart_defaults::is_calibrated(config.vdf.iterations_per_second);
        let docs: Vec<serde_json::Value> = tracked_files
            .iter()
            .map(|(path, ts, count)| {
                serde_json::json!({
                    "path": path,
                    "last_checkpoint": DateTime::from_timestamp_nanos(*ts).to_rfc3339(),
                    "checkpoint_count": count,
                })
            })
            .collect();
        let status = if !initialized {
            "not_initialized"
        } else if !calibrated {
            "not_calibrated"
        } else {
            "ready"
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": status,
                "tracked_documents": docs.len(),
                "documents": docs,
            }))?
        );
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    crate::smart_defaults::show_quick_status(
        &dir,
        config.vdf.iterations_per_second,
        &tracked_files,
    );
    Ok(())
}
