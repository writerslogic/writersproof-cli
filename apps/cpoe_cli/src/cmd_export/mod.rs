// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use cpoe::authorproof_protocol::crypto::EvidenceSigner;
use cpoe::tpm;

use crate::output::OutputMode;
use crate::spec::{attestation_tier_value, content_tier_from_cli, profile_uri};
use crate::util::{
    ensure_dirs, load_signing_key, load_vdf_params, open_secure_store, retry_on_busy,
};

mod keystroke;
mod output;
mod packet;

use output::{write_evidence_output, EvidenceOutputContext};
use packet::{build_evidence_packet, resolve_declaration, EvidencePacketContext};

/// Files larger than this use byte count as an approximation for char count.
pub(super) const CHAR_COUNT_READ_LIMIT: i64 = 10_000_000;

fn validate_checkpoint_count(file_path: &Path, events: &[cpoe::SecureEvent]) -> Result<()> {
    use crate::spec::MIN_CHECKPOINTS_PER_PACKET;

    let file_name = || {
        file_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file_path.display().to_string())
    };

    if events.is_empty() {
        return Err(anyhow!(
            "No checkpoints found for this file.\n\n\
             Create one first with: cpoe commit {}",
            file_name()
        ));
    }

    if events.len() < MIN_CHECKPOINTS_PER_PACKET {
        return Err(anyhow!(
            "Insufficient checkpoints (found {}, need {}). Run 'cpoe commit' for this file.",
            events.len(),
            MIN_CHECKPOINTS_PER_PACKET
        ));
    }

    Ok(())
}

fn default_output_path(file_path: &Path, format_lower: &str) -> PathBuf {
    // Use only the final file name component to prevent directory traversal
    // from relative paths containing "..".
    let name = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let raw = match format_lower {
        "html" | "report" => format!("{}.report.html", name),
        "pdf" => format!("{}.report.pdf", name),
        "c2pa" => format!("{}.c2pa", name),
        "md" | "markdown" => format!("{}.evidence.md", name),
        _ => format!("{}.evidence.json", name),
    };
    // Ensure the output filename has no path separators or traversal components.
    let sanitized = Path::new(&raw).file_name().unwrap_or_default().to_owned();
    PathBuf::from(sanitized)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn cmd_export(
    file_path: &PathBuf,
    tier: &str,
    output: Option<PathBuf>,
    format: &str,
    no_beacons: bool,
    beacon_timeout: u64,
    out: &OutputMode,
) -> Result<()> {
    if no_beacons && !out.quiet && !out.json {
        eprintln!("Note: --no-beacons is set; beacon anchoring will be skipped.");
    }
    if beacon_timeout != 5 && !no_beacons && !out.quiet && !out.json {
        eprintln!("Note: --beacon-timeout set to {}s.", beacon_timeout);
    }
    let file_path_owned = file_path.clone();
    let (abs_path_str, events, config, vdf_params) =
        tokio::task::spawn_blocking(move || -> Result<_> {
            let abs_path = fs::canonicalize(&file_path_owned).map_err(|e| {
                anyhow!(
                    "Cannot resolve path {}: {}\n\n\
                     Check that the path is valid and accessible.",
                    file_path_owned.display(),
                    e
                )
            })?;
            let abs_path_str = abs_path.to_string_lossy().into_owned();

            let db = open_secure_store()?;
            let events = retry_on_busy(|| db.get_events_for_file(&abs_path_str))?;

            let config = ensure_dirs()?;
            let vdf_params = load_vdf_params(&config);

            Ok((abs_path_str, events, config, vdf_params))
        })
        .await
        .context("export I/O task")??;

    validate_checkpoint_count(file_path, &events)?;

    let dir = &config.data_dir;

    if vdf_params.iterations_per_second == 0 {
        return Err(anyhow!(
            "VDF not calibrated. Run 'cpoe init' or 'cpoe calibrate' first."
        ));
    }

    let tpm_provider = tpm::detect_provider();
    let caps = tpm_provider.capabilities();
    let tpm_device_id = tpm_provider.device_id();

    let signer: Box<dyn EvidenceSigner> = if caps.hardware_backed {
        if !out.quiet && !out.json {
            println!(
                "Using hardware provider for evidence signing: {}",
                tpm_device_id
            );
        }
        Box::new(tpm::TpmSigner::new(tpm_provider))
    } else {
        Box::new(load_signing_key(dir)?)
    };

    let latest = events
        .last()
        .ok_or_else(|| anyhow!("No events found for this file"))?;

    let tier_lower = tier.to_lowercase();
    if !matches!(
        tier_lower.as_str(),
        "basic" | "standard" | "enhanced" | "maximum"
    ) {
        anyhow::bail!(
            "Unknown evidence tier '{}'. Valid tiers: basic, standard, enhanced, maximum",
            tier
        );
    }
    let keystroke_evidence = if tier_lower == "enhanced" || tier_lower == "maximum" {
        keystroke::load_keystroke_evidence(dir, &abs_path_str)
    } else {
        serde_json::Value::Null
    };

    let title = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    let decl = resolve_declaration(
        &tier_lower,
        latest.content_hash,
        latest.event_hash,
        title,
        signer.as_ref(),
        out,
    )?;

    let total_iterations: u64 = events.iter().map(|e| e.vdf_iterations).sum();
    let total_vdf_time = Duration::try_from_secs_f64(
        total_iterations as f64 / vdf_params.iterations_per_second.max(1) as f64,
    )
    .unwrap_or(Duration::ZERO);

    let spec_content_tier = content_tier_from_cli(&tier_lower);
    let spec_profile_uri = profile_uri();
    let spec_attestation_tier =
        attestation_tier_value(caps.supports_attestation, caps.hardware_backed);

    let packet = build_evidence_packet(&EvidencePacketContext {
        file_path,
        abs_path_str: &abs_path_str,
        events: &events,
        latest,
        vdf_params: &vdf_params,
        tier_lower: &tier_lower,
        spec_content_tier,
        spec_profile_uri,
        spec_attestation_tier,
        total_vdf_time: &total_vdf_time,
        decl: &decl,
        keystroke_evidence: &keystroke_evidence,
    })?;

    if !out.quiet && !out.json {
        let identity_path = dir.join("identity.json");
        match fs::read_to_string(&identity_path) {
            Ok(identity_data) => match serde_json::from_str::<serde_json::Value>(&identity_data) {
                Ok(identity) => {
                    println!(
                        "Including key hierarchy evidence: {}",
                        identity
                            .get("fingerprint")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                    );
                }
                Err(e) => {
                    eprintln!(
                        "Warning: failed to parse {}: {}",
                        identity_path.display(),
                        e
                    );
                }
            },
            Err(e) => {
                eprintln!("Warning: failed to read {}: {}", identity_path.display(), e);
            }
        }
    }

    if tier_lower != "basic" && !out.quiet && !out.json {
        println!("Building evidence packet... done.");
    }

    let format_lower = format.to_lowercase();
    let out_path = match output {
        Some(p) => {
            // Reject user-supplied paths that contain parent-directory traversal
            // components (".."), which could write evidence output outside the
            // current directory without the user noticing.
            if p.components().any(|c| c == std::path::Component::ParentDir) {
                return Err(anyhow!(
                    "Output path '{}' contains '..'; use an absolute path or a plain filename.",
                    p.display()
                ));
            }
            p
        }
        None => default_output_path(file_path, &format_lower),
    };

    write_evidence_output(&EvidenceOutputContext {
        format_lower: &format_lower,
        out_path: &out_path,
        file_path,
        events: &events,
        packet: &packet,
        signer: signer.as_ref(),
        vdf_params: &vdf_params,
        tier,
        tier_lower: &tier_lower,
        spec_content_tier,
        spec_profile_uri,
        spec_attestation_tier,
        total_vdf_time: &total_vdf_time,
        caps: &caps,
        tpm_device_id: &tpm_device_id,
        out,
    })?;

    // Submit beacon anchor unless disabled.
    if !no_beacons {
        let beacon_result =
            cpoe::ffi::beacon::ffi_submit_beacon(abs_path_str.clone(), beacon_timeout);
        if beacon_result.success {
            if !out.quiet && !out.json {
                if let Some(ref url) = beacon_result.verification_url {
                    println!("Beacon anchor submitted: {}", url);
                } else {
                    println!("Beacon anchor submitted.");
                }
            }
        } else if !out.quiet && !out.json {
            eprintln!(
                "Warning: beacon submission failed: {}",
                beacon_result
                    .error_message
                    .as_deref()
                    .unwrap_or("unknown error")
            );
        }
    }

    if out.json {
        let json_out = serde_json::json!({
            "success": true,
            "file": out_path.to_string_lossy(),
            "checkpoints": events.len(),
            "tier": tier_lower,
            "format": format_lower,
            "verification_url": "https://writerslogic.com/verify"
        });
        println!("{}", serde_json::to_string(&json_out)?);
    } else if !out.quiet {
        println!();
        println!("Recipients can verify this evidence at: https://writerslogic.com/verify");
    }

    Ok(())
}
