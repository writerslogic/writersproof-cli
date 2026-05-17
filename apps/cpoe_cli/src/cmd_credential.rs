// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use std::path::Path;

use crate::cli::CredentialAction;
use crate::output::OutputMode;
use crate::util::{check_ffi_result, path_str};

pub(crate) fn cmd_credential(action: CredentialAction, out: &OutputMode) -> Result<()> {
    match action {
        CredentialAction::Create { path, session } => {
            cmd_credential_create(&path, &session, out)
        }
        CredentialAction::Verify { file } => cmd_credential_verify(&file, out),
        CredentialAction::Info => cmd_credential_info(out),
    }
}

fn cmd_credential_create(path: &Path, session_id: &str, out: &OutputMode) -> Result<()> {
    let path_str = path_str(path);

    let score = cpoe::ffi::forensics::ffi_compute_process_score(path_str);
    if !score.success {
        return Err(anyhow!(
            "{}",
            score
                .error_message
                .unwrap_or_else(|| "Cannot compute process score".to_string())
        ));
    }

    let verdict = if score.meets_threshold {
        "consistent"
    } else {
        "inconclusive"
    };

    let tier = if score.composite >= 0.8 {
        "T3"
    } else if score.composite >= 0.5 {
        "T2"
    } else {
        "T1"
    };

    let result = cpoe::ffi::credentials::ffi_create_authorship_credential(
        session_id.to_string(),
        tier.to_string(),
        verdict.to_string(),
        score.composite,
    );

    check_ffi_result(result.success, &result.error_message)?;

    let cbor_hex = result.credential_cbor_hex.unwrap_or_default();

    let signed = cpoe::ffi::credentials::ffi_sign_credential(cbor_hex.clone());
    let final_hex = if signed.success {
        signed.signed_cbor_hex.unwrap_or(cbor_hex)
    } else {
        eprintln!(
            "Warning: credential created but signing failed: {}",
            signed.error_message.unwrap_or_default()
        );
        cbor_hex
    };

    if out.json {
        println!(
            "{}",
            serde_json::json!({
                "credential_cbor_hex": final_hex,
                "document_hash_hex": result.document_hash_hex,
                "verdict": verdict,
                "composite_score": score.composite,
            })
        );
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("Authorship credential created and signed.");
    println!();
    println!(
        "Document Hash: {}",
        result.document_hash_hex.unwrap_or_default()
    );
    println!("Verdict:       {}", verdict);
    println!("Score:         {:.3}", score.composite);
    println!();
    let truncated_end = if final_hex.len() > 32 {
        &final_hex[final_hex.len() - 16..]
    } else {
        ""
    };
    println!("Credential (CBOR hex):");
    println!(
        "  {}...{}",
        &final_hex[..32.min(final_hex.len())],
        truncated_end
    );

    Ok(())
}

fn cmd_credential_verify(file: &Path, out: &OutputMode) -> Result<()> {
    // Read credential hex from file.
    let content = std::fs::read_to_string(file)
        .map_err(|e| anyhow!("Failed to read credential file: {}", e))?;
    let hex_str = content.trim().to_string();

    // Get the credential status first.
    let status = cpoe::ffi::credentials::ffi_get_credential_status(hex_str.clone());

    if !status.success {
        return Err(anyhow!(
            "{}",
            status
                .error_message
                .unwrap_or_else(|| "Unknown error".to_string())
        ));
    }

    if out.json {
        println!(
            "{}",
            serde_json::json!({
                "is_valid": status.is_valid,
                "issued_at_ms": status.issued_at_ms,
                "expires_at_ms": status.expires_at_ms,
                "issuer": status.issuer,
            })
        );
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("=== Credential Verification ===");
    println!();
    println!(
        "Valid:      {}",
        if status.is_valid { "YES" } else { "NO" }
    );
    println!("Issuer:     {}", status.issuer);
    println!("Issued At:  {} ms", status.issued_at_ms);
    println!("Expires At: {} ms", status.expires_at_ms);

    Ok(())
}

fn cmd_credential_info(out: &OutputMode) -> Result<()> {
    let info = cpoe::ffi::attestation::ffi_get_attestation_info();

    if out.json {
        println!(
            "{}",
            serde_json::json!({
                "tier": info.tier,
                "tier_label": info.tier_label,
                "provider_type": info.provider_type,
                "hardware_bound": info.hardware_bound,
                "supports_sealing": info.supports_sealing,
                "has_monotonic_counter": info.has_monotonic_counter,
                "has_secure_clock": info.has_secure_clock,
                "device_id": info.device_id,
            })
        );
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("=== Attestation Info ===");
    println!();
    println!("Tier:               T{} ({})", info.tier, info.tier_label);
    println!("Provider:           {}", info.provider_type);
    println!("Hardware Bound:     {}", info.hardware_bound);
    println!("Supports Sealing:   {}", info.supports_sealing);
    println!("Monotonic Counter:  {}", info.has_monotonic_counter);
    println!("Secure Clock:       {}", info.has_secure_clock);
    println!("Device ID:          {}", info.device_id);

    Ok(())
}
