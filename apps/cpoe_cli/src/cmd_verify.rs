// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#![allow(clippy::ptr_arg)]

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::PathBuf;

use cpoe::authorproof_protocol::forensics::ForensicVerdict;
use cpoe::authorproof_protocol::rfc::{CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET};
use cpoe::evidence;
use cpoe::verify::{self, FullVerificationResult, VerifyOptions};
use cpoe::war;

use crate::output::OutputMode;
use crate::spec::{EAT_PROFILE_URI, MIN_CHECKPOINTS_PER_PACKET, PROFILE_URI};
use cpoe::{derive_hmac_key, SecureStore};
use zeroize::Zeroizing;

use crate::util::{ensure_dirs, load_vdf_params, writersproof_dir};

pub(crate) fn cmd_verify(
    file_path: &PathBuf,
    key: Option<PathBuf>,
    output_war: Option<PathBuf>,
    out: &OutputMode,
) -> Result<()> {
    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if ext == "json" {
        verify_json(file_path, output_war, out)
    } else if ext == "cpoe" || ext == "cbor" {
        verify_cpop(file_path, out)
    } else if ext == "cwar" || ext == "war" {
        verify_cwar(file_path, out)
    } else if matches!(ext, "db" | "sqlite") {
        verify_db(file_path, key, out)
    } else {
        Err(anyhow!(
            "Unknown file format '{}'. Expected .json, .cpoe, .cwar, or .db",
            ext
        ))
    }
}

fn verify_json(file_path: &PathBuf, output_war: Option<PathBuf>, out: &OutputMode) -> Result<()> {
    let data = fs::read(file_path).context("read evidence file")?;
    let raw_json: serde_json::Value =
        serde_json::from_slice(&data).context("parse evidence JSON")?;

    let spec_warnings = check_spec_compliance(&raw_json);

    let packet: evidence::Packet =
        serde_json::from_value(raw_json.clone()).context("parse evidence packet")?;

    let config = ensure_dirs()?;
    let vdf_params = load_vdf_params(&config);

    let opts = VerifyOptions {
        vdf_params,
        expected_nonce: None,
        run_forensics: true,
        trusted_public_key: None,
    };

    let result = verify::full_verify(&packet, &opts);

    if let Some(war_path) = output_war {
        write_war_appraisal(&packet, &war_path)?;
    }

    // Unsigned packets (signature == None) are accepted when structural checks
    // pass; only an explicit signature failure (Some(false)) invalidates.
    // A packet with zero checkpoints is meaningless and is always rejected.
    let overall_valid =
        result.structural && result.signature != Some(false) && !packet.checkpoints.is_empty();

    if out.json {
        print_json_result(file_path, &packet, &raw_json, &result, &spec_warnings);
        if !overall_valid {
            return Err(anyhow!("Verification failed"));
        }
        return Ok(());
    }

    if out.quiet {
        if !overall_valid {
            return Err(anyhow!("Verification failed"));
        }
        return Ok(());
    }

    print_human_result(file_path, &packet, &raw_json, &result, &spec_warnings);

    if !overall_valid {
        return Err(anyhow!("Verification failed"));
    }

    Ok(())
}

fn check_spec_compliance(raw_json: &serde_json::Value) -> Vec<String> {
    let mut warnings = Vec::new();

    if let Some(spec) = raw_json.get("spec") {
        if let Some(tag) = spec.get("cbor_tag").and_then(|v| v.as_u64()) {
            if tag != CBOR_TAG_EVIDENCE_PACKET {
                warnings.push(format!(
                    "Evidence CBOR tag mismatch: expected {}, found {}",
                    CBOR_TAG_EVIDENCE_PACKET, tag
                ));
            }
        }
        if let Some(uri) = spec.get("profile_uri").and_then(|v| v.as_str()) {
            if uri != PROFILE_URI && uri != EAT_PROFILE_URI {
                warnings.push(format!("Unknown profile URI: {}", uri));
            }
        }
        if let Some(tier) = spec.get("content_tier").and_then(|v| v.as_u64()) {
            if !(1..=3).contains(&tier) {
                warnings.push(format!("Invalid content-tier: {}", tier));
            }
        }
        if let Some(at) = spec.get("attestation_tier").and_then(|v| v.as_u64()) {
            if !(1..=4).contains(&at) {
                warnings.push(format!("Invalid attestation-tier: {}", at));
            }
        }
    }

    if let Some(checkpoints) = raw_json.get("checkpoints").and_then(|v| v.as_array()) {
        if checkpoints.len() < MIN_CHECKPOINTS_PER_PACKET {
            warnings.push(format!(
                "Insufficient checkpoints: {} (minimum {})",
                checkpoints.len(),
                MIN_CHECKPOINTS_PER_PACKET
            ));
        }
    }

    warnings
}

fn verdict_str(v: &ForensicVerdict) -> &'static str {
    match v {
        ForensicVerdict::V1VerifiedHuman => "V1: Verified Human",
        ForensicVerdict::V2LikelyHuman => "V2: Likely Human",
        ForensicVerdict::V3Suspicious => "V3: Suspicious",
        ForensicVerdict::V4LikelySynthetic => "V4: Likely Synthetic",
        ForensicVerdict::V5ConfirmedForgery => "V5: Confirmed Forgery",
        ForensicVerdict::V6InsufficientData => "V6: Insufficient Data",
    }
}

fn status_icon(ok: bool) -> &'static str {
    if ok {
        "[OK]"
    } else {
        "[FAIL]"
    }
}

fn print_json_result(
    file_path: &PathBuf,
    packet: &evidence::Packet,
    raw_json: &serde_json::Value,
    result: &FullVerificationResult,
    spec_warnings: &[String],
) {
    let signature_present = result.signature.is_some();
    let signed = result.signature.is_some();
    let mut obj = serde_json::json!({
        "valid": result.structural && result.signature == Some(true),
        "signed": signed,
        "file": file_path.to_string_lossy(),
        "document": packet.document.title,
        "checkpoints": packet.checkpoints.len(),
        "total_elapsed": format!("{:?}", packet.total_elapsed_time()),
        "verdict": verdict_str(&result.verdict),
        "structural": result.structural,
        "signature": result.signature,
        "signature_present": signature_present,
        "seals": {
            "jitter_tag_present": result.seals.jitter_tag_present,
            "entangled_binding_valid": result.seals.entangled_binding_valid,
            "checkpoints_checked": result.seals.checkpoints_checked,
        },
        "duration": {
            "computed_min_seconds": result.duration.computed_min_seconds,
            "claimed_seconds": result.duration.claimed_seconds,
            "ratio": result.duration.ratio,
            "plausible": result.duration.plausible,
        },
        "key_provenance": {
            "hierarchy_consistent": result.key_provenance.hierarchy_consistent,
            "signing_key_consistent": result.key_provenance.signing_key_consistent,
            "ratchet_monotonic": result.key_provenance.ratchet_monotonic,
        },
    });

    if let Some(ref forensics) = result.forensics {
        obj["forensics"] = serde_json::json!({
            "assessment_score": forensics.assessment_score,
            "risk_level": format!("{}", forensics.risk_level),
            "anomaly_count": forensics.anomaly_count,
            "cadence_cv": forensics.cadence.coefficient_of_variation,
            "is_robotic": forensics.cadence.is_robotic,
            "hurst_exponent": forensics.hurst_exponent,
            "snr_flagged": forensics.snr.as_ref().map(|s: &cpoe::analysis::SnrAnalysis| s.flagged),
            "lyapunov_flagged": forensics.lyapunov.as_ref().map(|l: &cpoe::analysis::LyapunovAnalysis| l.flagged),
            "iki_compression_flagged": forensics.iki_compression.as_ref().map(|c: &cpoe::analysis::IkiCompressionAnalysis| c.flagged),
            "labyrinth_plausible": forensics.labyrinth.as_ref().map(|l: &cpoe::analysis::LabyrinthAnalysis| l.is_biologically_plausible()),
        });
    }

    if let Some(ref pcp) = result.per_checkpoint {
        obj["per_checkpoint"] = serde_json::json!({
            "pct_flagged": pcp.pct_flagged,
            "suspicious": pcp.suspicious,
            "total_checkpoints": pcp.checkpoint_flags.len(),
        });
    }

    let mut all_warnings: Vec<String> = spec_warnings.to_vec();
    all_warnings.extend(result.warnings.iter().cloned());
    if !all_warnings.is_empty() {
        obj["warnings"] = serde_json::json!(all_warnings);
    }

    if let Some(spec) = raw_json.get("spec") {
        obj["spec"] = spec.clone();
    }

    println!("{}", obj);
}

fn print_human_result(
    _file_path: &PathBuf,
    packet: &evidence::Packet,
    raw_json: &serde_json::Value,
    result: &FullVerificationResult,
    spec_warnings: &[String],
) {
    let overall = result.structural && result.signature != Some(false);
    println!(
        "{} Evidence packet {}",
        status_icon(overall),
        if overall { "Verified" } else { "INVALID" }
    );
    println!("  Document: {}", packet.document.title);
    println!("  Checkpoints: {}", packet.checkpoints.len());
    println!("  Total elapsed: {:?}", packet.total_elapsed_time());
    println!("  Verdict: {}", verdict_str(&result.verdict));

    println!();
    println!("Verification checks:");
    println!(
        "  {} Structural (chain hashes, VDF proofs)",
        status_icon(result.structural)
    );
    match result.signature {
        Some(true) => println!("  {} Packet signature", status_icon(true)),
        Some(false) => println!("  {} Packet signature", status_icon(false)),
        None => println!("  [--] Packet signature (unsigned)"),
    }
    match result.seals.jitter_tag_present {
        Some(v) => println!("  {} Jitter seal", status_icon(v)),
        None => println!("  [--] Jitter seal (not present)"),
    }
    match result.seals.entangled_binding_valid {
        Some(v) => println!("  {} Entangled binding", status_icon(v)),
        None => println!("  [--] Entangled binding (not present)"),
    }
    println!(
        "  {} Duration cross-check (ratio: {:.2}x)",
        status_icon(result.duration.plausible),
        result.duration.ratio
    );
    match result.key_provenance.hierarchy_consistent {
        Some(v) => println!("  {} Key hierarchy", status_icon(v)),
        None => println!("  [--] Key hierarchy (not present)"),
    }
    println!(
        "  {} Signing key consistent",
        status_icon(result.key_provenance.signing_key_consistent)
    );
    println!(
        "  {} Ratchet monotonic",
        status_icon(result.key_provenance.ratchet_monotonic)
    );

    if let Some(ref forensics) = result.forensics {
        println!();
        println!("Forensic analysis:");
        println!(
            "  Assessment score: {:.2} ({})",
            forensics.assessment_score, forensics.risk_level
        );
        println!("  Anomaly count: {}", forensics.anomaly_count);
        println!(
            "  Cadence CV: {:.3}{}",
            forensics.cadence.coefficient_of_variation,
            if forensics.cadence.is_robotic {
                " (ROBOTIC)"
            } else {
                ""
            }
        );
        if let Some(ref hurst) = forensics.hurst_exponent {
            println!("  Hurst exponent: {:.3}", hurst);
        }
        if let Some(ref snr) = forensics.snr {
            println!(
                "  SNR: {:.1} dB{}",
                snr.snr_db,
                if snr.flagged { " (FLAGGED)" } else { "" }
            );
        }
        if let Some(ref lyap) = forensics.lyapunov {
            println!(
                "  Lyapunov exponent: {:.3}{}",
                lyap.exponent,
                if lyap.flagged { " (FLAGGED)" } else { "" }
            );
        }
        if let Some(ref comp) = forensics.iki_compression {
            println!(
                "  IKI compression ratio: {:.3}{}",
                comp.ratio,
                if comp.flagged { " (FLAGGED)" } else { "" }
            );
        }
        if let Some(ref lab) = forensics.labyrinth {
            println!(
                "  Labyrinth: dim={}, corr_dim={:.2}, det={:.2}{}",
                lab.embedding_dimension,
                lab.correlation_dimension,
                lab.determinism,
                if lab.is_biologically_plausible() {
                    ""
                } else {
                    " (NOT PLAUSIBLE)"
                }
            );
        }
    }

    if let Some(ref pcp) = result.per_checkpoint {
        println!();
        println!(
            "Per-checkpoint analysis: {:.0}% flagged{}",
            pcp.pct_flagged.get() * 100.0,
            if pcp.suspicious { " (SUSPICIOUS)" } else { "" }
        );
    }

    if let Some(spec) = raw_json.get("spec") {
        println!();
        println!("Spec conformance (draft-condrey-rats-pop):");
        if let Some(uri) = spec.get("profile_uri").and_then(|v| v.as_str()) {
            println!("  Profile: {}", uri);
        }
        if let Some(ct) = spec.get("content_tier").and_then(|v| v.as_u64()) {
            let tier_name = match ct {
                1 => "core",
                2 => "enhanced",
                3 => "maximum",
                _ => "unknown",
            };
            println!("  Content tier: {} ({})", ct, tier_name);
        }
        if let Some(at) = spec.get("attestation_tier").and_then(|v| v.as_u64()) {
            let tier_name = match at {
                1 => "software-only (T1)",
                2 => "attested-software (T2)",
                3 => "hardware-bound (T3)",
                4 => "hardware-hardened (T4)",
                _ => "unknown",
            };
            println!("  Attestation tier: {}", tier_name);
        }
        if let Some(tag) = spec.get("cbor_tag").and_then(|v| v.as_u64()) {
            println!("  CBOR tag: {}", tag);
        }
    }

    let mut all_warnings: Vec<String> = spec_warnings.to_vec();
    all_warnings.extend(result.warnings.iter().cloned());
    if !all_warnings.is_empty() {
        println!();
        println!("Warnings:");
        for w in &all_warnings {
            println!("  [WARN] {}", w);
        }
    }
}

fn write_war_appraisal(packet: &evidence::Packet, war_path: &PathBuf) -> Result<()> {
    let policy = cpoe::AppraisalPolicy::new("urn:cpoe:policy:verify", "1.0");
    match war::appraise(packet, &policy) {
        Ok(ear) => {
            let json = serde_json::to_string_pretty(&ear).context("serialize WAR appraisal")?;
            fs::write(war_path, json).context("write WAR file")?;
            eprintln!("WAR appraisal written to: {}", war_path.display());
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("WAR appraisal failed: {}", e)),
    }
}

fn verify_cpop(file_path: &PathBuf, out: &OutputMode) -> Result<()> {
    let data = fs::read(file_path).context("read CPoE file")?;

    // Strip and verify CRC32 footer if present: [CBOR][CRC32-BE 4 bytes][magic "CPOE" 4 bytes]
    let data = if data.len() > 8 && &data[data.len() - 4..] == b"CPOE" {
        let crc_offset = data.len() - 8;
        let stored_crc = u32::from_be_bytes([
            data[crc_offset],
            data[crc_offset + 1],
            data[crc_offset + 2],
            data[crc_offset + 3],
        ]);
        let cbor_data = &data[..crc_offset];
        let computed_crc = crc32fast::hash(cbor_data);
        if stored_crc != computed_crc {
            anyhow::bail!(
                "CRC32 integrity check failed: stored {:08x}, computed {:08x}",
                stored_crc,
                computed_crc,
            );
        }
        if !out.quiet && !out.json {
            println!("  CRC32: {:08x} (verified)", computed_crc);
        }
        cbor_data.to_vec()
    } else {
        data
    };

    // Evidence files may be COSE_Sign1 envelopes (signed) or raw CBOR (unsigned).
    let cbor_payload = cpoe::ffi::helpers::unwrap_cose_or_raw(&data);
    match cpoe::authorproof_protocol::rfc::wire_types::packet::EvidencePacketWire::decode_cbor(
        &cbor_payload,
    ) {
        Ok(packet) => {
            let validation_result = packet.validate();
            let validation_ok = validation_result.is_ok();
            let validation_err = validation_result.err().map(|e| e.to_string());

            if out.json {
                let mut obj = serde_json::json!({
                    "valid": validation_ok,
                    "file": file_path.to_string_lossy(),
                    "version": packet.version,
                    "profile": packet.profile_uri,
                    "checkpoints": packet.checkpoints.len(),
                });
                if let Some(tier) = &packet.attestation_tier {
                    obj["attestation_tier"] = serde_json::json!(format!("{:?}", tier));
                }
                if let Some(ct) = &packet.content_tier {
                    obj["content_tier"] = serde_json::json!(format!("{:?}", ct));
                }
                if let Some(err) = &validation_err {
                    obj["validation_error"] = serde_json::json!(err);
                }
                println!("{}", obj);
                return Ok(());
            }

            if !out.quiet {
                if validation_ok {
                    println!("[OK] CPoE evidence packet Verified");
                } else if let Some(err) = &validation_err {
                    println!("[WARN] CPoE decoded but validation failed: {}", err);
                }
                println!("  Version: {}", packet.version);
                println!("  Profile: {}", packet.profile_uri);
                println!("  Checkpoints: {}", packet.checkpoints.len());
                if let Some(tier) = &packet.attestation_tier {
                    println!("  Attestation tier: {:?}", tier);
                }
                if let Some(ct) = &packet.content_tier {
                    println!("  Content tier: {:?}", ct);
                }
            }
            Ok(())
        }
        Err(e) => {
            if out.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": false,
                        "file": file_path.to_string_lossy(),
                        "error": e.to_string(),
                    })
                );
            } else {
                println!("[FAILED] CPoE evidence packet INVALID: {}", e);
            }
            Err(anyhow!("Verification failed"))
        }
    }
}

fn verify_cwar(file_path: &PathBuf, out: &OutputMode) -> Result<()> {
    const MAX_CWAR_SIZE: u64 = 10_000_000; // 10 MB
    let meta = fs::metadata(file_path).context("stat WAR file")?;
    if meta.len() > MAX_CWAR_SIZE {
        return Err(anyhow!(
            "WAR file too large ({} bytes, max {})",
            meta.len(),
            MAX_CWAR_SIZE
        ));
    }
    let data = fs::read_to_string(file_path).context("read WAR file")?;
    let war_block =
        war::Block::decode_ascii(&data).map_err(|e| anyhow!("parse WAR block: {}", e))?;
    let report = war_block.verify(None);

    if out.json {
        let checks: Vec<serde_json::Value> = report
            .checks
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "passed": c.passed,
                    "message": c.message,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "valid": report.valid,
                "file": file_path.to_string_lossy(),
                "version": report.details.version,
                "author": report.details.author,
                "document_id": report.details.document_id,
                "timestamp": report.details.timestamp,
                "checks": checks,
                "summary": report.summary,
            })
        );
        if !report.valid {
            return Err(anyhow!("Verification failed"));
        }
        return Ok(());
    }

    if !out.quiet {
        if report.valid {
            println!("[OK] WAR block Verified");
        } else {
            println!("[FAILED] WAR block INVALID");
        }
        println!("  Version: {}", report.details.version);
        println!("  Author: {}", report.details.author);
        // Truncate document_id to first 16 chars for display; if shorter, show full ID.
        println!(
            "  Document: {}",
            report
                .details
                .document_id
                .get(..16)
                .unwrap_or(&report.details.document_id)
        );
        println!("  Timestamp: {}", report.details.timestamp);
        println!();
        println!("Verification checks:");
        for check in &report.checks {
            let status = if check.passed { "[OK]" } else { "[FAIL]" };
            println!("  {} {}: {}", status, check.name, check.message);
        }
        println!();
        println!("  Spec reference (draft-condrey-rats-pop):");
        println!(
            "    WAR CBOR tag: {} (attestation-result)",
            CBOR_TAG_ATTESTATION_RESULT
        );
        println!(
            "    Evidence CBOR tag: {} (evidence-packet)",
            CBOR_TAG_EVIDENCE_PACKET
        );
    }

    if !report.valid {
        if !out.quiet {
            println!();
            println!("Summary: {}", report.summary);
        }
        return Err(anyhow!("Verification failed"));
    }
    Ok(())
}

fn verify_db(file_path: &PathBuf, key: Option<PathBuf>, out: &OutputMode) -> Result<()> {
    let key_path = match key {
        Some(k) => k,
        None => writersproof_dir()?.join("signing_key"),
    };

    if !out.quiet && !out.json {
        println!("Verifying database: {}", file_path.display());
    }

    let key_data = Zeroizing::new(fs::read(&key_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow!(
                "Signing key not found: {}\n\n\
                 Specify the key with --key, or run 'cpoe init' first.",
                key_path.display()
            )
        } else {
            anyhow!("read signing key: {}", e)
        }
    })?);
    if key_data.len() != 32 && key_data.len() != 64 {
        anyhow::bail!(
            "Invalid signing key: expected 32 bytes (seed) or 64 bytes (keypair), got {}",
            key_data.len()
        );
    }
    if key_data.len() == 64 {
        eprintln!(
            "Note: 64-byte key detected (Ed25519 keypair); \
             using first 32 bytes (seed) for HMAC."
        );
    }
    let hmac_key = derive_hmac_key(&key_data[..32]);

    match SecureStore::open(file_path, hmac_key) {
        Ok(_) => {
            if out.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": true,
                        "file": file_path.to_string_lossy(),
                        "type": "database",
                    })
                );
            } else if !out.quiet {
                println!("[OK] Database integrity Verified");
            }
            Ok(())
        }
        Err(e) => {
            if out.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": false,
                        "file": file_path.to_string_lossy(),
                        "type": "database",
                        "error": e.to_string(),
                    })
                );
            } else {
                println!("[FAILED] Database integrity FAILED: {}", e);
            }
            Err(anyhow!("Verification failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- check_spec_compliance ---

    #[test]
    fn test_spec_compliance_valid_evidence_no_warnings() {
        let json = serde_json::json!({
            "spec": {
                "cbor_tag": CBOR_TAG_EVIDENCE_PACKET,
                "profile_uri": PROFILE_URI,
                "content_tier": 1,
                "attestation_tier": 1,
            },
            "checkpoints": [{"a": 1}, {"b": 2}, {"c": 3}],
        });
        let warnings = check_spec_compliance(&json);
        assert!(
            warnings.is_empty(),
            "valid evidence should produce no warnings, got: {warnings:?}"
        );
    }

    #[test]
    fn test_spec_compliance_wrong_cbor_tag() {
        let json = serde_json::json!({
            "spec": { "cbor_tag": 999999 },
            "checkpoints": [{"a": 1}, {"b": 2}, {"c": 3}],
        });
        let warnings = check_spec_compliance(&json);
        assert!(
            warnings.iter().any(|w| w.contains("CBOR tag mismatch")),
            "wrong CBOR tag should produce warning, got: {warnings:?}"
        );
    }

    #[test]
    fn test_spec_compliance_unknown_profile_uri() {
        let json = serde_json::json!({
            "spec": { "profile_uri": "urn:example:unknown" },
            "checkpoints": [{"a": 1}, {"b": 2}, {"c": 3}],
        });
        let warnings = check_spec_compliance(&json);
        assert!(
            warnings.iter().any(|w| w.contains("Unknown profile URI")),
            "unknown profile URI should be warned, got: {warnings:?}"
        );
    }

    #[test]
    fn test_spec_compliance_eat_profile_uri_accepted() {
        let json = serde_json::json!({
            "spec": { "profile_uri": EAT_PROFILE_URI },
            "checkpoints": [{"a": 1}, {"b": 2}, {"c": 3}],
        });
        let warnings = check_spec_compliance(&json);
        assert!(
            !warnings.iter().any(|w| w.contains("profile URI")),
            "EAT profile URI should be accepted, got: {warnings:?}"
        );
    }

    #[test]
    fn test_spec_compliance_content_tier_out_of_range() {
        for bad_tier in [0u64, 4, 100] {
            let json = serde_json::json!({
                "spec": { "content_tier": bad_tier },
                "checkpoints": [{"a": 1}, {"b": 2}, {"c": 3}],
            });
            let warnings = check_spec_compliance(&json);
            assert!(
                warnings.iter().any(|w| w.contains("Invalid content-tier")),
                "content_tier={bad_tier} should warn, got: {warnings:?}"
            );
        }
    }

    #[test]
    fn test_spec_compliance_content_tier_valid_range() {
        for tier in 1u64..=3 {
            let json = serde_json::json!({
                "spec": { "content_tier": tier },
                "checkpoints": [{"a": 1}, {"b": 2}, {"c": 3}],
            });
            let warnings = check_spec_compliance(&json);
            assert!(
                !warnings.iter().any(|w| w.contains("content-tier")),
                "content_tier={tier} should be valid, got: {warnings:?}"
            );
        }
    }

    #[test]
    fn test_spec_compliance_attestation_tier_boundaries() {
        // Valid: 1..=4
        for tier in 1u64..=4 {
            let json = serde_json::json!({ "spec": { "attestation_tier": tier }, "checkpoints": [{}, {}, {}] });
            let warnings = check_spec_compliance(&json);
            assert!(
                !warnings.iter().any(|w| w.contains("attestation-tier")),
                "attestation_tier={tier} should be valid"
            );
        }
        // Invalid: 0, 5
        for bad in [0u64, 5] {
            let json = serde_json::json!({ "spec": { "attestation_tier": bad }, "checkpoints": [{}, {}, {}] });
            let warnings = check_spec_compliance(&json);
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains("Invalid attestation-tier")),
                "attestation_tier={bad} should warn"
            );
        }
    }

    #[test]
    fn test_spec_compliance_insufficient_checkpoints() {
        for count in 0..MIN_CHECKPOINTS_PER_PACKET {
            let cps: Vec<serde_json::Value> =
                (0..count).map(|i| serde_json::json!({"i": i})).collect();
            let json = serde_json::json!({ "spec": {}, "checkpoints": cps });
            let warnings = check_spec_compliance(&json);
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains("Insufficient checkpoints")),
                "{count} checkpoints should warn"
            );
        }
    }

    #[test]
    fn test_spec_compliance_exact_minimum_no_warning() {
        let cps: Vec<serde_json::Value> = (0..MIN_CHECKPOINTS_PER_PACKET)
            .map(|i| serde_json::json!({"i": i}))
            .collect();
        let json = serde_json::json!({ "spec": {}, "checkpoints": cps });
        let warnings = check_spec_compliance(&json);
        assert!(
            !warnings.iter().any(|w| w.contains("checkpoints")),
            "exactly MIN_CHECKPOINTS should not warn"
        );
    }

    #[test]
    fn test_spec_compliance_missing_spec_no_crash() {
        let json = serde_json::json!({ "checkpoints": [{}, {}, {}] });
        let warnings = check_spec_compliance(&json);
        assert!(
            !warnings.iter().any(|w| w.contains("CBOR")),
            "missing spec section should not produce CBOR warnings"
        );
    }

    #[test]
    fn test_spec_compliance_multiple_violations() {
        let json = serde_json::json!({
            "spec": { "cbor_tag": 0, "profile_uri": "urn:bogus", "content_tier": 99, "attestation_tier": 0 },
            "checkpoints": [],
        });
        let warnings = check_spec_compliance(&json);
        assert!(
            warnings.len() >= 4,
            "should report >=4 warnings, got {}: {warnings:?}",
            warnings.len()
        );
    }

    // --- verdict_str ---

    #[test]
    fn test_verdict_str_all_variants() {
        assert_eq!(
            verdict_str(&ForensicVerdict::V1VerifiedHuman),
            "V1: Verified Human"
        );
        assert_eq!(
            verdict_str(&ForensicVerdict::V2LikelyHuman),
            "V2: Likely Human"
        );
        assert_eq!(
            verdict_str(&ForensicVerdict::V3Suspicious),
            "V3: Suspicious"
        );
        assert_eq!(
            verdict_str(&ForensicVerdict::V4LikelySynthetic),
            "V4: Likely Synthetic"
        );
        assert_eq!(
            verdict_str(&ForensicVerdict::V5ConfirmedForgery),
            "V5: Confirmed Forgery"
        );
        assert_eq!(
            verdict_str(&ForensicVerdict::V6InsufficientData),
            "V6: Insufficient Data"
        );
    }

    #[test]
    fn test_verdict_str_version_prefix_ordering() {
        let verdicts = [
            ForensicVerdict::V1VerifiedHuman,
            ForensicVerdict::V2LikelyHuman,
            ForensicVerdict::V3Suspicious,
            ForensicVerdict::V4LikelySynthetic,
            ForensicVerdict::V5ConfirmedForgery,
            ForensicVerdict::V6InsufficientData,
        ];
        for (i, v) in verdicts.iter().enumerate() {
            let s = verdict_str(v);
            assert!(
                s.starts_with(&format!("V{}: ", i + 1)),
                "verdict {i} should start with 'V{}: ', got: {s}",
                i + 1
            );
        }
    }

    // --- status_icon ---

    #[test]
    fn test_status_icon_values() {
        assert_eq!(status_icon(true), "[OK]");
        assert_eq!(status_icon(false), "[FAIL]");
    }
}
