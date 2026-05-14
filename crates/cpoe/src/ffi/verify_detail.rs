// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::evidence::{CheckpointProof, DocumentInfo, Packet};
use crate::ffi::helpers::detect_attestation_tier_info;
use crate::ffi::types::catch_ffi_panic;
use crate::verify::{full_verify, VerifyOptions};
use authorproof_protocol::rfc::wire_types::EvidencePacketWire;

use crate::ffi::helpers::unwrap_cose_or_raw;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiOrdinalGap {
    pub expected: u64,
    pub actual: u64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCheckpointFlag {
    pub ordinal: u64,
    pub flagged: bool,
    pub flag_reason: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiVerifyDetail {
    pub success: bool,
    pub overall_valid: bool,
    pub signature_valid: bool,
    pub chain_integrity: bool,
    pub checkpoint_count: u32,
    pub swf_iterations_per_second: u64,
    pub attestation_tier: u8,
    pub attestation_tier_label: String,
    pub unsigned_checkpoints: Vec<u64>,
    pub ordinal_gaps: Vec<FfiOrdinalGap>,
    pub warnings: Vec<String>,
    pub checkpoint_flags: Vec<FfiCheckpointFlag>,
    pub error_message: Option<String>,
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_verify_evidence_detailed(path: String) -> FfiVerifyDetail {
    catch_ffi_panic!(FfiVerifyDetail {
        success: false,
        overall_valid: false,
        signature_valid: false,
        chain_integrity: false,
        checkpoint_count: 0,
        swf_iterations_per_second: 0,
        attestation_tier: 0,
        attestation_tier_label: String::new(),
        unsigned_checkpoints: vec![],
        ordinal_gaps: vec![],
        warnings: vec![],
        checkpoint_flags: vec![],
        error_message: Some("engine internal error".to_string()),
    }, {
    log::debug!("ffi_verify_evidence_detailed: path={}", path);
    let (_, tier_num, tier_label) = detect_attestation_tier_info();

    let err = |msg: String| FfiVerifyDetail {
        success: false,
        overall_valid: false,
        signature_valid: false,
        chain_integrity: false,
        checkpoint_count: 0,
        swf_iterations_per_second: 0,
        attestation_tier: tier_num,
        attestation_tier_label: tier_label.clone(),
        unsigned_checkpoints: vec![],
        ordinal_gaps: vec![],
        warnings: vec![],
        checkpoint_flags: vec![],
        error_message: Some(msg),
    };

    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p,
        Err(e) => return err(e),
    };

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => return err(format!("Failed to read file: {e}")),
    };

    // Evidence files may be wrapped in a COSE_Sign1 envelope (signed exports)
    // or raw CBOR (legacy/unsigned). Try to unwrap COSE first, then decode.
    let cbor_payload = unwrap_cose_or_raw(&data);

    // Try wire format (EvidencePacketWire) first since ffi_export_evidence produces it,
    // then fall back to the legacy engine Packet format.
    let packet = match EvidencePacketWire::decode_cbor(&cbor_payload) {
        Ok(wire) => wire_to_packet(&wire),
        Err(_) => match Packet::decode(&cbor_payload) {
            Ok(p) => p,
            Err(e) => return err(format!("Failed to decode evidence: {e}")),
        },
    };

    let checkpoint_count = packet.checkpoints.len() as u32;
    let swf_ips = packet.vdf_params.iterations_per_second;

    let opts = VerifyOptions {
        vdf_params: packet.vdf_params,
        expected_nonce: None,
        run_forensics: true,
        trusted_public_key: None,
    };

    let result = full_verify(&packet, &opts);

    let signature_valid = result.signature.unwrap_or(false);
    let chain_integrity = result.structural;
    let overall_valid = chain_integrity
        && signature_valid
        && result.duration.plausible
        && result.key_provenance.signing_key_consistent;

    let unsigned_checkpoints: Vec<u64> = if packet.key_hierarchy.is_none() {
        (0..checkpoint_count as u64).collect()
    } else {
        let signed_ordinals: std::collections::HashSet<u64> = packet
            .key_hierarchy
            .as_ref()
            .map(|kh| kh.checkpoint_signatures.iter().map(|s| s.ordinal).collect())
            .unwrap_or_default();
        (0..checkpoint_count as u64)
            .filter(|o| !signed_ordinals.contains(o))
            .collect()
    };

    let mut ordinal_gaps = Vec::new();
    for (i, cp) in packet.checkpoints.iter().enumerate() {
        let expected = i as u64;
        if cp.ordinal != expected {
            ordinal_gaps.push(FfiOrdinalGap {
                expected,
                actual: cp.ordinal,
            });
        }
    }

    let checkpoint_flags: Vec<FfiCheckpointFlag> = result
        .per_checkpoint
        .as_ref()
        .map(|pcp| {
            pcp.checkpoint_flags
                .iter()
                .map(|cf| {
                    let reason = if cf.flagged {
                        let mut reasons = Vec::new();
                        if cf.timing_cv > 1.5 {
                            reasons.push(format!("high timing CV ({:.2})", cf.timing_cv));
                        }
                        if cf.max_velocity_bps > 50.0 {
                            reasons.push(format!("high velocity ({:.0} B/s)", cf.max_velocity_bps));
                        }
                        if cf.all_append {
                            reasons.push("all-append pattern".to_string());
                        }
                        if reasons.is_empty() {
                            Some("flagged".to_string())
                        } else {
                            Some(reasons.join("; "))
                        }
                    } else {
                        None
                    };
                    FfiCheckpointFlag {
                        ordinal: cf.ordinal,
                        flagged: cf.flagged,
                        flag_reason: reason,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    FfiVerifyDetail {
        success: true,
        overall_valid,
        signature_valid,
        chain_integrity,
        checkpoint_count,
        swf_iterations_per_second: swf_ips,
        attestation_tier: tier_num,
        attestation_tier_label: tier_label,
        unsigned_checkpoints,
        ordinal_gaps,
        warnings: result.warnings,
        checkpoint_flags,
        error_message: None,
    }
    })
}

/// Convert an RFC wire-format `EvidencePacketWire` into the engine's internal `Packet`
/// so it can pass through `full_verify`.
fn wire_to_packet(wire: &EvidencePacketWire) -> Packet {
    let checkpoints: Vec<CheckpointProof> = wire
        .checkpoints
        .iter()
        .map(|cp| {
            let content_hash = hex::encode(&cp.content_hash.digest);
            let prev_hash = hex::encode(&cp.prev_hash.digest);
            let checkpoint_hash = hex::encode(&cp.checkpoint_hash.digest);
            let vdf_input = Some(hex::encode(&cp.process_proof.input));
            let vdf_output = Some(hex::encode(&cp.process_proof.merkle_root));
            let vdf_iterations = Some(cp.process_proof.params.steps);
            let elapsed = if cp.process_proof.claimed_duration > 0 {
                Some(std::time::Duration::from_millis(
                    cp.process_proof.claimed_duration,
                ))
            } else {
                None
            };

            CheckpointProof {
                ordinal: cp.sequence,
                content_hash,
                content_size: cp.char_count,
                timestamp: chrono::DateTime::from_timestamp_millis(
                    i64::try_from(cp.timestamp).unwrap_or(i64::MAX),
                )
                .unwrap_or_default(),
                message: None,
                vdf_input,
                vdf_output,
                vdf_iterations,
                elapsed_time: elapsed,
                previous_hash: prev_hash,
                hash: checkpoint_hash,
                signature: None,
            }
        })
        .collect();

    let last_cp = checkpoints.last();
    let final_hash = last_cp
        .map(|cp| cp.content_hash.clone())
        .unwrap_or_default();
    let final_size = last_cp.map(|cp| cp.content_size).unwrap_or(0);
    let chain_hash = last_cp.map(|cp| cp.hash.clone()).unwrap_or_default();

    let filename = wire
        .document
        .filename
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    Packet {
        version: wire.version as i32,
        exported_at: chrono::DateTime::from_timestamp_millis(
            i64::try_from(wire.created).unwrap_or(i64::MAX),
        )
        .unwrap_or_default(),
        document: DocumentInfo {
            title: filename.clone(),
            path: filename,
            final_hash,
            final_size,
        },
        checkpoints,
        chain_hash,
        ..Default::default()
    }
}
