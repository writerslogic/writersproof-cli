// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Seal verification and duration/key-provenance checks.

use base64::Engine;
use ed25519_dalek::Verifier;

use crate::evidence::Packet;
use crate::vdf;

use super::{
    DurationCheck, KeyProvenanceCheck, SealVerification, SWF_DURATION_RATIO_MAX,
    SWF_DURATION_RATIO_MIN,
};

/// Phase 4: Structural seal verification.
///
/// NOTE: Full HMAC re-derivation requires the session key which is not available
/// during third-party verification. This check validates structural presence only.
/// Full seal verification is performed by the original author's engine which has
/// access to the session key material.
pub(super) fn verify_seals_structural(
    packet: &Packet,
    warnings: &mut Vec<String>,
) -> SealVerification {
    let mut jitter_tag_present: Option<bool> = None;
    // NOTE: Entangled binding verification requires session key material not available
    // during third-party verification. This field remains None.
    let entangled_binding_valid: Option<bool> = None;
    let mut checkpoints_checked = 0;

    // Check declaration-level jitter seal
    if let Some(decl) = &packet.declaration {
        if let Some(ref sealed) = decl.jitter_sealed {
            // The jitter seal in the declaration binds the declaration to the jitter session.
            // Verify the jitter hash is non-zero.
            if sealed.jitter_hash == [0u8; 32] {
                warnings.push("Declaration jitter seal has zero hash".to_string());
                jitter_tag_present = Some(false);
            } else {
                jitter_tag_present = Some(true);
                checkpoints_checked += 1;
            }
        }
    }

    // Check checkpoint-level bindings
    for cp in &packet.checkpoints {
        if let (Some(vdf_in), Some(vdf_out)) = (&cp.vdf_input, &cp.vdf_output) {
            // Verify VDF input/output are well-formed 32-byte hex
            let in_ok = match hex::decode(vdf_in) {
                Ok(b) => b.len() == 32,
                Err(e) => {
                    log::warn!(
                        "Checkpoint {} VDF input hex decode failed: {e}",
                        cp.ordinal
                    );
                    false
                }
            };
            let out_ok = match hex::decode(vdf_out) {
                Ok(b) => b.len() == 32,
                Err(e) => {
                    log::warn!(
                        "Checkpoint {} VDF output hex decode failed: {e}",
                        cp.ordinal
                    );
                    false
                }
            };

            if !in_ok || !out_ok {
                warnings.push(format!(
                    "Checkpoint {} has malformed VDF input/output",
                    cp.ordinal
                ));
            }
            checkpoints_checked += 1;
        }
    }

    // If packet has jitter_binding at the top level, validate its presence
    if let Some(ref jb) = packet.jitter_binding {
        if jb.entropy_commitment.hash == [0u8; 32] {
            warnings.push("Jitter binding has zero entropy commitment hash".to_string());
            jitter_tag_present = Some(false);
        } else if jitter_tag_present.is_none() {
            jitter_tag_present = Some(true);
        }
    }

    SealVerification {
        jitter_tag_present,
        entangled_binding_valid,
        checkpoints_checked,
    }
}

/// Phase 5: Cross-check VDF duration against wall-clock timestamps.
///
/// Duration comparison is approximate: it measures the span from the first
/// to the last checkpoint timestamp, which may under-count actual authoring
/// time (e.g., pauses before the first checkpoint or after the last).
pub(super) fn verify_duration(
    packet: &Packet,
    vdf_params: &vdf::Parameters,
    warnings: &mut Vec<String>,
) -> DurationCheck {
    if vdf_params.iterations_per_second == 0 {
        warnings.push(
            "VDF iterations_per_second is zero — duration check cannot be performed".to_string(),
        );
        return DurationCheck {
            computed_min_seconds: 0.0,
            claimed_seconds: 0.0,
            ratio: 0.0,
            plausible: false,
        };
    }

    let total_iterations: u64 = packet
        .checkpoints
        .iter()
        .filter_map(|cp| cp.vdf_iterations)
        .sum();

    // Compute minimum wall time from iterations.
    // The iterations_per_second == 0 case is already handled by the early return above,
    // so no inner guard is needed here.
    let computed_min_seconds = total_iterations as f64 / vdf_params.iterations_per_second as f64;

    // Claimed elapsed time from min to max checkpoint timestamp
    let claimed_seconds = if packet.checkpoints.len() >= 2 {
        let min_ts = packet.checkpoints.iter().map(|cp| cp.timestamp).min();
        let max_ts = packet.checkpoints.iter().map(|cp| cp.timestamp).max();
        match (min_ts, max_ts) {
            (Some(min), Some(max)) => (max - min).num_milliseconds().max(0) as f64 / 1000.0,
            _ => 0.0,
        }
    } else {
        0.0
    };

    let ratio = if computed_min_seconds > 0.0 {
        claimed_seconds / computed_min_seconds
    } else {
        // No VDF iteration data; ratio is meaningless. Use 0.0 to avoid a false
        // "clean" 1.0 that would hide the absence of proof data.
        0.0
    };

    let plausible = if computed_min_seconds > 0.0 {
        (SWF_DURATION_RATIO_MIN..=SWF_DURATION_RATIO_MAX).contains(&ratio)
    } else if !packet.checkpoints.is_empty() {
        // One or more checkpoints exist but none carried VDF iteration data.
        // A packet with checkpoints must have VDF proofs to be considered plausible.
        warnings.push("No VDF proof data found".to_string());
        false
    } else {
        // Zero-checkpoint packet (e.g., a bare structural shell): no proof is expected.
        true
    };

    // Only emit ratio-based warnings when we actually have VDF data to compare against.
    if !plausible && computed_min_seconds > 0.0 {
        if ratio < SWF_DURATION_RATIO_MIN {
            warnings.push(format!(
                "Duration implausible: claimed {:.1}s but VDF requires minimum {:.1}s (ratio {:.2}x)",
                claimed_seconds, computed_min_seconds, ratio
            ));
        } else {
            warnings.push(format!(
                "Duration suspicious: claimed {:.1}s vs VDF minimum {:.1}s (ratio {:.2}x, max {:.1}x)",
                claimed_seconds, computed_min_seconds, ratio, SWF_DURATION_RATIO_MAX
            ));
        }
    }

    DurationCheck {
        computed_min_seconds,
        claimed_seconds,
        ratio,
        plausible,
    }
}

/// Phase 6: Validate key provenance (hierarchy consistency, signing key, ratchet).
pub(super) fn verify_key_provenance(
    packet: &Packet,
    warnings: &mut Vec<String>,
) -> KeyProvenanceCheck {
    let mut hierarchy_consistent: Option<bool> = None;
    let mut signing_key_consistent = true;
    let mut ratchet_monotonic = true;

    if let Some(ref kh) = packet.key_hierarchy {
        // Verify master → session certificate chain
        let master_bytes_opt = hex::decode(&kh.master_public_key)
            .ok()
            .filter(|b| b.len() == 32);
        let session_bytes_opt = hex::decode(&kh.session_public_key)
            .ok()
            .filter(|b| b.len() == 32);
        let cert_bytes_opt = base64::engine::general_purpose::STANDARD
            .decode(&kh.session_certificate)
            .ok()
            .filter(|b| b.len() == 64);
        let master_ok = master_bytes_opt.is_some();
        let session_ok = session_bytes_opt.is_some();
        let cert_ok = cert_bytes_opt.is_some();

        if !master_ok || !session_ok || !cert_ok {
            warnings.push("Key hierarchy has invalid key/certificate lengths".to_string());
            hierarchy_consistent = Some(false);
        } else if let Some(ref doc_hash_hex) = kh.session_document_hash {
            // Verify the certificate signature only when document hash is available.
            // Use already-decoded bytes from the length checks above.
            let master_bytes = master_bytes_opt.expect("master_ok is true");
            let session_bytes = session_bytes_opt.expect("session_ok is true");
            let session_id_result = hex::decode(&kh.session_id).ok().filter(|b| b.len() == 32);
            let doc_hash_result = hex::decode(doc_hash_hex).ok().filter(|b| b.len() == 32);
            match (session_id_result, doc_hash_result) {
                (Some(sid_bytes), Some(dh_bytes)) => {
                    let mut session_id_arr = [0u8; 32];
                    let mut doc_hash_arr = [0u8; 32];
                    session_id_arr.copy_from_slice(&sid_bytes);
                    doc_hash_arr.copy_from_slice(&dh_bytes);
                    match crate::keyhierarchy::verification::validate_cert_byte_lengths(
                        &master_bytes,
                        &session_bytes,
                        cert_bytes_opt.as_deref().expect("cert_ok is true"),
                        &session_id_arr,
                        kh.session_started,
                        &doc_hash_arr,
                    ) {
                        Ok(()) => hierarchy_consistent = Some(true),
                        Err(e) => {
                            warnings.push(format!("Key hierarchy certificate invalid: {}", e));
                            hierarchy_consistent = Some(false);
                        }
                    }
                }
                _ => {
                    warnings.push(
                        "Key hierarchy session_id or session_document_hash has invalid length"
                            .to_string(),
                    );
                    hierarchy_consistent = Some(false);
                }
            }
        } else {
            // No document hash available; skip signature verification, only length checks passed.
            hierarchy_consistent = Some(true);
        }

        // Single pass: check ratchet indices are strictly monotonic, non-negative,
        // reference valid ratchet keys, and cryptographically verify Ed25519 signatures.
        let mut prev_index = -1i64;
        for sig in &kh.checkpoint_signatures {
            let idx = sig.ratchet_index as i64;
            if idx < 0 {
                ratchet_monotonic = false;
                signing_key_consistent = false;
                warnings.push(format!(
                    "Ratchet index negative ({}) at checkpoint {}",
                    idx, sig.ordinal
                ));
                continue;
            }
            if idx <= prev_index {
                ratchet_monotonic = false;
                warnings.push(format!(
                    "Ratchet index non-monotonic at checkpoint {}",
                    sig.ordinal
                ));
                continue;
            }
            prev_index = idx;

            let uidx = sig.ratchet_index as usize;
            if uidx >= kh.ratchet_public_keys.len() {
                signing_key_consistent = false;
                warnings.push(format!(
                    "Checkpoint {} references ratchet index {} but only {} keys exist",
                    sig.ordinal,
                    uidx,
                    kh.ratchet_public_keys.len()
                ));
                continue;
            }

            // AUD-026: Cryptographically verify Ed25519 checkpoint signatures.
            // Decode the ratchet public key and signature from hex, then verify.
            let pubkey = match crate::utils::crypto_types::Ed25519Pubkey::from_hex(
                &kh.ratchet_public_keys[uidx],
            ) {
                Ok(pk) => pk,
                Err(_) => {
                    signing_key_consistent = false;
                    warnings.push(format!(
                        "Checkpoint {}: ratchet key {} has invalid hex/length",
                        sig.ordinal, uidx
                    ));
                    continue;
                }
            };
            let ed_sig = match crate::utils::crypto_types::Ed25519Sig::from_hex(&sig.signature) {
                Ok(s) => s,
                Err(_) => {
                    signing_key_consistent = false;
                    warnings.push(format!(
                        "Checkpoint {}: signature has invalid hex/length",
                        sig.ordinal
                    ));
                    continue;
                }
            };
            let hash_bytes = match hex::decode(&sig.checkpoint_hash) {
                Ok(b) => b,
                Err(_) => {
                    signing_key_consistent = false;
                    warnings.push(format!(
                        "Checkpoint {}: checkpoint_hash has invalid hex",
                        sig.ordinal
                    ));
                    continue;
                }
            };

            match pubkey.to_verifying_key() {
                Ok(vk) => {
                    if vk.verify(&hash_bytes, &ed_sig.to_signature()).is_err() {
                        signing_key_consistent = false;
                        warnings.push(format!(
                            "Checkpoint {}: Ed25519 signature verification FAILED",
                            sig.ordinal
                        ));
                    }
                }
                Err(_) => {
                    signing_key_consistent = false;
                    warnings.push(format!(
                        "Checkpoint {}: invalid Ed25519 public key",
                        sig.ordinal
                    ));
                }
            }
        }
    } else {
        warnings.push("No key hierarchy present".to_string());
    }

    // Also check packet-level signing key consistency
    if let Some(ref pubkey) = packet.signing_public_key {
        if let Some(ref kh) = packet.key_hierarchy {
            // The packet signing key should match one of the ratchet keys
            let pubkey_hex = hex::encode(pubkey);
            let found = kh
                .ratchet_public_keys
                .iter()
                .any(|k| k.eq_ignore_ascii_case(&pubkey_hex))
                || kh.session_public_key.eq_ignore_ascii_case(&pubkey_hex);
            if !found {
                warnings
                    .push("Packet signing key does not match any key in the hierarchy".to_string());
                signing_key_consistent = false;
            }
        }
    }

    KeyProvenanceCheck {
        hierarchy_consistent,
        signing_key_consistent,
        ratchet_monotonic,
    }
}
