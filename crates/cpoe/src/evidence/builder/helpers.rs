// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Helper functions for evidence packet construction.

use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};

use crate::declaration;
use crate::error::Error;

use crate::evidence::types::*;

const EVENTS_BINDING_DST: &[u8] = b"cpoe-events-binding-v1";
const EPHEMERAL_CHECKPOINT_DST: &[u8] = b"cpoe-checkpoint-v1";

/// Convert an internal anchor proof to the evidence packet format.
pub fn convert_anchor_proof(proof: &crate::anchors::Proof) -> AnchorProof {
    let provider = format!("{:?}", proof.provider).to_lowercase();
    let timestamp = proof.confirmed_at.unwrap_or(proof.submitted_at);
    AnchorProof {
        provider: provider.clone(),
        provider_name: provider,
        legal_standing: String::new(),
        regions: Vec::new(),
        hash: hex::encode(proof.anchored_hash),
        timestamp,
        status: format!("{:?}", proof.status).to_lowercase(),
        raw_proof: general_purpose::STANDARD.encode(&proof.proof_data),
        verify_url: proof.location.clone(),
    }
}

/// Compute binding hash over secure events.
///
/// Includes event count to prevent truncation attacks.
pub fn compute_events_binding_hash(events: &[crate::store::SecureEvent]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EVENTS_BINDING_DST);
    hasher.update((events.len() as u64).to_be_bytes());
    for e in events {
        hasher.update(e.event_hash);
    }
    hasher.finalize().into()
}

/// A content snapshot from an ephemeral session checkpoint.
#[derive(Debug)]
pub struct EphemeralSnapshot {
    pub timestamp_ns: i64,
    pub content_hash: [u8; 32],
    pub char_count: u64,
    pub message: Option<String>,
}

/// Build an evidence packet from ephemeral session data.
///
/// Constructs a signed declaration and checkpoint chain from in-memory
/// snapshots. The caller provides the signing key and session metadata;
/// this function handles all evidence assembly.
///
/// Note: packets built here lack VDF proofs, jitter bindings, and
/// physical context that the full Builder pipeline provides. The resulting
/// evidence is structurally simpler (Basic strength tier).
pub fn build_ephemeral_packet(
    final_hash_hex: &str,
    statement: &str,
    context_label: &str,
    snapshots: &[EphemeralSnapshot],
    signing_key: &ed25519_dalek::SigningKey,
    jitter_intervals: &[u64],
    keystroke_count: u64,
) -> crate::error::Result<Packet> {
    let final_hash = hex::decode(final_hash_hex)
        .map_err(|e| Error::evidence(format!("invalid final hash: {e}")))?;
    if final_hash.len() != 32 {
        return Err(Error::evidence(format!(
            "final hash must be 32 bytes, got {}",
            final_hash.len()
        )));
    }
    let mut doc_hash = [0u8; 32];
    doc_hash.copy_from_slice(&final_hash[..32]);

    // Ephemeral packets have no checkpoint chain, so use the last snapshot's
    // content_hash as the chain binding for the no-AI declaration. This binds
    // the declaration to the final document state rather than to a checkpoint hash.
    let chain_hash = snapshots
        .last()
        .map(|s| s.content_hash)
        .unwrap_or([0u8; 32]);

    let signed_decl =
        declaration::no_ai_declaration(doc_hash, chain_hash, context_label, statement)
            .sign(signing_key)
            .map_err(|e| Error::evidence(format!("declaration signing failed: {e}")))?;

    let mut checkpoints: Vec<CheckpointProof> = Vec::with_capacity(snapshots.len());
    for (i, snap) in snapshots.iter().enumerate() {
        let prev_hash = if i > 0 {
            checkpoints[i - 1].hash.clone()
        } else {
            hex::encode([0u8; 32])
        };
        // Compute a deterministic checkpoint hash from its fields
        let mut cp_hasher = Sha256::new();
        cp_hasher.update(EPHEMERAL_CHECKPOINT_DST);
        cp_hasher.update((i as u64).to_be_bytes());
        cp_hasher.update(hex::decode(&prev_hash).unwrap_or_else(|e| {
            log::warn!("Invalid prev_hash hex in checkpoint chain: {e}");
            vec![0u8; 32]
        }));
        cp_hasher.update(snap.content_hash);
        cp_hasher.update(snap.char_count.to_be_bytes());
        cp_hasher.update((snap.timestamp_ns.max(0) as u64).to_be_bytes());
        let cp_hash = hex::encode(<[u8; 32]>::from(cp_hasher.finalize()));

        checkpoints.push(CheckpointProof {
            ordinal: i as u64,
            timestamp: chrono::DateTime::from_timestamp_nanos(snap.timestamp_ns),
            content_hash: hex::encode(snap.content_hash),
            content_size: snap.char_count,
            vdf_input: None,
            vdf_output: None,
            vdf_iterations: None,
            elapsed_time: None,
            previous_hash: prev_hash,
            hash: cp_hash,
            message: snap.message.clone(),
            signature: None,
        });
    }

    // Build keystroke evidence from accumulated jitter intervals
    let keystroke_evidence = if !jitter_intervals.is_empty() {
        let started = snapshots.first().map(|s| s.timestamp_ns).unwrap_or(0);
        let ended = snapshots.last().map(|s| s.timestamp_ns).unwrap_or(0);
        let started_at = chrono::DateTime::from_timestamp_nanos(started);
        let ended_at = chrono::DateTime::from_timestamp_nanos(ended);
        let elapsed_ns = crate::utils::ns_elapsed(ended, started);
        let duration_secs =
            crate::utils::ns_to_secs(i64::try_from(elapsed_ns).unwrap_or_else(|_| {
                log::warn!("Elapsed nanoseconds {elapsed_ns} exceeds i64::MAX; clamping");
                i64::MAX
            }));
        let duration = std::time::Duration::from_nanos(elapsed_ns);

        let total_keystrokes = keystroke_count;
        let kpm = if duration_secs > 0.0 {
            (total_keystrokes as f64 / duration_secs) * 60.0
        } else {
            0.0
        };

        // Human typing: typically 30-300 KPM; upper bound 600 KPM allows
        // burst-typing, competitive typists, and keyboard-repeat artifacts.
        let plausible = (1.0..=600.0).contains(&kpm) || total_keystrokes < 10;

        Some(KeystrokeEvidence {
            session_id: crate::utils::short_hex_id(&doc_hash),
            started_at,
            ended_at,
            duration,
            total_keystrokes,
            total_samples: i32::try_from(jitter_intervals.len()).unwrap_or(i32::MAX),
            keystrokes_per_minute: kpm,
            unique_doc_states: i32::try_from(snapshots.len()).unwrap_or(i32::MAX),
            chain_valid: !checkpoints.is_empty(),
            plausible_human_rate: plausible,
            samples: vec![],
            typing_samples: Vec::new(),
            phys_ratio: None,
        })
    } else {
        None
    };

    // AUD-032: Generate claims and limitations for ephemeral packets
    let mut claims = vec![Claim {
        claim_type: ClaimType::ChainIntegrity,
        description: "Content states form an unbroken cryptographic chain".to_string(),
        confidence: "cryptographic".to_string(),
    }];
    if keystroke_evidence
        .as_ref()
        .is_some_and(|k| k.plausible_human_rate)
    {
        claims.push(Claim {
            claim_type: ClaimType::KeystrokesVerified,
            description: "Keystroke timing consistent with human input".to_string(),
            confidence: "statistical".to_string(),
        });
    }
    claims.push(Claim {
        claim_type: ClaimType::ProcessDeclared,
        description: "Author declaration recorded and signed".to_string(),
        confidence: "cryptographic".to_string(),
    });

    let mut limitations = vec![
        "No VDF time-binding proofs (ephemeral session)".to_string(),
        "No hardware attestation available".to_string(),
    ];
    if keystroke_evidence.is_none() {
        limitations.push("No keystroke timing data collected".to_string());
    }

    let packet = Packet {
        document: DocumentInfo {
            title: context_label.to_string(),
            path: format!("ephemeral://{}", crate::utils::short_hex_id(&doc_hash)),
            final_hash: final_hash_hex.to_string(),
            final_size: snapshots.last().map(|s| s.char_count).unwrap_or(0),
        },
        checkpoints,
        chain_hash: hex::encode(chain_hash),
        declaration: Some(signed_decl),
        keystroke: keystroke_evidence,
        claims,
        limitations,
        ..Default::default()
    };

    Ok(packet)
}
