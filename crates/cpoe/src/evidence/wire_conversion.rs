// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Conversion from internal checkpoint chain to CDDL-conformant wire types.
//!
//! Bridges `checkpoint::Chain` → `EvidencePacketWire` for spec-compliant
//! CBOR export per draft-condrey-rats-pop.

use sha2::{Digest, Sha256};

use crate::checkpoint::{Chain, Checkpoint};
use crate::error::{Error, Result};
use crate::evidence::types::{CHECKPOINT_ID_DST, PACKET_ID_DST};
use crate::keyhierarchy::types::CheckpointSignature;
use authorproof_protocol::rfc::wire_types::checkpoint::CheckpointWire;
use authorproof_protocol::rfc::wire_types::components::{
    DocumentRef, EditDelta, JitterBindingWire, MerkleProof, PhysicalState, ProcessProof,
    ProofParams,
};
use authorproof_protocol::rfc::wire_types::enums::{AttestationTier, ContentTier, ProofAlgorithm};
use authorproof_protocol::rfc::wire_types::hash::HashValue;
use authorproof_protocol::rfc::wire_types::packet::EvidencePacketWire;

const PROFILE_URI: &str = "urn:ietf:params:rats:eat:profile:pop:1.0";

/// Minimum jitter quantization per draft-condrey-rats-pop §11.4 (privacy).
const JITTER_QUANTIZATION_MS: u64 = 5;

/// Convert a checkpoint chain to a spec-conformant `EvidencePacketWire`.
///
/// Each call mixes a fresh 8-byte random salt into the packet and checkpoint
/// ID hashes so that re-exporting the same chain produces unique IDs and
/// prevents accidental cross-export collisions.
pub fn chain_to_wire(chain: &Chain) -> Result<EvidencePacketWire> {
    chain_to_wire_with_signatures(chain, &[])
}

/// Convert a checkpoint chain to a spec-conformant `EvidencePacketWire`,
/// including Lamport one-shot signatures from the key hierarchy when available.
pub fn chain_to_wire_with_signatures(
    chain: &Chain,
    checkpoint_sigs: &[CheckpointSignature],
) -> Result<EvidencePacketWire> {
    // Random salt so each export produces unique packet/checkpoint IDs even
    // when re-exporting an identical chain.
    let export_nonce = rand::random::<[u8; 8]>();

    // Single pass: detect jitter presence and physical-state coverage for tier selection
    let (has_jitter, all_have_physical) =
        chain
            .checkpoints
            .iter()
            .fold((false, true), |(any_jitter, all_phys), cp| {
                let has_j = cp.rfc_jitter.is_some();
                let has_p = cp
                    .jitter_binding
                    .as_ref()
                    .is_some_and(|jb| jb.physics_seed.is_some());
                (any_jitter || has_j, all_phys && has_p)
            });
    // ENHANCED/MAXIMUM tiers use entangled algorithm 21 per §entangled-mode-requirement
    let use_entangled = has_jitter;

    let sig_by_ordinal: std::collections::HashMap<u64, &CheckpointSignature> =
        checkpoint_sigs.iter().map(|s| (s.ordinal, s)).collect();

    let checkpoints: Vec<CheckpointWire> = chain
        .checkpoints
        .iter()
        .map(|cp| {
            let lamport = sig_by_ordinal.get(&cp.ordinal).copied();
            checkpoint_to_wire(cp, use_entangled, &export_nonce, lamport)
        })
        .collect::<Result<Vec<_>>>()?;

    let last_cp = chain.checkpoints.last();
    let content_hash = last_cp.map(|cp| cp.content_hash).unwrap_or([0u8; 32]);
    let content_size = last_cp.map(|cp| cp.content_size).unwrap_or(0);

    let filename = std::path::Path::new(&chain.metadata.document_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string());

    let document = DocumentRef {
        content_hash: HashValue::try_sha256(content_hash.to_vec()).map_err(Error::crypto)?,
        filename,
        byte_length: content_size,
        char_count: content_size, // byte_length used as proxy when char count unavailable
        salt_mode: None,
        salt_commitment: None,
    };

    // Derive attestation tier from hardware evidence on checkpoints
    let has_tpm = chain.checkpoints.iter().any(|cp| cp.tpm_binding.is_some());
    let attestation_tier = Some(if has_tpm {
        AttestationTier::HardwareBound
    } else {
        AttestationTier::SoftwareOnly
    });
    // ENHANCED = jitter binding; MAXIMUM = jitter + physical state on all checkpoints
    let is_maximum_tier = has_jitter && all_have_physical;
    let content_tier = if is_maximum_tier {
        Some(ContentTier::Maximum)
    } else if has_jitter {
        Some(ContentTier::Enhanced)
    } else {
        Some(ContentTier::Core)
    };

    Ok(EvidencePacketWire {
        version: 1,
        profile_uri: PROFILE_URI.to_string(),
        packet_id: {
            let mut h = Sha256::new();
            h.update(PACKET_ID_DST);
            h.update(content_hash);
            h.update(export_nonce);
            let d = h.finalize();
            let mut id = [0u8; 16];
            id.copy_from_slice(&d[..16]);
            id
        },
        created: u64::try_from(chrono::Utc::now().timestamp_millis().max(0)).unwrap_or(0),
        document,
        checkpoints,
        attestation_tier,
        limitations: None,
        profile: None,
        presence_challenges: None,
        channel_binding: None,
        signing_public_key: None,
        content_tier,
        previous_packet_ref: None,
        packet_sequence: None,
        physical_liveness: None,
        baseline_verification: None,
        author_did: {
            #[cfg(feature = "did-webvh")]
            {
                crate::identity::did_webvh::load_active_did()
                    .map_err(|e| log::debug!("DID not available for wire conversion: {e}"))
                    .ok()
            }
            #[cfg(not(feature = "did-webvh"))]
            {
                None
            }
        },
        document_content: None,
        document_filename: None,
        project_files: None,
        session_counter: None,
    })
}

fn checkpoint_to_wire(
    cp: &Checkpoint,
    use_entangled: bool,
    export_nonce: &[u8; 8],
    lamport: Option<&CheckpointSignature>,
) -> Result<CheckpointWire> {
    #[cfg(feature = "posme")]
    let posme_algorithm = if let Some(ref posme_bytes) = cp.posme_swf {
        match ciborium::from_reader::<posme::PosmeProof, _>(posme_bytes.as_slice()) {
            Ok(proof) => Some(if proof.proof_algorithm == 31 {
                ProofAlgorithm::SwfPosmeEntangled
            } else {
                ProofAlgorithm::SwfPosme
            }),
            Err(_) => Some(ProofAlgorithm::SwfPosme),
        }
    } else {
        None
    };
    #[cfg(not(feature = "posme"))]
    let posme_algorithm: Option<ProofAlgorithm> = None;

    let process_proof = if let Some(swf) = &cp.argon2_swf {
        // §entangled-mode-requirement: ENHANCED/MAXIMUM → algorithm 21
        let algorithm = if use_entangled {
            ProofAlgorithm::SwfArgon2idEntangled
        } else {
            ProofAlgorithm::SwfArgon2id
        };
        ProcessProof {
            algorithm,
            params: ProofParams {
                time_cost: swf.params.time_cost as u64,
                memory_cost: swf.params.memory_cost as u64,
                parallelism: swf.params.parallelism as u64,
                steps: swf.params.iterations,
                waypoint_interval: None,
                waypoint_memory: None,
                reads_per_step: None,
                challenges: None,
                recursion_depth: None,
            },
            input: swf.input.to_vec(),
            merkle_root: swf.merkle_root.to_vec(),
            sampled_proofs: swf
                .sampled_proofs
                .iter()
                .map(|sp| MerkleProof {
                    leaf_index: sp.leaf_index,
                    sibling_path: sp
                        .sibling_path
                        .iter()
                        .map(|s| serde_bytes::ByteBuf::from(s.to_vec()))
                        .collect(),
                    leaf_value: sp.leaf_value.to_vec(),
                })
                .collect(),
            claimed_duration: u64::try_from(swf.claimed_duration.as_millis()).unwrap_or(u64::MAX),
        }
    } else if let Some(vdf) = &cp.vdf {
        ProcessProof {
            algorithm: ProofAlgorithm::SwfSha256,
            params: ProofParams {
                time_cost: 1,
                memory_cost: 0,
                parallelism: 1,
                steps: vdf.iterations,
                waypoint_interval: None,
                waypoint_memory: None,
                reads_per_step: None,
                challenges: None,
                recursion_depth: None,
            },
            input: vdf.input.to_vec(),
            merkle_root: vdf.output.to_vec(),
            sampled_proofs: vec![],
            claimed_duration: u64::try_from(vdf.duration.as_millis()).unwrap_or(u64::MAX),
        }
    } else {
        ProcessProof {
            algorithm: ProofAlgorithm::SwfSha256,
            params: ProofParams {
                time_cost: 0,
                memory_cost: 0,
                parallelism: 0,
                steps: 0,
                waypoint_interval: None,
                waypoint_memory: None,
                reads_per_step: None,
                challenges: None,
                recursion_depth: None,
            },
            input: vec![0u8; 32],
            merkle_root: vec![0u8; 32],
            sampled_proofs: vec![],
            claimed_duration: 0,
        }
    };

    let mut process_proof = process_proof;
    if let Some(alg) = posme_algorithm {
        process_proof.algorithm = alg;
    }

    let merkle_root = &process_proof.merkle_root;
    let swf_input = &process_proof.input;
    let has_merkle_root = merkle_root.len() >= 32 && merkle_root.iter().any(|&b| b != 0);

    let (jitter_binding_wire, physical_state_wire) = if let Some(rfc_jitter) = &cp.rfc_jitter {
        // §11.4: quantize intervals to limit timing side-channel leakage
        let intervals: Vec<u64> = rfc_jitter
            .raw_intervals
            .as_ref()
            .map(|ri| {
                ri.intervals
                    .iter()
                    .map(|&v| {
                        let ms = v as u64;
                        ((ms + JITTER_QUANTIZATION_MS / 2) / JITTER_QUANTIZATION_MS)
                            * JITTER_QUANTIZATION_MS
                    })
                    .collect()
            })
            .unwrap_or_default();

        let entropy_estimate = if rfc_jitter.summary.entropy_bits.is_finite()
            && rfc_jitter.summary.entropy_bits >= 0.0
        {
            (rfc_jitter.summary.entropy_bits * 100.0).min(u64::MAX as f64) as u64
        } else {
            0
        };

        let jitter_seal = if has_merkle_root {
            let intervals_cbor =
                authorproof_protocol::codec::cbor::encode(&intervals).map_err(|e| {
                    Error::evidence(format!("CBOR encode intervals for jitter seal: {e}"))
                })?;
            crate::crypto::compute_jitter_seal(merkle_root, swf_input, &intervals_cbor)
        } else {
            vec![0u8; 32]
        };

        let jb_wire = JitterBindingWire {
            intervals,
            entropy_estimate,
            jitter_seal,
        };

        let ps_wire = cp.jitter_binding.as_ref().and_then(|jb| {
            jb.physics_seed.map(|seed| PhysicalState {
                thermal: vec![],
                entropy_delta: 0,
                kernel_commitment: Some(seed),
                inertial_samples: None,
            })
        });

        (Some(jb_wire), ps_wire)
    } else {
        (None, None)
    };

    let entangled_mac = if let (true, Some(jb)) = (has_merkle_root, jitter_binding_wire.as_ref()) {
        match authorproof_protocol::codec::cbor::encode(jb) {
            Ok(jb_cbor) => {
                let ps_cbor = match physical_state_wire.as_ref() {
                    Some(ps) => authorproof_protocol::codec::cbor::encode(ps).map_err(|e| {
                        Error::evidence(format!(
                            "CBOR encode physical-state for entangled MAC: {e}"
                        ))
                    })?,
                    None => vec![],
                };
                Some(crate::crypto::compute_entangled_mac(
                    merkle_root,
                    swf_input,
                    &cp.previous_hash,
                    &cp.content_hash,
                    &jb_cbor,
                    &ps_cbor,
                ))
            }
            Err(e) => {
                log::error!(
                    "CBOR encode jitter-binding for entangled MAC failed: {e} — skipping MAC"
                );
                None
            }
        }
    } else {
        None
    };

    let mut wire = CheckpointWire {
        sequence: cp.ordinal,
        checkpoint_id: {
            let mut h = Sha256::new();
            h.update(CHECKPOINT_ID_DST);
            h.update(cp.content_hash);
            h.update(cp.ordinal.to_le_bytes());
            h.update(export_nonce);
            let d = h.finalize();
            let mut id = [0u8; 16];
            id.copy_from_slice(&d[..16]);
            id
        },
        timestamp: u64::try_from(cp.timestamp.timestamp_millis().max(0)).unwrap_or(0),
        content_hash: HashValue::try_sha256(cp.content_hash.to_vec()).map_err(Error::crypto)?,
        char_count: cp.content_size,
        // Placeholder: per-checkpoint edit deltas are not tracked in the
        // internal evidence model yet. Populated with zeros until the
        // checkpoint chain records incremental edit operations.
        delta: EditDelta {
            chars_added: 0,
            chars_deleted: 0,
            op_count: 0,
            positions: None,
            edit_graph_hash: None,
            cursor_trajectory_histogram: None,
            revision_depth_histogram: None,
            pause_duration_histogram: None,
            metric_binding_hash: None,
        },
        prev_hash: HashValue::try_sha256(cp.previous_hash.to_vec()).map_err(Error::crypto)?,
        checkpoint_hash: HashValue::zero_sha256(), // overwritten by compute_hash() below
        process_proof,
        jitter_binding: jitter_binding_wire,
        physical_state: physical_state_wire,
        entangled_mac,
        receipts: None,
        active_probes: None,
        hat_proof: None,
        beacon_anchor: None,
        verifier_nonce: None,
        lamport_signature: lamport.and_then(|s| s.lamport_signature.clone()),
        lamport_pubkey_fingerprint: lamport.and_then(|s| s.lamport_pubkey_fingerprint.clone()),
        posme_proof: cp.posme_swf.clone(),
    };
    // SHA-256(CBOR(checkpoint \ {8})) per spec
    wire.checkpoint_hash = wire.compute_hash().map_err(Error::crypto)?;
    Ok(wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyhierarchy::types::CheckpointSignature;

    fn test_params() -> crate::vdf::Parameters {
        crate::vdf::Parameters {
            iterations_per_second: 1000,
            min_iterations: 10,
            max_iterations: 100_000,
        }
    }

    fn test_chain_with_checkpoints(path: &std::path::Path) -> Chain {
        let mut chain = Chain::new(path, test_params())
            .expect("create chain")
            .with_signature_policy(crate::checkpoint::SignaturePolicy::Optional);
        chain.commit(Some("first".to_string())).expect("commit 1");
        chain.commit(Some("second".to_string())).expect("commit 2");
        chain.commit(Some("third".to_string())).expect("commit 3");
        chain
    }

    #[test]
    fn test_chain_to_wire_with_lamport_signatures() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello").expect("write");
        let chain = test_chain_with_checkpoints(&path);

        let lamport_sig = vec![0xAB; 8192];
        let lamport_fp = vec![0xCD; 8];

        let sigs = vec![
            CheckpointSignature {
                ordinal: 0,
                public_key: [0u8; 32],
                signature: [0u8; 64],
                checkpoint_hash: [0u8; 32],
                counter_value: None,
                counter_delta: None,
                lamport_signature: Some(lamport_sig.clone()),
                lamport_pubkey_fingerprint: Some(lamport_fp.clone()),
                lamport_public_key: None,
            },
            CheckpointSignature {
                ordinal: 2,
                public_key: [0u8; 32],
                signature: [0u8; 64],
                checkpoint_hash: [0u8; 32],
                counter_value: None,
                counter_delta: None,
                lamport_signature: Some(lamport_sig.clone()),
                lamport_pubkey_fingerprint: Some(lamport_fp.clone()),
                lamport_public_key: None,
            },
        ];

        let packet = chain_to_wire_with_signatures(&chain, &sigs).expect("chain_to_wire");
        assert_eq!(packet.checkpoints.len(), 3);

        // Ordinal 0 has a matching signature
        assert_eq!(
            packet.checkpoints[0].lamport_signature.as_ref().unwrap(),
            &lamport_sig
        );
        assert_eq!(
            packet.checkpoints[0]
                .lamport_pubkey_fingerprint
                .as_ref()
                .unwrap(),
            &lamport_fp
        );

        // Ordinal 1 has no matching signature
        assert!(packet.checkpoints[1].lamport_signature.is_none());
        assert!(packet.checkpoints[1].lamport_pubkey_fingerprint.is_none());

        // Ordinal 2 has a matching signature
        assert!(packet.checkpoints[2].lamport_signature.is_some());
    }

    #[test]
    fn test_chain_to_wire_without_signatures() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello").expect("write");
        let chain = test_chain_with_checkpoints(&path);

        let packet = chain_to_wire(&chain).expect("chain_to_wire");
        assert_eq!(packet.checkpoints.len(), 3);
        for cp in &packet.checkpoints {
            assert!(cp.lamport_signature.is_none());
            assert!(cp.lamport_pubkey_fingerprint.is_none());
        }
    }
}
