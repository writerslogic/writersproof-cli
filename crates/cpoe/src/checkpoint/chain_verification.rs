// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Verification logic for checkpoint chains.

use crate::error::{Error, Result};
use crate::vdf;

use super::chain::Chain;
use super::chain_helpers::{genesis_prev_hash, mix_physics_seed};
use super::types::*;

/// Verify a single checkpoint's VDF proof against its expected input.
///
/// Computes the expected VDF input from the checkpoint's fields and the previous
/// checkpoint's VDF output (for entangled mode), then verifies the proof.
fn verify_single_checkpoint_vdf(
    i: usize,
    checkpoint: &Checkpoint,
    prev_vdf_output: Option<[u8; 32]>,
    mode: EntanglementMode,
) -> Result<()> {
    let vdf_proof = match checkpoint.vdf.as_ref() {
        Some(v) => v,
        None => return Ok(()),
    };

    let expected_input = compute_expected_vdf_input(i, checkpoint, prev_vdf_output, mode)?;

    if vdf_proof.input != expected_input {
        return Err(Error::checkpoint(format!(
            "checkpoint {i}: VDF input mismatch"
        )));
    }
    if !vdf::verify(vdf_proof) {
        return Err(Error::checkpoint(format!(
            "checkpoint {i}: VDF verification failed"
        )));
    }
    Ok(())
}

/// Compute the expected VDF input for a checkpoint given its mode and predecessors.
fn compute_expected_vdf_input(
    i: usize,
    checkpoint: &Checkpoint,
    prev_vdf_output: Option<[u8; 32]>,
    mode: EntanglementMode,
) -> Result<[u8; 32]> {
    match mode {
        EntanglementMode::Legacy => Ok(vdf::chain_input(
            checkpoint.content_hash,
            checkpoint.previous_hash,
            checkpoint.ordinal,
        )),
        EntanglementMode::Entangled => {
            let previous_output = prev_vdf_output.unwrap_or([0u8; 32]);

            let jitter_binding = checkpoint.jitter_binding.as_ref().ok_or_else(|| {
                Error::checkpoint(format!(
                    "checkpoint {i}: missing jitter binding (required for entangled mode)"
                ))
            })?;

            let base_input = vdf::chain_input_entangled(
                previous_output,
                jitter_binding.jitter_hash,
                checkpoint.content_hash,
                checkpoint.ordinal,
            );
            Ok(mix_physics_seed(base_input, jitter_binding.physics_seed))
        }
    }
}

/// Extract the VDF output from a checkpoint's proof, returning an error if absent.
fn require_prev_vdf_output(checkpoints: &[Checkpoint], i: usize) -> Result<[u8; 32]> {
    match checkpoints[i - 1].vdf.as_ref() {
        Some(v) => Ok(v.output),
        None => Err(Error::checkpoint(format!(
            "checkpoint {i}: previous checkpoint missing VDF (required for entangled chain)"
        ))),
    }
}

impl Chain {
    /// Verify the chain, returning `Err` on failure.
    pub fn verify(&self) -> Result<()> {
        let report = self.verify_detailed();
        if report.valid {
            Ok(())
        } else if report.errors.is_empty() {
            Err(Error::checkpoint("verification failed"))
        } else {
            Err(Error::checkpoint(report.errors.join("; ")))
        }
    }

    /// Lightweight hash-chain check (no VDF reverification).
    ///
    /// Genesis checkpoint: accepts both legacy all-zeros `previous_hash` and
    /// spec-correct `H(document-ref)` for backward compatibility with chains
    /// created before the genesis hash computation was standardized.
    pub fn verify_hash_chain(&self) -> Result<()> {
        for (i, cp) in self.checkpoints.iter().enumerate() {
            if cp.compute_hash() != cp.hash {
                return Err(Error::checkpoint(format!(
                    "checkpoint {i}: computed hash does not match stored hash"
                )));
            }
            if i > 0 {
                if cp.previous_hash != self.checkpoints[i - 1].hash {
                    return Err(Error::checkpoint(format!(
                        "checkpoint {i}: previous_hash does not match checkpoint {}'s hash",
                        i - 1
                    )));
                }
            } else {
                let is_spec_genesis = genesis_prev_hash(
                    cp.content_hash,
                    cp.content_size,
                    &self.metadata.document_path,
                    None,
                )
                .map(|h| cp.previous_hash == h)
                .unwrap_or(false);
                if !is_spec_genesis {
                    return Err(Error::checkpoint(
                        "checkpoint 0: invalid genesis previous_hash",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Verify the chain and return a detailed report with warnings and failures.
    ///
    /// This performs structural verification only: hash linkage, ordinal sequence,
    /// genesis prev-hash, and timestamp sanity. Cryptographic signature verification
    /// of individual checkpoints is deferred to the caller (see `unsigned_checkpoints`
    /// in the returned report for checkpoints that lack signatures).
    pub fn verify_detailed(&self) -> VerificationReport {
        let mut report = VerificationReport::new();

        for (i, checkpoint) in self.checkpoints.iter().enumerate() {
            if let Err(e) = checkpoint.validate_timestamp() {
                report.fail(format!("checkpoint {i}: {e}"));
                return report;
            }

            // H-002: Non-monotonic timestamps indicate clock manipulation or
            // system clock regression. Allow up to 1 second of drift tolerance
            // for NTP corrections; reject larger regressions as evidence of
            // backdating or tampering.
            if i > 0 {
                let prev_ts = self.checkpoints[i - 1].timestamp;
                if checkpoint.timestamp < prev_ts {
                    let drift = prev_ts
                        .signed_duration_since(checkpoint.timestamp)
                        .num_seconds();
                    if drift > 1 {
                        report.fail(format!(
                            "checkpoint {i}: timestamp backdated by {drift}s \
                             (before previous checkpoint)"
                        ));
                        return report;
                    }
                    report.clock_tolerance_violations.push((i, drift));
                    report
                        .warnings
                        .push(format!("checkpoint {i}: minor clock drift ({drift}s)"));
                }
            }

            if checkpoint.compute_hash() != checkpoint.hash {
                report.fail(format!("checkpoint {i}: hash mismatch"));
                return report;
            }

            if checkpoint.ordinal != i as u64 {
                report.ordinal_gaps.push((i as u64, checkpoint.ordinal));
                report.fail(format!(
                    "checkpoint {i}: ordinal gap (expected {i}, got {})",
                    checkpoint.ordinal
                ));
                return report;
            }

            if i > 0 {
                if checkpoint.previous_hash != self.checkpoints[i - 1].hash {
                    report.fail(format!("checkpoint {i}: broken chain link"));
                    return report;
                }
            } else {
                let is_spec_genesis = genesis_prev_hash(
                    checkpoint.content_hash,
                    checkpoint.content_size,
                    &self.metadata.document_path,
                    None,
                )
                .map(|h| checkpoint.previous_hash == h)
                .unwrap_or(false);
                if !is_spec_genesis {
                    report.fail("checkpoint 0: invalid genesis prev-hash".into());
                    return report;
                }
            }

            match checkpoint.signature.as_ref() {
                None => {
                    report.unsigned_checkpoints.push(checkpoint.ordinal);
                    match self.metadata.signature_policy {
                        SignaturePolicy::Required => {
                            report.fail(format!(
                                "checkpoint {i}: unsigned (signature required by policy)"
                            ));
                            return report;
                        }
                        SignaturePolicy::Optional => {
                            report
                                .warnings
                                .push(format!("checkpoint {i}: unsigned (optional policy)"));
                        }
                    }
                }
                Some(sig) => {
                    // H-004: Intentionally structural-only; we verify Ed25519
                    // signature length but defer cryptographic verification to
                    // keyhierarchy/verification.rs (verify_checkpoint_signatures)
                    // which has access to the session's public key. The Chain
                    // struct never holds key material by design.
                    if sig.len() != 64 {
                        report.signature_failures.push(checkpoint.ordinal);
                        report.fail(format!(
                            "checkpoint {i}: invalid Ed25519 signature length {} \
                             (expected 64 bytes; cryptographic verification deferred \
                             to keyhierarchy)",
                            sig.len()
                        ));
                        return report;
                    }
                    report.warnings.push(format!(
                        "checkpoint {i}: Ed25519 signature present but not \
                         cryptographically verified (no verifying key in chain; \
                         use keyhierarchy::verify_checkpoint_signatures for full check)"
                    ));
                }
            }

            // VDF presence checks (mode-specific requirements)
            match self.metadata.entanglement_mode {
                EntanglementMode::Legacy if checkpoint.vdf.is_none() && i > 0 => {
                    report.fail(format!(
                        "checkpoint {i}: missing VDF proof (required for time verification)"
                    ));
                    return report;
                }
                EntanglementMode::Legacy if checkpoint.vdf.is_none() => {
                    report.warnings.push(
                        "checkpoint 0: no VDF proof; chain predates genesis-VDF requirement"
                            .to_string(),
                    );
                }
                EntanglementMode::Entangled if checkpoint.vdf.is_none() => {
                    report.fail(format!(
                        "checkpoint {i}: missing VDF proof (required for entangled verification)"
                    ));
                    return report;
                }
                _ => {
                    // VDF present; resolve previous VDF output for entangled mode
                    let prev_vdf_output = if self.metadata.entanglement_mode
                        == EntanglementMode::Entangled
                        && i > 0
                    {
                        match require_prev_vdf_output(&self.checkpoints, i) {
                            Ok(out) => Some(out),
                            Err(e) => {
                                report.fail(e.to_string());
                                return report;
                            }
                        }
                    } else {
                        None
                    };

                    if let Err(e) = verify_single_checkpoint_vdf(
                        i,
                        checkpoint,
                        prev_vdf_output,
                        self.metadata.entanglement_mode,
                    ) {
                        report.fail(e.to_string());
                        return report;
                    }
                }
            }

            if let Some(rfc_vdf) = &checkpoint.rfc_vdf {
                use super::types::{VDF_RFC_INPUT_END, VDF_RFC_INPUT_OFFSET};
                // The 64-byte output field encodes [vdf_output || vdf_input].
                // Verify the input half matches the challenge field.
                if rfc_vdf.output[VDF_RFC_INPUT_OFFSET..VDF_RFC_INPUT_END] != rfc_vdf.challenge {
                    report.fail(format!(
                        "checkpoint {i}: rfc_vdf layout mismatch \
                         (input half of output != challenge)"
                    ));
                    return report;
                }
            }

            // H-003: Argon2 SWF verification checks internal consistency only
            // (Merkle proof over the Argon2id output). Verifying that the SWF
            // input was correctly derived requires the session context, which
            // is not available during standalone chain verification.
            if let Some(swf) = &checkpoint.argon2_swf {
                match vdf::swf_argon2::verify(swf) {
                    Ok(true) => {}
                    Ok(false) => {
                        report.fail(format!(
                            "checkpoint {i}: Argon2id SWF Merkle verification failed"
                        ));
                        return report;
                    }
                    Err(e) => {
                        report.fail(format!("checkpoint {i}: Argon2id SWF error: {e}"));
                        return report;
                    }
                }
            }

            // PoSME SWF verification: checks proof structure, param bounds, and
            // algorithm consistency. Seed-binding verification (jitter data,
            // challenge nonce, VDF output) requires session context and is
            // deferred to the evidence verification pipeline.
            #[cfg(feature = "posme")]
            if let Some(posme_bytes) = &checkpoint.posme_swf {
                let proof: posme::PosmeProof = match ciborium::from_reader(posme_bytes.as_slice()) {
                    Ok(p) => p,
                    Err(e) => {
                        report.fail(format!(
                            "checkpoint {i}: PoSME proof deserialization failed: {e}"
                        ));
                        return report;
                    }
                };
                if let Err(e) = proof.params.validate() {
                    report.fail(format!("checkpoint {i}: PoSME params invalid: {e}"));
                    return report;
                }
                // Algorithm field must be 30 (standard) or 31 (entangled).
                if proof.proof_algorithm != 30 && proof.proof_algorithm != 31 {
                    report.fail(format!(
                        "checkpoint {i}: PoSME proof_algorithm {} not recognized (expected 30 or 31)",
                        proof.proof_algorithm
                    ));
                    return report;
                }
                // Entangled proofs must carry entanglement points.
                if proof.proof_algorithm == 31 && proof.entanglement_points.is_empty() {
                    report.fail(format!(
                        "checkpoint {i}: PoSME entangled proof (alg 31) has no entanglement points"
                    ));
                    return report;
                }
                // VDF must be present alongside PoSME (time anchor binding).
                if checkpoint.vdf.is_none() && checkpoint.ordinal > 0 {
                    report.warnings.push(format!(
                        "checkpoint {i}: PoSME proof present but no VDF time anchor"
                    ));
                }
                // Duration plausibility: CORE (4 MiB arena) completes in ~10ms
                // on modern hardware; use 1ms floor as conservative lower bound.
                let min_duration_ms = 1u128;
                if proof.claimed_duration.as_millis() < min_duration_ms && checkpoint.ordinal > 0 {
                    report.warnings.push(format!(
                        "checkpoint {i}: PoSME claimed_duration {}ms below \
                         plausibility floor ({min_duration_ms}ms)",
                        proof.claimed_duration.as_millis()
                    ));
                }
            }

            // H-007: Verify MMR inclusion proof if present. Cross-checkpoint anchor:
            // proof[N].root must equal checkpoint[N+1].mmr_root (the pre-append root
            // stored by finalize_checkpoint), detecting any MMR rollback or root swap.
            if let Some(proof_bytes) = &checkpoint.mmr_inclusion_proof {
                match crate::mmr::InclusionProof::deserialize(proof_bytes) {
                    Err(_) => {
                        report.fail(format!("checkpoint {i}: malformed mmr_inclusion_proof"));
                        return report;
                    }
                    Ok(proof) => {
                        if let Err(e) = proof.verify(&checkpoint.hash) {
                            report
                                .fail(format!("checkpoint {i}: MMR inclusion proof invalid: {e}"));
                            return report;
                        }
                        if let Some(next_cp) = self.checkpoints.get(i + 1) {
                            if let Some(next_mmr_root) = next_cp.mmr_root {
                                if proof.root != next_mmr_root {
                                    report.fail(format!(
                                        "checkpoint {i}: MMR proof root does not match \
                                         checkpoint {} mmr_root (rollback detected)",
                                        i + 1
                                    ));
                                    return report;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Integrity metadata (checkpoint_count, mmr_root, metadata_signature)
        // is verified externally via CheckpointMmr, not stored on Chain.

        report
    }

}
