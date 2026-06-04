// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Full verification pipeline for evidence packets.
//!
//! Orchestrates structural verification, HMAC seal re-derivation,
//! duration cross-checks, key provenance validation, forensic analysis,
//! and WAR appraisal into a single `FullVerificationResult`.

mod pipeline;
mod seals;
mod verdict;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

use crate::evidence::Packet;
use crate::forensics::{ForensicMetrics, PerCheckpointResult};
use crate::vdf;
use authorproof_protocol::forensics::ForensicVerdict;

/// Options controlling what the full verification pipeline checks.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// VDF parameters for structural/time proof verification.
    pub vdf_params: vdf::Parameters,
    /// Expected verifier nonce for freshness validation.
    pub expected_nonce: Option<[u8; 32]>,
    /// Whether to run forensic analysis (requires behavioral data in packet).
    pub run_forensics: bool,
    /// External trust anchor for baseline verification. When `Some`, uses
    /// `verify_with_trusted_key()` instead of self-signed verification.
    pub trusted_public_key: Option<[u8; 32]>,
    /// Whether to verify external timestamp anchors (OTS, RFC 3161) if present.
    pub verify_anchors: bool,
}

/// Result of HMAC seal re-derivation checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealVerification {
    /// Whether a jitter tag is present and structurally valid. None if no jitter binding.
    pub jitter_tag_present: Option<bool>,
    /// Whether the entangled binding matches. None if no entangled MAC.
    pub entangled_binding_valid: Option<bool>,
    /// Number of checkpoints checked for seal verification.
    pub checkpoints_checked: usize,
}

/// Result of duration cross-check between VDF iterations and wall time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurationCheck {
    /// Minimum wall time computed from VDF iterations (seconds).
    pub computed_min_seconds: f64,
    /// Claimed elapsed time from checkpoint timestamps (seconds).
    pub claimed_seconds: f64,
    /// Ratio: claimed / computed_min.
    pub ratio: f64,
    /// Whether the duration is plausible (0.5x to 3.0x).
    pub plausible: bool,
}

/// SWF duration bound constants per spec.
const SWF_DURATION_RATIO_MIN: f64 = 0.5;
const SWF_DURATION_RATIO_MAX: f64 = 3.0;

/// Result of key provenance validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyProvenanceCheck {
    /// Whether key hierarchy is internally consistent. None if no hierarchy.
    pub hierarchy_consistent: Option<bool>,
    /// Whether the same signing key is used across all checkpoint signatures.
    pub signing_key_consistent: bool,
    /// Whether ratchet key indices are monotonically increasing.
    pub ratchet_monotonic: bool,
}

/// Complete result of the full verification pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullVerificationResult {
    /// Structural verification (chain hashes, VDF proofs, declaration).
    pub structural: bool,
    /// Packet-level signature verification. None if unsigned.
    pub signature: Option<bool>,
    /// HMAC seal re-derivation results.
    pub seals: SealVerification,
    /// Duration cross-check.
    pub duration: DurationCheck,
    /// Key provenance validation.
    pub key_provenance: KeyProvenanceCheck,
    /// Forensic analysis results (if run_forensics=true and data available).
    pub forensics: Option<ForensicMetrics>,
    /// Per-checkpoint flag analysis.
    pub per_checkpoint: Option<PerCheckpointResult>,
    /// Overall forensic verdict.
    pub verdict: ForensicVerdict,
    /// Number of anchor proofs verified (0 if none present or verify_anchors=false).
    pub anchors_verified: usize,
    /// Accumulated warnings from all phases.
    pub warnings: Vec<String>,
}

/// Run the full verification pipeline on an evidence packet.
pub fn full_verify(packet: &Packet, opts: &VerifyOptions) -> FullVerificationResult {
    let mut warnings = Vec::new();

    // Phase 1: Structural verification
    let structural = match if let Some(tk) = opts.trusted_public_key {
        packet.verify_with_trusted_key(opts.vdf_params, tk)
    } else {
        packet.verify_self_signed(opts.vdf_params)
    } {
        Ok(()) => true,
        Err(e) => {
            warnings.push(format!("Structural verification failed: {}", e));
            false
        }
    };

    // Signature verification
    let signature = if packet.packet_signature.is_some() {
        match packet.verify_signature(opts.expected_nonce.as_ref()) {
            Ok(()) => Some(true),
            Err(e) => {
                warnings.push(format!("Signature verification failed: {}", e));
                Some(false)
            }
        }
    } else {
        warnings.push("Packet is unsigned".to_string());
        None
    };

    // Declaration verification
    let declaration_valid = if let Some(decl) = &packet.declaration {
        if decl.verify().is_err() {
            warnings.push("Declaration signature is invalid".to_string());
            false
        } else {
            true
        }
    } else {
        warnings.push("No declaration present".to_string());
        false
    };

    // Short-circuit: if structural verification failed, skip all subsequent phases
    // to avoid producing misleading "valid" results on tampered evidence.
    let (seals, duration, key_provenance, forensics, per_checkpoint) = if !structural {
        (
            SealVerification {
                jitter_tag_present: None,
                entangled_binding_valid: None,
                checkpoints_checked: 0,
            },
            DurationCheck {
                plausible: false,
                computed_min_seconds: 0.0,
                claimed_seconds: 0.0,
                ratio: 0.0,
            },
            KeyProvenanceCheck {
                hierarchy_consistent: None,
                signing_key_consistent: false,
                ratchet_monotonic: false,
            },
            None,
            None,
        )
    } else {
        // Phase 4: HMAC seal re-derivation
        let seals = seals::verify_seals_structural(packet, &mut warnings);

        // Phase 5: Duration cross-check
        let duration = seals::verify_duration(packet, &opts.vdf_params, &mut warnings);

        // Phase 6: Key provenance
        let key_provenance = seals::verify_key_provenance(packet, &mut warnings);

        // Phases 2+3: Forensic analysis
        let (forensics, per_checkpoint) = if opts.run_forensics {
            pipeline::run_forensics(packet, &mut warnings)
        } else {
            (None, None)
        };

        (seals, duration, key_provenance, forensics, per_checkpoint)
    };

    // Anchor verification placeholder: wire-format anchor proofs (CheckpointWire
    // field 21) are verified during CBOR-level import via AnchorManager::verify_anchor().
    // The internal Packet type does not carry anchor data, so we report 0 here.
    // Full async anchor verification is performed by the CLI/FFI export path.
    let anchors_verified = 0usize;

    // Compute overall verdict
    let verdict = verdict::compute_verdict(
        structural,
        signature,
        declaration_valid,
        &seals,
        &duration,
        &key_provenance,
        forensics.as_ref(),
        per_checkpoint.as_ref(),
    );

    FullVerificationResult {
        structural,
        signature,
        seals,
        duration,
        key_provenance,
        forensics,
        per_checkpoint,
        verdict,
        anchors_verified,
        warnings,
    }
}
