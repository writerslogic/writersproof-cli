// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! PoSME sequential work function adapter for the checkpoint system.
//!
//! Thin wrapper around the `posme` crate that adapts its prover/verifier
//! to the cpoe checkpoint commit and verification flows.

use crate::error::{Error, Result};

/// Compute a PoSME proof for a checkpoint.
///
/// `seed`: 32-byte seed derived from checkpoint context (see `posme_seed_*` in params.rs).
/// `tier`: content tier (1=core, 2=standard, 3=enhanced, 4=maximum).
///
/// Returns the CBOR-serialized proof bytes for storage in `Checkpoint.posme_swf`.
pub fn compute(seed: [u8; 32], tier: u8) -> Result<Vec<u8>> {
    let params = posme::PosmeParams::for_tier(tier)
        .map_err(|e| Error::crypto(format!("PoSME invalid tier: {e}")))?;
    let proof = posme::prover::execute(&seed, &params)
        .map_err(|e| Error::crypto(format!("PoSME execution failed: {e}")))?;
    ciborium_encode(&proof)
        .map_err(|e| Error::crypto(format!("PoSME proof serialization failed: {e}")))
}

/// Verify a PoSME proof from its CBOR-serialized bytes.
///
/// `seed`: 32-byte seed that was used during computation.
/// `proof_bytes`: raw CBOR from `Checkpoint.posme_swf`.
pub fn verify(seed: [u8; 32], proof_bytes: &[u8]) -> Result<()> {
    let proof: posme::PosmeProof = ciborium_decode(proof_bytes)
        .map_err(|e| Error::crypto(format!("PoSME proof deserialization failed: {e}")))?;
    proof.validate_structure()
        .map_err(|e| Error::crypto(format!("PoSME proof structure invalid: {e}")))?;
    posme::verifier::verify(&seed, &proof)
        .map_err(|e| Error::crypto(format!("PoSME verification failed: {e}")))
}

/// Compute a PoSME proof with jitter entanglement (algorithm 31).
///
/// `jitter_hashes`: behavioral jitter sample hashes collected during the session.
pub fn compute_entangled(seed: [u8; 32], tier: u8, jitter_hashes: &[[u8; 32]]) -> Result<Vec<u8>> {
    let params = posme::PosmeParams::for_tier(tier)
        .map_err(|e| Error::crypto(format!("PoSME invalid tier: {e}")))?;
    let proof = posme::prover::execute_entangled(&seed, &params, jitter_hashes)
        .map_err(|e| Error::crypto(format!("PoSME entangled execution failed: {e}")))?;
    ciborium_encode(&proof)
        .map_err(|e| Error::crypto(format!("PoSME proof serialization failed: {e}")))
}

/// Select PoSME parameters for a content tier.
pub fn params_for_tier(tier: u8) -> Result<posme::PosmeParams> {
    posme::PosmeParams::for_tier(tier)
        .map_err(|e| Error::crypto(format!("PoSME invalid tier: {e}")))
}

fn ciborium_encode<T: serde::Serialize>(value: &T) -> std::result::Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn ciborium_decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> std::result::Result<T, String> {
    ciborium::from_reader(bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_and_verify_roundtrip() {
        let seed = [0x42u8; 32];
        let proof_bytes = compute(seed, 1).expect("compute");
        assert!(!proof_bytes.is_empty());
        verify(seed, &proof_bytes).expect("verify");
    }

    #[test]
    fn wrong_seed_fails_verify() {
        let seed = [0x42u8; 32];
        let proof_bytes = compute(seed, 1).expect("compute");
        let wrong_seed = [0x43u8; 32];
        assert!(verify(wrong_seed, &proof_bytes).is_err());
    }

    #[test]
    fn corrupted_proof_fails() {
        let seed = [0x42u8; 32];
        let mut proof_bytes = compute(seed, 1).expect("compute");
        proof_bytes[10] ^= 0xff;
        assert!(verify(seed, &proof_bytes).is_err());
    }
}
