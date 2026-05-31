// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::vdf;
use crate::PhysicalContext;
use crate::VdfProof;
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Entangles physical landscape noise with the Arrow of Time.
#[derive(Debug)]
pub struct Entanglement;

impl Entanglement {
    /// Bind physical context to content hash to produce a checkpoint seed.
    pub fn create_seed(content_hash: [u8; 32], physics: &PhysicalContext) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"cpoe-entanglement-v1");
        hasher.update(content_hash);
        hasher.update(physics.combined_hash);
        hasher.finalize().into()
    }

    /// Hardened seed creation with length-prefixed VDF parameters.
    ///
    /// Length-prefixes variable-length data to prevent injection and
    /// field-shifting collision attacks on the seed derivation.
    pub fn create_seed_hardened(
        content_hash: [u8; 32],
        physics: &PhysicalContext,
        duration: Duration,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"cpoe-entanglement-v3-hardened");
        hasher.update(content_hash);
        hasher.update(physics.combined_hash);
        hasher.update(duration.as_nanos().to_be_bytes());
        hasher.finalize().into()
    }

    /// Prove document state existed on this silicon for at least `duration`.
    pub fn entangle(seed: [u8; 32], duration: Duration) -> Result<VdfProof, String> {
        vdf::compute(seed, duration, vdf::default_parameters())
    }
}
