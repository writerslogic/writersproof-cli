// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! EAR (Entity Attestation Result) types per draft-ietf-rats-ear.
//!
//! All types and constants are re-exported from `authorproof_protocol`.
//! This module adds engine-specific extensions (freshness checks using
//! the engine's monotonic clock, and a `VerifierId` default that stamps
//! the engine crate version).

// Re-export all EAR types and constants from protocol crate.
pub use authorproof_protocol::war::ear::{
    Ar4siStatus, EarAppraisal, EarToken, SealClaims, TrustVectorProjection,
    TrustworthinessVector, VerifierId, CWT_KEY_EAT_PROFILE, CWT_KEY_IAT, CWT_KEY_SUBMODS,
    EAR_KEY_POLICY_ID, EAR_KEY_STATUS, EAR_KEY_TRUST_VECTOR, EAR_KEY_VERIFIER_ID,
    CPOE_EAR_PROFILE, CPOE_EVIDENCE_PROFILE, POP_EAR_PROFILE, POP_KEY_ABSENCE,
    POP_KEY_CHAIN_DURATION, POP_KEY_CHAIN_LENGTH,
    POP_KEY_ENTROPY, POP_KEY_EVIDENCE_REF, POP_KEY_FORENSIC, POP_KEY_FORGERY_COST,
    POP_KEY_PROCESS_END, POP_KEY_PROCESS_START, POP_KEY_SEAL, POP_KEY_WARNINGS,
};

/// Engine-specific extensions for [`EarToken`].
pub trait EarTokenExt {
    /// Verify that the token was issued within the given maximum age,
    /// using the engine's monotonic clock.
    fn verify_freshness_engine(&self, max_age: std::time::Duration) -> bool;
}

impl EarTokenExt for EarToken {
    fn verify_freshness_engine(&self, max_age: std::time::Duration) -> bool {
        let now = crate::utils::now_secs() as i64;
        let age_secs = now.saturating_sub(self.iat);
        age_secs >= 0 && age_secs <= max_age.as_secs() as i64
    }
}

/// Build a [`VerifierId`] stamped with the engine crate version.
pub fn engine_verifier_id() -> VerifierId {
    VerifierId {
        build: format!("cpoe-engine/{}", env!("CARGO_PKG_VERSION")),
        developer: "writerslogic".to_string(),
    }
}
