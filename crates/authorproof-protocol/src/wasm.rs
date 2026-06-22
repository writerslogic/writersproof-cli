// SPDX-License-Identifier: Apache-2.0

//! WASM bindings for authorproof_protocol.
//!
//! Build with: `wasm-pack build --target web --features wasm`

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use crate::evidence::Verifier;
#[cfg(feature = "wasm")]
use crate::forensics::{ForensicVerdict, ForensicsEngine};
#[cfg(feature = "wasm")]
use ed25519_dalek::VerifyingKey;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct VerificationResult {
    is_valid: bool,
    forensic_verdict: String,
    checkpoint_count: u32,
    chain_duration_secs: u64,
    coefficient_of_variation: f64,
    hurst_exponent: f64,
    linearity_score: f64,
    error_message: String,
    explanation: String,
}

#[cfg(feature = "wasm")]
impl VerificationResult {
    fn error(verdict: ForensicVerdict, message: String) -> Self {
        Self {
            is_valid: false,
            forensic_verdict: verdict.as_str().to_owned(),
            checkpoint_count: 0,
            chain_duration_secs: 0,
            coefficient_of_variation: 0.0,
            hurst_exponent: -1.0,
            linearity_score: -1.0,
            error_message: message,
            explanation: String::new(),
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl VerificationResult {
    #[wasm_bindgen(getter)]
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    #[wasm_bindgen(getter)]
    pub fn forensic_verdict(&self) -> String {
        self.forensic_verdict.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn checkpoint_count(&self) -> u32 {
        self.checkpoint_count
    }

    #[wasm_bindgen(getter)]
    pub fn chain_duration_secs(&self) -> u64 {
        self.chain_duration_secs
    }

    #[wasm_bindgen(getter)]
    pub fn coefficient_of_variation(&self) -> f64 {
        self.coefficient_of_variation
    }

    #[wasm_bindgen(getter)]
    pub fn hurst_exponent(&self) -> f64 {
        self.hurst_exponent
    }

    #[wasm_bindgen(getter)]
    pub fn linearity_score(&self) -> f64 {
        self.linearity_score
    }

    #[wasm_bindgen(getter)]
    pub fn error_message(&self) -> String {
        self.error_message.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn explanation(&self) -> String {
        self.explanation.clone()
    }
}

/// Main WASM entry point: verify COSE-signed CPoE evidence + forensic analysis.
/// Performs COSE Ed25519 signature verification, CBOR tag validation,
/// causality chain verification, adversarial collapse detection,
/// and Hurst exponent estimation. Returns forensic verdict V1-V5.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_cpoe_evidence(evidence_bytes: &[u8], public_key_bytes: &[u8]) -> VerificationResult {
    let key_bytes: [u8; 32] = match public_key_bytes.try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            return VerificationResult::error(
                ForensicVerdict::V3Suspicious,
                "Public key must be exactly 32 bytes".into(),
            );
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(e) => {
            return VerificationResult::error(
                ForensicVerdict::V3Suspicious,
                format!("Invalid public key: {}", e),
            );
        }
    };

    let verifier = Verifier::new(verifying_key);

    match verifier.verify(evidence_bytes) {
        Ok(packet) => {
            let timestamps: Vec<u64> = std::iter::once(packet.created)
                .chain(packet.checkpoints.iter().map(|cp| cp.timestamp))
                .collect();

            let engine = ForensicsEngine::from_timestamps(&timestamps, true);
            let analysis = engine.analyze();

            VerificationResult {
                is_valid: analysis.verdict.is_verified(),
                forensic_verdict: analysis.verdict.as_str().to_owned(),
                // Saturates to u32::MAX for WASM compatibility; real packets won't exceed this.
                checkpoint_count: u32::try_from(analysis.checkpoint_count).unwrap_or(u32::MAX),
                chain_duration_secs: analysis.chain_duration_secs,
                coefficient_of_variation: analysis.coefficient_of_variation,
                hurst_exponent: analysis.hurst_exponent.unwrap_or(-1.0),
                linearity_score: analysis.linearity_score.unwrap_or(-1.0),
                error_message: String::new(),
                explanation: analysis.explanation,
            }
        }
        Err(e) => {
            let verdict = match &e {
                crate::error::Error::Crypto(_) => ForensicVerdict::V5ConfirmedForgery,
                crate::error::Error::Validation(_) => ForensicVerdict::V3Suspicious,
                _ => ForensicVerdict::V3Suspicious,
            };

            let mut result = VerificationResult::error(verdict, e.to_string());
            result.explanation = format!("Verification failed: {}", e);
            result
        }
    }
}
