// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::Error;

use super::helpers::{
    ai_extent_str, ai_purpose_str, collaborator_role_str, extent_rank, hash_opt_bytes,
    hash_opt_str, hash_str, modality_type_str,
};
use super::types::{AiExtent, Declaration, DeclarationJitter, DeclarationSummary};

impl Declaration {
    /// Verify the Ed25519 signature against the signing payload.
    pub fn verify(&self) -> Result<(), String> {
        let pk_len = self.author_public_key.len();
        if pk_len != 32 {
            return Err(format!(
                "invalid public key length: expected 32, got {pk_len}"
            ));
        }
        let sig_len = self.signature.len();
        if sig_len != 64 {
            return Err(format!(
                "invalid signature length: expected 64, got {sig_len}"
            ));
        }

        let pubkey_bytes: [u8; 32] = self
            .author_public_key
            .as_slice()
            .try_into()
            .map_err(|_| format!("invalid public key length: expected 32, got {pk_len}"))?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| format!("invalid signature length: expected 64, got {sig_len}"))?;

        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| "public key is not a valid Ed25519 key".to_string())?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&self.signing_payload(), &signature)
            .map_err(|_| "signature verification failed".to_string())
    }

    /// Return true if any AI tools are declared.
    pub fn has_ai_usage(&self) -> bool {
        !self.ai_tools.is_empty()
    }

    /// Return the highest AI extent across all declared tools.
    pub fn max_ai_extent(&self) -> AiExtent {
        let mut max = AiExtent::None;
        for tool in &self.ai_tools {
            if extent_rank(&tool.extent) > extent_rank(&max) {
                max = tool.extent.clone();
            }
        }
        max
    }

    /// Serialize to pretty-printed JSON bytes.
    pub fn encode(&self) -> crate::error::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| Error::validation(format!("encode: {e}")))
    }

    /// Deserialize a declaration from JSON bytes.
    pub fn decode(data: &[u8]) -> crate::error::Result<Declaration> {
        serde_json::from_slice(data).map_err(|e| Error::validation(format!("decode: {e}")))
    }

    /// Generate a compact summary including signature validity.
    pub fn summary(&self) -> DeclarationSummary {
        let tools: Vec<String> = self.ai_tools.iter().map(|t| t.tool.clone()).collect();

        DeclarationSummary {
            title: self.title.clone(),
            ai_usage: self.has_ai_usage(),
            ai_tools: tools,
            max_ai_extent: ai_extent_str(&self.max_ai_extent()).to_string(),
            collaborators: self.collaborators.len(),
            signature_valid: self.verify().is_ok(),
        }
    }

    /// Signing payload v3: length-prefixed strings, millis timestamp,
    /// f64::to_bits for floating-point determinism, None/Some discriminants.
    pub(crate) fn signing_payload(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"cpoe-declaration-v3");
        hasher.update(self.document_hash);
        hasher.update(self.chain_hash);
        hash_str(&mut hasher, &self.title);

        hasher.update((self.input_modalities.len() as u64).to_be_bytes());
        for modality in &self.input_modalities {
            hash_str(&mut hasher, modality_type_str(&modality.modality_type));
            hasher.update(modality.percentage.to_bits().to_be_bytes());
            hash_opt_str(&mut hasher, modality.note.as_deref());
        }

        hasher.update((self.ai_tools.len() as u64).to_be_bytes());
        for tool in &self.ai_tools {
            hash_str(&mut hasher, &tool.tool);
            hash_opt_str(&mut hasher, tool.version.as_deref());
            hash_str(&mut hasher, ai_purpose_str(&tool.purpose));
            hash_opt_str(&mut hasher, tool.interaction.as_deref());
            hash_str(&mut hasher, ai_extent_str(&tool.extent));
            hasher.update((tool.sections.len() as u64).to_be_bytes());
            for section in &tool.sections {
                hash_str(&mut hasher, section);
            }
        }

        hasher.update((self.collaborators.len() as u64).to_be_bytes());
        for collaborator in &self.collaborators {
            hash_str(&mut hasher, &collaborator.name);
            hash_str(&mut hasher, collaborator_role_str(&collaborator.role));
            hasher.update((collaborator.sections.len() as u64).to_be_bytes());
            for section in &collaborator.sections {
                hash_str(&mut hasher, section);
            }
            hash_opt_bytes(&mut hasher, collaborator.public_key.as_deref());
        }

        hash_str(&mut hasher, &self.statement);
        // Use timestamp_millis (safe until ~year 292M) instead of nanos (overflows ~2262)
        hasher.update(self.created_at.timestamp_millis().to_be_bytes());
        hasher.update(self.version.to_be_bytes());
        hasher.update((self.author_public_key.len() as u64).to_be_bytes());
        hasher.update(&self.author_public_key);

        // Include jitter seal in signing payload (WAR/1.2)
        // Discriminant ensures None vs Some produce distinct hashes.
        // None = jitter not attempted OR measurement failed.
        // Callers should check JitterStatus for disambiguation.
        match &self.jitter_sealed {
            Some(jitter) => {
                hasher.update([1u8]);
                hasher.update(b"cpoe-jitter-seal-v1");
                hasher.update(jitter.jitter_hash);
                hasher.update(jitter.keystroke_count.to_be_bytes());
                hasher.update(jitter.duration_ms.to_be_bytes());
                hasher.update(jitter.avg_interval_ms.to_bits().to_be_bytes());
                hasher.update(jitter.entropy_bits.to_bits().to_be_bytes());
                hasher.update(if jitter.hardware_sealed {
                    &[1u8]
                } else {
                    &[0u8]
                });
            }
            None => {
                hasher.update([0u8]);
            }
        }

        hasher.finalize().to_vec()
    }

    /// Return true if a hardware jitter seal is attached.
    pub fn has_jitter_seal(&self) -> bool {
        self.jitter_sealed.is_some()
    }
}

impl DeclarationJitter {
    /// Build from raw jitter timing samples (microseconds).
    pub fn from_samples(
        jitter_samples: &[u32],
        duration_ms: u64,
        hardware_sealed: bool,
    ) -> Result<Self, &'static str> {
        let keystroke_count = jitter_samples.len() as u64;
        if keystroke_count == 0 {
            return Err("zero keystroke count");
        }

        let mut hasher = Sha256::new();
        hasher.update(b"cpoe-declaration-jitter-v1");
        hasher.update(keystroke_count.to_be_bytes());
        for sample in jitter_samples {
            hasher.update(sample.to_be_bytes());
        }
        let jitter_hash: [u8; 32] = hasher.finalize().into();

        let avg_interval_ms = if keystroke_count > 1 {
            duration_ms as f64 / (keystroke_count - 1) as f64
        } else {
            duration_ms as f64
        };

        // Entropy estimate: sum of clamped log2 of each sample value. This is a
        // heuristic that improves with sample count; it is not a rigorous
        // information-theoretic entropy measurement.
        let entropy_bits = jitter_samples
            .iter()
            .map(|&j| {
                if j > 0 {
                    (j as f64).log2().clamp(0.5, 8.0)
                } else {
                    0.0
                }
            })
            .sum();

        Ok(Self {
            jitter_hash,
            keystroke_count,
            duration_ms,
            avg_interval_ms,
            entropy_bits,
            hardware_sealed,
        })
    }

    /// Create jitter evidence from pre-computed values.
    pub fn new(
        jitter_hash: [u8; 32],
        keystroke_count: u64,
        duration_ms: u64,
        avg_interval_ms: f64,
        entropy_bits: f64,
        hardware_sealed: bool,
    ) -> Result<Self, crate::error::Error> {
        if !avg_interval_ms.is_finite() || !entropy_bits.is_finite() {
            return Err(crate::error::Error::crypto(
                "jitter evidence contains non-finite avg_interval_ms or entropy_bits",
            ));
        }
        Ok(Self {
            jitter_hash,
            keystroke_count,
            duration_ms,
            avg_interval_ms,
            entropy_bits,
            hardware_sealed,
        })
    }
}
