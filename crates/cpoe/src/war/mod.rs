// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! WAR (Written Authorship Report) block encoding and verification.
//!
//! PGP-style ASCII-armored evidence format -- human-readable and
//! independently verifiable.

pub mod appraisal;
pub mod common;
pub mod compat;
pub mod ear;
pub mod encoding;
pub mod profiles;
pub mod trust_bundle;
pub mod types;
pub mod verification;

#[cfg(test)]
mod tests;

pub use appraisal::appraise;
pub use ear::{Ar4siStatus, EarAppraisal, EarToken, SealClaims, TrustworthinessVector, VerifierId};
pub use encoding::word_wrap;
pub use types::{Block, CheckResult, ForensicDetails, Seal, VerificationReport, Version};
pub use verification::compute_seal;

use crate::evidence::Packet;
use crate::trust_policy::AppraisalPolicy;
use authorproof_protocol::crypto::EvidenceSigner;

impl Block {
    /// Create from an evidence packet.
    pub fn from_packet(packet: &Packet) -> Result<Self, String> {
        let declaration = packet
            .declaration
            .as_ref()
            .ok_or("evidence packet missing declaration")?;

        let version = if declaration.has_jitter_seal() {
            Version::V1_1
        } else {
            Version::V1_0
        };

        let document_id = hex::decode(&packet.document.final_hash)
            .map_err(|e| format!("invalid document hash: {e}"))?;
        if document_id.len() != 32 {
            return Err("document hash must be 32 bytes".to_string());
        }
        let mut doc_id = [0u8; 32];
        doc_id.copy_from_slice(&document_id);

        let author = if declaration.author_public_key.len() == 32 {
            let fingerprint = &hex::encode(&declaration.author_public_key)[..16];
            format!("key:{}", fingerprint)
        } else {
            "unknown".to_string()
        };

        let seal = compute_seal(packet, declaration)?;

        // Tool declaration: structured from declaration.ai_tools
        let tool = if declaration.ai_tools.is_empty() {
            Some("none".to_string())
        } else {
            let t = &declaration.ai_tools[0];
            let extent = match t.extent {
                crate::declaration::AiExtent::None => "none",
                crate::declaration::AiExtent::Minimal => "minor",
                crate::declaration::AiExtent::Moderate => "moderate",
                crate::declaration::AiExtent::Substantial => "substantial",
            };
            Some(format!("ai:{}:{}", t.tool, extent))
        };

        // Evidence trust tier
        let tier = Some(
            match packet
                .trust_tier
                .unwrap_or(crate::evidence::TrustTier::Local)
            {
                crate::evidence::TrustTier::Local => "T1",
                crate::evidence::TrustTier::Signed => "T2",
                crate::evidence::TrustTier::NonceBound => "T3",
                crate::evidence::TrustTier::Attested => "T4",
            }
            .to_string(),
        );

        let checkpoints = Some(packet.checkpoints.len() as u64);

        // Duration from first to last checkpoint
        let duration_secs = if packet.checkpoints.len() >= 2 {
            let first = packet.checkpoints.first().unwrap().timestamp;
            let last = packet.checkpoints.last().unwrap().timestamp;
            let delta = (last - first).num_seconds().max(0) as u64;
            Some(delta)
        } else {
            None
        };

        Ok(Self {
            version,
            author,
            document_id: doc_id,
            timestamp: packet.exported_at,
            statement: declaration.statement.clone(),
            seal,
            tool,
            tier,
            score: None, // Set during forensic analysis or export
            checkpoints,
            duration_secs,
            rfc3161_timestamp: None,
            evidence: Some(Box::new(packet.clone())),
            signed: false,
            verifier_nonce: packet.verifier_nonce,
            ear: None,
        })
    }

    /// Create from an owned evidence packet. Callers that no longer need
    /// the packet after block creation should prefer this to avoid holding
    /// two copies simultaneously.
    pub fn from_packet_owned(packet: Packet) -> Result<Self, String> {
        let mut block = Self::from_packet(&packet)?;
        block.evidence = Some(Box::new(packet));
        Ok(block)
    }

    /// Create a signed WAR block from an evidence packet.
    pub fn from_packet_signed(
        packet: &Packet,
        signer: &dyn EvidenceSigner,
    ) -> Result<Self, String> {
        let mut block = Self::from_packet(packet)?;
        block.sign(signer)?;
        Ok(block)
    }

    /// Create a V2.0 WAR block from an evidence packet with EAR appraisal.
    pub fn from_packet_appraised(
        packet: &Packet,
        signer: &dyn EvidenceSigner,
        policy: &AppraisalPolicy,
    ) -> crate::error::Result<Self> {
        let mut block = Self::from_packet(packet)
            .map_err(|e| crate::error::Error::evidence(format!("block creation failed: {e}")))?;
        block
            .sign(signer)
            .map_err(|e| crate::error::Error::evidence(format!("signing failed: {e}")))?;

        let mut ear = appraisal::appraise(packet, policy)?;

        if let Some(appr) = ear.submods.get_mut("pop") {
            appr.pop_seal = Some(SealClaims {
                h1: block.seal.h1,
                h2: block.seal.h2,
                h3: block.seal.h3,
                signature: block.seal.signature,
                public_key: block.seal.public_key,
            });
        }

        block.version = Version::V2_0;
        block.ear = Some(ear);
        Ok(block)
    }

    /// Domain separation tag for WAR seal signatures.
    /// Prevents cross-protocol confusion by ensuring a signature produced
    /// for the WAR seal cannot be misinterpreted in any other context.
    const SEAL_SIG_DST: &'static [u8] = b"cpoe-war-seal-v1";

    /// Sign the WAR block's seal with the given signer (software or hardware).
    ///
    /// The signature covers `SEAL_SIG_DST || H3` (domain-separated) to prevent
    /// cross-protocol signature confusion.
    pub fn sign(&mut self, signer: &dyn EvidenceSigner) -> Result<(), String> {
        crate::integrity::runtime_integrity_check()
            .map_err(|e| format!("integrity check failed: {e}"))?;
        let mut msg = Vec::with_capacity(Self::SEAL_SIG_DST.len() + 32);
        msg.extend_from_slice(Self::SEAL_SIG_DST);
        msg.extend_from_slice(&self.seal.h3);
        let signature_bytes = signer
            .sign(&msg)
            .map_err(|e| format!("signing failed: {}", e))?;

        if signature_bytes.len() != 64 {
            return Err(format!(
                "invalid signature length: expected 64, got {}",
                signature_bytes.len()
            ));
        }

        self.seal.signature.copy_from_slice(&signature_bytes);
        self.signed = true;

        Ok(())
    }
}

/// Build a signed ASCII-armored WAR block from ephemeral session data.
///
/// This is the engine-layer entry point for ephemeral WAR signing. The FFI
/// layer handles key loading and snapshot type marshaling; this function
/// owns the packet assembly, signing, and encoding so they are unit-testable
/// without a key file or Swift runtime.
pub fn build_signed_ephemeral_block(
    final_hash_hex: &str,
    statement: &str,
    context_label: &str,
    snapshots: &[crate::evidence::EphemeralSnapshot],
    jitter_intervals: &[u64],
    keystroke_count: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<String, String> {
    let packet = crate::evidence::build_ephemeral_packet(
        final_hash_hex,
        statement,
        context_label,
        snapshots,
        signing_key,
        jitter_intervals,
        keystroke_count,
    )
    .map_err(|e| format!("{e}"))?;
    let block = Block::from_packet_signed(&packet, signing_key)
        .map_err(|e| format!("WAR block creation failed: {e}"))?;
    Ok(block.encode_ascii())
}
