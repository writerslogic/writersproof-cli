// SPDX-License-Identifier: Apache-2.0

use crate::codec::{decode_evidence, encode_evidence};
use crate::crypto::{hash_sha256, sign_evidence_cose, verify_evidence_cose, EvidenceSigner};
use crate::error::{Error, Result};
use crate::rfc::{
    AttestationTier, Checkpoint, DocumentRef, EvidencePacket, HashAlgorithm, HashValue,
};
use cpoe_jitter::{EntropySource, PhysJitter};
use ed25519_dalek::VerifyingKey;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::war::ear::{CPOE_EVIDENCE_PROFILE, POP_EAR_PROFILE};

fn hash_document_ref(doc: &DocumentRef) -> Result<HashValue> {
    doc.compute_hash()
        .map_err(Error::Protocol)
}

fn now_millis() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Protocol(format!("system clock error: {}", e)))?
        .as_millis() as u64)
}

/// Incrementally build a signed CPoP evidence packet with causality-chained checkpoints.
pub struct Builder {
    version: u32,
    profile_uri: String,
    packet_id: [u8; 16],
    created: u64,
    document: DocumentRef,
    checkpoints: Vec<Checkpoint>,
    last_checkpoint_hash: HashValue,
    signer: Box<dyn EvidenceSigner>,
    jitter: PhysJitter,
    min_causality_entropy_bits: u8,
    attestation_tier: AttestationTier,
    baseline_verification: Option<crate::baseline::BaselineVerification>,
}

/// Production floor for causality-lock entropy. 8 bits = 256 possible values,
/// enough to block brute-force pre-computation within a single VDF window.
pub const DEFAULT_MIN_CAUSALITY_ENTROPY_BITS: u8 = 8;

impl Builder {
    pub fn new(document: DocumentRef, signer: Box<dyn EvidenceSigner>) -> Result<Self> {
        let mut packet_id = [0u8; 16];
        OsRng.fill_bytes(&mut packet_id);

        let now = now_millis()?;

        let initial_hash = hash_document_ref(&document)?;

        Ok(Self {
            version: 1,
            profile_uri: CPOE_EVIDENCE_PROFILE.to_string(),
            packet_id,
            created: now,
            document,
            checkpoints: Vec::new(),
            last_checkpoint_hash: initial_hash,
            signer,
            jitter: PhysJitter::new(1),
            min_causality_entropy_bits: DEFAULT_MIN_CAUSALITY_ENTROPY_BITS,
            attestation_tier: AttestationTier::SoftwareOnly,
            baseline_verification: None,
        })
    }

    pub fn with_attestation_tier(mut self, tier: AttestationTier) -> Self {
        self.attestation_tier = tier;
        self
    }

    /// Configure the jitter's internal min-entropy threshold AND the Builder's
    /// causality-lock threshold to the same value. Callers that want to
    /// accept lower-entropy jitter (e.g. integration tests on fast CI hardware
    /// where timing std-dev is small) should set this explicitly.
    pub fn with_min_entropy_bits(mut self, bits: u8) -> Self {
        self.jitter = PhysJitter::new(bits);
        self.min_causality_entropy_bits = bits;
        self
    }

    pub fn with_baseline_verification(mut self, bv: crate::baseline::BaselineVerification) -> Self {
        self.baseline_verification = Some(bv);
        self
    }

    /// Append a checkpoint, extending the causality chain.
    pub fn add_checkpoint(&mut self, content: &[u8], char_count: u64) -> Result<()> {
        let now = now_millis()?;

        let sequence = self.checkpoints.len() as u64;
        let mut checkpoint_id = [0u8; 16];
        OsRng.fill_bytes(&mut checkpoint_id);

        let content_hash = hash_sha256(content);

        let entropy = self
            .jitter
            .sample(content)
            .map_err(|e| Error::Crypto(format!("PhysJitter sampling failed: {}", e)))?;

        if entropy.entropy_bits < self.min_causality_entropy_bits {
            return Err(Error::Crypto(format!(
                "PhysJitter entropy too low ({} bits); causality lock requires >= {} bits",
                entropy.entropy_bits, self.min_causality_entropy_bits,
            )));
        }

        // Causality Lock V2: HMAC(packet_id, prev_hash | content_hash | entropy)
        let checkpoint_hash = crate::crypto::compute_causality_lock_v2(
            &self.packet_id,
            &self.last_checkpoint_hash.digest,
            &content_hash.digest,
            &entropy.hash,
        )?;

        let checkpoint = Checkpoint {
            sequence,
            checkpoint_id: checkpoint_id.to_vec(),
            timestamp: now,
            content_hash,
            char_count,
            prev_hash: self.last_checkpoint_hash.clone(),
            checkpoint_hash: checkpoint_hash.clone(),
            jitter_hash: Some(HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: entropy.hash.to_vec(),
            }),
        };

        self.last_checkpoint_hash = checkpoint_hash;
        self.checkpoints.push(checkpoint);

        Ok(())
    }

    /// Finalize the evidence packet, CBOR-encode it, and wrap in a COSE_Sign1 envelope.
    ///
    /// Requires at least 3 checkpoints per the CDDL schema (`[3* checkpoint]`).
    pub fn finalize(self) -> Result<Vec<u8>> {
        const MIN_CHECKPOINTS: usize = 3;
        if self.checkpoints.len() < MIN_CHECKPOINTS {
            return Err(Error::Validation(format!(
                "Evidence packet requires at least {} checkpoints, got {}",
                MIN_CHECKPOINTS,
                self.checkpoints.len()
            )));
        }

        let packet = EvidencePacket {
            version: self.version,
            profile_uri: self.profile_uri,
            packet_id: self.packet_id.to_vec(),
            created: self.created,
            document: self.document,
            checkpoints: self.checkpoints,
            attestation_tier: Some(self.attestation_tier),
            baseline_verification: self.baseline_verification,
        };

        let encoded = encode_evidence(&packet)?;
        sign_evidence_cose(&encoded, self.signer.as_ref())
    }
}

/// Verify COSE-signed evidence packets: signature, causality chain, and temporal consistency.
pub struct Verifier {
    verifying_key: VerifyingKey,
}

impl Verifier {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Verify signature, decode the packet, and validate causality chain integrity.
    pub fn verify(&self, cose_data: &[u8]) -> Result<EvidencePacket> {
        let payload = verify_evidence_cose(cose_data, &self.verifying_key)?;
        let packet = decode_evidence(&payload)?;
        self.validate_structure(&packet)?;

        let mut last_hash = hash_document_ref(&packet.document)?;

        for (i, checkpoint) in packet.checkpoints.iter().enumerate() {
            if checkpoint.sequence != i as u64 {
                return Err(Error::Validation(format!(
                    "Sequence mismatch at index {}: expected {}, got {}",
                    i, i, checkpoint.sequence
                )));
            }

            if !checkpoint.prev_hash.ct_eq(&last_hash) {
                return Err(Error::Validation(format!(
                    "Causality chain broken at sequence {}: prev_hash mismatch",
                    checkpoint.sequence
                )));
            }

            let expected_hash = if let Some(ref jitter) = checkpoint.jitter_hash {
                crate::crypto::compute_causality_lock_v2(
                    &packet.packet_id,
                    &last_hash.digest,
                    &checkpoint.content_hash.digest,
                    &jitter.digest,
                )?
            } else {
                crate::crypto::compute_causality_lock(
                    &packet.packet_id,
                    &last_hash.digest,
                    &checkpoint.content_hash.digest,
                )?
            };

            if !checkpoint.checkpoint_hash.ct_eq(&expected_hash) {
                return Err(Error::Validation(format!(
                    "Causality chain broken at sequence {}: checkpoint_hash mismatch",
                    checkpoint.sequence
                )));
            }

            last_hash = expected_hash;
        }

        self.validate_temporal_consistency(&packet)?;

        if let Some(ref bv) = packet.baseline_verification {
            self.validate_baseline_verification(bv)?;
        }

        Ok(packet)
    }

    /// Verifies baseline session summary fields, digest integrity,
    /// identity_fingerprint == SHA-256(signer pubkey), and digest_signature COSE_Sign1.
    /// Behavioral similarity scoring is done at the engine layer.
    fn validate_baseline_verification(
        &self,
        bv: &crate::baseline::BaselineVerification,
    ) -> Result<()> {
        bv.session_summary
            .validate()
            .map_err(|e| Error::Validation(format!("Baseline session_summary: {e}")))?;

        if let Some(ref digest) = bv.digest {
            digest
                .validate()
                .map_err(|e| Error::Validation(format!("Baseline digest: {e}")))?;

            let pubkey_hash = hash_sha256(self.verifying_key.as_bytes());
            if digest.identity_fingerprint != pubkey_hash.digest {
                return Err(Error::Validation(
                    "Baseline digest identity_fingerprint does not match signer public key"
                        .to_string(),
                ));
            }

            match bv.digest_signature {
                None => {
                    return Err(Error::Validation(
                        "Baseline digest present but digest_signature is missing".to_string(),
                    ));
                }
                Some(ref sig) => {
                    let payload = verify_evidence_cose(sig, &self.verifying_key).map_err(|e| {
                        Error::Validation(format!(
                            "Baseline digest_signature COSE verification failed: {e}"
                        ))
                    })?;
                    let signed_digest: crate::baseline::BaselineDigest =
                        crate::codec::cbor::decode(&payload).map_err(|e| {
                            Error::Validation(format!(
                                "Baseline digest_signature payload decode failed: {e}"
                            ))
                        })?;
                    if signed_digest != *digest {
                        return Err(Error::Validation(
                            "Baseline digest_signature payload does not match embedded digest"
                                .to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_structure(&self, packet: &EvidencePacket) -> Result<()> {
        if packet.version != 1 {
            return Err(Error::Validation(format!(
                "Unsupported packet version: expected 1, got {}",
                packet.version
            )));
        }

        if packet.profile_uri != CPOE_EVIDENCE_PROFILE && packet.profile_uri != POP_EAR_PROFILE {
            return Err(Error::Validation(format!(
                "Invalid profile_uri: expected \"{}\", got \"{}\"",
                CPOE_EVIDENCE_PROFILE, packet.profile_uri
            )));
        }

        if packet.packet_id.len() != 16 {
            return Err(Error::Validation(format!(
                "Invalid packet_id length: expected 16, got {}",
                packet.packet_id.len()
            )));
        }

        if packet.packet_id.iter().all(|&b| b == 0) {
            return Err(Error::Validation(
                "packet_id is all zeros; insufficient entropy".to_string(),
            ));
        }

        if !packet.document.content_hash.validate() {
            return Err(Error::Validation(
                "Document content_hash digest length does not match algorithm".to_string(),
            ));
        }

        const MAX_FILENAME_LEN: usize = 256;
        if let Some(ref filename) = packet.document.filename {
            if filename.len() > MAX_FILENAME_LEN {
                return Err(Error::Validation(format!(
                    "Document filename too long: {} bytes exceeds limit of {}",
                    filename.len(),
                    MAX_FILENAME_LEN
                )));
            }
        }

        const MIN_CHECKPOINTS: usize = 3;
        if packet.checkpoints.len() < MIN_CHECKPOINTS {
            return Err(Error::Validation(format!(
                "Too few checkpoints: {} is below minimum of {}",
                packet.checkpoints.len(),
                MIN_CHECKPOINTS
            )));
        }

        const MAX_CHECKPOINTS: usize = 100_000;
        if packet.checkpoints.len() > MAX_CHECKPOINTS {
            return Err(Error::Validation(format!(
                "Too many checkpoints: {} exceeds limit of {}",
                packet.checkpoints.len(),
                MAX_CHECKPOINTS
            )));
        }

        let mut seen_checkpoint_ids = HashSet::with_capacity(packet.checkpoints.len());
        for checkpoint in &packet.checkpoints {
            if checkpoint.checkpoint_id.len() != 16 {
                return Err(Error::Validation(format!(
                    "Invalid checkpoint_id length at sequence {}: expected 16, got {}",
                    checkpoint.sequence,
                    checkpoint.checkpoint_id.len()
                )));
            }
            if !seen_checkpoint_ids.insert(&checkpoint.checkpoint_id) {
                return Err(Error::Validation(format!(
                    "Duplicate checkpoint_id at sequence {}",
                    checkpoint.sequence
                )));
            }
            if !checkpoint.content_hash.validate() {
                return Err(Error::Validation(format!(
                    "Invalid content_hash at sequence {}: digest length mismatch",
                    checkpoint.sequence
                )));
            }
            if !checkpoint.prev_hash.validate() {
                return Err(Error::Validation(format!(
                    "Invalid prev_hash at sequence {}: digest length mismatch",
                    checkpoint.sequence
                )));
            }
            if !checkpoint.checkpoint_hash.validate() {
                return Err(Error::Validation(format!(
                    "Invalid checkpoint_hash at sequence {}: digest length mismatch",
                    checkpoint.sequence
                )));
            }
            if let Some(ref jitter) = checkpoint.jitter_hash {
                if !jitter.validate() {
                    return Err(Error::Validation(format!(
                        "Invalid jitter_hash at sequence {}: digest length mismatch",
                        checkpoint.sequence
                    )));
                }
            }
        }

        Ok(())
    }

    fn validate_temporal_consistency(&self, packet: &EvidencePacket) -> Result<()> {
        if packet.checkpoints.is_empty() {
            return Ok(());
        }

        let mut last_ts = packet.created;

        for checkpoint in &packet.checkpoints {
            // Equal timestamps are allowed by design: millisecond resolution permits
            // rapid consecutive keystrokes to share the same timestamp value.
            if checkpoint.timestamp < last_ts {
                return Err(Error::Validation(format!(
                    "Temporal anomaly: checkpoint {} timestamp is before previous",
                    checkpoint.sequence
                )));
            }

            last_ts = checkpoint.timestamp;
        }

        // Adversarial collapse detection is handled by ForensicsEngine with
        // tolerance-based thresholds. The verifier only checks temporal ordering.

        Ok(())
    }
}
