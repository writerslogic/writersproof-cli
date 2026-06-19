// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Packet impl block: verification, signing, encoding/decoding, and hashing.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;

use crate::error::Error;
use crate::keyhierarchy;
use crate::tpm;
use crate::vdf;
use authorproof_protocol::codec::{self, Format, CBOR_TAG_CPOE};
use authorproof_protocol::rfc;

use super::types::{Packet, NONCE_BINDING_DST, PACKET_CONTENT_DST};

/// Minimum behavioral similarity for baseline verification to pass without warning.
const BASELINE_SIMILARITY_THRESHOLD: f64 = 0.7;

impl Packet {
    /// Verify packet integrity using self-signed key only (no external trust anchor).
    ///
    /// This proves internal consistency (chain hashes, VDF proofs, declaration,
    /// hardware, key hierarchy) but NOT authenticity, because the packet's own
    /// embedded `signing_public_key` is used for baseline verification.
    ///
    /// Suitable for Free-tier offline local witnessing. For production verification
    /// with an external trust anchor, use [`verify_with_trusted_key`].
    pub fn verify_self_signed(&self, vdf_params: vdf::Parameters) -> crate::error::Result<()> {
        log::warn!(
            "Self-signed verification: proves internal consistency only, not authenticity. \
             Use verify_with_trusted_key() for production verification."
        );
        self.verify_inner(vdf_params, None)
    }

    /// Verify packet integrity against an externally trusted public key.
    ///
    /// Uses `trusted_public_key` for baseline verification instead of the packet's
    /// embedded key, proving authenticity against an external trust anchor.
    pub fn verify_with_trusted_key(
        &self,
        _vdf_params: vdf::Parameters,
        trusted_public_key: [u8; 32],
    ) -> crate::error::Result<()> {
        self.verify_inner(_vdf_params, Some(trusted_public_key))
    }

    fn verify_inner(
        &self,
        _vdf_params: vdf::Parameters,
        trusted_public_key: Option<[u8; 32]>,
    ) -> crate::error::Result<()> {
        if let Some(last) = self.checkpoints.last() {
            let expected_chain_hash = last.hash.clone();
            if self
                .chain_hash
                .as_bytes()
                .ct_eq(expected_chain_hash.as_bytes())
                .unwrap_u8()
                == 0
            {
                return Err(Error::evidence("chain hash mismatch"));
            }
            if self
                .document
                .final_hash
                .as_bytes()
                .ct_eq(last.content_hash.as_bytes())
                .unwrap_u8()
                == 0
            {
                return Err(Error::evidence("document final hash mismatch"));
            }
            if self.document.final_size != last.content_size {
                return Err(Error::evidence("document final size mismatch"));
            }
        } else if !self.chain_hash.is_empty() {
            return Err(Error::evidence("chain hash present with no checkpoints"));
        }

        let mut prev_hash = String::new();
        for (i, cp) in self.checkpoints.iter().enumerate() {
            if i == 0 {
                // Accept spec-correct H(document-ref) genesis
                let is_doc_ref = hex::decode(&cp.content_hash)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .and_then(|content_hash| {
                        crate::checkpoint::genesis_prev_hash(
                            content_hash,
                            cp.content_size,
                            &self.document.path,
                            None,
                        )
                        .ok()
                    })
                    .map(|h| cp.previous_hash == hex::encode(h))
                    .unwrap_or(false);
                let is_valid_hex = cp.previous_hash.len() == 64
                    && cp.previous_hash.chars().all(|c| c.is_ascii_hexdigit());
                if !is_doc_ref && !is_valid_hex {
                    return Err(Error::evidence(
                        "checkpoint 0: invalid genesis previous hash",
                    ));
                }
                if !is_doc_ref && is_valid_hex {
                    log::warn!(
                        "checkpoint 0: genesis hash is valid hex but does not match document ref"
                    );
                }
            } else if cp.previous_hash != prev_hash {
                return Err(Error::evidence(format!(
                    "checkpoint {i}: broken chain link"
                )));
            }
            prev_hash = cp.hash.clone();

            if let (Some(iterations), Some(input_hex), Some(output_hex)) = (
                cp.vdf_iterations,
                cp.vdf_input.as_ref(),
                cp.vdf_output.as_ref(),
            ) {
                const MAX_VDF_ITERATIONS: u64 = 1_000_000_000;
                if iterations > MAX_VDF_ITERATIONS {
                    return Err(Error::evidence(format!(
                        "checkpoint {i}: VDF iterations {iterations} exceeds safety limit"
                    )));
                }
                let input = hex::decode(input_hex)
                    .map_err(|e| Error::evidence(format!("invalid hex: {e}")))?;
                let output = hex::decode(output_hex)
                    .map_err(|e| Error::evidence(format!("invalid hex: {e}")))?;
                let input_arr = crate::utils::to_array_32(&input).map_err(|_| {
                    Error::evidence(format!("checkpoint {i}: VDF input/output size mismatch"))
                })?;
                let output_arr = crate::utils::to_array_32(&output).map_err(|_| {
                    Error::evidence(format!("checkpoint {i}: VDF input/output size mismatch"))
                })?;
                let proof = vdf::VdfProof {
                    input: input_arr,
                    output: output_arr,
                    iterations,
                    duration: Duration::from_secs(0),
                };
                if !vdf::verify(&proof) {
                    return Err(Error::evidence(format!(
                        "checkpoint {i}: VDF verification failed"
                    )));
                }
            }
        }

        if let Some(decl) = &self.declaration {
            if decl.verify().is_err() {
                return Err(Error::evidence("declaration signature invalid"));
            }
        }

        if let Some(hardware) = &self.hardware {
            let trusted_keys: Vec<Vec<u8>> = trusted_public_key
                .map(|k| vec![k.to_vec()])
                .unwrap_or_default();
            if trusted_keys.is_empty() {
                log::warn!(
                    "Hardware attestation skipped: no trusted keys provided; \
                     binding authenticity cannot be verified"
                );
            } else if let Err(err) = tpm::verify_binding_chain(&hardware.bindings, &trusted_keys) {
                return Err(Error::evidence(format!(
                    "hardware attestation invalid: {:?}",
                    err
                )));
            }
        }

        if let Some(kh) = &self.key_hierarchy {
            let master_pub = hex::decode(&kh.master_public_key)
                .map_err(|e| Error::evidence(format!("invalid master_public_key hex: {e}")))?;
            if master_pub.len() != 32 {
                return Err(Error::evidence("master_public_key must be 32 bytes"));
            }
            let session_pub = hex::decode(&kh.session_public_key)
                .map_err(|e| Error::evidence(format!("invalid session_public_key hex: {e}")))?;
            if session_pub.len() != 32 {
                return Err(Error::evidence("session_public_key must be 32 bytes"));
            }
            let cert_raw = general_purpose::STANDARD
                .decode(&kh.session_certificate)
                .map_err(|e| Error::evidence(format!("invalid session_certificate base64: {e}")))?;

            if let Some(ref doc_hash_hex) = kh.session_document_hash {
                let session_id_bytes = hex::decode(&kh.session_id)
                    .map_err(|e| Error::evidence(format!("invalid session_id hex: {e}")))?;
                let doc_hash_bytes = hex::decode(doc_hash_hex).map_err(|e| {
                    Error::evidence(format!("invalid session_document_hash hex: {e}"))
                })?;
                let session_id_arr = crate::utils::to_array_32(&session_id_bytes)
                    .map_err(|_| Error::evidence("session_id must be 32 bytes"))?;
                let doc_hash_arr = crate::utils::to_array_32(&doc_hash_bytes)
                    .map_err(|_| Error::evidence("session_document_hash must be 32 bytes"))?;
                if let Err(err) = keyhierarchy::validate_cert_byte_lengths(
                    &master_pub,
                    &session_pub,
                    &cert_raw,
                    &session_id_arr,
                    kh.session_started,
                    &doc_hash_arr,
                ) {
                    return Err(Error::evidence(format!(
                        "key hierarchy verification failed: {err}"
                    )));
                }
            }

            for sig in &kh.checkpoint_signatures {
                if sig.ratchet_index < 0 {
                    return Err(Error::evidence(format!(
                        "negative ratchet index {}",
                        sig.ratchet_index
                    )));
                }
                let ratchet_index = usize::try_from(sig.ratchet_index)
                    .map_err(|_| Error::evidence("ratchet_index out of range"))?;
                let ratchet_hex = kh.ratchet_public_keys.get(ratchet_index).ok_or_else(|| {
                    Error::evidence(format!(
                        "ratchet index {} out of range (have {} keys)",
                        ratchet_index,
                        kh.ratchet_public_keys.len()
                    ))
                })?;
                let ratchet_pub = hex::decode(ratchet_hex)
                    .map_err(|e| Error::evidence(format!("invalid ratchet key hex: {e}")))?;
                if ratchet_pub.len() != 32 {
                    return Err(Error::evidence("ratchet public key must be 32 bytes"));
                }
                let checkpoint_hash = hex::decode(&sig.checkpoint_hash)
                    .map_err(|e| Error::evidence(format!("invalid checkpoint_hash hex: {e}")))?;
                let signature = general_purpose::STANDARD
                    .decode(&sig.signature)
                    .map_err(|e| Error::evidence(format!("invalid signature base64: {e}")))?;
                if signature.len() != 64 {
                    return Err(Error::evidence("ratchet signature must be 64 bytes"));
                }

                keyhierarchy::verify_ratchet_signature(&ratchet_pub, &checkpoint_hash, &signature)
                    .map_err(|e| {
                        Error::evidence(format!("key hierarchy verification failed: {e}"))
                    })?;
            }
        }

        if let Some(bv) = &self.baseline_verification {
            if let Some(digest) = &bv.digest {
                // H-012: digest present but signature missing is an error, not a silent pass.
                if bv.digest_signature.is_none() {
                    return Err(Error::evidence(
                        "baseline digest present but digest_signature is missing",
                    ));
                }
                if let Some(sig) = &bv.digest_signature {
                    // H-012: Prefer trusted external key; fall back to self-signed with warning.
                    let public_key_bytes = if let Some(tk) = trusted_public_key {
                        tk
                    } else {
                        log::warn!(
                            "Baseline verification uses self-signed key from the packet; \
                             this proves internal consistency only, not authenticity"
                        );
                        self.signing_public_key.ok_or_else(|| {
                            Error::signature("missing signing public key for baseline")
                        })?
                    };
                    let public_key = VerifyingKey::from_bytes(&public_key_bytes)
                        .map_err(|e| Error::signature(format!("invalid public key: {e}")))?;

                    let signature = Signature::from_bytes(
                        sig.as_slice()
                            .try_into()
                            .map_err(|_| Error::evidence("invalid signature length"))?,
                    );

                    let digest_json = serde_json::to_vec(digest)
                        .map_err(|e| Error::evidence(format!("digest serialize failed: {e}")))?;

                    public_key.verify(&digest_json, &signature).map_err(|e| {
                        Error::signature(format!("baseline digest signature invalid: {e}"))
                    })?;
                }

                let public_key_bytes = trusted_public_key
                    .or(self.signing_public_key)
                    .ok_or_else(|| Error::signature("missing signing public key"))?;
                let mut hasher = Sha256::new();
                hasher.update(public_key_bytes);
                let actual_fp = hasher.finalize();
                if digest.identity_fingerprint != actual_fp.as_slice() {
                    return Err(Error::evidence("baseline identity fingerprint mismatch"));
                }

                let similarity =
                    crate::baseline::verify_against_baseline(digest, &bv.session_summary);
                if similarity < BASELINE_SIMILARITY_THRESHOLD {
                    // Not a hard failure: low behavioral similarity can occur
                    // legitimately (e.g., different device, fatigue, new writing
                    // style). Forensic analysis can weigh this signal later.
                    log::warn!("Behavioral consistency low: {:.2}", similarity);
                }
            }
        }

        Ok(())
    }

    /// Sum elapsed time across all checkpoints.
    pub fn total_elapsed_time(&self) -> Duration {
        let mut total = Duration::from_secs(0);
        for cp in &self.checkpoints {
            if let Some(elapsed) = cp.elapsed_time {
                total += elapsed;
            }
        }
        total
    }

    /// Encode to CBOR with PPP semantic tag (RFC-compliant default).
    pub fn encode(&self) -> crate::error::Result<Vec<u8>> {
        codec::cbor::encode_cpoe(self).map_err(|e| Error::evidence(format!("encode failed: {e}")))
    }

    /// Encode in the specified format.
    pub fn encode_with_format(&self, format: Format) -> crate::error::Result<Vec<u8>> {
        match format {
            Format::Cbor => codec::cbor::encode_cpoe(self)
                .map_err(|e| Error::evidence(format!("encode failed: {e}"))),
            Format::Json => serde_json::to_vec_pretty(self)
                .map_err(|e| Error::evidence(format!("encode failed: {e}"))),
        }
    }

    /// Decode a packet, auto-detecting format. Validates CBOR tag if present.
    pub fn decode(data: &[u8]) -> crate::error::Result<Packet> {
        const MAX_EVIDENCE_SIZE: usize = 100 * 1024 * 1024; // 100 MB
        if data.len() > MAX_EVIDENCE_SIZE {
            return Err(Error::evidence(format!(
                "Evidence data too large: {} bytes (max {})",
                data.len(),
                MAX_EVIDENCE_SIZE
            )));
        }

        let format =
            Format::detect(data).ok_or_else(|| Error::evidence("unable to detect format"))?;

        match format {
            Format::Cbor => {
                if !codec::cbor::has_tag(data, CBOR_TAG_CPOE) {
                    return Err(Error::evidence("missing or invalid CBOR PPP tag"));
                }
                codec::cbor::decode_cpoe(data)
                    .map_err(|e| Error::evidence(format!("decode failed: {e}")))
            }
            Format::Json => serde_json::from_slice(data)
                .map_err(|e| Error::evidence(format!("decode failed: {e}"))),
        }
    }

    /// Decode with explicit format (skips format detection).
    pub fn decode_with_format(data: &[u8], format: Format) -> crate::error::Result<Packet> {
        match format {
            Format::Cbor => {
                if !codec::cbor::has_tag(data, CBOR_TAG_CPOE) {
                    return Err(Error::evidence("missing or invalid CBOR PPP tag"));
                }
                codec::cbor::decode_cpoe(data)
                    .map_err(|e| Error::evidence(format!("decode failed: {e}")))
            }
            Format::Json => serde_json::from_slice(data)
                .map_err(|e| Error::evidence(format!("decode failed: {e}"))),
        }
    }

    /// Deterministic SHA-256 hash via untagged CBOR (RFC 8949 Section 4.2).
    pub fn hash(&self) -> crate::error::Result<[u8; 32]> {
        let data = codec::cbor::encode(self)
            .map_err(|e| Error::evidence(format!("packet hash encode failed: {e}")))?;
        Ok(Sha256::digest(data).into())
    }

    /// Hash of ALL packet content excluding only the three signature-related fields
    /// (`verifier_nonce`, `packet_signature`, `signing_public_key`) to avoid
    /// circular dependencies during signing.
    ///
    /// Uses deterministic CBOR serialization ensuring every evidence field
    /// (behavioral, keystroke, jitter, hardware, forensics, etc.) is covered.
    /// Stripping any field invalidates the signature.
    pub fn content_hash(&self) -> crate::error::Result<[u8; 32]> {
        // When the three signature fields are already None, serialize directly
        // without cloning; serde skip_serializing_if = "Option::is_none" ensures
        // they are omitted from the output identically to a cleared clone.
        if self.verifier_nonce.is_none()
            && self.packet_signature.is_none()
            && self.signing_public_key.is_none()
        {
            return Self::hash_content_cbor(self);
        }
        // Post-signing path (verify_signature only): clone with signature
        // fields cleared. The fast path above covers sign() calls; this path
        // runs once per verification, not per-keystroke.
        let mut copy = self.clone();
        copy.verifier_nonce = None;
        copy.packet_signature = None;
        copy.signing_public_key = None;
        Self::hash_content_cbor(&copy)
    }

    fn hash_content_cbor(packet: &Self) -> crate::error::Result<[u8; 32]> {
        let data = codec::cbor::encode(packet)
            .map_err(|e| Error::crypto(format!("content_hash: CBOR encoding failed: {e}")))?;
        let mut hasher = Sha256::new();
        hasher.update(PACKET_CONTENT_DST);
        hasher.update(data);
        Ok(hasher.finalize().into())
    }

    /// Signing payload: `SHA-256(content_hash || nonce)` if nonce present,
    /// otherwise just `content_hash`.
    pub fn signing_payload(&self) -> crate::error::Result<[u8; 32]> {
        let content = self.content_hash()?;
        match &self.verifier_nonce {
            Some(nonce) => {
                let mut hasher = Sha256::new();
                hasher.update(NONCE_BINDING_DST);
                hasher.update(content);
                hasher.update(nonce);
                Ok(hasher.finalize().into())
            }
            None => Ok(content),
        }
    }

    /// Set a verifier-provided 32-byte freshness nonce. Clears any existing signature.
    pub fn set_verifier_nonce(&mut self, nonce: [u8; 32]) {
        self.verifier_nonce = Some(nonce);
        self.packet_signature = None;
        self.signing_public_key = None;
    }

    /// Ed25519-sign the packet. Binds to verifier nonce if one is set.
    pub fn sign(&mut self, signing_key: &SigningKey) -> crate::error::Result<()> {
        let payload = self.signing_payload()?;
        let signature = signing_key.sign(&payload);
        self.packet_signature = Some(signature.to_bytes());
        self.signing_public_key = Some(signing_key.verifying_key().to_bytes());
        Ok(())
    }

    /// Sign the packet and attach an author DID.
    pub fn sign_with_did(
        &mut self,
        signing_key: &SigningKey,
        author_did: Option<&str>,
    ) -> crate::error::Result<()> {
        self.author_did = author_did.map(String::from);
        self.sign(signing_key)?;
        Ok(())
    }

    /// Convenience: set nonce and sign in one call.
    pub fn sign_with_nonce(
        &mut self,
        signing_key: &SigningKey,
        nonce: [u8; 32],
    ) -> crate::error::Result<()> {
        self.set_verifier_nonce(nonce);
        self.sign(signing_key)
    }

    /// Compute the entangled hash for hardware co-signature.
    ///
    /// Binds document content, software signature, device time, and device identity
    /// into a single hash that the TPM/Secure Enclave signs.
    fn compute_hw_cosign_hash(
        doc_hash: &[u8],
        sw_signature: &[u8; 64],
        tpm_clock_ms: u64,
        monotonic_counter: u64,
        device_id: &str,
        public_key: &[u8],
        prev_hw_signature: &[u8],
    ) -> [u8; 32] {
        super::types::compute_hw_entangled_hash(
            doc_hash,
            sw_signature,
            tpm_clock_ms,
            monotonic_counter,
            device_id,
            public_key,
            prev_hw_signature,
        )
    }

    /// Add a self-entangled hardware co-signature from a TPM/Secure Enclave.
    ///
    /// Must be called AFTER `sign()`. The hardware signature covers:
    /// `SHA-256(DST || H(doc) || S_sw || clock || counter || device_id || S_hw(N-1))`
    ///
    /// This creates a 5-way binding: document + evidence + time + device + chain.
    /// Each co-signature depends on the previous one, forming a hardware-signed
    /// causal chain that cannot be forged without the full history.
    pub fn cosign_hardware(
        &mut self,
        tpm_provider: &dyn tpm::Provider,
        prev_cosignature: Option<&super::types::HardwareCosignature>,
    ) -> crate::error::Result<()> {
        let sw_sig = self.packet_signature.ok_or_else(|| {
            Error::signature("must sign with software key before hardware co-sign")
        })?;

        let doc_hash = self.document.final_hash.as_bytes();

        let clock_info = tpm_provider
            .clock_info()
            .map_err(|e| Error::crypto(format!("TPM clock: {e}")))?;

        let caps = tpm_provider.capabilities();
        let counter = clock_info.clock;

        let prev_sig = prev_cosignature
            .map(|c| c.signature.as_slice())
            .unwrap_or(&[]);
        let chain_index = prev_cosignature.map(|c| c.chain_index + 1).unwrap_or(0);

        let entangled_hash = Self::compute_hw_cosign_hash(
            doc_hash,
            &sw_sig,
            clock_info.clock,
            counter,
            &tpm_provider.device_id(),
            &tpm_provider.public_key(),
            prev_sig,
        );

        let signature = tpm_provider
            .sign(&entangled_hash)
            .map_err(|e| Error::crypto(format!("hardware co-sign: {e}")))?;

        self.hardware_cosignature = Some(super::types::HardwareCosignature {
            entangled_hash: entangled_hash.to_vec(),
            signature,
            public_key: tpm_provider.public_key(),
            device_id: tpm_provider.device_id(),
            tpm_clock_ms: clock_info.clock,
            monotonic_counter: counter,
            provider_type: if caps.hardware_backed {
                "hardware".to_string()
            } else {
                "software".to_string()
            },
            algorithm: format!("{:?}", tpm_provider.algorithm()),
            salt_commitment: None,
            prev_hw_signature: Some(prev_sig.to_vec()),
            chain_index,
            binding_type: Some("ed25519".to_string()),
        });

        Ok(())
    }

    /// Verify the hardware co-signature against the packet's software signature,
    /// document hash, and chain linkage.
    ///
    /// `prev_cosignature`: the previous co-signature in the chain for self-entanglement
    /// verification, or `None` for the genesis co-signature (chain_index must be 0).
    pub fn verify_hardware_cosignature(
        &self,
        prev_cosignature: Option<&super::types::HardwareCosignature>,
    ) -> crate::error::Result<()> {
        let cosig = self
            .hardware_cosignature
            .as_ref()
            .ok_or_else(|| Error::signature("no hardware co-signature present"))?;

        let sw_sig = self
            .packet_signature
            .ok_or_else(|| Error::signature("no software signature for co-sign verification"))?;

        // Verify chain linkage
        match (prev_cosignature, cosig.chain_index) {
            (None, 0) => {} // Genesis: no previous required
            (Some(prev), idx) if idx > 0 => {
                let stored_prev = cosig.prev_hw_signature.as_deref().unwrap_or(&[]);
                if stored_prev.len() != prev.signature.len()
                    || !bool::from(stored_prev.ct_eq(prev.signature.as_slice()))
                {
                    return Err(Error::signature(
                        "hardware co-signature chain broken: prev_hw_signature mismatch",
                    ));
                }
            }
            (None, idx) if idx > 0 => {
                return Err(Error::signature(format!(
                    "hardware co-signature chain_index is {idx} but no previous co-signature provided"
                )));
            }
            (Some(_), 0) => {
                return Err(Error::signature(
                    "hardware co-signature chain_index is 0 but previous co-signature provided",
                ));
            }
            _ => {}
        }

        let prev_sig = prev_cosignature
            .map(|c| c.signature.as_slice())
            .unwrap_or(&[]);

        let doc_hash = self.document.final_hash.as_bytes();

        let expected_hash = Self::compute_hw_cosign_hash(
            doc_hash,
            &sw_sig,
            cosig.tpm_clock_ms,
            cosig.monotonic_counter,
            &cosig.device_id,
            &cosig.public_key,
            prev_sig,
        );

        if expected_hash.ct_eq(&cosig.entangled_hash).unwrap_u8() != 1 {
            return Err(Error::signature(
                "hardware co-signature entangled hash mismatch; document, signature, or chain was modified",
            ));
        }

        tpm::verify_signature_for_provider(
            &cosig.provider_type,
            &cosig.public_key,
            &cosig.entangled_hash,
            &cosig.signature,
        )
        .map_err(|e| Error::signature(format!("hardware co-signature invalid: {e}")))?;

        Ok(())
    }

    /// Verify the packet signature, optionally checking `expected_nonce`
    /// to prevent replay attacks.
    pub fn verify_signature(&self, expected_nonce: Option<&[u8; 32]>) -> crate::error::Result<()> {
        match (expected_nonce, &self.verifier_nonce) {
            (Some(expected), Some(actual)) => {
                if expected.ct_eq(actual).unwrap_u8() != 1 {
                    return Err(Error::signature("verifier nonce mismatch"));
                }
            }
            (Some(_), None) => {
                return Err(Error::signature("expected verifier nonce but none present"));
            }
            // Nonce present but not expected is fine -- signature still binds to it
            (None, Some(_)) => {}
            (None, None) => {}
        }

        let signature_bytes = self
            .packet_signature
            .ok_or_else(|| Error::signature("packet not signed"))?;
        let public_key_bytes = self
            .signing_public_key
            .ok_or_else(|| Error::signature("missing signing public key"))?;

        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| Error::signature(format!("invalid public key: {e}")))?;

        let signature = Signature::from_bytes(&signature_bytes);

        let payload = self.signing_payload()?;
        public_key
            .verify(&payload, &signature)
            .map_err(|e| Error::signature(format!("signature verification failed: {e}")))?;

        Ok(())
    }

    /// Return true if a verifier nonce is set.
    pub fn has_verifier_nonce(&self) -> bool {
        self.verifier_nonce.is_some()
    }

    /// Return true if the packet has both a signature and public key.
    pub fn is_signed(&self) -> bool {
        self.packet_signature.is_some() && self.signing_public_key.is_some()
    }

    /// Derive trust tier: `Attested` > `NonceBound` > `Signed` > `Local`.
    pub fn compute_trust_tier(&self) -> super::types::TrustTier {
        use super::types::TrustTier;

        if self.writersproof_certificate_id.is_some() {
            TrustTier::Attested
        } else if self.is_signed() && self.has_verifier_nonce() {
            TrustTier::NonceBound
        } else if self.is_signed() {
            TrustTier::Signed
        } else {
            TrustTier::Local
        }
    }

    /// Convert to `PacketRfc` with integer keys for compact CBOR encoding.
    pub fn to_rfc(&self) -> Result<rfc::PacketRfc, super::rfc_conversion::RfcConversionError> {
        rfc::PacketRfc::try_from(self)
    }
}
