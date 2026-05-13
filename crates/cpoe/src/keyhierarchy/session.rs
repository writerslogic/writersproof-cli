// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce as AeadNonce,
};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use sha2::Digest;
use zeroize::Zeroizing;

use super::crypto::{
    build_cert_data_with_expiry, compute_entangled_nonce, hkdf_expand, RATCHET_ADVANCE_DOMAIN,
    RATCHET_INIT_DOMAIN, SESSION_DOMAIN, SIGNING_KEY_DOMAIN,
};
use super::error::KeyHierarchyError;

/// Domain separator for chain metadata signatures, distinct from per-checkpoint signing.
const CHAIN_METADATA_DOMAIN: &str = "cpoe-chain-metadata-signing-v1";
use super::types::{
    CheckpointSignature, KeyHierarchyEvidence, MasterIdentity, PufProvider, RatchetState, Session,
    SessionCertificate, SessionRecoveryState, VERSION,
};

use super::identity::derive_master_private_key;

pub(crate) fn start_session_inner(
    signing_key: &SigningKey,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    let master_pub_key = signing_key.verifying_key().to_bytes();

    let mut session_id = [0u8; 32];
    rand::rng().fill_bytes(&mut session_id);

    let created_at = Utc::now();
    let session_input = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&session_id);
        bytes.extend_from_slice(created_at.to_rfc3339().as_bytes());
        bytes
    };

    let key_bytes = Zeroizing::new(signing_key.to_bytes());
    let session_seed = hkdf_expand(
        key_bytes.as_slice(),
        SESSION_DOMAIN.as_bytes(),
        &session_input,
    )?;
    drop(key_bytes);
    // NOTE: ed25519_dalek::SigningKey holds a copy of the seed internally. The SigningKey is
    // dropped at end of scope, but the internal copy is not zeroized. This is a known
    // limitation tracked as SYS-033.
    let session_key = SigningKey::from_bytes(&session_seed);
    let session_pub = session_key.verifying_key().to_bytes();
    let expires_at = Some(created_at + chrono::Duration::hours(24));
    let cert_data = build_cert_data_with_expiry(
        session_id,
        &session_pub,
        created_at,
        document_hash,
        expires_at,
    );
    let signature = signing_key.sign(&cert_data).to_bytes();

    let certificate = SessionCertificate {
        session_id,
        session_pubkey: session_pub,
        created_at,
        document_hash,
        master_pubkey: master_pub_key,
        signature,
        version: VERSION,
        expires_at,
        start_quote: None,
        end_quote: None,
        start_counter: None,
        end_counter: None,
        start_reset_count: None,
        start_restart_count: None,
        end_reset_count: None,
        end_restart_count: None,
    };

    // hkdf_expand returns Zeroizing<[u8; 32]>, so the intermediate is cleared
    // on drop. ProtectedKey::from_zeroizing transfers ownership. SYS-033 residual.
    let ratchet_init = hkdf_expand(session_seed.as_slice(), RATCHET_INIT_DOMAIN.as_bytes(), &[])?;
    let ratchet_key = crate::crypto::mem::ProtectedKey::from_zeroizing(ratchet_init);

    Ok(Session {
        certificate,
        ratchet: RatchetState {
            current: ratchet_key,
            ordinal: 0,
            wiped: false,
        },
        signatures: Vec::new(),
        export_count: 0,
    })
}

pub fn start_session_with_key(
    master_key: &SigningKey,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    start_session_inner(master_key, document_hash)
}

pub fn start_session(
    puf: &dyn PufProvider,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    let master_key = derive_master_private_key(puf)?;
    start_session_inner(&master_key, document_hash)
}

impl Session {
    pub fn sign_checkpoint(
        &mut self,
        checkpoint_hash: [u8; 32],
    ) -> Result<CheckpointSignature, KeyHierarchyError> {
        if self.ratchet.wiped {
            return Err(KeyHierarchyError::RatchetWiped);
        }

        let signing_seed = hkdf_expand(
            self.ratchet.current.as_bytes(),
            SIGNING_KEY_DOMAIN.as_bytes(),
            &[],
        )?;
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let signature = signing_key.sign(&checkpoint_hash).to_bytes();

        // Lamport one-shot signature: derive a separate key from the ratchet
        // using a distinct domain separator so the two schemes are independent.
        let lamport_seed =
            hkdf_expand(self.ratchet.current.as_bytes(), b"cpoe-lamport-key-v1", &[])?;
        let (lamport_privkey, lamport_pubkey) =
            crate::crypto::lamport::LamportPrivateKey::from_seed(&lamport_seed);
        let lamport_sig = lamport_privkey.sign(&checkpoint_hash);

        let next_ratchet = hkdf_expand(
            self.ratchet.current.as_bytes(),
            RATCHET_ADVANCE_DOMAIN.as_bytes(),
            &checkpoint_hash,
        )?;

        let current_ordinal = self.ratchet.ordinal;
        self.ratchet.current = crate::crypto::ProtectedKey::from_zeroizing(next_ratchet);
        self.ratchet.ordinal += 1;

        let sig = CheckpointSignature {
            ordinal: current_ordinal,
            public_key,
            signature,
            checkpoint_hash,
            counter_value: None,
            counter_delta: None,
            lamport_signature: Some(lamport_sig.to_bytes().to_vec()),
            lamport_pubkey_fingerprint: Some(lamport_pubkey.fingerprint().to_vec()),
            lamport_public_key: Some(lamport_pubkey.to_bytes().to_vec()),
        };
        self.signatures.push(sig.clone());
        Ok(sig)
    }

    /// Sign a checkpoint with hardware counter integration.
    ///
    /// If a TPM provider is available, binds the checkpoint to the hardware
    /// counter and hashes the counter delta into the ratchet advance.
    pub fn sign_checkpoint_with_counter(
        &mut self,
        checkpoint_hash: [u8; 32],
        provider: &dyn crate::tpm::Provider,
        sealed_store: Option<&crate::sealed_identity::SealedIdentityStore>,
    ) -> Result<CheckpointSignature, KeyHierarchyError> {
        if self.ratchet.wiped {
            return Err(KeyHierarchyError::RatchetWiped);
        }

        let binding = provider.bind(&checkpoint_hash).map_err(|e| {
            log::warn!("TPM bind failed (falling back to software-only): {e}");
            e
        }).ok();
        let current_counter = binding.as_ref().and_then(|b| b.monotonic_counter);

        let previous_counter = self.signatures.last().and_then(|s| s.counter_value);
        let counter_delta = match (current_counter, previous_counter) {
            (Some(curr), Some(prev)) => Some(curr.saturating_sub(prev)),
            (Some(_), None) => Some(0),
            _ => None,
        };

        let signing_seed = hkdf_expand(
            self.ratchet.current.as_bytes(),
            SIGNING_KEY_DOMAIN.as_bytes(),
            &[],
        )?;
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let signature = signing_key.sign(&checkpoint_hash).to_bytes();

        // Lamport one-shot signature
        let lamport_seed =
            hkdf_expand(self.ratchet.current.as_bytes(), b"cpoe-lamport-key-v1", &[])?;
        let (lamport_privkey, lamport_pubkey) =
            crate::crypto::lamport::LamportPrivateKey::from_seed(&lamport_seed);
        let lamport_sig = lamport_privkey.sign(&checkpoint_hash);

        // Hash counter_delta into the ratchet advance
        let mut ratchet_input = checkpoint_hash.to_vec();
        if let Some(delta) = counter_delta {
            ratchet_input.extend_from_slice(&delta.to_be_bytes());
        }
        let next_ratchet = hkdf_expand(
            self.ratchet.current.as_bytes(),
            RATCHET_ADVANCE_DOMAIN.as_bytes(),
            &ratchet_input,
        )?;

        let current_ordinal = self.ratchet.ordinal;
        self.ratchet.current = crate::crypto::ProtectedKey::from_zeroizing(next_ratchet);
        self.ratchet.ordinal += 1;

        if let (Some(store), Some(counter)) = (sealed_store, current_counter) {
            if let Err(e) = store.advance_counter(counter) {
                log::warn!("Failed to advance sealed counter: {}", e);
            }
        }

        let sig = CheckpointSignature {
            ordinal: current_ordinal,
            public_key,
            signature,
            checkpoint_hash,
            counter_value: current_counter,
            counter_delta,
            lamport_signature: Some(lamport_sig.to_bytes().to_vec()),
            lamport_pubkey_fingerprint: Some(lamport_pubkey.fingerprint().to_vec()),
            lamport_public_key: Some(lamport_pubkey.to_bytes().to_vec()),
        };
        self.signatures.push(sig.clone());
        Ok(sig)
    }

    pub fn end(&mut self) {
        if !self.ratchet.wiped {
            self.ratchet.wiped = true;
        }
    }

    /// Generates closing quote with chain-entangled nonce for time-travel detection.
    pub fn end_with_provider(&mut self, provider: &dyn crate::tpm::Provider, mmr_root: &[u8; 32]) {
        let final_checkpoint_hash = self
            .signatures
            .last()
            .map(|s| s.checkpoint_hash)
            .unwrap_or([0u8; 32]);
        let closing_nonce = compute_entangled_nonce(
            &self.certificate.session_id,
            &final_checkpoint_hash,
            mmr_root,
        );

        if let Ok(quote) = provider.quote(&closing_nonce, &[0, 4, 7]) {
            self.certificate.end_quote = serde_json::to_vec(&quote)
                .map_err(|e| {
                    log::warn!("TPM quote serialization failed: {e}");
                    e
                })
                .ok();
        }

        if let Ok(binding) = provider.bind(&closing_nonce) {
            self.certificate.end_counter = binding.monotonic_counter;
        }
        if let Ok(clock) = provider.clock_info() {
            self.certificate.end_reset_count = Some(clock.reset_count);
            self.certificate.end_restart_count = Some(clock.restart_count);
        }

        self.end();
    }

    /// Bind session start to TPM state with chain-entangled nonce.
    pub fn bind_start_quote(&mut self, provider: &dyn crate::tpm::Provider, mmr_root: &[u8; 32]) {
        let start_nonce = compute_entangled_nonce(
            &self.certificate.session_id,
            &self.certificate.document_hash,
            mmr_root,
        );

        if let Ok(quote) = provider.quote(&start_nonce, &[0, 4, 7]) {
            self.certificate.start_quote = serde_json::to_vec(&quote)
                .map_err(|e| {
                    log::warn!("TPM quote serialization failed: {e}");
                    e
                })
                .ok();
        }

        if let Ok(binding) = provider.bind(&start_nonce) {
            self.certificate.start_counter = binding.monotonic_counter;
        }

        if let Ok(clock) = provider.clock_info() {
            self.certificate.start_reset_count = Some(clock.reset_count);
            self.certificate.start_restart_count = Some(clock.restart_count);
        }
    }

    /// Sign chain metadata with the current ratchet key.
    ///
    /// Signs `SHA256("cpoe-chain-metadata-v1" || checkpoint_count || mmr_root || mmr_leaf_count)`.
    /// This makes checkpoint deletion detectable: changing the count breaks the signature.
    pub fn sign_chain_metadata(
        &mut self,
        metadata: &mut crate::checkpoint::ChainIntegrityMetadata,
    ) -> Result<(), KeyHierarchyError> {
        if self.ratchet.wiped {
            return Err(KeyHierarchyError::RatchetWiped);
        }

        let payload = crate::checkpoint_mmr::metadata_signing_payload(metadata);

        let signing_seed = hkdf_expand(
            self.ratchet.current.as_bytes(),
            CHAIN_METADATA_DOMAIN.as_bytes(),
            &[],
        )?;
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let signature = signing_key.sign(&payload).to_bytes();

        metadata.metadata_signature = Some(signature.to_vec());

        let next_ratchet = hkdf_expand(
            self.ratchet.current.as_bytes(),
            RATCHET_ADVANCE_DOMAIN.as_bytes(),
            &payload,
        )?;
        self.ratchet.current = crate::crypto::ProtectedKey::from_zeroizing(next_ratchet);
        self.ratchet.ordinal += 1;

        Ok(())
    }

    pub fn signatures(&self) -> Vec<CheckpointSignature> {
        self.signatures.clone()
    }

    pub fn current_ordinal(&self) -> u64 {
        self.ratchet.ordinal
    }

    pub fn export(&self, identity: &MasterIdentity) -> KeyHierarchyEvidence {
        let mut evidence = KeyHierarchyEvidence {
            version: VERSION as i32,
            master_identity: Some(identity.clone()),
            session_certificate: Some(self.certificate.clone()),
            checkpoint_signatures: self.signatures.clone(),
            master_fingerprint: identity.fingerprint.clone(),
            master_public_key: identity.public_key.to_vec(),
            device_id: identity.device_id.clone(),
            session_id: hex::encode(self.certificate.session_id),
            session_public_key: self.certificate.session_pubkey.to_vec(),
            session_started: self.certificate.created_at,
            session_certificate_raw: self.certificate.signature.to_vec(),
            ratchet_count: i32::try_from(self.signatures.len()).unwrap_or(i32::MAX),
            ratchet_public_keys: Vec::new(),
            hardware_attestation: None,
        };

        for sig in &self.signatures {
            evidence.ratchet_public_keys.push(sig.public_key.to_vec());
        }

        evidence
    }

    pub fn export_recovery_state(
        &mut self,
        puf: &dyn PufProvider,
    ) -> Result<SessionRecoveryState, KeyHierarchyError> {
        if self.ratchet.wiped {
            return Err(KeyHierarchyError::RatchetWiped);
        }

        let challenge = sha2::Sha256::digest(b"cpoe-ratchet-recovery-v2");
        let response = Zeroizing::new(puf.get_response(&challenge)?);
        let key = hkdf_expand(&response, b"ratchet-recovery-key-v2", &[])?;

        self.export_count += 1;
        let mut plaintext = Zeroizing::new(vec![0u8; 48]);
        plaintext[..32].copy_from_slice(self.ratchet.current.as_bytes());
        plaintext[32..40].copy_from_slice(&self.ratchet.ordinal.to_be_bytes());
        plaintext[40..48].copy_from_slice(&self.export_count.to_be_bytes());

        let cipher = ChaCha20Poly1305::new_from_slice(&*key)
            .map_err(|e| KeyHierarchyError::Crypto(format!("AEAD init: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| KeyHierarchyError::Crypto(format!("rng: {e}")))?;
        let aead_nonce = AeadNonce::from_slice(&nonce_bytes);

        let aad = (self.signatures.len() as u64).to_be_bytes();
        let ciphertext = cipher
            .encrypt(
                aead_nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|e| KeyHierarchyError::Crypto(format!("AEAD encrypt: {e}")))?;

        let mut encrypted = Vec::with_capacity(1 + 12 + ciphertext.len());
        encrypted.push(0x02); // version 2 = AEAD
        encrypted.extend_from_slice(&nonce_bytes);
        encrypted.extend_from_slice(&ciphertext);

        Ok(SessionRecoveryState {
            certificate: self.certificate.clone(),
            signatures: self.signatures.clone(),
            last_ratchet_state: encrypted,
            export_count: self.export_count,
        })
    }
}
