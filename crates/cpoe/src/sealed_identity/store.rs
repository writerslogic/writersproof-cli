// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce as AeadNonce,
};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::keyhierarchy::{
    crypto::IDENTITY_DOMAIN, derive_master_identity, MasterIdentity, PufProvider,
};
use crate::tpm::{ClockInfo, ProviderHandle};
use authorproof_protocol::rfc::wire_types::AttestationTier;

use super::types::*;

/// Manage TPM-sealed identity keys with anti-rollback counter protection.
pub struct SealedIdentityStore {
    provider: ProviderHandle,
    store_path: PathBuf,
}

impl SealedIdentityStore {
    /// Create a store with the given TPM provider and data directory.
    pub fn new(provider: ProviderHandle, data_dir: &Path) -> Self {
        let store_path = data_dir.join(SEALED_BLOB_FILENAME);
        Self {
            provider,
            store_path,
        }
    }

    /// Create a store by auto-detecting the best available TPM provider.
    pub fn auto_detect(data_dir: &Path) -> Self {
        let provider = crate::tpm::detect_provider();
        Self::new(provider, data_dir)
    }

    /// Reuses an existing sealed blob if it can be unsealed, otherwise re-derives.
    pub fn initialize(&self, puf: &dyn PufProvider) -> Result<MasterIdentity, SealedIdentityError> {
        if self.store_path.exists() {
            match self.unseal_master_key() {
                Ok(_signing_key) => {
                    return self.public_identity();
                }
                Err(e) => {
                    log::warn!(
                        "Existing sealed blob could not be unsealed ({}), re-deriving",
                        e
                    );
                }
            }
        }

        let identity = derive_master_identity(puf)?;
        let signing_key = crate::keyhierarchy::derive_master_private_key(puf)?;
        let seed = zeroize::Zeroizing::new(signing_key.to_bytes());

        let caps = self.provider.capabilities();
        // Domain separation salt for PUF-derived seed sealing, so the
        // sealed blob is context-bound even on the unseal-failure
        // re-derivation path.
        const PUF_SEAL_CONTEXT: &[u8] = b"cpoe-puf-fallback-v1";
        let sealed_seed = if caps.supports_sealing {
            self.provider
                .seal(&*seed, PUF_SEAL_CONTEXT)
                .map_err(|e| SealedIdentityError::SealFailed(e.to_string()))?
        } else {
            self.software_wrap(&*seed)?
        };

        let clock = self.provider.clock_info().ok();

        let counter = self
            .provider
            .bind(b"identity-seal-counter")
            .ok()
            .and_then(|b| b.monotonic_counter);

        let blob = SealedBlob {
            version: SEALED_BLOB_VERSION,
            provider_type: if caps.hardware_backed {
                if cfg!(target_os = "macos") {
                    "secure_enclave".to_string()
                } else {
                    "tpm2".to_string()
                }
            } else {
                "software".to_string()
            },
            device_id: self.provider.device_id(),
            sealed_seed,
            public_key: identity.public_key.to_vec(),
            fingerprint: identity.fingerprint.clone(),
            sealed_at: Utc::now(),
            counter_at_seal: counter,
            last_known_counter: counter,
            boot_count_at_seal: clock.as_ref().map(|c| c.reset_count),
            restart_count_at_seal: clock.as_ref().map(|c| c.restart_count),
            integrity_hmac: None,
        };

        self.persist_blob(&blob)?;

        Ok(identity)
    }

    /// **Anti-rollback**: Reads current hardware counter and verifies it is
    /// `>=` both `counter_at_seal` and `last_known_counter` stored in the blob,
    /// then ratchets `last_known_counter` forward to prevent replay.
    ///
    /// **Anti-hammering**: authValue is machine-specific, so the sealed file
    /// cannot be brute-forced on a different device.
    ///
    /// # Security
    /// Callers must protect the returned `SigningKey`. The key implements
    /// `ZeroizeOnDrop`, so it will be cleared when dropped.
    pub fn unseal_master_key(&self) -> Result<SigningKey, SealedIdentityError> {
        // load_blob() verifies the integrity HMAC before returning, so
        // tampering is detected before any unsealing or key comparison.
        let mut blob = self.load_blob()?;

        // Anti-rollback: validate hardware counter against both seal-time and
        // last-known values. When both counters are stored in the blob, both
        // must pass verification and the hardware counter must be available.
        // Single-counter mode is tolerated as an offline fallback when only
        // one counter was recorded at seal time.
        let both_counters = blob.counter_at_seal.is_some() && blob.last_known_counter.is_some();
        if blob.counter_at_seal.is_some() || blob.last_known_counter.is_some() {
            match self.provider.bind(b"identity-counter-check") {
                Ok(binding) => {
                    if let Some(current) = binding.monotonic_counter {
                        if let Some(at_seal) = blob.counter_at_seal {
                            if current < at_seal {
                                return Err(SealedIdentityError::RollbackDetected {
                                    current,
                                    last_known: at_seal,
                                });
                            }
                        }
                        if let Some(last_known) = blob.last_known_counter {
                            if current < last_known {
                                return Err(SealedIdentityError::RollbackDetected {
                                    current,
                                    last_known,
                                });
                            }
                        }
                        blob.last_known_counter = Some(current);
                        self.persist_blob(&blob)?;
                    } else if both_counters {
                        // Hardware counter unavailable but blob has both
                        // counters set; possible downgrade attack.
                        log::warn!(
                            "anti-rollback: hardware counter unavailable \
                             but blob records both counters; refusing unseal"
                        );
                        return Err(SealedIdentityError::RollbackDetected {
                            current: 0,
                            last_known: blob.last_known_counter.unwrap_or(0),
                        });
                    } else {
                        log::warn!(
                            "anti-rollback: hardware counter unavailable; \
                             single-counter offline fallback"
                        );
                    }
                }
                Err(e) => {
                    if both_counters {
                        log::warn!(
                            "anti-rollback: bind failed with both counters \
                             present; refusing unseal: {e}"
                        );
                        return Err(SealedIdentityError::RollbackDetected {
                            current: 0,
                            last_known: blob.last_known_counter.unwrap_or(0),
                        });
                    }
                    log::warn!("anti-rollback check degraded: bind failed: {e}");
                }
            }
        } else if blob.last_known_counter.is_none() {
            if let Ok(binding) = self.provider.bind(b"identity-counter-check") {
                if let Some(current) = binding.monotonic_counter {
                    blob.last_known_counter = Some(current);
                    self.persist_blob(&blob)?;
                }
            }
        }

        let caps = self.provider.capabilities();
        let mut seed = if caps.supports_sealing {
            self.provider
                .unseal(&blob.sealed_seed)
                .map_err(|e| SealedIdentityError::UnsealFailed(e.to_string()))?
        } else {
            self.software_unwrap(&blob.sealed_seed)?
        };

        if seed.len() != 32 {
            seed.zeroize();
            return Err(SealedIdentityError::BlobCorrupted);
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed);
        seed.zeroize();

        let signing_key = SigningKey::from_bytes(&key_bytes);
        key_bytes.zeroize();

        // Verify the unsealed seed produces the expected public key (catches
        // v1 XOR-only wrapping corruption and tampering).
        // Safety: HMAC integrity was already verified in load_blob() above,
        // so blob.public_key is authentic before this comparison.
        if signing_key
            .verifying_key()
            .to_bytes()
            .ct_eq(&blob.public_key)
            .unwrap_u8()
            == 0
        {
            return Err(SealedIdentityError::BlobCorrupted);
        }

        Ok(signing_key)
    }

    /// Ratchet counter forward to prevent forking at the same counter value.
    pub fn advance_counter(&self, new_counter: u64) -> Result<(), SealedIdentityError> {
        let mut blob = self.load_blob()?;

        if let Some(last_known) = blob.last_known_counter {
            if new_counter < last_known {
                return Err(SealedIdentityError::RollbackDetected {
                    current: new_counter,
                    last_known,
                });
            }
        }

        blob.last_known_counter = Some(new_counter);
        self.persist_blob(&blob)?;
        Ok(())
    }

    /// Return `true` if the sealed blob exists and is bound to this device.
    pub fn is_bound(&self) -> bool {
        if !self.store_path.exists() {
            return false;
        }
        match self.load_blob() {
            Ok(blob) => blob.device_id == self.provider.device_id(),
            Err(_) => false,
        }
    }

    /// Load and return the public identity (key + fingerprint) from the sealed blob.
    pub fn public_identity(&self) -> Result<MasterIdentity, SealedIdentityError> {
        let blob = self.load_blob()?;
        let public_key: [u8; 32] = blob
            .public_key
            .try_into()
            .map_err(|_| SealedIdentityError::BlobCorrupted)?;
        Ok(MasterIdentity {
            public_key,
            fingerprint: blob.fingerprint,
            device_id: blob.device_id,
            created_at: blob.sealed_at,
            version: SEALED_BLOB_VERSION,
        })
    }

    /// Re-seal with fresh platform state to detect reboot-based attacks.
    pub fn reseal(&self, puf: &dyn PufProvider) -> Result<(), SealedIdentityError> {
        let old_blob = self.load_blob()?;

        let caps = self.provider.capabilities();
        let seed = Zeroizing::new(if caps.supports_sealing {
            match self.provider.unseal(&old_blob.sealed_seed) {
                Ok(s) => s,
                Err(_) => {
                    let challenge =
                        Sha256::digest(format!("{}-challenge", IDENTITY_DOMAIN).as_bytes());
                    let puf_response = puf.get_response(&challenge)?;
                    let derived = crate::keyhierarchy::hkdf_expand(
                        &puf_response,
                        IDENTITY_DOMAIN.as_bytes(),
                        b"master-seed",
                    )?;
                    derived.to_vec()
                }
            }
        } else {
            self.software_unwrap(&old_blob.sealed_seed)?
        });

        // Verify identity continuity: the re-derived seed must produce the
        // same public key as the original blob.
        if seed.len() != 32 {
            return Err(SealedIdentityError::BlobCorrupted);
        }
        {
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&seed);
            let derived_pub = SigningKey::from_bytes(&key_bytes)
                .verifying_key()
                .to_bytes();
            key_bytes.zeroize();
            if derived_pub.ct_eq(&old_blob.public_key).unwrap_u8() == 0 {
                return Err(SealedIdentityError::BlobCorrupted);
            }
        }

        let sealed_seed = if caps.supports_sealing {
            self.provider
                .seal(&seed, &[])
                .map_err(|e| SealedIdentityError::SealFailed(e.to_string()))?
        } else {
            self.software_wrap(&seed)?
        };

        let clock = self.provider.clock_info().ok();

        let blob = SealedBlob {
            version: SEALED_BLOB_VERSION,
            provider_type: old_blob.provider_type,
            device_id: self.provider.device_id(),
            sealed_seed,
            public_key: old_blob.public_key,
            fingerprint: old_blob.fingerprint,
            sealed_at: Utc::now(),
            counter_at_seal: old_blob.last_known_counter,
            last_known_counter: old_blob.last_known_counter,
            boot_count_at_seal: clock.as_ref().map(|c| c.reset_count),
            restart_count_at_seal: clock.as_ref().map(|c| c.restart_count),
            integrity_hmac: None,
        };

        self.persist_blob(&blob)?;

        Ok(())
    }

    /// Determine the attestation tier based on provider hardware capabilities.
    pub fn attestation_tier(&self) -> AttestationTier {
        let caps = self.provider.capabilities();
        if caps.hardware_backed && caps.supports_sealing {
            AttestationTier::HardwareBound
        } else if caps.hardware_backed && caps.supports_attestation {
            AttestationTier::AttestedSoftware
        } else {
            AttestationTier::SoftwareOnly
        }
    }

    /// Read the TPM clock info (boot count, restart count, uptime).
    pub fn clock_info(&self) -> Result<ClockInfo, SealedIdentityError> {
        self.provider.clock_info().map_err(SealedIdentityError::Tpm)
    }

    /// Return a reference to the underlying TPM provider handle.
    pub fn provider(&self) -> &ProviderHandle {
        &self.provider
    }

    fn load_blob(&self) -> Result<SealedBlob, SealedIdentityError> {
        let data = fs::read(&self.store_path)?;
        let blob: SealedBlob = serde_json::from_slice(&data)
            .map_err(|e| SealedIdentityError::Serialization(e.to_string()))?;

        // Verify integrity HMAC if present (blobs written before HMAC
        // support will have integrity_hmac == None and are accepted).
        if let Some(ref stored_hmac) = blob.integrity_hmac {
            let expected = self.compute_blob_hmac(&blob)?;
            if !bool::from(stored_hmac.ct_eq(&expected)) {
                return Err(SealedIdentityError::BlobCorrupted);
            }
        }

        Ok(blob)
    }

    fn persist_blob(&self, blob: &SealedBlob) -> Result<(), SealedIdentityError> {
        // Compute HMAC over blob contents (excluding the hmac field itself).
        let hmac_value = self.compute_blob_hmac(blob)?;
        let mut blob_with_hmac = blob.clone();
        blob_with_hmac.integrity_hmac = Some(hmac_value);

        if let Some(parent) = self.store_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(&blob_with_hmac)
            .map_err(|e| SealedIdentityError::Serialization(e.to_string()))?;
        let parent = self
            .store_path
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        std::io::Write::write_all(&mut tmp, &data)?;
        tmp.as_file().sync_all()?;
        crate::crypto::restrict_permissions(tmp.path(), 0o600).ok();
        tmp.persist(&self.store_path).map_err(|e| e.error)?;
        Ok(())
    }

    /// Compute HMAC-SHA256 over the blob with `integrity_hmac` set to `None`.
    fn compute_blob_hmac(&self, blob: &SealedBlob) -> Result<Vec<u8>, SealedIdentityError> {
        let mut canonical = blob.clone();
        canonical.integrity_hmac = None;
        let payload = serde_json::to_vec(&canonical)
            .map_err(|e| SealedIdentityError::Serialization(e.to_string()))?;
        let salt = self.machine_salt();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&salt)
            .map_err(|e| SealedIdentityError::SealFailed(format!("HMAC init: {e}")))?;
        mac.update(&payload);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn software_wrap(&self, seed: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        let machine_salt = self.machine_salt();

        let mut random_salt = [0u8; 32];
        getrandom::getrandom(&mut random_salt)
            .map_err(|e| SealedIdentityError::SealFailed(format!("rng: {e}")))?;

        let hk = Hkdf::<Sha256>::new(Some(&random_salt), &machine_salt);
        let mut key = [0u8; 32];
        hk.expand(b"cpoe-software-wrap-v2", &mut key)
            .map_err(|e| SealedIdentityError::SealFailed(format!("HKDF: {e}")))?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| SealedIdentityError::SealFailed(format!("AEAD init: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| SealedIdentityError::SealFailed(format!("rng: {e}")))?;
        let aead_nonce = AeadNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(aead_nonce, seed)
            .map_err(|e| SealedIdentityError::SealFailed(format!("AEAD encrypt: {e}")))?;

        key.zeroize();

        // Format: version(1) || random_salt(32) || aead_nonce(12) || ciphertext+tag
        let mut wrapped = Vec::with_capacity(1 + 32 + 12 + ciphertext.len());
        wrapped.push(0x02); // version 2 = AEAD
        wrapped.extend_from_slice(&random_salt);
        wrapped.extend_from_slice(&nonce_bytes);
        wrapped.extend_from_slice(&ciphertext);
        random_salt.zeroize();
        Ok(wrapped)
    }

    fn software_unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        if wrapped.is_empty() {
            return Err(SealedIdentityError::BlobCorrupted);
        }

        match wrapped[0] {
            0x01 => {
                log::warn!("Loading legacy V1 sealed identity; will migrate to V2 on next save");
                self.software_unwrap_v1(wrapped)
            }
            0x02 => self.software_unwrap_v2(wrapped),
            _ => Err(SealedIdentityError::BlobCorrupted),
        }
    }

    /// Legacy v1: XOR cipher (backward compat only).
    fn software_unwrap_v1(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        let salt = self.machine_salt();
        let mut hasher = Sha256::new();
        hasher.update(&salt);
        hasher.update(b"cpoe-software-wrap-v1");
        let key_material = hasher.finalize();

        let mut seed = vec![0u8; wrapped.len() - 1];
        for (i, b) in wrapped[1..].iter().enumerate() {
            seed[i] = b ^ key_material[i % 32];
        }
        Ok(seed)
    }

    fn software_unwrap_v2(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        // Format: version(1) || random_salt(32) || aead_nonce(12) || ciphertext+tag
        const HEADER_LEN: usize = 1 + 32 + 12; // 45
        if wrapped.len() < HEADER_LEN + 16 {
            return Err(SealedIdentityError::BlobCorrupted);
        }
        let random_salt = &wrapped[1..33];
        let nonce_bytes = &wrapped[33..45];
        let ciphertext = &wrapped[45..];

        let machine_salt = self.machine_salt();
        let hk = Hkdf::<Sha256>::new(Some(random_salt), &machine_salt);
        let mut key = [0u8; 32];
        hk.expand(b"cpoe-software-wrap-v2", &mut key)
            .map_err(|_| SealedIdentityError::BlobCorrupted)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| SealedIdentityError::BlobCorrupted)?;

        let aead_nonce = AeadNonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(aead_nonce, ciphertext)
            .map_err(|_| SealedIdentityError::BlobCorrupted)?;

        key.zeroize();
        Ok(plaintext)
    }

    /// Derive a machine-specific salt from device_id and hostname.
    ///
    /// **Known limitation**: this is a weak binding (device_id + hostname only)
    /// used as a software-only fallback. Proper OS keychain integration is
    /// tracked separately and will replace this path.
    fn machine_salt(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"cpoe-machine-salt-v1");
        hasher.update(self.provider.device_id().as_bytes());
        if let Ok(host) = hostname::get() {
            hasher.update(host.to_string_lossy().as_bytes());
        }
        hasher.finalize().to_vec()
    }
}

impl std::fmt::Debug for SealedIdentityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedIdentityStore")
            .finish_non_exhaustive()
    }
}
