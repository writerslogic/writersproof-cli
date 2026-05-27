// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::{Binding, Capabilities, Provider, Quote, TpmError};
use crate::MutexRecover;
use chrono::Utc;
use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Software-only TPM provider for development and testing.
///
/// The signing key is automatically zeroized on drop via ed25519-dalek's
/// `ZeroizeOnDrop` implementation (enabled by the `zeroize` crate feature).
pub struct SoftwareProvider {
    signing_key: ed25519_dalek::SigningKey,
    state: Mutex<SoftwareState>,
}

struct SoftwareState {
    device_id: String,
    counter: u64,
}

impl Default for SoftwareProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftwareProvider {
    /// Create a new software TPM provider, returning an error if the OS RNG
    /// is unavailable.
    pub fn try_new() -> std::result::Result<Self, TpmError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut_slice()).map_err(|e| {
            log::error!("OS RNG unavailable: {e}");
            TpmError::NotAvailable
        })?;
        let seed_hash = Sha256::digest(seed.as_slice());
        let device_id = format!("sw-{}", crate::utils::short_hex_id(&seed_hash));
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        Ok(Self {
            signing_key,
            state: Mutex::new(SoftwareState {
                device_id,
                counter: 0,
            }),
        })
    }

    /// Create a new software TPM provider.
    ///
    /// # Panics
    /// Panics if the OS RNG is unavailable (should never happen on supported platforms).
    pub fn new() -> Self {
        Self::try_new().expect("OS RNG unavailable — cannot create software TPM")
    }

    /// Create a provider from an existing signing key.
    pub fn from_signing_key(key: ed25519_dalek::SigningKey) -> Self {
        let pk_hash = Sha256::digest(key.verifying_key().as_bytes());
        let device_id = format!("sw-{}", crate::utils::short_hex_id(&pk_hash));
        Self {
            signing_key: key,
            state: Mutex::new(SoftwareState {
                device_id,
                counter: 0,
            }),
        }
    }

    fn sign_payload(&self, data: &[u8]) -> Vec<u8> {
        self.signing_key.sign(data).to_bytes().to_vec()
    }
}

impl Provider for SoftwareProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_backed: false,
            supports_pcrs: false,
            supports_sealing: false,
            supports_attestation: true,
            monotonic_counter: true,
            secure_clock: false,
        }
    }

    fn device_id(&self) -> String {
        self.state.lock_recover().device_id.clone()
    }

    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::EdDSA
    }

    fn public_key(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    fn quote(&self, nonce: &[u8], _pcrs: &[u32]) -> Result<Quote, TpmError> {
        let device_id = self.device_id();
        let timestamp = Utc::now();
        let payload = super::build_binding_payload(nonce, &timestamp, &device_id);

        let signature = self.sign_payload(&payload);
        let public_key = self.public_key();

        Ok(Quote {
            provider_type: "software".to_string(),
            device_id,
            timestamp,
            nonce: nonce.to_vec(),
            attested_data: payload,
            signature,
            public_key,
            pcr_values: Vec::new(),
            extra: Default::default(),
        })
    }

    fn bind(&self, data: &[u8]) -> Result<Binding, TpmError> {
        let mut state = self.state.lock_recover();
        state.counter += 1;

        let data_hash = Sha256::digest(data).to_vec();
        let timestamp = Utc::now();
        let payload = super::build_binding_payload(&data_hash, &timestamp, &state.device_id);

        let signature = self.sign_payload(&payload);
        let public_key = self.public_key();

        Ok(Binding {
            version: 1,
            provider_type: "software".to_string(),
            device_id: state.device_id.clone(),
            timestamp,
            attested_hash: data_hash,
            signature,
            public_key,
            monotonic_counter: Some(state.counter),
            safe_clock: None,
            attestation: Some(super::Attestation {
                payload,
                quote: None,
            }),
        })
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        Ok(self.sign_payload(data))
    }

    fn verify(&self, binding: &Binding) -> Result<(), TpmError> {
        crate::tpm::verification::verify_binding(binding)
    }

    fn seal(&self, _data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::Sealing("software provider cannot seal".into()))
    }

    fn unseal(&self, _sealed: &[u8]) -> Result<Vec<u8>, TpmError> {
        Err(TpmError::Unsealing(
            "software provider cannot unseal".into(),
        ))
    }

    fn clock_info(&self) -> Result<super::ClockInfo, TpmError> {
        Ok(super::ClockInfo {
            clock: 0,
            reset_count: 0,
            restart_count: 0,
            safe: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_provider_lifecycle() {
        let provider = SoftwareProvider::new();

        let caps = provider.capabilities();
        assert!(!caps.hardware_backed);
        assert!(caps.supports_attestation);
        assert!(caps.monotonic_counter);
        assert!(!caps.supports_sealing);

        let device_id = provider.device_id();
        assert!(device_id.starts_with("sw-"));

        let data = b"test-binding";
        let binding = provider.bind(data).expect("bind failed");
        assert_eq!(binding.provider_type, "software");
        assert_eq!(binding.device_id, device_id);

        provider.verify(&binding).expect("verify failed");

        let nonce = b"nonce";
        let quote = provider.quote(nonce, &[]).expect("quote failed");
        assert_eq!(quote.nonce, nonce);
        crate::tpm::verify_quote(&quote).expect("quote verify failed");

        let binding2 = provider.bind(data).expect("bind 2");
        assert!(binding2.monotonic_counter.unwrap() > binding.monotonic_counter.unwrap());

        assert!(provider.seal(b"secret", &[]).is_err());
        assert!(provider.unseal(b"sealed").is_err());

        let info = provider.clock_info().expect("clock_info failed");
        assert_eq!(info.clock, 0);
        assert_eq!(info.reset_count, 0);
        assert_eq!(info.restart_count, 0);
        assert!(!info.safe);
    }
}

impl std::fmt::Debug for SoftwareProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareProvider").finish_non_exhaustive()
    }
}
