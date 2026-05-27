// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

mod attestation;
mod counter;
mod key_management;
mod platform;
mod sealing;
mod signing;
mod types;

#[cfg(test)]
mod tests;

pub use types::SecureEnclaveProvider;
#[allow(unused_imports)]
pub use types::{KeyAttestation, SecureEnclaveKeyInfo};

use counter::{load_counter, save_counter};
use key_management::{load_device_id, load_or_create_attestation_key, load_or_create_key};
use platform::{collect_hardware_info, is_secure_enclave_available, writersproof_dir};
use signing::sign;
use types::{HardwareInfo, SecureEnclaveState};

use super::{Attestation, Binding, Capabilities, Provider, Quote, TpmError};
use crate::MutexRecover;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::ptr::null_mut;
use std::sync::Mutex;
use std::time::SystemTime;

/// Initialize the Secure Enclave provider, returning `None` if unavailable.
pub fn try_init() -> Option<SecureEnclaveProvider> {
    // Under `cargo test --lib`, always skip the real Secure Enclave so
    // tests fall back to the software provider and never trigger a
    // keychain / biometric prompt.
    if cfg!(test) {
        return None;
    }
    if !is_secure_enclave_available() {
        return None;
    }

    let base_dir = match writersproof_dir() {
        Ok(d) => d,
        Err(e) => {
            log::error!("Secure Enclave init failed: {e}");
            return None;
        }
    };
    let counter_file = base_dir.join("se_counter");

    let mut state = SecureEnclaveState {
        key_ref: null_mut(),
        attestation_key_ref: None,
        device_id: String::new(),
        public_key: Vec::new(),
        attestation_public_key: None,
        counter: 0,
        counter_file,
        start_time: SystemTime::now(),
        hardware_info: HardwareInfo::default(),
    };

    if init_state(&mut state).is_err() {
        return None;
    }

    let cached_device_id = state.device_id.clone();
    let cached_public_key = state.public_key.clone();

    Some(SecureEnclaveProvider {
        state: Mutex::new(state),
        cached_device_id,
        cached_public_key,
    })
}

fn init_state(state: &mut SecureEnclaveState) -> Result<(), TpmError> {
    state.hardware_info = collect_hardware_info();
    state.hardware_info.se_available = true;

    state.device_id = load_device_id()?;

    load_or_create_key(state)?;

    if let Err(e) = load_or_create_attestation_key(state) {
        log::warn!("Could not create attestation key: {}", e);
    }

    load_counter(state)?;
    state.start_time = SystemTime::now();
    Ok(())
}

impl Provider for SecureEnclaveProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_backed: true,
            supports_pcrs: false,
            supports_sealing: true,
            supports_attestation: true,
            monotonic_counter: true,
            secure_clock: false,
        }
    }

    fn device_id(&self) -> String {
        self.cached_device_id.clone()
    }

    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::ES256
    }

    fn public_key(&self) -> Vec<u8> {
        self.cached_public_key.clone()
    }

    fn quote(&self, nonce: &[u8], _pcrs: &[u32]) -> Result<Quote, TpmError> {
        let state = self.state.lock_recover();
        let timestamp = Utc::now();
        let payload = crate::tpm::build_binding_payload(nonce, &timestamp, &state.device_id);

        let signature = sign(&state, &payload)?;

        Ok(Quote {
            provider_type: "secure-enclave".to_string(),
            device_id: state.device_id.clone(),
            timestamp,
            nonce: nonce.to_vec(),
            attested_data: payload,
            signature,
            public_key: state.public_key.clone(),
            pcr_values: Vec::new(),
            extra: Default::default(),
        })
    }

    fn bind(&self, data: &[u8]) -> Result<Binding, TpmError> {
        let mut state = self.state.lock_recover();

        let timestamp = Utc::now();
        let data_hash = Sha256::digest(data).to_vec();
        let next_counter = state.counter + 1;
        let payload = super::build_binding_payload(&data_hash, &timestamp, &state.device_id);

        let signature = sign(&state, &payload)?;

        // Persist counter only after signing succeeds to avoid gaps
        state.counter = next_counter;
        let _ = save_counter(&state);

        Ok(Binding {
            version: 1,
            provider_type: "secure-enclave".to_string(),
            device_id: state.device_id.clone(),
            timestamp,
            attested_hash: data_hash,
            signature,
            public_key: state.public_key.clone(),
            monotonic_counter: Some(state.counter),
            safe_clock: None,
            attestation: Some(Attestation {
                payload,
                quote: None,
            }),
        })
    }

    fn verify(&self, binding: &Binding) -> Result<(), TpmError> {
        crate::tpm::verification::verify_binding(binding)
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        let state = self.state.lock_recover();
        sign(&state, data)
    }

    fn seal(&self, data: &[u8], policy: &[u8]) -> Result<Vec<u8>, TpmError> {
        self.seal_impl(data, policy)
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, TpmError> {
        self.unseal_impl(sealed)
    }

    fn clock_info(&self) -> Result<super::ClockInfo, TpmError> {
        let state = self.state.lock_recover();
        let elapsed = u64::try_from(state.start_time.elapsed().unwrap_or_default().as_millis())
            .unwrap_or(u64::MAX);
        Ok(super::ClockInfo {
            clock: elapsed,
            reset_count: 0,
            restart_count: 0,
            safe: false,
        })
    }
}
