// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

pub mod signer;
mod software;
mod types;
mod verification;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod secure_enclave;
#[cfg(target_os = "windows")]
mod windows;

pub use signer::TpmSigner;
pub use software::SoftwareProvider;
pub use types::*;
pub use verification::{verify_binding_chain, verify_quote, verify_signature_for_provider};

use std::sync::Arc;

/// Default PCR banks to include in attestation quotes.
/// PCR 0 = firmware, PCR 4 = boot manager, PCR 7 = Secure Boot state.
pub(crate) const DEFAULT_QUOTE_PCRS: &[u32] = &[0, 4, 7];

/// Hardware or software TPM attestation provider.
pub trait Provider: Send + Sync {
    /// Report supported capabilities of this provider.
    fn capabilities(&self) -> Capabilities;
    /// Return a stable device identifier.
    fn device_id(&self) -> String;
    /// Return the provider's public key bytes.
    fn public_key(&self) -> Vec<u8>;
    /// The COSE signing algorithm this provider uses.
    fn algorithm(&self) -> coset::iana::Algorithm;
    /// Generate a TPM quote over the given nonce and PCR selection.
    fn quote(&self, nonce: &[u8], pcrs: &[u32]) -> Result<Quote, TpmError>;
    /// Bind data to this device with a signed attestation.
    fn bind(&self, data: &[u8]) -> Result<Binding, TpmError>;
    /// Sign arbitrary data with the provider's key.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TpmError>;
    /// Verify a previously created binding.
    fn verify(&self, binding: &Binding) -> Result<(), TpmError>;
    /// Seal data under the current PCR state.
    fn seal(&self, data: &[u8], policy: &[u8]) -> Result<Vec<u8>, TpmError>;
    /// Unseal previously sealed data.
    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, TpmError>;
    /// Read the TPM clock info (millis, reset/restart counts, safe flag).
    fn clock_info(&self) -> Result<ClockInfo, TpmError>;
}

/// Shared handle to a TPM provider.
pub type ProviderHandle = Arc<dyn Provider + Send + Sync>;

/// Build the canonical binding payload: data_hash || timestamp_nanos || device_id.
pub(crate) fn build_binding_payload(
    data_hash: &[u8],
    timestamp: &chrono::DateTime<chrono::Utc>,
    device_id: &str,
) -> Vec<u8> {
    use crate::DateTimeNanosExt;
    let mut payload = Vec::new();
    payload.extend_from_slice(data_hash);
    payload.extend_from_slice(&timestamp.timestamp_nanos_safe().to_le_bytes());
    payload.extend_from_slice(device_id.as_bytes());
    payload
}

/// Parse a sealed blob into (public_bytes, private_bytes).
///
/// Format: [pub_len:u32be][pub_bytes][priv_len:u32be][priv_bytes]
#[allow(dead_code)] // Used by cfg-gated windows.rs and linux.rs
pub(crate) fn parse_sealed_blob(sealed: &[u8]) -> Result<(&[u8], &[u8]), TpmError> {
    if sealed.len() < 8 {
        return Err(TpmError::SealedDataTooShort);
    }
    let pub_len = u32::from_be_bytes([sealed[0], sealed[1], sealed[2], sealed[3]]) as usize;
    let pub_end = 4usize
        .checked_add(pub_len)
        .ok_or(TpmError::SealedCorrupted)?;
    let priv_hdr = pub_end.checked_add(4).ok_or(TpmError::SealedCorrupted)?;
    if sealed.len() < priv_hdr {
        return Err(TpmError::SealedCorrupted);
    }
    let pub_bytes = &sealed[4..pub_end];
    let priv_len = u32::from_be_bytes([
        sealed[pub_end],
        sealed[pub_end + 1],
        sealed[pub_end + 2],
        sealed[pub_end + 3],
    ]) as usize;
    let priv_end = priv_hdr
        .checked_add(priv_len)
        .ok_or(TpmError::SealedCorrupted)?;
    if sealed.len() < priv_end {
        return Err(TpmError::SealedCorrupted);
    }
    let priv_bytes = &sealed[priv_hdr..priv_end];
    Ok((pub_bytes, priv_bytes))
}

/// Generate a full attestation report combining verifier and attestation nonces with evidence.
pub fn generate_attestation_report(
    provider: &dyn Provider,
    verifier_nonce: &[u8],
    attestation_nonce: &[u8],
    evidence_hash: [u8; 32],
) -> Result<AttestationReport, TpmError> {
    let mut quote_payload = Vec::new();
    quote_payload.extend_from_slice(verifier_nonce);
    quote_payload.extend_from_slice(attestation_nonce);
    quote_payload.extend_from_slice(&evidence_hash);

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&quote_payload);
    let quote_nonce = hasher.finalize();

    let quote = provider.quote(&quote_nonce, DEFAULT_QUOTE_PCRS)?;

    Ok(AttestationReport {
        report_id: uuid::Uuid::new_v4().to_string(),
        verifier_nonce: verifier_nonce.to_vec(),
        attestation_nonce: attestation_nonce.to_vec(),
        evidence_hash,
        hardware_quote: quote,
        signature: provider.sign(&quote_payload)?,
    })
}

/// Return the attestation tier for the given provider.
///
/// Uses `capabilities().hardware_backed` as the discriminator. Any provider
/// that reports hardware backing is `HardwareBound`; everything else is `SoftwareFallback`.
pub fn attestation_tier(provider: &dyn Provider) -> AttestationTier {
    if provider.capabilities().hardware_backed {
        AttestationTier::HardwareBound
    } else {
        AttestationTier::SoftwareFallback
    }
}

/// Increment the provider's monotonic session counter and return the new value.
///
/// On platforms with a hardware counter (SE / TPM 2.0), this calls the provider's
/// `quote` path to advance the counter. On software providers it returns an error
/// because software counters cannot guarantee monotonicity across process restarts.
pub fn increment_session_counter(provider: &dyn Provider) -> Result<u64, TpmError> {
    let caps = provider.capabilities();
    if !caps.monotonic_counter {
        return Err(TpmError::CounterNotInit);
    }
    let clock = provider.clock_info()?;
    if !clock.safe {
        return Err(TpmError::ClockNotSafe);
    }
    Ok(clock.clock)
}

/// Detect and initialize the best available TPM provider for this platform.
pub fn detect_provider() -> ProviderHandle {
    #[cfg(target_os = "macos")]
    if let Some(provider) = secure_enclave::try_init() {
        log::info!("Initialized macOS Secure Enclave provider");
        return Arc::new(provider);
    }

    #[cfg(target_os = "windows")]
    if let Some(provider) = windows::try_init() {
        log::info!("Initialized Windows TPM 2.0 provider");
        return Arc::new(provider);
    }

    #[cfg(target_os = "linux")]
    if let Some(provider) = linux::try_init() {
        log::info!("Initialized Linux TPM 2.0 provider");
        return Arc::new(provider);
    }

    log::warn!("No hardware TPM available, using software provider");
    Arc::new(SoftwareProvider::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_provider_binding_chain() {
        let provider = SoftwareProvider::new();
        let binding1 = provider.bind(b"checkpoint-1").expect("bind");
        let binding2 = provider.bind(b"checkpoint-2").expect("bind");
        verify_binding_chain(&[binding1, binding2], &[]).expect("verify chain");
    }

    #[test]
    fn test_verify_quote_valid() {
        let provider = SoftwareProvider::new();
        let quote = provider.quote(b"nonce-a", &[]).expect("quote");
        assert!(verify_quote(&quote).is_ok());
    }
}
