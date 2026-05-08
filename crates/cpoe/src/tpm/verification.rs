// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::{Binding, Quote, TpmError};
use ed25519_dalek::Verifier as _;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use subtle::Choice;

pub fn verify_binding_chain(
    bindings: &[Binding],
    trusted_keys: &[Vec<u8>],
) -> Result<(), TpmError> {
    if bindings.is_empty() {
        return Ok(());
    }
    if trusted_keys.is_empty() {
        return Err(TpmError::Verification(
            "trusted_keys required for chain verification; self-trust is not permitted".into(),
        ));
    }

    let mut last_counter: Option<u64> = None;
    for (idx, binding) in bindings.iter().enumerate() {
        if let Some(prev) = last_counter {
            if let Some(counter) = binding.monotonic_counter {
                if counter <= prev {
                    return Err(TpmError::CounterRollback);
                }
            }
        }

        verify_binding_with_trusted(binding, trusted_keys)
            .map_err(|_| TpmError::Verification(format!("binding {} failed", idx)))?;

        last_counter = binding.monotonic_counter;
    }

    Ok(())
}

pub fn verify_binding(binding: &Binding) -> Result<(), TpmError> {
    verify_binding_with_trusted(binding, &[])
}

fn verify_binding_with_trusted(
    binding: &Binding,
    trusted_keys: &[Vec<u8>],
) -> Result<(), TpmError> {
    if binding.attested_hash.len() != 32 {
        return Err(TpmError::InvalidBinding);
    }

    if binding.safe_clock == Some(false) {
        return Err(TpmError::ClockNotSafe);
    }
    if binding.safe_clock.is_none() {
        log::warn!("TPM clock safety unknown for binding");
    }

    let payload = binding_payload(binding);

    // When trusted keys are provided, verify against them (ignoring the embedded key,
    // which could be attacker-supplied). Verifies ALL keys to avoid leaking which key
    // matched via timing side-channel.
    if !trusted_keys.is_empty() {
        let mut any_valid = Choice::from(0u8);
        for key in trusted_keys {
            let valid = verify_signature_for_provider(
                &binding.provider_type,
                key,
                &payload,
                &binding.signature,
            )
            .is_ok();
            any_valid |= Choice::from(valid as u8);
        }
        if bool::from(any_valid) {
            return Ok(());
        }
        return Err(TpmError::Verification(
            "signature did not match any trusted key".into(),
        ));
    }

    // No trusted keys provided; self-verify against embedded key (local-only use).
    // WARNING: this path trusts the binding's own key; callers must provide trusted
    // keys for remote/adversarial verification.
    if !binding.public_key.is_empty() {
        return verify_signature_for_provider(
            &binding.provider_type,
            &binding.public_key,
            &payload,
            &binding.signature,
        );
    }

    Err(TpmError::InvalidSignature)
}

fn binding_payload(binding: &Binding) -> Vec<u8> {
    super::build_binding_payload(
        &binding.attested_hash,
        &binding.timestamp,
        &binding.device_id,
    )
}

pub fn verify_quote(quote: &Quote) -> Result<(), TpmError> {
    if quote.attested_data.is_empty() {
        return Err(TpmError::Quote("empty quote payload".into()));
    }
    if quote.signature.is_empty() {
        return Err(TpmError::InvalidSignature);
    }

    if quote.public_key.is_empty() {
        return Err(TpmError::InvalidSignature);
    }

    verify_signature_for_provider(
        &quote.provider_type,
        &quote.public_key,
        &quote.attested_data,
        &quote.signature,
    )
}

pub fn verify_signature_for_provider(
    provider_type: &str,
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), TpmError> {
    // Use provider_type to select the expected algorithm, avoiding algorithm confusion.
    // Software providers always use Ed25519; Secure Enclave uses ECDSA-P256;
    // Linux/Windows TPM may use RSA or ECDSA depending on key type.
    match provider_type {
        "software" => {
            if let Some(result) = try_verify_ed25519(public_key, payload, signature) {
                return result;
            }
            Err(TpmError::InvalidSignature)
        }
        "secure-enclave" => {
            if let Some(result) = try_verify_ecdsa_p256(public_key, payload, signature) {
                return result;
            }
            Err(TpmError::InvalidSignature)
        }
        "tpm2-linux" | "tpm2-windows" => {
            // Hardware TPM: try ECDSA first (P-256 SRK), then RSA
            if let Some(result) = try_verify_ecdsa_p256(public_key, payload, signature) {
                return result;
            }
            if let Some(result) = try_verify_rsa(public_key, payload, signature) {
                return result;
            }
            Err(TpmError::UnsupportedPublicKey)
        }
        _ => Err(TpmError::NotAvailable),
    }
}

fn try_verify_ed25519(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Option<Result<(), TpmError>> {
    let key_bytes: [u8; 32] = public_key.try_into().ok()?;
    let sig_bytes: [u8; 64] = signature.try_into().ok()?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).ok()?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    Some(
        vk.verify_strict(payload, &sig)
            .map_err(|_| TpmError::InvalidSignature),
    )
}

fn try_verify_ecdsa_p256(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Option<Result<(), TpmError>> {
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).ok()?;
    // Raw r||s (64 bytes)
    if signature.len() == 64 {
        let sig = p256::ecdsa::Signature::from_slice(signature).ok()?;
        return Some(
            vk.verify(payload, &sig)
                .map_err(|_| TpmError::InvalidSignature),
        );
    }
    // DER-encoded
    let der_sig = p256::ecdsa::DerSignature::from_bytes(signature).ok()?;
    Some(
        vk.verify(payload, &der_sig)
            .map_err(|_| TpmError::InvalidSignature),
    )
}

fn try_verify_rsa(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Option<Result<(), TpmError>> {
    let key = rsa::RsaPublicKey::from_pkcs1_der(public_key)
        .or_else(|_| rsa::RsaPublicKey::from_public_key_der(public_key))
        .ok()?;
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key);
    let sig = rsa::pkcs1v15::Signature::try_from(signature).ok()?;
    Some(
        verifying_key
            .verify(payload, &sig)
            .map_err(|_| TpmError::InvalidSignature),
    )
}
