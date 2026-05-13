// SPDX-License-Identifier: Apache-2.0

use coset::CborSerializable;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

use super::types::{C2paManifest, ValidationResult};
use super::{ASSERTION_LABEL_ACTIONS, ASSERTION_LABEL_HASH_DATA};

/// §15.10.1.2 standard manifest validation.
///
/// Performs structural validation and verifies the COSE_Sign1 Ed25519
/// signature against the public key embedded in the x5chain protected header.
/// Parse failures during signature verification are reported as warnings
/// rather than errors to allow structural validation to succeed independently.
pub fn validate_manifest(manifest: &C2paManifest) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let hard_binding_count = manifest
        .claim
        .created_assertions
        .iter()
        .filter(|a| url_has_label(&a.url, ASSERTION_LABEL_HASH_DATA))
        .count();
    if hard_binding_count != 1 {
        errors.push(format!(
            "Standard manifest requires exactly 1 hard binding, found {hard_binding_count}"
        ));
    }

    let actions_count = manifest
        .claim
        .created_assertions
        .iter()
        .filter(|a| url_has_label(&a.url, ASSERTION_LABEL_ACTIONS))
        .count();
    if actions_count != 1 {
        errors.push(format!(
            "Standard manifest requires exactly 1 actions assertion, found {actions_count}"
        ));
    }

    for (i, assertion) in manifest.claim.created_assertions.iter().enumerate() {
        if !assertion.url.contains(&manifest.manifest_label) {
            errors.push(format!(
                "created_assertions[{i}].url does not contain manifest label '{}'",
                manifest.manifest_label
            ));
        }
    }

    if !manifest.claim.signature.contains(&manifest.manifest_label) {
        errors.push(format!(
            "signature URI does not contain manifest label '{}'",
            manifest.manifest_label
        ));
    }

    if manifest.claim.claim_generator_info.is_empty() {
        errors.push("claim_generator_info must have at least one entry".to_string());
    } else if manifest.claim.claim_generator_info[0].name.is_empty() {
        // Safe: is_empty() guard above ensures [0] exists.
        errors.push("claim_generator_info[0].name must not be empty".to_string());
    }

    if manifest.claim.instance_id.is_empty() {
        errors.push("instanceID must not be empty".to_string());
    }

    if manifest.claim.signature.is_empty() {
        errors.push("signature URI must not be empty".to_string());
    }

    for (i, assertion) in manifest.claim.created_assertions.iter().enumerate() {
        if assertion.hash.len() != 32 {
            errors.push(format!(
                "created_assertions[{i}] hash length {} != 32",
                assertion.hash.len()
            ));
        }
        if assertion.url.is_empty() {
            errors.push(format!("created_assertions[{i}] has empty URL"));
        }
    }

    if manifest.assertion_boxes.len() != manifest.claim.created_assertions.len() {
        errors.push(format!(
            "assertion_boxes count ({}) != created_assertions count ({})",
            manifest.assertion_boxes.len(),
            manifest.claim.created_assertions.len()
        ));
    }

    for (i, (assertion_ref, box_bytes)) in manifest
        .claim
        .created_assertions
        .iter()
        .zip(manifest.assertion_boxes.iter())
        .enumerate()
    {
        if box_bytes.len() < 8 {
            errors.push(format!("assertion_boxes[{i}] too short"));
            continue;
        }
        let computed_hash = Sha256::digest(&box_bytes[8..]);
        if assertion_ref.hash != computed_hash.as_slice() {
            errors.push(format!(
                "created_assertions[{i}] hash mismatch: claim has {}, box hashes to {}",
                hex::encode(&assertion_ref.hash),
                hex::encode(computed_hash)
            ));
        }
    }

    if manifest.signature.is_empty() {
        errors.push("COSE_Sign1 signature is empty".to_string());
    } else {
        match verify_manifest_signature(manifest) {
            Ok(true) => {}
            Ok(false) => {
                errors.push("COSE_Sign1 signature verification failed".to_string());
            }
            Err(e) => {
                warnings.push(format!("Could not verify COSE_Sign1 signature: {e}"));
            }
        }
    }

    if manifest.manifest_label.is_empty() {
        warnings.push("manifest_label is empty".to_string());
    }

    ValidationResult { errors, warnings }
}

/// Verify the COSE_Sign1 signature on a manifest using the embedded x5chain key.
///
/// Extracts the public key from the x5chain header (either a raw 32-byte key
/// or a DER-encoded X.509 certificate) and verifies the signature.
pub fn verify_manifest_signature(manifest: &C2paManifest) -> Result<bool> {
    let sign1 = coset::CoseSign1::from_slice(&manifest.signature)
        .map_err(|e| Error::Crypto(format!("failed to parse COSE_Sign1: {e}")))?;

    let pk_bytes = extract_public_key(&sign1)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| Error::Crypto(format!("invalid Ed25519 public key: {e}")))?;

    verify_cose_sign1_ed25519(&sign1, &vk)
}

/// Verify the COSE_Sign1 signature on a manifest against a known public key.
pub fn verify_manifest_with_key(
    manifest: &C2paManifest,
    public_key: &[u8; 32],
) -> Result<bool> {
    let sign1 = coset::CoseSign1::from_slice(&manifest.signature)
        .map_err(|e| Error::Crypto(format!("failed to parse COSE_Sign1: {e}")))?;

    let vk = VerifyingKey::from_bytes(public_key)
        .map_err(|e| Error::Crypto(format!("invalid Ed25519 public key: {e}")))?;

    verify_cose_sign1_ed25519(&sign1, &vk)
}

/// Extract the Ed25519 public key from x5chain (label 33) in the protected header.
///
/// Handles both raw 32-byte public keys (legacy) and DER-encoded X.509
/// certificates (C2PA-compliant).
fn extract_public_key(sign1: &coset::CoseSign1) -> Result<[u8; 32]> {
    let pk_value = sign1
        .protected
        .header
        .rest
        .iter()
        .find(|(label, _)| *label == coset::Label::Int(33))
        .map(|(_, v)| v)
        .ok_or_else(|| {
            Error::Crypto("COSE_Sign1 protected header missing x5chain (label 33)".to_string())
        })?;

    match pk_value {
        ciborium::Value::Bytes(bytes) if bytes.len() == 32 => {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(bytes);
            Ok(pk)
        }
        ciborium::Value::Bytes(bytes) if bytes.len() > 32 => {
            super::cert::extract_public_key_from_cert(bytes)
        }
        ciborium::Value::Bytes(bytes) => Err(Error::Crypto(format!(
            "x5chain value too short: expected >=32 bytes, got {}",
            bytes.len()
        ))),
        _ => Err(Error::Crypto(
            "x5chain header value must be a byte string".to_string(),
        )),
    }
}

/// Returns true iff `url` ends with `/{label}` — an exact path-segment match.
///
/// Prevents bypass via prefix labels (e.g. "c2pa.hash.data-extra" matching
/// "c2pa.hash.data") that `str::contains` would incorrectly accept.
fn url_has_label(url: &str, label: &str) -> bool {
    url.ends_with(&format!("/{label}"))
}

/// Verify a COSE_Sign1 Ed25519 signature.
fn verify_cose_sign1_ed25519(
    sign1: &coset::CoseSign1,
    vk: &VerifyingKey,
) -> Result<bool> {
    let result = sign1.verify_signature(&[], |sig, sig_data| {
        let signature = Signature::from_slice(sig)
            .map_err(|e| Error::Crypto(format!("invalid signature format: {e}")))?;
        vk.verify(sig_data, &signature)
            .map_err(|e| Error::Crypto(format!("signature verification failed: {e}")))
    });

    match result {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}
