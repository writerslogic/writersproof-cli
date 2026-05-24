// SPDX-License-Identifier: Apache-2.0

use coset::CborSerializable;
use ed25519_dalek::VerifyingKey;
use sha2::Digest;

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

    if manifest.claim.claim_generator_info.is_empty()
        || manifest.claim.claim_generator_info[0].name.is_empty()
    {
        errors.push("claim_generator_info must contain at least one entry with a non-empty name".to_string());
    }

    if manifest.claim.instance_id.is_empty() {
        errors.push("instanceID must not be empty".to_string());
    }

    if manifest.claim.signature.is_empty() {
        errors.push("signature URI must not be empty".to_string());
    }

    let expected_hash_len = match manifest.claim.alg.as_deref() {
        Some("sha384") => 48,
        Some("sha512") => 64,
        _ => 32,
    };
    for (i, assertion) in manifest.claim.created_assertions.iter().enumerate() {
        if assertion.hash.len() != expected_hash_len {
            errors.push(format!(
                "created_assertions[{i}] hash length {} != {expected_hash_len}",
                assertion.hash.len()
            ));
            continue;
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
        let computed_hash = hash_assertion_box(&box_bytes[8..], manifest.claim.alg.as_deref());
        if subtle::ConstantTimeEq::ct_eq(
            assertion_ref.hash.as_slice(),
            computed_hash.as_slice(),
        )
        .unwrap_u8()
            == 0
        {
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
///
/// The C2PA signature uses detached payload mode (§13.2), so the claim CBOR
/// is reattached from `manifest.claim_cbor` before verification.
pub fn verify_manifest_signature(manifest: &C2paManifest) -> Result<bool> {
    let mut sign1 = coset::CoseSign1::from_slice(&manifest.signature)
        .map_err(|e| Error::Crypto(format!("failed to parse COSE_Sign1: {e}")))?;

    // Reattach detached payload for verification.
    if sign1.payload.is_none() {
        sign1.payload = Some(manifest.claim_cbor.clone());
    }

    let pk_bytes = extract_public_key(&sign1)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| Error::Crypto(format!("invalid Ed25519 public key: {e}")))?;

    match crate::crypto::verify_cose_sign1_ed25519(&sign1, &vk) {
        Ok(()) => Ok(true),
        Err(e) => {
            log::debug!("COSE_Sign1 verification failed (x5chain key): {e}");
            Ok(false)
        }
    }
}

/// Verify the COSE_Sign1 signature on a manifest against a known public key.
pub fn verify_manifest_with_key(
    manifest: &C2paManifest,
    public_key: &[u8; 32],
) -> Result<bool> {
    let mut sign1 = coset::CoseSign1::from_slice(&manifest.signature)
        .map_err(|e| Error::Crypto(format!("failed to parse COSE_Sign1: {e}")))?;

    if sign1.payload.is_none() {
        sign1.payload = Some(manifest.claim_cbor.clone());
    }

    let vk = VerifyingKey::from_bytes(public_key)
        .map_err(|e| Error::Crypto(format!("invalid Ed25519 public key: {e}")))?;

    match crate::crypto::verify_cose_sign1_ed25519(&sign1, &vk) {
        Ok(()) => Ok(true),
        Err(e) => {
            log::debug!("COSE_Sign1 verification failed (explicit key): {e}");
            Ok(false)
        }
    }
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

/// Hash assertion box content using the algorithm specified in the claim.
fn hash_assertion_box(data: &[u8], alg: Option<&str>) -> Vec<u8> {
    match alg {
        Some("sha384") => sha2::Sha384::digest(data).to_vec(),
        Some("sha512") => sha2::Sha512::digest(data).to_vec(),
        _ => sha2::Sha256::digest(data).to_vec(),
    }
}

/// Returns true iff `url` ends with `/{label}` — an exact path-segment match.
fn url_has_label(url: &str, label: &str) -> bool {
    url.len() > label.len()
        && url.as_bytes()[url.len() - label.len() - 1] == b'/'
        && url.ends_with(label)
}

