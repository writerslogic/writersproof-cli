// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI bindings for ISO mDoc-style authorship credentials.

use super::helpers::{load_signing_key, open_store};
use super::types::try_ffi;
use crate::credentials::AuthorshipCredential;

// ---------------------------------------------------------------------------
// FFI types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCredentialResult {
    pub success: bool,
    pub credential_cbor_hex: Option<String>,
    pub document_hash_hex: Option<String>,
    pub error_message: Option<String>,
}

impl FfiCredentialResult {
    fn ok(cbor_hex: String, doc_hash_hex: String) -> Self {
        Self {
            success: true,
            credential_cbor_hex: Some(cbor_hex),
            document_hash_hex: Some(doc_hash_hex),
            error_message: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            credential_cbor_hex: None,
            document_hash_hex: None,
            error_message: Some(msg.into()),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSignedCredentialResult {
    pub success: bool,
    pub signed_cbor_hex: Option<String>,
    pub error_message: Option<String>,
}

impl FfiSignedCredentialResult {
    fn ok(signed_hex: String) -> Self {
        Self {
            success: true,
            signed_cbor_hex: Some(signed_hex),
            error_message: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            signed_cbor_hex: None,
            error_message: Some(msg.into()),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiVerificationResult {
    pub success: bool,
    pub is_valid_signature: bool,
    pub attestation_tier: Option<String>,
    pub session_id: Option<String>,
    pub error_message: Option<String>,
}

impl FfiVerificationResult {
    fn ok(tier: String, session_id: String) -> Self {
        Self {
            success: true,
            is_valid_signature: true,
            attestation_tier: Some(tier),
            session_id: Some(session_id),
            error_message: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            is_valid_signature: false,
            attestation_tier: None,
            session_id: None,
            error_message: Some(msg.into()),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCredentialStatusResult {
    pub success: bool,
    pub is_valid: bool,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub issuer: String,
    pub error_message: Option<String>,
}

impl FfiCredentialStatusResult {
    fn ok(valid: bool, issued: i64, expires: i64, issuer: String) -> Self {
        Self {
            success: true,
            is_valid: valid,
            issued_at_ms: issued,
            expires_at_ms: expires,
            issuer,
            error_message: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            is_valid: false,
            issued_at_ms: 0,
            expires_at_ms: 0,
            issuer: String::new(),
            error_message: Some(msg.into()),
        }
    }
}

impl super::types::FfiErrResult for FfiCredentialResult {
    fn ffi_err(msg: impl Into<String>) -> Self {
        Self::err(msg)
    }
}

impl super::types::FfiErrResult for FfiSignedCredentialResult {
    fn ffi_err(msg: impl Into<String>) -> Self {
        Self::err(msg)
    }
}

impl super::types::FfiErrResult for FfiVerificationResult {
    fn ffi_err(msg: impl Into<String>) -> Self {
        Self::err(msg)
    }
}

impl super::types::FfiErrResult for FfiCredentialStatusResult {
    fn ffi_err(msg: impl Into<String>) -> Self {
        Self::err(msg)
    }
}

// ---------------------------------------------------------------------------
// Exported FFI functions
// ---------------------------------------------------------------------------

/// Create an authorship credential from a session's text fragments.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_create_authorship_credential(
    session_id: String,
    attestation_tier: String,
    process_verdict: String,
    confidence: f64,
) -> FfiCredentialResult {
    if session_id.is_empty() {
        return FfiCredentialResult::err("Session ID is required");
    }
    if !confidence.is_finite() {
        return FfiCredentialResult::err("Confidence must be a finite number");
    }
    let confidence = confidence.clamp(0.0, 1.0);

    let store = try_ffi!(open_store(), FfiCredentialResult);
    let fragments = try_ffi!(
        store
            .get_fragments_for_session(&session_id)
            .map_err(|e| format!("Failed to load fragments: {e}")),
        FfiCredentialResult
    );

    if fragments.is_empty() {
        return FfiCredentialResult::err("No text fragments found for session");
    }

    let author_did = super::helpers::load_did().ok();

    let credential = AuthorshipCredential::from_session(
        &session_id,
        &fragments,
        &attestation_tier,
        &process_verdict,
        confidence,
        author_did.as_deref(),
    );

    let doc_hash_hex = hex::encode(&credential.claims.document_hash);

    match credential.to_cbor() {
        Ok(cbor) => FfiCredentialResult::ok(hex::encode(cbor), doc_hash_hex),
        Err(e) => FfiCredentialResult::err(format!("Failed to encode credential: {e}")),
    }
}

/// Sign a credential with the device signing key.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sign_credential(credential_cbor_hex: String) -> FfiSignedCredentialResult {
    let cbor_bytes = match hex::decode(&credential_cbor_hex) {
        Ok(b) => b,
        Err(e) => return FfiSignedCredentialResult::err(format!("Invalid hex: {e}")),
    };

    let mut credential = match AuthorshipCredential::from_cbor(&cbor_bytes) {
        Ok(c) => c,
        Err(e) => return FfiSignedCredentialResult::err(format!("Invalid credential CBOR: {e}")),
    };

    let signing_key = try_ffi!(
        load_signing_key().map_err(|e| format!("Signing key unavailable: {e}")),
        FfiSignedCredentialResult
    );

    match credential.sign_cose(&signing_key) {
        Ok(signed) => FfiSignedCredentialResult::ok(hex::encode(signed)),
        Err(e) => FfiSignedCredentialResult::err(format!("Signing failed: {e}")),
    }
}

/// Verify a signed credential's COSE_Sign1 envelope.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_verify_credential(
    signed_cbor_hex: String,
    public_key_hex: String,
) -> FfiVerificationResult {
    let signed_bytes = match hex::decode(&signed_cbor_hex) {
        Ok(b) => b,
        Err(e) => return FfiVerificationResult::err(format!("Invalid signed hex: {e}")),
    };

    let pk_bytes = match hex::decode(&public_key_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return FfiVerificationResult::err("public_key_hex must be 64 hex chars (32 bytes)"),
    };

    let vk = match ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(e) => return FfiVerificationResult::err(format!("Invalid public key: {e}")),
    };

    match AuthorshipCredential::verify_cose(&signed_bytes, &vk) {
        Ok(credential) => FfiVerificationResult::ok(
            credential.claims.attestation_tier,
            credential.claims.session_id,
        ),
        Err(e) => FfiVerificationResult::err(format!("Verification failed: {e}")),
    }
}

/// Get credential status (valid/expired) from CBOR bytes.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_credential_status(credential_cbor_hex: String) -> FfiCredentialStatusResult {
    let cbor_bytes = match hex::decode(&credential_cbor_hex) {
        Ok(b) => b,
        Err(e) => return FfiCredentialStatusResult::err(format!("Invalid hex: {e}")),
    };

    let credential = match AuthorshipCredential::from_cbor(&cbor_bytes) {
        Ok(c) => c,
        Err(e) => return FfiCredentialStatusResult::err(format!("Invalid credential CBOR: {e}")),
    };

    FfiCredentialStatusResult::ok(
        credential.is_valid(),
        credential.validity.issued_at,
        credential.validity.expires_at,
        credential.validity.issuer,
    )
}
