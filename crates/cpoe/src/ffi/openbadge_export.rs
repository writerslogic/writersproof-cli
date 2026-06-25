// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI entrypoints for Open Badges 3.0 (1EdTech) credential export.
//!
//! Mirrors [`crate::ffi::vc_export`] but projects the EAR token into an
//! `OpenBadgeCredential` instead of a W3C VC. The EAR build, signing key,
//! `eddsa-jcs-2022` proof, and verification logic are shared with the VC path.

use crate::ffi::types::{catch_ffi_panic, try_ffi, FfiErrResult, FfiResult, FfiVcVerifyResult};
use crate::ffi::vc_export::build_ear_and_report_for_path;
use crate::war::profiles::openbadge;

/// Derive the authorship mode (badge identity) from a built report: AI
/// disclosure from the signed declaration, writing/composition mode from the
/// forensic breakdown.
fn openbadge_mode_from_report(report: &crate::report::WarReport) -> openbadge::AuthorshipMode {
    let ai_disclosed = report
        .declaration_summary
        .as_ref()
        .map(|d| !d.ai_tools.is_empty())
        .unwrap_or(false);
    let writing_mode = report
        .forensic_metrics
        .as_ref()
        .map(|f| f.writing_mode.as_str());
    let composition_mode = report
        .forensic_metrics
        .as_ref()
        .and_then(|f| f.composition_mode.as_deref());
    openbadge::infer_authorship_mode(writing_mode, composition_mode, ai_disclosed)
}

/// Export a signed Open Badges 3.0 credential (Data Integrity / JSON).
///
/// Loads evidence from the store, builds an EAR token, and signs the badge with
/// the device Ed25519 key using the `eddsa-jcs-2022` cryptosuite. Writes
/// pretty-printed JSON to `output_path` via atomic rename.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_openbadge_json(
    evidence_path: String,
    document_path: String,
    output_path: String,
) -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    log::debug!(
        "ffi_export_openbadge_json: evidence_path={} document_path={} output_path={}",
        evidence_path, document_path, output_path
    );

    let out = try_ffi!(
        crate::sentinel::helpers::validate_path(&output_path)
            .map_err(|e| format!("Invalid output path: {e}")),
        FfiResult
    );

    let signing_key = try_ffi!(crate::ffi::helpers::load_signing_key(), FfiResult);
    let provider = crate::tpm::detect_provider();

    let (ear, author_did, report) = try_ffi!(
        build_ear_and_report_for_path(&evidence_path, &document_path, &signing_key),
        FfiResult
    );
    let mode = openbadge_mode_from_report(&report);

    let badge = try_ffi!(
        openbadge::to_signed_open_badge_credential(&ear, &author_did, mode, &*provider)
            .map_err(|e| e.to_string()),
        FfiResult
    );

    let json = try_ffi!(
        serde_json::to_string_pretty(&badge)
            .map_err(|e| format!("OpenBadge JSON serialization failed: {e}")),
        FfiResult
    );

    try_ffi!(crate::ffi::helpers::atomic_write(&out, json.as_bytes()), FfiResult);

    FfiResult::ok(format!("Exported signed OpenBadge credential to {}", out.display()))
    })
}

/// Export a VC-JWT (JOSE / `EdDSA`) secured Open Badges 3.0 credential.
///
/// This is the securing format 1EdTech's OB 3.0 conformance certifies (the JWT
/// Proof Format). Writes the compact JWS string to `output_path`.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_openbadge_jwt(
    evidence_path: String,
    document_path: String,
    output_path: String,
) -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    log::debug!(
        "ffi_export_openbadge_jwt: evidence_path={} document_path={} output_path={}",
        evidence_path, document_path, output_path
    );

    let out = try_ffi!(
        crate::sentinel::helpers::validate_path(&output_path)
            .map_err(|e| format!("Invalid output path: {e}")),
        FfiResult
    );

    let signing_key = try_ffi!(crate::ffi::helpers::load_signing_key(), FfiResult);
    let provider = crate::tpm::detect_provider();

    let (ear, author_did, report) = try_ffi!(
        build_ear_and_report_for_path(&evidence_path, &document_path, &signing_key),
        FfiResult
    );
    let mode = openbadge_mode_from_report(&report);

    let jwt = try_ffi!(
        openbadge::to_jwt_secured_open_badge(&ear, &author_did, mode, &*provider)
            .map_err(|e| e.to_string()),
        FfiResult
    );

    try_ffi!(crate::ffi::helpers::atomic_write(&out, jwt.as_bytes()), FfiResult);

    FfiResult::ok(format!("Exported VC-JWT OpenBadge credential to {}", out.display()))
    })
}

/// Export a COSE_Sign1-secured Open Badges 3.0 credential (CBOR).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_openbadge_cbor(
    evidence_path: String,
    document_path: String,
    output_path: String,
) -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    log::debug!(
        "ffi_export_openbadge_cbor: evidence_path={} document_path={} output_path={}",
        evidence_path, document_path, output_path
    );

    let out = try_ffi!(
        crate::sentinel::helpers::validate_path(&output_path)
            .map_err(|e| format!("Invalid output path: {e}")),
        FfiResult
    );

    let signing_key = try_ffi!(crate::ffi::helpers::load_signing_key(), FfiResult);
    let provider = crate::tpm::detect_provider();

    let (ear, author_did, report) = try_ffi!(
        build_ear_and_report_for_path(&evidence_path, &document_path, &signing_key),
        FfiResult
    );
    let mode = openbadge_mode_from_report(&report);

    let cbor_bytes = try_ffi!(
        openbadge::to_cose_secured_open_badge(&ear, &author_did, mode, &*provider)
            .map_err(|e| e.to_string()),
        FfiResult
    );

    try_ffi!(crate::ffi::helpers::atomic_write(&out, &cbor_bytes), FfiResult);

    FfiResult::ok(format!("Exported COSE-secured OpenBadge credential to {}", out.display()))
    })
}

/// Verify an Open Badges 3.0 credential file (JSON or CBOR) using the local
/// device key.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_verify_openbadge(badge_path: String) -> FfiVcVerifyResult {
    catch_ffi_panic!(@err FfiVcVerifyResult, {
    let signing_key = match crate::ffi::helpers::load_signing_key() {
        Ok(k) => k,
        Err(e) => return FfiVcVerifyResult::ffi_err(format!("Cannot load signing key: {e}")),
    };
    let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());
    ffi_verify_openbadge_with_key(badge_path, pub_hex)
    })
}

/// Verify an Open Badges 3.0 credential file (JSON or CBOR) with an explicit
/// public key.
///
/// `verifying_key_hex` is the 32-byte Ed25519 public key as 64 hex characters.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_verify_openbadge_with_key(
    badge_path: String,
    verifying_key_hex: String,
) -> FfiVcVerifyResult {
    catch_ffi_panic!(@err FfiVcVerifyResult, {
    log::debug!("ffi_verify_openbadge_with_key: badge_path={}", badge_path);

    let key_bytes = match hex::decode(&verifying_key_hex) {
        Ok(b) if b.len() == 32 => b,
        Ok(b) => {
            return FfiVcVerifyResult::ffi_err(format!(
                "Invalid key length: expected 32 bytes, got {}",
                b.len()
            ))
        }
        Err(e) => return FfiVcVerifyResult::ffi_err(format!("Invalid key hex: {e}")),
    };
    let key_arr: [u8; 32] = match key_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return FfiVcVerifyResult::ffi_err("Invalid key length".to_string()),
    };
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&key_arr) {
        Ok(k) => k,
        Err(e) => return FfiVcVerifyResult::ffi_err(format!("Invalid Ed25519 key: {e}")),
    };

    let path = match crate::sentinel::helpers::validate_path(&badge_path) {
        Ok(p) => p,
        Err(e) => return FfiVcVerifyResult::ffi_err(format!("Invalid path: {e}")),
    };

    const MAX_BADGE_FILE_SIZE: u64 = 4 * 1024 * 1024; // 4 MiB
    match std::fs::metadata(&path) {
        Ok(m) if m.len() > MAX_BADGE_FILE_SIZE => {
            return FfiVcVerifyResult::ffi_err(format!(
                "OpenBadge file too large: {} bytes (max {})",
                m.len(),
                MAX_BADGE_FILE_SIZE
            ));
        }
        Ok(_) => {}
        Err(e) => return FfiVcVerifyResult::ffi_err(format!("Cannot stat OpenBadge file: {e}")),
    }

    let data = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => return FfiVcVerifyResult::ffi_err(format!("Cannot read OpenBadge file: {e}")),
    };

    let path_str = path.to_string_lossy().to_lowercase();
    let is_cbor = path_str.ends_with(".cbor");

    if is_cbor {
        verify_cbor_badge(&data, &verifying_key)
    } else {
        verify_json_badge(&data, &verifying_key)
    }
    })
}

fn verify_cbor_badge(
    data: &[u8],
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> FfiVcVerifyResult {
    match openbadge::verify_cose_secured_open_badge(data, verifying_key) {
        Ok(badge) => badge_verify_result(&badge, true),
        Err(e) => FfiVcVerifyResult {
            success: false,
            signature_valid: false,
            error_message: Some(e.to_string()),
            ..Default::default()
        },
    }
}

fn verify_json_badge(
    data: &[u8],
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> FfiVcVerifyResult {
    let badge: openbadge::OpenBadgeCredential = match serde_json::from_slice(data) {
        Ok(b) => b,
        Err(e) => return FfiVcVerifyResult::ffi_err(format!("Invalid OpenBadge JSON: {e}")),
    };

    let proof = match &badge.proof {
        Some(p) => p,
        None => {
            return FfiVcVerifyResult {
                success: false,
                signature_valid: false,
                issuer_did: Some(badge.issuer.id.clone()),
                subject_did: Some(badge.credential_subject.id.clone()),
                error_message: Some("OpenBadge has no proof".to_string()),
                ..Default::default()
            }
        }
    };

    let signature_valid = verify_badge_data_integrity_proof(&badge, proof, verifying_key);
    badge_verify_result(&badge, signature_valid)
}

fn badge_verify_result(
    badge: &openbadge::OpenBadgeCredential,
    signature_valid: bool,
) -> FfiVcVerifyResult {
    let now = chrono::Utc::now();
    let is_expired = badge
        .valid_until
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|exp| now > exp)
        .unwrap_or(false);

    let verdict = badge
        .credential_subject
        .process_attestation
        .as_ref()
        .map(|pa| pa.status.clone());

    FfiVcVerifyResult {
        success: signature_valid,
        signature_valid,
        issuer_did: Some(badge.issuer.id.clone()),
        subject_did: Some(badge.credential_subject.id.clone()),
        verdict,
        valid_from: Some(badge.valid_from.clone()),
        valid_until: badge.valid_until.clone(),
        is_expired,
        error_message: if signature_valid {
            None
        } else {
            Some("Signature verification failed".to_string())
        },
    }
}

/// Verify an `eddsa-jcs-2022` Data Integrity proof on an Open Badge credential.
///
/// Replicates the signing-input construction from
/// [`openbadge::to_signed_open_badge_credential`].
fn verify_badge_data_integrity_proof(
    badge: &openbadge::OpenBadgeCredential,
    proof: &crate::war::profiles::vc::VcProof,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> bool {
    use ed25519_dalek::Verifier;
    use sha2::{Digest, Sha256};

    if proof.cryptosuite != "eddsa-jcs-2022" {
        log::warn!(
            "Unsupported OpenBadge cryptosuite: {}; only eddsa-jcs-2022 is supported",
            proof.cryptosuite
        );
        return false;
    }

    let hex_part = match proof.proof_value.strip_prefix('f') {
        Some(h) => h,
        None => {
            log::warn!(
                "Unsupported multibase prefix in OpenBadge proofValue; expected 'f' (base16)"
            );
            return false;
        }
    };
    let sig_bytes = match hex::decode(hex_part) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("Invalid hex in OpenBadge proofValue: {e}");
            return false;
        }
    };
    let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let proof_options = crate::war::profiles::vc::VcProof {
        proof_value: String::new(),
        ..proof.clone()
    };
    let proof_options_canon = match serde_jcs::to_string(&proof_options) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut doc_without_proof = badge.clone();
    doc_without_proof.proof = None;
    let doc_canon = match serde_jcs::to_string(&doc_without_proof) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut signing_input = [0u8; 64];
    signing_input[..32].copy_from_slice(&Sha256::digest(proof_options_canon.as_bytes()));
    signing_input[32..].copy_from_slice(&Sha256::digest(doc_canon.as_bytes()));

    verifying_key.verify(&signing_input, &signature).is_ok()
}
