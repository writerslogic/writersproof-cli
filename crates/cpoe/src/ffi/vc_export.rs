// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::types::{catch_ffi_panic, try_ffi, FfiErrResult, FfiResult, FfiVcVerifyResult};
use crate::war::ear::{
    Ar4siStatus, EarAppraisal, EarToken, TrustworthinessVector, VerifierId,
};
use crate::war::profiles::vc;
use std::collections::BTreeMap;

/// Export a signed W3C VC 2.0 (Data Integrity / JSON) for a tracked document.
///
/// Loads evidence from the store, builds an EAR token, signs the VC with the
/// device Ed25519 key using the `eddsa-jcs-2022` cryptosuite, and writes
/// pretty-printed JSON to `output_path` via atomic rename.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_vc_json(
    evidence_path: String,
    document_path: String,
    output_path: String,
) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!(
        "ffi_export_vc_json: evidence_path={} document_path={} output_path={}",
        evidence_path, document_path, output_path
    );

    let out = try_ffi!(
        crate::sentinel::helpers::validate_path(&output_path)
            .map_err(|e| format!("Invalid output path: {e}")),
        FfiResult
    );

    let signing_key = try_ffi!(
        crate::ffi::helpers::load_signing_key(),
        FfiResult
    );
    let provider = crate::tpm::detect_provider();

    let (ear, author_did) = try_ffi!(
        build_ear_for_path(&evidence_path, &document_path, &signing_key),
        FfiResult
    );

    let vc = try_ffi!(
        vc::to_signed_verifiable_credential(&ear, &author_did, &*provider)
            .map_err(|e| e.to_string()),
        FfiResult
    );

    let json = try_ffi!(
        serde_json::to_string_pretty(&vc).map_err(|e| format!("VC JSON serialization failed: {e}")),
        FfiResult
    );

    try_ffi!(
        atomic_write(&out, json.as_bytes()),
        FfiResult
    );

    FfiResult::ok(format!("Exported signed VC JSON to {}", out.display()))
    })
}

/// Export a COSE_Sign1-secured VC (CBOR) for a tracked document.
///
/// Builds the same EAR token as `ffi_export_vc_json` but wraps it in a
/// COSE_Sign1 envelope per the W3C VC+COSE specification (May 2025).
/// The output file uses the `.vc.cbor` convention.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_vc_cbor(
    evidence_path: String,
    document_path: String,
    output_path: String,
) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!(
        "ffi_export_vc_cbor: evidence_path={} document_path={} output_path={}",
        evidence_path, document_path, output_path
    );

    let out = try_ffi!(
        crate::sentinel::helpers::validate_path(&output_path)
            .map_err(|e| format!("Invalid output path: {e}")),
        FfiResult
    );

    let signing_key = try_ffi!(
        crate::ffi::helpers::load_signing_key(),
        FfiResult
    );
    let provider = crate::tpm::detect_provider();

    let (ear, author_did) = try_ffi!(
        build_ear_for_path(&evidence_path, &document_path, &signing_key),
        FfiResult
    );

    let cbor_bytes = try_ffi!(
        vc::to_cose_secured_vc(&ear, &author_did, &*provider)
            .map_err(|e| e.to_string()),
        FfiResult
    );

    try_ffi!(
        atomic_write(&out, &cbor_bytes),
        FfiResult
    );

    FfiResult::ok(format!("Exported COSE-secured VC to {}", out.display()))
    })
}

/// Verify a Verifiable Credential file (JSON or CBOR).
///
/// Detects format from the file extension:
/// - `.vc.json` or `.json`: Data Integrity proof (eddsa-jcs-2022)
/// - `.vc.cbor` or `.cbor`: COSE_Sign1 envelope
///
/// Returns signature validity and credential metadata. The local device signing
/// key is used as the verifying key; for cross-device verification the caller
/// must supply an external key via a dedicated API.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_verify_vc(vc_path: String) -> FfiVcVerifyResult {
    catch_ffi_panic!(FfiVcVerifyResult::ffi_err("engine internal error"), {
    log::debug!("ffi_verify_vc: vc_path={}", vc_path);

    let path = match crate::sentinel::helpers::validate_path(&vc_path) {
        Ok(p) => p,
        Err(e) => return FfiVcVerifyResult::ffi_err(format!("Invalid path: {e}")),
    };

    const MAX_VC_FILE_SIZE: u64 = 4 * 1024 * 1024; // 4 MiB
    match std::fs::metadata(&path) {
        Ok(m) if m.len() > MAX_VC_FILE_SIZE => {
            return FfiVcVerifyResult::ffi_err(format!(
                "VC file too large: {} bytes (max {})",
                m.len(),
                MAX_VC_FILE_SIZE
            ));
        }
        Ok(_) => {}
        Err(e) => return FfiVcVerifyResult::ffi_err(format!("Cannot stat VC file: {e}")),
    }

    let data = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => return FfiVcVerifyResult::ffi_err(format!("Cannot read VC file: {e}")),
    };

    let path_str = path.to_string_lossy().to_lowercase();
    let is_cbor = path_str.ends_with(".vc.cbor") || path_str.ends_with(".cbor");

    let signing_key = match crate::ffi::helpers::load_signing_key() {
        Ok(k) => k,
        Err(e) => return FfiVcVerifyResult::ffi_err(format!("Cannot load signing key: {e}")),
    };
    let verifying_key = signing_key.verifying_key();

    if is_cbor {
        verify_cbor_vc(&data, &verifying_key)
    } else {
        verify_json_vc(&data, &verifying_key)
    }
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build an [`EarToken`] from the evidence store for `evidence_path`.
///
/// Uses the existing WAR report pipeline (via `build_war_report_for_path`) to
/// derive scores and trust vectors, then assembles an EAR token exactly as the
/// report's `build_vc_json` does. Returns `(ear, author_did)`.
fn build_ear_for_path(
    evidence_path: &str,
    _document_path: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(EarToken, String), String> {
    let (report, _) = crate::ffi::report::build_war_report_for_path(evidence_path)?;

    let pub_key = signing_key.verifying_key();
    let author_did = crate::identity::did_key_from_public(pub_key.as_bytes())
        .or_else(|| report.author_did.clone())
        .ok_or_else(|| "Cannot derive author DID from signing key".to_string())?;

    let (_, tier_num, _) = crate::ffi::helpers::detect_attestation_tier_info();

    let tv = TrustworthinessVector {
        sourced_data: if report.score >= 60 {
            Ar4siStatus::Affirming as i8
        } else if report.score >= 40 {
            Ar4siStatus::Warning as i8
        } else {
            Ar4siStatus::None as i8
        },
        hardware: if tier_num >= 2 {
            Ar4siStatus::Affirming as i8
        } else {
            Ar4siStatus::None as i8
        },
        instance_identity: if tier_num >= 3 {
            Ar4siStatus::Affirming as i8
        } else if tier_num >= 1 {
            Ar4siStatus::Warning as i8
        } else {
            Ar4siStatus::None as i8
        },
        ..Default::default()
    };

    let chain_duration = if report.total_duration_min > 0.0 {
        Some((report.total_duration_min * 60.0) as u64)
    } else {
        None
    };

    let evidence_ref = hex::decode(&report.document_hash)
        .map_err(|e| format!("Invalid document_hash hex: {e}"))?;

    let appraisal = EarAppraisal {
        ear_status: score_to_ar4si(report.score),
        ear_trustworthiness_vector: Some(tv),
        ear_appraisal_policy_id: Some("urn:writerslogic:policy:pop-standard:1.0".to_string()),
        pop_seal: None,
        pop_evidence_ref: Some(evidence_ref),
        pop_entropy_report: None,
        pop_forgery_cost: None,
        pop_forensic_summary: None,
        pop_chain_length: Some(report.checkpoints.len() as u64),
        pop_chain_duration: chain_duration,
        pop_process_start: report.checkpoints.first().map(|cp| cp.timestamp.to_rfc3339()),
        pop_process_end: report.checkpoints.last().map(|cp| cp.timestamp.to_rfc3339()),
        pop_absence_claims: None,
        pop_warnings: None,
    };

    let mut submods = BTreeMap::new();
    submods.insert("pop".to_string(), appraisal);

    let ear = EarToken {
        eat_profile: crate::war::ear::POP_EAR_PROFILE.to_string(),
        iat: chrono::Utc::now().timestamp(),
        ear_verifier_id: VerifierId::default(),
        submods,
    };

    Ok((ear, author_did))
}

fn score_to_ar4si(score: u32) -> Ar4siStatus {
    if score >= 60 {
        Ar4siStatus::Affirming
    } else if score >= 40 {
        Ar4siStatus::None
    } else if score >= 20 {
        Ar4siStatus::Warning
    } else {
        Ar4siStatus::Contraindicated
    }
}

fn atomic_write(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("Failed to create temp file: {e}"))?;
    std::io::Write::write_all(&mut tmp, data)
        .map_err(|e| format!("Failed to write VC: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("Failed to sync VC to disk: {e}"))?;
    tmp.persist(path)
        .map_err(|e| format!("Failed to finalize VC file: {e}"))?;
    Ok(())
}

fn verify_cbor_vc(
    data: &[u8],
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> FfiVcVerifyResult {
    match vc::verify_cose_secured_vc(data, verifying_key) {
        Ok(credential) => {
            let now = chrono::Utc::now();
            let is_expired = credential
                .valid_until
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|exp| now > exp)
                .unwrap_or(false);
            FfiVcVerifyResult {
                success: true,
                signature_valid: true,
                issuer_did: Some(credential.issuer.clone()),
                subject_did: Some(credential.credential_subject.id.clone()),
                verdict: Some(
                    credential
                        .credential_subject
                        .process_attestation
                        .status
                        .clone(),
                ),
                valid_from: Some(credential.valid_from.clone()),
                valid_until: credential.valid_until.clone(),
                is_expired,
                error_message: None,
            }
        }
        Err(e) => FfiVcVerifyResult {
            success: false,
            signature_valid: false,
            error_message: Some(e.to_string()),
            ..Default::default()
        },
    }
}

fn verify_json_vc(
    data: &[u8],
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> FfiVcVerifyResult {
    let credential: vc::VerifiableCredential = match serde_json::from_slice(data) {
        Ok(c) => c,
        Err(e) => {
            return FfiVcVerifyResult::ffi_err(format!("Invalid VC JSON: {e}"));
        }
    };

    let proof = match &credential.proof {
        Some(p) => p,
        None => {
            return FfiVcVerifyResult {
                success: false,
                signature_valid: false,
                issuer_did: Some(credential.issuer.clone()),
                subject_did: Some(credential.credential_subject.id.clone()),
                error_message: Some("VC has no proof".to_string()),
                ..Default::default()
            };
        }
    };

    let signature_valid = verify_data_integrity_proof(&credential, proof, verifying_key);

    let now = chrono::Utc::now();
    let is_expired = credential
        .valid_until
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|exp| now > exp)
        .unwrap_or(false);

    FfiVcVerifyResult {
        success: signature_valid,
        signature_valid,
        issuer_did: Some(credential.issuer.clone()),
        subject_did: Some(credential.credential_subject.id.clone()),
        verdict: Some(
            credential
                .credential_subject
                .process_attestation
                .status
                .clone(),
        ),
        valid_from: Some(credential.valid_from.clone()),
        valid_until: credential.valid_until.clone(),
        is_expired,
        error_message: if signature_valid {
            None
        } else {
            Some("Signature verification failed".to_string())
        },
    }
}

/// Verify an `eddsa-jcs-2022` Data Integrity proof.
///
/// Replicates the signing input construction from `to_signed_verifiable_credential`:
/// `SHA-256(proof_options_jcs) || SHA-256(document_jcs)` where `proof_options`
/// is the proof object with an empty `proofValue`.
fn verify_data_integrity_proof(
    credential: &vc::VerifiableCredential,
    proof: &vc::VcProof,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> bool {
    use ed25519_dalek::Verifier;
    use sha2::{Digest, Sha256};

    if proof.cryptosuite != "eddsa-jcs-2022" {
        log::warn!(
            "Unsupported VC cryptosuite: {}; only eddsa-jcs-2022 is supported",
            proof.cryptosuite
        );
        return false;
    }

    let hex_part = proof.proof_value.strip_prefix('f').unwrap_or("");
    let sig_bytes = match hex::decode(hex_part) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let proof_options = vc::VcProof {
        proof_value: String::new(),
        ..proof.clone()
    };
    let proof_options_canon = match serde_jcs::to_string(&proof_options) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Reconstruct the document as it was before the proof was attached.
    let mut doc_without_proof = credential.clone();
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
