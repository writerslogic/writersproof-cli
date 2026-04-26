// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::crypto::{build_cert_data, build_cert_data_with_expiry, fingerprint_for_public_key};
use super::error::KeyHierarchyError;
use super::types::{
    CheckpointSignature, KeyHierarchyEvidence, SessionBindingReport, SessionCertificate,
};

/// Verify the Ed25519 signature on a session certificate against the embedded master key.
///
/// **Security note**: This only verifies internal consistency (the signature
/// matches the embedded `master_pubkey`). Callers must separately validate
/// that `master_pubkey` belongs to a trusted identity anchor before relying
/// on the certificate for authorization decisions.
pub fn verify_session_certificate(cert: &SessionCertificate) -> Result<(), KeyHierarchyError> {
    if let Some(expires_at) = cert.expires_at {
        if Utc::now() > expires_at {
            return Err(KeyHierarchyError::Crypto(
                "session certificate has expired".to_string(),
            ));
        }
    }

    let cert_data = build_cert_data_with_expiry(
        cert.session_id,
        &cert.session_pubkey,
        cert.created_at,
        cert.document_hash,
        cert.expires_at,
    );

    let pubkey = VerifyingKey::from_bytes(&cert.master_pubkey)
        .map_err(|_| KeyHierarchyError::InvalidCert)?;

    let signature = Signature::from_bytes(&cert.signature);
    pubkey
        .verify(&cert_data, &signature)
        .map_err(|_| KeyHierarchyError::InvalidCert)
}

/// Verify ordinal sequence, Ed25519 signatures, and counter monotonicity for all checkpoints.
///
/// **Security note**: This function verifies each signature against its stated
/// public key but does NOT verify that those public keys were derived from the
/// session's ratchet chain. Full ratchet binding verification requires the
/// session seed and is performed at a higher level when available.
pub fn verify_checkpoint_signatures(
    signatures: &[CheckpointSignature],
) -> Result<(), KeyHierarchyError> {
    let mut prev_counter: Option<u64> = None;
    let mut prev_was_adjacent = false;

    for (i, sig) in signatures.iter().enumerate() {
        if sig.ordinal != u64::try_from(i).unwrap_or(u64::MAX) {
            return Err(KeyHierarchyError::OrdinalMismatch);
        }

        let pubkey = VerifyingKey::from_bytes(&sig.public_key)
            .map_err(|_| KeyHierarchyError::SignatureFailed)?;
        let signature = Signature::from_bytes(&sig.signature);
        pubkey
            .verify(&sig.checkpoint_hash, &signature)
            .map_err(|_| KeyHierarchyError::SignatureFailed)?;

        // Verify Lamport one-shot signature if present.
        // The Lamport key is derived from the same ratchet state but with a
        // different domain separator, so we verify it independently.
        if let Some(ref lamport_bytes) = sig.lamport_signature {
            let lamport_sig = crate::crypto::lamport::LamportSignature::from_bytes(lamport_bytes)
                .ok_or_else(|| {
                KeyHierarchyError::Crypto(format!(
                    "invalid Lamport signature length at ordinal {}",
                    sig.ordinal
                ))
            })?;

            if let Some(ref pubkey_bytes) = sig.lamport_public_key {
                // Full cryptographic verification against the included public key.
                let lamport_pubkey = crate::crypto::lamport::LamportPublicKey::from_bytes(
                    pubkey_bytes,
                )
                .ok_or_else(|| {
                    KeyHierarchyError::Crypto(format!(
                        "invalid Lamport public key length at ordinal {}",
                        sig.ordinal
                    ))
                })?;

                // If a fingerprint is also present, verify it matches the public key.
                if let Some(ref fp) = sig.lamport_pubkey_fingerprint {
                    if fp.as_slice() != lamport_pubkey.fingerprint() {
                        return Err(KeyHierarchyError::Crypto(format!(
                            "Lamport public key fingerprint mismatch at ordinal {}",
                            sig.ordinal
                        )));
                    }
                }

                if !lamport_pubkey.verify(&sig.checkpoint_hash, &lamport_sig) {
                    return Err(KeyHierarchyError::Crypto(format!(
                        "Lamport signature verification failed at ordinal {}",
                        sig.ordinal
                    )));
                }
            } else {
                // No public key available; fall back to structural validation only.
                // This means we can check the signature size but cannot verify the
                // actual cryptographic binding. This weakens the chain guarantee.
                log::warn!(
                    "Lamport verification at ordinal {}: no public key available, \
                     falling back to structural-only validation",
                    sig.ordinal
                );
                if lamport_sig.to_bytes().len() != 256 * 32 {
                    return Err(KeyHierarchyError::Crypto(format!(
                        "Lamport signature wrong size at ordinal {}",
                        sig.ordinal
                    )));
                }
            }
        }

        if let Some(current) = sig.counter_value {
            if let Some(prev) = prev_counter {
                if current < prev {
                    return Err(KeyHierarchyError::Crypto(format!(
                        "counter rollback at ordinal {}: {} < {}",
                        sig.ordinal, current, prev,
                    )));
                }
                // Only validate delta against the immediately preceding counter
                if prev_was_adjacent {
                    if let Some(delta) = sig.counter_delta {
                        // Safe: current >= prev guaranteed by the check on line 67
                        if delta != current - prev {
                            return Err(KeyHierarchyError::Crypto(format!(
                                "counter delta mismatch at ordinal {}: \
                                 delta {} != {} - {}",
                                sig.ordinal, delta, current, prev,
                            )));
                        }
                    }
                }
            }
            prev_counter = Some(current);
            prev_was_adjacent = true;
        } else {
            prev_was_adjacent = false;
        }
    }
    Ok(())
}

/// Verify session TPM binding: checks that reboot counters haven't changed
/// mid-session (time-travel detection) and that counter deltas are consistent.
pub fn verify_session_binding(
    cert: &SessionCertificate,
) -> Result<SessionBindingReport, KeyHierarchyError> {
    let mut report = SessionBindingReport {
        has_start_quote: cert.start_quote.is_some(),
        has_end_quote: cert.end_quote.is_some(),
        counter_delta: None,
        reboot_detected: false,
        restart_detected: false,
        warnings: Vec::new(),
    };

    if let (Some(start), Some(end)) = (cert.start_counter, cert.end_counter) {
        if end < start {
            return Err(KeyHierarchyError::Crypto(format!(
                "session counter rollback: end {} < start {}",
                end, start,
            )));
        }
        report.counter_delta = Some(end - start);
    }

    if let (Some(start_rc), Some(end_rc)) = (cert.start_reset_count, cert.end_reset_count) {
        if end_rc != start_rc {
            report.reboot_detected = true;
            report.warnings.push(format!(
                "TPM ResetCount changed mid-session: {} -> {} (machine was rebooted)",
                start_rc, end_rc,
            ));
        }
    }

    if let (Some(start_rst), Some(end_rst)) = (cert.start_restart_count, cert.end_restart_count) {
        if end_rst != start_rst {
            report.restart_detected = true;
            report.warnings.push(format!(
                "TPM RestartCount changed mid-session: {} -> {} (TPM was restarted)",
                start_rst, end_rst,
            ));
        }
    }

    Ok(report)
}

/// Verify the full key hierarchy: certificate, identity binding, fingerprint, and checkpoint chain.
pub fn verify_key_hierarchy(evidence: &KeyHierarchyEvidence) -> Result<(), KeyHierarchyError> {
    let cert = evidence
        .session_certificate
        .as_ref()
        .ok_or(KeyHierarchyError::InvalidCert)?;
    verify_session_certificate(cert)?;

    if let Some(identity) = &evidence.master_identity {
        if identity.public_key != cert.master_pubkey {
            return Err(KeyHierarchyError::InvalidCert);
        }
    }

    // Require master_public_key to be present and verify fingerprint consistency.
    // An empty master_public_key would skip fingerprint validation, enabling identity spoofing.
    if evidence.master_public_key.is_empty() {
        return Err(KeyHierarchyError::InvalidCert);
    }
    let expected = fingerprint_for_public_key(&evidence.master_public_key);
    if expected != evidence.master_fingerprint {
        return Err(KeyHierarchyError::InvalidCert);
    }

    // Use safe cast for ratchet count comparison
    let sig_count = i32::try_from(evidence.checkpoint_signatures.len()).unwrap_or(i32::MAX);
    if evidence.ratchet_count != sig_count {
        return Err(KeyHierarchyError::InvalidCert);
    }

    verify_ratchet_key_consistency(evidence)?;
    verify_checkpoint_signatures(&evidence.checkpoint_signatures)
}

/// Verify that checkpoint signature public keys are consistent with the
/// declared ratchet public keys in the evidence.
///
/// This does NOT verify that the ratchet keys were correctly derived (that
/// requires the secret seed), but it does verify the evidence is internally
/// consistent: each checkpoint was signed by the ratchet key the evidence claims.
pub fn verify_ratchet_key_consistency(
    evidence: &KeyHierarchyEvidence,
) -> Result<(), KeyHierarchyError> {
    if evidence.ratchet_public_keys.len() != evidence.checkpoint_signatures.len() {
        return Err(KeyHierarchyError::Crypto(format!(
            "ratchet key count ({}) != checkpoint signature count ({})",
            evidence.ratchet_public_keys.len(),
            evidence.checkpoint_signatures.len(),
        )));
    }

    for (i, (ratchet_key, sig)) in evidence
        .ratchet_public_keys
        .iter()
        .zip(evidence.checkpoint_signatures.iter())
        .enumerate()
    {
        if ratchet_key != &sig.public_key {
            return Err(KeyHierarchyError::Crypto(format!(
                "ratchet key mismatch at ordinal {}: \
                 evidence claims different key than signature",
                i,
            )));
        }
    }

    Ok(())
}

/// Validate Ed25519 byte lengths and verify the certificate signature.
///
/// Checks that `master_pubkey` is 32 bytes, `session_pubkey` is 32 bytes,
/// and `cert_signature` is 64 bytes, then performs Ed25519 signature
/// verification over `build_cert_data(session_id, session_pubkey, created_at, document_hash)`
/// against `master_pubkey`, matching the signing path in `session.rs`.
pub fn validate_cert_byte_lengths(
    master_pubkey: &[u8],
    session_pubkey: &[u8],
    cert_signature: &[u8],
    session_id: &[u8; 32],
    created_at: DateTime<Utc>,
    document_hash: &[u8; 32],
) -> Result<(), KeyHierarchyError> {
    if master_pubkey.len() != 32 {
        return Err(KeyHierarchyError::InvalidCert);
    }
    if session_pubkey.len() != 32 {
        return Err(KeyHierarchyError::InvalidCert);
    }
    if cert_signature.len() != 64 {
        return Err(KeyHierarchyError::InvalidCert);
    }

    let cert_data = build_cert_data(*session_id, session_pubkey, created_at, *document_hash);
    let vk = VerifyingKey::from_bytes(master_pubkey.try_into().expect("length checked"))
        .map_err(|_| KeyHierarchyError::InvalidCert)?;
    let sig = Signature::from_bytes(cert_signature.try_into().expect("length checked"));
    vk.verify(&cert_data, &sig)
        .map_err(|_| KeyHierarchyError::InvalidCert)?;

    Ok(())
}

/// Verify a single ratchet key's Ed25519 signature over a checkpoint hash.
pub fn verify_ratchet_signature(
    ratchet_pubkey: &[u8],
    checkpoint_hash: &[u8],
    signature: &[u8],
) -> Result<(), KeyHierarchyError> {
    if ratchet_pubkey.len() != 32 {
        return Err(KeyHierarchyError::Crypto(
            "invalid ratchet public key size".to_string(),
        ));
    }
    if checkpoint_hash.len() != 32 {
        return Err(KeyHierarchyError::Crypto(
            "invalid checkpoint hash size".to_string(),
        ));
    }
    if signature.len() != 64 {
        return Err(KeyHierarchyError::Crypto(
            "invalid signature size".to_string(),
        ));
    }

    let pubkey =
        VerifyingKey::from_bytes(ratchet_pubkey.try_into().map_err(|_| {
            KeyHierarchyError::Crypto("invalid ratchet public key size".to_string())
        })?)
        .map_err(|_| KeyHierarchyError::Crypto("invalid ratchet public key".to_string()))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| KeyHierarchyError::Crypto("invalid signature size".to_string()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    pubkey
        .verify(checkpoint_hash, &sig)
        .map_err(|_| KeyHierarchyError::SignatureFailed)
}
