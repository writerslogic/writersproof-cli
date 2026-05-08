// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce as AeadNonce,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::crypto::{hkdf_expand, RATCHET_INIT_DOMAIN};
use super::error::KeyHierarchyError;
use super::identity::derive_master_identity;
use super::types::{PufProvider, RatchetState, Session, SessionRecoveryState};
use super::verification::verify_session_certificate;

pub fn recover_session(
    puf: &dyn PufProvider,
    recovery: &SessionRecoveryState,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    if subtle::ConstantTimeEq::ct_eq(
        &recovery.certificate.session_id[..],
        &[0u8; 32][..],
    )
    .into()
    {
        return Err(KeyHierarchyError::NoRecoveryData);
    }

    verify_session_certificate(&recovery.certificate)?;

    if recovery.certificate.document_hash != document_hash {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let identity = derive_master_identity(puf)?;
    if identity.public_key != recovery.certificate.master_pubkey {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    if !recovery.last_ratchet_state.is_empty() {
        return recover_session_with_ratchet(puf, recovery);
    }

    recover_session_with_new_ratchet(puf, recovery)
}

fn recover_session_with_ratchet(
    puf: &dyn PufProvider,
    recovery: &SessionRecoveryState,
) -> Result<Session, KeyHierarchyError> {
    let data = &recovery.last_ratchet_state;
    if data.is_empty() {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    match data[0] {
        0x02 => recover_ratchet_v2_aead(puf, recovery),
        v => Err(KeyHierarchyError::Crypto(format!(
            "Recovery data uses legacy format (version byte {v:#04x}) which is no longer \
             supported due to its unauthenticated XOR cipher. \
             Use an older release of WritersLogic to migrate your recovery state to v2 AEAD \
             before upgrading."
        ))),
    }
}

/// v2 ratchet recovery: ChaCha20-Poly1305 AEAD.
fn recover_ratchet_v2_aead(
    puf: &dyn PufProvider,
    recovery: &SessionRecoveryState,
) -> Result<Session, KeyHierarchyError> {
    // Format: version(1) || aead_nonce(12) || ciphertext+tag
    const HEADER_LEN: usize = 1 + 12; // 13
    let data = &recovery.last_ratchet_state;
    if data.len() < HEADER_LEN + 16 {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let nonce_bytes = &data[1..13];
    let ciphertext = &data[13..];

    let challenge = Sha256::digest(b"cpoe-ratchet-recovery-v2");
    let response = Zeroizing::new(puf.get_response(&challenge)?);
    let key = hkdf_expand(&response, b"ratchet-recovery-key-v2", &[])?;

    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| KeyHierarchyError::SessionRecoveryFailed)?;
    let aead_nonce = AeadNonce::from_slice(nonce_bytes);

    let aad = (recovery.signatures.len() as u64).to_be_bytes();
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                aead_nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| KeyHierarchyError::SessionRecoveryFailed)?,
    );
    drop(key);

    if plaintext.len() < 48 {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let mut ratchet_state = [0u8; 32];
    ratchet_state.copy_from_slice(&plaintext[..32]);
    let ordinal = u64::from_be_bytes(
        plaintext[32..40]
            .try_into()
            .map_err(|_| KeyHierarchyError::SessionRecoveryFailed)?,
    );
    let export_count = u64::from_be_bytes(
        plaintext[40..48]
            .try_into()
            .map_err(|_| KeyHierarchyError::SessionRecoveryFailed)?,
    );

    let expected_ordinal = recovery
        .signatures
        .last()
        .map_or(0u64, |s| s.ordinal.saturating_add(1));
    if ordinal != expected_ordinal {
        log::warn!(
            "v2 recovery ordinal mismatch: decrypted {}, expected {} from signature chain",
            ordinal,
            expected_ordinal,
        );
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let protected = crate::crypto::ProtectedKey::new(ratchet_state);
    ratchet_state.zeroize();
    Ok(Session {
        certificate: recovery.certificate.clone(),
        ratchet: RatchetState {
            current: protected,
            ordinal,
            wiped: false,
        },
        signatures: recovery.signatures.clone(),
        export_count,
    })
}

fn recover_session_with_new_ratchet(
    puf: &dyn PufProvider,
    recovery: &SessionRecoveryState,
) -> Result<Session, KeyHierarchyError> {
    let mut next_ordinal = 0u64;
    if let Some(last) = recovery.signatures.last() {
        next_ordinal = last.ordinal.saturating_add(1);
    }

    let challenge = Sha256::digest(b"cpoe-ratchet-continuation-v1");
    let response = Zeroizing::new(puf.get_response(&challenge)?);

    let mut last_hash = [0u8; 32];
    if let Some(last) = recovery.signatures.last() {
        last_hash = last.checkpoint_hash;
    }

    let mut continuation_input = Zeroizing::new(Vec::new());
    continuation_input.extend_from_slice(&response);
    continuation_input.extend_from_slice(&last_hash);
    continuation_input.extend_from_slice(&recovery.certificate.session_id);

    let ratchet_init = hkdf_expand(
        &continuation_input,
        RATCHET_INIT_DOMAIN.as_bytes(),
        b"continuation",
    )?;
    drop(continuation_input);

    Ok(Session {
        certificate: recovery.certificate.clone(),
        ratchet: RatchetState {
            current: crate::crypto::ProtectedKey::from_zeroizing(ratchet_init),
            ordinal: next_ordinal,
            wiped: false,
        },
        signatures: recovery.signatures.clone(),
        export_count: 0,
    })
}
