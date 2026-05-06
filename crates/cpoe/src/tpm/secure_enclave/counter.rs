// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::types::SecureEnclaveState;
use crate::tpm::TpmError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use subtle::ConstantTimeEq;

/// Derive an HMAC key for counter integrity from the signing public key.
fn derive_counter_hmac_key(public_key: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(b"cpoe-counter-auth-v1");
    hasher.update(public_key);
    hasher.finalize().to_vec()
}

/// Compute HMAC-SHA256 over the 8-byte counter value.
fn compute_counter_hmac(hmac_key: &[u8], counter_bytes: &[u8; 8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(hmac_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(counter_bytes);
    mac.finalize().into_bytes().into()
}

pub(super) fn load_counter(state: &mut SecureEnclaveState) -> Result<(), TpmError> {
    match fs::read(&state.counter_file) {
        Ok(data) if data.len() == 40 => {
            // New format: 8-byte counter + 32-byte HMAC
            let counter_bytes: [u8; 8] = data[0..8].try_into().expect("slice is exactly 8 bytes");
            let stored_hmac: [u8; 32] = data[8..40].try_into().expect("slice is exactly 32 bytes");

            let hmac_key = derive_counter_hmac_key(&state.public_key);
            let expected_hmac = compute_counter_hmac(&hmac_key, &counter_bytes);

            if stored_hmac.ct_eq(&expected_hmac).unwrap_u8() == 0 {
                log::error!(
                    "Counter HMAC verification failed — possible tampering: {:?}",
                    state.counter_file
                );
                return Err(TpmError::CounterRollback);
            }

            state.counter = u64::from_be_bytes(counter_bytes);
            Ok(())
        }
        Ok(data) if data.len() == 8 => {
            // Legacy format (no HMAC) — accept and immediately re-persist with HMAC
            // to close the rollback window before any caller can act on the value.
            let bytes: [u8; 8] = data[0..8].try_into().expect("slice is exactly 8 bytes");
            state.counter = u64::from_be_bytes(bytes);
            save_counter(state).map_err(TpmError::Io)?;
            Ok(())
        }
        Ok(data) => {
            log::error!(
                "Counter file corrupt ({} bytes, expected 8 or 40): {:?}",
                data.len(),
                state.counter_file
            );
            Err(TpmError::CounterRollback)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            state.counter = 0;
            Ok(())
        }
        Err(e) => Err(TpmError::Io(e)),
    }
}

pub(super) fn save_counter(state: &SecureEnclaveState) -> std::io::Result<()> {
    if let Some(parent) = state.counter_file.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let counter_bytes = state.counter.to_be_bytes();
    let hmac_key = derive_counter_hmac_key(&state.public_key);
    let hmac = compute_counter_hmac(&hmac_key, &counter_bytes);

    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(&counter_bytes);
    buf.extend_from_slice(&hmac);

    // Atomic write: write to temp, fsync, rename to avoid partial writes on crash.
    let parent = state
        .counter_file
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        tmp.write_all(&buf)?;
        tmp.as_file().sync_all()?;
        crate::crypto::restrict_permissions(tmp.path(), 0o600)?;
        tmp.persist(&state.counter_file).map_err(|e| e.error)?;
        Ok(())
    })();
    if let Err(ref e) = write_result {
        log::error!(
            "Failed to persist counter to {:?}: {}",
            state.counter_file,
            e
        );
    }
    write_result
}
