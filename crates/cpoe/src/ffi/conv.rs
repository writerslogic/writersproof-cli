// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI crypto conversion helpers.
//!
//! Routes signing and pubkey encoding through `Ed25519Sig` / `Ed25519Pubkey`
//! newtypes so all FFI signing sites get type-safe crypto handling.

use crate::utils::crypto_types::{Ed25519Pubkey, Ed25519Sig};

/// Hex-encode an Ed25519 public key from a signing key.
#[inline]
pub fn pubkey_hex(signing_key: &ed25519_dalek::SigningKey) -> String {
    Ed25519Pubkey::from(signing_key.verifying_key()).to_hex()
}

/// Sign a payload and return the hex-encoded signature.
#[inline]
pub fn sign_hex(signing_key: &ed25519_dalek::SigningKey, payload: &[u8]) -> String {
    Ed25519Sig::from(ed25519_dalek::Signer::sign(signing_key, payload)).to_hex()
}
