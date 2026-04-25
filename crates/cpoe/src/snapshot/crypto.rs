// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const SNAPSHOT_KEY_DOMAIN: &[u8] = b"writerslogic-snapshot-v1";
const SNAPSHOT_NONCE_DOMAIN: &[u8] = b"writerslogic-snapshot-nonce-v1";

fn derive_blob_key(signing_key_bytes: &[u8; 32], content_hash: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(SNAPSHOT_KEY_DOMAIN), signing_key_bytes);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(content_hash, key.as_mut())
        .expect("32-byte output is within HKDF-SHA256 limit");
    key
}

fn derive_blob_nonce(signing_key_bytes: &[u8; 32], content_hash: &[u8; 32]) -> [u8; 12] {
    let hk = Hkdf::<Sha256>::new(Some(SNAPSHOT_NONCE_DOMAIN), signing_key_bytes);
    let mut okm = [0u8; 12];
    hk.expand(content_hash, &mut okm)
        .expect("12-byte output is within HKDF-SHA256 limit");
    okm
}

/// Compress and encrypt plaintext. Verifies the content hash matches the plaintext
/// before encrypting — a mismatch here would make the blob unrecoverable.
pub fn encrypt_blob(
    signing_key_bytes: &[u8; 32],
    content_hash: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    const MAX_SNAPSHOT_SIZE: usize = 100 * 1024 * 1024;
    if plaintext.len() > MAX_SNAPSHOT_SIZE {
        return Err("snapshot too large (>100 MB)".to_string());
    }

    let actual_hash: [u8; 32] = Sha256::digest(plaintext).into();
    if actual_hash != *content_hash {
        return Err("content hash does not match plaintext".to_string());
    }

    let compressed =
        zstd::encode_all(plaintext, 3).map_err(|e| format!("zstd compress failed: {e}"))?;

    let mut key = derive_blob_key(signing_key_bytes, content_hash);
    let nonce_bytes = derive_blob_nonce(signing_key_bytes, content_hash);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|e| format!("cipher init failed: {e}"))?;

    let ciphertext = cipher
        .encrypt(nonce, compressed.as_slice())
        .map_err(|e| format!("encryption failed: {e}"))?;

    key.zeroize();
    Ok(ciphertext)
}

/// Decrypt, decompress, and verify content hash integrity.
pub fn decrypt_blob(
    signing_key_bytes: &[u8; 32],
    content_hash: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let mut key = derive_blob_key(signing_key_bytes, content_hash);
    let nonce_bytes = derive_blob_nonce(signing_key_bytes, content_hash);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|e| format!("cipher init failed: {e}"))?;

    let compressed = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decryption failed (tampered or wrong key): {e}"))?;

    key.zeroize();

    const MAX_SNAPSHOT_SIZE: u64 = 100 * 1024 * 1024;
    let decoder = zstd::stream::read::Decoder::new(compressed.as_slice())
        .map_err(|e| format!("zstd decoder init failed: {e}"))?;
    let mut limited = std::io::Read::take(decoder, MAX_SNAPSHOT_SIZE + 1);
    let mut plaintext = Vec::new();
    std::io::Read::read_to_end(&mut limited, &mut plaintext)
        .map_err(|e| format!("zstd decompress failed: {e}"))?;
    if plaintext.len() as u64 > MAX_SNAPSHOT_SIZE {
        return Err("decompressed snapshot exceeds size limit".to_string());
    }

    let actual_hash: [u8; 32] = Sha256::digest(&plaintext).into();
    if actual_hash != *content_hash {
        return Err("decrypted content hash mismatch (storage corruption)".to_string());
    }

    Ok(plaintext)
}
