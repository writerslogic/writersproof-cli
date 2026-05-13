// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use sha2::{Digest, Sha256};
use std::fmt;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

const N: usize = 256;
const H_SZ: usize = 32;
const PAIR: usize = N * 2 * H_SZ;

pub struct LamportPrivateKey {
    secrets: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for LamportPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LamportPrivateKey")
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct LamportPublicKey {
    pub hashes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct LamportSignature {
    pub revealed: Vec<u8>,
}

impl LamportSignature {
    pub fn to_bytes(&self) -> &[u8] {
        &self.revealed
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != N * H_SZ {
            return None;
        }
        Some(Self {
            revealed: bytes.to_vec(),
        })
    }
}

impl LamportPrivateKey {
    pub fn from_seed(seed: &[u8; 32]) -> (Self, LamportPublicKey) {
        let mut secrets = Zeroizing::new(vec![0u8; PAIR]);
        let mut hashes = vec![0u8; PAIR];
        for i in 0..(N * 2) {
            let s = Sha256::new()
                .chain_update(b"cpoe-lamport-v1")
                .chain_update(seed)
                .chain_update((i as u32).to_le_bytes())
                .finalize();
            let off = i * H_SZ;
            secrets[off..off + H_SZ].copy_from_slice(&s);
            hashes[off..off + H_SZ].copy_from_slice(&Sha256::digest(s));
        }
        (Self { secrets }, LamportPublicKey { hashes })
    }

    pub fn sign(self, msg_hash: &[u8; 32]) -> LamportSignature {
        let mut revealed = vec![0u8; N * H_SZ];
        for i in 0..N {
            let bit = (msg_hash[i / 8] >> (7 - (i % 8))) & 1;
            let s_off = (i * 2 + bit as usize) * H_SZ;
            revealed[i * H_SZ..(i + 1) * H_SZ].copy_from_slice(&self.secrets[s_off..s_off + H_SZ]);
        }
        LamportSignature { revealed }
    }
}

impl LamportPublicKey {
    pub fn verify(&self, msg_hash: &[u8; 32], sig: &LamportSignature) -> bool {
        if sig.revealed.len() != N * H_SZ {
            return false;
        }
        let mut ok = Choice::from(1u8);
        for i in 0..N {
            let bit = (msg_hash[i / 8] >> (7 - (i % 8))) & 1;
            let actual = Sha256::digest(&sig.revealed[i * H_SZ..(i + 1) * H_SZ]);
            let exp_off = (i * 2 + bit as usize) * H_SZ;
            ok &= actual
                .as_slice()
                .ct_eq(&self.hashes[exp_off..exp_off + H_SZ]);
        }
        ok.into()
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.hashes
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PAIR {
            return None;
        }
        Some(Self {
            hashes: bytes.to_vec(),
        })
    }

    pub fn fingerprint(&self) -> [u8; 8] {
        let h = Sha256::digest(&self.hashes);
        let mut fp = [0u8; 8];
        fp.copy_from_slice(&h[..8]);
        fp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let seed = [0x42u8; 32];
        let (privkey, pubkey) = LamportPrivateKey::from_seed(&seed);
        let msg = Sha256::digest(b"test message");
        let msg_hash: [u8; 32] = msg.into();
        let sig = privkey.sign(&msg_hash);
        assert!(pubkey.verify(&msg_hash, &sig));
    }

    #[test]
    fn wrong_message_fails_verification() {
        let seed = [0x42u8; 32];
        let (privkey, pubkey) = LamportPrivateKey::from_seed(&seed);
        let msg1: [u8; 32] = Sha256::digest(b"message 1").into();
        let msg2: [u8; 32] = Sha256::digest(b"message 2").into();
        let sig = privkey.sign(&msg1);
        assert!(!pubkey.verify(&msg2, &sig));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (privkey, _) = LamportPrivateKey::from_seed(&[0x01; 32]);
        let (_, pubkey2) = LamportPrivateKey::from_seed(&[0x02; 32]);
        let msg: [u8; 32] = Sha256::digest(b"test").into();
        let sig = privkey.sign(&msg);
        assert!(!pubkey2.verify(&msg, &sig));
    }

    #[test]
    fn signature_size_is_8192_bytes() {
        let (privkey, _) = LamportPrivateKey::from_seed(&[0xAA; 32]);
        let msg = [0u8; 32];
        let sig = privkey.sign(&msg);
        assert_eq!(sig.to_bytes().len(), 256 * 32);
    }

    #[test]
    fn public_key_size_is_16384_bytes() {
        let (_, pubkey) = LamportPrivateKey::from_seed(&[0xBB; 32]);
        assert_eq!(pubkey.to_bytes().len(), 256 * 2 * 32);
    }

    #[test]
    fn fingerprint_is_8_bytes() {
        let (_, pubkey) = LamportPrivateKey::from_seed(&[0xCC; 32]);
        assert_eq!(pubkey.fingerprint().len(), 8);
    }

    #[test]
    fn deterministic_key_generation() {
        let (_, pk1) = LamportPrivateKey::from_seed(&[0xDD; 32]);
        let (_, pk2) = LamportPrivateKey::from_seed(&[0xDD; 32]);
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let (_, pk1) = LamportPrivateKey::from_seed(&[0x01; 32]);
        let (_, pk2) = LamportPrivateKey::from_seed(&[0x02; 32]);
        assert_ne!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn signature_from_bytes_roundtrip() {
        let (privkey, _) = LamportPrivateKey::from_seed(&[0xEE; 32]);
        let msg = [0xFF; 32];
        let sig = privkey.sign(&msg);
        let bytes = sig.to_bytes().to_vec();
        let recovered = LamportSignature::from_bytes(&bytes)
            .expect("from_bytes should succeed for a valid serialized LamportSignature");
        assert_eq!(recovered.to_bytes(), sig.to_bytes());
    }

    #[test]
    fn signature_from_bytes_wrong_length_returns_none() {
        assert!(LamportSignature::from_bytes(&[0u8; 100]).is_none());
        assert!(LamportSignature::from_bytes(&[]).is_none());
    }

    #[test]
    fn public_key_from_bytes_wrong_length_returns_none() {
        assert!(LamportPublicKey::from_bytes(&[0u8; 100]).is_none());
        assert!(LamportPublicKey::from_bytes(&[]).is_none());
    }

    #[test]
    fn truncated_signature_fails_verification() {
        let (_, pubkey) = LamportPrivateKey::from_seed(&[0x11; 32]);
        let msg = [0u8; 32];
        let bad_sig = LamportSignature {
            revealed: vec![0u8; 100],
        };
        assert!(!pubkey.verify(&msg, &bad_sig));
    }
}
