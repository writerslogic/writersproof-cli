// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

static SECRET: OnceLock<u64> = OnceLock::new();
static NONCE: AtomicU64 = AtomicU64::new(0);

fn get_mask(n: u64) -> u64 {
    n ^ *SECRET.get_or_init(|| {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b)
            .expect("getrandom failed; cannot initialize obfuscation secret");
        u64::from_ne_bytes(b)
    })
}

fn apply_mask(data: &mut [u8], mut mask: u64) {
    for chunk in data.chunks_mut(8) {
        let len = chunk.len();
        let mut b = [0u8; 8];
        b[..len].copy_from_slice(chunk);
        let val = u64::from_ne_bytes(b) ^ mask;
        chunk.copy_from_slice(&val.to_ne_bytes()[..len]);
        mask = mask.rotate_left(13).wrapping_add(0x9E3779B9);
    }
}

#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct ObfuscatedString {
    nonce: u64,
    data: Vec<u8>,
}

impl Default for ObfuscatedString {
    fn default() -> Self {
        Self::new("")
    }
}

impl std::fmt::Debug for ObfuscatedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl ObfuscatedString {
    pub fn new(s: &str) -> Self {
        let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
        let mut data = s.as_bytes().to_vec();
        apply_mask(&mut data, get_mask(nonce));
        Self { nonce, data }
    }

    pub fn reveal(&self) -> Zeroizing<String> {
        let mut d = self.data.clone();
        apply_mask(&mut d, get_mask(self.nonce));
        Zeroizing::new(String::from_utf8(d).unwrap_or_default())
    }
}

#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct Obfuscated<T> {
    nonce: u64,
    data: Vec<u8>,
    _p: std::marker::PhantomData<T>,
}

impl<T: Serialize + for<'de> Deserialize<'de>> Obfuscated<T> {
    pub fn new(val: &T) -> Self {
        let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
        let mut data = bincode::serde::encode_to_vec(val, bincode::config::standard())
            .unwrap_or_else(|e| {
                log::warn!("ObfuscatedString serialization failed: {e}");
                Vec::new()
            });
        apply_mask(&mut data, get_mask(nonce));
        Self {
            nonce,
            data,
            _p: std::marker::PhantomData,
        }
    }

    pub fn reveal(&self) -> Option<T> {
        let mut d = self.data.clone();
        apply_mask(&mut d, get_mask(self.nonce));
        let res = bincode::serde::decode_from_slice(&d, bincode::config::standard())
            .ok()
            .map(|(v, _)| v);
        d.zeroize();
        res
    }
}

impl PartialEq for ObfuscatedString {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.reveal()
            .as_bytes()
            .ct_eq(other.reveal().as_bytes())
            .into()
    }
}

impl<T: Serialize + for<'de> Deserialize<'de> + PartialEq> PartialEq for Obfuscated<T> {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        // Deobfuscate both to canonical serialized bytes and compare in constant time.
        let mut a = self.data.clone();
        apply_mask(&mut a, get_mask(self.nonce));
        let mut b = other.data.clone();
        apply_mask(&mut b, get_mask(other.nonce));
        let result = if a.len() == b.len() {
            a.ct_eq(&b).into()
        } else {
            false
        };
        a.zeroize();
        b.zeroize();
        result
    }
}

impl<T> std::fmt::Debug for Obfuscated<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Obfuscated")
            .field("data", &"[REDACTED]")
            .finish()
    }
}
