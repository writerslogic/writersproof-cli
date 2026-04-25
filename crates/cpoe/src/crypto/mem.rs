// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::utils::mlock::{mlock, munlock};
use std::ops::Deref;
use zeroize::{Zeroize, Zeroizing};

pub struct ProtectedKey<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> ProtectedKey<N> {
    pub fn new(mut bytes: [u8; N]) -> Self {
        let key = Self(Zeroizing::new(bytes));
        mlock(key.0.as_ptr(), N);
        bytes.zeroize();
        key
    }

    pub fn from_zeroizing(z: Zeroizing<[u8; N]>) -> Self {
        let key = Self(z);
        mlock(key.0.as_ptr(), N);
        key
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> std::fmt::Debug for ProtectedKey<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[PROTECTED KEY]")
    }
}

impl<const N: usize> Drop for ProtectedKey<N> {
    fn drop(&mut self) {
        munlock(self.0.as_ptr(), N);
    }
}

impl<const N: usize> Deref for ProtectedKey<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct ProtectedBuf(Zeroizing<Vec<u8>>);

impl ProtectedBuf {
    pub fn new(bytes: Vec<u8>) -> Self {
        let buf = Self(Zeroizing::new(bytes));
        mlock(buf.0.as_ptr(), buf.0.len());
        buf
    }
}

impl std::fmt::Debug for ProtectedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[PROTECTED BUF]")
    }
}

impl Deref for ProtectedBuf {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ProtectedBuf {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ProtectedBuf {
    fn drop(&mut self) {
        munlock(self.0.as_ptr(), self.0.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_key_stores_and_retrieves() {
        assert_eq!(ProtectedKey::new([0xAB; 32]).as_bytes(), &[0xAB; 32]);
    }

    #[test]
    fn protected_key_deref() {
        let slice: &[u8; 16] = &*ProtectedKey::new([0x42; 16]);
        assert_eq!(slice, &[0x42; 16]);
    }

    #[test]
    fn protected_key_debug_is_redacted() {
        let debug = format!("{:?}", ProtectedKey::new([0xFF; 32]));
        assert!(!debug.contains("ff"));
        assert!(debug.contains("PROTECTED"));
    }

    #[test]
    fn protected_key_from_zeroizing() {
        let key = ProtectedKey::from_zeroizing(Zeroizing::new([0x01; 32]));
        assert_eq!(key.as_bytes(), &[0x01; 32]);
    }

    #[test]
    fn protected_buf_stores_and_retrieves() {
        assert_eq!(ProtectedBuf::new(vec![1, 2, 3]).as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn protected_buf_deref() {
        let slice: &[u8] = &*ProtectedBuf::new(vec![10, 20]);
        assert_eq!(slice, &[10, 20]);
    }

    #[test]
    fn protected_buf_debug_is_redacted() {
        assert!(format!("{:?}", ProtectedBuf::new(vec![0xFF])).contains("PROTECTED"));
    }

    #[test]
    fn protected_buf_empty() {
        assert!(ProtectedBuf::new(vec![]).as_slice().is_empty());
    }
}
