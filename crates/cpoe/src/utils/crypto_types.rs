// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Strongly-typed wrappers for cryptographic byte arrays.
//!
//! These newtypes replace raw `String` fields that previously held hex-encoded
//! keys, signatures, and hashes. The inner bytes are validated at construction
//! time, making invalid state unrepresentable.

use serde::{Deserialize, Serialize};
use std::fmt;
use subtle::ConstantTimeEq;

/// A SHA-256 or BLAKE3 hash (32 bytes), serialized as hex in human-readable formats.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HexHash(#[serde(with = "crate::serde_utils::hex_array")] pub [u8; 32]);

/// An Ed25519 public key (32 bytes), serialized as hex in human-readable formats.
///
/// Uses constant-time comparison to prevent timing side-channels in auth paths.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ed25519Pubkey(#[serde(with = "crate::serde_utils::hex_array")] pub [u8; 32]);

impl PartialEq for Ed25519Pubkey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for Ed25519Pubkey {}
impl std::hash::Hash for Ed25519Pubkey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// An Ed25519 signature (64 bytes), serialized as hex in human-readable formats.
///
/// Uses constant-time comparison to prevent timing side-channels.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ed25519Sig(#[serde(with = "crate::serde_utils::hex_array")] pub [u8; 64]);

impl PartialEq for Ed25519Sig {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for Ed25519Sig {}
impl std::hash::Hash for Ed25519Sig {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// A variable-length hex-encoded byte vector for signatures/proofs of non-standard sizes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HexBytes(pub Vec<u8>);

impl Serialize for HexBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::serde_utils::hex_vec::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = crate::serde_utils::hex_vec::deserialize(deserializer)?;
        if bytes.len() > MAX_HEX_BYTES_LEN {
            return Err(serde::de::Error::custom(format!(
                "HexBytes exceeds maximum length: {} > {}",
                bytes.len(),
                MAX_HEX_BYTES_LEN
            )));
        }
        Ok(Self(bytes))
    }
}

// --- HexHash ---

impl HexHash {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut arr = [0u8; 32];
        hex::decode_to_slice(s, &mut arr)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for HexHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HexHash({}…)", &hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for HexHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl From<[u8; 32]> for HexHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<HexHash> for [u8; 32] {
    fn from(h: HexHash) -> Self {
        h.0
    }
}

impl AsRef<[u8]> for HexHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for HexHash {
    fn default() -> Self {
        Self::ZERO
    }
}

// --- Ed25519Pubkey ---

impl Ed25519Pubkey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut arr = [0u8; 32];
        hex::decode_to_slice(s, &mut arr)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn to_verifying_key(
        &self,
    ) -> Result<ed25519_dalek::VerifyingKey, ed25519_dalek::SignatureError> {
        ed25519_dalek::VerifyingKey::from_bytes(&self.0)
    }
}

impl fmt::Debug for Ed25519Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Pubkey({}…)", &hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for Ed25519Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}…", &hex::encode(&self.0[..8]))
    }
}

impl From<[u8; 32]> for Ed25519Pubkey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<ed25519_dalek::VerifyingKey> for Ed25519Pubkey {
    fn from(vk: ed25519_dalek::VerifyingKey) -> Self {
        Self(vk.to_bytes())
    }
}

impl From<Ed25519Pubkey> for [u8; 32] {
    fn from(k: Ed25519Pubkey) -> Self {
        k.0
    }
}

impl AsRef<[u8]> for Ed25519Pubkey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// --- Ed25519Sig ---

impl Ed25519Sig {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut arr = [0u8; 64];
        hex::decode_to_slice(s, &mut arr)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn to_signature(&self) -> ed25519_dalek::Signature {
        ed25519_dalek::Signature::from_bytes(&self.0)
    }
}

impl fmt::Debug for Ed25519Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Sig({}…)", &hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for Ed25519Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}…", &hex::encode(&self.0[..8]))
    }
}

impl From<[u8; 64]> for Ed25519Sig {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl From<ed25519_dalek::Signature> for Ed25519Sig {
    fn from(sig: ed25519_dalek::Signature) -> Self {
        Self(sig.to_bytes())
    }
}

impl From<Ed25519Sig> for [u8; 64] {
    fn from(s: Ed25519Sig) -> Self {
        s.0
    }
}

impl AsRef<[u8]> for Ed25519Sig {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// --- HexBytes ---

/// Maximum deserialized length for HexBytes (16 KiB — covers Lamport signatures).
const MAX_HEX_BYTES_LEN: usize = 16_384;

impl HexBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        Ok(Self(hex::decode(s)?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl fmt::Debug for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preview = &self.0[..self.0.len().min(4)];
        write!(
            f,
            "HexBytes({}… [{} bytes])",
            hex::encode(preview),
            self.0.len()
        )
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HexBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_hash_roundtrip() {
        let h = HexHash::from_bytes([0xab; 32]);
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        let back: HexHash = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn hex_hash_from_hex() {
        let hex_str = "ab".repeat(32);
        let h = HexHash::from_hex(&hex_str).unwrap();
        assert_eq!(h.0, [0xab; 32]);
    }

    #[test]
    fn hex_hash_from_hex_invalid() {
        assert!(HexHash::from_hex("not_hex").is_err());
        assert!(HexHash::from_hex(&"ab".repeat(16)).is_err());
    }

    #[test]
    fn ed25519_pubkey_roundtrip() {
        let k = Ed25519Pubkey::from_bytes([0x01; 32]);
        let json = serde_json::to_string(&k).unwrap();
        let back: Ed25519Pubkey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn ed25519_sig_roundtrip() {
        let s = Ed25519Sig::from_bytes([0xff; 64]);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, format!("\"{}\"", "ff".repeat(64)));
        let back: Ed25519Sig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn hex_bytes_roundtrip() {
        let b = HexBytes::new(vec![1, 2, 3, 4, 5]);
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, "\"0102030405\"");
        let back: HexBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn display_formats() {
        let h = HexHash::from_bytes([0xde; 32]);
        assert_eq!(h.to_hex(), "de".repeat(32));
        assert_eq!(format!("{h}"), "de".repeat(32));
    }
}
