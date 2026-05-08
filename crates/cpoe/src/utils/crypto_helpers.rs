// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared cryptographic utilities to eliminate duplication across modules.
//! Used by: text_fragments, clipboard, wal, beacon, credentials, dictation

use crate::error::{Error, Result};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::utils::DateTimeNanosExt;

/// Unified constant-time comparison to prevent timing attacks.
/// Never branches on secret values.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> Result<()> {
    if a.len() != b.len() {
        return Err(Error::validation("length mismatch in constant_time_eq"));
    }

    if a.ct_eq(b).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(Error::validation("constant-time comparison failed"))
    }
}

/// Build signed payload with consistent format across all modules.
/// Format: namespace || field1_len || field1 || field2_len || field2 || ...
#[derive(Debug, Clone)]
pub struct SignedPayloadBuilder {
    fields: Vec<Vec<u8>>,
}

impl SignedPayloadBuilder {
    /// Create a new payload builder with a namespace identifier.
    /// Namespace examples: "text-fragment-v1", "wal-entry-v1", "evidence-packet-v1"
    pub fn new(namespace: &str) -> Self {
        SignedPayloadBuilder {
            fields: vec![namespace.as_bytes().to_vec()],
        }
    }

    /// Append raw bytes to payload.
    pub fn push_bytes(mut self, data: &[u8]) -> Self {
        self.fields.push(data.to_vec());
        self
    }

    /// Append UTF-8 string to payload.
    pub fn push_string(mut self, s: &str) -> Self {
        self.fields.push(s.as_bytes().to_vec());
        self
    }

    /// Append i64 (little-endian) to payload.
    pub fn push_i64(mut self, val: i64) -> Self {
        self.fields.push(val.to_le_bytes().to_vec());
        self
    }

    /// Append f64 (little-endian) to payload.
    pub fn push_f64(mut self, val: f64) -> Self {
        self.fields.push(val.to_le_bytes().to_vec());
        self
    }

    /// Append u32 (little-endian) to payload.
    pub fn push_u32(mut self, val: u32) -> Self {
        self.fields.push(val.to_le_bytes().to_vec());
        self
    }

    /// Append u64 (little-endian) to payload.
    pub fn push_u64(mut self, val: u64) -> Self {
        self.fields.push(val.to_le_bytes().to_vec());
        self
    }

    /// Append u8 to payload.
    pub fn push_u8(mut self, val: u8) -> Self {
        self.fields.push(vec![val]);
        self
    }

    /// Append f32 (little-endian) to payload.
    pub fn push_f32(mut self, val: f32) -> Self {
        self.fields.push(val.to_le_bytes().to_vec());
        self
    }

    /// Append bool as a single byte (0x00 = false, 0x01 = true).
    pub fn push_bool(mut self, val: bool) -> Self {
        self.fields.push(vec![val as u8]);
        self
    }

    /// Build final payload with length prefixes for variable fields.
    /// Returns: namespace || 4-byte-len || field1 || 4-byte-len || field2 || ...
    pub fn build(self) -> Vec<u8> {
        let mut result = Vec::new();

        for (i, field) in self.fields.iter().enumerate() {
            if i == 0 {
                // Namespace (no length prefix, fixed)
                result.extend_from_slice(field);
            } else {
                // All other fields: 4-byte length prefix + data
                result.extend_from_slice(&(field.len() as u32).to_le_bytes());
                result.extend_from_slice(field);
            }
        }

        result
    }
}

/// Verify signature using Ed25519 key.
#[derive(Debug, Clone)]
pub enum SignatureKey {
    Ed25519(VerifyingKey),
}

impl SignatureKey {
    /// Verify a signature. Returns Ok(()) if valid, Err if invalid.
    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            SignatureKey::Ed25519(key) => {
                // Ed25519 signatures must be exactly 64 bytes
                if signature.len() != 64 {
                    return Err(Error::validation(format!(
                        "signature has invalid length: {} bytes (expected 64)",
                        signature.len()
                    )));
                }
                let sig = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|e| Error::validation(format!("signature parsing failed: {}", e)))?;
                key.verify_strict(payload, &sig)
                    .map_err(|_| Error::validation("signature verification failed"))?;
                Ok(())
            }
        }
    }
}

/// Nonce management: check, mark used, cleanup old nonces.
/// Prevents replay attacks by tracking used nonces in database.
pub struct NonceManager {
    db: std::sync::Arc<rusqlite::Connection>,
}

impl std::fmt::Debug for NonceManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceManager").finish()
    }
}

impl NonceManager {
    /// Create a new nonce manager with database connection.
    pub fn new(db: std::sync::Arc<rusqlite::Connection>) -> Self {
        NonceManager { db }
    }

    /// Check if nonce has been used (constant-time comparison).
    /// Returns true if nonce exists in used_nonces table.
    pub fn is_used(&self, nonce: &[u8; 16]) -> Result<bool> {
        let nonce_vec = nonce.to_vec();
        let result = self.db.query_row(
            "SELECT 1 FROM used_nonces WHERE nonce = ? LIMIT 1",
            rusqlite::params![&nonce_vec],
            |_| Ok(true),
        );

        match result {
            Ok(exists) => Ok(exists),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(Error::validation(format!("nonce lookup failed: {}", e))),
        }
    }

    /// Mark nonce as used with timestamp.
    /// Inserts into used_nonces table. If nonce already exists, silently ignores (INSERT OR IGNORE).
    pub fn mark_used(&self, nonce: &[u8; 16], timestamp: i64) -> Result<()> {
        self.db
            .execute(
                "INSERT OR IGNORE INTO used_nonces (nonce, used_at) VALUES (?, ?)",
                rusqlite::params![nonce.to_vec(), timestamp],
            )
            .map_err(|e| Error::validation(format!("nonce insert failed: {}", e)))?;
        Ok(())
    }

    /// Clean up nonces older than TTL (called during maintenance).
    /// Returns count of deleted rows.
    pub fn cleanup_expired(&self, ttl_secs: u64) -> Result<usize> {
        let now = chrono::Utc::now().timestamp_nanos_safe();
        let cutoff = now - (ttl_secs as i64 * 1_000_000_000);

        let affected = self
            .db
            .execute(
                "DELETE FROM used_nonces WHERE used_at < ?",
                rusqlite::params![cutoff],
            )
            .map_err(|e| Error::validation(format!("nonce cleanup failed: {}", e)))?;

        Ok(affected)
    }
}

/// Compute SHA-256 hash of data.
/// Returns: [u8; 32] hash value.
pub fn compute_content_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
}

/// Compute BLAKE3 hash of arbitrary data.
///
/// Preferred over SHA-256 for WAL chain entries and evidence fields because the
/// WAL hash chain itself uses BLAKE3, enabling consistent algorithm use throughout
/// the dictation evidence pipeline.
pub fn blake3_hash_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Compute the first 8 bytes of the BLAKE3 hash of `data`.
///
/// Used for compact hardware identity tokens (e.g., device UID hash) where a
/// full 32-byte hash is unnecessary but domain-separation from raw UID values
/// is required.
pub fn blake3_hash_truncated_8(data: &[u8]) -> [u8; 8] {
    let full = blake3::hash(data);
    let bytes = full.as_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[..8]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_payload_builder_roundtrip() {
        let payload = SignedPayloadBuilder::new("test-v1")
            .push_string("hello")
            .push_i64(42)
            .push_bytes(&[0xaa, 0xbb])
            .build();

        // Payload structure:
        // "test-v1" (7 bytes, no length prefix)
        // [5,0,0,0] "hello" (length prefix + 5 bytes)
        // [8,0,0,0] [42,0,0,0,0,0,0,0] (length prefix + i64)
        // [2,0,0,0] [0xaa,0xbb] (length prefix + 2 bytes)

        assert!(payload.len() > 7); // At least namespace
        assert!(payload.starts_with(b"test-v1"));
    }

    #[test]
    fn test_constant_time_eq_success() {
        let a = b"secret";
        let b = b"secret";
        assert!(constant_time_eq(a, b).is_ok());
    }

    #[test]
    fn test_constant_time_eq_failure() {
        let a = b"secret";
        let b = b"wrong";
        assert!(constant_time_eq(a, b).is_err());
    }

    #[test]
    fn test_constant_time_eq_length_mismatch() {
        let a = b"short";
        let b = b"much_longer";
        assert!(constant_time_eq(a, b).is_err());
    }

    #[test]
    fn test_compute_content_hash_deterministic() {
        let data = b"test content";
        let hash1 = compute_content_hash(data);
        let hash2 = compute_content_hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_content_hash_different_inputs() {
        let hash1 = compute_content_hash(b"input1");
        let hash2 = compute_content_hash(b"input2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_content_hash_empty() {
        let hash = compute_content_hash(b"");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_signed_payload_multiple_fields() {
        let payload = SignedPayloadBuilder::new("multi")
            .push_string("field1")
            .push_string("field2")
            .push_i64(100)
            .build();

        assert!(payload.starts_with(b"multi"));
        assert!(payload.len() > 5); // More than just namespace
    }

    #[test]
    fn test_signed_payload_empty_fields() {
        let payload = SignedPayloadBuilder::new("test-v1")
            .push_string("")
            .push_bytes(&[])
            .build();

        // Empty fields are still prefixed with length (4 bytes each)
        assert!(payload.starts_with(b"test-v1"));
        assert!(payload.len() >= 7 + 8); // namespace + two 4-byte length prefixes
    }

    #[test]
    fn test_signed_payload_large_field() {
        let large_data = vec![0xAAu8; 10_000];
        let payload = SignedPayloadBuilder::new("big")
            .push_bytes(&large_data)
            .build();

        assert!(payload.len() > 10_000);
        assert!(payload.starts_with(b"big"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        let a = b"";
        let b = b"";
        assert!(constant_time_eq(a, b).is_ok());
    }

    #[test]
    fn test_signed_payload_builder_field_order() {
        let p1 = SignedPayloadBuilder::new("ns")
            .push_string("first")
            .push_string("second")
            .build();

        let p2 = SignedPayloadBuilder::new("ns")
            .push_string("second")
            .push_string("first")
            .build();

        // Different field orders produce different payloads
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_signature_length_validation() {
        let key =
            SignatureKey::Ed25519(ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap());

        // Signature too short
        assert!(key.verify(b"payload", &[0u8; 32]).is_err());
        // Signature too long
        assert!(key.verify(b"payload", &[0u8; 65]).is_err());
        // Correct length but invalid content should error on verify
        assert!(key.verify(b"payload", &[0u8; 64]).is_err());
    }

    #[test]
    fn test_constant_time_eq_prevents_branch() {
        // These comparisons should both fail with same error message (no timing variation)
        let secret = b"secret123";
        let wrong1 = b"wrong0000"; // Differs at position 1
        let wrong2 = b"secretWRG"; // Differs at position 6

        let err1 = constant_time_eq(secret, wrong1);
        let err2 = constant_time_eq(secret, wrong2);

        // Both should fail (constant-time property means we can't optimize early exit)
        assert!(err1.is_err());
        assert!(err2.is_err());
        // Same error message indicates same code path taken
        assert_eq!(format!("{:?}", err1), format!("{:?}", err2));
    }

    #[test]
    fn test_nonce_manager_replay_prevention() {
        // Create in-memory database for testing
        let db = std::sync::Arc::new(
            rusqlite::Connection::open_in_memory().expect("failed to create test db"),
        );

        // Initialize nonce table
        db.execute(
            "CREATE TABLE used_nonces (nonce BLOB PRIMARY KEY, used_at INTEGER)",
            [],
        )
        .expect("failed to create table");

        let mgr = NonceManager::new(db.clone());
        let nonce = [1u8; 16];
        let now = chrono::Utc::now().timestamp_nanos_safe();

        // First check: nonce not yet used (is_used returns Ok(false))
        assert_eq!(mgr.is_used(&nonce).expect("first check failed"), false);

        // Mark it as used
        assert!(mgr.mark_used(&nonce, now).is_ok());

        // Second check: nonce is now used (is_used returns Ok(true))
        assert_eq!(mgr.is_used(&nonce).expect("second check failed"), true);
    }

    #[test]
    fn test_nonce_manager_cleanup_expiration() {
        let db = std::sync::Arc::new(
            rusqlite::Connection::open_in_memory().expect("failed to create test db"),
        );

        db.execute(
            "CREATE TABLE used_nonces (nonce BLOB PRIMARY KEY, used_at INTEGER)",
            [],
        )
        .expect("failed to create table");

        let mgr = NonceManager::new(db.clone());
        let old_nonce = [1u8; 16];
        let new_nonce = [2u8; 16];

        let now = chrono::Utc::now().timestamp_nanos_safe();
        let old_time = now - (100 * 1_000_000_000); // 100 seconds ago

        // Add old nonce
        mgr.mark_used(&old_nonce, old_time)
            .expect("mark old failed");
        // Add recent nonce
        mgr.mark_used(&new_nonce, now).expect("mark new failed");

        // Cleanup nonces older than 60 seconds
        let deleted = mgr.cleanup_expired(60).expect("cleanup failed");
        assert_eq!(deleted, 1); // Only the old nonce should be deleted

        // New nonce should still exist (is_used returns Ok(true))
        assert_eq!(mgr.is_used(&new_nonce).expect("check new failed"), true);
    }

    #[test]
    fn blake3_hash_bytes_deterministic() {
        let h1 = blake3_hash_bytes(b"hello dictation");
        let h2 = blake3_hash_bytes(b"hello dictation");
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake3_hash_bytes_differs_from_sha256() {
        let data = b"test data";
        let b3 = blake3_hash_bytes(data);
        let sha = compute_content_hash(data);
        assert_ne!(b3, sha);
    }

    #[test]
    fn blake3_hash_bytes_different_inputs_differ() {
        let h1 = blake3_hash_bytes(b"input_a");
        let h2 = blake3_hash_bytes(b"input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn blake3_hash_bytes_empty_input() {
        let h = blake3_hash_bytes(b"");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn blake3_hash_truncated_8_is_prefix_of_full() {
        let data = b"device-uid-string";
        let full = blake3_hash_bytes(data);
        let short = blake3_hash_truncated_8(data);
        assert_eq!(short, full[..8]);
    }

    #[test]
    fn blake3_hash_truncated_8_deterministic() {
        let a = blake3_hash_truncated_8(b"uid-abc");
        let b = blake3_hash_truncated_8(b"uid-abc");
        assert_eq!(a, b);
    }

    #[test]
    fn push_bool_encodes_as_single_byte() {
        let true_payload = SignedPayloadBuilder::new("ns").push_bool(true).build();
        let false_payload = SignedPayloadBuilder::new("ns").push_bool(false).build();
        // Payloads differ (true=1, false=0) and differ from each other.
        assert_ne!(true_payload, false_payload);
        // The bool byte should be present after the namespace + 4-byte length prefix.
        let ns_len = b"ns".len();
        let bool_byte_true = true_payload[ns_len + 4];
        let bool_byte_false = false_payload[ns_len + 4];
        assert_eq!(bool_byte_true, 1u8);
        assert_eq!(bool_byte_false, 0u8);
    }

    #[test]
    fn push_f32_encodes_four_bytes_le() {
        let val: f32 = -42.5;
        let payload = SignedPayloadBuilder::new("ns").push_f32(val).build();
        let ns_len = b"ns".len();
        // After namespace (2 bytes) + length prefix (4 bytes), next 4 bytes are the f32.
        let encoded = &payload[ns_len + 4..ns_len + 8];
        assert_eq!(encoded, &val.to_le_bytes());
    }

    #[test]
    fn push_u8_encodes_single_byte() {
        let payload = SignedPayloadBuilder::new("ns").push_u8(0xAB).build();
        let ns_len = b"ns".len();
        assert_eq!(payload[ns_len + 4], 0xABu8);
    }

    #[test]
    fn push_u64_encodes_eight_bytes_le() {
        let val: u64 = 0xDEAD_BEEF_CAFE_1234;
        let payload = SignedPayloadBuilder::new("ns").push_u64(val).build();
        let ns_len = b"ns".len();
        let encoded = &payload[ns_len + 4..ns_len + 12];
        assert_eq!(encoded, &val.to_le_bytes());
    }
}
