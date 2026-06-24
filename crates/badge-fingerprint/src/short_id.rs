//! Deterministic `WP-XXXX-XXXX` short-id derived from an existing WritersProof
//! identifier (an author DID, or a verify.writersproof.com id).
//!
//! The fingerprint badge is a *visual commitment* to this short-id. Deriving the
//! short-id from an identifier we already assign — rather than inventing a
//! parallel id system — keeps a single source of truth: the engine derives it at
//! issuance and the verify portal can recompute it to cross-check the value
//! carried in the signed credential.

use sha2::{Digest, Sha256};

/// Crockford base32 alphabet (no I, L, O, U — unambiguous when read aloud or
/// transcribed from a printout/fax).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Domain-separation tag. Bumping the version cleanly re-keys every short-id.
const DST: &str = "wp-short-id-v1:";

/// Derive the human-readable `WP-XXXX-XXXX` short-id from an existing identifier.
///
/// Deterministic and platform-independent: the same identifier always yields the
/// same short-id, so the value the engine signs into the credential matches what
/// the verify portal recomputes.
pub fn short_id_from_identifier(identifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DST.as_bytes());
    hasher.update(identifier.as_bytes());
    let digest = hasher.finalize();

    // Take the first 40 bits and encode as 8 Crockford base32 characters.
    let mut acc: u64 = 0;
    for &b in digest.iter().take(5) {
        acc = (acc << 8) | b as u64;
    }
    let mut chars = [0u8; 8];
    for (i, slot) in chars.iter_mut().enumerate() {
        let shift = 5 * (7 - i);
        let idx = ((acc >> shift) & 0x1f) as usize;
        *slot = CROCKFORD[idx];
    }
    // `chars` is ASCII by construction.
    let s = core::str::from_utf8(&chars).unwrap_or("00000000");
    format!("WP-{}-{}", &s[..4], &s[4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_well_formed() {
        let a = short_id_from_identifier("did:key:z6MkExample");
        let b = short_id_from_identifier("did:key:z6MkExample");
        assert_eq!(a, b);
        assert!(a.starts_with("WP-"));
        assert_eq!(a.len(), 12); // WP-XXXX-XXXX
        assert_eq!(a.as_bytes()[7], b'-');
        // Only Crockford-safe characters in the two groups.
        for c in a[3..].chars().filter(|c| *c != '-') {
            assert!(CROCKFORD.contains(&(c as u8)), "char {c} not in alphabet");
        }
    }

    #[test]
    fn distinct_identifiers_distinct_ids() {
        assert_ne!(
            short_id_from_identifier("did:key:z6MkAlice"),
            short_id_from_identifier("did:key:z6MkBob")
        );
    }
}
