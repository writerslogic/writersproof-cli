//! Deterministic `WP-XXXX-XXXX-XXXX-XXXX` short-id derived from an existing
//! WritersProof identifier (an author DID, or a verify.writersproof.com id).
//!
//! The fingerprint badge is a *visual commitment* to this short-id. Deriving the
//! short-id from an identifier we already assign — rather than inventing a
//! parallel id system — keeps a single source of truth: the engine derives it at
//! issuance and the verify portal can recompute it to cross-check the value
//! carried in the signed credential.

use sha2::{Digest, Sha256};

/// Unambiguous alphabet: digits and uppercase letters with the look-alikes
/// `0 1 I L O U` removed (so no 0/O, 1/I/L, or U/V confusion when read aloud,
/// printed, or faxed). 30 symbols.
const ALPHABET: &[u8; 30] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Number of payload characters. 30^16 ≈ 2^78.5, so two distinct identifiers
/// collide with negligible probability even at billions of badges — the value
/// is hash-derived, so this is the only collision surface.
const ID_CHARS: usize = 16;

/// Domain-separation tag. Bumping the version cleanly re-keys every short-id.
const DST: &str = "wp-short-id-v1:";

/// Derive the human-readable `WP-XXXX-XXXX-XXXX-XXXX` short-id from an existing
/// identifier.
///
/// Deterministic and platform-independent: the same identifier always yields the
/// same short-id, so the value the engine signs into the credential matches what
/// the verify portal recomputes.
pub fn short_id_from_identifier(identifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DST.as_bytes());
    hasher.update(identifier.as_bytes());
    let digest = hasher.finalize();

    // Treat the first 128 bits of the digest as a big-endian integer and emit
    // `ID_CHARS` base-30 digits (most-significant first). The residual bias from
    // 30^16 not dividing 2^128 is ~2^-49 — astronomically small.
    let bytes: [u8; 16] = digest[..16].try_into().unwrap_or([0u8; 16]);
    let mut acc = u128::from_be_bytes(bytes);
    let mut chars = [0u8; ID_CHARS];
    for slot in chars.iter_mut().rev() {
        *slot = ALPHABET[(acc % 30) as usize];
        acc /= 30;
    }

    // `chars` is ASCII by construction.
    let s = core::str::from_utf8(&chars).unwrap_or("");
    format!("WP-{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16])
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
        assert_eq!(a.len(), 22); // WP-XXXX-XXXX-XXXX-XXXX
                                 // Group separators.
        for i in [2usize, 7, 12, 17] {
            assert_eq!(a.as_bytes()[i], b'-');
        }
    }

    #[test]
    fn no_ambiguous_characters() {
        // Sample a spread of identifiers and confirm the payload never contains
        // a look-alike character.
        for i in 0..256 {
            let id = short_id_from_identifier(&format!("did:key:sample-{i}"));
            for c in id.chars().filter(|c| *c != '-' && *c != 'W' && *c != 'P') {
                assert!(!"01ILOU".contains(c), "ambiguous char {c} in {id}");
                assert!(ALPHABET.contains(&(c as u8)), "char {c} not in alphabet");
            }
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
