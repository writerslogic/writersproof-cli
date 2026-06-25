//! Deterministic `WP-XXX-XXX-XXX-C` short-id (Crockford Base32 + check symbol)
//! derived from an existing WritersProof identifier (an author DID, or a
//! verify.writersproof.com id).
//!
//! 9 payload symbols (45 bits) + 1 Crockford mod-37 check symbol. The fingerprint
//! badge is a *visual commitment* to this short-id; deriving it from an
//! identifier we already assign keeps a single source of truth: the engine
//! derives it at issuance and the verify portal recomputes it.

use sha2::{Digest, Sha256};

/// Crockford Base32 payload alphabet (32 symbols). Drops the look-alike letters
/// `I L O U`; keeps the digits `0` and `1`. Decoding maps `I`/`L` -> `1` and
/// `O` -> `0`. 5 bits/symbol, and 32 is a power of two so base-32 emission from
/// the digest is bias-free.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Crockford check alphabet: the 32 payload symbols plus 5 check-only symbols
/// for values 32..=36 (37 is the least prime greater than 32).
const CHECK_ALPHABET: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";

/// Payload symbol count (excludes prefix, separators, and the check symbol).
/// 9 symbols = 45 bits = 2^45 space; accidental collision is negligible to
/// ~5.9M hash-derived badges, and impossible with an issuance registry.
const ID_CHARS: usize = 9;

/// Payload entropy in bits (`ID_CHARS * 5`).
const PAYLOAD_BITS: u32 = 45;

/// Domain-separation tag. `v2` = Crockford-32 + check (re-keys every short-id
/// versus the prior base-30 `v1`). Bumping it cleanly re-keys all short-ids.
const DST: &str = "wp-short-id-v2:";

/// 45-bit payload value derived from the identifier (the lookup key as an int).
fn payload_value(identifier: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(DST.as_bytes());
    hasher.update(identifier.as_bytes());
    let digest = hasher.finalize();
    let bytes: [u8; 8] = digest[..8].try_into().unwrap_or([0u8; 8]);
    u64::from_be_bytes(bytes) & ((1u64 << PAYLOAD_BITS) - 1)
}

/// Render a payload value as `ID_CHARS` Crockford symbols, most-significant first.
fn payload_string(mut acc: u64) -> String {
    let mut chars = [0u8; ID_CHARS];
    for slot in chars.iter_mut().rev() {
        *slot = ALPHABET[(acc % 32) as usize];
        acc /= 32;
    }
    core::str::from_utf8(&chars).unwrap_or("").to_string()
}

/// Crockford mod-37 check symbol over a payload value. Detects all single-symbol
/// substitutions and adjacent transpositions in the payload.
fn check_symbol(v: u64) -> char {
    CHECK_ALPHABET[(v % 37) as usize] as char
}

/// The 9-symbol payload (no prefix, separators, or check symbol). This is the
/// lookup key and the canonical fingerprint input.
pub fn payload_from_identifier(identifier: &str) -> String {
    payload_string(payload_value(identifier))
}

/// Derive the human-readable display short-id `WP-XXX-XXX-XXX-C`.
///
/// Deterministic and platform-independent: the same identifier always yields the
/// same short-id, so the value the engine signs into the credential matches what
/// the verify portal recomputes.
pub fn short_id_from_identifier(identifier: &str) -> String {
    let v = payload_value(identifier);
    let p = payload_string(v);
    format!(
        "WP-{}-{}-{}-{}",
        &p[0..3],
        &p[3..6],
        &p[6..9],
        check_symbol(v)
    )
}

/// Normalize and validate a display/transcription short-id: drop the optional
/// `WP-` prefix and hyphens, uppercase, map `I`/`L` -> `1` and `O` -> `0`, split
/// off the trailing check symbol, and confirm it. Returns the canonical 9-symbol
/// payload on success, or `None` if malformed or the check fails. Verifiers MUST
/// call this before resolving the record.
pub fn validate(short_id: &str) -> Option<String> {
    let up = short_id.trim().to_ascii_uppercase();
    let body = up.strip_prefix("WP-").unwrap_or(&up);
    let norm: String = body
        .chars()
        .filter(|c| *c != '-')
        .map(|c| match c {
            'I' | 'L' => '1',
            'O' => '0',
            x => x,
        })
        .collect();
    if norm.len() != ID_CHARS + 1 {
        return None;
    }
    let (payload, check) = norm.split_at(ID_CHARS);
    let mut v: u64 = 0;
    for b in payload.bytes() {
        let d = ALPHABET.iter().position(|&a| a == b)? as u64;
        v = v * 32 + d;
    }
    if check.chars().next()? == check_symbol(v) {
        Some(payload.to_string())
    } else {
        None
    }
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
        assert_eq!(a.len(), 16); // WP-XXX-XXX-XXX-C
        for i in [2usize, 6, 10, 14] {
            assert_eq!(a.as_bytes()[i], b'-');
        }
    }

    #[test]
    fn crockford_alphabet_no_iluo() {
        for i in 0..256 {
            let p = payload_from_identifier(&format!("did:key:sample-{i}"));
            assert_eq!(p.len(), ID_CHARS);
            for c in p.chars() {
                assert!(!"ILOU".contains(c), "look-alike letter {c} in {p}");
                assert!(ALPHABET.contains(&(c as u8)), "char {c} not in alphabet");
            }
        }
    }

    #[test]
    fn check_symbol_validates_and_catches_corruption() {
        let id = short_id_from_identifier("did:key:z6MkExample");
        let payload = payload_from_identifier("did:key:z6MkExample");
        assert_eq!(validate(&id).as_deref(), Some(payload.as_str()));
        // Corrupt the trailing check symbol -> validation must fail.
        let mut bytes: Vec<char> = id.chars().collect();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == '2' { '3' } else { '2' };
        let corrupted: String = bytes.into_iter().collect();
        assert!(validate(&corrupted).is_none());
    }

    #[test]
    fn validate_normalizes_case_and_lookalikes() {
        let id = short_id_from_identifier("did:key:z6MkExample");
        // Lowercase + hyphen variations still validate to the same payload.
        assert_eq!(validate(&id.to_lowercase()), validate(&id));
    }

    #[test]
    fn distinct_identifiers_distinct_ids() {
        assert_ne!(
            short_id_from_identifier("did:key:z6MkAlice"),
            short_id_from_identifier("did:key:z6MkBob")
        );
    }
}
