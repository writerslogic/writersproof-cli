// SPDX-License-Identifier: Apache-2.0

//! C2PA Manifest embedding for unstructured text using Unicode Variation Selectors.
//!
//! Implements the `C2PATextManifestWrapper` structure per C2PA spec section
//! "Embedding Manifests into Unstructured Text". Each byte of the JUMBF
//! manifest is encoded as a Unicode Variation Selector character that is
//! visually non-rendering.

/// Magic bytes: "C2PATXT\0" (0x4332504154585400)
const MAGIC: [u8; 8] = [0x43, 0x32, 0x50, 0x41, 0x54, 0x58, 0x54, 0x00];
const VERSION: u8 = 1;
const HEADER_SIZE: usize = 8 + 1 + 4; // magic + version + manifestLength

/// Zero-Width No-Break Space prefix (U+FEFF).
const ZWNBSP: char = '\u{FEFF}';

/// Convert a byte to the corresponding Unicode Variation Selector codepoint.
fn byte_to_variation_selector(b: u8) -> char {
    if b <= 15 {
        // U+FE00..U+FE0F (base variation selectors)
        char::from_u32(0xFE00 + b as u32).unwrap()
    } else {
        // U+E0100..U+E01EF (supplementary variation selectors)
        char::from_u32(0xE0100 + (b as u32 - 16)).unwrap()
    }
}

/// Convert a Unicode Variation Selector codepoint back to a byte.
/// Returns `None` if the codepoint is not a valid variation selector.
fn variation_selector_to_byte(cp: u32) -> Option<u8> {
    if (0xFE00..=0xFE0F).contains(&cp) {
        Some((cp - 0xFE00) as u8)
    } else if (0xE0100..=0xE01EF).contains(&cp) {
        Some((cp - 0xE0100) as u8 + 16)
    } else {
        None
    }
}

/// Encode raw bytes as a sequence of Unicode Variation Selector characters.
fn encode_bytes_as_vs(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4);
    for &b in bytes {
        out.push(byte_to_variation_selector(b));
    }
    out
}

/// Compute the deterministic target wrapper byte length for a manifest of
/// `manifest_len` bytes, per the C2PA spec formula:
///   E_target = 3 + (HEADER_SIZE + M) * 4 + 6
fn deterministic_exclusion_length(manifest_len: usize) -> usize {
    3 + (HEADER_SIZE + manifest_len) * 4 + 6
}

/// Build the `C2PATextManifestWrapper` binary payload (before VS encoding).
fn build_wrapper_bytes(jumbf: &[u8]) -> Vec<u8> {
    let manifest_len = jumbf.len() as u32;
    let mut payload = Vec::with_capacity(HEADER_SIZE + jumbf.len());
    payload.extend_from_slice(&MAGIC);
    payload.push(VERSION);
    payload.extend_from_slice(&manifest_len.to_be_bytes());
    payload.extend_from_slice(jumbf);
    payload
}

/// Encode a C2PA JUMBF manifest as a `C2PATextManifestWrapper` string
/// suitable for appending to unstructured text.
///
/// Returns the encoded string (ZWNBSP prefix + variation selectors) and the
/// deterministic exclusion byte length for use in `c2pa.hash.data`.
pub fn encode_text_manifest(jumbf: &[u8]) -> (String, usize) {
    let wrapper_bytes = build_wrapper_bytes(jumbf);
    let encoded = encode_bytes_as_vs(&wrapper_bytes);

    // Compute actual UTF-8 byte length of the encoded wrapper (without prefix).
    let actual_vs_len: usize = encoded.len();
    let e_target = deterministic_exclusion_length(jumbf.len());

    // The prefix ZWNBSP is 3 bytes in UTF-8.
    let actual_total = 3 + actual_vs_len;
    let gap = e_target.saturating_sub(actual_total);

    // Decompose gap = 3a + 4b where b = gap % 3, a = (gap - 4b) / 3
    let b_count = gap % 3;
    let a_count = (gap - 4 * b_count) / 3;

    // Padding: a_count bytes of 0x00 (encodes to 3-byte VS) + b_count bytes of 0x10 (4-byte VS)
    let mut padding_bytes = Vec::with_capacity(a_count + b_count);
    padding_bytes.resize(a_count, 0x00);
    padding_bytes.resize(a_count + b_count, 0x10);
    let padding_vs = encode_bytes_as_vs(&padding_bytes);

    let mut result = String::with_capacity(3 + actual_vs_len + padding_vs.len());
    result.push(ZWNBSP);
    result.push_str(&encoded);
    result.push_str(&padding_vs);

    (result, e_target)
}

/// Decode a `C2PATextManifestWrapper` from a text string.
///
/// Scans for ZWNBSP + variation selector sequences, validates the magic
/// number, and extracts the JUMBF manifest bytes.
///
/// Returns the JUMBF manifest bytes on success.
pub fn decode_text_manifest(text: &str) -> Result<Vec<u8>, &'static str> {
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != ZWNBSP {
            continue;
        }

        // Collect contiguous variation selectors.
        let mut vs_bytes = Vec::new();
        while let Some(&next) = chars.peek() {
            let cp = next as u32;
            if let Some(b) = variation_selector_to_byte(cp) {
                vs_bytes.push(b);
                chars.next();
            } else {
                break;
            }
        }

        if vs_bytes.len() < HEADER_SIZE {
            continue;
        }

        // Check magic.
        if vs_bytes[..8] != MAGIC {
            continue;
        }

        // Check version.
        if vs_bytes[8] != VERSION {
            return Err("manifest.text.corruptedWrapper: unsupported version");
        }

        // Read manifest length (big-endian u32).
        let manifest_len =
            u32::from_be_bytes([vs_bytes[9], vs_bytes[10], vs_bytes[11], vs_bytes[12]]) as usize;

        if vs_bytes.len() < HEADER_SIZE + manifest_len {
            return Err("manifest.text.corruptedWrapper: truncated manifest");
        }

        let jumbf = vs_bytes[HEADER_SIZE..HEADER_SIZE + manifest_len].to_vec();
        return Ok(jumbf);
    }

    Err("manifest.text.corruptedWrapper: no wrapper found")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small_manifest() {
        let manifest = b"test-jumbf-data-here";
        let (encoded, exclusion_len) = encode_text_manifest(manifest);

        // Should start with ZWNBSP.
        assert!(encoded.starts_with('\u{FEFF}'));

        // Should be invisible (no printable characters).
        for c in encoded.chars() {
            assert!(
                c == ZWNBSP
                    || (0xFE00..=0xFE0F).contains(&(c as u32))
                    || (0xE0100..=0xE01EF).contains(&(c as u32)),
                "unexpected visible character: U+{:04X}",
                c as u32
            );
        }

        // Exclusion length should match actual UTF-8 byte length.
        assert_eq!(encoded.len(), exclusion_len);

        // Roundtrip decode.
        let decoded = decode_text_manifest(&encoded).unwrap();
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn roundtrip_with_surrounding_text() {
        let manifest = b"\x00\x01\x0F\x10\xFF";
        let (wrapper, _) = encode_text_manifest(manifest);

        let text = format!("Hello, world! This is a document.{wrapper}");
        let decoded = decode_text_manifest(&text).unwrap();
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn detect_no_wrapper() {
        let result = decode_text_manifest("Just plain text.");
        assert!(result.is_err());
    }

    #[test]
    fn byte_to_vs_coverage() {
        // 0x00 -> U+FE00, 0x0F -> U+FE0F
        assert_eq!(byte_to_variation_selector(0x00) as u32, 0xFE00);
        assert_eq!(byte_to_variation_selector(0x0F) as u32, 0xFE0F);
        // 0x10 -> U+E0100, 0xFF -> U+E01EF
        assert_eq!(byte_to_variation_selector(0x10) as u32, 0xE0100);
        assert_eq!(byte_to_variation_selector(0xFF) as u32, 0xE01EF);
    }

    #[test]
    fn vs_to_byte_roundtrip() {
        for b in 0..=255u8 {
            let vs = byte_to_variation_selector(b);
            assert_eq!(variation_selector_to_byte(vs as u32), Some(b));
        }
    }

    #[test]
    fn deterministic_padding_length() {
        // For any manifest size, the encoded wrapper UTF-8 length
        // should exactly equal the deterministic exclusion length.
        for size in [0, 1, 13, 100, 1000, 10000] {
            let manifest = vec![0xABu8; size];
            let (encoded, exclusion_len) = encode_text_manifest(&manifest);
            assert_eq!(
                encoded.len(),
                exclusion_len,
                "mismatch for manifest size {size}"
            );
        }
    }
}
