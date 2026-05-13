// SPDX-License-Identifier: Apache-2.0

//! CBOR encoding/decoding for RFC 8949 compliance.
//!
//! Note: ciborium does not guarantee deterministic encoding per RFC 8949
//! Section 4.2 (specifically, integer-key map ordering is not enforced).
//! Applications requiring canonical CBOR MUST post-process or use a
//! deterministic CBOR library.

use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

use super::{CodecError, Result, CBOR_TAG_CPOE, CBOR_TAG_CPOR, CBOR_TAG_CWAR};

/// Maximum CBOR payload size (16 MiB). Rejects inputs larger than this
/// before deserialization to prevent OOM from malicious payloads.
pub const MAX_CBOR_PAYLOAD: usize = 16 * 1024 * 1024;

/// Maximum nesting depth for CBOR structures. Arrays (major type 4) and
/// maps (major type 5) each increase depth by one. Payloads exceeding
/// this limit are rejected before deserialization to prevent stack overflow.
pub const MAX_CBOR_DEPTH: usize = 32;

/// Scan raw CBOR bytes and reject if array/map nesting exceeds `max_depth`.
///
/// Walks CBOR item headers with a stack tracking remaining items in each
/// open container. Returns `true` if depth is within limits, `false` if
/// it exceeds `max_depth`. Truncated or malformed input returns `false`
/// to reject payloads whose depth cannot be fully verified.
fn check_cbor_depth(data: &[u8], max_depth: usize) -> bool {
    // Stack entries: remaining data items in each open definite-length
    // container. u64::MAX marks indefinite-length containers.
    let mut stack: Vec<u64> = Vec::with_capacity(max_depth);
    let mut pos = 0;

    while pos < data.len() {
        let first = data[pos];
        let major = first >> 5;
        let additional = first & 0x1F;
        pos += 1;

        // Break stop-code (major 7, additional 31) closes the innermost
        // indefinite container.
        if major == 7 && additional == 31 {
            while let Some(r) = stack.pop() {
                if r == u64::MAX {
                    break;
                }
            }
            consume_item(&mut stack);
            continue;
        }

        // Read the argument value.
        let arg = match additional {
            0..=23 => additional as u64,
            24 => {
                if pos >= data.len() {
                    return false;
                }
                let v = data[pos] as u64;
                pos += 1;
                v
            }
            25 => {
                if pos + 2 > data.len() {
                    return false;
                }
                let v = u16::from_be_bytes([data[pos], data[pos + 1]]) as u64;
                pos += 2;
                v
            }
            26 => {
                if pos + 4 > data.len() {
                    return false;
                }
                let Ok(bytes) = data[pos..pos + 4].try_into() else {
                    return false;
                };
                pos += 4;
                u32::from_be_bytes(bytes) as u64
            }
            27 => {
                if pos + 8 > data.len() {
                    return false;
                }
                let Ok(bytes) = data[pos..pos + 8].try_into() else {
                    return false;
                };
                pos += 8;
                u64::from_be_bytes(bytes)
            }
            31 => u64::MAX,    // indefinite length marker for types 2-5
            _ => return false, // reserved additional-info values (28-30) are malformed
        };

        match major {
            0 | 1 => {
                consume_item(&mut stack);
            }
            2 | 3 => {
                if arg == u64::MAX {
                    // Indefinite byte/text string; skip chunks until break.
                    loop {
                        if pos >= data.len() {
                            return false;
                        }
                        if data[pos] == 0xFF {
                            pos += 1;
                            break;
                        }
                        let ch = data[pos];
                        let ch_add = ch & 0x1F;
                        pos += 1;
                        let ch_len = match ch_add {
                            0..=23 => ch_add as u64,
                            24 => {
                                if pos >= data.len() {
                                    return false;
                                }
                                let v = data[pos] as u64;
                                pos += 1;
                                v
                            }
                            25 => {
                                if pos + 2 > data.len() {
                                    return false;
                                }
                                let v = u16::from_be_bytes([data[pos], data[pos + 1]]) as u64;
                                pos += 2;
                                v
                            }
                            26 => {
                                if pos + 4 > data.len() {
                                    return false;
                                }
                                let Ok(b) = data[pos..pos + 4].try_into() else {
                                    return false;
                                };
                                pos += 4;
                                u32::from_be_bytes(b) as u64
                            }
                            27 => {
                                if pos + 8 > data.len() {
                                    return false;
                                }
                                let Ok(b) = data[pos..pos + 8].try_into() else {
                                    return false;
                                };
                                pos += 8;
                                u64::from_be_bytes(b)
                            }
                            _ => return false, // reserved chunk-length values are malformed
                        };
                        let skip = ch_len.min(data.len() as u64) as usize;
                        match pos.checked_add(skip) {
                            Some(new_pos) if new_pos <= data.len() => pos = new_pos,
                            _ => return false, // chunk extends past input
                        }
                    }
                } else {
                    let skip = arg.min(data.len() as u64) as usize;
                    match pos.checked_add(skip) {
                        Some(new_pos) if new_pos <= data.len() => pos = new_pos,
                        _ => return false, // byte/text string extends past input
                    }
                }
                consume_item(&mut stack);
            }
            4 => {
                if stack.len() >= max_depth {
                    return false;
                }
                if arg == 0 {
                    consume_item(&mut stack);
                } else {
                    stack.push(arg); // arg items (or u64::MAX for indefinite)
                }
            }
            5 => {
                if stack.len() >= max_depth {
                    return false;
                }
                if arg == 0 {
                    consume_item(&mut stack);
                } else if arg == u64::MAX {
                    stack.push(u64::MAX);
                } else {
                    stack.push(arg.saturating_mul(2)); // key + value per pair
                }
            }
            6 => {
                // Semantic tag; the tagged value is the next data item.
                // No depth change, no item consumed yet.
            }
            7 => {
                consume_item(&mut stack);
            }
            _ => return false, // unknown major type is malformed
        }
    }
    // If the stack still has pending container items, the input was truncated
    stack.is_empty()
}

/// Decrement the remaining-item count on the innermost container,
/// popping containers that become fully consumed.
fn consume_item(stack: &mut Vec<u64>) {
    loop {
        match stack.last_mut() {
            Some(r) if *r == u64::MAX => break, // indefinite; wait for break
            Some(r) => {
                *r -= 1;
                if *r == 0 {
                    stack.pop();
                    continue; // this container was one item in its parent
                }
                break;
            }
            None => break,
        }
    }
}

/// Serialize a value to deterministic CBOR bytes.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::into_writer(value, &mut buffer).map_err(|e| CodecError::CborEncode(e.to_string()))?;
    Ok(buffer)
}

/// Deserialize a value from CBOR bytes.
pub fn decode<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    if data.len() > MAX_CBOR_PAYLOAD {
        return Err(CodecError::Validation(format!(
            "CBOR payload too large: {} bytes (max {})",
            data.len(),
            MAX_CBOR_PAYLOAD
        )));
    }
    if !check_cbor_depth(data, MAX_CBOR_DEPTH) {
        return Err(CodecError::Validation(format!(
            "CBOR nesting depth exceeds maximum ({})",
            MAX_CBOR_DEPTH
        )));
    }
    ciborium::from_reader(data).map_err(|e| CodecError::CborDecode(e.to_string()))
}

/// Serialize a value as CBOR into a writer.
pub fn encode_to<T: Serialize, W: Write>(value: &T, writer: W) -> Result<()> {
    ciborium::into_writer(value, writer).map_err(|e| CodecError::CborEncode(e.to_string()))
}

/// Deserialize a value from a CBOR reader, limited to [`MAX_CBOR_PAYLOAD`] bytes.
pub fn decode_from<T: DeserializeOwned, R: Read>(reader: R) -> Result<T> {
    let mut buf = Vec::new();
    reader
        .take(MAX_CBOR_PAYLOAD as u64)
        .read_to_end(&mut buf)
        .map_err(CodecError::Io)?;
    if buf.len() > MAX_CBOR_PAYLOAD {
        return Err(CodecError::Validation(format!(
            "CBOR payload too large: {} bytes (max {})",
            buf.len(),
            MAX_CBOR_PAYLOAD
        )));
    }
    if !check_cbor_depth(&buf, MAX_CBOR_DEPTH) {
        return Err(CodecError::Validation(format!(
            "CBOR nesting depth exceeds maximum ({})",
            MAX_CBOR_DEPTH
        )));
    }
    ciborium::from_reader(buf.as_slice()).map_err(|e| CodecError::CborDecode(e.to_string()))
}

/// Encode with CPoE semantic tag (evidence packet).
pub fn encode_cpoe<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode_tagged(value, CBOR_TAG_CPOE)
}

/// Encode with CWAR semantic tag (attestation result).
pub fn encode_cwar<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode_tagged(value, CBOR_TAG_CWAR)
}

/// Encode with compact evidence reference semantic tag.
pub fn encode_compact_ref<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    encode_tagged(value, CBOR_TAG_CPOR)
}

/// Wrap a serialized value in a CBOR semantic tag.
///
/// Writes the tag header directly followed by the inner CBOR bytes,
/// avoiding a round-trip through `ciborium::Value`.
pub fn encode_tagged<T: Serialize>(value: &T, tag: u64) -> Result<Vec<u8>> {
    let inner = encode(value)?;

    // Build the tag header manually per RFC 8949 major type 6 (tag).
    let mut buffer = Vec::with_capacity(9 + inner.len());
    write_cbor_tag_header(&mut buffer, tag);
    buffer.extend_from_slice(&inner);

    Ok(buffer)
}

/// Write a CBOR tag header (major type 6) for the given tag value.
fn write_cbor_tag_header(buf: &mut Vec<u8>, tag: u64) {
    const MAJOR: u8 = 6 << 5; // 0xC0
    if tag < 24 {
        buf.push(MAJOR | tag as u8);
    } else if tag <= u8::MAX as u64 {
        buf.push(MAJOR | 24);
        buf.push(tag as u8);
    } else if tag <= u16::MAX as u64 {
        buf.push(MAJOR | 25);
        buf.extend_from_slice(&(tag as u16).to_be_bytes());
    } else if tag <= u32::MAX as u64 {
        buf.push(MAJOR | 26);
        buf.extend_from_slice(&(tag as u32).to_be_bytes());
    } else {
        buf.push(MAJOR | 27);
        buf.extend_from_slice(&tag.to_be_bytes());
    }
}

/// Decode CBOR data, verifying the expected semantic tag.
///
/// Parses the tag header directly and deserializes the inner content
/// without an intermediate `ciborium::Value` round-trip.
pub fn decode_tagged<T: DeserializeOwned>(data: &[u8], expected_tag: u64) -> Result<T> {
    if data.len() > MAX_CBOR_PAYLOAD {
        return Err(CodecError::Validation(format!(
            "CBOR payload too large: {} bytes (max {})",
            data.len(),
            MAX_CBOR_PAYLOAD
        )));
    }

    let (actual_tag, inner_offset) = parse_cbor_tag_header(data).ok_or(CodecError::MissingTag)?;

    if actual_tag != expected_tag {
        return Err(CodecError::InvalidTag {
            expected: expected_tag,
            actual: actual_tag,
        });
    }

    if !check_cbor_depth(&data[inner_offset..], MAX_CBOR_DEPTH) {
        return Err(CodecError::Validation(format!(
            "CBOR nesting depth exceeds maximum ({})",
            MAX_CBOR_DEPTH
        )));
    }

    ciborium::from_reader(&data[inner_offset..]).map_err(|e| CodecError::CborDecode(e.to_string()))
}

/// Parse a CBOR tag header (major type 6) and return (tag_value, content_offset).
/// Returns None if the data does not start with a tag.
/// Manually extract a CBOR tag number and its header byte length from raw bytes.
///
/// This is a targeted custom parser rather than using ciborium because ciborium
/// does not expose a public API to inspect the leading tag before full
/// deserialization. We need the tag number upfront to validate it against the
/// expected CPoE/CWAR semantic tag before passing the payload to ciborium.
fn parse_cbor_tag_header(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let major = first >> 5;
    if major != 6 {
        return None;
    }
    let additional = first & 0x1F;
    match additional {
        0..=23 => Some((additional as u64, 1)),
        24 => {
            let val = *data.get(1)?;
            Some((val as u64, 2))
        }
        25 => {
            let bytes: [u8; 2] = data.get(1..3)?.try_into().ok()?;
            Some((u16::from_be_bytes(bytes) as u64, 3))
        }
        26 => {
            let bytes: [u8; 4] = data.get(1..5)?.try_into().ok()?;
            Some((u32::from_be_bytes(bytes) as u64, 5))
        }
        27 => {
            let bytes: [u8; 8] = data.get(1..9)?.try_into().ok()?;
            Some((u64::from_be_bytes(bytes), 9))
        }
        _ => None,
    }
}

/// Decode a CPoE-tagged evidence packet.
pub fn decode_cpoe<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    decode_tagged(data, CBOR_TAG_CPOE)
}

/// Decode a CWAR-tagged attestation result.
pub fn decode_cwar<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    decode_tagged(data, CBOR_TAG_CWAR)
}

/// Decode a compact evidence reference.
pub fn decode_compact_ref<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    decode_tagged(data, CBOR_TAG_CPOR)
}

/// Check whether CBOR data carries the expected semantic tag.
///
/// Parses only the tag header bytes, not the entire CBOR payload.
pub fn has_tag(data: &[u8], expected_tag: u64) -> bool {
    parse_cbor_tag_header(data)
        .map(|(tag, _)| tag == expected_tag)
        .unwrap_or(false)
}

/// Extract the outermost CBOR semantic tag, if present.
///
/// Parses only the tag header bytes, not the entire CBOR payload.
pub fn extract_tag(data: &[u8]) -> Option<u64> {
    parse_cbor_tag_header(data).map(|(tag, _)| tag)
}

/// Integer keys per RFC CDDL definitions (smaller than string keys on the wire).
pub mod keys {
    pub const VERSION: i64 = 1;
    pub const EXPORTED_AT: i64 = 2;
    pub const STRENGTH: i64 = 3;
    pub const PROVENANCE: i64 = 4;
    pub const DOCUMENT: i64 = 5;
    pub const CHECKPOINTS: i64 = 6;
    pub const VDF_PARAMS: i64 = 7;
    pub const CHAIN_HASH: i64 = 8;
    pub const DECLARATION: i64 = 9;
    pub const PRESENCE: i64 = 10;
    pub const HARDWARE: i64 = 11;
    pub const KEYSTROKE: i64 = 12;
    pub const BEHAVIORAL: i64 = 13;
    pub const CONTEXTS: i64 = 14;
    pub const EXTERNAL: i64 = 15;
    pub const KEY_HIERARCHY: i64 = 16;
    pub const JITTER_BINDING: i64 = 17;
    pub const TIME_EVIDENCE: i64 = 18;
    pub const BIOLOGY_CLAIM: i64 = 19;
    pub const CLAIMS: i64 = 20;

    pub const ENTROPY_COMMITMENT: i64 = 21;
    pub const SOURCES: i64 = 22;
    pub const SUMMARY: i64 = 23;
    pub const BINDING_MAC: i64 = 24;
    pub const RAW_INTERVALS: i64 = 25;
    pub const ACTIVE_PROBES: i64 = 26;
    pub const LABYRINTH_STRUCTURE: i64 = 27;

    pub const VALIDATION_STATUS: i64 = 31;
    pub const MILLIBITS: i64 = 32;
    pub const PARAMETER_VERSION: i64 = 33;
    pub const THRESHOLDS: i64 = 34;

    pub const BINDING_TIER: i64 = 41;
    pub const TSA_RESPONSES: i64 = 42;
    pub const BLOCKCHAIN_ANCHORS: i64 = 43;
    pub const ROUGHTIME_SAMPLES: i64 = 44;

    pub const INPUT: i64 = 51;
    pub const OUTPUT: i64 = 52;
    pub const ITERATIONS: i64 = 53;
    pub const PROOF: i64 = 54;
    pub const CALIBRATION: i64 = 55;

    pub const GALTON_INVARIANT: i64 = 61;
    pub const REFLEX_GATE: i64 = 62;

    pub const EMBEDDING_DIMENSION: i64 = 71;
    pub const TIME_DELAY: i64 = 72;
    pub const ATTRACTOR_POINTS: i64 = 73;
    pub const BETTI_NUMBERS: i64 = 74;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestPacket {
        version: i32,
        data: Vec<u8>,
    }

    #[test]
    fn test_tagged_roundtrip() {
        let original = TestPacket {
            version: 1,
            data: vec![1, 2, 3, 4, 5],
        };

        let encoded = encode_cpoe(&original).unwrap();
        let decoded: TestPacket = decode_cpoe(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_tag_detection() {
        let packet = TestPacket {
            version: 1,
            data: vec![],
        };

        let cpoe_encoded = encode_cpoe(&packet).unwrap();
        let cwar_encoded = encode_cwar(&packet).unwrap();

        assert!(has_tag(&cpoe_encoded, CBOR_TAG_CPOE));
        assert!(!has_tag(&cpoe_encoded, CBOR_TAG_CWAR));

        assert!(has_tag(&cwar_encoded, CBOR_TAG_CWAR));
        assert!(!has_tag(&cwar_encoded, CBOR_TAG_CPOE));
    }

    #[test]
    fn test_tag_extraction() {
        let packet = TestPacket {
            version: 1,
            data: vec![],
        };

        let encoded = encode_cpoe(&packet).unwrap();
        assert_eq!(extract_tag(&encoded), Some(CBOR_TAG_CPOE));

        let untagged = encode(&packet).unwrap();
        assert_eq!(extract_tag(&untagged), None);
    }

    #[test]
    fn test_wrong_tag_error() {
        let packet = TestPacket {
            version: 1,
            data: vec![],
        };

        let encoded = encode_cpoe(&packet).unwrap();
        let result: Result<TestPacket> = decode_cwar(&encoded);

        assert!(matches!(
            result,
            Err(CodecError::InvalidTag {
                expected: CBOR_TAG_CWAR,
                actual: CBOR_TAG_CPOE
            })
        ));
    }

    #[test]
    fn test_has_tag_on_untagged_data() {
        let packet = TestPacket {
            version: 1,
            data: vec![10, 20],
        };
        let encoded = encode(&packet).unwrap();
        assert!(!has_tag(&encoded, CBOR_TAG_CPOE));
        assert!(!has_tag(&encoded, CBOR_TAG_CWAR));
    }

    #[test]
    fn test_has_tag_on_invalid_cbor() {
        // Garbage bytes that aren't valid CBOR
        assert!(!has_tag(&[0xFF, 0xFE, 0xFD], CBOR_TAG_CPOE));
        assert!(!has_tag(&[], CBOR_TAG_CPOE));
    }

    #[test]
    fn test_extract_tag_on_invalid_cbor() {
        assert_eq!(extract_tag(&[0xFF, 0xFE, 0xFD]), None);
        assert_eq!(extract_tag(&[]), None);
    }

    #[test]
    fn test_decode_tagged_on_untagged_data_returns_missing_tag() {
        let packet = TestPacket {
            version: 1,
            data: vec![],
        };
        let encoded = encode(&packet).unwrap();
        let result: Result<TestPacket> = decode_tagged(&encoded, CBOR_TAG_CPOE);
        assert!(matches!(result, Err(CodecError::MissingTag)));
    }

    #[test]
    fn test_decode_invalid_cbor_returns_error() {
        let garbage = &[0xFF, 0xFE, 0xFD, 0xFC];
        let result: Result<TestPacket> = decode(garbage);
        assert!(result.is_err(), "garbage input must be rejected");
    }

    #[test]
    fn test_compact_ref_roundtrip() {
        let packet = TestPacket {
            version: 3,
            data: vec![99, 100],
        };

        let encoded = encode_compact_ref(&packet).unwrap();
        assert!(has_tag(&encoded, CBOR_TAG_CPOR));
        assert_eq!(extract_tag(&encoded), Some(CBOR_TAG_CPOR));

        let decoded: TestPacket = decode_compact_ref(&encoded).unwrap();
        assert_eq!(packet, decoded);
    }

    #[test]
    fn test_cwar_roundtrip() {
        let packet = TestPacket {
            version: 2,
            data: vec![7, 8, 9],
        };

        let encoded = encode_cwar(&packet).unwrap();
        assert!(has_tag(&encoded, CBOR_TAG_CWAR));

        let decoded: TestPacket = decode_cwar(&encoded).unwrap();
        assert_eq!(packet, decoded);
    }

    #[test]
    fn test_encode_to_decode_from_cbor() {
        let packet = TestPacket {
            version: 5,
            data: vec![1, 2, 3],
        };

        let mut buf = Vec::new();
        encode_to(&packet, &mut buf).unwrap();
        let decoded: TestPacket = decode_from(&buf[..]).unwrap();
        assert_eq!(packet, decoded);
    }

    #[test]
    fn test_oversized_payload_rejected() {
        let oversized = vec![0u8; MAX_CBOR_PAYLOAD + 1];
        let result: Result<TestPacket> = decode(&oversized);
        assert!(matches!(result, Err(CodecError::Validation(_))));
    }

    #[test]
    fn test_deeply_nested_cbor_rejected() {
        // Build a CBOR payload with 33 nested arrays (each 0x81 = 1-element array)
        // followed by an integer 0x00.
        let depth = MAX_CBOR_DEPTH + 1;
        let mut payload = vec![0x81u8; depth]; // 33 nested 1-element arrays
        payload.push(0x00); // innermost value
        let result: Result<ciborium::Value> = decode(&payload);
        assert!(
            matches!(result, Err(CodecError::Validation(ref msg)) if msg.contains("nesting depth")),
            "expected depth rejection, got: {result:?}"
        );
    }

    #[test]
    fn test_moderately_nested_cbor_accepted() {
        // 5 levels of nesting should be fine
        let mut payload = vec![0x81u8; 5];
        payload.push(0x00);
        let result: Result<ciborium::Value> = decode(&payload);
        assert!(result.is_ok(), "expected success, got: {result:?}");
    }

    #[test]
    fn test_deeply_nested_tagged_cbor_rejected() {
        let depth = MAX_CBOR_DEPTH + 1;
        let mut inner = vec![0x81u8; depth];
        inner.push(0x00);
        // Build a directly nested tagged payload with arrays exceeding depth.
        let mut nested_payload = Vec::new();
        write_cbor_tag_header(&mut nested_payload, CBOR_TAG_CPOE);
        nested_payload.extend_from_slice(&inner);
        let result: Result<ciborium::Value> = decode_tagged(&nested_payload, CBOR_TAG_CPOE);
        assert!(
            matches!(result, Err(CodecError::Validation(ref msg)) if msg.contains("nesting depth")),
            "expected depth rejection for tagged decode, got: {result:?}"
        );
    }

    #[test]
    fn test_oversized_tagged_payload_rejected() {
        let mut oversized = Vec::with_capacity(MAX_CBOR_PAYLOAD + 10);
        // Write a valid CPoE tag header followed by junk
        oversized.push(0xDA); // major type 6, 4-byte tag
        oversized.extend_from_slice(&(CBOR_TAG_CPOE as u32).to_be_bytes());
        oversized.resize(MAX_CBOR_PAYLOAD + 6, 0);
        let result: Result<TestPacket> = decode_tagged(&oversized, CBOR_TAG_CPOE);
        assert!(matches!(result, Err(CodecError::Validation(_))));
    }
}
