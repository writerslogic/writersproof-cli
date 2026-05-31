// SPDX-License-Identifier: Apache-2.0

//! Codec module for RFC-compliant serialization.
//!
//! Supports both CBOR (primary, RFC 8949) and JSON (legacy) encoding
//! for Proof-of-Process evidence packets.

pub mod cbor;
pub mod json;

use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

/// CBOR semantic tag for Compact Proof-of-Process (CPoE) evidence packet.
/// Tag value: 1129336645 (0x43504F45 = "CPoE" in ASCII)
/// Per draft-condrey-rats-pop CDDL and IANA CBOR tag registry.
pub const CBOR_TAG_CPOE: u64 = 1129336645;

/// CBOR semantic tag for Compact Writers Attestation Result (CWAR).
/// Tag value: 1129791826 (0x43574152 = "CWAR" in ASCII)
/// Per draft-condrey-rats-pop CDDL and IANA CBOR tag registry.
pub const CBOR_TAG_CWAR: u64 = 1129791826;

/// CBOR semantic tag for Compact Evidence Reference.
/// Tag value: 1129336658 (0x43504F52 = "CPoR")
pub const CBOR_TAG_CPOR: u64 = 1129336658;

/// IANA Private Enterprise Number for WritersLogic Inc.
pub const IANA_PEN: u32 = 65074;

/// Wire serialization format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// CBOR encoding for evidence packets (RFC 8949 deterministic)
    #[default]
    Cbor,
    /// JSON encoding (legacy, for human readability)
    Json,
}

impl Format {
    /// Return the MIME type for this format.
    pub fn mime_type(&self) -> &'static str {
        match self {
            Format::Cbor => "application/c2pa",
            Format::Json => "application/json",
        }
    }

    /// Return the file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            Format::Cbor => "c2pa",
            Format::Json => "json",
        }
    }

    /// Detect format from the first byte of encoded data.
    ///
    /// Returns `None` (with a log warning) if the data is empty or the
    /// leading byte does not match any known CBOR or JSON prefix.
    pub fn detect(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            log::warn!("Format::detect called with empty data");
            return None;
        }
        // CBOR map starts with 0xA (major type 5) or tagged value 0xD9/0xDA/0xDB
        // JSON starts with '{' (0x7B) or '[' (0x5B)
        match data[0] {
            0x7B | 0x5B => Some(Format::Json),
            // Ranges document CBOR major types: 4 (array), 5 (map), 6 (tag).
            #[allow(clippy::manual_range_patterns)]
            0x80..=0x9F | 0xA0..=0xBF | 0xC0..=0xD8 | 0xD9 | 0xDA | 0xDB => Some(Format::Cbor),
            _ => {
                log::warn!(
                    "Format::detect: unrecognized leading byte 0x{:02X} (len={})",
                    data[0],
                    data.len()
                );
                None
            }
        }
    }
}

/// Encoding/decoding errors for CBOR and JSON codecs.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("CBOR encoding error: {0}")]
    CborEncode(String),
    #[error("CBOR decoding error: {0}")]
    CborDecode(String),
    #[error("JSON encoding error: {0}")]
    JsonEncode(String),
    #[error("JSON decoding error: {0}")]
    JsonDecode(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    #[error("missing semantic tag")]
    MissingTag,
    #[error("invalid semantic tag: expected {expected}, got {actual}")]
    InvalidTag { expected: u64, actual: u64 },
    #[error("validation error: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, CodecError>;

/// Serialize a value in the specified format.
pub fn encode<T: Serialize>(value: &T, format: Format) -> Result<Vec<u8>> {
    match format {
        Format::Cbor => cbor::encode(value),
        Format::Json => json::encode(value),
    }
}

/// Deserialize a value from the specified format.
pub fn decode<T: DeserializeOwned>(data: &[u8], format: Format) -> Result<T> {
    match format {
        Format::Cbor => cbor::decode(data),
        Format::Json => json::decode(data),
    }
}

/// Auto-detect format and deserialize.
pub fn decode_auto<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    let format = Format::detect(data)
        .ok_or_else(|| CodecError::InvalidFormat("unable to detect format".to_string()))?;
    decode(data, format)
}

/// Serialize a value into a writer in the specified format.
pub fn encode_to<T: Serialize, W: Write>(value: &T, writer: W, format: Format) -> Result<()> {
    match format {
        Format::Cbor => cbor::encode_to(value, writer),
        Format::Json => json::encode_to(value, writer),
    }
}

/// Deserialize a value from a reader in the specified format.
pub fn decode_from<T: DeserializeOwned, R: Read>(reader: R, format: Format) -> Result<T> {
    match format {
        Format::Cbor => cbor::decode_from(reader),
        Format::Json => json::decode_from(reader),
    }
}

// Backward-compatible convenience functions from v0.1
/// Alias for engine-era constant names.
pub const CBOR_TAG_EVIDENCE_PACKET: u64 = CBOR_TAG_CPOE;
/// Alias for engine-era constant names.
pub const CBOR_TAG_ATTESTATION_RESULT: u64 = CBOR_TAG_CWAR;

/// Serialize an EvidencePacket to CBOR with the registered tag.
pub fn encode_evidence(packet: &crate::rfc::EvidencePacket) -> crate::error::Result<Vec<u8>> {
    cbor::encode_cpoe(packet)
        .map_err(|e| crate::error::Error::Serialization(format!("CBOR encode_evidence: {e}")))
}

/// Deserialize CBOR-tagged bytes into an EvidencePacket.
pub fn decode_evidence(bytes: &[u8]) -> crate::error::Result<crate::rfc::EvidencePacket> {
    cbor::decode_cpoe(bytes).map_err(|e| crate::error::Error::Serialization(e.to_string()))
}

/// Serialize an AttestationResult to CBOR with the registered tag.
pub fn encode_attestation(result: &crate::rfc::AttestationResult) -> crate::error::Result<Vec<u8>> {
    cbor::encode_cwar(result).map_err(|e| crate::error::Error::Serialization(e.to_string()))
}

/// Deserialize CBOR-tagged bytes into an AttestationResult.
pub fn decode_attestation(bytes: &[u8]) -> crate::error::Result<crate::rfc::AttestationResult> {
    cbor::decode_cwar(bytes).map_err(|e| crate::error::Error::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        name: String,
        value: i32,
        data: Vec<u8>,
    }

    #[test]
    fn test_format_detection() {
        // JSON object
        assert_eq!(Format::detect(b"{\"key\":\"value\"}"), Some(Format::Json));
        // JSON array
        assert_eq!(Format::detect(b"[1,2,3]"), Some(Format::Json));
        // CBOR map (small, 0xA0-0xB7)
        assert_eq!(Format::detect(&[0xA1, 0x01, 0x02]), Some(Format::Cbor));
        // Empty
        assert_eq!(Format::detect(&[]), None);
    }

    #[test]
    fn test_roundtrip_cbor() {
        let original = TestStruct {
            name: "test".to_string(),
            value: 42,
            data: vec![1, 2, 3, 4],
        };

        let encoded = encode(&original, Format::Cbor).unwrap();
        let decoded: TestStruct = decode(&encoded, Format::Cbor).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_json() {
        let original = TestStruct {
            name: "test".to_string(),
            value: 42,
            data: vec![1, 2, 3, 4],
        };

        let encoded = encode(&original, Format::Json).unwrap();
        let decoded: TestStruct = decode(&encoded, Format::Json).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_auto_detect_decode() {
        let original = TestStruct {
            name: "auto".to_string(),
            value: 100,
            data: vec![5, 6, 7],
        };

        let cbor_encoded = encode(&original, Format::Cbor).unwrap();
        let cbor_decoded: TestStruct = decode_auto(&cbor_encoded).unwrap();
        assert_eq!(original, cbor_decoded);

        let json_encoded = encode(&original, Format::Json).unwrap();
        let json_decoded: TestStruct = decode_auto(&json_encoded).unwrap();
        assert_eq!(original, json_decoded);
    }

    #[test]
    fn test_format_mime_type() {
        assert_eq!(Format::Cbor.mime_type(), "application/c2pa");
        assert_eq!(Format::Json.mime_type(), "application/json");
    }

    #[test]
    fn test_format_extension() {
        assert_eq!(Format::Cbor.extension(), "c2pa");
        assert_eq!(Format::Json.extension(), "json");
    }

    #[test]
    fn test_format_default_is_cbor() {
        assert_eq!(Format::default(), Format::Cbor);
    }

    #[test]
    fn test_format_detect_tagged_cbor() {
        // 0xD9 = 2-byte tag header (CBOR major type 6)
        assert_eq!(Format::detect(&[0xD9, 0x01, 0x02]), Some(Format::Cbor));
        // 0xDA = 4-byte tag header
        assert_eq!(
            Format::detect(&[0xDA, 0x00, 0x00, 0x00, 0x01]),
            Some(Format::Cbor)
        );
        // 0xDB = 8-byte tag header
        assert_eq!(Format::detect(&[0xDB]), Some(Format::Cbor));
    }

    #[test]
    fn test_format_detect_unknown_byte() {
        // A byte that doesn't match JSON or CBOR patterns
        assert_eq!(Format::detect(&[0x00]), None);
        assert_eq!(Format::detect(&[0x42]), None);
        assert_eq!(Format::detect(&[0xFF]), None);
    }

    #[test]
    fn test_decode_auto_empty_data() {
        let result = decode_auto::<TestStruct>(&[]);
        assert!(matches!(result, Err(CodecError::InvalidFormat(_))));
    }

    #[test]
    fn test_encode_to_decode_from_cbor() {
        let original = TestStruct {
            name: "writer".to_string(),
            value: -7,
            data: vec![0xFF, 0x00],
        };

        let mut buf = Vec::new();
        encode_to(&original, &mut buf, Format::Cbor).unwrap();
        let decoded: TestStruct = decode_from(&buf[..], Format::Cbor).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_to_decode_from_json() {
        let original = TestStruct {
            name: "writer".to_string(),
            value: -7,
            data: vec![0xFF, 0x00],
        };

        let mut buf = Vec::new();
        encode_to(&original, &mut buf, Format::Json).unwrap();
        let decoded: TestStruct = decode_from(&buf[..], Format::Json).unwrap();
        assert_eq!(original, decoded);
    }
}
