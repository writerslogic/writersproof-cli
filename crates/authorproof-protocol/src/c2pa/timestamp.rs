// SPDX-License-Identifier: Apache-2.0

//! RFC 3161 timestamping support for C2PA manifests.
//!
//! C2PA 2.4 requires a `sigTst` entry in the COSE unprotected header containing
//! an RFC 3161 `TimeStampToken`. This module builds the DER-encoded
//! `TimeStampReq`, parses the `TimeStampResp`, and constructs the COSE
//! unprotected header carrying the token per C2PA spec.
//!
//! The module is intentionally HTTP-free to preserve wasm compatibility.
//! Callers are responsible for transporting the request to a TSA and
//! passing the response back.

use crate::error::{Error, Result};
use der::asn1::ObjectIdentifier;
use der::Encode;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// OIDs
// ---------------------------------------------------------------------------

/// id-sha256 (2.16.840.1.101.3.4.2.1).
const SHA256_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

// ---------------------------------------------------------------------------
// TimeStampReq builder
// ---------------------------------------------------------------------------

/// Build a DER-encoded RFC 3161 `TimeStampReq` for the given SHA-256 hash.
///
/// The request asks for certificates in the response (`certReq = true`) and
/// includes a random 8-byte nonce for replay protection.
///
/// ```text
/// TimeStampReq ::= SEQUENCE {
///     version         INTEGER { v1(1) },
///     messageImprint  MessageImprint,
///     reqPolicy       OBJECT IDENTIFIER  OPTIONAL,
///     nonce           INTEGER             OPTIONAL,
///     certReq         BOOLEAN DEFAULT FALSE,
///     extensions  [0] IMPLICIT Extensions OPTIONAL
/// }
///
/// MessageImprint ::= SEQUENCE {
///     hashAlgorithm   AlgorithmIdentifier,
///     hashedMessage   OCTET STRING
/// }
/// ```
pub fn build_timestamp_request(signature_hash: &[u8; 32]) -> Vec<u8> {
    // We build the DER by hand because the ASN.1 structure is small and fixed.
    // This avoids pulling in a full ASN.1 compiler dependency.

    // Generate an 8-byte random nonce.
    let mut nonce_bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);

    // -- AlgorithmIdentifier for SHA-256 --
    // SEQUENCE { OID sha256, NULL }
    let sha256_oid_der = SHA256_OID
        .to_der()
        .expect("SHA-256 OID DER encoding is infallible");
    // NULL parameter: 05 00
    let alg_id_inner_len = sha256_oid_der.len() + 2; // OID + NULL
    let mut alg_id = vec![0x30, alg_id_inner_len as u8];
    alg_id.extend_from_slice(&sha256_oid_der);
    alg_id.extend_from_slice(&[0x05, 0x00]); // NULL

    // -- MessageImprint --
    // SEQUENCE { AlgorithmIdentifier, OCTET STRING(hash) }
    let hash_octet = der_octet_string(signature_hash);
    let msg_imprint_inner_len = alg_id.len() + hash_octet.len();
    let mut msg_imprint = vec![0x30];
    der_push_length(&mut msg_imprint, msg_imprint_inner_len);
    msg_imprint.extend_from_slice(&alg_id);
    msg_imprint.extend_from_slice(&hash_octet);

    // -- Nonce (INTEGER) --
    // Ensure the nonce is encoded as a positive integer (prepend 0x00 if high bit set).
    let nonce_int = der_unsigned_integer(&nonce_bytes);

    // -- certReq (BOOLEAN TRUE) --
    let cert_req = [0x01, 0x01, 0xFF]; // BOOLEAN TRUE

    // -- version (INTEGER 1) --
    let version = [0x02, 0x01, 0x01]; // INTEGER 1

    // -- TimeStampReq SEQUENCE --
    let inner_len =
        version.len() + msg_imprint.len() + nonce_int.len() + cert_req.len();
    let mut req = vec![0x30];
    der_push_length(&mut req, inner_len);
    req.extend_from_slice(&version);
    req.extend_from_slice(&msg_imprint);
    req.extend_from_slice(&nonce_int);
    req.extend_from_slice(&cert_req);

    req
}

/// Compute the SHA-256 hash of COSE signature bytes, then build a timestamp
/// request for it. Convenience wrapper combining hashing + request building.
pub fn build_timestamp_request_for_signature(signature_bytes: &[u8]) -> Vec<u8> {
    let hash: [u8; 32] = Sha256::digest(signature_bytes).into();
    build_timestamp_request(&hash)
}

// ---------------------------------------------------------------------------
// TimeStampResp parser
// ---------------------------------------------------------------------------

/// Parse a DER-encoded RFC 3161 `TimeStampResp` and extract the
/// `TimeStampToken` (CMS `ContentInfo`) bytes.
///
/// ```text
/// TimeStampResp ::= SEQUENCE {
///     status          PKIStatusInfo,
///     timeStampToken  ContentInfo OPTIONAL
/// }
///
/// PKIStatusInfo ::= SEQUENCE {
///     status        PKIStatus,       -- INTEGER
///     statusString  PKIFreeText  OPTIONAL,
///     failInfo      PKIFailureInfo OPTIONAL
/// }
/// ```
///
/// Returns the raw DER bytes of the `TimeStampToken` on success.
pub fn parse_timestamp_response(response_bytes: &[u8]) -> Result<Vec<u8>> {
    if response_bytes.len() < 5 {
        return Err(Error::Protocol(
            "TSA response too short to be a valid TimeStampResp".into(),
        ));
    }

    // Outer SEQUENCE
    let (_, outer_content) = parse_der_sequence(response_bytes)
        .map_err(|e| Error::Protocol(format!("TSA response: invalid outer SEQUENCE: {e}")))?;

    // First element: PKIStatusInfo SEQUENCE
    let (status_len, status_content) = parse_der_sequence(outer_content)
        .map_err(|e| Error::Protocol(format!("TSA response: invalid PKIStatusInfo: {e}")))?;

    // Extract PKIStatus INTEGER from PKIStatusInfo
    let status_value = parse_der_integer(status_content)
        .map_err(|e| Error::Protocol(format!("TSA response: invalid PKIStatus INTEGER: {e}")))?;

    if status_value != 0 {
        return Err(Error::Protocol(format!(
            "TSA returned non-granted status: {} (0=granted, 1=grantedWithMods, \
             2=rejection, 3=waiting, 4=revocationWarning, 5=revocationNotification)",
            status_value
        )));
    }

    // The TimeStampToken follows the PKIStatusInfo SEQUENCE.
    let token_offset = status_len;
    if token_offset >= outer_content.len() {
        return Err(Error::Protocol(
            "TSA response: granted status but no TimeStampToken present".into(),
        ));
    }

    let token_bytes = &outer_content[token_offset..];

    // Validate that the token starts with a SEQUENCE tag (CMS ContentInfo).
    if token_bytes.is_empty() || token_bytes[0] != 0x30 {
        return Err(Error::Protocol(
            "TSA response: TimeStampToken is not a valid DER SEQUENCE".into(),
        ));
    }

    // Return the full TLV (tag + length + value) of the ContentInfo.
    let total_len = der_tlv_total_length(token_bytes)
        .map_err(|e| Error::Protocol(format!("TSA response: invalid TimeStampToken TLV: {e}")))?;

    Ok(token_bytes[..total_len].to_vec())
}

// ---------------------------------------------------------------------------
// sigTst COSE header builder
// ---------------------------------------------------------------------------

/// Build a COSE unprotected header containing the C2PA `sigTst` structure.
///
/// Per C2PA 2.4 Section 14.4, the `sigTst` entry in the unprotected header
/// is structured as:
///
/// ```cbor
/// "sigTst": {
///     "tstTokens": [
///         { "val": h'<TimeStampToken bytes>' }
///     ]
/// }
/// ```
///
/// The text key `"sigTst"` is used (not an integer label).
pub fn build_sigtst_header(timestamp_token: &[u8]) -> coset::Header {
    let val_entry = ciborium::Value::Map(vec![(
        ciborium::Value::Text("val".to_string()),
        ciborium::Value::Bytes(timestamp_token.to_vec()),
    )]);

    let tst_tokens = ciborium::Value::Map(vec![(
        ciborium::Value::Text("tstTokens".to_string()),
        ciborium::Value::Array(vec![val_entry]),
    )]);

    let mut header = coset::Header::default();
    header.rest.push((
        coset::Label::Text("sigTst".to_string()),
        tst_tokens,
    ));
    header
}

/// Inject a `sigTst` unprotected header into an existing serialized
/// COSE_Sign1 structure.
///
/// Parses the COSE_Sign1, merges the timestamp into the unprotected header,
/// and re-serializes. The signature remains valid because the unprotected
/// header is not covered by the COSE_Sign1 signature.
pub fn inject_timestamp_into_cose(
    cose_sign1_bytes: &[u8],
    timestamp_token: &[u8],
) -> Result<Vec<u8>> {
    use coset::{CborSerializable, TaggedCborSerializable};

    let mut sign1 = coset::CoseSign1::from_tagged_slice(cose_sign1_bytes)
        .or_else(|_| coset::CoseSign1::from_slice(cose_sign1_bytes))
        .map_err(|e| Error::Crypto(format!("failed to parse COSE_Sign1 for timestamp injection: {e}")))?;

    let sigtst_header = build_sigtst_header(timestamp_token);
    sign1.unprotected.rest.extend(sigtst_header.rest);

    sign1
        .to_vec()
        .map_err(|e| Error::Crypto(format!("failed to re-encode COSE_Sign1 with sigTst: {e}")))
}

// ---------------------------------------------------------------------------
// DER encoding/parsing helpers
// ---------------------------------------------------------------------------

/// Encode a byte slice as a DER OCTET STRING.
fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    der_push_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

/// Encode a byte slice as a DER unsigned INTEGER.
///
/// Prepends a leading 0x00 byte if the high bit of the first byte is set
/// to ensure the integer is interpreted as positive.
fn der_unsigned_integer(data: &[u8]) -> Vec<u8> {
    let needs_pad = !data.is_empty() && (data[0] & 0x80) != 0;
    let content_len = data.len() + if needs_pad { 1 } else { 0 };
    let mut out = vec![0x02];
    der_push_length(&mut out, content_len);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(data);
    out
}

/// Push a DER length encoding (short or long form).
fn der_push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xFF {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else if len <= 0xFF_FFFF {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x84);
        buf.push((len >> 24) as u8);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

/// Parse DER length field starting at `data[0]`. Returns (num_bytes_consumed, length_value).
fn parse_der_length(data: &[u8]) -> std::result::Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("empty length field".into());
    }
    let first = data[0];
    if first < 0x80 {
        Ok((1, first as usize))
    } else {
        let num_octets = (first & 0x7F) as usize;
        if num_octets == 0 || num_octets > 4 {
            return Err(format!("unsupported length encoding: {num_octets} octets"));
        }
        if data.len() < 1 + num_octets {
            return Err("truncated length field".into());
        }
        let mut len: usize = 0;
        for i in 0..num_octets {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Ok((1 + num_octets, len))
    }
}

/// Parse a DER SEQUENCE tag at the start of `data`.
/// Returns (total TLV bytes consumed, content slice).
fn parse_der_sequence(data: &[u8]) -> std::result::Result<(usize, &[u8]), String> {
    if data.is_empty() || data[0] != 0x30 {
        return Err("expected SEQUENCE tag (0x30)".into());
    }
    let (len_bytes, content_len) = parse_der_length(&data[1..])?;
    let header_len = 1 + len_bytes;
    let total = header_len + content_len;
    if data.len() < total {
        return Err(format!(
            "SEQUENCE truncated: need {total} bytes, have {}",
            data.len()
        ));
    }
    Ok((total, &data[header_len..total]))
}

/// Parse a DER INTEGER and return its value as i64.
/// Only handles small integers (up to 8 content bytes).
fn parse_der_integer(data: &[u8]) -> std::result::Result<i64, String> {
    if data.is_empty() || data[0] != 0x02 {
        return Err("expected INTEGER tag (0x02)".into());
    }
    let (len_bytes, content_len) = parse_der_length(&data[1..])?;
    if content_len == 0 || content_len > 8 {
        return Err(format!("INTEGER content length {content_len} out of range"));
    }
    let start = 1 + len_bytes;
    if data.len() < start + content_len {
        return Err("INTEGER truncated".into());
    }
    let content = &data[start..start + content_len];
    // Sign-extend from the first byte.
    let mut value: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in content {
        value = (value << 8) | (b as i64);
    }
    Ok(value)
}

/// Compute the total TLV length of a DER element starting at `data[0]`.
fn der_tlv_total_length(data: &[u8]) -> std::result::Result<usize, String> {
    if data.is_empty() {
        return Err("empty TLV".into());
    }
    let (len_bytes, content_len) = parse_der_length(&data[1..])?;
    let total = 1 + len_bytes + content_len;
    if data.len() < total {
        return Err(format!(
            "TLV truncated: need {total} bytes, have {}",
            data.len()
        ));
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_request_is_valid_der() {
        let hash = [0xABu8; 32];
        let req = build_timestamp_request(&hash);

        // Must start with SEQUENCE tag.
        assert_eq!(req[0], 0x30, "request must start with SEQUENCE tag");

        // Parse the outer SEQUENCE to verify structure.
        let (_, content) = parse_der_sequence(&req).expect("valid outer SEQUENCE");
        assert!(!content.is_empty());

        // First field: version INTEGER 1
        let version = parse_der_integer(content).expect("valid version INTEGER");
        assert_eq!(version, 1);
    }

    #[test]
    fn timestamp_request_contains_hash() {
        let hash = [0x42u8; 32];
        let req = build_timestamp_request(&hash);

        // The 32-byte hash must appear somewhere in the request.
        let hash_pos = req
            .windows(32)
            .position(|w| w == hash)
            .expect("hash must appear in request");
        assert!(hash_pos > 0);
    }

    #[test]
    fn timestamp_request_convenience_wrapper() {
        let sig_bytes = b"some-cose-signature-bytes";
        let req = build_timestamp_request_for_signature(sig_bytes);
        assert_eq!(req[0], 0x30);

        // The SHA-256 of sig_bytes must appear in the request.
        let expected_hash: [u8; 32] = Sha256::digest(sig_bytes).into();
        assert!(req.windows(32).any(|w| w == expected_hash));
    }

    #[test]
    fn parse_timestamp_response_rejects_short() {
        let result = parse_timestamp_response(&[0x30, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_timestamp_response_rejects_non_granted() {
        // Build a minimal TimeStampResp with status = 2 (rejection).
        // SEQUENCE { SEQUENCE { INTEGER 2 } }
        let resp = &[
            0x30, 0x05, // outer SEQUENCE, length 5
            0x30, 0x03, // PKIStatusInfo SEQUENCE, length 3
            0x02, 0x01, 0x02, // INTEGER 2
        ];
        let result = parse_timestamp_response(resp);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("non-granted status: 2"),
            "unexpected error: {err_msg}"
        );
    }

    #[test]
    fn parse_timestamp_response_extracts_token() {
        // Build a minimal valid TimeStampResp:
        // SEQUENCE {
        //   SEQUENCE { INTEGER 0 },       -- PKIStatusInfo: granted
        //   SEQUENCE { <fake token> }      -- TimeStampToken (ContentInfo)
        // }
        let fake_token_content = [0x01, 0x02, 0x03, 0x04];
        let token_seq_len = fake_token_content.len();
        // Token SEQUENCE TLV
        let mut token_seq = vec![0x30, token_seq_len as u8];
        token_seq.extend_from_slice(&fake_token_content);

        // PKIStatusInfo: SEQUENCE { INTEGER 0 }
        let status_info = [0x30, 0x03, 0x02, 0x01, 0x00];

        // Outer SEQUENCE
        let inner_len = status_info.len() + token_seq.len();
        let mut resp = vec![0x30, inner_len as u8];
        resp.extend_from_slice(&status_info);
        resp.extend_from_slice(&token_seq);

        let token = parse_timestamp_response(&resp).expect("should parse granted response");
        assert_eq!(token, token_seq);
    }

    #[test]
    fn parse_timestamp_response_rejects_missing_token() {
        // Granted status but no TimeStampToken following.
        let resp = &[
            0x30, 0x05, // outer SEQUENCE
            0x30, 0x03, // PKIStatusInfo
            0x02, 0x01, 0x00, // INTEGER 0 (granted)
        ];
        let result = parse_timestamp_response(resp);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("no TimeStampToken"),
            "unexpected error: {err_msg}"
        );
    }

    #[test]
    fn build_sigtst_header_structure() {
        let token = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let header = build_sigtst_header(&token);

        // Should have exactly one entry in rest.
        assert_eq!(header.rest.len(), 1);

        let (label, value) = &header.rest[0];
        assert_eq!(*label, coset::Label::Text("sigTst".to_string()));

        // Value should be a map with "tstTokens" key.
        if let ciborium::Value::Map(map) = value {
            assert_eq!(map.len(), 1);
            let (key, arr) = &map[0];
            assert_eq!(*key, ciborium::Value::Text("tstTokens".to_string()));
            if let ciborium::Value::Array(tokens) = arr {
                assert_eq!(tokens.len(), 1);
                if let ciborium::Value::Map(token_map) = &tokens[0] {
                    assert_eq!(token_map.len(), 1);
                    let (val_key, val_bytes) = &token_map[0];
                    assert_eq!(*val_key, ciborium::Value::Text("val".to_string()));
                    assert_eq!(*val_bytes, ciborium::Value::Bytes(token.clone()));
                } else {
                    panic!("expected map inside tstTokens array");
                }
            } else {
                panic!("expected array for tstTokens");
            }
        } else {
            panic!("expected map value for sigTst");
        }
    }

    #[test]
    fn inject_timestamp_roundtrip() {
        // Build a COSE_Sign1 and inject a timestamp into it.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let payload = b"test-claim-payload";
        let cose_bytes =
            crate::crypto::sign_evidence_cose(payload, &signing_key).expect("sign");

        let fake_token = vec![0x30, 0x03, 0x01, 0x02, 0x03]; // minimal DER SEQUENCE
        let modified = inject_timestamp_into_cose(&cose_bytes, &fake_token).expect("inject");

        // Parse the modified COSE_Sign1 and check for sigTst.
        use coset::CborSerializable;
        let sign1 = coset::CoseSign1::from_slice(&modified).expect("parse modified");
        let sigtst_entry = sign1
            .unprotected
            .rest
            .iter()
            .find(|(label, _)| *label == coset::Label::Text("sigTst".to_string()));
        assert!(sigtst_entry.is_some(), "sigTst must be present in unprotected header");

        // Original signature should still verify (unprotected header is not signed).
        let verified = crate::crypto::verify_evidence_cose(
            &modified,
            &signing_key.verifying_key(),
        )
        .expect("signature must still verify after timestamp injection");
        assert_eq!(verified, payload);
    }

    #[test]
    fn der_unsigned_integer_no_pad() {
        let data = [0x42, 0x00];
        let encoded = der_unsigned_integer(&data);
        // Tag 0x02, length 2, content 0x42 0x00
        assert_eq!(encoded, vec![0x02, 0x02, 0x42, 0x00]);
    }

    #[test]
    fn der_unsigned_integer_with_pad() {
        let data = [0x80, 0x01];
        let encoded = der_unsigned_integer(&data);
        // High bit set, needs padding: Tag 0x02, length 3, 0x00 0x80 0x01
        assert_eq!(encoded, vec![0x02, 0x03, 0x00, 0x80, 0x01]);
    }
}
