// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! IETF SCITT (Supply Chain Integrity, Transparency, and Trust) types.
//!
//! Per draft-ietf-scitt-architecture. SCITT provides standards-based transparency
//! receipts that can replace CPoE's proprietary beacon attestation format.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::evidence::WpBeaconAttestation;

use super::C2PA_MEDIA_TYPE;

/// A SCITT Signed Statement is a COSE_Sign1 payload submitted to a Transparency Service.
/// CPoE evidence packets are natural Signed Statements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStatement {
    /// The COSE_Sign1 encoded evidence packet.
    pub envelope: Vec<u8>,
    /// Content type of the payload (application/c2pa).
    pub content_type: String,
    /// Subject identifier (document hash or DID).
    pub subject: String,
}

/// A SCITT Receipt is a countersignature from the Transparency Service
/// proving the statement was included in the append-only log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyReceipt {
    /// CBOR-encoded receipt (inclusion proof in Merkle tree).
    pub receipt_cbor: Vec<u8>,
    /// Timestamp from the Transparency Service (RFC 3339).
    pub registered_at: String,
    /// The Transparency Service's identifier.
    pub service_id: String,
}

/// Convert a CPoE evidence packet into a SCITT Signed Statement.
///
/// The evidence CBOR bytes become the envelope, the document hash is hex-encoded
/// as the subject identifier, and the content type is set to the CPoE media type.
pub fn evidence_to_signed_statement(evidence_cbor: &[u8], doc_hash: &[u8; 32]) -> SignedStatement {
    let subject = doc_hash.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });

    SignedStatement {
        envelope: evidence_cbor.to_vec(),
        content_type: C2PA_MEDIA_TYPE.to_string(),
        subject,
    }
}

/// Convert a CPoE beacon attestation to a SCITT-compatible receipt structure.
///
/// This is a bridge for migrating from proprietary beacons to standards-based receipts.
/// The beacon's counter-signature and timestamp map onto the receipt fields;
/// the drand round and NIST pulse are CBOR-encoded as the receipt body.
pub fn beacon_to_receipt_format(beacon: &WpBeaconAttestation) -> Result<TransparencyReceipt> {
    // Encode the beacon's randomness proofs as a minimal CBOR map for the receipt body.
    let mut buf = Vec::new();
    ciborium::into_writer(
        &ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("drand_round".to_string()),
                ciborium::value::Value::Integer(beacon.drand_round.into()),
            ),
            (
                ciborium::value::Value::Text("drand_randomness".to_string()),
                ciborium::value::Value::Text(beacon.drand_randomness.clone()),
            ),
            (
                ciborium::value::Value::Text("nist_pulse_index".to_string()),
                ciborium::value::Value::Integer(beacon.nist_pulse_index.into()),
            ),
            (
                ciborium::value::Value::Text("nist_output_value".to_string()),
                ciborium::value::Value::Text(beacon.nist_output_value.clone()),
            ),
            (
                ciborium::value::Value::Text("wp_signature".to_string()),
                ciborium::value::Value::Text(beacon.wp_signature.clone()),
            ),
        ]),
        &mut buf,
    )
    .map_err(|e| crate::error::Error::Internal(format!("CBOR serialization failed: {e}")))?;

    Ok(TransparencyReceipt {
        receipt_cbor: buf,
        registered_at: beacon.fetched_at.clone(),
        service_id: "writersproof-beacon-v1".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_to_signed_statement() {
        let evidence = vec![0xD2, 0x84, 0x01, 0x02];
        let doc_hash = [0xABu8; 32];

        let stmt = evidence_to_signed_statement(&evidence, &doc_hash);

        assert_eq!(stmt.envelope, evidence);
        assert_eq!(stmt.content_type, C2PA_MEDIA_TYPE);
        assert_eq!(stmt.subject.len(), 64);
        assert!(stmt.subject.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(stmt.subject.starts_with("ab"));
    }

    #[test]
    fn test_signed_statement_subject_is_hex_of_hash() {
        let doc_hash = [0x00u8; 32];
        let stmt = evidence_to_signed_statement(&[], &doc_hash);
        assert_eq!(
            stmt.subject,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_beacon_to_receipt_format() {
        let beacon = WpBeaconAttestation {
            drand_round: 12345,
            drand_randomness: "aa".repeat(32),
            nist_pulse_index: 67890,
            nist_output_value: "bb".repeat(64),
            nist_timestamp: "2026-03-24T00:00:00Z".to_string(),
            fetched_at: "2026-03-24T00:00:01Z".to_string(),
            wp_signature: "cc".repeat(64),
            wp_key_id: None,
        };

        let receipt = beacon_to_receipt_format(&beacon).unwrap();

        assert_eq!(receipt.registered_at, "2026-03-24T00:00:01Z");
        assert_eq!(receipt.service_id, "writersproof-beacon-v1");
        assert!(!receipt.receipt_cbor.is_empty());

        // Verify the CBOR decodes back to a map with the expected keys.
        let val: ciborium::value::Value =
            ciborium::de::from_reader(&receipt.receipt_cbor[..]).expect("valid CBOR");
        let map = match val {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("expected CBOR map"),
        };
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn test_transparency_receipt_serde_roundtrip() {
        let receipt = TransparencyReceipt {
            receipt_cbor: vec![0xA0],
            registered_at: "2026-01-01T00:00:00Z".to_string(),
            service_id: "test-service".to_string(),
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        let decoded: TransparencyReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn test_scitt_signed_statement_structure() {
        let evidence = vec![0xD2, 0x84, 0x43, 0x50, 0x4F, 0x50];
        let doc_hash = [0x42u8; 32];
        let stmt = evidence_to_signed_statement(&evidence, &doc_hash);

        // Envelope preserves exact evidence bytes.
        assert_eq!(stmt.envelope, evidence);
        // Content type is the CPoE media type.
        assert_eq!(stmt.content_type, C2PA_MEDIA_TYPE);
        // Subject is 64-char hex of the doc hash.
        assert_eq!(stmt.subject.len(), 64);
        assert!(stmt.subject.starts_with("42"));
        assert!(stmt.subject.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_scitt_beacon_to_receipt() {
        let beacon = WpBeaconAttestation {
            drand_round: 99999,
            drand_randomness: "deadbeef".repeat(8),
            nist_pulse_index: 55555,
            nist_output_value: "cafebabe".repeat(16),
            nist_timestamp: "2026-03-25T12:00:00Z".to_string(),
            fetched_at: "2026-03-25T12:00:05Z".to_string(),
            wp_signature: "ff".repeat(64),
            wp_key_id: None,
        };

        let receipt = beacon_to_receipt_format(&beacon).unwrap();

        // registered_at comes from fetched_at.
        assert_eq!(receipt.registered_at, "2026-03-25T12:00:05Z");
        // service_id is the beacon service identifier.
        assert_eq!(receipt.service_id, "writersproof-beacon-v1");
        // Receipt CBOR decodes to a map with 5 entries.
        let val: ciborium::value::Value =
            ciborium::de::from_reader(&receipt.receipt_cbor[..]).expect("valid CBOR");
        let map = match val {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("expected CBOR map in receipt"),
        };
        assert_eq!(map.len(), 5);

        // Verify specific fields are present and correct.
        let has_drand_round = map.iter().any(|(k, v)| {
            matches!(k, ciborium::value::Value::Text(s) if s == "drand_round")
                && matches!(v, ciborium::value::Value::Integer(i) if {
                    let n: i128 = (*i).into();
                    n == 99999
                })
        });
        assert!(has_drand_round, "receipt should contain drand_round=99999");
    }

    #[test]
    fn test_signed_statement_serde_roundtrip() {
        let stmt = SignedStatement {
            envelope: vec![0x01, 0x02],
            content_type: C2PA_MEDIA_TYPE.to_string(),
            subject: "abcd".to_string(),
        };
        let json = serde_json::to_string(&stmt).expect("serialize");
        let decoded: SignedStatement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(stmt, decoded);
    }
}
