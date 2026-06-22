// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! RATS (Remote Attestation Procedures) interoperability module.
//!
//! Implements the IETF RATS architecture (RFC 9334) for CPoE's proof-of-effort
//! attestation flow. Provides:
//!
//! - **types**: RATS roles (Attester, Verifier, Relying Party) and wire-format
//!   wrappers for Evidence and Attestation Results
//! - **eat**: CWT encoding/decoding for EAR tokens in COSE_Sign1 envelopes
//!   per RFC 8392 and draft-ietf-rats-ear
//! - **corim**: CoRIM reference values manifest (draft-ietf-rats-corim)
//! - **scitt**: SCITT transparency receipts (draft-ietf-scitt-architecture)
//! - **toip**: ToIP Ecosystem Governance Framework and TRQP query types

pub mod corim;
pub mod eat;
pub mod scitt;
pub mod toip;
pub mod types;

/// C2PA media type used for evidence packets and attestation results.
pub const C2PA_MEDIA_TYPE: &str = "application/c2pa";

pub use corim::CpoeReferenceValues;
#[allow(deprecated)]
pub use eat::decode_eat_cwt_unverified;
pub use eat::{decode_eat_cwt_verified, encode_eat_cwt};
pub use scitt::{SignedStatement, TransparencyReceipt};
pub use toip::{EcosystemGovernanceFramework, TrqpQuery, TrqpResponse};
pub use types::{AttestationResult, Evidence, RatsRole};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use coset::CborSerializable;

    use crate::tpm::{Provider, SoftwareProvider};
    use crate::war::ear::{
        Ar4siStatus, EarAppraisal, EarToken, TrustworthinessVector, VerifierId, CPOE_EAR_PROFILE,
    };

    #[allow(deprecated)]
    use super::*;

    fn test_ear_token() -> EarToken {
        let mut submods = BTreeMap::new();
        submods.insert(
            "pop".to_string(),
            EarAppraisal {
                ear_status: Ar4siStatus::Affirming,
                ear_trustworthiness_vector: Some(TrustworthinessVector {
                    instance_identity: 2,
                    configuration: 2,
                    executables: 0,
                    file_system: 2,
                    hardware: 2,
                    runtime_opaque: 2,
                    storage_opaque: 2,
                    sourced_data: 2,
                }),
                ear_appraisal_policy_id: Some("pop-default-v1".to_string()),
                pop_seal: None,
                pop_evidence_ref: None,
                pop_entropy_report: None,
                pop_forgery_cost: None,
                pop_forensic_summary: None,
                pop_chain_length: Some(42),
                pop_chain_duration: Some(3600),
                pop_absence_claims: None,
                pop_warnings: Some(vec!["low entropy in segment 3".to_string()]),
                pop_process_start: None,
                pop_process_end: None,
            },
        );

        EarToken {
            eat_profile: CPOE_EAR_PROFILE.to_string(),
            iat: 1711324800,
            ear_verifier_id: VerifierId::default(),
            submods,
        }
    }

    #[test]
    fn test_encode_decode_cwt_roundtrip() {
        let ear = test_ear_token();
        let provider = SoftwareProvider::new();

        let cwt_bytes = encode_eat_cwt(&ear, &provider).expect("encode failed");
        assert!(!cwt_bytes.is_empty());

        let pk: [u8; 32] = provider.public_key().try_into().unwrap();
        let decoded = decode_eat_cwt_verified(&cwt_bytes, &pk).expect("decode failed");

        assert_eq!(decoded.eat_profile, ear.eat_profile);
        assert_eq!(decoded.iat, ear.iat);
        assert_eq!(decoded.ear_verifier_id.build, ear.ear_verifier_id.build);
        assert_eq!(
            decoded.ear_verifier_id.developer,
            ear.ear_verifier_id.developer
        );

        let pop = decoded.pop_appraisal().expect("missing pop submod");
        let orig = ear.pop_appraisal().expect("missing original pop submod");

        assert_eq!(pop.ear_status, orig.ear_status);
        assert_eq!(pop.pop_chain_length, orig.pop_chain_length);
        assert_eq!(pop.pop_chain_duration, orig.pop_chain_duration);
        assert_eq!(pop.pop_warnings, orig.pop_warnings);
        assert_eq!(pop.ear_appraisal_policy_id, orig.ear_appraisal_policy_id);

        // Trust vector roundtrip
        let tv = pop
            .ear_trustworthiness_vector
            .as_ref()
            .expect("missing trust vector");
        let orig_tv = orig
            .ear_trustworthiness_vector
            .as_ref()
            .expect("missing original trust vector");
        assert_eq!(tv, orig_tv);
    }

    #[test]
    fn test_cwt_has_cose_sign1_structure() {
        let ear = test_ear_token();
        let provider = SoftwareProvider::new();

        let cwt_bytes = encode_eat_cwt(&ear, &provider).expect("encode failed");

        // COSE_Sign1 is a 4-element CBOR array [protected, unprotected, payload, signature].
        // coset serializes without the optional CBOR tag, so first byte is 0x84 (4-element array).
        assert!(cwt_bytes.len() > 4, "CWT too short to contain COSE_Sign1");
        assert_eq!(
            cwt_bytes[0], 0x84,
            "expected COSE_Sign1 4-element array (0x84), got 0x{:02X}",
            cwt_bytes[0]
        );

        // Verify it parses back as a valid COSE_Sign1
        let sign1 = coset::CoseSign1::from_slice(&cwt_bytes).expect("should parse as COSE_Sign1");
        assert!(sign1.payload.is_some(), "COSE_Sign1 should have a payload");
        assert!(
            !sign1.signature.is_empty(),
            "COSE_Sign1 should have a signature"
        );
    }

    #[test]
    fn test_eat_cwt_includes_all_claims() {
        let ear = test_ear_token();
        let provider = SoftwareProvider::new();
        let cwt_bytes = encode_eat_cwt(&ear, &provider).expect("encode");

        // Decode payload from COSE_Sign1 and verify all EAR claims present.
        let sign1 = coset::CoseSign1::from_slice(&cwt_bytes).expect("parse COSE_Sign1");
        let payload = sign1.payload.expect("payload");
        let value: ciborium::Value =
            ciborium::from_reader(payload.as_slice()).expect("CBOR payload");
        let map = match &value {
            ciborium::Value::Map(m) => m,
            _ => panic!("payload should be CBOR map"),
        };

        // Check CWT standard claims: iss(1), sub(2), iat(6).
        let keys: Vec<i64> = map
            .iter()
            .filter_map(|(k, _)| match k {
                ciborium::Value::Integer(i) => {
                    let v: i128 = (*i).into();
                    i64::try_from(v).ok()
                }
                _ => None,
            })
            .collect();
        assert!(keys.contains(&1), "missing CWT iss");
        assert!(keys.contains(&2), "missing CWT sub");
        assert!(keys.contains(&6), "missing CWT iat");
        // EAT profile (265), verifier_id (1004), submods (266).
        assert!(keys.contains(&265), "missing EAT profile");
        assert!(keys.contains(&1004), "missing verifier ID");
        assert!(keys.contains(&266), "missing submods");
    }

    #[test]
    fn test_eat_cwt_cose_structure() {
        let ear = test_ear_token();
        let provider = SoftwareProvider::new();
        let cwt_bytes = encode_eat_cwt(&ear, &provider).expect("encode");

        // Must be a valid COSE_Sign1: 4-element CBOR array.
        assert_eq!(
            cwt_bytes[0], 0x84,
            "COSE_Sign1 must start with 0x84 (4-element array)"
        );

        let sign1 = coset::CoseSign1::from_slice(&cwt_bytes).expect("parse as COSE_Sign1");
        // Has protected headers, payload, and non-empty signature.
        assert!(sign1.payload.is_some());
        assert!(!sign1.signature.is_empty());
        // Protected header contains algorithm.
        assert!(sign1.protected.header.alg.is_some());
    }

    #[test]
    fn test_rats_types() {
        // RatsRole construction and labels
        assert_eq!(RatsRole::Attester.as_str(), "attester");
        assert_eq!(RatsRole::Verifier.as_str(), "verifier");
        assert_eq!(RatsRole::RelyingParty.as_str(), "relying-party");

        // Evidence wrapper
        let evidence = Evidence::new(vec![0xD2, 0x84, 0x01]);
        assert_eq!(Evidence::MEDIA_TYPE, super::C2PA_MEDIA_TYPE);
        assert_eq!(evidence.as_bytes(), &[0xD2, 0x84, 0x01]);

        // AttestationResult wrapper
        let result = AttestationResult::new(vec![0xD2, 0x84, 0x02]);
        assert_eq!(AttestationResult::MEDIA_TYPE, super::C2PA_MEDIA_TYPE);
        assert_eq!(result.as_bytes(), &[0xD2, 0x84, 0x02]);

        // Equality
        assert_eq!(RatsRole::Attester, RatsRole::Attester);
        assert_ne!(RatsRole::Attester, RatsRole::Verifier);
    }

    #[test]
    fn test_eat_cwt_verified_correct_key() {
        let ear = test_ear_token();
        let provider = SoftwareProvider::new();
        let cwt_bytes = encode_eat_cwt(&ear, &provider).expect("encode");

        let pk: [u8; 32] = provider.public_key().try_into().unwrap();
        let decoded = decode_eat_cwt_verified(&cwt_bytes, &pk).expect("verified decode");
        assert_eq!(decoded.eat_profile, ear.eat_profile);
        assert_eq!(decoded.iat, ear.iat);
    }

    #[test]
    fn test_eat_cwt_verified_wrong_key_fails() {
        let ear = test_ear_token();
        let provider = SoftwareProvider::new();
        let cwt_bytes = encode_eat_cwt(&ear, &provider).expect("encode");

        let wrong_provider = SoftwareProvider::new();
        let wrong_pk: [u8; 32] = wrong_provider.public_key().try_into().unwrap();
        let err = decode_eat_cwt_verified(&cwt_bytes, &wrong_pk).unwrap_err();
        assert!(
            err.to_string().contains("signature verification failed"),
            "expected signature error, got: {err}"
        );
    }
}
