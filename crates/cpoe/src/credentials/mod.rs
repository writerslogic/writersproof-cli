// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! ISO mDoc-style authorship credentials.
//!
//! Provides `AuthorshipCredential` for packaging authorship evidence into
//! a signed, portable credential with CBOR encoding and COSE_Sign1 envelope.

use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::store::text_fragments::TextFragment;

/// Document type identifier for authorship credentials.
pub const DOCTYPE_AUTHORSHIP_V1: &str = "com.writerslogic.authorship.v1";

/// Namespace for authorship claims.
pub const NAMESPACE_AUTHORSHIP: &str = "com.writerslogic.authorship";

/// Default credential validity duration: 365 days in milliseconds.
const DEFAULT_VALIDITY_MS: i64 = 365 * 24 * 60 * 60 * 1000;

/// An authorship credential containing claims about a document's creation
/// process, suitable for CBOR encoding and COSE_Sign1 signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorshipCredential {
    pub document_type: String,
    pub namespace: String,
    pub validity: ValidityInfo,
    pub claims: AuthorshipClaims,
    /// COSE_Sign1 envelope bytes, populated after signing.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes_opt")]
    pub issuer_signed: Option<Vec<u8>>,
}

/// Validity period and issuer information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityInfo {
    /// Issuance timestamp (Unix milliseconds).
    pub issued_at: i64,
    /// Expiration timestamp (Unix milliseconds).
    pub expires_at: i64,
    /// Issuer identifier.
    pub issuer: String,
}

/// Claims about the authorship process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorshipClaims {
    pub author_did: Option<String>,
    #[serde(with = "serde_bytes")]
    pub document_hash: Vec<u8>,
    pub session_id: String,
    pub attestation_tier: String,
    pub process_verdict: String,
    pub authorship_confidence: f64,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes_opt")]
    pub keystroke_proof: Option<Vec<u8>>,
    pub composition_ratio: Option<f64>,
    pub source_attributions: Vec<SourceAttribution>,
    pub ai_disclosure: Option<String>,
}

/// Attribution of content to a source session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAttribution {
    pub source_session_id: String,
    pub source_app: String,
    pub fragment_count: usize,
    pub verified: bool,
}

impl AuthorshipCredential {
    /// Build a credential from text fragments and forensic assessment.
    #[allow(dead_code)]
    pub fn from_session(
        session_id: &str,
        fragments: &[TextFragment],
        attestation_tier: &str,
        process_verdict: &str,
        confidence: f64,
        author_did: Option<&str>,
    ) -> Self {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        // Compute document hash from all fragment hashes
        let mut hasher = Sha256::new();
        for f in fragments {
            hasher.update(&f.fragment_hash);
        }
        let document_hash = hasher.finalize().to_vec();

        // Build source attributions from fragments with source sessions
        let mut attr_map = std::collections::HashMap::<String, SourceAttribution>::new();
        for f in fragments {
            if let Some(ref src_session) = f.source_session_id {
                let entry =
                    attr_map
                        .entry(src_session.clone())
                        .or_insert_with(|| SourceAttribution {
                            source_session_id: src_session.clone(),
                            source_app: f.source_app_bundle_id.clone().unwrap_or_default(),
                            fragment_count: 0,
                            verified: false,
                        });
                entry.fragment_count += 1;
            }
        }

        // Compute composition ratio: original vs total fragments
        let total = fragments.len().max(1);
        let original = fragments
            .iter()
            .filter(|f| f.source_session_id.is_none())
            .count();
        let composition_ratio = original as f64 / total as f64;

        Self {
            document_type: DOCTYPE_AUTHORSHIP_V1.to_string(),
            namespace: NAMESPACE_AUTHORSHIP.to_string(),
            validity: ValidityInfo {
                issued_at: now_ms,
                expires_at: now_ms + DEFAULT_VALIDITY_MS,
                issuer: "WritersProof".to_string(),
            },
            claims: AuthorshipClaims {
                author_did: author_did.map(String::from),
                document_hash,
                session_id: session_id.to_string(),
                attestation_tier: attestation_tier.to_string(),
                process_verdict: process_verdict.to_string(),
                authorship_confidence: confidence.clamp(0.0, 1.0),
                keystroke_proof: None,
                composition_ratio: Some(composition_ratio),
                source_attributions: attr_map.into_values().collect(),
                ai_disclosure: None,
            },
            issuer_signed: None,
        }
    }

    /// Serialize the credential to CBOR bytes.
    #[allow(dead_code)]
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| Error::crypto(format!("CBOR encode error: {e}")))?;
        Ok(buf)
    }

    /// Deserialize a credential from CBOR bytes.
    #[allow(dead_code)]
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes).map_err(|e| Error::crypto(format!("CBOR decode error: {e}")))
    }

    /// Wrap in a COSE_Sign1 envelope and sign with Ed25519.
    ///
    /// Sets `self.issuer_signed` and returns the signed COSE bytes.
    #[allow(dead_code)]
    pub fn sign_cose(&mut self, signing_key: &ed25519_dalek::SigningKey) -> Result<Vec<u8>> {
        let payload = self.to_cbor()?;

        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .build();

        let mut sign_error: Option<Error> = None;
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(&[], |sig_data| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    signing_key.sign(sig_data).to_vec()
                })) {
                    Ok(sig) => sig,
                    Err(_) => {
                        sign_error = Some(Error::crypto("Ed25519 signing failed"));
                        Vec::new()
                    }
                }
            })
            .build();

        if let Some(e) = sign_error {
            return Err(e);
        }

        if sign1.signature.is_empty() {
            return Err(Error::crypto("COSE signing produced empty signature"));
        }

        let signed_bytes = sign1
            .to_vec()
            .map_err(|e| Error::crypto(format!("COSE encode error: {e}")))?;

        self.issuer_signed = Some(signed_bytes.clone());
        Ok(signed_bytes)
    }

    /// Verify a signed credential and extract it from the COSE envelope.
    #[allow(dead_code)]
    pub fn verify_cose(
        signed_bytes: &[u8],
        public_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self> {
        let sign1 = coset::CoseSign1::from_slice(signed_bytes)
            .map_err(|e| Error::crypto(format!("COSE decode error: {e}")))?;

        let expected_alg = coset::Algorithm::Assigned(coset::iana::Algorithm::EdDSA);
        if sign1.protected.header.alg.as_ref() != Some(&expected_alg) {
            return Err(Error::crypto(
                "Credential expected EdDSA algorithm in COSE header",
            ));
        }

        if sign1.signature.is_empty() {
            return Err(Error::crypto("Credential missing signature"));
        }

        sign1.verify_signature(&[], |sig_bytes, tbs_data| {
            let signature = ed25519_dalek::Signature::from_slice(sig_bytes)
                .map_err(|_| Error::crypto("Invalid Ed25519 signature format"))?;
            public_key
                .verify(tbs_data, &signature)
                .map_err(|_| Error::crypto("Credential signature verification failed"))
        })?;

        let payload = sign1
            .payload
            .ok_or_else(|| Error::crypto("Missing credential payload"))?;

        let mut credential = Self::from_cbor(&payload)?;
        credential.issuer_signed = Some(signed_bytes.to_vec());
        Ok(credential)
    }

    /// Check if the credential is still valid (not expired).
    #[allow(dead_code)]
    pub fn is_valid(&self) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        now_ms >= self.validity.issued_at && now_ms <= self.validity.expires_at
    }
}

/// serde helper for `Option<Vec<u8>>` using serde_bytes.
mod serde_bytes_opt {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        val: &Option<Vec<u8>>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match val {
            Some(bytes) => serde_bytes::Bytes::new(bytes).serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_test_credential() -> AuthorshipCredential {
        AuthorshipCredential {
            document_type: DOCTYPE_AUTHORSHIP_V1.to_string(),
            namespace: NAMESPACE_AUTHORSHIP.to_string(),
            validity: ValidityInfo {
                issued_at: 1_000_000,
                expires_at: 1_000_000 + DEFAULT_VALIDITY_MS,
                issuer: "test".to_string(),
            },
            claims: AuthorshipClaims {
                author_did: Some("did:web:example.com".to_string()),
                document_hash: vec![0xAA; 32],
                session_id: "test-session-1".to_string(),
                attestation_tier: "HardwareBound".to_string(),
                process_verdict: "human_authored".to_string(),
                authorship_confidence: 0.95,
                keystroke_proof: None,
                composition_ratio: Some(0.85),
                source_attributions: vec![],
                ai_disclosure: None,
            },
            issuer_signed: None,
        }
    }

    #[test]
    fn test_cbor_roundtrip() {
        let cred = make_test_credential();
        let bytes = cred.to_cbor().expect("encode");
        let decoded = AuthorshipCredential::from_cbor(&bytes).expect("decode");
        assert_eq!(decoded.document_type, DOCTYPE_AUTHORSHIP_V1);
        assert_eq!(decoded.claims.session_id, "test-session-1");
        assert!((decoded.claims.authorship_confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sign_verify_cose_roundtrip() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let mut cred = make_test_credential();
        let signed_bytes = cred.sign_cose(&signing_key).expect("sign");

        assert!(cred.issuer_signed.is_some());
        assert!(!signed_bytes.is_empty());

        let verified =
            AuthorshipCredential::verify_cose(&signed_bytes, &verifying_key).expect("verify");
        assert_eq!(verified.claims.session_id, "test-session-1");
        assert_eq!(verified.claims.document_hash, vec![0xAA; 32]);
        assert!(verified.issuer_signed.is_some());
    }

    #[test]
    fn test_verify_cose_wrong_key_fails() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[99u8; 32]).verifying_key();

        let mut cred = make_test_credential();
        let signed_bytes = cred.sign_cose(&signing_key).expect("sign");

        let err = AuthorshipCredential::verify_cose(&signed_bytes, &wrong_key);
        assert!(err.is_err());
    }

    #[test]
    fn test_verify_cose_tampered_payload_fails() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let mut cred = make_test_credential();
        let mut signed_bytes = cred.sign_cose(&signing_key).expect("sign");

        // Tamper with a byte in the middle
        if signed_bytes.len() > 50 {
            signed_bytes[50] ^= 0xFF;
        }

        let err = AuthorshipCredential::verify_cose(&signed_bytes, &verifying_key);
        assert!(err.is_err());
    }

    #[test]
    fn test_is_valid_checks_expiry() {
        let mut cred = make_test_credential();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        cred.validity.issued_at = now_ms - 1000;
        cred.validity.expires_at = now_ms + 60_000;
        assert!(cred.is_valid());

        // Expired credential
        cred.validity.expires_at = now_ms - 1;
        assert!(!cred.is_valid());
    }

    #[test]
    fn test_confidence_clamped() {
        let cred = AuthorshipCredential::from_session(
            "sess-1",
            &[],
            "SoftwareOnly",
            "human_authored",
            1.5, // exceeds 1.0
            None,
        );
        assert!((cred.claims.authorship_confidence - 1.0).abs() < f64::EPSILON);

        let cred2 = AuthorshipCredential::from_session(
            "sess-2",
            &[],
            "SoftwareOnly",
            "human_authored",
            -0.5, // below 0.0
            None,
        );
        assert!(cred2.claims.authorship_confidence.abs() < f64::EPSILON);
    }
}
