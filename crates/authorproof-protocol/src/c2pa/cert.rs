// SPDX-License-Identifier: Apache-2.0

//! Self-signed X.509 certificate generation for C2PA x5chain headers.
//!
//! The C2PA spec requires `x5chain` (COSE header label 33) to contain
//! DER-encoded X.509 certificate chain bytes, not raw public keys.
//! This module generates a self-signed Ed25519 certificate suitable
//! for embedding in the COSE_Sign1 protected header.

use crate::error::{Error, Result};
use der::asn1::{BitString, ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use ed25519_dalek::SigningKey;
use sha2::Digest;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{CertificateInner, TbsCertificateInner, Version};
use x509_cert::ext::Extension;
use x509_cert::name::RdnSequence;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

/// OID for Ed25519 (RFC 8410): 1.3.101.112
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// C2PA claim signing EKU OID: 1.3.6.1.4.1.62558.2.1
const C2PA_CLAIM_SIGNING_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.2.1");

/// Basic Constraints OID: 2.5.29.19
const BASIC_CONSTRAINTS_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// Key Usage OID: 2.5.29.15
const KEY_USAGE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

/// Extended Key Usage OID: 2.5.29.37
const EKU_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// Subject Key Identifier OID: 2.5.29.14
const SKI_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// Subject and Issuer DN for self-signed CPoE certificates.
const CERT_DN: &str = "CN=WritersProof CPoE Signer,O=WritersLogic";

/// Certificate validity duration: 1 year (365 days).
const VALIDITY_DAYS: u64 = 365;

/// Generate a self-signed X.509 v3 certificate for the given Ed25519 signing key.
///
/// The certificate uses:
/// - Subject/Issuer: `CN=WritersProof CPoE Signer, O=WritersLogic`
/// - Validity: 1 year from the current time
/// - Algorithm: Ed25519 (OID 1.3.101.112)
/// - Self-signed with the same key
///
/// Returns the DER-encoded certificate bytes.
pub fn generate_self_signed_cert(signing_key: &SigningKey) -> Result<Vec<u8>> {
    let dn: RdnSequence = CERT_DN
        .parse()
        .map_err(|e| Error::Crypto(format!("failed to parse certificate DN: {e}")))?;

    // Ed25519 algorithm identifier: OID only, no parameters (RFC 8410 Section 3)
    let algorithm = AlgorithmIdentifierOwned {
        oid: ED25519_OID,
        parameters: None,
    };

    // Serial number derived from public key hash for determinism.
    // Take first 20 bytes of SHA-256(public_key) as the serial number.
    let pk_bytes = signing_key.verifying_key().to_bytes();
    let pk_hash = sha2::Sha256::digest(pk_bytes);
    debug_assert_eq!(pk_hash.len(), 32, "SHA-256 digest must be 32 bytes");
    let serial: SerialNumber = SerialNumber::new(&pk_hash[..20])
        .map_err(|e| Error::Crypto(format!("failed to create serial number: {e}")))?;

    // Validity: now to now + 1 year
    let validity = Validity::from_now(core::time::Duration::from_secs(
        VALIDITY_DAYS * 24 * 60 * 60,
    ))
    .map_err(|e| Error::Crypto(format!("failed to create validity period: {e}")))?;

    // SubjectPublicKeyInfo for Ed25519
    let spki = SubjectPublicKeyInfoOwned {
        algorithm: algorithm.clone(),
        subject_public_key: BitString::from_bytes(&pk_bytes)
            .map_err(|e| Error::Crypto(format!("failed to encode public key: {e}")))?,
    };

    // Build X.509 v3 extensions required by C2PA Trust Model:
    // 1. BasicConstraints (critical): cA=FALSE (end-entity)
    // 2. KeyUsage (critical): digitalSignature
    // 3. ExtendedKeyUsage: c2pa-kp-claimSigning (1.3.6.1.4.1.62558.2.1)
    // 4. SubjectKeyIdentifier: SHA-256(publicKey)[..20]
    let extensions = build_c2pa_extensions(&pk_hash)?;

    let tbs = TbsCertificateInner {
        version: Version::V3,
        serial_number: serial,
        signature: algorithm.clone(),
        issuer: dn.clone(),
        validity,
        subject: dn,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    // DER-encode the TBS certificate for signing.
    let tbs_der = tbs
        .to_der()
        .map_err(|e| Error::Crypto(format!("failed to DER-encode TBS certificate: {e}")))?;

    // Sign with Ed25519
    let signature_bytes = ed25519_dalek::Signer::sign(signing_key, &tbs_der)
        .to_bytes()
        .to_vec();

    let signature = BitString::from_bytes(&signature_bytes)
        .map_err(|e| Error::Crypto(format!("failed to encode signature: {e}")))?;

    let cert = CertificateInner {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature,
    };

    cert.to_der()
        .map_err(|e| Error::Crypto(format!("failed to DER-encode certificate: {e}")))
}

/// Extract the Ed25519 public key bytes from a DER-encoded X.509 certificate.
///
/// Parses the certificate and extracts the 32-byte Ed25519 public key
/// from the SubjectPublicKeyInfo field.
pub fn extract_public_key_from_cert(cert_der: &[u8]) -> Result<[u8; 32]> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| Error::Crypto(format!("failed to parse certificate DER: {e}")))?;

    let spki = &cert.tbs_certificate.subject_public_key_info;

    // Verify this is an Ed25519 certificate
    if spki.algorithm.oid != ED25519_OID {
        return Err(Error::Crypto(format!(
            "expected Ed25519 OID ({}), got {}",
            ED25519_OID, spki.algorithm.oid
        )));
    }

    let raw_bytes = spki.subject_public_key.raw_bytes();

    if raw_bytes.len() != 32 {
        return Err(Error::Crypto(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            raw_bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(raw_bytes);
    Ok(key)
}

/// Build X.509 v3 extensions required by the C2PA Trust Model.
fn build_c2pa_extensions(
    pk_hash: &[u8],
) -> Result<x509_cert::ext::Extensions> {
    // 1. BasicConstraints (critical): cA=FALSE
    // DER: SEQUENCE { BOOLEAN FALSE } → 30 03 01 01 00
    let basic_constraints_value = OctetString::new(vec![0x30, 0x03, 0x01, 0x01, 0x00])
        .map_err(|e| Error::Crypto(format!("BasicConstraints encoding: {e}")))?;
    let basic_constraints = Extension {
        extn_id: BASIC_CONSTRAINTS_OID,
        critical: true,
        extn_value: basic_constraints_value,
    };

    // 2. KeyUsage (critical): digitalSignature (bit 0)
    // DER: BIT STRING { 03 02 07 80 } → 07 unused bits, 0x80 = bit 0 set
    let key_usage_value = OctetString::new(vec![0x03, 0x02, 0x07, 0x80])
        .map_err(|e| Error::Crypto(format!("KeyUsage encoding: {e}")))?;
    let key_usage = Extension {
        extn_id: KEY_USAGE_OID,
        critical: true,
        extn_value: key_usage_value,
    };

    // 3. ExtendedKeyUsage: c2pa-kp-claimSigning (1.3.6.1.4.1.62558.2.1)
    // DER-encode the OID inside a SEQUENCE.
    let eku_oid_der = C2PA_CLAIM_SIGNING_OID
        .to_der()
        .map_err(|e| Error::Crypto(format!("EKU OID encoding: {e}")))?;
    let mut eku_seq = vec![0x30, eku_oid_der.len() as u8];
    eku_seq.extend_from_slice(&eku_oid_der);
    let eku_value = OctetString::new(eku_seq)
        .map_err(|e| Error::Crypto(format!("EKU encoding: {e}")))?;
    let eku = Extension {
        extn_id: EKU_OID,
        critical: false,
        extn_value: eku_value,
    };

    // 4. SubjectKeyIdentifier: first 20 bytes of SHA-256(publicKey)
    // DER: OCTET STRING wrapping the 20-byte key ID
    let ski_bytes = &pk_hash[..20.min(pk_hash.len())];
    let mut ski_der = vec![0x04, ski_bytes.len() as u8];
    ski_der.extend_from_slice(ski_bytes);
    let ski_value = OctetString::new(ski_der)
        .map_err(|e| Error::Crypto(format!("SKI encoding: {e}")))?;
    let ski = Extension {
        extn_id: SKI_OID,
        critical: false,
        extn_value: ski_value,
    };

    Ok(vec![basic_constraints, key_usage, eku, ski])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    #[test]
    fn generate_cert_and_extract_key_roundtrip() {
        let key = test_signing_key();
        let cert_der = generate_self_signed_cert(&key).unwrap();

        // Certificate should be non-trivial size (DER overhead + 32-byte key + 64-byte sig)
        assert!(cert_der.len() > 100, "cert too small: {} bytes", cert_der.len());

        // Extract key should match original
        let extracted = extract_public_key_from_cert(&cert_der).unwrap();
        assert_eq!(extracted, key.verifying_key().to_bytes());
    }

    #[test]
    fn generated_cert_is_valid_der() {
        let key = test_signing_key();
        let cert_der = generate_self_signed_cert(&key).unwrap();

        // Should parse back as a valid Certificate
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();
        assert_eq!(cert.tbs_certificate.version, Version::V3);
    }

    #[test]
    fn generated_cert_has_correct_subject() {
        let key = test_signing_key();
        let cert_der = generate_self_signed_cert(&key).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();

        let subject_str = cert.tbs_certificate.subject.to_string();
        assert!(
            subject_str.contains("WritersProof CPoE Signer"),
            "unexpected subject: {}",
            subject_str
        );
        assert!(
            subject_str.contains("WritersLogic"),
            "unexpected subject: {}",
            subject_str
        );
    }

    #[test]
    fn generated_cert_uses_ed25519() {
        let key = test_signing_key();
        let cert_der = generate_self_signed_cert(&key).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();

        assert_eq!(
            cert.tbs_certificate.subject_public_key_info.algorithm.oid,
            ED25519_OID
        );
        assert_eq!(cert.tbs_certificate.signature.oid, ED25519_OID);
        assert_eq!(cert.signature_algorithm.oid, ED25519_OID);
    }

    #[test]
    fn generated_cert_signature_verifies() {
        let key = test_signing_key();
        let cert_der = generate_self_signed_cert(&key).unwrap();
        let cert = x509_cert::Certificate::from_der(&cert_der).unwrap();

        // Re-encode TBS and verify the signature
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        let sig_bytes = cert.signature.raw_bytes();
        let sig = ed25519_dalek::Signature::from_slice(sig_bytes).unwrap();
        let vk = VerifyingKey::from_bytes(&key.verifying_key().to_bytes()).unwrap();
        ed25519_dalek::Verifier::verify(&vk, &tbs_der, &sig).unwrap();
    }

    #[test]
    fn extract_key_rejects_invalid_der() {
        let result = extract_public_key_from_cert(&[0xFF, 0x00, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn different_keys_produce_different_certs() {
        let key1 = SigningKey::from_bytes(&[1u8; 32]);
        let key2 = SigningKey::from_bytes(&[2u8; 32]);

        let cert1 = generate_self_signed_cert(&key1).unwrap();
        let cert2 = generate_self_signed_cert(&key2).unwrap();

        assert_ne!(cert1, cert2);

        let pk1 = extract_public_key_from_cert(&cert1).unwrap();
        let pk2 = extract_public_key_from_cert(&cert2).unwrap();
        assert_ne!(pk1, pk2);
        assert_eq!(pk1, key1.verifying_key().to_bytes());
        assert_eq!(pk2, key2.verifying_key().to_bytes());
    }
}
