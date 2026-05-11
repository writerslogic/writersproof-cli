// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Self-signed X.509 client certificate for mTLS authentication.
//!
//! Generates a self-signed ECDSA-P256 certificate using the hardware key
//! (Secure Enclave / TPM). The server validates the public key matches the
//! enrolled `hardware_key_id`, so no CA chain is needed.
//!
//! Cached at `{DATA_DIR}/client_cert.der` and regenerated on key rotation.

use der::{Decode, Encode};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{CertificateInner, TbsCertificateInner, Version};
use x509_cert::name::RdnSequence;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::error::{Error, Result};
use crate::tpm::Provider;

/// OID for ecPublicKey (1.2.840.10045.2.1).
const EC_PUBLIC_KEY_OID: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// OID for prime256v1 / secp256r1 (1.2.840.10045.3.1.7).
const PRIME256V1_OID: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// OID for ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
const ECDSA_SHA256_OID: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Certificate validity period: 1 year.
const VALIDITY_DAYS: u64 = 365;

/// Certificate subject/issuer DN prefix.
const CERT_DN_PREFIX: &str = "CN=";

/// Generate or load a cached self-signed client certificate for mTLS.
///
/// The certificate uses the hardware provider's ECDSA-P256 public key and is
/// self-signed via `provider.sign()`. Cached at `{DATA_DIR}/client_cert.der`.
///
/// Returns the DER-encoded certificate.
pub fn load_or_generate_client_cert(provider: &dyn Provider) -> Result<CertificateDer<'static>> {
    let data_dir =
        crate::utils::get_data_dir().ok_or_else(|| Error::crypto("data directory not found"))?;
    let cert_path = data_dir.join("client_cert.der");

    // Check for cached cert.
    if cert_path.is_file() {
        match std::fs::read(&cert_path) {
            Ok(der) if der.len() > 100 => {
                return Ok(CertificateDer::from(der));
            }
            Ok(_) => log::warn!("Cached mTLS client cert too small; regenerating"),
            Err(e) => log::warn!("Failed to read cached mTLS client cert: {e}; regenerating"),
        }
    }

    let cert_der = generate_client_cert(provider)?;

    // Cache via atomic write.
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| Error::crypto(format!("failed to create data dir: {e}")))?;
    let parent = cert_path.parent().unwrap_or(std::path::Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| Error::crypto(format!("failed to create temp file for cert: {e}")))?;
    std::fs::write(tmp.path(), cert_der.as_ref())
        .map_err(|e| Error::crypto(format!("failed to write cert temp file: {e}")))?;
    tmp.persist(&cert_path)
        .map_err(|e| Error::crypto(format!("failed to persist client cert: {e}")))?;

    log::info!("Generated mTLS client certificate at {}", cert_path.display());
    Ok(cert_der)
}

/// Generate a self-signed X.509 v3 certificate with the provider's P-256 key.
fn generate_client_cert(provider: &dyn Provider) -> Result<CertificateDer<'static>> {
    let pubkey_bytes = provider.public_key();
    if pubkey_bytes.len() != 65 || pubkey_bytes[0] != 0x04 {
        return Err(Error::crypto(format!(
            "expected 65-byte uncompressed P-256 public key, got {} bytes",
            pubkey_bytes.len()
        )));
    }

    // CN = first 16 hex chars of SHA-256(public_key) for identification.
    let pk_hash = Sha256::digest(&pubkey_bytes);
    let cn_hex = hex::encode(&pk_hash[..8]);
    let dn_str = format!("{CERT_DN_PREFIX}{cn_hex}");
    let dn: RdnSequence = dn_str
        .parse()
        .map_err(|e| Error::crypto(format!("failed to parse DN: {e}")))?;

    // Signature algorithm: ecdsa-with-SHA256.
    let sig_algorithm = AlgorithmIdentifierOwned {
        oid: ECDSA_SHA256_OID,
        parameters: None,
    };

    // Serial number from public key hash. Use 16 bytes to stay within
    // RFC 5280's 20-octet limit after ASN.1 INTEGER padding.
    let serial: SerialNumber = SerialNumber::new(&pk_hash[..16])
        .map_err(|e| Error::crypto(format!("failed to create serial number: {e}")))?;

    // Validity: now + 1 year.
    let validity = Validity::from_now(core::time::Duration::from_secs(
        VALIDITY_DAYS * 24 * 60 * 60,
    ))
    .map_err(|e| Error::crypto(format!("failed to create validity period: {e}")))?;

    // SubjectPublicKeyInfo for EC P-256.
    // Algorithm: ecPublicKey with parameter prime256v1.
    let ec_algorithm = AlgorithmIdentifierOwned {
        oid: EC_PUBLIC_KEY_OID,
        parameters: Some(
            der::asn1::AnyRef::from(&PRIME256V1_OID)
                .to_der()
                .map_err(|e| Error::crypto(format!("failed to encode prime256v1 OID: {e}")))
                .and_then(|der_bytes| {
                    der::asn1::Any::from_der(&der_bytes)
                        .map_err(|e| Error::crypto(format!("failed to parse Any: {e}")))
                })?,
        ),
    };

    let spki = SubjectPublicKeyInfoOwned {
        algorithm: ec_algorithm,
        subject_public_key: der::asn1::BitString::from_bytes(&pubkey_bytes)
            .map_err(|e| Error::crypto(format!("failed to encode public key: {e}")))?,
    };

    let tbs = TbsCertificateInner {
        version: Version::V3,
        serial_number: serial,
        signature: sig_algorithm.clone(),
        issuer: dn.clone(),
        validity,
        subject: dn,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };

    // DER-encode the TBS certificate for signing.
    let tbs_der = tbs
        .to_der()
        .map_err(|e| Error::crypto(format!("failed to DER-encode TBS certificate: {e}")))?;

    // Sign with hardware key. The SE hashes internally (ECDSA-SHA256-message).
    let signature_bytes = provider
        .sign(&tbs_der)
        .map_err(|e| Error::crypto(format!("hardware signing of TBS failed: {e}")))?;

    let signature = der::asn1::BitString::from_bytes(&signature_bytes)
        .map_err(|e| Error::crypto(format!("failed to encode signature: {e}")))?;

    let cert = CertificateInner {
        tbs_certificate: tbs,
        signature_algorithm: sig_algorithm,
        signature,
    };

    let cert_der = cert
        .to_der()
        .map_err(|e| Error::crypto(format!("failed to DER-encode certificate: {e}")))?;

    Ok(CertificateDer::from(cert_der))
}

/// Test-only accessor for `generate_client_cert` (used by integration tests in `cert_resolver`).
#[cfg(test)]
pub(super) fn generate_client_cert_for_test(provider: &dyn Provider) -> CertificateDer<'static> {
    generate_client_cert(provider).expect("test cert generation should not fail")
}

/// Invalidate the cached client certificate, forcing regeneration on next use.
///
/// Called during key rotation to ensure the new key gets a fresh certificate.
pub fn invalidate_cached_cert() -> Result<()> {
    let data_dir =
        crate::utils::get_data_dir().ok_or_else(|| Error::crypto("data directory not found"))?;
    let cert_path = data_dir.join("client_cert.der");
    if cert_path.exists() {
        std::fs::remove_file(&cert_path)
            .map_err(|e| Error::crypto(format!("failed to remove cached client cert: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::{Binding, Capabilities, ClockInfo, Quote, TpmError};

    #[derive(Debug)]
    struct MockP256Provider;

    impl Provider for MockP256Provider {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                hardware_backed: true,
                supports_pcrs: false,
                supports_sealing: false,
                supports_attestation: false,
                monotonic_counter: false,
                secure_clock: false,
            }
        }
        fn device_id(&self) -> String {
            "mock-p256".into()
        }
        fn public_key(&self) -> Vec<u8> {
            // Uncompressed P-256 point (0x04 || x || y), 65 bytes.
            let mut key = vec![0x04];
            key.extend_from_slice(&[0xAA; 32]); // x
            key.extend_from_slice(&[0xBB; 32]); // y
            key
        }
        fn algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::ES256
        }
        fn quote(&self, _nonce: &[u8], _pcrs: &[u32]) -> std::result::Result<Quote, TpmError> {
            Err(TpmError::NotAvailable)
        }
        fn bind(&self, _data: &[u8]) -> std::result::Result<Binding, TpmError> {
            Err(TpmError::NotAvailable)
        }
        fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, TpmError> {
            // Return a plausible DER-encoded ECDSA signature.
            let mut sig = vec![0x30, 0x44];
            sig.extend_from_slice(&[0x02, 0x20]);
            sig.extend_from_slice(&[0xAB; 32]); // r
            sig.extend_from_slice(&[0x02, 0x20]);
            // Use first 32 bytes of data as s (or pad).
            let s_len = data.len().min(32);
            sig.extend_from_slice(&data[..s_len]);
            sig.resize(70, 0);
            Ok(sig)
        }
        fn verify(&self, _binding: &Binding) -> std::result::Result<(), TpmError> {
            Ok(())
        }
        fn seal(&self, _data: &[u8], _policy: &[u8]) -> std::result::Result<Vec<u8>, TpmError> {
            Err(TpmError::NotAvailable)
        }
        fn unseal(&self, _sealed: &[u8]) -> std::result::Result<Vec<u8>, TpmError> {
            Err(TpmError::NotAvailable)
        }
        fn clock_info(&self) -> std::result::Result<ClockInfo, TpmError> {
            Err(TpmError::NotAvailable)
        }
    }

    #[test]
    fn generate_cert_produces_valid_der() {
        let provider = MockP256Provider;
        let cert = generate_client_cert(&provider).unwrap();
        assert!(cert.as_ref().len() > 100, "cert DER should be substantial");

        // Should be parseable as X.509.
        let parsed: CertificateInner =
            der::Decode::from_der(cert.as_ref()).expect("cert should be valid DER");
        assert_eq!(parsed.tbs_certificate.version, Version::V3);
    }

    #[test]
    fn rejects_invalid_pubkey_length() {
        #[derive(Debug)]
        struct BadKeyProvider;
        impl Provider for BadKeyProvider {
            fn capabilities(&self) -> Capabilities {
                Capabilities {
                    hardware_backed: false,
                    supports_pcrs: false,
                    supports_sealing: false,
                    supports_attestation: false,
                    monotonic_counter: false,
                    secure_clock: false,
                }
            }
            fn device_id(&self) -> String {
                "bad".into()
            }
            fn public_key(&self) -> Vec<u8> {
                vec![0x04; 33] // Wrong length for P-256.
            }
            fn algorithm(&self) -> coset::iana::Algorithm {
                coset::iana::Algorithm::ES256
            }
            fn quote(&self, _: &[u8], _: &[u32]) -> std::result::Result<Quote, TpmError> {
                Err(TpmError::NotAvailable)
            }
            fn bind(&self, _: &[u8]) -> std::result::Result<Binding, TpmError> {
                Err(TpmError::NotAvailable)
            }
            fn sign(&self, _: &[u8]) -> std::result::Result<Vec<u8>, TpmError> {
                Ok(vec![0; 70])
            }
            fn verify(&self, _: &Binding) -> std::result::Result<(), TpmError> {
                Ok(())
            }
            fn seal(&self, _: &[u8], _: &[u8]) -> std::result::Result<Vec<u8>, TpmError> {
                Err(TpmError::NotAvailable)
            }
            fn unseal(&self, _: &[u8]) -> std::result::Result<Vec<u8>, TpmError> {
                Err(TpmError::NotAvailable)
            }
            fn clock_info(&self) -> std::result::Result<ClockInfo, TpmError> {
                Err(TpmError::NotAvailable)
            }
        }

        let result = generate_client_cert(&BadKeyProvider);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("33 bytes"), "error should mention length: {err}");
    }

    #[test]
    fn load_or_generate_with_temp_dir() {
        let tmp = tempfile::tempdir().unwrap();
        // Set CPOE_DATA_DIR to temp dir for testing.
        let _guard = scopeguard::guard(
            std::env::var("CPOE_DATA_DIR").ok(),
            |prev| match prev {
                Some(v) => std::env::set_var("CPOE_DATA_DIR", v),
                None => std::env::remove_var("CPOE_DATA_DIR"),
            },
        );
        std::env::set_var("CPOE_DATA_DIR", tmp.path());

        let provider = MockP256Provider;
        let cert1 = load_or_generate_client_cert(&provider).unwrap();
        assert!(cert1.as_ref().len() > 100);

        // Second call should return cached cert.
        let cert2 = load_or_generate_client_cert(&provider).unwrap();
        assert_eq!(cert1.as_ref(), cert2.as_ref(), "should return cached cert");

        // Invalidate and regenerate.
        invalidate_cached_cert().unwrap();
        assert!(!tmp.path().join("client_cert.der").exists());
    }
}
