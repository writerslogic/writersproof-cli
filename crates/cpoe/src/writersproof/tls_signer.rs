// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! rustls `SigningKey`/`Signer` adapter for hardware-backed ECDSA-P256.
//!
//! Bridges the `tpm::Provider::sign()` interface (which uses the Secure Enclave
//! on macOS or TPM on Windows/Linux) into rustls's TLS client authentication.
//! The private key never enters process memory.

use std::sync::Arc;

use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error as TlsError, SignatureAlgorithm, SignatureScheme};

use crate::tpm::ProviderHandle;

/// A rustls `SigningKey` backed by hardware (Secure Enclave / TPM).
///
/// Only offers `ECDSA_NISTP256_SHA256` since that's what the SE supports.
pub struct HardwareSigningKey {
    provider: ProviderHandle,
}

impl std::fmt::Debug for HardwareSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareSigningKey").finish_non_exhaustive()
    }
}

impl HardwareSigningKey {
    pub fn new(provider: ProviderHandle) -> Self {
        Self { provider }
    }
}

impl SigningKey for HardwareSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&SignatureScheme::ECDSA_NISTP256_SHA256) {
            Some(Box::new(HardwareSigner {
                provider: self.provider.clone(),
            }))
        } else {
            None
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

/// Performs a single TLS CertificateVerify signature via hardware.
///
/// rustls passes the full message (not pre-hashed) per the `Signer` trait contract.
/// The SE's `kSecKeyAlgorithmECDSASignatureMessageX962SHA256` hashes internally,
/// which satisfies the requirement: "the implementer must hash it using the hash
/// function implicit in scheme()."
struct HardwareSigner {
    provider: ProviderHandle,
}

impl std::fmt::Debug for HardwareSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareSigner").finish_non_exhaustive()
    }
}

impl Signer for HardwareSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        self.provider
            .sign(message)
            .map_err(|e| TlsError::General(format!("hardware signing failed: {e}")))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::{Binding, Capabilities, ClockInfo, Provider, Quote, TpmError};

    #[derive(Debug)]
    struct MockProvider;

    impl Provider for MockProvider {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                has_secure_enclave: false,
                has_tpm: false,
                has_key_attestation: false,
            }
        }
        fn device_id(&self) -> String {
            "mock".into()
        }
        fn public_key(&self) -> Vec<u8> {
            vec![0x04; 65] // uncompressed P-256 point placeholder
        }
        fn algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::ES256
        }
        fn quote(&self, _nonce: &[u8], _pcrs: &[u32]) -> Result<Quote, TpmError> {
            Err(TpmError::NotSupported)
        }
        fn bind(&self, _data: &[u8]) -> Result<Binding, TpmError> {
            Err(TpmError::NotSupported)
        }
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TpmError> {
            // Return a fake DER-encoded ECDSA signature
            let mut sig = vec![0x30, 0x44]; // SEQUENCE header
            sig.extend_from_slice(&[0x02, 0x20]); // INTEGER r
            sig.extend_from_slice(&[0xAB; 32]);
            sig.extend_from_slice(&[0x02, 0x20]); // INTEGER s
            sig.extend_from_slice(&data[..32.min(data.len())]);
            sig.resize(70, 0);
            Ok(sig)
        }
        fn verify(&self, _binding: &Binding) -> Result<(), TpmError> {
            Ok(())
        }
        fn seal(&self, _data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TpmError> {
            Err(TpmError::NotSupported)
        }
        fn unseal(&self, _sealed: &[u8]) -> Result<Vec<u8>, TpmError> {
            Err(TpmError::NotSupported)
        }
        fn clock_info(&self) -> Result<ClockInfo, TpmError> {
            Err(TpmError::NotSupported)
        }
    }

    #[test]
    fn choose_scheme_offers_p256() {
        let key = HardwareSigningKey::new(Arc::new(MockProvider));
        let offered = &[
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ];
        assert!(key.choose_scheme(offered).is_some());
    }

    #[test]
    fn choose_scheme_rejects_unsupported() {
        let key = HardwareSigningKey::new(Arc::new(MockProvider));
        let offered = &[SignatureScheme::RSA_PKCS1_SHA256, SignatureScheme::ED25519];
        assert!(key.choose_scheme(offered).is_none());
    }

    #[test]
    fn signer_produces_output() {
        let key = HardwareSigningKey::new(Arc::new(MockProvider));
        let signer = key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap();
        let result = signer.sign(b"test message for TLS CertificateVerify");
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn algorithm_is_ecdsa() {
        let key = HardwareSigningKey::new(Arc::new(MockProvider));
        assert_eq!(key.algorithm(), SignatureAlgorithm::ECDSA);
    }
}
