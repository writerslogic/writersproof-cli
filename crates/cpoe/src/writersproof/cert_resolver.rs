// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! rustls `ResolvesClientCert` implementation for hardware-backed mTLS.
//!
//! Presents the self-signed client certificate and delegates signing to the
//! Secure Enclave / TPM via `HardwareSigningKey`.

use std::sync::Arc;

use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;
use rustls::SignatureScheme;

use super::tls_signer::HardwareSigningKey;

/// Resolves client certificates for mTLS using a hardware-backed key.
///
/// Holds a pre-built `CertifiedKey` containing the self-signed cert and
/// the `HardwareSigningKey` that delegates to `tpm::Provider::sign()`.
#[derive(Debug)]
pub struct MtlsCertResolver {
    certified_key: Arc<CertifiedKey>,
}

impl MtlsCertResolver {
    /// Create a new resolver from a DER-encoded client certificate and signing key.
    pub fn new(cert_der: CertificateDer<'static>, signing_key: Arc<HardwareSigningKey>) -> Self {
        let certified_key = CertifiedKey::new(vec![cert_der], signing_key);
        Self {
            certified_key: Arc::new(certified_key),
        }
    }
}

impl ResolvesClientCert for MtlsCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        // Only offer our cert if the server supports ECDSA-P256-SHA256.
        if sigschemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256) {
            Some(self.certified_key.clone())
        } else {
            None
        }
    }

    fn has_certs(&self) -> bool {
        true
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
                hardware_backed: false,
                supports_pcrs: false,
                supports_sealing: false,
                supports_attestation: false,
                monotonic_counter: false,
                secure_clock: false,
            }
        }
        fn device_id(&self) -> String {
            "mock".into()
        }
        fn public_key(&self) -> Vec<u8> {
            let mut key = vec![0x04];
            key.extend_from_slice(&[0xAA; 32]);
            key.extend_from_slice(&[0xBB; 32]);
            key
        }
        fn algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::ES256
        }
        fn quote(&self, _: &[u8], _: &[u32]) -> Result<Quote, TpmError> {
            Err(TpmError::NotAvailable)
        }
        fn bind(&self, _: &[u8]) -> Result<Binding, TpmError> {
            Err(TpmError::NotAvailable)
        }
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TpmError> {
            let mut sig = vec![0x30, 0x44, 0x02, 0x20];
            sig.extend_from_slice(&[0xAB; 32]);
            sig.extend_from_slice(&[0x02, 0x20]);
            sig.extend_from_slice(&data[..32.min(data.len())]);
            sig.resize(70, 0);
            Ok(sig)
        }
        fn verify(&self, _: &Binding) -> Result<(), TpmError> {
            Ok(())
        }
        fn seal(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, TpmError> {
            Err(TpmError::NotAvailable)
        }
        fn unseal(&self, _: &[u8]) -> Result<Vec<u8>, TpmError> {
            Err(TpmError::NotAvailable)
        }
        fn clock_info(&self) -> Result<ClockInfo, TpmError> {
            Err(TpmError::NotAvailable)
        }
    }

    fn make_resolver() -> MtlsCertResolver {
        let provider: Arc<dyn Provider + Send + Sync> = Arc::new(MockProvider);
        let signing_key = Arc::new(HardwareSigningKey::new(provider));
        // Use a minimal DER blob as placeholder cert.
        let fake_cert = CertificateDer::from(vec![0x30; 64]);
        MtlsCertResolver::new(fake_cert, signing_key)
    }

    #[test]
    fn resolve_with_matching_scheme() {
        let resolver = make_resolver();
        let schemes = &[
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ];
        assert!(resolver.resolve(&[], schemes).is_some());
    }

    #[test]
    fn resolve_rejects_unsupported_schemes() {
        let resolver = make_resolver();
        let schemes = &[SignatureScheme::RSA_PKCS1_SHA256, SignatureScheme::ED25519];
        assert!(resolver.resolve(&[], schemes).is_none());
    }

    #[test]
    fn has_certs_returns_true() {
        let resolver = make_resolver();
        assert!(resolver.has_certs());
    }

    /// End-to-end TLS handshake test using real P-256 crypto.
    ///
    /// Sets up a rustls server requiring client certs and a client using our
    /// `MtlsCertResolver`. Verifies the handshake completes and the server
    /// receives the client certificate.
    #[test]
    fn tls_handshake_with_real_p256() {
        use p256::ecdsa::{DerSignature, SigningKey as P256SigningKey, VerifyingKey};
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{
            CertificateDer, PrivateSec1KeyDer, ServerName, UnixTime,
        };
        use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
        use rustls::{
            ClientConnection, DigitallySignedStruct, DistinguishedName,
            ServerConfig, ServerConnection, SignatureScheme,
        };

        // -- Real P-256 provider --
        #[derive(Debug)]
        struct RealP256Provider {
            signing_key: P256SigningKey,
        }

        impl Provider for RealP256Provider {
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
                "test-p256".into()
            }
            fn public_key(&self) -> Vec<u8> {
                let vk = VerifyingKey::from(&self.signing_key);
                vk.to_encoded_point(false).as_bytes().to_vec()
            }
            fn algorithm(&self) -> coset::iana::Algorithm {
                coset::iana::Algorithm::ES256
            }
            fn quote(&self, _: &[u8], _: &[u32]) -> Result<Quote, TpmError> {
                Err(TpmError::NotAvailable)
            }
            fn bind(&self, _: &[u8]) -> Result<Binding, TpmError> {
                Err(TpmError::NotAvailable)
            }
            fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TpmError> {
                // Real ECDSA-SHA256 signature (hash-then-sign, same as SE).
                use p256::ecdsa::signature::{SignatureEncoding, Signer as _};
                let sig: DerSignature = self
                    .signing_key
                    .try_sign(data)
                    .map_err(|e: p256::ecdsa::Error| TpmError::Signing(e.to_string()))?;
                Ok(sig.to_vec())
            }
            fn verify(&self, _: &Binding) -> Result<(), TpmError> {
                Ok(())
            }
            fn seal(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, TpmError> {
                Err(TpmError::NotAvailable)
            }
            fn unseal(&self, _: &[u8]) -> Result<Vec<u8>, TpmError> {
                Err(TpmError::NotAvailable)
            }
            fn clock_info(&self) -> Result<ClockInfo, TpmError> {
                Err(TpmError::NotAvailable)
            }
        }

        // -- Permissive verifiers for test --
        #[derive(Debug)]
        struct AcceptAnyClient;

        impl ClientCertVerifier for AcceptAnyClient {
            fn root_hint_subjects(&self) -> &[DistinguishedName] {
                &[]
            }
            fn verify_client_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _now: UnixTime,
            ) -> std::result::Result<ClientCertVerified, rustls::Error> {
                Ok(ClientCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![SignatureScheme::ECDSA_NISTP256_SHA256]
            }
        }

        #[derive(Debug)]
        struct AcceptAnyServer;

        impl ServerCertVerifier for AcceptAnyServer {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp: &[u8],
                _now: UnixTime,
            ) -> std::result::Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![SignatureScheme::ECDSA_NISTP256_SHA256]
            }
        }

        // -- Generate real keys --
        let client_sk = P256SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let server_sk = P256SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

        // -- Client side: generate cert + resolver --
        let client_provider: Arc<dyn Provider + Send + Sync> =
            Arc::new(RealP256Provider { signing_key: client_sk });
        let client_cert =
            super::super::client_cert::generate_client_cert_for_test(client_provider.as_ref());
        let signing_key = Arc::new(HardwareSigningKey::new(client_provider));
        let resolver = MtlsCertResolver::new(client_cert.clone(), signing_key);

        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
            .with_client_cert_resolver(Arc::new(resolver));

        // -- Server side: generate cert + config --
        let server_secret = p256::SecretKey::from(&server_sk);
        let server_sec1 = server_secret.to_sec1_der().unwrap();
        let server_provider: Arc<dyn Provider + Send + Sync> =
            Arc::new(RealP256Provider { signing_key: server_sk });
        let server_cert =
            super::super::client_cert::generate_client_cert_for_test(server_provider.as_ref());

        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(AcceptAnyClient))
            .with_single_cert(
                vec![server_cert],
                PrivateSec1KeyDer::from(server_sec1.to_vec()).into(),
            )
            .expect("server config");

        // -- Handshake via byte pipe --
        let mut client =
            ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
                .expect("client connection");
        let mut server =
            ServerConnection::new(Arc::new(server_config)).expect("server connection");

        // Pump data between client and server until handshake completes.
        let mut buf = Vec::new();
        for _ in 0..20 {
            // Client -> Server
            buf.clear();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut &buf[..]).unwrap();
                server.process_new_packets().unwrap();
            }

            // Server -> Client
            buf.clear();
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                client.read_tls(&mut &buf[..]).unwrap();
                client.process_new_packets().unwrap();
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }

        assert!(!client.is_handshaking(), "client handshake did not complete");
        assert!(!server.is_handshaking(), "server handshake did not complete");

        // Verify the server received the client cert.
        let peer_certs = server.peer_certificates().expect("server should see client cert");
        assert_eq!(peer_certs.len(), 1);
        assert_eq!(peer_certs[0].as_ref(), client_cert.as_ref());
    }
}
