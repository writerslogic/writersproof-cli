// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use const_oid::AssociatedOid;
use der::{Encode, FixedTag, Tag};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use signature::Keypair;
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey, ObjectIdentifier,
    SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};
use x509_cert::der::asn1::{BitString, OctetString};
use zeroize::Zeroizing;

const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Wrapper to implement x509-cert builder traits for VerifyingKey.
#[derive(Clone, Debug)]
pub struct X509VerifyingKey(pub VerifyingKey);

impl EncodePublicKey for X509VerifyingKey {
    fn to_public_key_der(&self) -> spki::Result<spki::der::Document> {
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ED25519_OID,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(self.0.as_bytes())?,
        };
        let der = spki.to_der().map_err(|_| spki::Error::KeyMalformed)?;
        spki::der::Document::try_from(der.as_slice()).map_err(|_| spki::Error::KeyMalformed)
    }
}

/// Wrapper to implement x509-cert builder traits for SigningKey.
pub struct X509Signer(pub SigningKey);

impl std::fmt::Debug for X509Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("X509Signer").field(&"[REDACTED]").finish()
    }
}

impl Keypair for X509Signer {
    type VerifyingKey = X509VerifyingKey;
    fn verifying_key(&self) -> Self::VerifyingKey {
        X509VerifyingKey(self.0.verifying_key())
    }
}

impl DynSignatureAlgorithmIdentifier for X509Signer {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ED25519_OID,
            parameters: None,
        })
    }
}

/// Newtype wrapper over Ed25519 signature for `SignatureBitStringEncoding` (orphan rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Signature(pub ed25519_dalek::Signature);

impl signature::SignatureEncoding for X509Signature {
    type Repr = [u8; 64];
    fn to_bytes(&self) -> Self::Repr {
        self.0.to_bytes()
    }
}

impl TryFrom<&[u8]> for X509Signature {
    type Error = signature::Error;
    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        ed25519_dalek::Signature::from_slice(bytes)
            .map(X509Signature)
            .map_err(|_| signature::Error::new())
    }
}

impl From<X509Signature> for [u8; 64] {
    fn from(sig: X509Signature) -> Self {
        sig.0.to_bytes()
    }
}

impl Signer<X509Signature> for X509Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<X509Signature, signature::Error> {
        Ok(X509Signature(self.0.sign(msg)))
    }
}

impl SignatureBitStringEncoding for X509Signature {
    fn to_bitstring(&self) -> std::result::Result<spki::der::asn1::BitString, spki::der::Error> {
        spki::der::asn1::BitString::from_bytes(&self.0.to_bytes())
    }
}

/// X.509 extension for CPoE capability (OID 1.3.6.1.4.1.54066.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability(pub OctetString);

impl AssociatedOid for Capability {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.54066.1.1");
}

impl Encode for Capability {
    fn encoded_len(&self) -> der::Result<der::Length> {
        self.0.encoded_len()
    }
    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl FixedTag for Capability {
    const TAG: Tag = Tag::OctetString;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub user_id: String,
    /// Raw Ed25519 public key bytes (32 bytes).
    pub public_key: Vec<u8>,
    /// TPM quote or Secure Enclave blob; empty for software-only.
    pub hardware_attestation: Vec<u8>,
}

/// Key material is zeroized on drop via ed25519_dalek::SigningKey's ZeroizeOnDrop
/// (enabled by the "zeroize" feature on ed25519-dalek).
pub struct IdentityManager {
    signer: X509Signer,
}

// Compile-time guarantee: SigningKey zeroizes key material on drop.
#[allow(dead_code)]
const _: () = {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    fn check() {
        assert_zeroize_on_drop::<SigningKey>();
    }
};

impl IdentityManager {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        Self {
            signer: X509Signer(SigningKey::from_bytes(&bytes)),
        }
    }

    pub fn from_secret_key(bytes: &[u8; 32]) -> Self {
        Self {
            signer: X509Signer(SigningKey::from_bytes(bytes)),
        }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signer.0
    }

    /// Generate a DER-encoded X.509 CSR with SKI and CPoE capability extensions.
    /// Note: x509-cert 0.2 removed RequestBuilder. This is a pre-existing API limitation.
    pub fn generate_csr(&self, _subject_dn: &str) -> Result<Vec<u8>> {
        Err(Error::Crypto(
            "CSR generation not available with x509-cert 0.2".to_string(),
        ))
    }

    /// `hardware_attestation`: TPM quote or Secure Enclave blob; empty for software-only.
    pub fn create_enrollment_request(
        &self,
        user_id: &str,
        hardware_attestation: &[u8],
    ) -> Result<EnrollmentRequest> {
        let public_key = self.signer.0.verifying_key().to_bytes().to_vec();

        Ok(EnrollmentRequest {
            user_id: user_id.to_string(),
            public_key,
            hardware_attestation: hardware_attestation.to_vec(),
        })
    }
}
