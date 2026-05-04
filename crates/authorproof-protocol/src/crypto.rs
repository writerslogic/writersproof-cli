// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use crate::rfc::{HashAlgorithm, HashValue};
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Compute a SHA-256 hash and return it as a `HashValue`.
pub fn hash_sha256(data: &[u8]) -> HashValue {
    let mut hasher = Sha256::new();
    hasher.update(data);
    HashValue {
        algorithm: HashAlgorithm::Sha256,
        digest: hasher.finalize().to_vec(),
    }
}

/// Length-prefixes fields to prevent concatenation ambiguity.
fn hmac_update_field(mac: &mut HmacSha256, data: &[u8]) -> Result<()> {
    if data.len() > u32::MAX as usize {
        return Err(Error::Crypto("field too large for length prefix".into()));
    }
    mac.update(&(data.len() as u32).to_be_bytes());
    mac.update(data);
    Ok(())
}

/// Inputs are length-prefixed and domain-separated to prevent concatenation ambiguity.
pub fn compute_causality_lock(
    key: &[u8],
    prev_hash: &[u8],
    current_hash: &[u8],
) -> Result<HashValue> {
    compute_causality_lock_inner(key, b"causality_v1", prev_hash, current_hash, &[])
}

/// Binds physical entropy (jitter) to the content chain.
/// Inputs are length-prefixed and domain-separated.
pub fn compute_causality_lock_v2(
    key: &[u8],
    prev_hash: &[u8],
    current_hash: &[u8],
    phys_entropy: &[u8],
) -> Result<HashValue> {
    compute_causality_lock_inner(key, b"causality_v2", prev_hash, current_hash, phys_entropy)
}

fn compute_causality_lock_inner(
    key: &[u8],
    dst: &[u8],
    prev_hash: &[u8],
    current_hash: &[u8],
    phys_entropy: &[u8],
) -> Result<HashValue> {
    // Derive a 32-byte HMAC key via SHA-256 to meet the minimum recommended
    // key length for HMAC-SHA256, even when packet_id is only 16 bytes.
    let derived_key: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(key).into());
    let mut mac = HmacSha256::new_from_slice(derived_key.as_ref())
        .map_err(|e| Error::Crypto(format!("HMAC key error: {}", e)))?;

    hmac_update_field(&mut mac, dst)?;
    hmac_update_field(&mut mac, prev_hash)?;
    hmac_update_field(&mut mac, current_hash)?;
    // Always include phys_entropy (even if empty) so v2 domain structure
    // is unambiguous. The length-prefix differentiates empty from absent.
    hmac_update_field(&mut mac, phys_entropy)?;

    Ok(HashValue {
        algorithm: HashAlgorithm::Sha256,
        digest: mac.finalize().into_bytes().to_vec(),
    })
}

pub trait EvidenceSigner {
    /// Sign `data` and return the raw signature bytes.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    /// Return the COSE algorithm identifier for this signer (e.g., EdDSA).
    fn algorithm(&self) -> coset::iana::Algorithm;
    /// Return the public key bytes corresponding to this signer.
    fn public_key(&self) -> Vec<u8>;
}

impl EvidenceSigner for SigningKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(ed25519_dalek::Signer::sign(self, data).to_bytes().to_vec())
    }

    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::EdDSA
    }

    fn public_key(&self) -> Vec<u8> {
        self.verifying_key().to_bytes().to_vec()
    }
}

pub fn sign_evidence_cose(payload: &[u8], signer: &dyn EvidenceSigner) -> Result<Vec<u8>> {
    cose_sign1(payload, signer, coset::Header::default(), coset::Header::default())
}

/// C2PA 2.4 COSE_Sign1: x5chain in protected header per spec requirement.
///
/// When `cert_der` is `Some`, the DER-encoded X.509 certificate is placed in
/// x5chain (label 33). Otherwise falls back to raw public key bytes.
pub(crate) fn cose_sign1_c2pa(
    payload: &[u8],
    signer: &dyn EvidenceSigner,
    cert_der: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let x5chain_bytes = cert_der
        .map(|d| d.to_vec())
        .unwrap_or_else(|| signer.public_key());
    let mut protected_extra = coset::Header::default();
    protected_extra.rest.push((
        coset::Label::Int(33), // x5chain, RFC 9360
        ciborium::Value::Bytes(x5chain_bytes),
    ));
    cose_sign1(payload, signer, protected_extra, coset::Header::default())
}

pub(crate) fn cose_sign1(
    payload: &[u8],
    signer: &dyn EvidenceSigner,
    protected_extra: coset::Header,
    unprotected: coset::Header,
) -> Result<Vec<u8>> {
    let mut protected = HeaderBuilder::new().algorithm(signer.algorithm()).build();
    protected.rest.extend(protected_extra.rest);

    let mut builder = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload.to_vec());

    let mut sign_error: Option<Error> = None;
    builder = builder.create_signature(&[], |sig_data| match signer.sign(sig_data) {
        Ok(sig) => sig,
        Err(e) => {
            sign_error = Some(e);
            Vec::new()
        }
    });

    if let Some(e) = sign_error {
        return Err(e);
    }

    let sign1 = builder.build();

    if sign1.signature.is_empty() {
        return Err(Error::Crypto(
            "COSE signing produced empty signature".to_string(),
        ));
    }

    sign1
        .to_vec()
        .map_err(|e| Error::Crypto(format!("COSE encoding error: {}", e)))
}

/// Maximum COSE_Sign1 input size (1 MiB) to prevent OOM on oversized payloads.
const MAX_COSE_INPUT_SIZE: usize = 1024 * 1024;

pub fn verify_evidence_cose(cose_data: &[u8], verifying_key: &VerifyingKey) -> Result<Vec<u8>> {
    if cose_data.len() > MAX_COSE_INPUT_SIZE {
        return Err(Error::Crypto(format!(
            "COSE input too large: {} bytes (max {})",
            cose_data.len(),
            MAX_COSE_INPUT_SIZE
        )));
    }
    let sign1 = coset::CoseSign1::from_slice(cose_data)
        .map_err(|e| Error::Crypto(format!("COSE decoding error: {}", e)))?;

    sign1.verify_signature(&[], |sig, sig_data| {
        let signature = Signature::from_slice(sig)
            .map_err(|e| Error::Crypto(format!("Invalid signature format: {}", e)))?;
        verifying_key
            .verify(sig_data, &signature)
            .map_err(|e| Error::Crypto(format!("Signature verification failed: {}", e)))
    })?;

    sign1
        .payload
        .ok_or_else(|| Error::Crypto("Missing payload in COSE_Sign1".to_string()))
}
