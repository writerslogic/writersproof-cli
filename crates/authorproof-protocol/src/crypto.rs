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

/// C2PA 2.4 COSE_Sign1: x5chain in protected header, detached payload (§13.2).
///
/// When `cert_der` is `Some`, the DER-encoded X.509 certificate is placed in
/// x5chain (label 33). Otherwise falls back to raw public key bytes.
///
/// The payload is used for signing but is NOT included in the serialized
/// COSE_Sign1 (detached mode). The verifier must supply the claim bytes
/// separately when verifying.
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
    cose_sign1_detached(payload, signer, protected_extra, coset::Header::default())
}

/// Build a COSE_Sign1 with detached payload (payload signed but not serialized).
pub(crate) fn cose_sign1_detached(
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

    let mut sign1 = builder.build();

    if sign1.signature.is_empty() {
        return Err(Error::Crypto(
            "COSE signing produced empty signature".to_string(),
        ));
    }

    // Detach payload per C2PA §13.2 — claim bytes live in the claim box.
    sign1.payload = None;

    sign1
        .to_vec()
        .map_err(|e| Error::Crypto(format!("COSE encoding error: {}", e)))
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

/// Parse a COSE_Sign1, accepting both tagged (Tag 18) and untagged CBOR.
fn parse_cose_sign1(data: &[u8]) -> Result<coset::CoseSign1> {
    use coset::TaggedCborSerializable;
    coset::CoseSign1::from_tagged_slice(data)
        .or_else(|_| coset::CoseSign1::from_slice(data))
        .map_err(|e| Error::Crypto(format!("COSE_Sign1 decode error: {}", e)))
}

/// Verify an Ed25519 signature on an already-parsed COSE_Sign1 structure.
///
/// Returns `Ok(())` on success, `Err` on verification failure.
pub(crate) fn verify_cose_sign1_ed25519(
    sign1: &coset::CoseSign1,
    verifying_key: &VerifyingKey,
) -> Result<()> {
    sign1.verify_signature(&[], |sig, sig_data| {
        let signature = Signature::from_slice(sig)
            .map_err(|e| Error::Crypto(format!("Invalid signature format: {}", e)))?;
        verifying_key
            .verify(sig_data, &signature)
            .map_err(|e| Error::Crypto(format!("Signature verification failed: {}", e)))
    })
}

pub fn verify_evidence_cose(cose_data: &[u8], verifying_key: &VerifyingKey) -> Result<Vec<u8>> {
    if cose_data.len() > MAX_COSE_INPUT_SIZE {
        return Err(Error::Crypto(format!(
            "COSE input too large: {} bytes (max {})",
            cose_data.len(),
            MAX_COSE_INPUT_SIZE
        )));
    }
    let sign1 = parse_cose_sign1(cose_data)?;

    verify_cose_sign1_ed25519(&sign1, verifying_key)?;

    sign1
        .payload
        .ok_or_else(|| Error::Crypto("Missing payload in COSE_Sign1".to_string()))
}

// ---------------------------------------------------------------------------
// Countersignature (nested COSE_Sign1)
// ---------------------------------------------------------------------------

/// COSE label for the countersigner's key ID in the protected header.
const COUNTERSIGN_KID_LABEL: &str = "writersproof-ca";

/// Countersign a signed `.cpop` packet by wrapping it in a second COSE_Sign1.
///
/// The original COSE_Sign1 bytes become the payload of a new COSE_Sign1 signed
/// by the countersigner (typically the WritersProof CA). This avoids the
/// `Sig_structure` mismatch that would occur if transplanting a Sign1 signature
/// into a COSE_Sign container (the "to-be-signed" structures differ).
///
/// Verification: parse the outer COSE_Sign1, verify the CA signature, extract
/// the payload (original `.cpop` bytes), then verify the author's signature.
///
/// Stripping the countersig: extract the outer COSE_Sign1 payload — that's the
/// original `.cpop` file, unmodified.
pub fn countersign_packet(
    cpop_bytes: &[u8],
    countersigner: &dyn EvidenceSigner,
) -> Result<Vec<u8>> {
    if cpop_bytes.len() > MAX_COSE_INPUT_SIZE {
        return Err(Error::Crypto(format!(
            "Input too large for countersigning: {} bytes (max {})",
            cpop_bytes.len(),
            MAX_COSE_INPUT_SIZE
        )));
    }

    // Validate the input is a well-formed COSE_Sign1 before wrapping.
    let _ = parse_cose_sign1(cpop_bytes)?;

    let protected = HeaderBuilder::new()
        .algorithm(countersigner.algorithm())
        .key_id(COUNTERSIGN_KID_LABEL.as_bytes().to_vec())
        .build();

    let mut sign_error: Option<Error> = None;
    let builder = CoseSign1Builder::new()
        .protected(protected)
        .payload(cpop_bytes.to_vec())
        .create_signature(&[], |sig_data| match countersigner.sign(sig_data) {
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
            "Countersigning produced empty signature".to_string(),
        ));
    }

    sign1
        .to_vec()
        .map_err(|e| Error::Crypto(format!("COSE encoding error: {}", e)))
}

/// Verify a countersigned packet: check the CA signature, then extract and
/// verify the inner author signature.
///
/// Returns the decoded inner CBOR payload (the evidence packet bytes) on success.
pub fn verify_countersigned_packet(
    countersigned_bytes: &[u8],
    ca_verifying_key: &VerifyingKey,
    author_verifying_key: &VerifyingKey,
) -> Result<Vec<u8>> {
    if countersigned_bytes.len() > MAX_COSE_INPUT_SIZE * 2 {
        return Err(Error::Crypto("Countersigned packet too large".to_string()));
    }

    // Verify outer (CA) signature and extract inner .cpop bytes.
    let outer = parse_cose_sign1(countersigned_bytes)?;
    verify_cose_sign1_ed25519(&outer, ca_verifying_key)?;
    let inner_bytes = outer
        .payload
        .ok_or_else(|| Error::Crypto("Missing inner payload in countersigned packet".to_string()))?;

    // Verify inner (author) signature and extract evidence payload.
    verify_evidence_cose(&inner_bytes, author_verifying_key)
}

/// Strip the countersignature, returning the original `.cpop` bytes.
///
/// Verifies the outer CA signature before extraction to ensure the
/// countersigned packet hasn't been tampered with. Returns the inner
/// COSE_Sign1 bytes (the original `.cpop` file).
pub fn strip_countersignature(
    countersigned_bytes: &[u8],
    ca_verifying_key: &VerifyingKey,
) -> Result<Vec<u8>> {
    let outer = parse_cose_sign1(countersigned_bytes)?;
    verify_cose_sign1_ed25519(&outer, ca_verifying_key)?;
    outer
        .payload
        .ok_or_else(|| Error::Crypto("Missing inner payload".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn make_signed_cpop(author_key: &SigningKey) -> Vec<u8> {
        let payload = b"fake-evidence-cbor-payload-for-testing";
        sign_evidence_cose(payload, author_key).expect("sign")
    }

    #[test]
    fn countersign_roundtrip() {
        let author_key = test_signing_key(1);
        let ca_key = test_signing_key(2);

        // 1. Sign original .cpop
        let cpop = make_signed_cpop(&author_key);
        assert!(!cpop.is_empty());

        // 2. Countersign with CA key
        let countersigned = countersign_packet(&cpop, &ca_key).expect("countersign");
        assert!(countersigned.len() > cpop.len());

        // 3. Verify both signatures
        let evidence_payload = verify_countersigned_packet(
            &countersigned,
            &ca_key.verifying_key(),
            &author_key.verifying_key(),
        )
        .expect("verify both");
        assert_eq!(evidence_payload, b"fake-evidence-cbor-payload-for-testing");
    }

    #[test]
    fn strip_countersig_recovers_original() {
        let author_key = test_signing_key(3);
        let ca_key = test_signing_key(4);

        let cpop = make_signed_cpop(&author_key);
        let countersigned = countersign_packet(&cpop, &ca_key).expect("countersign");

        // Strip the CA signature
        let recovered = strip_countersignature(&countersigned, &ca_key.verifying_key())
            .expect("strip");

        // Recovered bytes must be identical to original .cpop
        assert_eq!(recovered, cpop);

        // Original still verifies independently
        let payload = verify_evidence_cose(&recovered, &author_key.verifying_key())
            .expect("verify original");
        assert_eq!(payload, b"fake-evidence-cbor-payload-for-testing");
    }

    #[test]
    fn countersign_rejects_tampered_inner() {
        let author_key = test_signing_key(5);
        let ca_key = test_signing_key(6);
        let wrong_author = test_signing_key(7);

        let cpop = make_signed_cpop(&author_key);
        let countersigned = countersign_packet(&cpop, &ca_key).expect("countersign");

        // CA signature valid, but wrong author key → inner verification fails
        let result = verify_countersigned_packet(
            &countersigned,
            &ca_key.verifying_key(),
            &wrong_author.verifying_key(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn countersign_rejects_tampered_outer() {
        let author_key = test_signing_key(8);
        let ca_key = test_signing_key(9);
        let wrong_ca = test_signing_key(10);

        let cpop = make_signed_cpop(&author_key);
        let countersigned = countersign_packet(&cpop, &ca_key).expect("countersign");

        // Wrong CA key → outer verification fails
        let result = verify_countersigned_packet(
            &countersigned,
            &wrong_ca.verifying_key(),
            &author_key.verifying_key(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn countersign_rejects_non_cose_input() {
        let ca_key = test_signing_key(11);
        let result = countersign_packet(b"not-cose-data", &ca_key);
        assert!(result.is_err());
    }

    #[test]
    fn countersign_has_ca_kid_header() {
        let author_key = test_signing_key(12);
        let ca_key = test_signing_key(13);

        let cpop = make_signed_cpop(&author_key);
        let countersigned = countersign_packet(&cpop, &ca_key).expect("countersign");

        let outer = parse_cose_sign1(&countersigned).expect("parse outer");
        let kid = &outer.protected.header.key_id;
        assert_eq!(kid, COUNTERSIGN_KID_LABEL.as_bytes());
    }
}
