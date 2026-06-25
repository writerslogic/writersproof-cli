// SPDX-License-Identifier: Apache-2.0

//! Attest and verify a C2PA manifest embedded directly in unstructured text.
//!
//! This composes the existing manifest builder ([`C2paManifestBuilder`]), the
//! JUMBF codec, and the C2PA "Embedding Manifests into Unstructured Text"
//! variation-selector carrier ([`super::text_embed`]) into a complete
//! attest -> verify flow. The result is plain text with an invisible,
//! self-verifying provenance manifest appended — portable across copy/paste and
//! verifiable by any C2PA-text-aware tool.
//!
//! Unlike AI-provenance watermarking, the embedded manifest carries the
//! human proof-of-process assertions produced by [`C2paManifestBuilder`]
//! (process-proof, evidence-chain, keystroke-cadence, embedded VC).
//!
//! ## Soft binding (`c2pa.hash.data`)
//!
//! The manifest's hard binding hashes the document with the appended wrapper
//! bytes excluded (zeroed), per [`super::embed::hash_with_exclusions`]. Because
//! the excluded region is zeroed rather than removed, the content hash depends
//! only on the original text and the wrapper length — not on the wrapper bytes
//! themselves. The wrapper length feeds back into the manifest size (the
//! exclusion `length` field), so [`attest_text`] resolves it to a fixpoint
//! before computing the final hash, mirroring [`super::embed::embed_manifest_in_pdf`].

use subtle::ConstantTimeEq;

use crate::crypto::EvidenceSigner;
use crate::error::{Error, Result};

use super::builder::C2paManifestBuilder;
use super::embed::hash_with_exclusions;
use super::jumbf::decode_jumbf;
use super::text_embed::{decode_text_manifest, encode_text_manifest};
use super::types::{C2paManifest, ExclusionRange, HashDataAssertion, HashExclusion};
use super::validation::{validate_manifest, verify_manifest_signature};
use super::ASSERTION_LABEL_HASH_DATA;

/// Maximum fixpoint iterations for resolving the exclusion length.
/// Converges in 2-3 iterations in practice; the cap is a safety backstop.
const MAX_FIXPOINT_ITERS: usize = 6;

/// Outcome of verifying a text-embedded C2PA manifest.
#[derive(Debug, Clone)]
pub struct TextVerification {
    /// The COSE_Sign1 claim signature verified against its embedded key.
    pub signature_valid: bool,
    /// The recomputed content hash matches the manifest's `c2pa.hash.data` binding.
    pub content_hash_valid: bool,
    /// Structural validation errors (excluding the signature, reported separately).
    pub structural_errors: Vec<String>,
}

impl TextVerification {
    /// True iff signature, content binding, and structure all check out.
    pub fn is_valid(&self) -> bool {
        self.signature_valid && self.content_hash_valid && self.structural_errors.is_empty()
    }
}

/// Embed a C2PA manifest invisibly into `text`, returning the watermarked text.
///
/// The `builder` supplies the manifest assertions (forensic signals, evidence
/// chain, embedded VC, etc.); this function sets the text format, resolves the
/// soft-binding exclusion to a fixpoint, computes the content hash, and appends
/// the variation-selector wrapper.
///
/// The original text is preserved verbatim as a prefix; the wrapper is appended
/// and consists solely of non-rendering characters (ZWNBSP + variation selectors).
pub fn attest_text(
    text: &str,
    builder: C2paManifestBuilder,
    signer: &dyn EvidenceSigner,
) -> Result<String> {
    let orig_len = text.len() as u64;
    let placeholder_hash = [0u8; 32];
    // Stamp one creation timestamp so every fixpoint rebuild is byte-identical;
    // a fresh per-build `Utc::now()` could vary the manifest length and trip the
    // stability check below. A caller-supplied `created_at` takes precedence.
    let builder = builder
        .format("text/plain")
        .created_at_if_unset(chrono::Utc::now().to_rfc3339());

    // Fixpoint: the exclusion `length` field changes the manifest size, which
    // changes the wrapper length (e_target). Iterate until e_target is stable.
    let mut excl_len: u64 = 0;
    let mut e_target: usize = 0;
    let mut converged = false;
    for _ in 0..MAX_FIXPOINT_ITERS {
        let jumbf = builder
            .clone()
            .document_hash(placeholder_hash)
            .exclusions(vec![ExclusionRange {
                start: orig_len,
                length: excl_len,
            }])
            .build_jumbf(signer)?;
        let (_wrapper, target) = encode_text_manifest(&jumbf);
        if target as u64 == excl_len {
            e_target = target;
            converged = true;
            break;
        }
        excl_len = target as u64;
        e_target = target;
    }
    if !converged {
        return Err(Error::Protocol(
            "attest_text: exclusion length did not converge".to_string(),
        ));
    }

    // The content hash is over (original text ++ wrapper) with the wrapper
    // region zeroed. Since it is zeroed, the actual wrapper bytes are
    // irrelevant — only orig_len and e_target matter — so a synthetic
    // zero-filled region yields the identical hash the verifier recomputes.
    let mut hash_input = Vec::with_capacity(text.len() + e_target);
    hash_input.extend_from_slice(text.as_bytes());
    hash_input.resize(text.len() + e_target, 0u8);
    let content_hash = hash_with_exclusions(
        &hash_input,
        &[HashExclusion {
            start: text.len(),
            length: e_target,
        }],
    );

    // Final manifest: real hash + the stabilized exclusion. The 32-byte hash
    // has the same CBOR width as the placeholder, so the JUMBF size — and thus
    // the wrapper length — is unchanged. Assert that invariant.
    let final_jumbf = builder
        .document_hash(content_hash)
        .exclusions(vec![ExclusionRange {
            start: orig_len,
            length: excl_len,
        }])
        .build_jumbf(signer)?;
    let (wrapper, final_target) = encode_text_manifest(&final_jumbf);
    if final_target != e_target {
        return Err(Error::Protocol(format!(
            "attest_text: wrapper length unstable ({e_target} vs {final_target})"
        )));
    }

    Ok(format!("{text}{wrapper}"))
}

/// Verify a text-embedded C2PA manifest.
///
/// Decodes the wrapper, parses the manifest, verifies the COSE_Sign1 signature
/// and the manifest's internal assertion-box hashes, and recomputes the
/// `c2pa.hash.data` content binding over the supplied text (with the stored
/// exclusion zeroed). Returns a [`TextVerification`]; callers should check
/// [`TextVerification::is_valid`].
pub fn verify_text(watermarked: &str) -> Result<TextVerification> {
    let jumbf = decode_text_manifest(watermarked)
        .map_err(|e| Error::Validation(format!("text manifest decode: {e}")))?;
    let manifest = decode_jumbf(&jumbf)?;

    let signature_valid = verify_manifest_signature(&manifest).unwrap_or(false);

    // Structural validation (assertion-box hashes, required assertions, etc.).
    // The COSE signature result is surfaced separately via `signature_valid`,
    // so drop its line from the structural error list to avoid double-counting.
    let structural_errors: Vec<String> = validate_manifest(&manifest)
        .errors
        .into_iter()
        .filter(|e| !e.contains("COSE_Sign1"))
        .collect();

    let content_hash_valid = match extract_hash_data(&manifest) {
        Some(hd) if hd.algorithm == "sha256" => {
            let exclusions: Vec<HashExclusion> = hd
                .exclusions
                .iter()
                .map(|e| HashExclusion {
                    start: e.start as usize,
                    length: e.length as usize,
                })
                .collect();
            let computed = hash_with_exclusions(watermarked.as_bytes(), &exclusions);
            computed.as_slice().ct_eq(hd.hash.as_slice()).unwrap_u8() == 1
        }
        _ => false,
    };

    Ok(TextVerification {
        signature_valid,
        content_hash_valid,
        structural_errors,
    })
}

/// Extract the `c2pa.hash.data` assertion from a manifest's assertion boxes.
fn extract_hash_data(manifest: &C2paManifest) -> Option<HashDataAssertion> {
    for box_bytes in &manifest.assertion_boxes {
        if let Some((label, cbor)) = parse_assertion_box(box_bytes) {
            if label == ASSERTION_LABEL_HASH_DATA {
                return ciborium::from_reader(cbor).ok();
            }
        }
    }
    None
}

/// Walk an assertion JUMBF superbox, returning its `(label, cbor_content)`.
///
/// The box layout (from `build_assertion_jumbf_cbor`) is a `jumb` superbox
/// containing a `jumd` description (UUID + NUL-terminated label) followed by a
/// `cbor` content box.
fn parse_assertion_box(box_bytes: &[u8]) -> Option<(String, &[u8])> {
    if box_bytes.len() < 8 || &box_bytes[4..8] != b"jumb" {
        return None;
    }
    let mut off = 8;
    let mut label: Option<String> = None;
    let mut cbor: Option<&[u8]> = None;
    while off + 8 <= box_bytes.len() {
        let len = u32::from_be_bytes([
            box_bytes[off],
            box_bytes[off + 1],
            box_bytes[off + 2],
            box_bytes[off + 3],
        ]) as usize;
        if len < 8 || off + len > box_bytes.len() {
            break;
        }
        let btype = &box_bytes[off + 4..off + 8];
        let body = &box_bytes[off + 8..off + len];
        if btype == b"jumd" && body.len() > 17 {
            // 16-byte UUID + 1 toggle byte, then NUL-terminated label.
            let label_bytes = &body[17..];
            let end = label_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(label_bytes.len());
            label = String::from_utf8(label_bytes[..end].to_vec()).ok();
        } else if btype == b"cbor" {
            cbor = Some(body);
        }
        off += len;
    }
    match (label, cbor) {
        (Some(l), Some(c)) => Some((l, c)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa::builder::C2paManifestBuilder;
    use crate::rfc::{Checkpoint, DocumentRef, EvidencePacket, HashAlgorithm, HashValue};
    use ed25519_dalek::SigningKey;

    fn test_packet() -> EvidencePacket {
        EvidencePacket {
            version: 1,
            profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
            packet_id: vec![0xAA; 16],
            created: 1710000000000,
            document: DocumentRef {
                content_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: vec![0xAB; 32],
                },
                filename: Some("essay.txt".to_string()),
                byte_length: 1024,
                char_count: 512,
            },
            checkpoints: vec![Checkpoint {
                sequence: 0,
                checkpoint_id: vec![0u8; 16],
                timestamp: 1710000001000,
                content_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: vec![0x01u8; 32],
                },
                char_count: 100,
                prev_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: vec![0u8; 32],
                },
                checkpoint_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: vec![0x11u8; 32],
                },
                jitter_hash: None,
            }],
            attestation_tier: None,
            baseline_verification: None,
        }
    }

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn builder() -> C2paManifestBuilder {
        C2paManifestBuilder::new(test_packet(), b"evidence-cbor".to_vec(), [0u8; 32])
            .document_filename("essay.txt")
    }

    #[test]
    fn roundtrip_attest_then_verify() {
        let key = signer();
        let text = "This essay was written by a human, keystroke by keystroke.";
        let watermarked = attest_text(text, builder(), &key).expect("attest");

        // The original text is preserved verbatim as a prefix.
        assert!(watermarked.starts_with(text));
        // A non-empty wrapper was appended.
        assert!(watermarked.len() > text.len(), "wrapper must be appended");

        let v = verify_text(&watermarked).expect("verify");
        assert!(v.signature_valid, "signature must verify");
        assert!(v.content_hash_valid, "content binding must verify");
        assert!(
            v.structural_errors.is_empty(),
            "no structural errors: {:?}",
            v.structural_errors
        );
        assert!(v.is_valid());
    }

    #[test]
    fn tamper_visible_text_fails_content_binding() {
        let key = signer();
        let text = "The quick brown fox jumps over the lazy dog.";
        let watermarked = attest_text(text, builder(), &key).expect("attest");

        // Mutate one visible character in place (same byte length, so the
        // wrapper offset is unchanged) — the content hash must no longer match.
        let tampered = watermarked.replacen("quick", "slick", 1);
        assert_ne!(tampered, watermarked);

        let v = verify_text(&tampered).expect("verify");
        assert!(
            v.signature_valid,
            "signature still valid (manifest untouched)"
        );
        assert!(
            !v.content_hash_valid,
            "tampered text must break the content binding"
        );
        assert!(!v.is_valid());
    }

    #[test]
    fn wrapper_roundtrips_to_exact_jumbf() {
        let key = signer();
        let text = "short";
        let watermarked = attest_text(text, builder(), &key).expect("attest");

        let jumbf = decode_text_manifest(&watermarked).expect("decode wrapper");
        // The decoded JUMBF parses back into a manifest with a hash.data binding.
        let manifest = decode_jumbf(&jumbf).expect("decode jumbf");
        let hd = extract_hash_data(&manifest).expect("hash.data assertion present");
        assert_eq!(hd.algorithm, "sha256");
        // The stored exclusion length equals the appended wrapper's byte length.
        let wrapper_bytes = watermarked.len() - text.len();
        assert_eq!(hd.exclusions.len(), 1);
        assert_eq!(hd.exclusions[0].start, text.len() as u64);
        assert_eq!(hd.exclusions[0].length, wrapper_bytes as u64);
    }

    #[test]
    fn fixpoint_stable_across_manifest_sizes() {
        let key = signer();
        // Vary the manifest size via differently-sized text and a larger
        // assertion set, and confirm attest+verify converges and validates
        // for each — exercising the exclusion-length fixpoint at several sizes.
        let texts = [
            "x",
            "A medium-length paragraph of prose that a person typed out.",
            &"word ".repeat(400), // ~2KB of text
        ];
        for t in texts {
            let watermarked = attest_text(t, builder(), &key).expect("attest");
            let wrapper_bytes = watermarked.len() - t.len();
            // Re-derive: the stored exclusion length must equal the real wrapper length.
            let jumbf = decode_text_manifest(&watermarked).expect("decode");
            let manifest = decode_jumbf(&jumbf).expect("jumbf");
            let hd = extract_hash_data(&manifest).expect("hash.data");
            assert_eq!(
                hd.exclusions[0].length,
                wrapper_bytes as u64,
                "exclusion length must match wrapper for text len {}",
                t.len()
            );
            let v = verify_text(&watermarked).expect("verify");
            assert!(v.is_valid(), "must verify for text len {}", t.len());
        }
    }

    #[test]
    fn deterministic_with_fixed_timestamp() {
        let key = signer();
        let text = "Determinism requires a fixed creation timestamp.";
        let ts = "2024-06-01T12:00:00+00:00".to_string();
        let a = attest_text(text, builder().created_at(ts.clone()), &key).expect("attest a");
        let b = attest_text(text, builder().created_at(ts), &key).expect("attest b");
        assert_eq!(
            a, b,
            "same input + fixed timestamp must yield an identical watermark"
        );
        assert!(verify_text(&a).expect("verify").is_valid());
    }

    #[test]
    fn wrapper_conforms_to_c2pa_text_spec() {
        // Locks our output to the C2PA "Embedding Manifests into Unstructured
        // Text" carrier format. Full third-party interop (e.g. another vendor's
        // C2PA-text verifier) requires an external tool; this asserts the
        // on-the-wire format such a verifier consumes.
        let key = signer();
        let text = "conformance check";
        let watermarked = attest_text(text, builder(), &key).expect("attest");
        let wrapper = &watermarked[text.len()..];

        let mut chars = wrapper.chars();
        assert_eq!(
            chars.next(),
            Some('\u{FEFF}'),
            "wrapper must start with ZWNBSP"
        );
        for c in chars {
            let cp = c as u32;
            assert!(
                (0xFE00..=0xFE0F).contains(&cp) || (0xE0100..=0xE01EF).contains(&cp),
                "wrapper must contain only variation selectors; found U+{cp:04X}"
            );
        }

        // The first 9 decoded bytes are the wrapper header: magic + version.
        let header: Vec<u8> = wrapper
            .chars()
            .skip(1)
            .take(9)
            .map(|c| {
                let cp = c as u32;
                if (0xFE00..=0xFE0F).contains(&cp) {
                    (cp - 0xFE00) as u8
                } else {
                    (cp - 0xE0100) as u8 + 16
                }
            })
            .collect();
        assert_eq!(&header[..8], b"C2PATXT\0", "magic bytes");
        assert_eq!(header[8], 1, "wrapper version");

        // Decodes to a manifest with a claim generator and a hash.data binding.
        let jumbf = decode_text_manifest(&watermarked).expect("decode wrapper");
        let manifest = decode_jumbf(&jumbf).expect("decode jumbf");
        assert!(
            !manifest.claim.claim_generator_info.name.is_empty(),
            "claim generator present"
        );
        assert!(
            extract_hash_data(&manifest).is_some(),
            "hash.data assertion present"
        );
    }
}
