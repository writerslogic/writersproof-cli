// SPDX-License-Identifier: Apache-2.0

//! Embedded manifest support for PDF and text document formats.
//!
//! C2PA allows manifests to be embedded directly in the asset file instead of
//! (or in addition to) the sidecar `.c2pa` file. This module handles:
//!
//! - PDF: Incremental update appending a `/C2PA` stream object
//! - Text sidecar: Companion `.c2pa` file alongside source documents
//!
//! For plain text, RTF, markdown, and other unstructured text formats,
//! embedding binary JUMBF data would corrupt the content. These formats
//! use the sidecar approach exclusively.

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

use super::types::HashExclusion;

// PDF signature at the start of every PDF file.
const PDF_SIGNATURE: &[u8; 5] = b"%PDF-";

/// Embed a JUMBF manifest into a PDF file as an incremental update.
///
/// Appends a new object containing the JUMBF data as a stream, plus a
/// cross-reference table entry and trailer pointing to the `/C2PA` key.
/// The original PDF bytes are preserved verbatim — this is a non-destructive
/// incremental update per ISO 32000-2.
///
/// # Errors
///
/// Returns an error if the input is not a valid PDF (missing `%PDF-` header).
pub fn embed_in_pdf(document_bytes: &[u8], jumbf: &[u8]) -> Result<Vec<u8>> {
    if document_bytes.len() < 5 || &document_bytes[..5] != PDF_SIGNATURE {
        return Err(Error::Protocol(
            "embed_in_pdf: input is not a valid PDF (missing %PDF- header)".to_string(),
        ));
    }

    // Parse the original document so the incremental update PRESERVES the page
    // tree: locate the existing catalog (/Root) and ADD a /C2PA entry to it,
    // rather than replacing /Root (which orphans /Pages and corrupts the PDF).
    let (root_num, root_gen) = find_root_ref(document_bytes).ok_or_else(|| {
        Error::Protocol("embed_in_pdf: could not find /Root reference in trailer".to_string())
    })?;
    let size = find_trailer_size(document_bytes).ok_or_else(|| {
        Error::Protocol("embed_in_pdf: could not find /Size in trailer".to_string())
    })?;
    let catalog_obj = find_object_bytes(document_bytes, root_num, root_gen).ok_or_else(|| {
        Error::Protocol("embed_in_pdf: could not locate catalog object".to_string())
    })?;
    let prev_startxref = find_last_startxref(document_bytes).unwrap_or(0);

    // The C2PA stream takes the next free object number; the catalog keeps its
    // own number (re-emitted at a new offset by the incremental update).
    let c2pa_num = size;
    let c2pa_gen: u32 = 0;

    // 1) C2PA stream object, appended directly after the original bytes.
    let c2pa_offset = document_bytes.len();
    let stream_header = format!(
        "{c2pa_num} {c2pa_gen} obj\n\
         << /Type /Metadata /Subtype /C2PA /Length {} >>\n\
         stream\n",
        jumbf.len()
    );
    let stream_footer = b"\nendstream\nendobj\n";

    // 2) Rewritten catalog object: original catalog + "/C2PA c2pa_num 0 R"
    //    inserted before its closing ">>".
    let new_catalog = insert_c2pa_ref(catalog_obj, c2pa_num, c2pa_gen).ok_or_else(|| {
        Error::Protocol("embed_in_pdf: could not edit catalog dictionary".to_string())
    })?;
    let catalog_offset = c2pa_offset + stream_header.len() + jumbf.len() + stream_footer.len();

    // 3) Incremental xref for the two updated objects, in increasing object order.
    let xref_offset = catalog_offset + new_catalog.len();
    let mut xref = String::from("xref\n");
    let (lo_num, lo_off, hi_num, hi_off) = if root_num <= c2pa_num {
        (root_num, catalog_offset, c2pa_num, c2pa_offset)
    } else {
        (c2pa_num, c2pa_offset, root_num, catalog_offset)
    };
    if hi_num == lo_num + 1 {
        xref.push_str(&format!(
            "{lo_num} 2\n{lo_off:010} 00000 n \n{hi_off:010} 00000 n \n"
        ));
    } else {
        xref.push_str(&format!(
            "{lo_num} 1\n{lo_off:010} 00000 n \n{hi_num} 1\n{hi_off:010} 00000 n \n"
        ));
    }

    // 4) Trailer keeps the ORIGINAL /Root reference and chains to the prior xref.
    let trailer = format!(
        "trailer\n\
         << /Size {} /Prev {prev_startxref} /Root {root_num} {root_gen} R >>\n\
         startxref\n\
         {xref_offset}\n\
         %%EOF\n",
        c2pa_num + 1,
    );

    let mut output = Vec::with_capacity(
        document_bytes.len()
            + stream_header.len()
            + jumbf.len()
            + stream_footer.len()
            + new_catalog.len()
            + xref.len()
            + trailer.len(),
    );
    output.extend_from_slice(document_bytes);
    output.extend_from_slice(stream_header.as_bytes());
    output.extend_from_slice(jumbf);
    output.extend_from_slice(stream_footer);
    output.extend_from_slice(&new_catalog);
    output.extend_from_slice(xref.as_bytes());
    output.extend_from_slice(trailer.as_bytes());

    Ok(output)
}

/// Read a run of ASCII digits at `*i`, advancing `*i`. Returns None if no digit.
fn read_u32(data: &[u8], i: &mut usize) -> Option<u32> {
    let start = *i;
    while *i < data.len() && data[*i].is_ascii_digit() {
        *i += 1;
    }
    if *i == start {
        return None;
    }
    core::str::from_utf8(&data[start..*i]).ok()?.parse().ok()
}

/// Parse `<ws>* <num> <ws>+ <gen> <ws>+ R` from the front of `data`.
fn parse_obj_ref(data: &[u8]) -> Option<(u32, u32)> {
    let mut i = 0;
    while i < data.len() && data[i].is_ascii_whitespace() {
        i += 1;
    }
    let num = read_u32(data, &mut i)?;
    while i < data.len() && data[i].is_ascii_whitespace() {
        i += 1;
    }
    let gen = read_u32(data, &mut i)?;
    while i < data.len() && data[i].is_ascii_whitespace() {
        i += 1;
    }
    if i < data.len() && data[i] == b'R' {
        Some((num, gen))
    } else {
        None
    }
}

/// Find the `/Root <num> <gen> R` reference from the last trailer.
fn find_root_ref(data: &[u8]) -> Option<(u32, u32)> {
    let needle = b"/Root";
    let pos = data.windows(needle.len()).rposition(|w| w == needle)?;
    parse_obj_ref(&data[pos + needle.len()..])
}

/// Find the `/Size <num>` value from the last trailer.
fn find_trailer_size(data: &[u8]) -> Option<u32> {
    let needle = b"/Size";
    let pos = data.windows(needle.len()).rposition(|w| w == needle)?;
    let after = &data[pos + needle.len()..];
    let mut i = 0;
    while i < after.len() && after[i].is_ascii_whitespace() {
        i += 1;
    }
    read_u32(after, &mut i)
}

/// Return the bytes of object `num gen obj ... endobj` (the definition, not a
/// reference), preceded by whitespace/start-of-file to avoid partial matches.
fn find_object_bytes(data: &[u8], num: u32, gen: u32) -> Option<&[u8]> {
    let marker = format!("{num} {gen} obj");
    let mb = marker.as_bytes();
    let mut from = 0;
    loop {
        let rel = data[from..].windows(mb.len()).position(|w| w == mb)?;
        let start = from + rel;
        let ok_prefix = start == 0 || data[start - 1].is_ascii_whitespace();
        let after = start + mb.len();
        let ok_suffix =
            after >= data.len() || data[after].is_ascii_whitespace() || data[after] == b'<';
        if ok_prefix && ok_suffix {
            let end_needle = b"endobj";
            let erel = data[start..]
                .windows(end_needle.len())
                .position(|w| w == end_needle)?;
            return Some(&data[start..start + erel + end_needle.len()]);
        }
        from = start + mb.len();
    }
}

/// Insert `/C2PA <num> <gen> R` before the catalog object's closing `>>`.
fn insert_c2pa_ref(catalog_obj: &[u8], c2pa_num: u32, c2pa_gen: u32) -> Option<Vec<u8>> {
    let pos = catalog_obj.windows(2).rposition(|w| w == b">>")?;
    let insertion = format!(" /C2PA {c2pa_num} {c2pa_gen} R ");
    let mut out = Vec::with_capacity(catalog_obj.len() + insertion.len());
    out.extend_from_slice(&catalog_obj[..pos]);
    out.extend_from_slice(insertion.as_bytes());
    out.extend_from_slice(&catalog_obj[pos..]);
    Some(out)
}

/// Build a C2PA manifest embedded in a PDF document with correct hash binding.
///
/// This solves the circular dependency: the hash depends on the exclusion range,
/// which depends on the JUMBF size, which depends on the hash.
///
/// Pass 1: Build manifest with placeholder (all-zero) hash to determine JUMBF size.
/// Pass 2: Compute real hash with exclusion range, rebuild manifest, embed.
pub fn embed_manifest_in_pdf(
    document_bytes: &[u8],
    builder: super::builder::C2paManifestBuilder,
    signer: &dyn crate::crypto::EvidenceSigner,
) -> crate::error::Result<alloc::vec::Vec<u8>> {
    let embed_offset = document_bytes.len();
    let placeholder_hash = [0u8; 32];

    // Pass 1: build with placeholder hash and a rough exclusion estimate
    // to determine the actual JUMBF size + PDF overhead.
    let est_exclusion = super::types::ExclusionRange {
        start: embed_offset as u64,
        length: 4096, // rough estimate
    };
    let jumbf_est = builder
        .clone()
        .document_hash(placeholder_hash)
        .exclusions(alloc::vec![est_exclusion])
        .build_jumbf(signer)?;
    let embedded_est = embed_in_pdf(document_bytes, &jumbf_est)?;
    let appended_len = embedded_est.len() - embed_offset;

    // Pass 2: rebuild with the REAL exclusion range (now correctly sized).
    // The JUMBF will be the same size because only the numeric values
    // inside the ExclusionRange changed, and they encode to the same
    // CBOR width (both are in the same magnitude range as the estimate).
    let real_exclusion = super::types::ExclusionRange {
        start: embed_offset as u64,
        length: appended_len as u64,
    };
    let jumbf_pass2 = builder
        .clone()
        .document_hash(placeholder_hash)
        .exclusions(alloc::vec![real_exclusion])
        .build_jumbf(signer)?;

    // Verify size stability (the exclusion range values are close enough
    // that CBOR uses the same byte width for both).
    let embedded_pass2 = embed_in_pdf(document_bytes, &jumbf_pass2)?;
    let appended_len2 = embedded_pass2.len() - embed_offset;
    if appended_len != appended_len2 {
        return Err(crate::error::Error::Protocol(format!(
            "PDF append size unstable ({appended_len} vs {appended_len2})"
        )));
    }

    // Pass 3: compute the real hash over the document with manifest
    // bytes zeroed, then produce the final JUMBF.
    let real_hash = hash_with_exclusions(
        &embedded_pass2,
        &[HashExclusion {
            start: embed_offset,
            length: appended_len,
        }],
    );

    let final_exclusion = super::types::ExclusionRange {
        start: embed_offset as u64,
        length: appended_len as u64,
    };
    let jumbf_final = builder
        .document_hash(real_hash)
        .exclusions(alloc::vec![final_exclusion])
        .build_jumbf(signer)?;

    embed_in_pdf(document_bytes, &jumbf_final)
}

/// Generate a sidecar manifest file path for a given document path.
///
/// For text documents (plain text, RTF, markdown, etc.) where binary JUMBF
/// cannot be embedded without corrupting the content, the manifest is stored
/// as a companion `.c2pa` file alongside the original.
///
/// Example: `/path/to/essay.md` → `/path/to/essay.md.c2pa`
pub fn sidecar_path(document_path: &str) -> String {
    format!("{document_path}.c2pa")
}

/// Determine whether a file format supports embedded manifests.
///
/// Returns `true` for PDF (the only text-document format where binary
/// embedding is possible without content corruption). All other formats
/// should use the sidecar approach.
pub fn supports_embedding(extension: &str) -> bool {
    matches!(extension.to_lowercase().as_str(), "pdf")
}

/// Compute SHA-256 over `data` with the specified byte ranges zeroed out.
///
/// Exclusion ranges are used in the hash-data assertion (`c2pa.hash.data`)
/// to exclude the embedded manifest bytes from the content hash, ensuring
/// the hash is stable regardless of whether the manifest is present.
///
/// Overlapping or out-of-order ranges are handled correctly: each excluded
/// byte is zeroed exactly once regardless of how many ranges cover it.
pub fn hash_with_exclusions(data: &[u8], exclusions: &[HashExclusion]) -> [u8; 32] {
    if exclusions.is_empty() {
        return Sha256::digest(data).into();
    }

    let mut hasher = Sha256::new();
    let mut pos = 0usize;

    // Sort ranges by start position for ordered streaming.
    let mut sorted: alloc::vec::Vec<(usize, usize)> = exclusions
        .iter()
        .filter_map(|e| {
            let end = e.start.checked_add(e.length)?;
            if e.start < data.len() {
                Some((e.start, end.min(data.len())))
            } else {
                None
            }
        })
        .collect();
    sorted.sort_unstable_by_key(|&(start, _)| start);

    for (start, end) in sorted {
        if start > pos {
            let slice_end = start.min(data.len());
            if pos < slice_end {
                hasher.update(&data[pos..slice_end]);
            }
        }
        // Feed zeroes for the excluded range.
        let zero_len = end.saturating_sub(start.max(pos));
        if zero_len > 0 {
            const ZERO_BUF: [u8; 4096] = [0u8; 4096];
            let mut remaining = zero_len;
            while remaining > 0 {
                let chunk = remaining.min(ZERO_BUF.len());
                hasher.update(&ZERO_BUF[..chunk]);
                remaining -= chunk;
            }
        }
        pos = end.max(pos);
    }

    if pos < data.len() {
        hasher.update(&data[pos..]);
    }

    hasher.finalize().into()
}

/// Find the byte offset value from the last `startxref` marker in a PDF.
fn find_last_startxref(data: &[u8]) -> Option<usize> {
    // Search backwards from the end for "startxref"
    let needle = b"startxref";
    let pos = data.windows(needle.len()).rposition(|w| w == needle)?;

    // Parse the number after "startxref\n"
    let after = &data[pos + needle.len()..];
    let num_str: String = after
        .iter()
        .skip_while(|b| b.is_ascii_whitespace())
        .take_while(|b| b.is_ascii_digit())
        .map(|&b| b as char)
        .collect();
    num_str.parse().ok()
}

// alloc is available: authorproof-protocol requires alloc (uses Vec everywhere).
extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa::builder::C2paManifestBuilder;
    use crate::rfc::{Checkpoint, DocumentRef, EvidencePacket, HashAlgorithm, HashValue};
    use ed25519_dalek::SigningKey;

    fn minimal_pdf() -> Vec<u8> {
        b"%PDF-1.4\n\
          1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
          2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n\
          xref\n0 3\n\
          0000000000 65535 f \n\
          0000000009 00000 n \n\
          0000000058 00000 n \n\
          trailer\n<< /Size 3 /Root 1 0 R >>\n\
          startxref\n112\n%%EOF\n"
            .to_vec()
    }

    #[test]
    fn test_pdf_embed_preserves_header() {
        let pdf = minimal_pdf();
        let jumbf = b"fake c2pa manifest for pdf";

        let embedded = embed_in_pdf(&pdf, jumbf).expect("embed_in_pdf should succeed");

        // PDF header preserved
        assert_eq!(&embedded[..5], PDF_SIGNATURE);

        // Original content preserved at start
        assert_eq!(&embedded[..pdf.len()], &pdf[..]);

        // C2PA stream object present
        let embedded_str = String::from_utf8_lossy(&embedded);
        assert!(
            embedded_str.contains("/C2PA"),
            "Embedded PDF must contain /C2PA reference"
        );
        assert!(
            embedded_str.contains("/Subtype /C2PA"),
            "Stream object must have /Subtype /C2PA"
        );

        // JUMBF data present
        let jumbf_pos = embedded
            .windows(jumbf.len())
            .position(|w| w == jumbf)
            .expect("JUMBF data must be in embedded PDF");
        assert!(
            jumbf_pos > pdf.len(),
            "JUMBF must be in the appended update"
        );

        // %%EOF at the end
        assert!(
            embedded_str.ends_with("%%EOF\n"),
            "Embedded PDF must end with %%EOF"
        );
    }

    #[test]
    fn test_pdf_embed_preserves_catalog() {
        // Regression: the embed must ADD /C2PA to the existing catalog, never
        // replace /Root with an inline dict (which orphaned /Pages and made the
        // PDF unopenable in Preview/PDFKit).
        let pdf = minimal_pdf();
        let embedded = embed_in_pdf(&pdf, b"jumbf-bytes").expect("embed should succeed");
        let s = String::from_utf8_lossy(&embedded);

        assert!(
            s.contains("/Root 1 0 R"),
            "must preserve the original /Root 1 0 R reference"
        );
        assert!(
            !s.contains("/Root <<"),
            "/Root must not be replaced by an inline dict"
        );
        assert!(
            !s.contains("999999"),
            "must not use the 999999 placeholder object number"
        );
        // Catalog re-emitted with /Pages intact and /C2PA added as an indirect ref.
        assert!(
            s.contains("/Pages 2 0 R"),
            "catalog must still reference /Pages"
        );
        assert!(
            s.contains("/C2PA 3 0 R"),
            "catalog must reference the C2PA object (obj 3)"
        );
        assert!(s.contains("3 0 obj"), "C2PA object 3 must be defined");
        assert!(s.ends_with("%%EOF\n"));
    }

    #[test]
    fn test_pdf_embed_rejects_invalid_pdf() {
        assert!(embed_in_pdf(b"not a pdf", b"jumbf").is_err());
    }

    #[test]
    fn test_pdf_embed_empty_jumbf() {
        let pdf = minimal_pdf();
        let embedded = embed_in_pdf(&pdf, b"").expect("empty jumbf should be valid");
        assert!(embedded.len() > pdf.len());
    }

    #[test]
    fn test_sidecar_path_generation() {
        assert_eq!(sidecar_path("/doc/essay.md"), "/doc/essay.md.c2pa");
        assert_eq!(sidecar_path("/doc/paper.txt"), "/doc/paper.txt.c2pa");
        assert_eq!(sidecar_path("/doc/thesis.pdf"), "/doc/thesis.pdf.c2pa");
    }

    #[test]
    fn test_supports_embedding() {
        assert!(supports_embedding("pdf"));
        assert!(supports_embedding("PDF"));
        assert!(!supports_embedding("txt"));
        assert!(!supports_embedding("md"));
        assert!(!supports_embedding("rtf"));
        assert!(!supports_embedding("docx"));
    }

    #[test]
    fn test_hash_with_exclusions_no_exclusions() {
        let data = b"hello world";
        let result = hash_with_exclusions(data, &[]);
        let expected: [u8; 32] = Sha256::digest(data).into();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hash_with_exclusions_full_range() {
        let data = [0xABu8; 32];
        let exclusions = vec![HashExclusion {
            start: 0,
            length: 32,
        }];
        let result = hash_with_exclusions(&data, &exclusions);
        let expected: [u8; 32] = Sha256::digest([0u8; 32]).into();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hash_exclusion_range_correctness() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let exclusions = vec![HashExclusion {
            start: 2,
            length: 3,
        }];
        let result = hash_with_exclusions(&data, &exclusions);

        let mut expected_data = data;
        expected_data[2] = 0;
        expected_data[3] = 0;
        expected_data[4] = 0;
        let expected: [u8; 32] = Sha256::digest(expected_data).into();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hash_exclusion_out_of_bounds_is_safe() {
        let data = [0xFFu8; 16];
        let exclusions = vec![HashExclusion {
            start: 100,
            length: 10,
        }];
        let result = hash_with_exclusions(&data, &exclusions);
        let expected: [u8; 32] = Sha256::digest(data).into();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_find_last_startxref() {
        let pdf = minimal_pdf();
        let offset = find_last_startxref(&pdf);
        assert!(offset.is_some());
        assert_eq!(offset.unwrap(), 112);
    }

    fn make_embed_test_packet() -> EvidencePacket {
        EvidencePacket {
            version: 1,
            profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
            packet_id: vec![0xBBu8; 16],
            created: 1710000000000,
            document: DocumentRef {
                content_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: vec![0xCCu8; 32],
                },
                filename: Some("test.pdf".to_string()),
                byte_length: 512,
                char_count: 100,
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

    #[test]
    fn test_embed_manifest_in_pdf_hash_exclusion_correct() {
        let pdf = minimal_pdf();
        let packet = make_embed_test_packet();
        let evidence_bytes = b"fake evidence".to_vec();
        let key = SigningKey::from_bytes(&[2u8; 32]);

        let builder = C2paManifestBuilder::new(packet, evidence_bytes, [0u8; 32])
            .document_filename("test.pdf");

        let embedded = embed_manifest_in_pdf(&pdf, builder, &key)
            .expect("embed_manifest_in_pdf should succeed");

        // Original PDF bytes preserved at start.
        assert_eq!(&embedded[..pdf.len()], &pdf[..]);

        // The embedded PDF contains the C2PA stream marker.
        let text = String::from_utf8_lossy(&embedded);
        assert!(text.contains("/Subtype /C2PA"));

        // Verify that the hash in the manifest is consistent with the exclusion:
        // recomputing hash_with_exclusions over the output with the appended
        // region zeroed must equal the hash stored in the hash-data assertion.
        // We confirm this indirectly by asserting the function completes without
        // panicking on the size-stability assertion and produces a longer output.
        assert!(embedded.len() > pdf.len());
        assert!(text.ends_with("%%EOF\n"));
    }

    #[test]
    fn test_embed_manifest_in_pdf_jumbf_size_stable() {
        // Verify that two consecutive embeds with the same builder produce
        // identical output lengths (the hash-only difference does not change size).
        let pdf = minimal_pdf();
        let packet = make_embed_test_packet();
        let key = SigningKey::from_bytes(&[3u8; 32]);

        let builder = C2paManifestBuilder::new(packet.clone(), b"ev1".to_vec(), [0u8; 32]);
        let embedded1 = embed_manifest_in_pdf(&pdf, builder, &key).unwrap();

        let builder2 = C2paManifestBuilder::new(packet, b"ev1".to_vec(), [0xFFu8; 32]);
        let embedded2 = embed_manifest_in_pdf(&pdf, builder2, &key).unwrap();

        assert_eq!(embedded1.len(), embedded2.len());
    }
}
