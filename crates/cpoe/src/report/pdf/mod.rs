// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! PDF report generation for Forensic Authorship Examination Reports.
//!
//! Produces self-contained forensic artifact PDFs with anti-forgery security
//! features (guilloche, microtext, void pantograph) derived from the
//! cryptographic seal. The PDF embeds document metadata, a human-readable
//! verification block, and optionally the full CBOR evidence payload.

mod charts;
mod embed;
mod layout;
mod layout_sections;
mod security;

use crate::report::types::WarReport;
use printpdf::*;
use std::io::BufWriter;

/// Render a signed PDF report from a `WarReport`.
///
/// The returned bytes are a complete PDF document ready to write to disk.
/// The PDF includes:
/// - Security features (guilloché, microtext) seeded from `security_seed`
/// - Embedded WAR block in a PDF annotation (for offline verification)
/// - QR code linking to WritersProof verification
///
/// `security_seed` should be `signer.sign(b"cpoe-security-v1" || H3)` — a 64-byte
/// value that only the signing key holder can produce.
///
/// # Errors
///
/// Returns an error if font loading or PDF serialization fails (should not happen
/// with built-in fonts under normal conditions).
pub fn render_pdf(
    report: &WarReport,
    security_seed: Option<&[u8; 64]>,
) -> crate::error::Result<Vec<u8>> {
    let version = env!("CARGO_PKG_VERSION");
    let doc_hash_short = report
        .document_hash
        .get(..16)
        .unwrap_or(&report.document_hash);

    let (doc, page1, layer1) = PdfDocument::new(
        format!(
            "Forensic Authorship Examination Report - {}",
            report.report_id
        ),
        Mm(210.0), // A4 width
        Mm(297.0), // A4 height
        "Layer 1",
    );

    // Set PDF document info metadata
    let doc = doc
        .with_author(format!("CPoE Forensic Engine {}", version))
        .with_subject(format!(
            "Authorship examination report for document {}",
            doc_hash_short
        ))
        .with_creator("WritersLogic CPoE Engine")
        .with_producer(format!("cpoe-engine/{}", version))
        .with_keywords(vec![
            report.report_id.clone(),
            report.document_hash.clone(),
            report.signing_key_fingerprint.clone(),
            report.verdict.label().to_string(),
            report.enfsi_tier.label().to_string(),
            report.algorithm_version.clone(),
            report.schema_version.clone(),
        ]);

    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| format!("failed to load Helvetica font: {e}"))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| format!("failed to load HelveticaBold font: {e}"))?;
    let font_mono = doc
        .add_builtin_font(BuiltinFont::Courier)
        .map_err(|e| format!("failed to load Courier font: {e}"))?;

    let fonts = PdfFonts {
        regular: font,
        bold: font_bold,
        mono: font_mono,
    };

    let footer = format!(
        "WritersLogic Inc.  ·  {}  ·  {}",
        report.report_id, report.algorithm_version,
    );

    // Page 1: Header, verdict, declaration, QR
    let current_layer = doc.get_page(page1).get_layer(layer1);
    if let Some(seed) = security_seed {
        security::draw_guilloche_border(&current_layer, seed);
    }
    layout::draw_page1(&current_layer, report, &fonts, security_seed, &footer);

    // Page 2: Evidence analysis, temporal witnesses, flags
    let (page2, layer2) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page2).get_layer(layer2);
    if let Some(seed) = security_seed {
        security::draw_guilloche_border(&current_layer, seed);
    }
    layout_sections::draw_page2(&current_layer, report, &fonts, &footer);

    // Page 3: Forensic analysis details
    let (page3, layer3) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page3).get_layer(layer3);
    if let Some(seed) = security_seed {
        security::draw_guilloche_border(&current_layer, seed);
    }
    layout_sections::draw_forensics_page(&current_layer, report, &fonts, &footer);

    // Page 4: Scope, verification instructions, verification block
    let (page4, layer4) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page4).get_layer(layer4);
    layout_sections::draw_page3(&current_layer, report, &fonts, &footer);

    // Page 5 (optional): Machine-readable evidence payload
    if report.evidence_cbor_b64.is_some() {
        let (page5, layer5) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
        let current_layer = doc.get_page(page5).get_layer(layer5);
        embed::draw_evidence_page(&current_layer, report, &fonts, &footer);
    }

    // Page 6 (optional): W3C Verifiable Credential
    if report.verifiable_credential_json.is_some() {
        let (vc_page, vc_layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
        let current_layer = doc.get_page(vc_page).get_layer(vc_layer);
        if let Some(seed) = security_seed {
            security::draw_guilloche_border(&current_layer, seed);
        }
        embed::draw_vc_page(&current_layer, report, &fonts, &footer);
    }

    // Serialize to bytes
    let mut buf = BufWriter::new(Vec::new());
    doc.save(&mut buf)
        .map_err(|e| format!("PDF serialization failed: {e}"))?;
    let pdf_bytes = buf
        .into_inner()
        .map_err(|e| format!("PDF buffer flush failed: {e}"))?;

    // Embed the VC JSON as a PDF file attachment so tools can extract it
    // without OCR. We round-trip through lopdf since printpdf's save
    // consumes the document and builds the catalog internally.
    if let Some(ref vc_json) = report.verifiable_credential_json {
        return embed_vc_attachment(pdf_bytes, vc_json.as_bytes());
    }

    Ok(pdf_bytes)
}

/// Embed a VC JSON-LD as a PDF /EmbeddedFiles attachment.
///
/// Re-parses the serialized PDF, adds the embedded file entry to the
/// catalog's /Names dictionary, and re-serializes.
fn embed_vc_attachment(pdf_bytes: Vec<u8>, vc_json: &[u8]) -> crate::error::Result<Vec<u8>> {
    use printpdf::lopdf::{self, Dictionary as LoDict, Object, Stream, StringFormat};

    let mut doc = lopdf::Document::load_mem(&pdf_bytes)
        .map_err(|e| format!("failed to re-parse PDF for VC embedding: {e}"))?;

    // 1. Stream object holding the raw JSON bytes (lopdf will deflate-compress
    //    on Document::compress(), which printpdf calls in release builds).
    let mut stream_dict = LoDict::new();
    stream_dict.set("Type", Object::Name(b"EmbeddedFile".to_vec()));
    stream_dict.set("Subtype", Object::Name(b"application/ld+json".to_vec()));
    stream_dict.set(
        "Params",
        Object::Dictionary({
            let mut params = LoDict::new();
            params.set("Size", Object::Integer(vc_json.len() as i64));
            params
        }),
    );
    let stream = Stream::new(stream_dict, vc_json.to_vec());
    let stream_id = doc.add_object(stream);

    // 2. File specification dictionary (PDF 1.7, section 7.11.3).
    let mut filespec = LoDict::new();
    filespec.set("Type", Object::Name(b"Filespec".to_vec()));
    filespec.set(
        "F",
        Object::String(b"credential.jsonld".to_vec(), StringFormat::Literal),
    );
    filespec.set(
        "UF",
        Object::String(b"credential.jsonld".to_vec(), StringFormat::Literal),
    );
    filespec.set(
        "Desc",
        Object::String(
            b"W3C Verifiable Credential 2.0 (JSON-LD)".to_vec(),
            StringFormat::Literal,
        ),
    );
    filespec.set("AFRelationship", Object::Name(b"Data".to_vec()));
    let mut ef = LoDict::new();
    ef.set("F", Object::Reference(stream_id));
    ef.set("UF", Object::Reference(stream_id));
    filespec.set("EF", Object::Dictionary(ef));
    let filespec_id = doc.add_object(filespec);

    // 3. /Names -> /EmbeddedFiles name tree in the catalog.
    //    We use a single-entry leaf node (Names array, not Kids).
    let names_array = vec![
        Object::String(b"credential.jsonld".to_vec(), StringFormat::Literal),
        Object::Reference(filespec_id),
    ];
    let mut embedded_files = LoDict::new();
    embedded_files.set("Names", Object::Array(names_array));
    let embedded_files_id = doc.add_object(embedded_files);

    // Determine how /Names is stored in the catalog so we can handle
    // both inline dictionaries and indirect references without borrow conflicts.
    enum NamesLocation {
        Reference(lopdf::ObjectId),
        Inline,
        Missing,
    }

    let location = {
        let catalog = doc
            .catalog()
            .map_err(|e| format!("failed to access PDF catalog: {e}"))?;
        if catalog.has(b"Names") {
            match catalog.get(b"Names") {
                Ok(Object::Reference(id)) => NamesLocation::Reference(*id),
                _ => NamesLocation::Inline,
            }
        } else {
            NamesLocation::Missing
        }
    };

    match location {
        NamesLocation::Reference(names_ref) => {
            let names_dict = doc
                .get_dictionary_mut(names_ref)
                .map_err(|e| format!("failed to access /Names dict: {e}"))?;
            names_dict.set("EmbeddedFiles", Object::Reference(embedded_files_id));
        }
        NamesLocation::Inline => {
            let catalog = doc
                .catalog_mut()
                .map_err(|e| format!("failed to access PDF catalog: {e}"))?;
            if let Ok(Object::Dictionary(ref mut names_dict)) = catalog.get_mut(b"Names") {
                names_dict.set("EmbeddedFiles", Object::Reference(embedded_files_id));
            }
        }
        NamesLocation::Missing => {
            let mut names_dict = LoDict::new();
            names_dict.set("EmbeddedFiles", Object::Reference(embedded_files_id));
            let names_id = doc.add_object(names_dict);
            let catalog = doc
                .catalog_mut()
                .map_err(|e| format!("failed to access PDF catalog: {e}"))?;
            catalog.set("Names", Object::Reference(names_id));
        }
    }

    // Also add /AF array on the catalog for PDF 2.0 associated files.
    let catalog = doc
        .catalog_mut()
        .map_err(|e| format!("failed to access PDF catalog for AF: {e}"))?;
    catalog.set("AF", Object::Array(vec![Object::Reference(filespec_id)]));

    let mut out = Vec::new();
    doc.save_to(&mut out)
        .map_err(|e| format!("failed to re-serialize PDF with VC attachment: {e}"))?;

    Ok(out)
}

/// Font handles for the PDF document.
pub(crate) struct PdfFonts {
    pub regular: IndirectFontRef,
    pub bold: IndirectFontRef,
    pub mono: IndirectFontRef,
}
