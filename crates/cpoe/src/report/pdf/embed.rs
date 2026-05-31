// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Embedding of WAR block and verification data in PDF metadata.
//!
//! The PDF embeds the ASCII-armored WAR block and compact reference
//! as custom metadata fields. This enables offline extraction and
//! verification without the WritersProof API. When CBOR evidence is
//! available, a dedicated page renders the base64 payload as extractable text.

use super::PdfFonts;
use crate::report::types::WarReport;
use printpdf::PdfLayerReference;

/// Draw a page containing the base64-encoded CBOR evidence payload.
///
/// This makes the PDF a self-contained forensic artifact; the payload is
/// extractable by copy-paste or by automated text extraction tools.
pub fn draw_evidence_page(
    layer: &PdfLayerReference,
    r: &WarReport,
    fonts: &PdfFonts,
    footer: &str,
) {
    use super::layout::{text, wrap_text_lines, BLACK, CONTENT_WIDTH, GRAY, MARGIN_LEFT, PAGE_TOP};

    let mut y = PAGE_TOP;

    text(
        layer,
        "Appendix A. Machine-Readable Evidence Payload",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 6.0;

    text(
        layer,
        "The following base64-encoded CBOR payload contains the cryptographically signed evidence",
        5.5,
        MARGIN_LEFT,
        y,
        &fonts.regular,
        GRAY,
    );
    y -= 3.5;
    text(
        layer,
        "packet for this report. Decode and verify with: cpoe verify --from-b64 <payload>",
        5.5,
        MARGIN_LEFT,
        y,
        &fonts.regular,
        GRAY,
    );
    y -= 6.0;

    // Draw the base64 text in a bordered box using monospace font
    let b64 = match r.evidence_cbor_b64 {
        Some(ref s) => s.as_str(),
        None => return,
    };

    // Box background
    let box_top = y;
    let box_h = box_top - 18.0; // leave room for footer
    super::layout::fill_rect(
        layer,
        MARGIN_LEFT,
        box_top - box_h,
        CONTENT_WIDTH,
        box_h,
        (0.98, 0.98, 0.98),
    );
    super::layout::stroke_rect(
        layer,
        MARGIN_LEFT,
        box_top - box_h,
        CONTENT_WIDTH,
        box_h,
        0.3,
        (0.88, 0.88, 0.88),
    );

    // Wrap at ~100 chars for monospace readability
    let lines = wrap_text_lines(b64, 100);
    let mut ty = box_top - 3.0;
    let bottom = box_top - box_h + 2.0;
    for line in &lines {
        if ty < bottom {
            text(
                layer,
                "[payload truncated, see .c2pa sidecar for full evidence]",
                4.5,
                MARGIN_LEFT + 3.0,
                ty,
                &fonts.regular,
                GRAY,
            );
            break;
        }
        text(layer, line, 4.5, MARGIN_LEFT + 3.0, ty, &fonts.mono, BLACK);
        ty -= 3.2;
    }

    // Footer
    text(layer, footer, 5.0, MARGIN_LEFT, 10.0, &fonts.regular, GRAY);
}

/// Draw a page containing the W3C Verifiable Credential JSON-LD.
///
/// The VC is rendered as extractable monospace text so automated tools
/// can parse it without OCR.
pub fn draw_vc_page(layer: &PdfLayerReference, r: &WarReport, fonts: &PdfFonts, footer: &str) {
    use super::layout::{text, wrap_text_lines, BLACK, CONTENT_WIDTH, GRAY, MARGIN_LEFT, PAGE_TOP};

    let vc_json = match r.verifiable_credential_json {
        Some(ref s) => s.as_str(),
        None => return,
    };

    let mut y = PAGE_TOP;

    text(
        layer,
        "Appendix B. W3C Verifiable Credential 2.0",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 6.0;

    text(
        layer,
        "Signed credential with Ed25519 Data Integrity proof (eddsa-rdfc-2022 cryptosuite).",
        5.5,
        MARGIN_LEFT,
        y,
        &fonts.regular,
        GRAY,
    );
    y -= 3.5;

    if let Some(ref did) = r.author_did {
        text(
            layer,
            &format!("Author DID: {did}"),
            5.5,
            MARGIN_LEFT,
            y,
            &fonts.mono,
            BLACK,
        );
        y -= 5.0;
    }

    y -= 3.0;

    // Box background
    let box_top = y;
    let box_h = box_top - 18.0;
    super::layout::fill_rect(
        layer,
        MARGIN_LEFT,
        box_top - box_h,
        CONTENT_WIDTH,
        box_h,
        (0.98, 0.98, 0.98),
    );
    super::layout::stroke_rect(
        layer,
        MARGIN_LEFT,
        box_top - box_h,
        CONTENT_WIDTH,
        box_h,
        0.3,
        (0.88, 0.88, 0.88),
    );

    let lines = wrap_text_lines(vc_json, 100);
    let mut ty = box_top - 3.0;
    let bottom = box_top - box_h + 2.0;
    for line in &lines {
        if ty < bottom {
            text(
                layer,
                "[credential truncated, see HTML report for full JSON-LD]",
                4.5,
                MARGIN_LEFT + 3.0,
                ty,
                &fonts.regular,
                GRAY,
            );
            break;
        }
        text(layer, line, 4.5, MARGIN_LEFT + 3.0, ty, &fonts.mono, BLACK);
        ty -= 3.2;
    }

    text(layer, footer, 5.0, MARGIN_LEFT, 10.0, &fonts.regular, GRAY);
}
