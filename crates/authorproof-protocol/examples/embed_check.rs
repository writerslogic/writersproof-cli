// SPDX-License-Identifier: Apache-2.0
//! Manual validation harness: build a classic-xref 1-page PDF, embed a C2PA
//! manifest via `embed_in_pdf`, and write both files so the result can be opened
//! with a real PDF reader (macOS PDFKit/Preview) to confirm it is not corrupt.
//!
//! Run: `cargo run -p authorproof-protocol --example embed_check`

use authorproof_protocol::c2pa::embed::embed_in_pdf;
use std::fs;

fn main() {
    let bodies = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
    ];
    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.push_str(&format!("{} 0 obj\n{}\nendobj\n", i + 1, body));
    }
    let xref_off = pdf.len();
    let n = bodies.len() + 1;
    pdf.push_str(&format!("xref\n0 {n}\n0000000000 65535 f \n"));
    for off in &offsets {
        pdf.push_str(&format!("{off:010} 00000 n \n"));
    }
    pdf.push_str(&format!(
        "trailer\n<< /Size {n} /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n"
    ));

    let base = pdf.into_bytes();
    fs::write("/tmp/base.pdf", &base).expect("write base");
    let embedded =
        embed_in_pdf(&base, b"fake-jumbf-c2pa-manifest-data-for-validation").expect("embed_in_pdf");
    fs::write("/tmp/embedded.pdf", &embedded).expect("write embedded");
    println!("base={} embedded={}", base.len(), embedded.len());
}
