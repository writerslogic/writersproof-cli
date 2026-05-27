// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

mod advanced;
mod analysis;
mod declaration;
mod evidence;
mod header;
mod legal;

use super::helpers::*;
use crate::report::types::*;
use crate::utils::finite_or;
use std::fmt::{self, Write};

const TMPL_METHODOLOGY: &str = include_str!("../templates/methodology.html");
const TMPL_GLOSSARY: &str = include_str!("../templates/glossary.html");
const TMPL_SCOPE: &str = include_str!("../templates/scope.html");
const TMPL_VERIFICATION: &str = include_str!("../templates/verification.html");

pub(super) const REPORT_TITLE: &str = "Forensic Authorship Examination Report";
pub(super) const SEC_DECLARATION: &str = "Declaration of Findings";
pub(super) const SEC_METHODOLOGY: &str = "Methodology";
pub(super) const SEC_CHAIN: &str = "Chain of Evidence";
pub(super) const SEC_PROCESS: &str = "Findings: Process Evidence";
pub(super) const SEC_TIMELINE: &str = "Session Timeline";
pub(super) const SEC_DIMENSIONS: &str = "Detailed Dimension Analysis";
pub(super) const SEC_STATISTICS: &str = "Statistical Analysis: Per-Dimension Likelihood Ratios";
pub(super) const SEC_CHECKPOINTS: &str = "Checkpoint Chain Integrity";
pub(super) const SEC_FORGERY: &str = "Forgery Resistance Assessment";
pub(super) const SEC_FLAGS: &str = "Analysis Flags";
pub(super) const SEC_SCOPE: &str = "Scope, Limitations, and Admissibility";
pub(super) const SEC_TEXT: &str = "Analyzed Text";
pub(super) const SEC_VERIFY: &str = "Independent Verification";
pub(super) const SEC_GLOSSARY: &str = "Glossary of Terms";

pub(super) fn section_heading(html: &mut String, number: u32, title: &str) -> fmt::Result {
    write!(
        html,
        r#"<h2><span class="section-number">{}.</span> {}</h2>"#,
        number, title
    )
}

/// Validate a CSS color value to prevent XSS injection via style attributes.
pub(super) fn sanitize_css_color(color: &str) -> &str {
    let bytes = color.as_bytes();
    let valid = bytes.first() == Some(&b'#')
        && matches!(bytes.len(), 4 | 5 | 7 | 9)
        && bytes[1..].iter().all(|b| b.is_ascii_hexdigit());
    if valid {
        color
    } else {
        "#4a4a4a"
    }
}

// Re-export all section functions for the parent module.
pub(in crate::report::html) use advanced::*;
pub(in crate::report::html) use analysis::*;
pub(in crate::report::html) use declaration::*;
pub(in crate::report::html) use evidence::*;
pub(in crate::report::html) use header::*;
pub(in crate::report::html) use legal::*;
