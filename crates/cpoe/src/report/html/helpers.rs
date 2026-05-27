// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use std::fmt::{self, Write};

pub(super) fn row(html: &mut String, label: &str, value: &str) -> fmt::Result {
    write!(
        html,
        "<tr><td>{}</td><td>{}</td></tr>",
        html_escape(label),
        html_escape(value)
    )
}

pub(super) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub(super) fn format_lr(lr: f64) -> String {
    if !lr.is_finite() || lr < 0.0 {
        return "N/A".to_string();
    }
    if lr >= 10_000.0 {
        format!("{:.0}", lr)
    } else if lr >= 1_000.0 {
        format_number(lr as u64)
    } else if lr >= 100.0 {
        format!("{:.0}", lr)
    } else if lr >= 10.0 {
        format!("{:.1}", lr)
    } else {
        format!("{:.2}", lr)
    }
}

pub(super) use crate::utils::formatting::{format_bytes, format_duration_human, format_number};
