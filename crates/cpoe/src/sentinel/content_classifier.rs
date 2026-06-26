// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Classify pasted content by semantic type.

use super::types::{PasteContentKind, PasteboardTypeInventory};

const MIN_TABLE_LINES: usize = 2;
const CONSISTENCY_THRESHOLD: f64 = 0.75;
const MEDIA_TEXT_THRESHOLD: usize = 30;

/// Classify the semantic type of pasted content from the pasteboard type
/// inventory and plain-text representation.
pub fn classify_paste_content_kind(
    text: &str,
    inventory: &PasteboardTypeInventory,
) -> PasteContentKind {
    let trimmed = text.trim();

    if inventory.has_image {
        return if trimmed.len() < MEDIA_TEXT_THRESHOLD {
            PasteContentKind::Media
        } else {
            PasteContentKind::Mixed
        };
    }

    if (inventory.has_rtf || inventory.has_html) && trimmed.is_empty() {
        return PasteContentKind::FormattingOnly;
    }

    if inventory.has_spreadsheet {
        return PasteContentKind::StructuredData;
    }

    if has_consistent_delimiters(trimmed, '\t', 1) || has_consistent_delimiters(trimmed, ',', 2) {
        return PasteContentKind::StructuredData;
    }

    PasteContentKind::Prose
}

/// Check if text has lines with a consistent count of `delimiter`, where each
/// line has at least `min_per_line` occurrences and >= `CONSISTENCY_THRESHOLD`
/// of lines share the same count.
fn has_consistent_delimiters(text: &str, delimiter: char, min_per_line: usize) -> bool {
    let counts: Vec<usize> = text
        .lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty())
        .map(|l| l.chars().filter(|&c| c == delimiter).count())
        .collect();

    if counts.len() < MIN_TABLE_LINES {
        return false;
    }

    if counts.iter().any(|&c| c < min_per_line) {
        return false;
    }

    // Find max frequency. For typical paste sizes (<100 lines), a linear scan
    // on a sorted slice beats HashMap allocation overhead.
    let mut sorted = counts.clone();
    sorted.sort_unstable();
    let mut max_freq: usize = 0;
    let mut run: usize = 1;
    for w in sorted.windows(2) {
        if w[0] == w[1] {
            run += 1;
        } else {
            max_freq = max_freq.max(run);
            run = 1;
        }
    }
    max_freq = max_freq.max(run);

    (max_freq as f64 / counts.len() as f64) >= CONSISTENCY_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_inventory() -> PasteboardTypeInventory {
        PasteboardTypeInventory::default()
    }

    fn image_inventory() -> PasteboardTypeInventory {
        PasteboardTypeInventory {
            has_image: true,
            ..Default::default()
        }
    }

    fn spreadsheet_inventory() -> PasteboardTypeInventory {
        PasteboardTypeInventory {
            has_plain_text: true,
            has_spreadsheet: true,
            ..Default::default()
        }
    }

    fn rtf_inventory() -> PasteboardTypeInventory {
        PasteboardTypeInventory {
            has_rtf: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_prose_default() {
        let kind = classify_paste_content_kind("Hello world", &empty_inventory());
        assert_eq!(kind, PasteContentKind::Prose);
    }

    #[test]
    fn test_image_no_text() {
        let kind = classify_paste_content_kind("", &image_inventory());
        assert_eq!(kind, PasteContentKind::Media);
    }

    #[test]
    fn test_image_with_alt_text() {
        let kind = classify_paste_content_kind("photo.png", &image_inventory());
        assert_eq!(kind, PasteContentKind::Media);
    }

    #[test]
    fn test_image_with_substantial_text() {
        let text = "This is a long caption describing the image in detail for accessibility";
        let kind = classify_paste_content_kind(text, &image_inventory());
        assert_eq!(kind, PasteContentKind::Mixed);
    }

    #[test]
    fn test_formatting_only() {
        let kind = classify_paste_content_kind("   \n  ", &rtf_inventory());
        assert_eq!(kind, PasteContentKind::FormattingOnly);
    }

    #[test]
    fn test_spreadsheet_type() {
        let kind = classify_paste_content_kind("A\tB\nC\tD", &spreadsheet_inventory());
        assert_eq!(kind, PasteContentKind::StructuredData);
    }

    #[test]
    fn test_tab_delimited_table() {
        let text = "Name\tAge\tCity\nAlice\t30\tNYC\nBob\t25\tSF\n";
        let kind = classify_paste_content_kind(text, &empty_inventory());
        assert_eq!(kind, PasteContentKind::StructuredData);
    }

    #[test]
    fn test_csv_data() {
        let text = "name,age,city\nalice,30,nyc\nbob,25,sf\n";
        let kind = classify_paste_content_kind(text, &empty_inventory());
        assert_eq!(kind, PasteContentKind::StructuredData);
    }

    #[test]
    fn test_single_line_not_table() {
        let text = "col1\tcol2\tcol3";
        let kind = classify_paste_content_kind(text, &empty_inventory());
        assert_eq!(kind, PasteContentKind::Prose);
    }

    #[test]
    fn test_prose_with_commas_not_csv() {
        let text = "Hello, world\nFoo, bar\nBaz, quux\n";
        let kind = classify_paste_content_kind(text, &empty_inventory());
        assert_eq!(kind, PasteContentKind::Prose);
    }

    #[test]
    fn test_inconsistent_tabs_not_table() {
        let text = "a\tb\tc\nd\te\nf\n";
        let kind = classify_paste_content_kind(text, &empty_inventory());
        assert_eq!(kind, PasteContentKind::Prose);
    }

    #[test]
    fn test_rtf_with_text_is_prose() {
        let kind = classify_paste_content_kind("This is real content", &rtf_inventory());
        assert_eq!(kind, PasteContentKind::Prose);
    }
}
