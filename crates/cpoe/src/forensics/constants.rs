// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared constants for forensic analysis modules.

/// Zone ID for correction/backspace keystrokes in jitter samples.
pub const CORRECTION_ZONE: u8 = 0xFF;

/// Pause threshold: IKI >= this is considered a pause (2 seconds).
pub const PAUSE_THRESHOLD_NS: u64 = 2_000_000_000;

/// Burst threshold: IKI < this is considered within a typing burst (200ms).
pub const BURST_THRESHOLD_NS: u64 = 200_000_000;

/// AI tool bundle ID substrings for focus-switch classification.
///
/// Used by both composition mode detection and AI-mediated authoring analysis.
/// Matched case-insensitively against bundle IDs and app names via `.contains()`.
pub const AI_APP_PATTERNS: &[&str] = &[
    "openai",
    "chatgpt",
    "anthropic",
    "claude",
    "copilot",
    "cursor",
    "codeium",
    "tabnine",
    "bard",
    "gemini",
    "perplexity",
];

/// Browser bundle IDs that may host AI chat interfaces.
pub const BROWSER_BUNDLE_IDS: &[&str] = &[
    "com.apple.Safari",
    "com.google.Chrome",
    "org.mozilla.firefox",
    "com.microsoft.edgemac",
    "com.brave.Browser",
    "company.thebrowser.Browser",
];
