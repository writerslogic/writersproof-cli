// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared constants for forensic analysis modules.

/// Zone ID for correction/backspace keystrokes in jitter samples.
pub const CORRECTION_ZONE: u8 = 0xFF;

/// Pause threshold: IKI >= this is considered a pause (2 seconds).
pub const PAUSE_THRESHOLD_NS: u64 = 2_000_000_000;
/// f64 version for direct arithmetic.
pub const PAUSE_THRESHOLD_NS_F64: f64 = PAUSE_THRESHOLD_NS as f64;
/// Pause threshold in milliseconds.
pub const PAUSE_THRESHOLD_MS: f64 = 2000.0;

/// Burst threshold: IKI < this is considered within a typing burst (200ms).
pub const BURST_THRESHOLD_NS: u64 = 200_000_000;
/// f64 version for direct arithmetic.
pub const BURST_THRESHOLD_NS_F64: f64 = BURST_THRESHOLD_NS as f64;
/// Burst threshold in milliseconds.
pub const BURST_THRESHOLD_MS: f64 = 200.0;

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
    "windsurf",
    "sourcegraph",
    "cody",
];

/// Exact macOS bundle IDs of known AI assistant applications.
/// Pastes originating from these apps are flagged with `PASTE_FROM_AI_TOOL`.
/// Maintain alongside [`AI_APP_PATTERNS`] — additions may need both lists.
pub const KNOWN_AI_APP_BUNDLE_IDS: &[&str] = &[
    "com.anthropic.claudefordesktop",
    "com.anthropic.claude",
    "com.openai.chat",
    "com.openai.chatgpt",
    "com.openai.chatgpt.macos",
    "com.microsoft.copilot",
    "com.github.copilot",
    "com.cursor.Cursor",
    "dev.cursor.app",
    "com.todesktop.230313mzl4w4u92", // Cursor alternative ID
    "com.codeium.windsurf",
    "com.sourcegraph.cody",
    "com.google.bard",
    "com.google.gemini",
    "com.perplexity.mac",
    "io.perplexity.macos",
    "com.mistral.mistral",
    "com.cohere.coral",
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
