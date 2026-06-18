// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Registry of known writing applications with storage metadata.
//!
//! Centralises knowledge about how different apps store their documents so the
//! sentinel can:
//!
//! 1. Identify documents by window title for apps that do not expose
//!    `AXDocument` (container-based, cloud-library, or database-backed apps).
//! 2. Emit a list of container directories to watch so file-change events
//!    arrive even when the app uses a non-standard storage location.
//! 3. Drive the title-inference check in `types.rs` —
//!    `infer_document_path_from_title_with_bundle` queries
//!    `needs_title_inference()` from this module at runtime.
//!
//! # Adding a new app
//!
//! Add a `WritingApp` entry to `KNOWN_WRITING_APPS`. Specify:
//! - `bundle_id`: the macOS CFBundleIdentifier (use `mdls -name kMDItemCFBundleIdentifier <app>`)
//! - `display_name`: human-readable name shown in logs / status
//! - `storage`: one of the `StoragePattern` variants
//! - `container_paths`: slice of paths relative to `$HOME` that should be
//!   added to the file-watch list. Use empty `&[]` for file-based apps.
//! - `needs_title_inference`: `true` when the app does not expose a real
//!   file path via `AXDocument`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// How the engine witnesses content for a given application.
///
/// `Auto` (default) selects the mode based on `StoragePattern`:
/// - `FileBased` / `BundleBased` → file-level hashing (current behavior)
/// - `ContainerBased` / `CloudLibrary` / `DatabaseBacked` → content-level
///   paragraph Merkle trees
///
/// Users can override per-app in settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WitnessingMode {
    /// Automatically select based on the app's `StoragePattern`.
    #[default]
    Auto,
    /// Hash the document file directly at each checkpoint.
    FileLevel,
    /// Build a paragraph-level Merkle tree from extracted text content.
    ContentLevel,
    /// File hash + content Merkle tree (for apps like Word that save files
    /// but also export to different formats).
    Hybrid,
}

impl WitnessingMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            WitnessingMode::Auto => "auto",
            WitnessingMode::FileLevel => "file_level",
            WitnessingMode::ContentLevel => "content_level",
            WitnessingMode::Hybrid => "hybrid",
        }
    }

    /// Resolve `Auto` to a concrete mode based on the app's storage pattern.
    pub fn resolve(self, storage: StoragePattern) -> Self {
        if self != WitnessingMode::Auto {
            return self;
        }
        match storage {
            StoragePattern::FileBased | StoragePattern::BundleBased => WitnessingMode::FileLevel,
            StoragePattern::ContainerBased
            | StoragePattern::CloudLibrary
            | StoragePattern::DatabaseBacked => WitnessingMode::ContentLevel,
        }
    }
}

impl std::str::FromStr for WitnessingMode {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "auto" => Ok(WitnessingMode::Auto),
            "file_level" => Ok(WitnessingMode::FileLevel),
            "content_level" => Ok(WitnessingMode::ContentLevel),
            "hybrid" => Ok(WitnessingMode::Hybrid),
            _ => Err(()),
        }
    }
}

/// Granularity for content-level witnessing.
///
/// Controls how text is segmented before hashing into the content Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContentGranularity {
    /// Split on double-newlines (blank lines). Best for prose.
    #[default]
    Paragraph,
    /// Split on sentence boundaries (period/question/exclamation + space).
    /// Finer granularity, larger proofs.
    Sentence,
    /// Split on single newlines. Best for code, poetry, screenplays.
    Block,
}

impl ContentGranularity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContentGranularity::Paragraph => "paragraph",
            ContentGranularity::Sentence => "sentence",
            ContentGranularity::Block => "block",
        }
    }
}

impl std::str::FromStr for ContentGranularity {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "paragraph" => Ok(ContentGranularity::Paragraph),
            "sentence" => Ok(ContentGranularity::Sentence),
            "block" => Ok(ContentGranularity::Block),
            _ => Err(()),
        }
    }
}

/// How a writing application stores its content on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePattern {
    /// Documents are saved as ordinary files; the sentinel discovers them
    /// through the Accessibility `AXDocument` attribute or FSEvents.
    FileBased,
    /// Content lives inside an app group container (`~/Library/Group Containers/…`).
    /// The container path is provided so it can be watched directly.
    ContainerBased,
    /// Content is managed in an iCloud drive library
    /// (`~/Library/Mobile Documents/…`). The library path is watched.
    CloudLibrary,
    /// Content is stored in a private SQLite database or proprietary format
    /// inside the app's sandbox. The sentinel watches the container for any
    /// change activity; document identity comes from the window title.
    DatabaseBacked,
    /// Content is stored in a macOS package/bundle directory (e.g. `.scriv`, `.fdx`).
    /// The sentinel watches the bundle root via `AXDocument` and additionally
    /// registers a recursive FSEvents watcher on the bundle's internal content
    /// subtree so per-chapter edits contribute to the parent session.
    BundleBased,
}

/// Variant of title-format parser to use for a specific app.
///
/// Each variant encodes app-specific knowledge about how the app formats its
/// window title so the sentinel can extract the document name or path without
/// falling through to the generic separator loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
#[serde(rename_all = "snake_case")]
pub enum TitleParserVariant {
    /// Generic separator-based extraction (default).
    #[default]
    Generic,
    /// BBEdit: `"filename — /full/path/to/file"` — the right segment is the absolute path.
    BBEdit,
    /// Obsidian: `"Note Title - Vault Name"` — left is the note, right is vault (not a path).
    Obsidian,
    /// VS Code / VS Code Insiders: `"filename - folder - Visual Studio Code"` — first segment only.
    VSCode,
    /// Nova: `"filename · Nova"` — split on `" · "`, take left.
    Nova,
    /// Terminal emulators running editors. Parses titles like:
    /// - `"filename (+) - VIM"`, `"filename - GNU nano 8.0"`
    /// - `"vim — filename — 80×24"` (Terminal.app format)
    /// - `"filename - GNU Emacs at host"`
    TerminalEditor,
}


/// Confidence level from auto-discovery probing.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeConfidence {
    /// App was running and AX probe succeeded.
    High,
    /// Filesystem heuristics matched but app was not running.
    Medium,
    /// Defaulted to FileBased with no other signals.
    Low,
}

/// Metadata about a writing application known to WritersProof.
#[derive(Debug, Clone)]
pub struct WritingApp {
    /// macOS `CFBundleIdentifier` (case-insensitive matching).
    pub bundle_id: &'static str,
    /// Human-readable application name.
    pub display_name: &'static str,
    /// How the app stores its documents.
    pub storage: StoragePattern,
    /// Paths relative to `$HOME` that the file watcher should observe.
    /// These supplement (or replace) ordinary `AXDocument`-derived paths.
    pub container_paths: &'static [&'static str],
    /// When `true`, the sentinel will accept bare document names from the
    /// window title even without a recognised file extension.
    pub needs_title_inference: bool,
    /// Override the default debounce interval (in milliseconds) for this app.
    ///
    /// `None` means use the global sentinel default. `DatabaseBacked` apps
    /// benefit from a shorter debounce (≈50 ms) because their storage events
    /// fire at high frequency; `BundleBased` apps need a longer window (≈300 ms)
    /// to avoid triggering on intermediate compile/save operations.
    pub default_debounce_ms: Option<u64>,
    /// Which title-format parser to use when inferring the document path from
    /// the window title. `Generic` covers the common `"name - App"` pattern;
    /// app-specific variants handle known stable formats.
    pub title_parser: TitleParserVariant,
    /// How the engine witnesses content for this app. `Auto` selects based on
    /// `storage`. Users can override per-app in settings.
    pub witnessing_mode: WitnessingMode,
}

/// A user-added writing application, persisted to `user_apps.json`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UserWritingApp {
    pub bundle_id: String,
    pub display_name: String,
    pub storage: StoragePattern,
    pub container_paths: Vec<String>,
    pub needs_title_inference: bool,
    #[serde(default)]
    pub default_debounce_ms: Option<u64>,
    #[serde(default)]
    pub title_parser: TitleParserVariant,
    #[serde(default)]
    pub witnessing_mode: WitnessingMode,
    /// When this entry was added (Unix timestamp in JSON).
    #[serde(with = "system_time_serde")]
    pub added_at: SystemTime,
    pub probe_confidence: ProbeConfidence,
}

/// All writing applications known to WritersProof.
///
/// Order does not matter; searched by `bundle_id` (case-insensitive).
pub static KNOWN_WRITING_APPS: &[WritingApp] = &[
    // ── Microsoft ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.microsoft.Word",
        display_name: "Microsoft Word",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.microsoft.onenote.mac",
        display_name: "Microsoft OneNote",
        storage: StoragePattern::ContainerBased,
        container_paths: &[
            "Library/Containers/com.microsoft.onenote.mac/Data/Library/Application Support",
        ],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Apple iWork ────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.apple.iWork.Pages",
        display_name: "Pages",
        storage: StoragePattern::CloudLibrary,
        container_paths: &["Library/Mobile Documents/com~apple~Pages/Documents"],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Ulysses ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.ulyssesapp.mac",
        display_name: "Ulysses",
        storage: StoragePattern::CloudLibrary,
        container_paths: &[
            "Library/Mobile Documents/X5AZV975AG~com~soulmen~ulysses3/Documents",
            "Library/Containers/com.ulyssesapp.mac/Data/Library/Application Support/Ulysses",
        ],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Bear ────────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "net.shinyfrog.bear",
        display_name: "Bear",
        storage: StoragePattern::DatabaseBacked,
        container_paths: &[
            "Library/Group Containers/9K33E3U3T4.com.shinyfrog.bear/Application Data",
        ],
        needs_title_inference: true,
        default_debounce_ms: Some(50),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── iA Writer ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "pro.writer.mac",
        display_name: "iA Writer",
        storage: StoragePattern::FileBased,
        container_paths: &["Library/Mobile Documents/pro~writer~mac/Documents"],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Scrivener ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.literatureandlatte.scrivener3",
        display_name: "Scrivener",
        storage: StoragePattern::BundleBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: Some(300),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Vellum ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.180g.vellum",
        display_name: "Vellum",
        storage: StoragePattern::BundleBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: Some(300),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Affinity Publisher ─────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.seriflabs.affinitypublisher",
        display_name: "Affinity Publisher",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.seriflabs.affinitypublisher2",
        display_name: "Affinity Publisher 2",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Drafts ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.agiletortoise.Drafts-OSX",
        display_name: "Drafts",
        storage: StoragePattern::ContainerBased,
        container_paths: &[
            "Library/Group Containers/com.agiletortoise.Drafts-Shared",
            "Library/Mobile Documents/iCloud~com~agiletortoise~Drafts5/Documents",
        ],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Craft ──────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.luki.paper.mac",
        display_name: "Craft",
        storage: StoragePattern::ContainerBased,
        container_paths: &[
            "Library/Containers/com.luki.paper.mac/Data/Library/Application Support/Craft",
        ],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Highland 2 ─────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.quoteunquoteapps.highland2",
        display_name: "Highland 2",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Final Draft ────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.finaldraft.mac.finaldraft10",
        display_name: "Final Draft",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.finaldraft.mac.fd11",
        display_name: "Final Draft 11",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.finaldraft.mac.fd12",
        display_name: "Final Draft 12",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.finaldraft.mac.fd13",
        display_name: "Final Draft 13",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Fade In ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.moviemagic.fadein",
        display_name: "Fade In",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Hemingway Editor ───────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.hemingwayapp.hemingway",
        display_name: "Hemingway Editor",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true, // Electron; exposes limited AX info
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.typora.Typora",
        display_name: "Typora",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── MarkText ───────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.github.marktext",
        display_name: "MarkText",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Obsidian ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "md.obsidian",
        display_name: "Obsidian",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Obsidian,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Typora ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "abnerworks.Typora",
        display_name: "Typora",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Zettlr ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.zettlr.app",
        display_name: "Zettlr",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Logseq ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.logseq.logseq",
        display_name: "Logseq",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Notion ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.notion.id",
        display_name: "Notion",
        storage: StoragePattern::ContainerBased,
        container_paths: &[
            "Library/Application Support/Notion",
        ],
        needs_title_inference: true,
        default_debounce_ms: Some(50),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.notion.Notion",
        display_name: "Notion",
        storage: StoragePattern::ContainerBased,
        container_paths: &[
            "Library/Containers/com.notion.Notion/Data/Library/Application Support/Notion",
        ],
        needs_title_inference: true,
        default_debounce_ms: Some(50),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Figma ──────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.figma.Desktop",
        display_name: "Figma",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Cursor ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.todesktop.230313mzl4w4u92",
        display_name: "Cursor",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::VSCode,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── VS Code ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.microsoft.VSCode",
        display_name: "Visual Studio Code",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::VSCode,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.microsoft.VSCodeInsiders",
        display_name: "VS Code Insiders",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::VSCode,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Noteship ───────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.red-sweater.noteship",
        display_name: "Noteship",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Notebooks ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.alfonsschmid.Notebooks",
        display_name: "Notebooks",
        storage: StoragePattern::FileBased,
        container_paths: &["Library/Mobile Documents/com~alfonsschmid~Notebooks/Documents"],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Mellel ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.redlers.mellel",
        display_name: "Mellel",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Nisus Writer ───────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.nisus.NisusWriter",
        display_name: "Nisus Writer Pro",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── TextEdit (built-in) ────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.apple.TextEdit",
        display_name: "TextEdit",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── BBEdit ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.barebones.bbedit",
        display_name: "BBEdit",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::BBEdit,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Ghostwriter ────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "io.github.wereturtle.ghostwriter",
        display_name: "Ghostwriter",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Manuskript ─────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.olivierkes.manuskript",
        display_name: "Manuskript",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── LibreOffice Writer ─────────────────────────────────────────────────
    WritingApp {
        bundle_id: "org.libreoffice.script",
        display_name: "LibreOffice",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Marked 2 (preview app; writers use it with other editors) ──────────
    WritingApp {
        bundle_id: "com.brettterpstra.marked2",
        display_name: "Marked 2",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Taskpaper ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.hogbaysoftware.TaskPaper3",
        display_name: "TaskPaper",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── FoldingText ────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.foldingtext.FoldingText",
        display_name: "FoldingText",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Byword ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.metaclassy.byword",
        display_name: "Byword",
        storage: StoragePattern::FileBased,
        container_paths: &["Library/Mobile Documents/com~metaclassy~byword/Documents"],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Markdown Editor ────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.markdowneditor.mac",
        display_name: "Markdown Editor",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Coppice ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.mekentosj.coppice",
        display_name: "Coppice",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Bike Outliner ──────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.hogbaysoftware.Bike",
        display_name: "Bike Outliner",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── OmniOutliner ───────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.omnigroup.OmniOutliner5",
        display_name: "OmniOutliner",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Celtx (web, but has a desktop wrapper) ─────────────────────────────
    WritingApp {
        bundle_id: "com.celtx.mac",
        display_name: "Celtx",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Apple Notes ────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.apple.Notes",
        display_name: "Apple Notes",
        storage: StoragePattern::DatabaseBacked,
        container_paths: &[
            "Library/Group Containers/group.com.apple.notes",
            "Library/Containers/com.apple.Notes/Data/Library/Notes",
        ],
        needs_title_inference: true,
        default_debounce_ms: Some(50),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Sublime Text ───────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.sublimetext.4",
        display_name: "Sublime Text",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.sublimetext.3",
        display_name: "Sublime Text 3",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Nova ───────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.panic.Nova",
        display_name: "Nova",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Nova,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Storyist ───────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.storyist.mac",
        display_name: "Storyist",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── WriteRoom ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.hogbaysoftware.WriteRoom",
        display_name: "WriteRoom",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── OmmWriter ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.ommwriter.ommwriter",
        display_name: "OmmWriter",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true, // limited AX support
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Warp (modern terminal — vim/emacs authors) ─────────────────────────
    WritingApp {
        bundle_id: "dev.warp.Warp-Stable",
        display_name: "Warp",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true, // title shows cwd / running command
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Adobe InDesign ─────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.adobe.InDesign",
        display_name: "Adobe InDesign",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Keynote ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.apple.iWork.Keynote",
        display_name: "Keynote",
        storage: StoragePattern::CloudLibrary,
        container_paths: &["Library/Mobile Documents/com~apple~Keynote/Documents"],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── PowerPoint ─────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.microsoft.Powerpoint",
        display_name: "Microsoft PowerPoint",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Apple Mail ─────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.apple.mail",
        display_name: "Apple Mail",
        storage: StoragePattern::ContainerBased,
        container_paths: &[],
        needs_title_inference: true, // compose windows only expose subject
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Microsoft Outlook ──────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.microsoft.Outlook",
        display_name: "Microsoft Outlook",
        storage: StoragePattern::ContainerBased,
        container_paths: &["Library/Group Containers/UBF8T346G9.Office/Outlook"],
        needs_title_inference: true, // compose windows only expose subject
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── TeXShop ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "TeXShop",
        display_name: "TeXShop",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Texpad ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.vallettaventures.Texpad",
        display_name: "Texpad",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Craft ──────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.lukilabs.lukiapp",
        display_name: "Craft",
        storage: StoragePattern::ContainerBased,
        container_paths: &[
            "Library/Group Containers/group.com.lukilabs.lukiapp",
        ],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Day One ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.bloombuilt.dayone-mac",
        display_name: "Day One",
        storage: StoragePattern::DatabaseBacked,
        container_paths: &[
            "Library/Group Containers/5U8NS4GX82.com.bloombuilt.dayone",
        ],
        needs_title_inference: true,
        default_debounce_ms: Some(50),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── MacDown ────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.uranusjr.macdown",
        display_name: "MacDown",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── GoodNotes ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.goodnotesapp.x",
        display_name: "GoodNotes",
        storage: StoragePattern::CloudLibrary,
        container_paths: &[
            "Library/Mobile Documents/iCloud~com~goodnotesapp~x/Documents",
        ],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── CotEditor ──────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.coteditor.CotEditor",
        display_name: "CotEditor",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── MacVim ─────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "org.vim.MacVim",
        display_name: "MacVim",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Zed ────────────────────────────────────────────────────────────────
    WritingApp {
        bundle_id: "dev.zed.Zed",
        display_name: "Zed",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::VSCode,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "dev.zed.Zed-Preview",
        display_name: "Zed Preview",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::VSCode,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Terminal Emulators ────────────────────────────────────────────────
    WritingApp {
        bundle_id: "com.apple.Terminal",
        display_name: "Terminal",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::TerminalEditor,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.googlecode.iterm2",
        display_name: "iTerm2",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::TerminalEditor,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.github.wez.wezterm",
        display_name: "WezTerm",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::TerminalEditor,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "net.kovidgoyal.kitty",
        display_name: "Kitty",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::TerminalEditor,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "io.alacritty",
        display_name: "Alacritty",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::TerminalEditor,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "dev.warp.Warp-Stable",
        display_name: "Warp",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::TerminalEditor,
        witnessing_mode: WitnessingMode::Auto,
    },
    // ── Opaque Container Apps (content-level witnessing) ──────────────────
    WritingApp {
        bundle_id: "com.eastgate.Tinderbox-11",
        display_name: "Tinderbox",
        storage: StoragePattern::DatabaseBacked,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: Some(300),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::ContentLevel,
    },
    WritingApp {
        bundle_id: "com.devon-technologies.think3",
        display_name: "DEVONthink 3",
        storage: StoragePattern::DatabaseBacked,
        container_paths: &[
            "Library/Application Support/DEVONthink 3",
        ],
        needs_title_inference: true,
        default_debounce_ms: Some(50),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::ContentLevel,
    },
    // ── Additional Writing & Note Apps ────────────────────────────────────
    WritingApp {
        bundle_id: "com.grammarly.ProjectLlama",
        display_name: "Grammarly",
        storage: StoragePattern::ContainerBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: Some(50),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.writefull.writefull",
        display_name: "Writefull",
        storage: StoragePattern::ContainerBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.prowritingaid.prowritingaid",
        display_name: "ProWritingAid",
        storage: StoragePattern::ContainerBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "org.mozilla.thunderbird",
        display_name: "Thunderbird",
        storage: StoragePattern::ContainerBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.apple.Reminders",
        display_name: "Reminders",
        storage: StoragePattern::DatabaseBacked,
        container_paths: &["Library/Reminders"],
        needs_title_inference: true,
        default_debounce_ms: Some(50),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.goodnotesapp.GoodNotes5",
        display_name: "GoodNotes 5",
        storage: StoragePattern::CloudLibrary,
        container_paths: &[
            "Library/Group Containers/group.com.goodnotesapp.x",
        ],
        needs_title_inference: true,
        default_debounce_ms: Some(100),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::ContentLevel,
    },
    WritingApp {
        bundle_id: "com.apple.freeform",
        display_name: "Freeform",
        storage: StoragePattern::DatabaseBacked,
        container_paths: &["Library/Containers/com.apple.freeform/Data"],
        needs_title_inference: true,
        default_debounce_ms: Some(100),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::ContentLevel,
    },
    WritingApp {
        bundle_id: "com.jetbrains.intellij",
        display_name: "IntelliJ IDEA",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::VSCode,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.jetbrains.WebStorm",
        display_name: "WebStorm",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::VSCode,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.jetbrains.pycharm",
        display_name: "PyCharm",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::VSCode,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.jetbrains.goland",
        display_name: "GoLand",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::VSCode,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.jetbrains.rustrover",
        display_name: "RustRover",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::VSCode,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.apple.dt.Xcode",
        display_name: "Xcode",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.github.atom",
        display_name: "Atom",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::VSCode,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.noteship.app",
        display_name: "Noteship",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.atticus.mac",
        display_name: "Atticus",
        storage: StoragePattern::ContainerBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.dabblewriter.Dabble",
        display_name: "Dabble",
        storage: StoragePattern::ContainerBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.iawriter.mac",
        display_name: "iA Writer",
        storage: StoragePattern::CloudLibrary,
        container_paths: &[
            "Library/Mobile Documents/27N4MQEA55~pro~writer/Documents",
        ],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "app.novelai.desktop",
        display_name: "NovelAI",
        storage: StoragePattern::ContainerBased,
        container_paths: &[],
        needs_title_inference: true,
        default_debounce_ms: Some(50),
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
    WritingApp {
        bundle_id: "com.apptorium.Pockity",
        display_name: "Pockity",
        storage: StoragePattern::FileBased,
        container_paths: &[],
        needs_title_inference: false,
        default_debounce_ms: None,
        title_parser: TitleParserVariant::Generic,
        witnessing_mode: WitnessingMode::Auto,
    },
];

// ---------------------------------------------------------------------------
// Global registry (installed once at sentinel startup)
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

/// Global registry instance, set by `install_global()` during sentinel init.
/// Before installation, the static `lookup()` / `needs_title_inference()`
/// functions only search `KNOWN_WRITING_APPS`. After installation, user-added
/// apps are included in all lookups.
static GLOBAL_REGISTRY: OnceLock<AppRegistry> = OnceLock::new();

// ---------------------------------------------------------------------------
// Adaptive app detection
// ---------------------------------------------------------------------------

use dashmap::DashMap;

/// Runtime cache of auto-discovered writing apps. Apps are added here when the
/// user types 20+ keystrokes into an unknown app that has an AX text area.
/// Persisted to `user_apps.json` via `flush_discovered_apps()`.
static AUTO_DISCOVERED: OnceLock<DashMap<String, AutoDiscoveredApp>> = OnceLock::new();

fn auto_discovered() -> &'static DashMap<String, AutoDiscoveredApp> {
    AUTO_DISCOVERED.get_or_init(DashMap::new)
}

/// Apps where typing is never authorship-relevant (system UI, media, utilities).
/// Browsers, terminals, chat apps, and video conferencing are intentionally
/// NOT excluded: users write in web editors, compose social posts, draft
/// messages, and code in terminals.
const NON_WRITING_BUNDLES: &[&str] = &[
    "com.apple.finder",
    "com.apple.systempreferences",
    "com.apple.SystemPreferences",
    "com.apple.ActivityMonitor",
    "com.apple.Calculator",
    "com.apple.Spotlight",
    "com.apple.launchpad.launcher",
    "com.apple.loginwindow",
    "com.apple.screencaptureui",
    "com.apple.dock",
    "com.apple.Music",
    "com.apple.Photos",
    "com.apple.AppStore",
    "com.apple.archiveutility",
    "com.apple.DiskUtility",
    "com.apple.keychainaccess",
    "com.spotify.client",
    "com.1password.1password",
    "com.bitwarden.desktop",
    "com.lastpass.LastPass",
    "com.vmware.fusion",
    "com.parallels.desktop.console",
];

#[derive(Debug, Clone)]
struct AutoDiscoveredApp {
    display_name: String,
    storage: StoragePattern,
    needs_title_inference: bool,
    probe_confidence: ProbeConfidence,
}

/// Probe an unknown app's AX capabilities and cache the metadata.
///
/// This does NOT register the app as a "writing app" — per-session forensic
/// scoring already determines whether a session is real authorship. This
/// probe detects `needs_title_inference` and storage pattern so virtual
/// sessions work correctly for apps that lack AXDocument.
///
/// The cache is session-scoped (lives in memory, not persisted to
/// `user_apps.json`). Each launch re-probes on first encounter.
pub fn probe_and_cache(bundle_id: &str, app_name: &str) {
    if bundle_id.is_empty() {
        return;
    }
    let key = bundle_id.to_lowercase();
    if auto_discovered().contains_key(&key) || is_builtin_or_user(&key) {
        return;
    }
    if NON_WRITING_BUNDLES.iter().any(|b| b.eq_ignore_ascii_case(&key)) {
        return;
    }
    let probe = super::app_discovery::probe_app(bundle_id);
    log::info!(
        "Probed unknown app: {} ({}) storage={:?} title_infer={} confidence={:?}",
        probe.display_name, bundle_id, probe.storage,
        probe.needs_title_inference, probe.confidence,
    );
    auto_discovered().insert(key, AutoDiscoveredApp {
        display_name: if probe.display_name == bundle_id {
            app_name.to_string()
        } else {
            probe.display_name
        },
        storage: probe.storage,
        needs_title_inference: probe.needs_title_inference,
        probe_confidence: probe.confidence,
    });
}

/// Check if a bundle ID is in the builtin or user-added registry
/// (excluding auto-discovered cache).
fn is_builtin_or_user(bundle_id: &str) -> bool {
    if lookup(bundle_id).is_some() {
        return true;
    }
    if let Some(reg) = GLOBAL_REGISTRY.get() {
        return reg.is_known(bundle_id);
    }
    false
}

/// Check if an app was auto-discovered at runtime.
pub fn is_auto_discovered(bundle_id: &str) -> bool {
    auto_discovered().contains_key(&bundle_id.to_lowercase())
}

/// Return whether an auto-discovered app needs title inference.
pub fn auto_discovered_needs_title_inference(bundle_id: &str) -> bool {
    auto_discovered()
        .get(&bundle_id.to_lowercase())
        .map(|a| a.needs_title_inference)
        .unwrap_or(false)
}

/// Flush auto-discovered apps into the persistent user app registry.
/// Call on sentinel shutdown to persist discoveries across sessions.
pub fn flush_discovered_apps() {
    let Some(reg) = GLOBAL_REGISTRY.get() else { return };
    let discovered = auto_discovered();
    if discovered.is_empty() {
        return;
    }
    let data_dir = &reg.data_dir;
    let mut fresh_reg = AppRegistry::load(data_dir);
    let mut count = 0usize;
    for entry in discovered.iter() {
        let bundle_id = entry.key();
        let app = entry.value();
        let user_app = UserWritingApp {
            bundle_id: bundle_id.clone(),
            display_name: app.display_name.clone(),
            storage: app.storage,
            container_paths: Vec::new(),
            needs_title_inference: app.needs_title_inference,
            default_debounce_ms: None,
            title_parser: TitleParserVariant::Generic,
            witnessing_mode: WitnessingMode::Auto,
            added_at: SystemTime::now(),
            probe_confidence: app.probe_confidence,
        };
        if let Err(e) = fresh_reg.add_user_app(user_app) {
            log::warn!("Failed to persist auto-discovered app {bundle_id}: {e}");
        } else {
            count += 1;
        }
    }
    if count > 0 {
        log::info!("Flushed {count} auto-discovered apps to user registry");
    }
}

/// Install a loaded `AppRegistry` as the global instance.
///
/// Called once during sentinel startup. Subsequent calls are no-ops (the
/// first registry wins). This bridges the gap between the instance-based
/// `AppRegistry` and the static free functions used throughout the codebase.
pub fn install_global(registry: AppRegistry) {
    let _ = GLOBAL_REGISTRY.set(registry);
}

/// Look up a `WritingApp` by bundle ID (case-insensitive).
///
/// Checks user-added apps (via global registry) first, then builtins.
pub fn lookup(bundle_id: &str) -> Option<&'static WritingApp> {
    KNOWN_WRITING_APPS
        .iter()
        .find(|a| a.bundle_id.eq_ignore_ascii_case(bundle_id))
}

/// Return the `TitleParserVariant` for a bundle ID.
///
/// Checks the global registry (user overrides) first, then builtins.
pub fn title_parser_for(bundle_id: &str) -> TitleParserVariant {
    if let Some(reg) = GLOBAL_REGISTRY.get() {
        return reg.title_parser_for(bundle_id);
    }
    lookup(bundle_id)
        .map(|a| a.title_parser)
        .unwrap_or(TitleParserVariant::Generic)
}

/// Return paths (relative to `$HOME`) of all writing-app containers that
/// exist on the current system.
///
/// Used at sentinel startup to extend the file-watch list so that apps like
/// Ulysses and Bear produce file-change events even when their storage is not
/// in an ordinary `~/Documents` folder.
pub fn auto_watch_paths() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };

    let mut paths = Vec::new();
    for app in KNOWN_WRITING_APPS {
        for rel in app.container_paths {
            let abs = home.join(rel);
            if abs.exists() {
                paths.push(abs);
            }
        }
    }

    // Deduplicate (multiple apps may share a prefix).
    paths.sort();
    paths.dedup();
    paths
}

/// Return whether `bundle_id` belongs to a known writing app that requires
/// title-based document identity (i.e., does not expose `AXDocument`).
///
/// Checks user-added apps (via global registry) first, then builtins,
/// then auto-discovered apps.
pub fn needs_title_inference(bundle_id: &str) -> bool {
    if let Some(reg) = GLOBAL_REGISTRY.get() {
        if reg.is_known(bundle_id) {
            return reg.needs_title_inference(bundle_id);
        }
    }
    if let Some(builtin) = lookup(bundle_id) {
        return builtin.needs_title_inference;
    }
    auto_discovered_needs_title_inference(bundle_id)
}

/// Return whether `bundle_id` is recognized by builtins, user apps, or
/// auto-discovered apps.
pub fn is_known(bundle_id: &str) -> bool {
    if let Some(reg) = GLOBAL_REGISTRY.get() {
        if reg.is_known(bundle_id) {
            return true;
        }
    }
    if lookup(bundle_id).is_some() {
        return true;
    }
    is_auto_discovered(bundle_id)
}

// ---------------------------------------------------------------------------
// Persistence schema
// ---------------------------------------------------------------------------

const USER_APPS_SCHEMA_VERSION: u32 = 1;
const USER_APPS_FILENAME: &str = "user_apps.json";

#[derive(Deserialize)]
struct UserAppsFile {
    schema_version: u32,
    apps: Vec<UserWritingApp>,
}

mod system_time_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn serialize<S: Serializer>(time: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        time.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(UNIX_EPOCH + Duration::from_secs(secs))
    }
}

// ---------------------------------------------------------------------------
// Unified registry
// ---------------------------------------------------------------------------

/// Merges built-in and user-added writing apps into a single queryable
/// registry with JSON persistence and a precomputed title-inference set.
#[derive(Debug)]
pub struct AppRegistry {
    builtin: &'static [WritingApp],
    user: Vec<UserWritingApp>,
    /// Lowercase bundle IDs that need title-based document inference.
    title_inferred: HashSet<String>,
    data_dir: PathBuf,
}

impl AppRegistry {
    /// Load the registry from `data_dir/user_apps.json`.
    ///
    /// Missing file → empty user list. Malformed file → backup + empty list.
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(USER_APPS_FILENAME);
        let user = match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<UserAppsFile>(&contents) {
                Ok(file) if file.schema_version >= USER_APPS_SCHEMA_VERSION => {
                    if file.schema_version > USER_APPS_SCHEMA_VERSION {
                        log::warn!(
                            "user_apps.json schema_version {} (this build knows {}); \
                             loading anyway — unknown fields ignored",
                            file.schema_version,
                            USER_APPS_SCHEMA_VERSION
                        );
                    }
                    file.apps
                }
                Ok(file) => {
                    log::warn!(
                        "user_apps.json schema_version {} unsupported (expected >= {}); \
                         treating as empty",
                        file.schema_version,
                        USER_APPS_SCHEMA_VERSION
                    );
                    Vec::new()
                }
                Err(e) => {
                    log::error!("malformed user_apps.json: {e}; backing up");
                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let backup = path.with_extension(format!("json.corrupt.{ts}"));
                    if let Err(e2) = std::fs::rename(&path, &backup) {
                        log::error!("backup rename failed: {e2}");
                    }
                    Vec::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                log::error!("read user_apps.json: {e}; treating as empty");
                Vec::new()
            }
        };

        for app in &user {
            log::info!(
                "custom app loaded: {} ({}) storage={:?} title_inference={}",
                app.display_name,
                app.bundle_id,
                app.storage,
                app.needs_title_inference,
            );
        }

        let mut reg = Self {
            builtin: KNOWN_WRITING_APPS,
            user,
            title_inferred: HashSet::new(),
            data_dir: data_dir.to_path_buf(),
        };
        reg.rebuild_title_inferred();
        reg
    }

    /// Whether `bundle_id` requires title-based document inference.
    ///
    /// Replaces the static `TITLE_INFERRED_APPS` constant with a runtime
    /// query over the merged built-in + user app set.
    pub fn needs_title_inference(&self, bundle_id: &str) -> bool {
        self.title_inferred
            .contains(&bundle_id.to_ascii_lowercase())
    }

    /// Look up a built-in app by bundle ID (case-insensitive).
    pub fn lookup_builtin(&self, bundle_id: &str) -> Option<&'static WritingApp> {
        self.builtin
            .iter()
            .find(|a| a.bundle_id.eq_ignore_ascii_case(bundle_id))
    }

    /// Look up a user-added app by bundle ID (case-insensitive).
    pub fn lookup_user(&self, bundle_id: &str) -> Option<&UserWritingApp> {
        self.user
            .iter()
            .find(|a| a.bundle_id.eq_ignore_ascii_case(bundle_id))
    }

    /// Return the `TitleParserVariant` for a bundle ID, checking user apps
    /// first (user overrides builtin) then builtins.
    pub fn title_parser_for(&self, bundle_id: &str) -> TitleParserVariant {
        if let Some(user_app) = self.lookup_user(bundle_id) {
            return user_app.title_parser;
        }
        self.lookup_builtin(bundle_id)
            .map(|a| a.title_parser)
            .unwrap_or(TitleParserVariant::Generic)
    }

    /// Container watch paths from both built-in and user apps.
    pub fn auto_watch_paths(&self) -> Vec<PathBuf> {
        let Some(home) = dirs::home_dir() else {
            return Vec::new();
        };
        let mut paths = Vec::new();
        for app in self.builtin {
            for rel in app.container_paths {
                let abs = home.join(rel);
                if abs.exists() {
                    paths.push(abs);
                }
            }
        }
        for app in &self.user {
            for rel in &app.container_paths {
                let abs = home.join(rel);
                if abs.exists() {
                    paths.push(abs);
                }
            }
        }
        paths.sort();
        paths.dedup();
        paths
    }

    /// Whether `bundle_id` is recognized (either built-in or user-added).
    pub fn is_known(&self, bundle_id: &str) -> bool {
        self.lookup_builtin(bundle_id).is_some() || self.lookup_user(bundle_id).is_some()
    }

    /// Add (or replace) a user app. Writes to disk before updating memory,
    /// so on IO failure the in-memory state is never inconsistent.
    pub fn add_user_app(&mut self, app: UserWritingApp) -> crate::error::Result<()> {
        if app.bundle_id.is_empty() {
            return Err(crate::error::Error::validation(
                "bundle_id must not be empty",
            ));
        }
        if app.display_name.is_empty() {
            return Err(crate::error::Error::validation(
                "display_name must not be empty",
            ));
        }
        let mut next = self.user.clone();
        next.retain(|a| !a.bundle_id.eq_ignore_ascii_case(&app.bundle_id));
        next.push(app);
        self.persist(&next)?;
        self.user = next;
        self.rebuild_title_inferred();
        Ok(())
    }

    /// Remove a user app by bundle ID. Returns whether an entry was removed.
    /// Writes to disk before updating memory.
    pub fn remove_user_app(&mut self, bundle_id: &str) -> crate::error::Result<bool> {
        let mut next = self.user.clone();
        next.retain(|a| !a.bundle_id.eq_ignore_ascii_case(bundle_id));
        if next.len() == self.user.len() {
            return Ok(false);
        }
        self.persist(&next)?;
        self.user = next;
        self.rebuild_title_inferred();
        Ok(true)
    }

    pub fn user_apps(&self) -> &[UserWritingApp] {
        &self.user
    }

    fn rebuild_title_inferred(&mut self) {
        self.title_inferred.clear();
        for app in self.builtin {
            if app.needs_title_inference {
                self.title_inferred
                    .insert(app.bundle_id.to_ascii_lowercase());
            }
        }
        for app in &self.user {
            let key = app.bundle_id.to_ascii_lowercase();
            if app.needs_title_inference {
                self.title_inferred.insert(key);
            } else {
                // User override removes builtin entry.
                self.title_inferred.remove(&key);
            }
        }
    }

    /// Serialize `apps` to disk. Borrows the slice to avoid cloning.
    fn persist(&self, apps: &[UserWritingApp]) -> crate::error::Result<()> {
        #[derive(Serialize)]
        struct Wire<'a> {
            schema_version: u32,
            apps: &'a [UserWritingApp],
        }
        let json = serde_json::to_string_pretty(&Wire {
            schema_version: USER_APPS_SCHEMA_VERSION,
            apps,
        })
        .map_err(|e| crate::error::Error::config(format!("serialize user apps: {e}")))?;
        let path = self.user_apps_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::crypto::atomic_write(&path, json.as_bytes())?;
        Ok(())
    }

    fn user_apps_path(&self) -> PathBuf {
        self.data_dir.join(USER_APPS_FILENAME)
    }
}

// ---------------------------------------------------------------------------
// App-specific compile/export adapter
// ---------------------------------------------------------------------------

/// Per-app knowledge about compile pipelines and bundle internals.
///
/// Implement this trait for each `BundleBased` writing app to teach the sentinel
/// how to recognise compile helper processes and which bundle subdirectory contains
/// the prose content files.
pub trait AppAdapter: Send + Sync {
    /// The `CFBundleIdentifier` this adapter handles.
    fn bundle_id(&self) -> &str;

    /// Return `true` if `process_name` is a known compile/export helper for this app.
    fn is_compile_process(&self, process_name: &str) -> bool;

    /// Path inside the bundle root where prose content files live, if any.
    /// The sentinel registers a recursive FSEvents watcher on this subdirectory.
    fn internal_docs_path(&self) -> Option<&str>;
}

struct ScrivenerAdapter;
impl AppAdapter for ScrivenerAdapter {
    fn bundle_id(&self) -> &str {
        "com.literatureandlatte.scrivener3"
    }
    fn is_compile_process(&self, process_name: &str) -> bool {
        process_name == "Scrivener" || process_name.contains("scrivener-compile")
    }
    fn internal_docs_path(&self) -> Option<&str> {
        Some("Files/Data")
    }
}

struct FinalDraftAdapter;
impl AppAdapter for FinalDraftAdapter {
    fn bundle_id(&self) -> &str {
        "com.finaldraft.mac.finaldraft10"
    }
    fn is_compile_process(&self, process_name: &str) -> bool {
        process_name == "Final Draft"
            || process_name.contains("FinalDraft")
            || process_name == "PrintToPDF"
            || process_name == "FDCompanion"
    }
    fn internal_docs_path(&self) -> Option<&str> {
        None
    }
}

struct UlyssesAdapter;
impl AppAdapter for UlyssesAdapter {
    fn bundle_id(&self) -> &str {
        "com.ulyssesapp.mac"
    }
    fn is_compile_process(&self, process_name: &str) -> bool {
        process_name == "Ulysses"
    }
    fn internal_docs_path(&self) -> Option<&str> {
        None
    }
}

struct VellumAdapter;
impl AppAdapter for VellumAdapter {
    fn bundle_id(&self) -> &str {
        "com.180g.vellum"
    }
    fn is_compile_process(&self, process_name: &str) -> bool {
        process_name == "Vellum"
    }
    fn internal_docs_path(&self) -> Option<&str> {
        None
    }
}

struct TinderboxAdapter;
impl AppAdapter for TinderboxAdapter {
    fn bundle_id(&self) -> &str {
        "com.eastgate.Tinderbox-11"
    }
    fn is_compile_process(&self, process_name: &str) -> bool {
        process_name == "Tinderbox 11"
    }
    fn internal_docs_path(&self) -> Option<&str> {
        None
    }
}

/// Return a boxed `AppAdapter` for the given bundle ID, or `None` if no adapter exists.
pub fn adapter_for_bundle(bundle_id: &str) -> Option<Box<dyn AppAdapter>> {
    match bundle_id {
        id if id.eq_ignore_ascii_case("com.literatureandlatte.scrivener3") => {
            Some(Box::new(ScrivenerAdapter))
        }
        id if id.eq_ignore_ascii_case("com.finaldraft.mac.finaldraft10")
            || id.eq_ignore_ascii_case("com.finaldraft.mac.fd11")
            || id.eq_ignore_ascii_case("com.finaldraft.mac.fd12")
            || id.eq_ignore_ascii_case("com.finaldraft.mac.fd13") =>
        {
            Some(Box::new(FinalDraftAdapter))
        }
        id if id.eq_ignore_ascii_case("com.ulyssesapp.mac") => Some(Box::new(UlyssesAdapter)),
        id if id.eq_ignore_ascii_case("com.180g.vellum") => Some(Box::new(VellumAdapter)),
        id if id.starts_with("com.eastgate.Tinderbox") => {
            Some(Box::new(TinderboxAdapter))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_known_apps() {
        assert!(lookup("com.ulyssesapp.mac").is_some());
        assert!(lookup("net.shinyfrog.bear").is_some());
        assert!(lookup("com.microsoft.Word").is_some());
        assert!(lookup("com.seriflabs.affinitypublisher").is_some());
        // Case-insensitive
        assert!(lookup("COM.ULYSSESAPP.MAC").is_some());
        // Newly added apps
        assert!(lookup("com.apple.Notes").is_some());
        assert!(lookup("com.sublimetext.4").is_some());
        assert!(lookup("com.panic.Nova").is_some());
        assert!(lookup("com.storyist.mac").is_some());
        assert!(lookup("com.hogbaysoftware.WriteRoom").is_some());
        assert!(lookup("com.ommwriter.ommwriter").is_some());
        assert!(lookup("dev.warp.Warp-Stable").is_some());
        assert!(lookup("com.adobe.InDesign").is_some());
        assert!(lookup("com.apple.iWork.Keynote").is_some());
        assert!(lookup("com.microsoft.Powerpoint").is_some());
        assert!(lookup("com.apple.mail").is_some());
        assert!(lookup("com.microsoft.Outlook").is_some());
        assert!(lookup("TeXShop").is_some());
        assert!(lookup("com.vallettaventures.Texpad").is_some());
        assert!(lookup("com.lukilabs.lukiapp").is_some());
        assert!(lookup("com.bloombuilt.dayone-mac").is_some());
        assert!(lookup("com.uranusjr.macdown").is_some());
        assert!(lookup("com.agiletortoise.Drafts-OSX").is_some());
        assert!(lookup("com.goodnotesapp.x").is_some());
        assert!(lookup("com.coteditor.CotEditor").is_some());
        assert!(lookup("org.vim.MacVim").is_some());
        assert!(lookup("dev.zed.Zed").is_some());
        assert!(lookup("dev.zed.Zed-Preview").is_some());
    }

    #[test]
    fn test_lookup_unknown_app_returns_none() {
        assert!(lookup("com.nonexistent.App").is_none());
    }

    #[test]
    fn test_needs_title_inference() {
        assert!(needs_title_inference("net.shinyfrog.bear"));
        assert!(needs_title_inference("com.ulyssesapp.mac"));
        assert!(!needs_title_inference("com.microsoft.Word"));
        assert!(!needs_title_inference("com.apple.iWork.Pages"));
        // New title-inferred apps
        assert!(needs_title_inference("com.apple.Notes"));
        assert!(needs_title_inference("com.ommwriter.ommwriter"));
        assert!(needs_title_inference("dev.warp.Warp-Stable"));
        assert!(needs_title_inference("com.apple.mail"));
        assert!(needs_title_inference("com.microsoft.Outlook"));
        // New title-inferred apps
        assert!(needs_title_inference("com.lukilabs.lukiapp"));
        assert!(needs_title_inference("com.bloombuilt.dayone-mac"));
        assert!(needs_title_inference("com.agiletortoise.Drafts-OSX"));
        assert!(needs_title_inference("com.goodnotesapp.x"));
        // Zed
        assert!(needs_title_inference("dev.zed.Zed"));
        assert!(needs_title_inference("dev.zed.Zed-Preview"));
        // New file-based apps (should NOT need inference)
        assert!(!needs_title_inference("com.sublimetext.4"));
        assert!(!needs_title_inference("com.panic.Nova"));
        assert!(!needs_title_inference("com.adobe.InDesign"));
        assert!(!needs_title_inference("com.apple.iWork.Keynote"));
        assert!(!needs_title_inference("TeXShop"));
        assert!(!needs_title_inference("com.vallettaventures.Texpad"));
        assert!(!needs_title_inference("com.uranusjr.macdown"));
        assert!(!needs_title_inference("com.coteditor.CotEditor"));
        assert!(!needs_title_inference("org.vim.MacVim"));
    }

    #[test]
    fn test_auto_watch_paths_no_panic() {
        // Should not panic even when none of the paths exist.
        let _ = auto_watch_paths();
    }

    #[test]
    fn test_user_app_serialization_roundtrip() {
        let app = UserWritingApp {
            bundle_id: "com.example.Test".into(),
            display_name: "Test".into(),
            storage: StoragePattern::ContainerBased,
            container_paths: vec!["Library/Containers/com.example.Test".into()],
            needs_title_inference: true,
            added_at: SystemTime::now(),
            probe_confidence: ProbeConfidence::High,
            default_debounce_ms: None,
            title_parser: TitleParserVariant::Generic,
            witnessing_mode: WitnessingMode::Auto,
        };
        let json = serde_json::to_string(&app).unwrap();
        let rt: UserWritingApp = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.bundle_id, "com.example.Test");
        assert_eq!(rt.storage, StoragePattern::ContainerBased);
        assert_eq!(rt.probe_confidence, ProbeConfidence::High);
        assert!(rt.needs_title_inference);
        assert_eq!(rt.container_paths.len(), 1);
    }

    #[test]
    fn test_storage_pattern_serde_names() {
        let json = serde_json::to_string(&StoragePattern::DatabaseBacked).unwrap();
        assert_eq!(json, "\"database_backed\"");
        let rt: StoragePattern = serde_json::from_str("\"cloud_library\"").unwrap();
        assert_eq!(rt, StoragePattern::CloudLibrary);
    }

    #[test]
    fn test_registry_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AppRegistry::load(tmp.path());
        assert!(reg.user_apps().is_empty());
        // Builtins still present
        assert!(reg.lookup_builtin("com.microsoft.Word").is_some());
    }

    #[test]
    fn test_registry_malformed_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("user_apps.json"), "not json{{{").unwrap();
        let reg = AppRegistry::load(tmp.path());
        assert!(reg.user_apps().is_empty());
        // Corrupt backup exists
        let backups: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt"))
            .collect();
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn test_registry_future_schema_version_loads() {
        let tmp = tempfile::tempdir().unwrap();
        // Future versions with additive changes should still load
        let json = r#"{"schema_version": 99, "apps": [
            {"bundle_id":"com.future.App","display_name":"Future",
             "storage":"file_based","container_paths":[],
             "needs_title_inference":false,"added_at":1700000000,
             "probe_confidence":"high"}
        ]}"#;
        std::fs::write(tmp.path().join("user_apps.json"), json).unwrap();
        let reg = AppRegistry::load(tmp.path());
        assert_eq!(reg.user_apps().len(), 1);
        assert_eq!(reg.user_apps()[0].bundle_id, "com.future.App");
    }

    #[test]
    fn test_registry_ancient_schema_version_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("user_apps.json"),
            r#"{"schema_version": 0, "apps": []}"#,
        )
        .unwrap();
        let reg = AppRegistry::load(tmp.path());
        assert!(reg.user_apps().is_empty());
    }

    #[test]
    fn test_add_rejects_empty_bundle_id() {
        let tmp = tempfile::tempdir().unwrap();
        let mut reg = AppRegistry::load(tmp.path());
        let result = reg.add_user_app(UserWritingApp {
            bundle_id: "".into(),
            display_name: "Bad".into(),
            storage: StoragePattern::FileBased,
            container_paths: vec![],
            needs_title_inference: false,
            added_at: SystemTime::now(),
            probe_confidence: ProbeConfidence::Low,
            default_debounce_ms: None,
            title_parser: TitleParserVariant::Generic,
            witnessing_mode: WitnessingMode::Auto,
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_add_rejects_empty_display_name() {
        let tmp = tempfile::tempdir().unwrap();
        let mut reg = AppRegistry::load(tmp.path());
        let result = reg.add_user_app(UserWritingApp {
            bundle_id: "com.example.NoName".into(),
            display_name: "".into(),
            storage: StoragePattern::FileBased,
            container_paths: vec![],
            needs_title_inference: false,
            added_at: SystemTime::now(),
            probe_confidence: ProbeConfidence::Low,
            default_debounce_ms: None,
            title_parser: TitleParserVariant::Generic,
            witnessing_mode: WitnessingMode::Auto,
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_user_overrides_builtin() {
        let tmp = tempfile::tempdir().unwrap();
        let mut reg = AppRegistry::load(tmp.path());
        // Word is builtin with needs_title_inference: false
        assert!(!reg.needs_title_inference("com.microsoft.Word"));

        reg.add_user_app(UserWritingApp {
            bundle_id: "com.microsoft.Word".into(),
            display_name: "Word (custom)".into(),
            storage: StoragePattern::FileBased,
            container_paths: vec![],
            needs_title_inference: true,
            added_at: SystemTime::now(),
            probe_confidence: ProbeConfidence::Medium,
            default_debounce_ms: None,
            title_parser: TitleParserVariant::Generic,
            witnessing_mode: WitnessingMode::Auto,
        })
        .unwrap();

        assert!(reg.needs_title_inference("com.microsoft.Word"));
        assert!(reg.lookup_user("com.microsoft.Word").is_some());
    }

    #[test]
    fn test_registry_add_remove_persist() {
        let tmp = tempfile::tempdir().unwrap();
        let mut reg = AppRegistry::load(tmp.path());

        reg.add_user_app(UserWritingApp {
            bundle_id: "com.example.New".into(),
            display_name: "New App".into(),
            storage: StoragePattern::ContainerBased,
            container_paths: vec!["Library/Containers/com.example.New".into()],
            needs_title_inference: true,
            added_at: SystemTime::now(),
            probe_confidence: ProbeConfidence::Low,
            default_debounce_ms: None,
            title_parser: TitleParserVariant::Generic,
            witnessing_mode: WitnessingMode::Auto,
        })
        .unwrap();
        assert_eq!(reg.user_apps().len(), 1);
        assert!(reg.needs_title_inference("com.example.New"));

        // Reload from disk
        let reg2 = AppRegistry::load(tmp.path());
        assert_eq!(reg2.user_apps().len(), 1);
        assert_eq!(reg2.user_apps()[0].bundle_id, "com.example.New");
        assert!(reg2.needs_title_inference("com.example.New"));

        // Remove
        let mut reg2 = reg2;
        assert!(reg2.remove_user_app("com.example.New").unwrap());
        assert!(reg2.user_apps().is_empty());
        assert!(!reg2.needs_title_inference("com.example.New"));

        // Reload confirms deletion persisted
        let reg3 = AppRegistry::load(tmp.path());
        assert!(reg3.user_apps().is_empty());
    }

    #[test]
    fn test_registry_add_replaces_duplicate() {
        let tmp = tempfile::tempdir().unwrap();
        let mut reg = AppRegistry::load(tmp.path());

        let app = || UserWritingApp {
            bundle_id: "com.example.Dup".into(),
            display_name: "Dup".into(),
            storage: StoragePattern::FileBased,
            container_paths: vec![],
            needs_title_inference: false,
            added_at: SystemTime::now(),
            probe_confidence: ProbeConfidence::Low,
            default_debounce_ms: None,
            title_parser: TitleParserVariant::Generic,
            witnessing_mode: WitnessingMode::Auto,
        };
        reg.add_user_app(app()).unwrap();
        reg.add_user_app(app()).unwrap();
        assert_eq!(reg.user_apps().len(), 1);
    }

    #[test]
    fn test_registry_remove_nonexistent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut reg = AppRegistry::load(tmp.path());
        let removed = reg.remove_user_app("com.nonexistent.App").unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_all_container_apps_have_paths() {
        for app in KNOWN_WRITING_APPS {
            if matches!(
                app.storage,
                StoragePattern::ContainerBased
                    | StoragePattern::CloudLibrary
                    | StoragePattern::DatabaseBacked
            ) {
                assert!(
                    !app.container_paths.is_empty()
                        || app.storage == StoragePattern::ContainerBased,
                    "App '{}' has non-FileBased storage but no container_paths",
                    app.display_name
                );
            }
            // BundleBased apps use AXDocument for the bundle root path; no
            // container_paths are required.
        }
    }

    #[test]
    fn test_vellum_registered() {
        assert!(lookup("com.180g.vellum").is_some());
        let app = lookup("com.180g.vellum").unwrap();
        assert_eq!(app.storage, StoragePattern::BundleBased);
        assert!(!app.needs_title_inference);
    }

    #[test]
    fn test_scrivener_bundle_based() {
        let app = lookup("com.literatureandlatte.scrivener3").unwrap();
        assert_eq!(app.storage, StoragePattern::BundleBased);
    }

    #[test]
    fn test_adapter_for_bundle() {
        let a = adapter_for_bundle("com.literatureandlatte.scrivener3").unwrap();
        assert_eq!(a.internal_docs_path(), Some("Files/Data"));
        assert!(a.is_compile_process("Scrivener"));

        let b = adapter_for_bundle("com.180g.vellum").unwrap();
        assert!(b.is_compile_process("Vellum"));
        assert_eq!(b.internal_docs_path(), None);

        assert!(adapter_for_bundle("com.nonexistent.App").is_none());
    }

    #[test]
    fn test_bundle_based_serde() {
        let json = serde_json::to_string(&StoragePattern::BundleBased).unwrap();
        assert_eq!(json, "\"bundle_based\"");
        let rt: StoragePattern = serde_json::from_str("\"bundle_based\"").unwrap();
        assert_eq!(rt, StoragePattern::BundleBased);
    }
}
