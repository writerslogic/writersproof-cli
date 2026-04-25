// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

pub use crate::crypto::ObfuscatedString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusEventType {
    FocusGained,
    FocusLost,
    FocusUnknown,
}

#[derive(Debug, Clone)]
pub struct FocusEvent {
    pub event_type: FocusEventType,
    pub path: String,
    pub shadow_id: String,
    pub app_bundle_id: String,
    pub app_name: String,
    pub window_title: ObfuscatedString,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeEventType {
    Modified,
    Saved,
    Created,
    Deleted,
    /// File was renamed/moved. `new_path` is the destination.
    Renamed {
        new_path: String,
    },
}

#[derive(Debug, Clone)]
pub struct ChangeEvent {
    pub event_type: ChangeEventType,
    pub path: String,
    pub hash: Option<String>,
    pub size: Option<i64>,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEventType {
    Started,
    Focused,
    Unfocused,
    Saved,
    Ended,
    Renamed,
}

#[derive(Debug, Clone)]
pub struct SessionEvent {
    pub event_type: SessionEventType,
    pub session_id: String,
    pub document_path: String,
    pub timestamp: SystemTime,
    pub hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WindowInfo {
    pub path: Option<String>,
    pub application: String,
    pub title: ObfuscatedString,
    pub pid: Option<u32>,
    pub timestamp: SystemTime,
    pub is_document: bool,
    pub is_unsaved: bool,
    /// IDE workspace/project root, if detected
    pub project_root: Option<String>,
}

impl Default for WindowInfo {
    fn default() -> Self {
        Self {
            path: None,
            application: String::new(),
            title: ObfuscatedString::default(),
            pid: None,
            timestamp: SystemTime::now(),
            is_document: false,
            is_unsaved: false,
            project_root: None,
        }
    }
}

/// Max jitter samples retained per document to bound memory.
///
/// Memory implication: 50,000 samples * ~24 bytes each = ~1.2 MB per active document.
/// This is intentional; the full session is retained so that post-hoc forensic analysis
/// has access to the complete typing timeline without lossy downsampling. Sessions that
/// exceed this limit drop the oldest samples via the sliding-window eviction in the
/// sentinel. For typical writing sessions (< 10,000 keystrokes) the limit is never hit.
pub const MAX_DOCUMENT_JITTER_SAMPLES: usize = 50_000;

/// Maximum focus switch records per document session. Sessions that
/// exceed this limit drop the oldest records.
pub const MAX_FOCUS_SWITCHES: usize = 10_000;

/// Record of a focus switch away from the tracked document.
#[derive(Debug, Clone)]
pub struct FocusSwitchRecord {
    /// When focus was lost.
    pub lost_at: SystemTime,
    /// When focus was regained (None if not yet regained).
    pub regained_at: Option<SystemTime>,
    /// App that received focus.
    pub target_app: String,
    /// Bundle ID of the app that received focus.
    pub target_bundle_id: String,
}

/// Functional role of a detected AI tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AiToolCategory {
    /// Standalone generative AI (ChatGPT desktop, Claude desktop).
    DirectGenerative = 0,
    /// IDE-integrated assistant (GitHub Copilot, Cursor).
    AssistantCopilot = 1,
    /// Browser that may host AI frontends.
    BrowserHosted = 2,
    /// System automation tools (AppleScript, Automator).
    Automation = 3,
    /// Clipboard or text transformation utilities.
    ClipboardTransform = 4,
}

impl fmt::Display for AiToolCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectGenerative => f.write_str("direct-generative"),
            Self::AssistantCopilot => f.write_str("assistant-copilot"),
            Self::BrowserHosted => f.write_str("browser-hosted"),
            Self::Automation => f.write_str("automation"),
            Self::ClipboardTransform => f.write_str("clipboard-transform"),
        }
    }
}

impl AiToolCategory {
    /// Map a code-signing identity to its category and observation basis.
    /// Returns `None` for unrecognized signing IDs.
    pub fn from_signing_id(signing_id: &str) -> Option<(Self, ObservationBasis)> {
        match signing_id {
            // Tier 1: Direct AI tools (strong signal)
            "com.openai.chat"
            | "com.openai.chatgpt"
            | "com.anthropic.claude"
            | "com.ollama.ollama"
            | "ai.lmstudio.app"
            | "io.typingmind.app" => Some((Self::DirectGenerative, ObservationBasis::Observed)),

            "com.github.copilot"
            | "dev.cursor.app"
            | "com.todesktop.230313mzl4w4u92"
            | "com.replit.desktop" => Some((Self::AssistantCopilot, ObservationBasis::Observed)),

            // Tier 2: AI-capable environments (weak signal, needs correlation)
            "com.apple.Safari"
            | "com.google.Chrome"
            | "org.mozilla.firefox"
            | "com.microsoft.edgemac"
            | "company.thebrowser.Browser" => {
                Some((Self::BrowserHosted, ObservationBasis::Inferred))
            }

            "com.microsoft.VSCode"
            | "com.microsoft.VSCodeInsiders"
            | "com.jetbrains.intellij"
            | "com.jetbrains.pycharm"
            | "com.jetbrains.webstorm"
            | "notion.id"
            | "com.raycast.macos"
            | "dev.warp.Warp-Stable" => Some((Self::AssistantCopilot, ObservationBasis::Inferred)),

            "com.apple.Terminal" | "com.googlecode.iterm2" => {
                Some((Self::Automation, ObservationBasis::Inferred))
            }

            // Tier 3: Automation pathways (strong signal)
            "com.apple.ScriptEditor2" | "com.apple.Automator" | "com.apple.ShortcutsActions" => {
                Some((Self::Automation, ObservationBasis::Observed))
            }

            _ => None,
        }
    }
}

/// Source context of a keystroke during Phase 2 clipboard/paste tracking.
// NOTE: A parallel KeystrokeContext exists in store/text_fragments.rs.
// These should be consolidated in a future refactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeystrokeContext {
    /// User typing fresh text, not from clipboard.
    OriginalComposition,
    /// User editing text that was pasted (within paste window).
    PastedContent,
    /// User typing after paste boundary (fresh composition).
    AfterPaste,
}

impl fmt::Display for KeystrokeContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OriginalComposition => f.write_str("original"),
            Self::PastedContent => f.write_str("pasted"),
            Self::AfterPaste => f.write_str("after-paste"),
        }
    }
}

/// Paste context tracking for a keystroke window.
///
/// Tracks when a paste event occurred and the time window during which
/// subsequent keystrokes are considered part of the pasted content region.
#[derive(Debug, Clone)]
pub struct PasteContext {
    /// When paste occurred (nanoseconds since UNIX_EPOCH)
    pub paste_time: i64,
    /// When the paste context window closes (nanoseconds since UNIX_EPOCH)
    pub context_window_end: i64,
    /// Number of keystrokes after paste (for metrics)
    pub keystroke_count_after_paste: usize,
}

/// How an AI tool detection was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ObservationBasis {
    /// ES saw the process exec directly.
    Observed = 0,
    /// Inferred from context (e.g., browser may host AI frontends).
    Inferred = 1,
    /// Tool was running but no proof it affected this document.
    Correlated = 2,
}

impl fmt::Display for ObservationBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observed => f.write_str("observed"),
            Self::Inferred => f.write_str("inferred"),
            Self::Correlated => f.write_str("correlated"),
        }
    }
}

/// A single AI tool detection event with full context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedAiTool {
    /// Code-signing identity from ES.
    pub signing_id: String,
    /// Process ID at detection time.
    pub pid: i32,
    /// Parent process ID (from ES audit token).
    pub ppid: i32,
    /// Executable path on disk.
    pub exec_path: String,
    /// Functional category of this tool.
    pub category: AiToolCategory,
    /// How this detection was established.
    pub basis: ObservationBasis,
    /// When the detection occurred.
    pub detected_at: SystemTime,
}

#[derive(Debug)]
pub struct DocumentSession {
    pub path: String,
    pub session_id: String,
    pub shadow_id: Option<String>,
    pub start_time: SystemTime,
    pub last_focus_time: SystemTime,
    pub(crate) total_focus_ms: i64,
    pub focus_count: u32,
    pub initial_hash: Option<String>,
    pub current_hash: Option<String>,
    pub(crate) save_count: u32,
    pub(crate) change_count: u32,
    pub(crate) keystroke_count: u64,
    pub app_bundle_id: String,
    pub app_name: String,
    pub window_title: ObfuscatedString,
    /// Per-document jitter samples for forensic analysis.
    pub(crate) jitter_samples: Vec<crate::jitter::SimpleJitterSample>,
    /// Incremental hash chain over accepted jitter samples.
    ///
    /// Updated on every validated keystroke:
    ///   `state = SHA256(prev_state || timestamp_ns_be || duration_ns_be || zone)`
    /// Initialized at session start from the session_id so the chain is
    /// session-scoped.  Checkpoints read this directly — O(1), no allocation.
    pub(crate) jitter_hash_state: [u8; 32],
    /// Cognitive writing signal accumulator (word boundaries, edit ops, corrections).
    pub cognitive: crate::forensics::cognitive_accumulator::CognitiveAccumulator,
    /// Focus loss events during this session (timestamps when user switched away).
    pub focus_switches: VecDeque<FocusSwitchRecord>,
    /// AI tools detected by Endpoint Security during this session.
    pub ai_tools_detected: Vec<DetectedAiTool>,
    /// Number of ES capture gaps (dropped events) during this session.
    pub capture_gaps: u32,
    pub(crate) has_focus: bool,
    pub(crate) focus_started: Option<Instant>,
    pub event_validation: crate::forensics::event_validation::EventValidationState,
    /// Cumulative keystroke count from all previous sessions (loaded from store on start).
    pub cumulative_keystrokes_base: u64,
    /// Cumulative focus time from all previous sessions.
    pub cumulative_focus_ms_base: i64,
    /// Number of previous sessions for this document.
    pub session_number: u32,
    /// When this document was first tracked.
    pub first_tracked_at: Option<SystemTime>,
    /// Keystroke count at the time of the last committed checkpoint.
    pub last_checkpoint_keystrokes: u64,
    /// When this session last had focus (for idle auto-stop).
    pub last_focused_at: SystemTime,
    /// HW co-sign scheduler; present when a TPM provider is available.
    pub(crate) hw_cosign_scheduler: Option<crate::evidence::hw_cosign::HwCosignScheduler>,
    /// Last hardware co-signature bytes for self-entanglement chain.
    pub(crate) last_hw_cosign_signature: Option<Vec<u8>>,
    /// Chain index counter for hardware co-signatures.
    pub(crate) hw_cosign_chain_index: u64,
    /// Paste context window for keystroke classification (Phase 2.3).
    pub paste_context: Option<PasteContext>,
}

impl Clone for DocumentSession {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            session_id: self.session_id.clone(),
            shadow_id: self.shadow_id.clone(),
            start_time: self.start_time,
            last_focus_time: self.last_focus_time,
            total_focus_ms: self.total_focus_ms,
            focus_count: self.focus_count,
            initial_hash: self.initial_hash.clone(),
            current_hash: self.current_hash.clone(),
            save_count: self.save_count,
            change_count: self.change_count,
            keystroke_count: self.keystroke_count,
            app_bundle_id: self.app_bundle_id.clone(),
            app_name: self.app_name.clone(),
            window_title: self.window_title.clone(),
            jitter_samples: self.jitter_samples.clone(),
            jitter_hash_state: self.jitter_hash_state,
            cognitive: self.cognitive.clone(),
            focus_switches: self.focus_switches.clone(),
            ai_tools_detected: self.ai_tools_detected.clone(),
            capture_gaps: self.capture_gaps,
            has_focus: self.has_focus,
            focus_started: self.focus_started,
            event_validation: self.event_validation.clone(),
            cumulative_keystrokes_base: self.cumulative_keystrokes_base,
            cumulative_focus_ms_base: self.cumulative_focus_ms_base,
            session_number: self.session_number,
            first_tracked_at: self.first_tracked_at,
            last_checkpoint_keystrokes: self.last_checkpoint_keystrokes,
            last_focused_at: self.last_focused_at,
            // Scheduler contains zeroize-protected SE salt; not cloned.
            hw_cosign_scheduler: None,
            last_hw_cosign_signature: self.last_hw_cosign_signature.clone(),
            hw_cosign_chain_index: self.hw_cosign_chain_index,
            paste_context: self.paste_context.clone(),
        }
    }
}

impl DocumentSession {
    pub fn new(
        path: String,
        app_bundle_id: String,
        app_name: String,
        window_title: ObfuscatedString,
    ) -> Self {
        let session_id = generate_session_id();
        let now = SystemTime::now();
        // Initialize the incremental hash chain with a session-scoped seed so that
        // the chain is unforgeable without knowing the session_id at creation time.
        let jitter_hash_state = {
            let mut h = Sha256::new();
            h.update(b"cpoe-jitter-chain-v2");
            h.update(session_id.as_bytes());
            h.finalize().into()
        };

        Self {
            path,
            session_id,
            shadow_id: None,
            start_time: now,
            last_focus_time: now,
            total_focus_ms: 0,
            focus_count: 0,
            initial_hash: None,
            current_hash: None,
            save_count: 0,
            change_count: 0,
            keystroke_count: 0,
            app_bundle_id,
            app_name,
            window_title,
            jitter_samples: Vec::new(),
            jitter_hash_state,
            cognitive: crate::forensics::cognitive_accumulator::CognitiveAccumulator::new(),
            focus_switches: VecDeque::new(),
            ai_tools_detected: Vec::new(),
            capture_gaps: 0,
            has_focus: false,
            focus_started: None,
            event_validation: Default::default(),
            cumulative_keystrokes_base: 0,
            cumulative_focus_ms_base: 0,
            session_number: 0,
            first_tracked_at: None,
            last_checkpoint_keystrokes: 0,
            last_focused_at: now,
            hw_cosign_scheduler: None,
            last_hw_cosign_signature: None,
            hw_cosign_chain_index: 0,
            paste_context: None,
        }
    }

    /// Total keystrokes across all sessions including current.
    pub fn total_keystrokes(&self) -> u64 {
        self.cumulative_keystrokes_base + self.keystroke_count
    }

    /// Total focus duration across all sessions including current.
    pub fn total_focus_ms_cumulative(&self) -> i64 {
        self.cumulative_focus_ms_base + self.total_focus_ms
    }

    pub fn focus_gained(&mut self) {
        if !self.has_focus {
            self.has_focus = true;
            self.focus_started = Some(Instant::now());
            self.last_focus_time = SystemTime::now();
            self.last_focused_at = SystemTime::now();
            self.focus_count += 1;
        }
    }

    pub fn focus_lost(&mut self) {
        if self.has_focus {
            if let Some(started) = self.focus_started.take() {
                self.total_focus_ms = self.total_focus_ms.saturating_add(
                    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
                );
            }
            self.has_focus = false;
        }
    }

    pub fn is_focused(&self) -> bool {
        self.has_focus
    }

    pub fn average_event_confidence(&self) -> f64 {
        self.event_validation.average_confidence()
    }

    /// Includes currently active focus interval if focused.
    pub fn total_focus_duration(&self) -> Duration {
        let mut total = Duration::from_millis(self.total_focus_ms.max(0) as u64);
        if let Some(started) = self.focus_started {
            total += started.elapsed();
        }
        total
    }
}

/// Generate a 64-char hex session ID (32 random bytes).
/// Wal::open requires a `[u8; 32]` session key, so 32 bytes ensures
/// the hex string decodes without truncation or padding.
pub fn generate_session_id() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    hex::encode(bytes)
}

/// Binding context for sessions that may lack a traditional file path
/// (unsaved documents, browser editors, universal keystrokes).
#[derive(Debug, Clone)]
pub enum SessionBinding {
    FilePath(PathBuf),

    AppContext {
        bundle_id: String,
        window_hash: String,
        shadow_id: String,
    },

    /// Browser-based editors; components are hashed for privacy
    UrlContext {
        domain_hash: String,
        page_hash: String,
    },

    /// No specific document (universal keystroke capture)
    Universal {
        session_id: String,
    },
}

impl SessionBinding {
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::FilePath(path.into())
    }

    pub fn app_context(bundle_id: impl Into<String>, window_title: &str) -> Self {
        let window_hash = hash_string(window_title);
        let shadow_id = generate_session_id();
        Self::AppContext {
            bundle_id: bundle_id.into(),
            window_hash,
            shadow_id,
        }
    }

    pub fn url_context(url: &str) -> Self {
        let (domain, path) = parse_url_parts(url);
        Self::UrlContext {
            domain_hash: hash_string(&domain),
            page_hash: hash_string(&path),
        }
    }

    pub fn universal() -> Self {
        Self::Universal {
            session_id: generate_session_id(),
        }
    }

    pub fn key(&self) -> String {
        match self {
            Self::FilePath(path) => path.to_string_lossy().to_string(),
            Self::AppContext { shadow_id, .. } => format!("app:{}", shadow_id),
            Self::UrlContext {
                domain_hash,
                page_hash,
            } => format!("url:{}:{}", domain_hash, page_hash),
            Self::Universal { session_id } => format!("universal:{}", session_id),
        }
    }

    pub fn has_file_path(&self) -> bool {
        matches!(self, Self::FilePath(_))
    }

    pub fn file_path(&self) -> Option<&Path> {
        match self {
            Self::FilePath(path) => Some(path),
            _ => None,
        }
    }
}

pub fn hash_string(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    crate::utils::short_hex_id(&result)
}

pub fn parse_url_parts(url: &str) -> (String, String) {
    let url = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let parts: Vec<&str> = url.splitn(2, '/').collect();
    let domain = parts.first().unwrap_or(&"").to_string();
    let path = parts.get(1).unwrap_or(&"").to_string();

    // Validate domain looks plausible (non-empty, contains at least one dot).
    // Malformed inputs get a distinguishing prefix so their hash never
    // collides with a legitimate domain hash.
    if domain.is_empty() || !domain.contains('.') {
        log::warn!(
            "parse_url_parts: malformed domain {:?}, prefixing hash input",
            domain
        );
        return (format!("invalid:{}", domain), path);
    }

    (domain, path)
}

/// Known document file extensions for heuristic title-based path inference.
///
/// Intentionally hardcoded rather than configurable: these are structural
/// heuristics for window-title parsing, not user preferences. Adding an
/// extension here is a code change that should be reviewed for correctness.
/// Sorted lexicographically to enable binary search.
const DOC_EXTENSIONS: &[&str] = &[
    ".adoc", ".afdesign", ".afphoto", ".afpub", ".asciidoc",
    ".bat", ".c", ".cpp", ".css", ".csv",
    ".doc", ".docx", ".draft",
    ".eml", ".emlx", ".epub",
    ".fdx", ".fountain",
    ".go",
    ".h", ".html",
    ".idml", ".indd",
    ".java", ".jl", ".js", ".json", ".jsx",
    ".key", ".kt",
    ".latex", ".lua",
    ".md", ".mmd",
    ".odt", ".opml", ".org",
    ".pages", ".pdf", ".php", ".pl", ".ppt", ".pptx", ".ps1",
    ".r", ".rb", ".rs", ".rst", ".rtf",
    ".scala", ".scriv", ".scrivx", ".sh", ".story", ".swift",
    ".tex", ".toml", ".ts", ".tsx", ".txt",
    ".ulysses",
    ".wpd", ".wri",
    ".xls", ".xlsx", ".xml",
    ".yaml", ".yml",
];

/// Apps that do not expose `AXDocument` and require title-based document inference.
///
/// Includes Electron-based editors, native apps that store content in containers
/// or cloud libraries (Bear, Ulysses), and any app whose window title is the
/// only reliable source of document identity. For these apps, bare names without
/// a recognised file extension are accepted as document identifiers.
///
/// Keep in sync with `sentinel/app_registry.rs` `needs_title_inference` fields.
const TITLE_INFERRED_APPS: &[&str] = &[
    // Electron editors
    "abnerworks.Typora",
    "com.typora.Typora",
    "md.obsidian",
    "com.zettlr.app",
    "com.github.marktext",
    "com.logseq.logseq",
    "com.microsoft.VSCode",
    "com.microsoft.VSCodeInsiders",
    "com.todesktop.230313mzl4w4u92", // Cursor
    "com.notion.id",
    "com.notion.Notion",
    "com.figma.Desktop",
    "com.hemingwayapp.hemingway",
    "com.celtx.mac",
    // Container-based / cloud-library / database-backed apps (no AXDocument)
    "com.ulyssesapp.mac",
    "net.shinyfrog.bear",
    "com.agiletortoise.Drafts-OSX",
    "com.bloombuilt.dayone-mac",
    "com.luki.paper.mac",        // Craft
    "com.microsoft.onenote.mac",
    "com.apple.Notes",
    "com.ommwriter.ommwriter",
    "dev.warp.Warp-Stable",
    "com.apple.mail",
    "com.microsoft.Outlook",
];

/// Window title fragments that indicate no real document is open.
/// These are matched as exact (case-insensitive) whole titles, not substrings,
/// to avoid blocking legitimate documents like "Untitled Draft" or "Welcome Letter".
const SKIP_TITLE_FRAGMENTS: &[&str] = &[
    "untitled",
    "no file",
    "welcome",
    "settings",
    "preferences",
    "get started",
    "graph view",
    "daily note",
    "inbox",
    "mailboxes",
    "no subject",
];

/// Infer a document file path from a window title like `"file.rs - VSCode"`.
///
/// Splits on common separators (`" - "`, `" \u{2014} "`, `" | "`) and checks
/// segments for known file extensions or absolute path patterns.
pub fn infer_document_path_from_title(title: &str) -> Option<String> {
    infer_document_path_from_title_with_bundle(title, None)
}

/// Enhanced title inference that uses the app bundle ID for app-specific parsing.
///
/// When `bundle_id` identifies an Electron editor that never exposes `AXDocument`,
/// the function relaxes its heuristic: it will accept a bare filename even without
/// a recognized extension, as long as it doesn't look like a non-document title
/// (e.g. "Untitled", "Settings", "Graph View").
pub fn infer_document_path_from_title_with_bundle(
    title: &str,
    bundle_id: Option<&str>,
) -> Option<String> {
    if title.is_empty() {
        return None;
    }

    let is_title_inferred = bundle_id
        .map(|id| TITLE_INFERRED_APPS.iter().any(|e| e.eq_ignore_ascii_case(id)))
        .unwrap_or(false);

    // Try standard separator-based extraction first.
    let separators = [" \u{2014} ", " - ", " | "];
    for sep in &separators {
        if let Some(idx) = title.find(sep) {
            let left = title[..idx].trim();
            if looks_like_file_path(left) {
                return Some(left.to_string());
            }
            // For apps without AXDocument, accept the left segment as a document
            // name even without a recognised extension, unless it's a skip-title.
            if is_title_inferred && looks_like_document_name(left) {
                return Some(left.to_string());
            }
            // Also check remaining segments (right side, further splits).
            let rest = &title[idx + sep.len()..];
            let remaining: Vec<&str> = rest.split(sep).collect();
            for segment in &remaining {
                let segment = segment.trim();
                if looks_like_file_path(segment) {
                    return Some(segment.to_string());
                }
            }
        }
    }

    // No separator found — check the whole title.
    let trimmed = title.trim();
    if looks_like_file_path(trimmed) {
        return Some(trimmed.to_string());
    }
    if is_title_inferred && looks_like_document_name(trimmed) {
        return Some(trimmed.to_string());
    }

    None
}

fn looks_like_file_path(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    // Windows absolute path: C:\... or C:/...
    if s.len() >= 3
        && s.as_bytes().get(1) == Some(&b':')
        && matches!(s.as_bytes().get(2), Some(&b'\\') | Some(&b'/'))
    {
        return true;
    }
    // Unix absolute path
    if s.starts_with('/') && s.len() > 1 {
        return true;
    }

    let lower = s.to_lowercase();
    if let Some(dot_pos) = lower.rfind('.') {
        let ext = &lower[dot_pos..];
        if DOC_EXTENSIONS.binary_search(&ext).is_ok() {
            return true;
        }
    }

    false
}

/// Check if `s` looks like a plausible document name for an Electron editor.
///
/// Rejects known non-document titles ("Untitled", "Settings", etc.) and
/// strings that are too short or suspiciously long.
fn looks_like_document_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 260 {
        return false;
    }

    let lower = s.to_lowercase();

    // Reject known non-document titles. Match as exact title or as the
    // first word/phrase, so "Untitled" and "Untitled - App" are both
    // rejected but "Untitled Draft" is accepted as a legitimate document.
    for frag in SKIP_TITLE_FRAGMENTS {
        if lower == *frag || lower.starts_with(&format!("{frag} -")) {
            return false;
        }
    }

    // Must contain at least one alphanumeric character.
    if !s.chars().any(|c| c.is_alphanumeric()) {
        return false;
    }

    true
}

/// Returns `None` if the path contains traversal components or cannot be resolved.
pub fn normalize_document_path(path: &str) -> Option<String> {
    let p = Path::new(path);

    for component in p.components() {
        if matches!(component, std::path::Component::ParentDir) {
            log::warn!("Rejected path with traversal component: '{path}'");
            return None;
        }
    }

    match p.canonicalize() {
        Ok(canonical) => Some(canonical.to_string_lossy().to_string()),
        Err(e) => {
            log::warn!("Failed to canonicalize path '{path}': {e}");
            None
        }
    }
}
