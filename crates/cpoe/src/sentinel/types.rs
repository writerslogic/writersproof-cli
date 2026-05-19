// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

pub use crate::crypto::ObfuscatedString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
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
    /// CGWindowID of the focused window, used as a tiebreaker when two windows
    /// of the same app share a title-inferred session key.
    pub window_id: Option<u32>,
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
    /// A manuscript export was detected within 30s of the last checkpoint.
    ExportDetected,
    /// App compile pipeline started.
    CompileStarted,
    /// App compile pipeline finished.
    CompileFinished,
}

/// Per-chapter/segment keystroke and change counts for bundle documents.
///
/// Keyed by the path relative to the bundle root (e.g. `"Files/Data/<UUID>/content.rtf"`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionSegment {
    /// Path relative to the bundle root.
    pub rel_path: String,
    /// Keystroke count attributed to this segment during the current session.
    pub keystroke_count: u64,
    /// File-change event count (saves/modifications) for this segment.
    pub change_count: u32,
    /// Nanoseconds-since-epoch of the most recent change observed.
    pub last_modified_ns: i64,
    /// BLAKE3 hash of the segment's content at the most recent change (hex).
    pub content_hash: Option<String>,
}

/// Snapshot of a Scrivener project's binder structure captured from `project.scrivx`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScrivenerProjectMap {
    /// UUID (BinderItem ID) → display title.
    pub uuid_to_title: HashMap<String, String>,
    /// BLAKE3 hash of the `.scrivx` contents at snapshot time (hex).
    pub scrivx_hash: String,
    /// Nanoseconds-since-epoch when this snapshot was taken.
    pub captured_at_ns: i64,
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
    /// CGWindowID of the topmost window. Used to detect Space transitions
    /// where the frontmost app is unchanged but a different window is visible.
    pub window_number: Option<u32>,
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
            window_number: None,
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

/// Classification of physical keyboard device based on CGEvent keyboard_type field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum KeyboardDeviceClass {
    /// Apple built-in keyboard (MacBook). Types 40-42, 44-45.
    BuiltIn = 0,
    /// External Apple keyboard (Magic Keyboard, etc.). Types 43, 46-50, 195-196.
    ExternalApple = 1,
    /// JIS keyboard layout (built-in or external). Types 42, 106.
    Jis = 2,
    /// ISO keyboard layout. Type 41.
    Iso = 3,
    /// Unknown or third-party keyboard.
    Unknown = 4,
}

impl KeyboardDeviceClass {
    /// Classify from macOS CGEvent keyboard_type field (field 10).
    ///
    /// Apple keyboard type values from IOHIDFamily headers:
    /// - 40 (kANSI): MacBook built-in ANSI
    /// - 41 (kISO): ISO layout
    /// - 42 (kJIS): JIS layout
    /// - 44-45: Standard US variants
    /// - 43, 46-50: External Apple keyboards
    /// - 106: JIS variant (external)
    /// - 195-196: Magic Keyboard (M-series)
    pub fn from_keyboard_type(kb_type: i64) -> Self {
        match kb_type {
            40 | 44 | 45 => Self::BuiltIn,
            41 => Self::Iso,
            42 => Self::Jis,
            106 => Self::Jis,
            43 | 46..=50 | 195 | 196 => Self::ExternalApple,
            0 => Self::Unknown, // synthetic or sandboxed
            _ if kb_type > 0 => Self::Unknown,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for KeyboardDeviceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuiltIn => f.write_str("built-in"),
            Self::ExternalApple => f.write_str("external-apple"),
            Self::Jis => f.write_str("jis"),
            Self::Iso => f.write_str("iso"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

/// Modifier key state bitmask passed from the host platform.
///
/// On macOS, derived from `NSEvent.modifierFlags`. Platform-independent
/// representation: each bit corresponds to a modifier family regardless
/// of left/right distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ModifierFlags(pub u16);

impl ModifierFlags {
    pub const SHIFT: u16 = 1 << 0;
    pub const CONTROL: u16 = 1 << 1;
    pub const OPTION: u16 = 1 << 2; // Alt on non-Mac
    pub const COMMAND: u16 = 1 << 3; // Super/Win on non-Mac
    pub const FN: u16 = 1 << 4;
    pub const CAPS_LOCK: u16 = 1 << 5;

    pub fn has_shift(self) -> bool {
        self.0 & Self::SHIFT != 0
    }
    pub fn has_control(self) -> bool {
        self.0 & Self::CONTROL != 0
    }
    pub fn has_option(self) -> bool {
        self.0 & Self::OPTION != 0
    }
    pub fn has_command(self) -> bool {
        self.0 & Self::COMMAND != 0
    }
    pub fn has_fn(self) -> bool {
        self.0 & Self::FN != 0
    }
    /// True if any non-Shift command modifier is active (Ctrl/Cmd/Option).
    pub fn has_command_modifier(self) -> bool {
        self.0 & (Self::CONTROL | Self::COMMAND | Self::OPTION) != 0
    }
}

/// Semantic classification of a keystroke based on keycode + modifier state.
///
/// This allows evidence to record *what the user intended* (undo, copy, paste,
/// select-all) without storing the actual character or document content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KeystrokeSemantic {
    /// Regular character input (typing).
    Character = 0,
    /// Backspace / delete backward.
    DeleteBackward = 1,
    /// Forward delete (fn+Backspace on Mac).
    DeleteForward = 2,
    /// Word delete (Option+Backspace on Mac, Ctrl+Backspace on Win/Linux).
    DeleteWord = 3,
    /// Line delete (Cmd+Backspace on Mac).
    DeleteLine = 4,
    /// Undo (Cmd+Z / Ctrl+Z).
    Undo = 5,
    /// Redo (Cmd+Shift+Z / Ctrl+Shift+Z / Ctrl+Y).
    Redo = 6,
    /// Copy (Cmd+C / Ctrl+C).
    Copy = 7,
    /// Cut (Cmd+X / Ctrl+X).
    Cut = 8,
    /// Paste (Cmd+V / Ctrl+V).
    Paste = 9,
    /// Select All (Cmd+A / Ctrl+A).
    SelectAll = 10,
    /// Navigation (arrow keys, Home, End, Page Up/Down).
    Navigation = 11,
    /// Find / search (Cmd+F / Ctrl+F).
    Find = 12,
    /// Save (Cmd+S / Ctrl+S).
    Save = 13,
    /// Other modifier combo not classified above.
    OtherShortcut = 14,
    /// Tab key.
    Tab = 15,
    /// Return / Enter key.
    Return = 16,
}

impl KeystrokeSemantic {
    /// Classify a keystroke from its keycode and modifier flags.
    ///
    /// macOS keycodes are used as the canonical reference. The calling FFI layer
    /// is responsible for mapping platform keycodes to the macOS equivalents
    /// (which the Swift host already provides natively).
    pub fn classify(keycode: u16, modifiers: ModifierFlags) -> Self {
        // macOS virtual keycodes (from Events.h / Carbon HIToolbox)
        const KC_BACKSPACE: u16 = 0x33;
        const KC_FWD_DELETE: u16 = 0x75;
        const KC_TAB: u16 = 0x30;
        const KC_RETURN: u16 = 0x24;
        const KC_ENTER: u16 = 0x4C; // numpad Enter
        const KC_Z: u16 = 0x06;
        const KC_C: u16 = 0x08;
        const KC_X: u16 = 0x07;
        const KC_V: u16 = 0x09;
        const KC_A: u16 = 0x00;
        const KC_F: u16 = 0x03;
        const KC_S: u16 = 0x01;
        const KC_Y: u16 = 0x10;
        const KC_LEFT: u16 = 0x7B;
        const KC_RIGHT: u16 = 0x7C;
        const KC_UP: u16 = 0x7E;
        const KC_DOWN: u16 = 0x7D;
        const KC_HOME: u16 = 0x73;
        const KC_END: u16 = 0x77;
        const KC_PGUP: u16 = 0x74;
        const KC_PGDN: u16 = 0x79;

        // Deletion keys (check before modifier combos)
        if keycode == KC_BACKSPACE {
            if modifiers.has_command() {
                return Self::DeleteLine;
            }
            if modifiers.has_option() {
                return Self::DeleteWord;
            }
            return Self::DeleteBackward;
        }
        if keycode == KC_FWD_DELETE {
            if modifiers.has_option() {
                return Self::DeleteWord;
            }
            return Self::DeleteForward;
        }

        // Navigation keys
        if matches!(
            keycode,
            KC_LEFT | KC_RIGHT | KC_UP | KC_DOWN | KC_HOME | KC_END | KC_PGUP | KC_PGDN
        ) {
            return Self::Navigation;
        }

        if keycode == KC_TAB {
            return Self::Tab;
        }
        if keycode == KC_RETURN || keycode == KC_ENTER {
            return Self::Return;
        }

        // Command shortcuts (Cmd on Mac, Ctrl on Win/Linux)
        if modifiers.has_command() || modifiers.has_control() {
            return match keycode {
                KC_Z if modifiers.has_shift() => Self::Redo,
                KC_Z => Self::Undo,
                KC_Y if modifiers.has_control() => Self::Redo, // Ctrl+Y (Windows)
                KC_C => Self::Copy,
                KC_X => Self::Cut,
                KC_V => Self::Paste,
                KC_A => Self::SelectAll,
                KC_F => Self::Find,
                KC_S => Self::Save,
                _ => Self::OtherShortcut,
            };
        }

        Self::Character
    }

    /// True if this semantic represents a deletion operation.
    pub fn is_deletion(self) -> bool {
        matches!(
            self,
            Self::DeleteBackward | Self::DeleteForward | Self::DeleteWord | Self::DeleteLine
        )
    }

    /// True if this semantic represents editing (not typing new content).
    pub fn is_editing(self) -> bool {
        matches!(
            self,
            Self::DeleteBackward
                | Self::DeleteForward
                | Self::DeleteWord
                | Self::DeleteLine
                | Self::Undo
                | Self::Redo
                | Self::Cut
                | Self::Paste
                | Self::SelectAll
        )
    }
}

impl fmt::Display for KeystrokeSemantic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Character => "character",
            Self::DeleteBackward => "delete-backward",
            Self::DeleteForward => "delete-forward",
            Self::DeleteWord => "delete-word",
            Self::DeleteLine => "delete-line",
            Self::Undo => "undo",
            Self::Redo => "redo",
            Self::Copy => "copy",
            Self::Cut => "cut",
            Self::Paste => "paste",
            Self::SelectAll => "select-all",
            Self::Navigation => "navigation",
            Self::Find => "find",
            Self::Save => "save",
            Self::OtherShortcut => "other-shortcut",
            Self::Tab => "tab",
            Self::Return => "return",
        };
        f.write_str(s)
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

/// Detected file encoding based on BOM (Byte Order Mark) analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FileEncoding {
    /// UTF-8 without BOM (most common).
    Utf8 = 0,
    /// UTF-8 with BOM (EF BB BF).
    Utf8Bom = 1,
    /// UTF-16 Little Endian (FF FE).
    Utf16Le = 2,
    /// UTF-16 Big Endian (FE FF).
    Utf16Be = 3,
    /// UTF-32 Little Endian (FF FE 00 00).
    Utf32Le = 4,
    /// UTF-32 Big Endian (00 00 FE FF).
    Utf32Be = 5,
    /// ASCII (all bytes < 128).
    Ascii = 6,
    /// Encoding could not be determined (binary or empty file).
    Unknown = 7,
}

impl fmt::Display for FileEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8 => f.write_str("utf-8"),
            Self::Utf8Bom => f.write_str("utf-8-bom"),
            Self::Utf16Le => f.write_str("utf-16le"),
            Self::Utf16Be => f.write_str("utf-16be"),
            Self::Utf32Le => f.write_str("utf-32le"),
            Self::Utf32Be => f.write_str("utf-32be"),
            Self::Ascii => f.write_str("ascii"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

/// Result of a "Save As" detection heuristic.
///
/// When a new file event arrives and its content hash matches an active session,
/// this struct identifies the likely source session.
#[derive(Debug, Clone)]
pub struct SaveAsDetection {
    /// Path of the original (source) session.
    pub original_path: String,
    /// Session ID of the original session.
    pub original_session_id: String,
    /// Content hash that matched.
    pub content_hash: String,
}

/// Classification of paste content origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PasteSource {
    /// Content was previously typed in the same document session.
    SameDocument = 0,
    /// Content was typed in a different tracked document.
    OtherDocument = 1,
    /// Content from an untracked external source (browser, other app).
    External = 2,
    /// Source could not be determined.
    Unknown = 3,
}

impl fmt::Display for PasteSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameDocument => f.write_str("same-document"),
            Self::OtherDocument => f.write_str("other-document"),
            Self::External => f.write_str("external"),
            Self::Unknown => f.write_str("unknown"),
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
    /// Classification of where the pasted content originated.
    pub source: PasteSource,
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

/// In-flight state for a dictation session within a document session.
///
/// Created on `ffi_sentinel_dictation_begin`, consumed on `ffi_sentinel_dictation_end`.
#[derive(Debug)]
pub struct ActiveDictationSession {
    pub start_ns: i64,
    pub es_speech_pid: u32,
    pub audio_transport_type: u8,
    pub device_uid_hash: [u8; 8],
    pub fragment_count: u32,
    pub total_words: u32,
    /// Running sum of confidence values (avoids unbounded Vec growth).
    pub confidence_sum: f64,
    /// Running sum of squared confidence values (for stddev computation).
    pub confidence_sum_sq: f64,
    pub speaker_output_ever_active: bool,
    pub ambient_noise_db: f32,
    /// Keystroke count at dictation begin (compare with session count at end).
    pub keystrokes_at_begin: u64,
    /// Cumulative correction count across all recorded fragments.
    pub total_corrections: u32,
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
    /// O(1) index: timestamp_ns → index in jitter_samples. Kept in sync with jitter_samples.
    pub(crate) jitter_sample_index: std::collections::HashMap<i64, usize>,
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
    /// In-flight dictation session, present between DictationBegin and DictationEnd.
    pub active_dictation: Option<ActiveDictationSession>,
    /// Completed dictation events recorded during this document session.
    pub dictation_events: Vec<crate::evidence::DictationEvent>,
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
    /// Per-session keystroke semantic counts for evidence enrichment.
    pub(crate) semantic_counts: SemanticAccumulator,
    /// Per-device keystroke counts keyed by keyboard device class.
    pub(crate) device_keystroke_counts: HashMap<KeyboardDeviceClass, u64>,
    /// Detected file encoding at last checkpoint (for encoding transition detection).
    pub(crate) file_encoding: Option<FileEncoding>,
    /// Original temporary path if this file was opened from an email attachment
    /// or download and later saved to a permanent location. Preserved across
    /// renames so evidence shows the file's origin.
    pub origin_temp_path: Option<String>,
    /// Per-chapter keystroke/change counts for bundle documents (.scriv, .ulysses, Vellum).
    /// Empty for non-bundle documents. Keyed by path relative to the bundle root.
    pub(crate) segment_counts: HashMap<String, SessionSegment>,
    /// Scrivener binder structure snapshot, populated on first successful parse of
    /// `project.scrivx` and refreshed whenever the file hash changes.
    pub(crate) scrivener_project_map: Option<ScrivenerProjectMap>,
    /// Unix nanoseconds of the most recently detected export event for this session.
    pub(crate) last_export_detected_ns: Option<i64>,
    /// Confidence in the evidence path and storage metadata for this session.
    pub evidence_confidence: EvidenceConfidence,
    /// Real-time transcription suspicion flag. Updated periodically during
    /// keystroke capture to detect transcription-like correction patterns.
    /// When `is_suspicious`, checkpoints are forced on every tick (never skipped).
    pub(crate) transcription_suspicion: crate::forensics::error_ecology::TranscriptionSuspicion,
    /// Cross-window transcription detector: compares typed text against visible
    /// windows to detect retyping from a visible source.
    pub(crate) transcription_detector: crate::transcription::TranscriptionDetector,
}

/// Confidence in the evidence path and storage metadata for a document session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    /// AX-confirmed document path; all storage checks passed.
    Full,
    /// AX failed; path derived from title inference or CGWindowList.
    Partial,
    /// Unknown app matched via track_unknown_apps; no storage metadata.
    Heuristic,
}

/// Accumulates keystroke semantic classification counts for a session.
///
/// These counts are included in evidence packets to characterize the
/// author's editing behavior without recording raw keystrokes.
/// Whether a session is primarily new composition or revision of existing content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SessionActivityType {
    /// Primarily typing new content (<15% editing keystrokes).
    Composing = 0,
    /// Primarily revising existing content (>50% editing keystrokes).
    Editing = 1,
    /// Mix of composing and editing (15-50% editing keystrokes).
    Mixed = 2,
}

impl fmt::Display for SessionActivityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Composing => f.write_str("composing"),
            Self::Editing => f.write_str("editing"),
            Self::Mixed => f.write_str("mixed"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SemanticAccumulator {
    pub characters: u64,
    pub delete_backward: u64,
    pub delete_forward: u64,
    pub delete_word: u64,
    pub delete_line: u64,
    pub undo: u64,
    pub redo: u64,
    pub copy: u64,
    pub cut: u64,
    pub paste: u64,
    pub select_all: u64,
    pub navigation: u64,
    pub find: u64,
    pub save: u64,
    pub other_shortcut: u64,
    pub tab: u64,
    pub r#return: u64,
}

impl SemanticAccumulator {
    pub fn record(&mut self, semantic: KeystrokeSemantic) {
        match semantic {
            KeystrokeSemantic::Character => self.characters += 1,
            KeystrokeSemantic::DeleteBackward => self.delete_backward += 1,
            KeystrokeSemantic::DeleteForward => self.delete_forward += 1,
            KeystrokeSemantic::DeleteWord => self.delete_word += 1,
            KeystrokeSemantic::DeleteLine => self.delete_line += 1,
            KeystrokeSemantic::Undo => self.undo += 1,
            KeystrokeSemantic::Redo => self.redo += 1,
            KeystrokeSemantic::Copy => self.copy += 1,
            KeystrokeSemantic::Cut => self.cut += 1,
            KeystrokeSemantic::Paste => self.paste += 1,
            KeystrokeSemantic::SelectAll => self.select_all += 1,
            KeystrokeSemantic::Navigation => self.navigation += 1,
            KeystrokeSemantic::Find => self.find += 1,
            KeystrokeSemantic::Save => self.save += 1,
            KeystrokeSemantic::OtherShortcut => self.other_shortcut += 1,
            KeystrokeSemantic::Tab => self.tab += 1,
            KeystrokeSemantic::Return => self.r#return += 1,
        }
    }

    /// Total deletion keystrokes across all deletion types.
    pub fn total_deletions(&self) -> u64 {
        self.delete_backward + self.delete_forward + self.delete_word + self.delete_line
    }

    /// Ratio of editing keystrokes to total keystrokes.
    /// Returns 0.0 if no keystrokes recorded.
    pub fn editing_ratio(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        let editing = self.total_deletions()
            + self.undo
            + self.redo
            + self.cut
            + self.paste
            + self.select_all;
        editing as f64 / total as f64
    }

    /// Classify the session as primarily composing or editing.
    ///
    /// Thresholds: <15% editing = composing, >50% = editing, between = mixed.
    /// Returns `None` if fewer than 20 keystrokes recorded.
    pub fn session_activity_type(&self) -> Option<SessionActivityType> {
        if self.total() < 20 {
            return None;
        }
        let ratio = self.editing_ratio();
        Some(if ratio < 0.15 {
            SessionActivityType::Composing
        } else if ratio > 0.50 {
            SessionActivityType::Editing
        } else {
            SessionActivityType::Mixed
        })
    }

    /// Total keystrokes across all semantic types.
    pub fn total(&self) -> u64 {
        self.characters
            + self.delete_backward
            + self.delete_forward
            + self.delete_word
            + self.delete_line
            + self.undo
            + self.redo
            + self.copy
            + self.cut
            + self.paste
            + self.select_all
            + self.navigation
            + self.find
            + self.save
            + self.other_shortcut
            + self.tab
            + self.r#return
    }
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
            jitter_sample_index: self.jitter_sample_index.clone(),
            jitter_hash_state: self.jitter_hash_state,
            cognitive: self.cognitive.clone(),
            focus_switches: self.focus_switches.clone(),
            ai_tools_detected: self.ai_tools_detected.clone(),
            capture_gaps: self.capture_gaps,
            active_dictation: None,
            dictation_events: self.dictation_events.clone(),
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
            semantic_counts: self.semantic_counts.clone(),
            device_keystroke_counts: self.device_keystroke_counts.clone(),
            file_encoding: self.file_encoding,
            origin_temp_path: self.origin_temp_path.clone(),
            segment_counts: self.segment_counts.clone(),
            scrivener_project_map: self.scrivener_project_map.clone(),
            last_export_detected_ns: self.last_export_detected_ns,
            evidence_confidence: self.evidence_confidence,
            transcription_suspicion: self.transcription_suspicion.clone(),
            transcription_detector: self.transcription_detector.clone(),
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
            jitter_sample_index: std::collections::HashMap::new(),
            jitter_hash_state,
            cognitive: crate::forensics::cognitive_accumulator::CognitiveAccumulator::new(),
            focus_switches: VecDeque::new(),
            ai_tools_detected: Vec::new(),
            capture_gaps: 0,
            active_dictation: None,
            dictation_events: Vec::new(),
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
            semantic_counts: SemanticAccumulator::default(),
            device_keystroke_counts: HashMap::new(),
            file_encoding: None,
            origin_temp_path: None,
            segment_counts: HashMap::new(),
            scrivener_project_map: None,
            last_export_detected_ns: None,
            evidence_confidence: EvidenceConfidence::Full,
            transcription_suspicion: Default::default(),
            transcription_detector: crate::transcription::TranscriptionDetector::new(),
        }
    }

    /// Record a keystroke semantic classification.
    pub fn record_semantic(&mut self, semantic: KeystrokeSemantic) {
        self.semantic_counts.record(semantic);
    }

    /// Record a keystroke from a specific keyboard device type.
    pub fn record_device_keystroke(&mut self, keyboard_type: i64) {
        let device = KeyboardDeviceClass::from_keyboard_type(keyboard_type);
        *self.device_keystroke_counts.entry(device).or_insert(0) += 1;
    }

    /// Total keystrokes across all sessions including current.
    pub fn total_keystrokes(&self) -> u64 {
        self.cumulative_keystrokes_base + self.keystroke_count
    }

    /// Real-time WPM from the last 60 seconds of jitter samples.
    /// Iterates from the back (newest first) and stops as soon as
    /// samples fall outside the 60-second window — O(window) not O(total).
    pub fn recent_wpm(&self) -> f64 {
        // Use the samples' own timestamps rather than wall clock to avoid
        // mismatch between kernel event timestamps and SystemTime::now().
        if self.jitter_samples.len() < 2 {
            return 0.0;
        }
        let newest_ns = self.jitter_samples.last().unwrap().timestamp_ns;
        let window_ns = 60_000_000_000i64;
        let mut count = 0usize;
        let mut oldest_ns = newest_ns;
        for s in self.jitter_samples.iter().rev() {
            let delta = newest_ns - s.timestamp_ns;
            if delta >= window_ns {
                break;
            }
            if delta < 0 {
                continue;
            }
            count += 1;
            oldest_ns = s.timestamp_ns;
        }
        if count < 2 {
            return 0.0;
        }
        let window_secs = (newest_ns - oldest_ns) as f64 / 1_000_000_000.0;
        if window_secs < 1.0 {
            return 0.0;
        }
        (count as f64 / 5.0) / (window_secs / 60.0)
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
    ".adoc",
    ".afdesign",
    ".afphoto",
    ".afpub",
    ".asciidoc",
    ".bat",
    ".c",
    ".cpp",
    ".css",
    ".csv",
    ".doc",
    ".docx",
    ".draft",
    ".eml",
    ".emlx",
    ".epub",
    ".fdx",
    ".fountain",
    ".go",
    ".h",
    ".html",
    ".idml",
    ".indd",
    ".java",
    ".jl",
    ".js",
    ".json",
    ".jsx",
    ".key",
    ".kt",
    ".latex",
    ".lua",
    ".md",
    ".mmd",
    ".odt",
    ".opml",
    ".org",
    ".pages",
    ".pdf",
    ".php",
    ".pl",
    ".ppt",
    ".pptx",
    ".ps1",
    ".r",
    ".rb",
    ".rs",
    ".rst",
    ".rtf",
    ".scala",
    ".scriv",
    ".scrivx",
    ".sh",
    ".story",
    ".swift",
    ".tex",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".ulysses",
    ".wpd",
    ".wri",
    ".xls",
    ".xlsx",
    ".xml",
    ".yaml",
    ".yml",
];

// TITLE_INFERRED_APPS removed — the authoritative source is now
// `app_registry::needs_title_inference()` which queries KNOWN_WRITING_APPS
// (and, via AppRegistry, user-added apps).

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
        .map(super::app_registry::needs_title_inference)
        .unwrap_or(false);

    let title_parser = bundle_id
        .and_then(super::app_registry::lookup)
        .map(|a| a.title_parser)
        .unwrap_or(super::app_registry::TitleParserVariant::Generic);

    // App-specific parsers for apps with known stable title formats.
    match title_parser {
        super::app_registry::TitleParserVariant::BBEdit => {
            // "filename — /full/path/to/file" — the right segment is the absolute path.
            const EM_DASH_SEP: &str = " \u{2014} ";
            if let Some(idx) = title.find(EM_DASH_SEP) {
                let right = title[idx + EM_DASH_SEP.len()..].trim();
                if looks_like_file_path(right) {
                    return Some(right.to_string());
                }
            }
        }
        super::app_registry::TitleParserVariant::Obsidian => {
            // "Note Title - Vault Name" — left is the note, right is vault (not a path).
            for sep in &[" - ", " \u{2014} "] {
                if let Some(idx) = title.find(sep) {
                    let left = title[..idx].trim();
                    if looks_like_document_name(left) {
                        return Some(left.to_string());
                    }
                }
            }
        }
        super::app_registry::TitleParserVariant::VSCode
        | super::app_registry::TitleParserVariant::Nova => {
            // VS Code: "filename - folder - Visual Studio Code" → first segment.
            // Nova: "filename · Nova" → split on " · ", take left.
            let separators: &[&str] = &[" \u{00B7} ", " - ", " \u{2014} "];
            for sep in separators {
                if let Some(idx) = title.find(sep) {
                    let left = title[..idx].trim();
                    if looks_like_file_path(left)
                        || (is_title_inferred && looks_like_document_name(left))
                    {
                        return Some(left.to_string());
                    }
                }
            }
        }
        super::app_registry::TitleParserVariant::TerminalEditor => {
            // Terminal editors set titles in various formats:
            // vim:   "filename (+) - VIM" or "filename - Vi IMproved"
            // nano:  "filename - GNU nano 8.0"
            // emacs: "filename - GNU Emacs at host"
            // Terminal.app wraps: "vim — filename — 80×24"
            //
            // Strategy: strip known editor suffixes and dimension strings,
            // then look for a file path or document name in what remains.
            let editor_markers = [
                " - VIM", " - Vi IMproved", " - GVIM",
                " - GNU nano", " - GNU Emacs", " - Emacs",
                " - NeoVim", " - NVIM",
            ];
            let mut cleaned = title.to_string();
            for marker in &editor_markers {
                if let Some(idx) = cleaned.find(marker) {
                    cleaned = cleaned[..idx].to_string();
                    break;
                }
            }
            // Strip vim's modified marker: "filename (+)" → "filename"
            cleaned = cleaned.trim_end_matches(" (+)").trim_end_matches(" [+]").to_string();

            // Terminal.app format: "editor — filename — 80×24"
            // Split on em-dash, look for file paths in middle segments.
            const EM_DASH: &str = " \u{2014} ";
            if cleaned.contains(EM_DASH) {
                let parts: Vec<&str> = cleaned.split(EM_DASH).collect();
                for part in &parts {
                    let part = part.trim();
                    if looks_like_file_path(part) {
                        return Some(part.to_string());
                    }
                }
                // Skip dimension-like segments (e.g. "80×24") and editor names
                for part in &parts {
                    let part = part.trim();
                    if !part.is_empty()
                        && !part.contains('\u{00D7}') // × dimension separator
                        && looks_like_document_name(part)
                    {
                        // Skip if it matches the editor command itself
                        let lower = part.to_lowercase();
                        if !["vim", "nvim", "nano", "emacs", "vi", "bash", "zsh", "fish", "sh"]
                            .contains(&lower.as_str())
                        {
                            return Some(part.to_string());
                        }
                    }
                }
            }

            let cleaned = cleaned.trim();
            if looks_like_file_path(cleaned) {
                return Some(cleaned.to_string());
            }
            if looks_like_document_name(cleaned) {
                return Some(cleaned.to_string());
            }
        }
        super::app_registry::TitleParserVariant::Generic => {}
    }

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

/// Git repository context captured at checkpoint time for version-controlled files.
///
/// Provides diff statistics and branch/commit metadata so evidence packets
/// can correlate authoring activity with VCS state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitContext {
    /// Current branch name (e.g. "main", "feature/draft-2").
    pub branch: String,
    /// SHA-1 hash of the last commit that touched this file.
    pub last_commit: String,
    /// Lines added since last commit (from `git diff --stat`).
    pub insertions: u32,
    /// Lines removed since last commit (from `git diff --stat`).
    pub deletions: u32,
    /// Whether the file has staged changes (`git diff --cached`).
    pub is_staged: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> DocumentSession {
        DocumentSession::new(
            "/tmp/test.txt".into(),
            "com.test.app".into(),
            "TestApp".into(),
            ObfuscatedString::new("test"),
        )
    }

    #[test]
    fn test_recent_wpm_empty_samples() {
        let session = make_session();
        assert_eq!(session.recent_wpm(), 0.0);
    }

    #[test]
    fn test_recent_wpm_insufficient_samples() {
        let mut session = make_session();
        session.jitter_samples.push(crate::jitter::SimpleJitterSample {
            timestamp_ns: 1_000_000_000,
            duration_since_last_ns: 0,
            zone: 0,
            dwell_time_ns: None,
            flight_time_ns: None,
        });
        assert_eq!(session.recent_wpm(), 0.0);
    }

    #[test]
    fn test_recent_wpm_realistic_typing() {
        let mut session = make_session();
        // Simulate 60 WPM = 5 chars/sec = 200ms between keystrokes
        // 30 keystrokes over 6 seconds starting at t=1000s
        let base_ns = 1_000_000_000_000i64; // 1000 seconds in ns
        let interval_ns = 200_000_000i64; // 200ms
        for i in 0..30 {
            session.jitter_samples.push(crate::jitter::SimpleJitterSample {
                timestamp_ns: base_ns + (i as i64) * interval_ns,
                duration_since_last_ns: if i == 0 { 0 } else { interval_ns as u64 },
                zone: (i % 5) as u8,
                dwell_time_ns: Some(50_000_000),
                flight_time_ns: Some(150_000_000),
            });
        }
        let wpm = session.recent_wpm();
        // 30 keystrokes / 5 chars per word = 6 words over 5.8 seconds
        // 6 words / (5.8/60) minutes = ~62 WPM
        assert!(wpm > 50.0, "WPM should be ~62, got {wpm}");
        assert!(wpm < 80.0, "WPM should be ~62, got {wpm}");
    }

    #[test]
    fn test_recent_wpm_old_samples_excluded() {
        let mut session = make_session();
        let base_ns = 1_000_000_000_000i64;
        // 10 old samples from 120 seconds ago
        for i in 0..10 {
            session.jitter_samples.push(crate::jitter::SimpleJitterSample {
                timestamp_ns: base_ns + (i as i64) * 200_000_000,
                duration_since_last_ns: 200_000_000,
                zone: 0,
                dwell_time_ns: None,
                flight_time_ns: None,
            });
        }
        // 20 recent samples in the last 4 seconds
        let recent_base = base_ns + 120_000_000_000; // 120 seconds later
        for i in 0..20 {
            session.jitter_samples.push(crate::jitter::SimpleJitterSample {
                timestamp_ns: recent_base + (i as i64) * 200_000_000,
                duration_since_last_ns: 200_000_000,
                zone: 0,
                dwell_time_ns: None,
                flight_time_ns: None,
            });
        }
        let wpm = session.recent_wpm();
        // Only the 20 recent samples count (within 60s of newest)
        // 20 keys / 5 = 4 words over 3.8s = ~63 WPM
        assert!(wpm > 50.0, "WPM should be ~63, got {wpm}");
        assert!(wpm < 80.0, "WPM should be ~63, got {wpm}");
    }

    #[test]
    fn test_recent_wpm_very_fast_typing() {
        let mut session = make_session();
        let base_ns = 1_000_000_000_000i64;
        // 100 keystrokes at 50ms intervals = very fast typing
        for i in 0..100 {
            session.jitter_samples.push(crate::jitter::SimpleJitterSample {
                timestamp_ns: base_ns + (i as i64) * 50_000_000,
                duration_since_last_ns: 50_000_000,
                zone: (i % 5) as u8,
                dwell_time_ns: None,
                flight_time_ns: None,
            });
        }
        let wpm = session.recent_wpm();
        // 100 keys / 5 = 20 words over 4.95s = ~242 WPM
        assert!(wpm > 200.0, "WPM should be ~242, got {wpm}");
        assert!(wpm < 300.0, "WPM should be ~242, got {wpm}");
    }
}
