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
    /// Text content changed in the focused UI element (detected via
    /// `kAXValueChangedNotification`). Used to detect non-keyboard input
    /// (dictation, autocomplete, voice control) and to confirm keystroke
    /// attribution during rapid app switches.
    ValueChanged,
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
    /// Character count delta from `kAXValueChangedNotification`. Only set for
    /// `ValueChanged` events; `None` for all other event types.
    pub char_count_delta: Option<i64>,
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
    #[allow(dead_code)] // Deserialize target; not constructed in Rust code
    CompileStarted,
    /// App compile pipeline finished.
    #[allow(dead_code)] // Deserialize target; not constructed in Rust code
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

// ---------------------------------------------------------------------------
// Entropy-triggered checkpoint constants
// ---------------------------------------------------------------------------

/// Minimum elapsed time between checkpoints (nanoseconds). Protects the write
/// lock and gives SQLite a ~50ms write budget within the 10s interval.
pub const ENTROPY_CHECKPOINT_MIN_NS: i64 = 10_000_000_000;

/// Maximum elapsed time before a deadline checkpoint fires regardless of
/// entropy (nanoseconds). Guarantees coverage during slow typing or pauses.
pub const ENTROPY_CHECKPOINT_MAX_NS: i64 = 120_000_000_000;

/// Trigger threshold: the first 4 bytes of jitter_hash_state, interpreted as
/// a big-endian u32, must be below this value to fire. Calibrated for ~45s
/// average interval at 3 KPS: after the 10s floor, ~105 eligible keystrokes
/// each with probability 1/105 ≈ `u32::MAX / 105`.
pub const ENTROPY_TRIGGER_THRESHOLD: u32 = 40_920_472; // u32::MAX / 105

/// Domain separation tag for entropy checkpoint verification.
pub const ENTROPY_CHECKPOINT_DST: &[u8] = b"cpoe-jitter-chain-v2";

/// Max jitter samples retained per document to bound memory.
///
/// Default capacity for the per-document jitter ring buffer.
///
/// Memory: 50,000 samples * ~35 bytes each = ~1.7 MB per active document.
/// Before the buffer wraps (typical sessions < 10,000 keystrokes), it behaves
/// like a Vec with contiguous slice access. After wrapping, consumers use
/// `to_vec_chronological()` or the chronological iterator.
pub const MAX_DOCUMENT_JITTER_SAMPLES: usize = 50_000;

/// Fixed-capacity ring buffer for jitter samples.
///
/// Replaces `Vec<SimpleJitterSample>` + `HashMap<i64, usize>` index.
/// Before wrapping, provides zero-copy contiguous slice access via
/// `as_contiguous_slice()`. After wrapping, oldest samples are overwritten
/// and consumers that need a slice use `to_vec_chronological()`.
#[derive(Debug)]
pub(crate) struct JitterRingBuffer {
    buf: Vec<crate::jitter::SimpleJitterSample>,
    /// Next write position (wraps at capacity).
    head: usize,
    /// Number of valid samples (capped at capacity).
    len: usize,
    capacity: usize,
}

impl Clone for JitterRingBuffer {
    fn clone(&self) -> Self {
        Self {
            buf: self.buf.clone(),
            head: self.head,
            len: self.len,
            capacity: self.capacity,
        }
    }
}

impl JitterRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            head: 0,
            len: 0,
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the buffer has wrapped (oldest samples have been overwritten).
    fn has_wrapped(&self) -> bool {
        self.len == self.capacity && self.head != self.len
    }

    /// Push a sample. If at capacity, overwrites the oldest sample.
    pub fn push(&mut self, sample: crate::jitter::SimpleJitterSample) {
        if self.buf.len() < self.capacity {
            // Pre-wrap: append like a Vec.
            self.buf.push(sample);
            self.head = self.buf.len();
            self.len = self.buf.len();
        } else {
            // Post-wrap: overwrite at head.
            self.buf[self.head] = sample;
            self.head = (self.head + 1) % self.capacity;
            // len stays at capacity
        }
    }

    /// Undo the last push (for validation rollback). Returns the removed sample.
    pub fn undo_last(&mut self) -> Option<crate::jitter::SimpleJitterSample> {
        if self.len == 0 {
            return None;
        }
        if self.buf.len() < self.capacity {
            // Pre-wrap: simple pop.
            self.len -= 1;
            self.head = self.len;
            self.buf.pop()
        } else {
            // Post-wrap: rewind head. The sample is still in buf but logically removed.
            self.head = if self.head == 0 { self.capacity - 1 } else { self.head - 1 };
            self.len -= 1;
            Some(self.buf[self.head].clone())
        }
    }

    /// Most recent sample.
    pub fn last(&self) -> Option<&crate::jitter::SimpleJitterSample> {
        if self.len == 0 {
            return None;
        }
        if self.buf.len() < self.capacity {
            self.buf.last()
        } else {
            let idx = if self.head == 0 { self.capacity - 1 } else { self.head - 1 };
            Some(&self.buf[idx])
        }
    }

    /// Mutable reference to the most recent sample.
    pub fn last_mut(&mut self) -> Option<&mut crate::jitter::SimpleJitterSample> {
        if self.len == 0 {
            return None;
        }
        if self.buf.len() < self.capacity {
            self.buf.last_mut()
        } else {
            let idx = if self.head == 0 { self.capacity - 1 } else { self.head - 1 };
            Some(&mut self.buf[idx])
        }
    }

    /// Backward scan for dwell time backfill. Finds the most recent sample
    /// matching `timestamp_ns` within the last `max_scan` entries.
    pub fn find_recent_mut(
        &mut self,
        timestamp_ns: i64,
        max_scan: usize,
    ) -> Option<&mut crate::jitter::SimpleJitterSample> {
        if self.len == 0 {
            return None;
        }
        let scan_count = max_scan.min(self.len);
        if self.buf.len() < self.capacity {
            // Pre-wrap: scan backward from end.
            let start = self.len.saturating_sub(scan_count);
            for i in (start..self.len).rev() {
                if self.buf[i].timestamp_ns == timestamp_ns {
                    return Some(&mut self.buf[i]);
                }
            }
        } else {
            // Post-wrap: scan backward from head.
            for offset in 1..=scan_count {
                let idx = (self.head + self.capacity - offset) % self.capacity;
                if self.buf[idx].timestamp_ns == timestamp_ns {
                    return Some(&mut self.buf[idx]);
                }
            }
        }
        None
    }

    /// Contiguous slice access (zero-copy). Returns `Some` only before wrapping.
    pub fn as_contiguous_slice(&self) -> Option<&[crate::jitter::SimpleJitterSample]> {
        if !self.has_wrapped() {
            Some(&self.buf[..self.len])
        } else {
            None
        }
    }

    /// Borrow as a contiguous slice when possible (pre-wrap), otherwise allocate.
    /// Avoids allocation for 95%+ of real sessions (< 50k keystrokes).
    pub fn as_slice(&self) -> std::borrow::Cow<'_, [crate::jitter::SimpleJitterSample]> {
        if let Some(slice) = self.as_contiguous_slice() {
            std::borrow::Cow::Borrowed(slice)
        } else {
            std::borrow::Cow::Owned(self.to_vec_chronological())
        }
    }

    /// Returns all samples in chronological order as a Vec.
    pub fn to_vec_chronological(&self) -> Vec<crate::jitter::SimpleJitterSample> {
        if self.len == 0 {
            return Vec::new();
        }
        if !self.has_wrapped() {
            return self.buf[..self.len].to_vec();
        }
        // Post-wrap: tail (oldest) is from head..capacity, then 0..head.
        let mut result = Vec::with_capacity(self.len);
        result.extend_from_slice(&self.buf[self.head..]);
        result.extend_from_slice(&self.buf[..self.head]);
        result
    }

    /// Returns the trailing `n` samples in chronological order.
    pub fn trailing(&self, n: usize) -> Vec<crate::jitter::SimpleJitterSample> {
        let count = n.min(self.len);
        if count == 0 {
            return Vec::new();
        }
        if !self.has_wrapped() {
            let start = self.len - count;
            return self.buf[start..self.len].to_vec();
        }
        let mut result = Vec::with_capacity(count);
        for offset in (1..=count).rev() {
            let idx = (self.head + self.capacity - offset) % self.capacity;
            result.push(self.buf[idx].clone());
        }
        result
    }

    /// Iterate samples in reverse chronological order (newest first).
    pub fn iter_rev(&self) -> JitterRingRevIter<'_> {
        JitterRingRevIter { ring: self, offset: 0 }
    }

}

pub(crate) struct JitterRingRevIter<'a> {
    ring: &'a JitterRingBuffer,
    offset: usize,
}

impl<'a> Iterator for JitterRingRevIter<'a> {
    type Item = &'a crate::jitter::SimpleJitterSample;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.ring.len {
            return None;
        }
        self.offset += 1;
        if self.ring.buf.len() < self.ring.capacity {
            Some(&self.ring.buf[self.ring.len - self.offset])
        } else {
            let idx = (self.ring.head + self.ring.capacity - self.offset) % self.ring.capacity;
            Some(&self.ring.buf[idx])
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.ring.len - self.offset;
        (remaining, Some(remaining))
    }
}

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
            | "com.openai.chatgpt.macos"
            | "com.anthropic.claude"
            | "com.anthropic.claudefordesktop"
            | "com.google.gemini"
            | "com.google.bard"
            | "com.ollama.ollama"
            | "ai.lmstudio.app"
            | "io.typingmind.app" => Some((Self::DirectGenerative, ObservationBasis::Observed)),

            "com.github.copilot"
            | "com.microsoft.copilot"
            | "dev.cursor.app"
            | "com.todesktop.230313mzl4w4u92"
            | "com.codeium.windsurf"
            | "com.sourcegraph.cody"
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

    /// True if this semantic produces document content (characters, tab, return).
    pub fn is_content_producing(self) -> bool {
        matches!(self, Self::Character | Self::Tab | Self::Return)
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
// A parallel KeystrokeContext exists in store/text_fragments.rs with
// different serialization (PascalCase as_str/FromStr for SQLite vs
// kebab-case Display/Serde here for wire format). Intentionally separate.
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

/// Semantic type of pasted content. Prose is the forgery-risk category;
/// tables, images, and formatting are legitimate authoring artifacts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PasteContentKind {
    #[default]
    Prose = 0,
    StructuredData = 1,
    Media = 2,
    FormattingOnly = 3,
    Mixed = 4,
}

impl fmt::Display for PasteContentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prose => f.write_str("prose"),
            Self::StructuredData => f.write_str("structured-data"),
            Self::Media => f.write_str("media"),
            Self::FormattingOnly => f.write_str("formatting-only"),
            Self::Mixed => f.write_str("mixed"),
        }
    }
}

/// Pasteboard/clipboard content types present at capture time.
#[derive(Debug, Clone, Default)]
pub struct PasteboardTypeInventory {
    /// Raw UTI strings (macOS) or format names (Windows) for audit logging.
    pub utis: Vec<String>,
    pub has_plain_text: bool,
    pub has_rtf: bool,
    pub has_html: bool,
    pub has_image: bool,
    pub has_spreadsheet: bool,
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
    /// Semantic type of the pasted content (prose, table, image, etc.).
    pub content_kind: PasteContentKind,
    /// Number of characters in the pasted content (for scaled domestication).
    pub paste_char_count: usize,
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
    /// Number of interim recognition callbacks (non-final fragments).
    /// Real speech: 4-12/min. TTS through dictation: 0-1/min.
    pub interim_revision_count: u32,
    /// Self-repair cycles detected (fragment word count regressed from previous).
    /// Real composition: 3-8/min. TTS: 0.
    pub disfluency_count: u32,
    /// Word count from the most recent fragment (for detecting regressions).
    pub last_fragment_word_count: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScrollAttentionAccumulator {
    // --- scroll counters ---
    pub scroll_up_count: u64,
    pub scroll_down_count: u64,
    pub total_scroll_events: u64,
    pub direction_reversals: u64,
    pub last_scroll_sign: i8,
    pub scroll_near_edit_count: u64,
    pub scroll_before_edit_count: u64,
    pub last_scroll_ts_ns: i64,

    // --- scroll velocity (Welford online variance) ---
    scroll_vel_count: u64,
    scroll_vel_mean: f64,
    scroll_vel_m2: f64,

    // --- cursor position running statistics ---
    pub position_sample_count: u64,
    pub position_y_mean: f64,
    pub position_y_min: f64,
    pub position_y_max: f64,
    /// Y-position histogram bins for entropy (10 bins, 100px each from screen top).
    pub position_y_bins: [u64; 10],

    // --- cursor movement direction ---
    pub cursor_move_up_count: u64,
    pub cursor_move_down_count: u64,
    pub last_sample_y: f64,
    pub last_sample_ts_ns: i64,

    // --- dwell region tracking ---
    pub dwell_thirds_ns: [u64; 3],
    /// Timestamps of recent scroll events for scroll-before-edit detection (ring, max 64).
    #[serde(skip)]
    pub recent_scroll_timestamps: VecDeque<i64>,
}

impl ScrollAttentionAccumulator {
    /// Map a screen Y coordinate to a histogram bin index (0-9).
    pub fn y_to_bin(y: f64) -> usize {
        ((y.max(0.0) / 100.0).floor() as usize).min(9)
    }

    /// Record a scroll event magnitude for running velocity statistics (Welford).
    pub fn record_scroll_magnitude(&mut self, magnitude: f64) {
        self.scroll_vel_count += 1;
        let n = self.scroll_vel_count as f64;
        let delta = magnitude - self.scroll_vel_mean;
        self.scroll_vel_mean += delta / n;
        let delta2 = magnitude - self.scroll_vel_mean;
        self.scroll_vel_m2 += delta * delta2;
    }

    /// Scroll velocity coefficient of variation. Returns 0 if insufficient data.
    pub fn scroll_velocity_cv(&self) -> f64 {
        if self.scroll_vel_count < 2 || self.scroll_vel_mean <= 0.0 {
            return 0.0;
        }
        let variance = (self.scroll_vel_m2 / (self.scroll_vel_count as f64 - 1.0)).max(0.0);
        variance.sqrt() / self.scroll_vel_mean
    }

    /// Record a cursor Y position sample for running statistics and histogram.
    pub fn record_position(&mut self, y: f64) {
        self.position_sample_count += 1;
        let n = self.position_sample_count as f64;
        let delta = y - self.position_y_mean;
        self.position_y_mean += delta / n;
        if y < self.position_y_min || self.position_sample_count == 1 {
            self.position_y_min = y;
        }
        if y > self.position_y_max || self.position_sample_count == 1 {
            self.position_y_max = y;
        }
        self.position_y_bins[Self::y_to_bin(y)] += 1;
    }

    /// Record cursor movement direction relative to the last sampled position.
    pub fn record_direction(&mut self, y: f64) {
        if self.last_sample_ts_ns > 0 {
            let dy = y - self.last_sample_y;
            if dy.abs() > 1.0 {
                if dy < 0.0 {
                    self.cursor_move_up_count += 1;
                } else {
                    self.cursor_move_down_count += 1;
                }
            }
        }
    }
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
    /// Per-document jitter samples for forensic analysis (ring buffer).
    pub(crate) jitter_ring: JitterRingBuffer,
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
    /// Total checkpoints committed in this session (cumulative across restarts).
    pub checkpoint_count: u64,
    /// Nanosecond timestamp of the last committed checkpoint (jitter clock).
    /// Used by the entropy trigger to enforce the MIN_NS floor.
    pub(crate) last_checkpoint_ns: i64,
    /// When this session last had focus (for idle auto-stop).
    pub last_focused_at: SystemTime,
    /// HW co-sign scheduler; present when a TPM provider is available.
    pub(crate) hw_cosign_scheduler: Option<crate::evidence::hw_cosign::HwCosignScheduler>,
    /// Last hardware co-signature bytes for self-entanglement chain.
    pub(crate) last_hw_cosign_signature: Option<Vec<u8>>,
    /// Chain index counter for hardware co-signatures.
    pub(crate) hw_cosign_chain_index: u64,
    /// Paste context history for composition mode analysis (capped at 100).
    pub paste_context: Vec<PasteContext>,
    /// Number of times the user skipped a mandatory paste checkpoint.
    pub paste_checkpoint_skips: u32,
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
    /// Attestation linking a compile/export output to this session's source bundle.
    pub(crate) export_attestation: Option<crate::evidence::ManuscriptExportAttestation>,
    /// Confidence in the evidence path and storage metadata for this session.
    pub evidence_confidence: EvidenceConfidence,
    /// Human-readable reason the confidence was downgraded from Full.
    /// `None` when confidence is Full (no downgrade occurred).
    pub confidence_reason: Option<String>,
    /// Real-time transcription suspicion flag. Updated periodically during
    /// keystroke capture to detect transcription-like correction patterns.
    /// When `is_suspicious`, checkpoints are forced on every tick (never skipped).
    pub(crate) transcription_suspicion: crate::forensics::error_ecology::TranscriptionSuspicion,
    /// Cross-window transcription detector: compares typed text against visible
    /// windows to detect retyping from a visible source.
    pub(crate) transcription_detector: crate::transcription::TranscriptionDetector,
    /// CGWindowID of the active window for this session (used to exclude from cross-window checks).
    pub(crate) window_id: Option<u32>,
    /// Last writing mode label for hysteresis in live score polling.
    pub last_writing_mode: Option<String>,
    /// Content-bound edit context proofs: BLAKE3 keyed hashes of the 64-byte
    /// window around each detected cursor reposition. Populated at capture time
    /// when the platform provides document read access.
    #[cfg(feature = "content_binding")]
    pub(crate) edit_context_proofs: Vec<EditContextProof>,
    pub(crate) scroll_attention: ScrollAttentionAccumulator,
    /// Count of AXValueChanged events with no correlated keystroke (non-keyboard input).
    pub(crate) non_keyboard_change_count: u64,
    /// Net character delta from non-keyboard AXValueChanged events.
    pub(crate) non_keyboard_chars_inserted: i64,
}

/// BLAKE3 keyed hash of the 64-byte window around an edit position.
///
/// Computed at capture time when a cursor reposition is detected, binding the
/// edit location to the surrounding document content. An attacker who injects
/// fake cursor jumps must also produce plausible local context at every jump
/// site, which requires solving the composition problem itself.
///
/// Key = checkpoint content_hash (domain separator). Window = `doc[pos-32..pos+32]`.
#[cfg(feature = "content_binding")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditContextProof {
    /// Nanosecond timestamp of the cursor reposition event.
    pub timestamp_ns: i64,
    /// Document byte offset where the cursor landed.
    pub cursor_offset: u64,
    /// BLAKE3 keyed hash: `blake3::keyed_hash(content_hash, &doc[pos-32..pos+32])`.
    /// The binding key (content_hash) is not stored here; the verifier
    /// reconstructs it from the checkpoint chain.
    pub context_hash: [u8; 32],
}

#[cfg(feature = "content_binding")]
impl EditContextProof {
    /// Compute an edit context proof for a cursor reposition.
    ///
    /// `content_hash`: the document's BLAKE3 hash at the most recent checkpoint
    ///   (used as the BLAKE3 keyed-hash key; not stored in the proof).
    /// `document_bytes`: the full document content.
    /// `cursor_offset`: byte offset where the cursor landed.
    /// `timestamp_ns`: nanosecond timestamp of the reposition event.
    pub fn compute(
        content_hash: &[u8; 32],
        document_bytes: &[u8],
        cursor_offset: u64,
        timestamp_ns: i64,
    ) -> Option<Self> {
        let pos = cursor_offset as usize;
        let start = pos.saturating_sub(32);
        let end = (pos + 32).min(document_bytes.len());
        if end <= start {
            return None;
        }
        let window = &document_bytes[start..end];

        let context_hash = blake3::keyed_hash(content_hash, window);

        Some(Self {
            timestamp_ns,
            cursor_offset,
            context_hash: *context_hash.as_bytes(),
        })
    }

    /// Verify this proof against a document snapshot and the binding key
    /// reconstructed from the checkpoint chain.
    pub fn verify(&self, binding_key: &[u8; 32], document_bytes: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        let pos = self.cursor_offset as usize;
        let start = pos.saturating_sub(32);
        let end = (pos + 32).min(document_bytes.len());
        if end <= start {
            return false;
        }
        let window = &document_bytes[start..end];
        let expected = blake3::keyed_hash(binding_key, window);
        expected.as_bytes().ct_eq(&self.context_hash).into()
    }
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

impl fmt::Display for EvidenceConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("Full"),
            Self::Partial => f.write_str("Partial"),
            Self::Heuristic => f.write_str("Heuristic"),
        }
    }
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

    /// Total editing keystrokes (deletions + undo/redo + cut/paste + select-all).
    /// Mirrors `KeystrokeSemantic::is_editing()`.
    pub fn total_editing(&self) -> u64 {
        self.total_deletions()
            + self.undo
            + self.redo
            + self.cut
            + self.paste
            + self.select_all
    }

    /// Ratio of editing keystrokes to total keystrokes.
    /// Returns 0.0 if no keystrokes recorded.
    pub fn editing_ratio(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        self.total_editing() as f64 / total as f64
    }

    /// Classify the session as primarily composing or editing.
    ///
    /// Thresholds: <15% editing = composing, >50% = editing, between = mixed.
    /// Returns `None` if fewer than 20 keystrokes recorded.
    pub fn session_activity_type(&self) -> Option<SessionActivityType> {
        let total = self.total();
        if total < 20 {
            return None;
        }
        let ratio = self.total_editing() as f64 / total as f64;
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
    #[allow(clippy::field_reassign_with_default)]
    fn clone(&self) -> Self {
        // Destructure to get a compile error when a new field is added
        // without updating this impl. Fields that are intentionally NOT
        // cloned (active_dictation, hw_cosign_scheduler) are bound to `_`.
        let Self {
            ref path,
            ref session_id,
            ref shadow_id,
            start_time,
            last_focus_time,
            total_focus_ms,
            focus_count,
            ref initial_hash,
            ref current_hash,
            save_count,
            change_count,
            keystroke_count,
            ref app_bundle_id,
            ref app_name,
            ref window_title,
            ref jitter_ring,
            jitter_hash_state,
            ref cognitive,
            ref focus_switches,
            ref ai_tools_detected,
            capture_gaps,
            active_dictation: _,
            ref dictation_events,
            has_focus,
            focus_started,
            ref event_validation,
            cumulative_keystrokes_base,
            cumulative_focus_ms_base,
            session_number,
            first_tracked_at,
            last_checkpoint_keystrokes,
            checkpoint_count,
            last_checkpoint_ns,
            last_focused_at,
            hw_cosign_scheduler: _,
            ref last_hw_cosign_signature,
            hw_cosign_chain_index,
            ref paste_context,
            paste_checkpoint_skips,
            ref semantic_counts,
            ref device_keystroke_counts,
            file_encoding,
            ref origin_temp_path,
            ref segment_counts,
            ref scrivener_project_map,
            last_export_detected_ns,
            ref export_attestation,
            evidence_confidence,
            ref confidence_reason,
            ref transcription_suspicion,
            ref transcription_detector,
            ref last_writing_mode,
            #[cfg(feature = "content_binding")]
            ref edit_context_proofs,
            ref scroll_attention,
            window_id,
            non_keyboard_change_count,
            non_keyboard_chars_inserted,
        } = *self;

        Self {
            path: path.clone(),
            session_id: session_id.clone(),
            shadow_id: shadow_id.clone(),
            start_time,
            last_focus_time,
            total_focus_ms,
            focus_count,
            initial_hash: initial_hash.clone(),
            current_hash: current_hash.clone(),
            save_count,
            change_count,
            keystroke_count,
            app_bundle_id: app_bundle_id.clone(),
            app_name: app_name.clone(),
            window_title: window_title.clone(),
            jitter_ring: jitter_ring.clone(),
            jitter_hash_state,
            cognitive: cognitive.clone(),
            focus_switches: focus_switches.clone(),
            ai_tools_detected: ai_tools_detected.clone(),
            capture_gaps,
            active_dictation: None,
            dictation_events: dictation_events.clone(),
            has_focus,
            focus_started,
            event_validation: event_validation.clone(),
            cumulative_keystrokes_base,
            cumulative_focus_ms_base,
            session_number,
            first_tracked_at,
            last_checkpoint_keystrokes,
            checkpoint_count,
            last_checkpoint_ns,
            last_focused_at,
            // Scheduler contains zeroize-protected SE salt; not cloned.
            hw_cosign_scheduler: None,
            last_hw_cosign_signature: last_hw_cosign_signature.clone(),
            hw_cosign_chain_index,
            paste_context: paste_context.clone(),
            paste_checkpoint_skips,
            semantic_counts: semantic_counts.clone(),
            device_keystroke_counts: device_keystroke_counts.clone(),
            file_encoding,
            origin_temp_path: origin_temp_path.clone(),
            segment_counts: segment_counts.clone(),
            scrivener_project_map: scrivener_project_map.clone(),
            last_export_detected_ns,
            export_attestation: export_attestation.clone(),
            evidence_confidence,
            confidence_reason: confidence_reason.clone(),
            transcription_suspicion: transcription_suspicion.clone(),
            transcription_detector: transcription_detector.clone(),
            window_id,
            last_writing_mode: last_writing_mode.clone(),
            #[cfg(feature = "content_binding")]
            edit_context_proofs: edit_context_proofs.clone(),
            scroll_attention: scroll_attention.clone(),
            non_keyboard_change_count,
            non_keyboard_chars_inserted,
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
            jitter_ring: JitterRingBuffer::new(MAX_DOCUMENT_JITTER_SAMPLES),
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
            checkpoint_count: 0,
            last_checkpoint_ns: 0,
            last_focused_at: now,
            hw_cosign_scheduler: None,
            last_hw_cosign_signature: None,
            hw_cosign_chain_index: 0,
            paste_context: Vec::new(),
            paste_checkpoint_skips: 0,
            semantic_counts: SemanticAccumulator::default(),
            device_keystroke_counts: HashMap::new(),
            file_encoding: None,
            origin_temp_path: None,
            segment_counts: HashMap::new(),
            scrivener_project_map: None,
            last_export_detected_ns: None,
            export_attestation: None,
            // Starts as Full; downgraded to Partial/Heuristic by the focus
            // handler when AX path resolution or storage checks fail.
            evidence_confidence: EvidenceConfidence::Full,
            confidence_reason: None,
            transcription_suspicion: Default::default(),
            transcription_detector: crate::transcription::TranscriptionDetector::new(),
            window_id: None,
            last_writing_mode: None,
            #[cfg(feature = "content_binding")]
            edit_context_proofs: Vec::new(),
            scroll_attention: ScrollAttentionAccumulator::default(),
            non_keyboard_change_count: 0,
            non_keyboard_chars_inserted: 0,
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

    /// Record a content-bound edit context proof when a cursor reposition is detected.
    ///
    /// Called from the change handler when the platform can read the document at
    /// the edit position. The proof binds the cursor jump to the surrounding 64
    /// bytes of content via a BLAKE3 keyed hash, making it infeasible to inject
    /// fake jumps without producing plausible local context.
    ///
    /// `content_hash`: BLAKE3 hash of the full document at the most recent checkpoint.
    /// `document_bytes`: current document content.
    /// `cursor_offset`: byte position where the cursor landed.
    /// `timestamp_ns`: nanosecond-precision event timestamp.
    #[cfg(feature = "content_binding")]
    pub fn record_edit_context(
        &mut self,
        content_hash: &[u8; 32],
        document_bytes: &[u8],
        cursor_offset: u64,
        timestamp_ns: i64,
    ) {
        const MAX_PROOFS: usize = 10_000;
        if self.edit_context_proofs.len() >= MAX_PROOFS {
            return;
        }
        if let Some(proof) = EditContextProof::compute(
            content_hash,
            document_bytes,
            cursor_offset,
            timestamp_ns,
        ) {
            self.edit_context_proofs.push(proof);
        }
    }

    /// Total keystrokes across all sessions including current.
    pub fn total_keystrokes(&self) -> u64 {
        self.cumulative_keystrokes_base.saturating_add(self.keystroke_count)
    }

    /// Real-time WPM from the last 60 seconds of jitter samples.
    /// Iterates from the back (newest first) and stops as soon as
    /// samples fall outside the 60-second window — O(window) not O(total).
    pub fn recent_wpm(&self) -> f64 {
        // Use the samples' own timestamps rather than wall clock to avoid
        // mismatch between kernel event timestamps and SystemTime::now().
        if self.jitter_ring.len() < 2 {
            return 0.0;
        }
        let newest_ns = self.jitter_ring.last().unwrap().timestamp_ns;
        let window_ns = 60_000_000_000i64;
        let mut count = 0usize;
        let mut oldest_ns = newest_ns;
        for s in self.jitter_ring.iter_rev() {
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
        self.cumulative_focus_ms_base.saturating_add(self.total_focus_ms)
    }

    pub fn focus_gained(&mut self) {
        if !self.has_focus {
            self.has_focus = true;
            self.focus_started = Some(Instant::now());
            let now = SystemTime::now();
            self.last_focus_time = now;
            self.last_focused_at = now;
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
        debug_assert!(
            self.total_focus_ms >= 0,
            "total_focus_ms went negative: {}",
            self.total_focus_ms
        );
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
    let (domain, path) = match url.split_once('/') {
        Some((d, p)) => (d.to_string(), p.to_string()),
        None => (url.to_string(), String::new()),
    };

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
    ".ass",
    ".bat",
    ".bear",
    ".c",
    ".cpp",
    ".creole",
    ".css",
    ".csv",
    ".djot",
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
    ".highland",
    ".html",
    ".idml",
    ".indd",
    ".ink",
    ".ipynb",
    ".java",
    ".jl",
    ".js",
    ".json",
    ".jsx",
    ".key",
    ".kt",
    ".latex",
    ".lua",
    ".lyx",
    ".markua",
    ".md",
    ".mermaid",
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
    ".qmd",
    ".r",
    ".rb",
    ".rmd",
    ".rs",
    ".rst",
    ".rtf",
    ".scala",
    ".scriv",
    ".scrivx",
    ".sh",
    ".srt",
    ".story",
    ".swift",
    ".tbx",
    ".tex",
    ".textile",
    ".toml",
    ".ts",
    ".tsx",
    ".tw",
    ".twee",
    ".txt",
    ".typ",
    ".ulysses",
    ".ulyz",
    ".vtt",
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

/// Bare editor/shell command names to reject when extracting document names
/// from terminal window titles (e.g. "vim — filename — 80×24").
const TERMINAL_EDITOR_NAMES: &[&str] = &[
    // Vi family
    "vim", "nvim", "vi", "gvim", "mvim", "macvim", "nvi", "elvis",
    // Emacs family
    "emacs", "xemacs", "mg", "zemacs",
    // Nano/pico family
    "nano", "pico", "tilde",
    // Modern terminal editors
    "helix", "hx",
    "kakoune", "kak",
    "micro",
    "amp",
    "zee", "zi",
    "ox",
    "mle",
    "dte",
    "vis",
    // Classic editors
    "joe", "jstar", "jpico", "jmacs",
    "ed", "ex", "sed",
    "ne",
    "mcedit",
    "fte",
    "le",
    "diakonos",
    // Shells
    "bash", "zsh", "fish", "sh", "dash", "ksh", "tcsh", "csh",
    "elvish", "nushell", "nu", "ion", "xonsh", "oil", "osh",
    "powershell", "pwsh",
    // Terminal multiplexers
    "tmux", "screen", "zellij", "byobu", "dtach", "abduco",
    // Terminal emulator process names (when they appear as bare segments)
    "login",
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

    let is_terminal = bundle_id.map(is_terminal_bundle).unwrap_or(false);

    // For terminal emulators, strip editor suffixes before parsing.
    // These markers (" - VIM", " - GNU Emacs", etc.) only appear in terminal
    // titles, so applying them only to detected terminals avoids false positives
    // with GUI apps whose names partially overlap (e.g. "Visual" vs "Vis").
    let mut working: &str = title;
    if is_terminal {
        for marker in EDITOR_TITLE_MARKERS {
            if let Some(idx) = working.find(marker) {
                working = &working[..idx];
                break;
            }
        }
        working = working
            .trim_end_matches(" (+)")
            .trim_end_matches(" [+]");
    }

    let accept_bare = is_title_inferred || is_terminal;

    // Split on common separators and evaluate segments.
    let separators = [" \u{2014} ", " \u{00B7} ", " - ", " | "];
    for sep in &separators {
        if let Some(idx) = working.find(sep) {
            let left = working[..idx].trim();
            if looks_like_file_path(left) {
                return Some(left.to_string());
            }
            if accept_bare
                && looks_like_document_name(left)
                && !is_terminal_noise(left)
                && !left.contains('\u{00D7}')
            {
                return Some(left.to_string());
            }
            // Check remaining segments for absolute paths.
            let rest = &working[idx + sep.len()..];
            for segment in rest.split(sep) {
                let segment = segment.trim();
                if looks_like_file_path(segment) {
                    return Some(segment.to_string());
                }
            }
            // For terminal editors: remaining segments may contain the document
            // name (e.g. "vim — filename — 80×24").
            if is_terminal {
                for segment in rest.split(sep) {
                    let segment = segment.trim();
                    if !segment.contains('\u{00D7}')
                        && looks_like_document_name(segment)
                        && !is_terminal_noise(segment)
                    {
                        return Some(segment.to_string());
                    }
                }
            }
        }
    }

    // No separator found — check the whole working title.
    let trimmed = working.trim();
    if looks_like_file_path(trimmed) {
        return Some(trimmed.to_string());
    }
    if accept_bare && looks_like_document_name(trimmed) {
        return Some(trimmed.to_string());
    }

    None
}

/// Known terminal emulator bundle IDs. Used to detect terminal editor title
/// formats without relying on the app registry.
fn is_terminal_bundle(bundle_id: &str) -> bool {
    bundle_id.eq_ignore_ascii_case("com.apple.Terminal")
        || bundle_id.eq_ignore_ascii_case("com.googlecode.iterm2")
        || bundle_id.eq_ignore_ascii_case("com.github.wez.wezterm")
        || bundle_id.eq_ignore_ascii_case("net.kovidgoyal.kitty")
        || bundle_id.eq_ignore_ascii_case("io.alacritty")
        || bundle_id
            .to_ascii_lowercase()
            .starts_with("dev.warp.")
}

/// Editor suffix markers stripped from terminal window titles before parsing.
const EDITOR_TITLE_MARKERS: &[&str] = &[
    // Vi family
    " - VIM", " - Vi IMproved", " - GVIM", " - NVIM", " - NeoVim",
    // Emacs family
    " - GNU Emacs", " - Emacs", " - XEmacs",
    // Nano/pico
    " - GNU nano", " - Pico", " - tilde",
    // Modern terminal editors
    " - Helix", " - hx",
    " - Kakoune", " - kak",
    " - Micro",
    " - Amp",
    " - Vis",
    // Classic editors
    " - Joe", " - JOE",
    " - ne",
    " - mcedit",
    " - ed",
    // GUI editors (when launched from terminal)
    " - Sublime Text",
    " - TextMate",
];

/// Segments extracted from an Electron-style window title.
///
/// For titles like `"index.ts - MyProject - Visual Studio Code"`, this yields
/// `filename = "index.ts"` and `project_folder = Some("MyProject")`. The
/// folder hint is used to search common project roots on disk so that a bare
/// filename can be resolved to an absolute path without relying on AXDocument
/// or the FD scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TitlePathHint {
    /// The document filename (may or may not have an extension).
    pub filename: String,
    /// Optional project/folder name extracted from the title.
    pub project_folder: Option<String>,
}

/// Extract structured path hints from an Electron-style window title.
///
/// Handles these common patterns:
/// - `"filename — AppName"` (Typora, Zed single-file)
/// - `"filename - folder - AppName"` (VS Code, Cursor, Sublime Text)
/// - `"filename [project] - AppName"` (some editors)
/// - `"filename — folder — Zed"` (Zed with project)
/// - `"filename · Nova"` (Nova)
/// - `"Note Title - VaultName - Obsidian"` (Obsidian with vault)
///
/// Returns `None` if the title does not contain separators or the extracted
/// filename looks like a non-document title (e.g. "Settings").
pub fn extract_title_path_hint(
    title: &str,
    bundle_id: Option<&str>,
) -> Option<TitlePathHint> {
    if title.is_empty() {
        return None;
    }

    let is_title_inferred = bundle_id
        .map(super::app_registry::needs_title_inference)
        .unwrap_or(false);

    // Collect all segments by splitting on the known separators in order of
    // specificity.  We try em-dash first, then middot (Nova), then hyphen.
    let segments: Vec<&str> = if title.contains(" \u{2014} ") {
        title.split(" \u{2014} ").map(str::trim).collect()
    } else if title.contains(" \u{00B7} ") {
        title.split(" \u{00B7} ").map(str::trim).collect()
    } else if title.contains(" - ") {
        title.split(" - ").map(str::trim).collect()
    } else {
        return None;
    };

    if segments.is_empty() {
        return None;
    }

    // Known app-name suffixes to strip from the last segment. When the last
    // segment matches one of these, it is the application name and should not
    // be treated as a folder.
    const APP_SUFFIXES: &[&str] = &[
        "Visual Studio Code",
        "VS Code",
        "Code - Insiders",
        "Cursor",
        "Zed",
        "Zed Preview",
        "Sublime Text",
        "Sublime Text 3",
        "Nova",
        "Obsidian",
        "Typora",
        "Zettlr",
        "Mark Text",
        "MarkText",
        "Logseq",
        "Notion",
        "Hemingway Editor",
    ];

    let is_app_suffix = |s: &str| -> bool {
        APP_SUFFIXES.iter().any(|a| s.eq_ignore_ascii_case(a))
    };

    let filename;
    let mut project_folder = None;

    match segments.len() {
        1 => {
            // No separator or app name — unlikely to be useful.
            return None;
        }
        2 => {
            // "filename — AppName" or "filename — folder" (when app has its own
            // parser and we know the last segment is the app).
            let left = segments[0];
            let right = segments[1];

            if is_app_suffix(right) {
                filename = left;
            } else {
                filename = left;
                // For title-inferred apps, the right segment is likely a
                // project/vault name (e.g. Obsidian "Note - Vault").
                if is_title_inferred {
                    project_folder = Some(right.to_string());
                }
            }
        }
        _ => {
            // 3+ segments: "filename - folder - AppName" or more.
            let last = segments[segments.len() - 1];
            if is_app_suffix(last) {
                filename = segments[0];
                // The middle segment(s) are the project/folder path.
                // For "file - folder - App", folder = segments[1].
                // For "file - folder - subfolder - App", join them.
                let middle: Vec<&str> = segments[1..segments.len() - 1].to_vec();
                if !middle.is_empty() {
                    // Handle "[project]" bracket syntax in middle segments.
                    let folder = middle.join(std::path::MAIN_SEPARATOR_STR);
                    project_folder = Some(folder);
                }
            } else {
                // No recognized app suffix — take first as filename, second as
                // folder hint.
                filename = segments[0];
                project_folder = Some(segments[1].to_string());
            }
        }
    }

    // Reject known non-document titles.
    if !looks_like_document_name(filename) && !looks_like_file_path(filename) {
        return None;
    }

    // Strip bracket-wrapped project names from the filename itself:
    // "main.rs [writerslogic]" → filename="main.rs", project="writerslogic"
    let (clean_filename, bracket_project) = extract_bracket_project(filename);

    let project_folder = bracket_project
        .map(|p| p.to_string())
        .or(project_folder);

    Some(TitlePathHint {
        filename: clean_filename.to_string(),
        project_folder,
    })
}

/// Extract a `[project]` suffix from a filename segment.
/// Returns `(filename_without_bracket, Some(project_name))` or
/// `(original, None)`.
fn extract_bracket_project(s: &str) -> (&str, Option<&str>) {
    if let Some(open) = s.rfind('[') {
        if let Some(close) = s[open..].find(']') {
            let project = &s[open + 1..open + close];
            let before = s[..open].trim_end();
            if !project.is_empty() && !before.is_empty() {
                return (before, Some(project));
            }
        }
    }
    (s, None)
}

/// Try to resolve a `TitlePathHint` to an absolute file path on disk.
///
/// Uses the process's current working directory (which Electron editors set to
/// the project root) as the primary search path. Falls back to searching
/// `$HOME/<common_root>/<project_folder>` when the CWD is unavailable or
/// doesn't contain the file.
///
/// `pid` is the frontmost application's process ID; pass `None` to skip the
/// CWD probe (e.g. in tests or on platforms without proc support).
pub fn resolve_title_hint_to_path(hint: &TitlePathHint, pid: Option<u32>) -> Option<String> {
    // Strategy 1: process CWD — the most reliable signal for Electron editors.
    if let Some(pid) = pid {
        if let Some(cwd) = super::process_files::cwd_for_pid(pid) {
            // Direct child of cwd (VS Code opens project root as cwd).
            let candidate = cwd.join(&hint.filename);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
            // One level of subdirectories (src/filename, lib/filename, etc.)
            if let Ok(entries) = std::fs::read_dir(&cwd) {
                for entry in entries.filter_map(|e| e.ok()) {
                    if entry.path().is_dir() {
                        let sub = entry.path().join(&hint.filename);
                        if sub.is_file() {
                            return Some(sub.to_string_lossy().into_owned());
                        }
                    }
                }
            }
        }
    }

    // Strategy 2: folder hint from the title + common project roots.
    if let Some(ref folder) = hint.project_folder {
        let home = dirs::home_dir()?;
        const PROJECT_ROOTS: &[&str] = &[
            "", "Documents", "Desktop", "Developer", "Projects",
            "Code", "src", "repos", "workspace", "dev", "Sites",
        ];
        for root in PROJECT_ROOTS {
            let base = if root.is_empty() {
                home.join(folder)
            } else {
                home.join(root).join(folder)
            };
            if !base.is_dir() {
                continue;
            }
            let candidate = base.join(&hint.filename);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
            // One level of subdirectories.
            if let Ok(entries) = std::fs::read_dir(&base) {
                for entry in entries.filter_map(|e| e.ok()) {
                    if entry.path().is_dir() {
                        let sub = entry.path().join(&hint.filename);
                        if sub.is_file() {
                            return Some(sub.to_string_lossy().into_owned());
                        }
                    }
                }
            }
        }
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

    if let Some(dot_pos) = s.rfind('.') {
        let ext = &s[dot_pos..];
        // DOC_EXTENSIONS are all lowercase ASCII. Lowercase the short
        // extension into a stack buffer to avoid heap allocation.
        let ext_bytes = ext.as_bytes();
        if ext_bytes.len() <= 16 {
            let mut buf = [0u8; 16];
            for (i, &b) in ext_bytes.iter().enumerate() {
                buf[i] = b.to_ascii_lowercase();
            }
            if let Ok(lower_ext) = std::str::from_utf8(&buf[..ext_bytes.len()]) {
                if DOC_EXTENSIONS.binary_search(&lower_ext).is_ok() {
                    return true;
                }
            }
        }
    }

    false
}

/// True if `s` is a known terminal editor, shell, multiplexer, or tty device name.
fn is_terminal_noise(s: &str) -> bool {
    if TERMINAL_EDITOR_NAMES.iter().any(|n| s.eq_ignore_ascii_case(n)) {
        return true;
    }
    // macOS tty device names: ttys000..ttys999
    if s.len() == 7
        && s[..4].eq_ignore_ascii_case("ttys")
        && s[4..].bytes().all(|b| b.is_ascii_digit())
    {
        return true;
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

    // Reject known non-document titles. Match as exact title or as the
    // first word/phrase, so "Untitled" and "Untitled - App" are both
    // rejected but "Untitled Draft" is accepted as a legitimate document.
    // SKIP_TITLE_FRAGMENTS are all ASCII; use case-insensitive compare
    // to avoid a heap allocation from to_lowercase().
    for frag in SKIP_TITLE_FRAGMENTS {
        if s.eq_ignore_ascii_case(frag)
            || (s.len() > frag.len()
                && s.is_char_boundary(frag.len())
                && s[..frag.len()].eq_ignore_ascii_case(frag)
                && s[frag.len()..].starts_with(" -"))
        {
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

/// Returns `None` if the path contains traversal components, null bytes,
/// is not absolute, or cannot be resolved.
pub fn normalize_document_path(path: &str) -> Option<String> {
    if path.contains('\0') {
        log::warn!("Rejected path with null byte");
        return None;
    }

    let p = Path::new(path);

    if !p.is_absolute() {
        log::warn!("Rejected non-absolute path: '{path}'");
        return None;
    }

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
        session.jitter_ring.push(crate::jitter::SimpleJitterSample {
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
            session.jitter_ring.push(crate::jitter::SimpleJitterSample {
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
            session.jitter_ring.push(crate::jitter::SimpleJitterSample {
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
            session.jitter_ring.push(crate::jitter::SimpleJitterSample {
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
            session.jitter_ring.push(crate::jitter::SimpleJitterSample {
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
