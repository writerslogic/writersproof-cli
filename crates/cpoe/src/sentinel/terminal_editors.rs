// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Cross-platform terminal editor detection.
//!
//! When the focused application is a terminal emulator, this module inspects
//! the process tree to find a running text editor (vim, nvim, emacs, nano,
//! etc.) and resolves which file it has open.  This enables authorship
//! witnessing for users who write in terminal-based editors.
//!
//! Detection strategy (in order of reliability):
//! 1. **Process tree scan**: walk child processes of the terminal PID looking
//!    for known editor executables.
//! 2. **Window title parsing**: many terminals set their title to the editor's
//!    current file via OSC 2 escape sequences.
//! 3. **Open file descriptor enumeration**: if a process-files module is
//!    available, enumerate the editor process's open FDs to find document files.

use std::path::PathBuf;

/// Known terminal-based text editors (executable base names).
const KNOWN_EDITORS: &[&str] = &[
    "vim", "nvim", "vi", "emacs", "nano", "helix", "micro", "kakoune", "joe",
    "hx",   // helix binary name on some distros
    "kak",  // kakoune binary name
    "ne",   // nice editor
    "mcedit",
];

/// Known terminal emulator bundle IDs (macOS).
#[cfg(target_os = "macos")]
const TERMINAL_BUNDLE_IDS: &[&str] = &[
    "com.apple.Terminal",
    "com.googlecode.iterm2",
    "net.kovidgoyal.kitty",
    "org.alacritty",
    "com.mitchellh.ghostty",
    "dev.warp.Warp-Stable",
    "dev.warp.Warp",
    "com.github.wez.wezterm",
    "co.zeit.hyper",
    "io.tabby",
];

/// Known terminal emulator executable names (cross-platform).
const TERMINAL_EXECUTABLES: &[&str] = &[
    "Terminal",
    "iTerm2",
    "kitty",
    "alacritty",
    "ghostty",
    "wezterm-gui",
    "warp",
    "hyper",
    "tabby",
    "WindowsTerminal",
    "wt",
    "cmd",
    "powershell",
    "pwsh",
    "gnome-terminal-server",
    "konsole",
    "xfce4-terminal",
    "tilix",
    "terminator",
    "foot",
    "rio",
];

/// Information about a detected terminal editor.
#[derive(Debug, Clone)]
pub struct TerminalEditorInfo {
    /// Editor executable name (e.g., "nvim", "vim").
    pub editor: String,
    /// File path the editor has open, if resolved.
    pub file_path: Option<String>,
    /// PID of the editor process.
    pub editor_pid: u32,
}

/// Check whether a bundle ID identifies a terminal emulator.
#[cfg(target_os = "macos")]
pub fn is_terminal_emulator_bundle(bundle_id: &str) -> bool {
    let lower = bundle_id.to_lowercase();
    TERMINAL_BUNDLE_IDS
        .iter()
        .any(|&id| id.eq_ignore_ascii_case(&lower))
}

/// Check whether a bundle ID identifies a terminal emulator.
#[cfg(not(target_os = "macos"))]
pub fn is_terminal_emulator_bundle(_bundle_id: &str) -> bool {
    // On non-macOS, use executable name matching instead.
    false
}

/// Check whether an application name looks like a terminal emulator.
pub fn is_terminal_emulator_name(app_name: &str) -> bool {
    let lower = app_name.to_lowercase();
    TERMINAL_EXECUTABLES
        .iter()
        .any(|&name| lower.contains(&name.to_lowercase()))
}

/// Cached result of terminal editor detection to avoid process table scans
/// on every poll cycle (100ms).
struct EditorDetectionCache {
    result: Option<TerminalEditorInfo>,
    terminal_pid: u32,
    expires: std::time::Instant,
}

static EDITOR_CACHE: std::sync::Mutex<Option<EditorDetectionCache>> =
    std::sync::Mutex::new(None);

const EDITOR_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(2);

/// Detect an editor running inside a terminal process.
///
/// Results are cached for 2 seconds per terminal PID to avoid expensive
/// process table scans on every 100ms poll cycle.
pub fn detect_editor_in_terminal(terminal_pid: u32) -> Option<TerminalEditorInfo> {
    // Check cache first (recover from poisoned mutex).
    {
        let guard = EDITOR_CACHE.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ref cached) = *guard {
            if cached.terminal_pid == terminal_pid
                && cached.expires > std::time::Instant::now()
            {
                return cached.result.clone();
            }
        }
    }

    let result = detect_editor_uncached(terminal_pid);

    // Update cache.
    if let Ok(mut guard) = EDITOR_CACHE.lock() {
        *guard = Some(EditorDetectionCache {
            result: result.clone(),
            terminal_pid,
            expires: std::time::Instant::now() + EDITOR_CACHE_TTL,
        });
    }

    result
}

fn detect_editor_uncached(terminal_pid: u32) -> Option<TerminalEditorInfo> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};

    // Single process table scan shared across child + grandchild lookups.
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing().with_processes(
            ProcessRefreshKind::nothing().with_cmd(UpdateKind::OnlyIfNotSet),
        ),
    );
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let parent = sysinfo::Pid::from_u32(terminal_pid);
    let children: Vec<_> = sys
        .processes()
        .iter()
        .filter(|(_, p)| p.parent() == Some(parent))
        .map(|(pid, p)| (pid.as_u32(), p.name().to_string_lossy().into_owned()))
        .collect();

    if children.is_empty() {
        return None;
    }

    for (pid, name) in &children {
        let base_name = executable_base_name(name);
        if is_known_editor(&base_name) {
            let file_path = resolve_editor_file_with_sys(&sys, *pid, &base_name);
            return Some(TerminalEditorInfo {
                editor: base_name,
                file_path,
                editor_pid: *pid,
            });
        }
        // Check grandchildren (editor launched via shell: terminal → zsh → nvim).
        let child_pid = sysinfo::Pid::from_u32(*pid);
        for (gpid, gproc) in sys.processes().iter() {
            if gproc.parent() != Some(child_pid) {
                continue;
            }
            let gbase = executable_base_name(&gproc.name().to_string_lossy());
            if is_known_editor(&gbase) {
                let file_path = resolve_editor_file_with_sys(&sys, gpid.as_u32(), &gbase);
                return Some(TerminalEditorInfo {
                    editor: gbase,
                    file_path,
                    editor_pid: gpid.as_u32(),
                });
            }
        }
    }

    None
}

fn resolve_editor_file_with_sys(
    sys: &sysinfo::System,
    pid: u32,
    _editor: &str,
) -> Option<String> {
    // Try command-line arguments from the already-loaded process table.
    if let Some(proc) = sys.process(sysinfo::Pid::from_u32(pid)) {
        let cmd = proc.cmd();
        if !cmd.is_empty() {
            for arg in cmd.iter().rev() {
                let arg = arg.to_string_lossy();
                let arg = arg.trim();
                if arg.starts_with('-') || arg.starts_with('+') || arg.is_empty() {
                    continue;
                }
                if looks_like_file(arg) {
                    return Some(arg.to_string());
                }
            }
        }
    }

    // Fall back to process FD enumeration.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let docs = super::process_files::open_documents_for_pid(pid);
        if let Some(doc) = docs.into_iter().find(|f| f.writable) {
            return Some(doc.path.to_string_lossy().into_owned());
        }
    }

    None
}

/// Parse a terminal window title for editor and file information.
///
/// Many editors set the terminal title via OSC 2 escape sequences, producing
/// patterns like:
/// - `"file.txt - NVIM"` (neovim)
/// - `"VIM - file.txt"` or `"file.txt (+) - VIM"` (vim)
/// - `"nano  file.txt"` or `"  GNU nano 7.2  file.txt"`
/// - `"emacs@hostname"` or `"emacs: file.txt"`
/// - `"file.txt - helix"`
///
/// Returns `(editor_name, file_path)` if a pattern is recognized.
pub fn parse_terminal_title_for_editor(title: &str) -> Option<(String, String)> {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Pattern: "file - EDITOR" or "EDITOR - file"
    if let Some((left, right)) = trimmed.split_once(" - ") {
        let left = left.trim();
        let right = right.trim();

        // "file.txt - NVIM" / "file.txt - VIM" / "file.txt - helix"
        if is_known_editor(&right.to_lowercase()) {
            let file = strip_vim_modifiers(left);
            if looks_like_file(file) {
                return Some((right.to_lowercase(), file.to_string()));
            }
        }
        // "VIM - file.txt"
        if is_known_editor(&left.to_lowercase()) && looks_like_file(right) {
            return Some((left.to_lowercase(), right.to_string()));
        }
    }

    // Pattern: "editor: file" (emacs)
    if let Some((editor, file)) = trimmed.split_once(": ") {
        let editor_lower = editor.trim().to_lowercase();
        // Strip "user@host" from "emacs@host: file"
        let editor_base = editor_lower.split('@').next().unwrap_or(&editor_lower);
        if is_known_editor(editor_base) {
            let file = file.trim();
            if looks_like_file(file) {
                return Some((editor_base.to_string(), file.to_string()));
            }
        }
    }

    // Pattern: "  GNU nano 7.2  file.txt" (nano title format)
    let lower = trimmed.to_lowercase();
    if lower.contains("nano") {
        // Extract last whitespace-separated token as filename.
        if let Some(last) = trimmed.split_whitespace().last() {
            if looks_like_file(last) && !last.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return Some(("nano".to_string(), last.to_string()));
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn is_known_editor(name: &str) -> bool {
    KNOWN_EDITORS.contains(&name)
}

/// Extract the base executable name from a full path.
fn executable_base_name(name: &str) -> String {
    PathBuf::from(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(name)
        .to_lowercase()
}

/// Strip vim's modified/readonly indicators from a title component.
/// e.g., "file.txt (+)" → "file.txt", "[file.txt]" → "file.txt"
fn strip_vim_modifiers(s: &str) -> &str {
    let s = s.trim();
    let s = s.strip_suffix(" (+)").unwrap_or(s);
    let s = s.strip_suffix(" [+]").unwrap_or(s);
    let s = s.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(s);
    s.trim()
}

/// Reject file paths in system directories (adversarial title injection defense).
fn is_safe_document_path(s: &str) -> bool {
    const BLOCKED: &[&str] = &[
        "/etc/", "/System/", "/Library/", "/var/db/", "/var/run/",
        "/proc/", "/sys/", "/dev/", "/boot/", "/sbin/",
        "C:\\Windows\\", "C:\\Program Files",
    ];
    !BLOCKED.iter().any(|prefix| s.starts_with(prefix))
}

/// Heuristic: does this string look like a filename?
fn looks_like_file(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 4096 {
        return false;
    }
    // Absolute path.
    if s.starts_with('/') || (s.len() > 2 && s.as_bytes()[1] == b':') {
        return is_safe_document_path(s);
    }
    // Has a file extension.
    if s.contains('.') && !s.starts_with('.') {
        return true;
    }
    // Has path separators.
    if s.contains('/') || s.contains('\\') {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Terminal emulator detection ---

    #[cfg(target_os = "macos")]
    #[test]
    fn test_terminal_bundle_ids() {
        assert!(is_terminal_emulator_bundle("com.apple.Terminal"));
        assert!(is_terminal_emulator_bundle("com.googlecode.iterm2"));
        assert!(is_terminal_emulator_bundle("COM.APPLE.TERMINAL")); // case-insensitive
        assert!(!is_terminal_emulator_bundle("com.apple.TextEdit"));
        assert!(!is_terminal_emulator_bundle("com.microsoft.VSCode"));
    }

    #[test]
    fn test_terminal_name_detection() {
        assert!(is_terminal_emulator_name("iTerm2"));
        assert!(is_terminal_emulator_name("kitty"));
        assert!(is_terminal_emulator_name("Windows Terminal"));
        assert!(!is_terminal_emulator_name("TextEdit"));
        assert!(!is_terminal_emulator_name("Safari"));
    }

    // --- Editor name detection ---

    #[test]
    fn test_known_editors() {
        assert!(is_known_editor("vim"));
        assert!(is_known_editor("nvim"));
        assert!(is_known_editor("emacs"));
        assert!(is_known_editor("nano"));
        assert!(is_known_editor("helix"));
        assert!(is_known_editor("hx"));
        assert!(!is_known_editor("firefox"));
        assert!(!is_known_editor("ls"));
    }

    #[test]
    fn test_executable_base_name() {
        assert_eq!(executable_base_name("/usr/bin/nvim"), "nvim");
        assert_eq!(executable_base_name("/opt/homebrew/bin/helix"), "helix");
        assert_eq!(executable_base_name("vim"), "vim");
    }

    // --- Title parsing ---

    #[test]
    fn test_parse_nvim_title() {
        let result = parse_terminal_title_for_editor("essay.md - NVIM");
        assert!(result.is_some());
        let (editor, file) = result.unwrap();
        assert_eq!(editor, "nvim");
        assert_eq!(file, "essay.md");
    }

    #[test]
    fn test_parse_vim_title_with_modifier() {
        let result = parse_terminal_title_for_editor("essay.md (+) - VIM");
        assert!(result.is_some());
        let (editor, file) = result.unwrap();
        assert_eq!(editor, "vim");
        assert_eq!(file, "essay.md");
    }

    #[test]
    fn test_parse_vim_left_title() {
        let result = parse_terminal_title_for_editor("VIM - /Users/me/doc.txt");
        assert!(result.is_some());
        let (editor, file) = result.unwrap();
        assert_eq!(editor, "vim");
        assert_eq!(file, "/Users/me/doc.txt");
    }

    #[test]
    fn test_parse_emacs_title() {
        let result = parse_terminal_title_for_editor("emacs: draft.org");
        assert!(result.is_some());
        let (editor, file) = result.unwrap();
        assert_eq!(editor, "emacs");
        assert_eq!(file, "draft.org");
    }

    #[test]
    fn test_parse_emacs_with_host() {
        let result = parse_terminal_title_for_editor("emacs@myhost: paper.tex");
        assert!(result.is_some());
        let (editor, file) = result.unwrap();
        assert_eq!(editor, "emacs");
        assert_eq!(file, "paper.tex");
    }

    #[test]
    fn test_parse_nano_title() {
        let result = parse_terminal_title_for_editor("  GNU nano 7.2  readme.md");
        assert!(result.is_some());
        let (editor, file) = result.unwrap();
        assert_eq!(editor, "nano");
        assert_eq!(file, "readme.md");
    }

    #[test]
    fn test_parse_helix_title() {
        let result = parse_terminal_title_for_editor("main.rs - helix");
        assert!(result.is_some());
        let (editor, file) = result.unwrap();
        assert_eq!(editor, "helix");
        assert_eq!(file, "main.rs");
    }

    #[test]
    fn test_parse_no_editor() {
        assert!(parse_terminal_title_for_editor("~/projects").is_none());
        assert!(parse_terminal_title_for_editor("zsh").is_none());
        assert!(parse_terminal_title_for_editor("").is_none());
    }

    #[test]
    fn test_parse_absolute_path_in_title() {
        let result = parse_terminal_title_for_editor("/Users/me/novel.md - NVIM");
        assert!(result.is_some());
        let (_, file) = result.unwrap();
        assert_eq!(file, "/Users/me/novel.md");
    }

    // --- File heuristics ---

    #[test]
    fn test_looks_like_file() {
        assert!(looks_like_file("essay.md"));
        assert!(looks_like_file("/Users/me/doc.txt"));
        assert!(looks_like_file("src/main.rs"));
        assert!(!looks_like_file(""));
        assert!(!looks_like_file("   "));
    }

    #[test]
    fn test_strip_vim_modifiers() {
        assert_eq!(strip_vim_modifiers("file.txt (+)"), "file.txt");
        assert_eq!(strip_vim_modifiers("file.txt [+]"), "file.txt");
        assert_eq!(strip_vim_modifiers("[file.txt]"), "file.txt");
        assert_eq!(strip_vim_modifiers("file.txt"), "file.txt");
    }
}
