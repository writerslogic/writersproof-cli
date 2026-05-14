// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI functions for Endpoint Security event notifications from the host app.
//!
//! These are called by the Swift EndpointSecurityEventClient when ES events
//! match tracked documents or known AI tools.

use super::sentinel::get_running_sentinel;
use crate::ffi::types::catch_ffi_panic;
use crate::sentinel::types::{AiToolCategory, DetectedAiTool};
use crate::RwLockRecover;
use std::time::SystemTime;

/// Notify the sentinel that a tracked file was written or closed.
///
/// Called by the Swift ES client when `ES_EVENT_TYPE_NOTIFY_WRITE` or
/// `ES_EVENT_TYPE_NOTIFY_CLOSE` fires for a file that matches a tracked
/// document path. This can trigger an auto-checkpoint without polling.
///
/// Returns `true` if a checkpoint was committed.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_file_write(path: String, pid: i32, signing_id: String) -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_sentinel_es_file_write: path={}, pid={}, signing_id={}", path, pid, signing_id);
    let sentinel = match get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };

    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            log::warn!("ES file write path rejected: {e}");
            return false;
        }
    };

    // Only act on paths that are actually being tracked.
    let tracked = sentinel.tracked_files();
    if !tracked.iter().any(|t| t == &path) {
        return false;
    }

    log::info!(
        "ES file write detected for tracked document: {path} (pid={pid}, signing_id={signing_id})"
    );

    // Commit a checkpoint for this file since we know it was saved.
    sentinel.commit_checkpoint_for_path(&path)
    })
}

/// Notify the sentinel that a known AI tool process was launched.
///
/// Called by the Swift ES client when `ES_EVENT_TYPE_NOTIFY_EXEC` fires
/// for a process whose signing ID matches a known AI tool.
///
/// The sentinel constructs a `DetectedAiTool` with category and observation
/// basis, then persists it into all active document sessions. The detection
/// records tool presence, not document impact.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_ai_tool_detected(
    signing_id: String,
    pid: i32,
    ppid: i32,
    exec_path: String,
) -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_sentinel_es_ai_tool_detected: signing_id={}, pid={}, ppid={}, exec_path={}", signing_id, pid, ppid, exec_path);
    // signing_id is a macOS Team ID + bundle ID (max ~512 bytes);
    // exec_path is an absolute filesystem path (max 4096 bytes per POSIX PATH_MAX).
    // Combined max = 4608 bytes. Reject before touching sentinel state.
    if signing_id.len() > 512 || exec_path.len() > 4096 {
        log::warn!("ES AI tool params too long: signing_id={}, exec_path={}", signing_id.len(), exec_path.len());
        return false;
    }

    let sentinel = match get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };

    let (category, basis) = match AiToolCategory::from_signing_id(&signing_id) {
        Some(cb) => cb,
        None => {
            log::debug!("Unrecognized AI tool signing ID: {signing_id}");
            return false;
        }
    };

    log::info!(
        "AI tool detected via ES: signing_id={signing_id}, pid={pid}, \
         ppid={ppid}, category={category}, basis={basis}"
    );

    let tool = DetectedAiTool {
        signing_id: signing_id.clone(),
        pid,
        ppid,
        exec_path,
        category,
        basis,
        detected_at: SystemTime::now(),
    };

    // Persist into all active sessions, deduplicated on (signing_id, pid).
    const MAX_AI_TOOLS_PER_SESSION: usize = 256;
    let mut sessions = sentinel.sessions.write_recover();
    let mut updated = 0u32;
    for session in sessions.values_mut() {
        if session.ai_tools_detected.len() >= MAX_AI_TOOLS_PER_SESSION {
            log::warn!(
                "AI tool tracking limit reached ({MAX_AI_TOOLS_PER_SESSION}); ignoring {}",
                tool.signing_id
            );
            continue;
        }
        let already = session
            .ai_tools_detected
            .iter()
            .any(|t| t.signing_id == tool.signing_id && t.pid == tool.pid);
        if !already {
            session.ai_tools_detected.push(tool.clone());
            updated += 1;
        }
    }

    log::info!(
        "AI tool '{}' ({}) persisted to {} active session(s)",
        signing_id,
        category,
        updated
    );

    true
    })
}

/// Notify the sentinel that a tracked file was renamed or moved.
///
/// Called by the Swift ES client when `ES_EVENT_TYPE_NOTIFY_RENAME` fires.
/// Re-keys the active session from `old_path` to `new_path` so keystroke
/// attribution follows the file to its new location.
///
/// Returns `true` if a tracked session was updated.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_file_rename(old_path: String, new_path: String) -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_sentinel_es_file_rename: old_path={}, new_path={}", old_path, new_path);
    if old_path.len() > 4096 {
        return false;
    }
    let sentinel = match get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };

    let validated = match crate::sentinel::helpers::validate_path(&new_path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            log::warn!("Rename target path rejected: {e}");
            return false;
        }
    };

    log::info!("ES file rename detected: {old_path} -> {validated}");

    let mut sessions = sentinel.sessions.write_recover();
    if sessions.contains_key(&validated) {
        log::warn!("Rename target already tracked, ignoring: {old_path} -> {validated}");
        return false;
    }
    let mut session = match sessions.remove(&old_path) {
        Some(s) => s,
        None => return false,
    };
    session.path = validated.clone();
    sessions.insert(validated.clone(), session);
    drop(sessions);

    // Update current_focus if it pointed to the old path.
    let mut focus = sentinel.current_focus.write_recover();
    if focus.as_deref() == Some(old_path.as_str()) {
        *focus = Some(validated);
    }

    true
    })
}

/// Upgrade a virtual title:// session to a real file path when ES detects the
/// frontmost app opening a document file.
///
/// Called by the Swift ES client when `ES_EVENT_TYPE_NOTIFY_OPEN` fires for a
/// process that matches the frontmost app's PID and the opened path has a
/// recognized document extension. This gives ground-truth file identification
/// for Electron apps (VS Code, Cursor, Zed) that don't expose AXDocument.
///
/// Returns `true` if a session was upgraded from a title:// path.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_file_open(path: String, pid: i32) -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_sentinel_es_file_open: path={}, pid={}", path, pid);
    if path.len() > 4096 {
        return false;
    }
    let sentinel = match get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };

    let validated = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return false,
    };

    // Only upgrade if the currently focused session is a title:// virtual path.
    let current_path = {
        let focus = sentinel.current_focus.read_recover();
        focus.clone()
    };

    let current = match current_path {
        Some(ref p) if p.starts_with("title://") => p.clone(),
        _ => return false,
    };

    // Verify the opening process's bundle ID matches the focused session's app.
    // Resolve PID to bundle ID via NSRunningApplication (on macOS).
    let opener_bundle = crate::sentinel::macos_focus::bundle_id_for_pid(pid);

    // Check if this path has a recognized document extension.
    let ext_ok = std::path::Path::new(&validated)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            crate::sentinel::process_files::is_document_extension(&e.to_lowercase())
        })
        .unwrap_or(false);
    if !ext_ok {
        return false;
    }

    // Single write lock for the entire bundle verification + re-key operation
    // to prevent TOCTOU races between read and write phases.
    let mut sessions = sentinel.sessions.write_recover();

    let session_bid = sessions.get(&current).map(|s| s.app_bundle_id.clone());
    match (opener_bundle, session_bid) {
        (Some(opener), Some(bid)) if opener == bid => {}
        _ => return false,
    }

    if sessions.contains_key(&validated) {
        return false;
    }

    // Re-key the session from title:// to the real path.
    if let Some(mut session) = sessions.remove(&current) {
        log::info!(
            "ES file open: upgrading session from {} to {}",
            current, validated
        );
        session.origin_temp_path = Some(current.clone());
        session.path = validated.clone();
        session.evidence_confidence = crate::sentinel::types::EvidenceConfidence::Full;
        sessions.insert(validated.clone(), session);
        drop(sessions);

        // Re-check current_focus under the write lock to prevent overwriting
        // a concurrent focus change.
        let mut focus = sentinel.current_focus.write_recover();
        if focus.as_deref() == Some(current.as_str()) {
            *focus = Some(validated);
        }
        return true;
    }

    false
    })
}

/// Record an ES capture gap (dropped events detected via sequence number jump).
///
/// Called by the Swift ES client when `seq_num` or `global_seq_num` jumps,
/// indicating the kernel dropped events because the client couldn't keep up.
/// Marks all active sessions as degraded.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_capture_gap(missed_count: u32) -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_sentinel_es_capture_gap: missed_count={}", missed_count);
    let sentinel = match get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };

    log::warn!("ES capture gap: {missed_count} event(s) dropped by kernel");

    let mut sessions = sentinel.sessions.write_recover();
    for session in sessions.values_mut() {
        session.capture_gaps = session.capture_gaps.saturating_add(missed_count);
    }

    true
    })
}

/// Set a pre-fetched challenge nonce to be bound into the next checkpoint.
///
/// Called by the host app after requesting a challenge from the WritersProof CA.
/// The nonce is consumed by the next checkpoint timer tick; if no checkpoint
/// fires within 30 seconds, the nonce expires and is discarded.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_set_challenge_nonce(nonce: String) -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_sentinel_set_challenge_nonce: nonce_len={}", nonce.len());
    if nonce.len() > 1024 {
        log::warn!(
            "Challenge nonce too long ({} bytes), rejecting",
            nonce.len()
        );
        return false;
    }
    let sentinel = match get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };

    log::info!("Challenge nonce set for next checkpoint");
    *sentinel.pending_challenge.write_recover() = Some((nonce, None));
    true
    })
}

/// Return the list of AI tools detected across all active sessions (deduplicated).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_ai_tools_active() -> Vec<String> {
    catch_ffi_panic!(vec![], {
    log::debug!("ffi_sentinel_es_ai_tools_active called");
    let sentinel = match get_running_sentinel() {
        Some(s) => s,
        None => return Vec::new(),
    };

    let sessions = sentinel.sessions.read_recover();
    let mut seen = std::collections::HashSet::new();
    let mut tools = Vec::new();
    for session in sessions.values() {
        for tool in &session.ai_tools_detected {
            if seen.insert(&tool.signing_id) {
                tools.push(tool.signing_id.clone());
            }
        }
    }
    tools
    })
}

/// Known terminal text editors whose exec events should create tracking sessions.
/// Matched against the basename of the exec path.
const TERMINAL_EDITORS: &[&str] = &[
    "vi", "vim", "nvim", "neovim",
    "emacs", "emacsclient",
    "nano", "pico",
    "hx",       // Helix
    "micro",
    "joe", "jed",
    "mcedit",
    "kakoune", "kak",
];

/// Called by the Swift ES client when `ES_EVENT_TYPE_NOTIFY_EXEC` fires for a
/// process whose executable basename matches a known terminal text editor.
///
/// `editor_path` is the full exec path (e.g. `/usr/bin/vim`).
/// `file_arg` is the first non-flag argument — the file being opened.
///
/// Returns `true` if a tracking session was successfully started for the file.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_terminal_editor_exec(
    editor_path: String,
    file_arg: String,
) -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_sentinel_es_terminal_editor_exec: editor_path={}, file_arg={}", editor_path, file_arg);
    if editor_path.len() > 4096 || file_arg.len() > 4096 {
        log::warn!(
            "ffi_sentinel_es_terminal_editor_exec: args too long ({}/{})",
            editor_path.len(), file_arg.len()
        );
        return false;
    }
    if file_arg.is_empty() {
        return false;
    }

    let editor_name = std::path::Path::new(&editor_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    if !TERMINAL_EDITORS.contains(&editor_name) {
        log::debug!("ffi_sentinel_es_terminal_editor_exec: unrecognised editor {editor_name:?}");
        return false;
    }

    let sentinel = match get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };

    sentinel.inject_terminal_editor_session(&file_arg, editor_name)
    })
}

/// Notify the sentinel that a dictation session has begun for `doc_path`.
///
/// Called by `DictationMonitor.swift` when `SFSpeechRecognizer` starts recognizing
/// for a document that is already being tracked.
///
/// `device_uid_hash_hex` is the 8-byte IORegistry device UID hash, hex-encoded (16 chars).
/// `ambient_noise_db` is the dBFS reading from AVAudioEngine (-100.0 = not measured).
///
/// Returns `true` if the sentinel accepted the begin event.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_dictation_begin(
    doc_path: String,
    es_speech_pid: u32,
    audio_transport_type: u8,
    device_uid_hash_hex: String,
    ambient_noise_db: f32,
) -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_sentinel_dictation_begin: doc_path={}, es_speech_pid={}, audio_transport_type={}, ambient_noise_db={}", doc_path, es_speech_pid, audio_transport_type, ambient_noise_db);
    if doc_path.len() > 4096 || device_uid_hash_hex.len() > 16 {
        log::warn!("ffi_sentinel_dictation_begin: params too long");
        return false;
    }

    let device_uid_hash = match crate::utils::hex_decode_8(&device_uid_hash_hex) {
        Ok(h) => h,
        Err(e) => {
            log::warn!("ffi_sentinel_dictation_begin: invalid device_uid_hash_hex: {e}");
            return false;
        }
    };

    let sentinel = match get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };

    sentinel.begin_dictation(&doc_path, es_speech_pid, audio_transport_type, device_uid_hash, ambient_noise_db)
    })
}

/// Record an incremental recognition fragment from the speech recognizer.
///
/// Called by `DictationMonitor.swift` for each `SFSpeechRecognitionResult` that
/// is marked as final. `transcript_text` is hashed with BLAKE3 on the Rust side
/// and never stored — only the hash enters the WAL chain.
///
/// Returns `true` if the fragment was recorded.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_dictation_fragment(
    doc_path: String,
    word_count: u32,
    confidence: f32,
    correction_count: u32,
    transcript_text: String,
    speaker_output_active: bool,
) -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_sentinel_dictation_fragment: doc_path={}, word_count={}, confidence={}, correction_count={}, transcript_len={}, speaker_output_active={}", doc_path, word_count, confidence, correction_count, transcript_text.len(), speaker_output_active);
    if doc_path.len() > 4096 || transcript_text.len() > 65536 {
        log::warn!("ffi_sentinel_dictation_fragment: params too long");
        return false;
    }
    // confidence=0.0 is valid: it means "low confidence but recorded" (e.g. background noise).
    // Only NaN, infinity, and out-of-range values are rejected.
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        log::warn!("ffi_sentinel_dictation_fragment: invalid confidence {confidence}");
        return false;
    }

    let text_hash = crate::utils::blake3_hash_bytes(transcript_text.as_bytes());

    let sentinel = match get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };

    sentinel.record_dictation_fragment(
        &doc_path,
        word_count,
        confidence,
        correction_count,
        text_hash,
        speaker_output_active,
    )
    })
}

/// Finalize the active dictation session for `doc_path`.
///
/// Called by `DictationMonitor.swift` when `SFSpeechRecognizer` ends recognition.
/// `cross_window_similarity` (0.0–1.0) is computed by `CrossWindowDetector` on
/// the Swift side comparing the recognized text to visible screen content.
///
/// Returns `true` if the session was finalized and a `DictationEvent` was recorded.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_dictation_end(
    doc_path: String,
    speaker_output_active: bool,
    keystrokes_during: u32,
    cross_window_similarity: f32,
) -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_sentinel_dictation_end: doc_path={}, speaker_output_active={}, keystrokes_during={}, cross_window_similarity={}", doc_path, speaker_output_active, keystrokes_during, cross_window_similarity);
    if doc_path.len() > 4096 {
        log::warn!("ffi_sentinel_dictation_end: doc_path too long");
        return false;
    }
    if !cross_window_similarity.is_finite() {
        log::warn!("ffi_sentinel_dictation_end: invalid cross_window_similarity {cross_window_similarity}");
        return false;
    }
    let cross_window_similarity = cross_window_similarity.clamp(0.0, 1.0);

    let sentinel = match get_running_sentinel() {
        Some(s) => s,
        None => return false,
    };

    sentinel.end_dictation(&doc_path, speaker_output_active, keystrokes_during, cross_window_similarity)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel::types::{DocumentSession, ObservationBasis};

    fn make_session() -> DocumentSession {
        DocumentSession::new(
            "/tmp/test.txt".to_string(),
            "com.test".to_string(),
            "Test".to_string(),
            crate::crypto::ObfuscatedString::new("test"),
        )
    }

    fn make_tool(signing_id: &str, pid: i32) -> DetectedAiTool {
        let (category, basis) = AiToolCategory::from_signing_id(signing_id)
            .unwrap_or((AiToolCategory::DirectGenerative, ObservationBasis::Observed));
        DetectedAiTool {
            signing_id: signing_id.to_string(),
            pid,
            ppid: 1,
            exec_path: "/usr/bin/test".to_string(),
            category,
            basis,
            detected_at: SystemTime::now(),
        }
    }

    #[test]
    fn test_ai_tools_active_no_sentinel() {
        let tools = ffi_sentinel_es_ai_tools_active();
        assert!(tools.is_empty());
    }

    #[test]
    fn test_document_session_ai_tools_default_empty() {
        let session = make_session();
        assert!(session.ai_tools_detected.is_empty());
        assert_eq!(session.capture_gaps, 0);
    }

    #[test]
    fn test_document_session_ai_tools_dedup() {
        let mut session = make_session();
        let tool = make_tool("com.openai.chat", 100);
        session.ai_tools_detected.push(tool);
        // Simulate dedup on (signing_id, pid)
        let dup = make_tool("com.openai.chat", 100);
        let already = session
            .ai_tools_detected
            .iter()
            .any(|t| t.signing_id == dup.signing_id && t.pid == dup.pid);
        assert!(already);
        assert_eq!(session.ai_tools_detected.len(), 1);
        assert_eq!(session.ai_tools_detected[0].signing_id, "com.openai.chat");
    }

    #[test]
    fn test_document_session_multiple_ai_tools() {
        let mut session = make_session();
        session
            .ai_tools_detected
            .push(make_tool("com.openai.chat", 100));
        session
            .ai_tools_detected
            .push(make_tool("com.anthropic.claude", 200));
        assert_eq!(session.ai_tools_detected.len(), 2);
    }

    #[test]
    fn test_same_tool_different_pid_not_deduped() {
        let mut session = make_session();
        session
            .ai_tools_detected
            .push(make_tool("com.openai.chat", 100));
        session
            .ai_tools_detected
            .push(make_tool("com.openai.chat", 200));
        assert_eq!(session.ai_tools_detected.len(), 2);
    }

    #[test]
    fn test_ai_tool_category_mapping() {
        // Tier 1: direct AI tools (Observed)
        for id in [
            "com.openai.chat",
            "com.openai.chatgpt",
            "com.anthropic.claude",
            "com.ollama.ollama",
            "ai.lmstudio.app",
            "io.typingmind.app",
        ] {
            let (cat, basis) = AiToolCategory::from_signing_id(id).unwrap();
            assert_eq!(cat, AiToolCategory::DirectGenerative, "failed for {id}");
            assert_eq!(basis, ObservationBasis::Observed, "failed for {id}");
        }
        for id in [
            "com.github.copilot",
            "dev.cursor.app",
            "com.todesktop.230313mzl4w4u92",
            "com.replit.desktop",
        ] {
            let (cat, basis) = AiToolCategory::from_signing_id(id).unwrap();
            assert_eq!(cat, AiToolCategory::AssistantCopilot, "failed for {id}");
            assert_eq!(basis, ObservationBasis::Observed, "failed for {id}");
        }

        // Tier 2: AI-capable environments (Inferred)
        for id in [
            "com.apple.Safari",
            "com.google.Chrome",
            "org.mozilla.firefox",
        ] {
            let (cat, basis) = AiToolCategory::from_signing_id(id).unwrap();
            assert_eq!(cat, AiToolCategory::BrowserHosted, "failed for {id}");
            assert_eq!(basis, ObservationBasis::Inferred, "failed for {id}");
        }
        for id in [
            "com.microsoft.VSCode",
            "notion.id",
            "com.raycast.macos",
            "dev.warp.Warp-Stable",
        ] {
            let (cat, basis) = AiToolCategory::from_signing_id(id).unwrap();
            assert_eq!(cat, AiToolCategory::AssistantCopilot, "failed for {id}");
            assert_eq!(basis, ObservationBasis::Inferred, "failed for {id}");
        }
        for id in ["com.apple.Terminal", "com.googlecode.iterm2"] {
            let (cat, basis) = AiToolCategory::from_signing_id(id).unwrap();
            assert_eq!(cat, AiToolCategory::Automation, "failed for {id}");
            assert_eq!(basis, ObservationBasis::Inferred, "failed for {id}");
        }

        // Tier 3: automation (Observed)
        for id in [
            "com.apple.ScriptEditor2",
            "com.apple.Automator",
            "com.apple.ShortcutsActions",
        ] {
            let (cat, basis) = AiToolCategory::from_signing_id(id).unwrap();
            assert_eq!(cat, AiToolCategory::Automation, "failed for {id}");
            assert_eq!(basis, ObservationBasis::Observed, "failed for {id}");
        }

        // Unknown returns None
        assert!(AiToolCategory::from_signing_id("com.unknown.app").is_none());
    }

    #[test]
    fn test_capture_gap_tracking() {
        let mut session = make_session();
        assert_eq!(session.capture_gaps, 0);
        session.capture_gaps += 5;
        assert_eq!(session.capture_gaps, 5);
    }

    #[test]
    fn test_collect_ai_tool_limitations_no_sentinel() {
        let result = crate::ffi::evidence_export::collect_ai_tool_limitations("/tmp/test.txt");
        assert!(result.is_none());
    }
}
