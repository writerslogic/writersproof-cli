// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI functions for Endpoint Security event notifications from the host app.
//!
//! These are called by the Swift EndpointSecurityEventClient when ES events
//! match tracked documents or known AI tools.

use super::sentinel::get_sentinel;
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
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
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
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
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
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
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
}

/// Record an ES capture gap (dropped events detected via sequence number jump).
///
/// Called by the Swift ES client when `seq_num` or `global_seq_num` jumps,
/// indicating the kernel dropped events because the client couldn't keep up.
/// Marks all active sessions as degraded.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_capture_gap(missed_count: u32) -> bool {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    log::warn!("ES capture gap: {missed_count} event(s) dropped by kernel");

    let mut sessions = sentinel.sessions.write_recover();
    for session in sessions.values_mut() {
        session.capture_gaps = session.capture_gaps.saturating_add(missed_count);
    }

    true
}

/// Set a pre-fetched challenge nonce to be bound into the next checkpoint.
///
/// Called by the host app after requesting a challenge from the WritersProof CA.
/// The nonce is consumed by the next checkpoint timer tick; if no checkpoint
/// fires within 30 seconds, the nonce expires and is discarded.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_set_challenge_nonce(nonce: String) -> bool {
    if nonce.len() > 1024 {
        log::warn!(
            "Challenge nonce too long ({} bytes), rejecting",
            nonce.len()
        );
        return false;
    }
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return false,
    };

    log::info!("Challenge nonce set for next checkpoint");
    *sentinel.pending_challenge.write_recover() = Some((nonce, None));
    true
}

/// Return the list of AI tools detected across all active sessions (deduplicated).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sentinel_es_ai_tools_active() -> Vec<String> {
    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) if s.is_running() => s,
        _ => return Vec::new(),
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
