// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Background document tracking daemon.
//!
//! Monitors focused documents and manages tracking sessions automatically.
//! Operates invisibly during writing, surfacing only on explicit status requests.
//!
//! - Debounced focus change handling (200ms default)
//! - Multi-document session management with shadow buffers
//! - Platform-specific focus detection (macOS, Linux, Windows)

/// Sentinel-specific trace logging (delegates to `log::trace!`).
macro_rules! trace {
    ($($arg:tt)*) => {
        log::trace!($($arg)*)
    };
}
pub(crate) use trace;

pub mod app_registry;
pub use app_registry::{AppRegistry, ProbeConfidence, UserWritingApp};
pub mod behavioral_key;
pub mod clipboard;
pub mod core;
pub mod core_session;
mod core_setup;
pub mod daemon;
pub mod error;
pub mod focus;
pub mod helpers;
pub mod ipc_handler;
pub mod shadow;
pub mod types;

#[cfg(target_os = "macos")]
pub mod macos_focus;

#[cfg(not(target_os = "macos"))]
pub mod stub_focus;

#[cfg(target_os = "windows")]
pub mod windows_focus;

#[cfg(test)]
mod tests;

pub use self::clipboard::{ClipboardMonitor, CopyEvent, EvidenceEvent, ClipboardError};
pub use self::core::Sentinel;
pub use self::daemon::{
    cmd_start, cmd_start_foreground, cmd_status, cmd_stop, cmd_track, cmd_untrack, DaemonHandle,
    DaemonManager, DaemonState, DaemonStatus,
};
pub use self::error::{Result, SentinelError};
pub use self::focus::{PollingSentinelFocusTracker, SentinelFocusTracker, WindowProvider};
pub use self::helpers::{
    check_idle_sessions_sync, compute_file_hash, create_document_hash_payload,
    create_session_start_payload, detect_paste_boundary, end_all_sessions_sync, end_session_sync,
    focus_document_sync, handle_change_event_sync, handle_focus_event_sync,
    is_within_paste_window, unfocus_document_sync, update_keystroke_context_window,
};
pub use self::ipc_handler::SentinelIpcHandler;
pub use self::shadow::ShadowManager;
pub use self::types::{
    generate_session_id, hash_string, infer_document_path_from_title,
    infer_document_path_from_title_with_bundle, normalize_document_path, parse_url_parts,
    AiToolCategory, ChangeEvent, ChangeEventType, DetectedAiTool, DocumentSession, FocusEvent,
    FocusEventType, FocusSwitchRecord, KeystrokeContext, ObservationBasis, PasteContext,
    SessionBinding, SessionEvent, SessionEventType, WindowInfo,
};

// ---------------------------------------------------------------------------
// IOKit HID capture lifecycle (macOS only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
static HID_CAPTURE: std::sync::Mutex<Option<crate::platform::HidInputCapture>> =
    std::sync::Mutex::new(None);

/// Start IOKit HID capture for dual-layer keystroke validation.
/// No-op on non-macOS platforms.
#[cfg(target_os = "macos")]
pub(crate) fn start_hid_capture() {
    use crate::MutexRecover;
    let mut guard = HID_CAPTURE.lock_recover();
    if guard.is_some() {
        return; // Already running.
    }
    match crate::platform::HidInputCapture::start() {
        Some(capture) => {
            log::info!("IOKit HID capture started for dual-layer validation");
            *guard = Some(capture);
        }
        None => {
            log::info!("IOKit HID capture unavailable; dual-layer validation disabled");
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn start_hid_capture() {}

/// Stop IOKit HID capture. Called during sentinel shutdown.
#[cfg(target_os = "macos")]
pub(crate) fn stop_hid_capture() {
    use crate::MutexRecover;
    let mut guard = HID_CAPTURE.lock_recover();
    if let Some(mut capture) = guard.take() {
        capture.stop();
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn stop_hid_capture() {}

/// Get the HID keyDown count for dual-layer validation. Returns 0 if not running.
#[cfg(target_os = "macos")]
pub fn hid_key_down_count() -> u64 {
    use crate::MutexRecover;
    HID_CAPTURE
        .lock_recover()
        .as_ref()
        .map(|c| c.key_down_count())
        .unwrap_or(0)
}

#[cfg(not(target_os = "macos"))]
pub fn hid_key_down_count() -> u64 {
    0
}
