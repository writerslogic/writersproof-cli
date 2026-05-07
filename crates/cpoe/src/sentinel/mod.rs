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

pub mod app_discovery;
pub mod app_registry;
pub use app_discovery::ProbeResult;
pub use app_registry::{
    adapter_for_bundle, AppAdapter, AppRegistry, ProbeConfidence, StoragePattern, UserWritingApp,
};
pub mod behavioral_key;
pub mod bundle_monitor;
pub use self::bundle_monitor::{is_bundle_document, start_bundle_monitor, BundleMonitor};
pub mod permission_monitor;
pub mod clipboard;
pub mod core;
pub mod core_session;
mod core_setup;
pub mod daemon;
pub mod error;
pub mod focus;
pub mod helpers;
pub mod ipc_handler;
pub mod relationships;
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

pub use self::clipboard::{ClipboardError, ClipboardMonitor, CopyEvent, EvidenceEvent};
pub use self::core::Sentinel;
pub use self::daemon::{
    cmd_start, cmd_start_foreground, cmd_status, cmd_stop, cmd_track, cmd_untrack, DaemonHandle,
    DaemonManager, DaemonState, DaemonStatus,
};
pub use self::error::{Result, SentinelError};
pub use self::focus::{PollingSentinelFocusTracker, SentinelFocusTracker, WindowProvider};
pub use self::helpers::{
    attribute_change_to_segment, check_idle_sessions_sync, classify_paste_source,
    compute_file_hash, create_document_hash_payload, create_session_start_payload,
    detect_export_event, detect_paste_boundary, end_all_sessions_sync, end_session_sync,
    focus_document_sync, handle_change_event_sync, handle_focus_event_sync,
    is_within_paste_window, parse_fdx_scene_fingerprint, parse_scrivener_project_map,
    unfocus_document_sync, update_keystroke_context_window,
};
pub use self::ipc_handler::SentinelIpcHandler;
pub use self::shadow::ShadowManager;
pub use self::relationships::{CoEditedPair, detect_co_edited_files};
pub use self::types::{
    generate_session_id, hash_string, infer_document_path_from_title,
    infer_document_path_from_title_with_bundle, normalize_document_path, parse_url_parts,
    AiToolCategory, ChangeEvent, ChangeEventType, DetectedAiTool, DocumentSession, FocusEvent,
    FocusEventType, FocusSwitchRecord, KeystrokeContext, ObservationBasis, PasteContext,
    PasteSource, ScrivenerProjectMap, SessionBinding, SessionEvent, SessionEventType,
    SessionSegment, WindowInfo,
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

// ---------------------------------------------------------------------------
// Clipboard platform helpers (macOS NSPasteboard, called from ClipboardMonitor)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub(crate) async fn platform_clipboard_read(
) -> std::result::Result<(i32, String), self::clipboard::ClipboardError> {
    tokio::task::spawn_blocking(|| {
        use objc::runtime::Object;
        use std::ffi::CStr;
        use std::os::raw::c_char;
        unsafe {
            let pool: *mut Object = msg_send![class!(NSAutoreleasePool), new];
            let pasteboard: *mut Object = msg_send![class!(NSPasteboard), generalPasteboard];
            if pasteboard.is_null() {
                let _: () = msg_send![pool, drain];
                return Err(self::clipboard::ClipboardError::PasteboardAccessDenied);
            }
            let change_count: i64 = msg_send![pasteboard, changeCount];
            let ptype_bytes = b"public.utf8-plain-text\0";
            let ptype_cstr = CStr::from_bytes_with_nul(ptype_bytes).unwrap();
            let ptype_nsstr: *mut Object = msg_send![
                class!(NSString),
                stringWithUTF8String: ptype_cstr.as_ptr() as *const c_char
            ];
            let ns_text: *mut Object = msg_send![pasteboard, stringForType: ptype_nsstr];
            let text = if ns_text.is_null() {
                String::new()
            } else {
                let ptr: *const c_char = msg_send![ns_text, UTF8String];
                if ptr.is_null() {
                    String::new()
                } else {
                    CStr::from_ptr(ptr).to_string_lossy().into_owned()
                }
            };
            let _: () = msg_send![pool, drain];
            Ok((change_count as i32, text))
        }
    })
    .await
    .map_err(|e| self::clipboard::ClipboardError::Other(format!("Pasteboard task failed: {e}")))?
}

#[cfg(not(target_os = "macos"))]
pub(crate) async fn platform_clipboard_read(
) -> std::result::Result<(i32, String), self::clipboard::ClipboardError> {
    Ok((0, String::new()))
}

#[cfg(target_os = "macos")]
pub(crate) async fn platform_clipboard_bundle_id(
) -> std::result::Result<String, self::clipboard::ClipboardError> {
    tokio::task::spawn_blocking(|| {
        use objc::runtime::Object;
        use std::ffi::CStr;
        use std::os::raw::c_char;
        unsafe {
            let pool: *mut Object = msg_send![class!(NSAutoreleasePool), new];
            let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
            let active_app: *mut Object = msg_send![workspace, frontmostApplication];
            if active_app.is_null() {
                let _: () = msg_send![pool, drain];
                return Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus);
            }
            let bundle_id: *mut Object = msg_send![active_app, bundleIdentifier];
            let result = if bundle_id.is_null() {
                Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus)
            } else {
                let ptr: *const c_char = msg_send![bundle_id, UTF8String];
                if ptr.is_null() {
                    Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus)
                } else {
                    let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
                    if s.is_empty() {
                        Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus)
                    } else {
                        Ok(s)
                    }
                }
            };
            let _: () = msg_send![pool, drain];
            result
        }
    })
    .await
    .map_err(|e| self::clipboard::ClipboardError::Other(format!("Bundle ID task failed: {e}")))?
}

#[cfg(not(target_os = "macos"))]
pub(crate) async fn platform_clipboard_bundle_id(
) -> std::result::Result<String, self::clipboard::ClipboardError> {
    Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus)
}

#[cfg(target_os = "macos")]
pub(crate) async fn platform_clipboard_window_title(
) -> std::result::Result<String, self::clipboard::ClipboardError> {
    tokio::task::spawn_blocking(|| {
        use objc::runtime::Object;
        use std::ffi::CStr;
        use std::os::raw::c_char;
        unsafe {
            let pool: *mut Object = msg_send![class!(NSAutoreleasePool), new];
            let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
            let active_app: *mut Object = msg_send![workspace, frontmostApplication];
            if active_app.is_null() {
                let _: () = msg_send![pool, drain];
                return Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus);
            }
            let name: *mut Object = msg_send![active_app, localizedName];
            let result = if name.is_null() {
                Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus)
            } else {
                let ptr: *const c_char = msg_send![name, UTF8String];
                if ptr.is_null() {
                    Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus)
                } else {
                    Ok(CStr::from_ptr(ptr).to_string_lossy().into_owned())
                }
            };
            let _: () = msg_send![pool, drain];
            result
        }
    })
    .await
    .map_err(|e| {
        self::clipboard::ClipboardError::Other(format!("Window title task failed: {e}"))
    })?
}

#[cfg(not(target_os = "macos"))]
pub(crate) async fn platform_clipboard_window_title(
) -> std::result::Result<String, self::clipboard::ClipboardError> {
    Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus)
}
