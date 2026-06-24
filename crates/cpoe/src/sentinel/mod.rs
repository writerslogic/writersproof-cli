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
    adapter_for_bundle, install_global, AppAdapter, AppRegistry, ContentGranularity,
    ProbeConfidence, StoragePattern, UserWritingApp, WitnessingMode,
};
pub mod behavioral_key;
pub mod bundle_monitor;
pub use self::bundle_monitor::{is_bundle_document, start_bundle_monitor, BundleMonitor};
pub mod clipboard;
pub mod content_classifier;
pub mod content_fingerprint;
pub mod core;
pub mod core_session;
mod core_setup;
pub mod daemon;
pub mod document_watcher;
pub mod error;
mod event_handlers;
pub mod focus;
pub mod helpers;
pub mod ipc_handler;
pub mod permission_monitor;
pub mod process_files;
pub mod relationships;
pub mod remote_registry;
pub mod shadow;
pub mod terminal_editors;
pub mod types;

#[cfg(target_os = "macos")]
pub mod macos_focus;

#[cfg(target_os = "linux")]
pub mod linux_focus;

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
    attribute_change_to_segment, classify_paste_source, compute_file_hash,
    create_document_hash_payload, create_session_start_payload, detect_export_event,
    detect_paste_boundary, end_session_sync, focus_document_sync, handle_change_event_sync,
    handle_focus_event_sync, is_within_paste_window, parse_fdx_scene_fingerprint,
    parse_scrivener_project_map, unfocus_document_sync, update_keystroke_context_window,
};
pub use self::ipc_handler::SentinelIpcHandler;
pub use self::relationships::{detect_co_edited_files, CoEditedPair};
pub use self::shadow::ShadowManager;
pub use self::types::{
    extract_title_path_hint, generate_session_id, hash_string, infer_document_path_from_title,
    infer_document_path_from_title_with_bundle, normalize_document_path, parse_url_parts,
    resolve_title_hint_to_path, AiToolCategory, ChangeEvent, ChangeEventType, DetectedAiTool,
    DocumentSession, FocusEvent, FocusEventType, FocusSwitchRecord, KeystrokeContext,
    ObservationBasis, PasteContentKind, PasteContext, PasteSource, PasteboardTypeInventory,
    ScrivenerProjectMap, SessionBinding, SessionEvent, SessionEventType, SessionSegment,
    TitlePathHint, WindowInfo,
};

// ---------------------------------------------------------------------------
// IOKit HID capture lifecycle (macOS only)
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "macos", target_os = "windows"))]
static HID_CAPTURE: std::sync::Mutex<Option<crate::platform::HidInputCapture>> =
    std::sync::Mutex::new(None);

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn start_hid_capture() {
    use crate::MutexRecover;
    let mut guard = HID_CAPTURE.lock_recover();
    if guard.is_some() {
        return;
    }
    match crate::platform::HidInputCapture::start() {
        Some(capture) => {
            log::info!("HID capture started for dual-layer validation");
            *guard = Some(capture);
        }
        None => {
            log::info!("HID capture unavailable; dual-layer validation disabled");
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(crate) fn start_hid_capture() {}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn stop_hid_capture() {
    use crate::MutexRecover;
    let mut guard = HID_CAPTURE.lock_recover();
    if let Some(mut capture) = guard.take() {
        capture.stop();
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(crate) fn stop_hid_capture() {}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn hid_key_down_count() -> u64 {
    use crate::MutexRecover;
    HID_CAPTURE
        .lock_recover()
        .as_ref()
        .map(|c| c.key_down_count())
        .unwrap_or(0)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn hid_key_down_count() -> u64 {
    0
}

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

#[cfg(target_os = "windows")]
pub(crate) async fn platform_clipboard_read(
) -> std::result::Result<(i32, String), self::clipboard::ClipboardError> {
    tokio::task::spawn_blocking(|| {
        use windows::Win32::Foundation::HGLOBAL;
        use windows::Win32::System::DataExchange::{
            CloseClipboard, GetClipboardData, GetClipboardSequenceNumber, OpenClipboard,
        };
        use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};

        const CF_UNICODETEXT: u32 = 13;

        let seq = unsafe { GetClipboardSequenceNumber() } as i32;

        unsafe {
            OpenClipboard(None)
                .map_err(|_| self::clipboard::ClipboardError::PasteboardAccessDenied)?;

            let text = (|| -> String {
                let handle = match GetClipboardData(CF_UNICODETEXT) {
                    Ok(h) if !h.is_invalid() => h,
                    _ => return String::new(),
                };
                let hglobal = HGLOBAL(handle.0 as *mut _);
                let ptr = GlobalLock(hglobal) as *const u16;
                if ptr.is_null() {
                    return String::new();
                }
                let mut len = 0usize;
                while *ptr.add(len) != 0 {
                    len += 1;
                    if len > 4 * 1024 * 1024 {
                        break;
                    }
                }
                let slice = std::slice::from_raw_parts(ptr, len);
                let result = String::from_utf16_lossy(slice);
                let _ = GlobalUnlock(hglobal);
                result
            })();

            let _ = CloseClipboard();
            Ok((seq, text))
        }
    })
    .await
    .map_err(|e| self::clipboard::ClipboardError::Other(format!("Clipboard task failed: {e}")))?
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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

#[cfg(target_os = "windows")]
pub(crate) async fn platform_clipboard_bundle_id(
) -> std::result::Result<String, self::clipboard::ClipboardError> {
    tokio::task::spawn_blocking(|| {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        use windows::Win32::UI::WindowsAndMessaging::{
            GetForegroundWindow, GetWindowThreadProcessId,
        };

        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.is_invalid() {
                return Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus);
            }
            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == 0 {
                return Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus);
            }
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                .map_err(|_| self::clipboard::ClipboardError::NoMonitoredAppInFocus)?;
            let mut path = [0u16; 1024];
            let mut size = path.len() as u32;
            let result = QueryFullProcessImageNameW(
                handle,
                Default::default(),
                windows::core::PWSTR(path.as_mut_ptr()),
                &mut size,
            );
            let _ = CloseHandle(handle);
            result.map_err(|_| self::clipboard::ClipboardError::NoMonitoredAppInFocus)?;
            let exe_path = String::from_utf16_lossy(&path[..size as usize]);
            let name = std::path::Path::new(&exe_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(&exe_path)
                .to_string();
            if name.is_empty() {
                Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus)
            } else {
                Ok(name)
            }
        }
    })
    .await
    .map_err(|e| self::clipboard::ClipboardError::Other(format!("Bundle ID task failed: {e}")))?
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
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
    .map_err(|e| self::clipboard::ClipboardError::Other(format!("Window title task failed: {e}")))?
}

#[cfg(target_os = "windows")]
pub(crate) async fn platform_clipboard_window_title(
) -> std::result::Result<String, self::clipboard::ClipboardError> {
    tokio::task::spawn_blocking(|| {
        use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW};

        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.is_invalid() {
                return Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus);
            }
            let mut buf = [0u16; 512];
            let len = GetWindowTextW(hwnd, &mut buf);
            if len == 0 {
                return Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus);
            }
            Ok(String::from_utf16_lossy(&buf[..len as usize]))
        }
    })
    .await
    .map_err(|e| self::clipboard::ClipboardError::Other(format!("Window title task failed: {e}")))?
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(crate) async fn platform_clipboard_window_title(
) -> std::result::Result<String, self::clipboard::ClipboardError> {
    Err(self::clipboard::ClipboardError::NoMonitoredAppInFocus)
}

#[cfg(target_os = "macos")]
const MACOS_IMAGE_UTIS: &[&str] = &[
    "public.png",
    "public.tiff",
    "public.jpeg",
    "com.apple.pict",
    "public.heic",
    "com.compuserve.gif",
];

#[cfg(target_os = "macos")]
const MACOS_SPREADSHEET_UTIS: &[&str] = &[
    "com.microsoft.excel.xlsx",
    "com.microsoft.excel.xls",
    "org.openxmlformats.spreadsheetml.sheet",
    "com.apple.iwork.numbers.sffnumbers",
];

#[cfg(target_os = "macos")]
pub(crate) async fn platform_pasteboard_types() -> self::types::PasteboardTypeInventory {
    tokio::task::spawn_blocking(|| {
        use objc::runtime::Object;
        use std::ffi::CStr;
        use std::os::raw::c_char;
        unsafe {
            let pool: *mut Object = msg_send![class!(NSAutoreleasePool), new];
            let pasteboard: *mut Object = msg_send![class!(NSPasteboard), generalPasteboard];
            if pasteboard.is_null() {
                let _: () = msg_send![pool, drain];
                return self::types::PasteboardTypeInventory::default();
            }
            let types_array: *mut Object = msg_send![pasteboard, types];
            if types_array.is_null() {
                let _: () = msg_send![pool, drain];
                return self::types::PasteboardTypeInventory::default();
            }
            let count: usize = msg_send![types_array, count];
            let mut inv = self::types::PasteboardTypeInventory::default();
            for i in 0..count {
                let ns_type: *mut Object = msg_send![types_array, objectAtIndex: i];
                if ns_type.is_null() {
                    continue;
                }
                let ptr: *const c_char = msg_send![ns_type, UTF8String];
                if ptr.is_null() {
                    continue;
                }
                let uti = CStr::from_ptr(ptr).to_string_lossy();
                if uti == "public.utf8-plain-text" {
                    inv.has_plain_text = true;
                } else if uti == "public.rtf" {
                    inv.has_rtf = true;
                } else if uti == "public.html" {
                    inv.has_html = true;
                }
                if MACOS_IMAGE_UTIS.iter().any(|&u| u == uti.as_ref()) {
                    inv.has_image = true;
                }
                if MACOS_SPREADSHEET_UTIS.iter().any(|&u| u == uti.as_ref()) {
                    inv.has_spreadsheet = true;
                }
                inv.utis.push(uti.into_owned());
            }
            let _: () = msg_send![pool, drain];
            inv
        }
    })
    .await
    .unwrap_or_default()
}

#[cfg(target_os = "windows")]
pub(crate) async fn platform_pasteboard_types() -> self::types::PasteboardTypeInventory {
    tokio::task::spawn_blocking(|| {
        use windows::Win32::System::DataExchange::{
            CloseClipboard, EnumClipboardFormats, GetClipboardFormatNameW, OpenClipboard,
        };

        const CF_UNICODETEXT: u32 = 13;
        const CF_BITMAP: u32 = 2;
        const CF_DIB: u32 = 8;
        const CF_DIBV5: u32 = 17;

        let mut inv = self::types::PasteboardTypeInventory::default();

        unsafe {
            if OpenClipboard(None).is_err() {
                return inv;
            }

            let mut fmt = EnumClipboardFormats(0);
            while fmt != 0 {
                match fmt {
                    CF_UNICODETEXT => inv.has_plain_text = true,
                    CF_BITMAP | CF_DIB | CF_DIBV5 => inv.has_image = true,
                    _ => {
                        let mut buf = [0u16; 256];
                        let len = GetClipboardFormatNameW(fmt, &mut buf);
                        if len > 0 {
                            let name = String::from_utf16_lossy(&buf[..len as usize]);
                            if name == "Rich Text Format" {
                                inv.has_rtf = true;
                            } else if name == "HTML Format" {
                                inv.has_html = true;
                            }
                            inv.utis.push(name);
                        }
                    }
                }
                fmt = EnumClipboardFormats(fmt);
            }

            let _ = CloseClipboard();
        }
        inv
    })
    .await
    .unwrap_or_default()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub(crate) async fn platform_pasteboard_types() -> self::types::PasteboardTypeInventory {
    self::types::PasteboardTypeInventory::default()
}
