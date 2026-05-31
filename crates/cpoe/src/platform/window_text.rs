// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Cross-window text capture for transcription detection.
//!
//! On macOS, enumerates visible windows via `CGWindowListCopyWindowInfo` and
//! reads text content from each via the Accessibility API (`AXUIElement`).
//! On other platforms, provides a no-op stub.

use serde::{Deserialize, Serialize};

/// Text content captured from a visible window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowText {
    pub app_name: String,
    pub window_title: String,
    /// The text content read from the window. Never stored in evidence.
    pub text_content: String,
    pub pid: u32,
}

/// Captures text from visible windows on the current machine.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct WindowTextCapture;

#[cfg(target_os = "macos")]
impl WindowTextCapture {
    /// Enumerate visible windows and read their text content.
    ///
    /// `exclude_pid` filters out the monitored application's own windows.
    /// Returns text from on-screen, layer-0 windows that expose AX text content.
    pub fn capture_visible_windows(exclude_pid: Option<u32>) -> Vec<WindowText> {
        unsafe { capture_visible_windows_macos(exclude_pid) }
    }
}

#[cfg(target_os = "macos")]
unsafe fn capture_visible_windows_macos(exclude_pid: Option<u32>) -> Vec<WindowText> {
    use core_foundation::base::TCFType;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use core_foundation_sys::array::{CFArrayGetCount, CFArrayGetValueAtIndex};
    use core_foundation_sys::base::CFRelease;
    use core_foundation_sys::dictionary::CFDictionaryGetValueIfPresent;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGWindowListCopyWindowInfo(
            option: u32,
            relative_to_window: u32,
        ) -> core_foundation_sys::array::CFArrayRef;
    }

    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXUIElementCreateApplication(pid: i32) -> *mut std::ffi::c_void;
        fn AXUIElementCopyAttributeValue(
            element: *mut std::ffi::c_void,
            attribute: core_foundation_sys::string::CFStringRef,
            value: *mut *const std::ffi::c_void,
        ) -> i32;
    }

    const K_CG_WINDOW_LIST_OPTION_ON_SCREEN_ONLY: u32 = 1;
    const K_CG_NULL_WINDOW_ID: u32 = 0;

    let list =
        CGWindowListCopyWindowInfo(K_CG_WINDOW_LIST_OPTION_ON_SCREEN_ONLY, K_CG_NULL_WINDOW_ID);
    if list.is_null() {
        return Vec::new();
    }

    let count = CFArrayGetCount(list);
    let key_pid = CFString::from_static_string("kCGWindowOwnerPID");
    let key_name = CFString::from_static_string("kCGWindowName");
    let key_layer = CFString::from_static_string("kCGWindowLayer");
    let key_owner = CFString::from_static_string("kCGWindowOwnerName");

    let mut results = Vec::new();

    for i in 0..count {
        let raw_dict =
            CFArrayGetValueAtIndex(list, i) as core_foundation_sys::dictionary::CFDictionaryRef;
        if raw_dict.is_null() {
            continue;
        }

        // Only layer 0 (normal windows).
        let mut layer_ptr: *const std::ffi::c_void = std::ptr::null();
        if CFDictionaryGetValueIfPresent(raw_dict, key_layer.as_CFTypeRef(), &mut layer_ptr) != 0
            && !layer_ptr.is_null()
        {
            let layer_num =
                CFNumber::wrap_under_get_rule(layer_ptr as core_foundation::number::CFNumberRef);
            if layer_num.to_i32().unwrap_or(-1) != 0 {
                continue;
            }
        }

        // Read PID.
        let mut pid_ptr: *const std::ffi::c_void = std::ptr::null();
        if CFDictionaryGetValueIfPresent(raw_dict, key_pid.as_CFTypeRef(), &mut pid_ptr) == 0
            || pid_ptr.is_null()
        {
            continue;
        }
        let pid_num =
            CFNumber::wrap_under_get_rule(pid_ptr as core_foundation::number::CFNumberRef);
        let pid = pid_num.to_i32().unwrap_or(-1);
        if pid <= 0 {
            continue;
        }

        // Skip the excluded PID.
        if let Some(excl) = exclude_pid {
            if pid as u32 == excl {
                continue;
            }
        }

        // Read owner name.
        let app_name = {
            let mut ptr: *const std::ffi::c_void = std::ptr::null();
            if CFDictionaryGetValueIfPresent(raw_dict, key_owner.as_CFTypeRef(), &mut ptr) != 0
                && !ptr.is_null()
            {
                CFString::wrap_under_get_rule(ptr as core_foundation::string::CFStringRef)
                    .to_string()
            } else {
                String::new()
            }
        };

        // Read window title.
        let window_title = {
            let mut ptr: *const std::ffi::c_void = std::ptr::null();
            if CFDictionaryGetValueIfPresent(raw_dict, key_name.as_CFTypeRef(), &mut ptr) != 0
                && !ptr.is_null()
            {
                CFString::wrap_under_get_rule(ptr as core_foundation::string::CFStringRef)
                    .to_string()
            } else {
                String::new()
            }
        };

        // Try to read text content via AX.
        let text_content = read_window_text_via_ax(
            pid,
            AXUIElementCreateApplication,
            AXUIElementCopyAttributeValue,
        );

        if let Some(text) = text_content {
            if !text.is_empty() {
                results.push(WindowText {
                    app_name,
                    window_title,
                    text_content: text,
                    pid: pid as u32,
                });
            }
        }
    }

    CFRelease(list as *mut _);
    results
}

/// Read text content from an application's focused window via AX attributes.
///
/// Tries AXValue first (text fields), then AXSelectedText, then walks AXChildren
/// for AXStaticText elements.
#[cfg(target_os = "macos")]
unsafe fn read_window_text_via_ax(
    pid: i32,
    create_app: unsafe extern "C" fn(i32) -> *mut std::ffi::c_void,
    copy_attr: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        core_foundation_sys::string::CFStringRef,
        *mut *const std::ffi::c_void,
    ) -> i32,
) -> Option<String> {
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::CFRelease;

    const K_AX_ERROR_SUCCESS: i32 = 0;

    let app_element = create_app(pid);
    if app_element.is_null() {
        return None;
    }

    // Get focused window.
    let attr_focused = CFString::new("AXFocusedWindow");
    let mut focused_window: *const std::ffi::c_void = std::ptr::null();
    let err = copy_attr(
        app_element,
        attr_focused.as_concrete_TypeRef(),
        &mut focused_window,
    );
    if err != K_AX_ERROR_SUCCESS || focused_window.is_null() {
        CFRelease(app_element);
        return None;
    }

    // Try AXValue (text areas, text fields).
    let result = try_ax_string(focused_window as *mut _, copy_attr, "AXValue")
        .or_else(|| try_ax_string(focused_window as *mut _, copy_attr, "AXSelectedText"));

    CFRelease(focused_window as *mut _);
    CFRelease(app_element);
    result
}

/// Attempt to read a string-valued AX attribute from an element.
#[cfg(target_os = "macos")]
unsafe fn try_ax_string(
    element: *mut std::ffi::c_void,
    copy_attr: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        core_foundation_sys::string::CFStringRef,
        *mut *const std::ffi::c_void,
    ) -> i32,
    attribute: &str,
) -> Option<String> {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::string::CFString;

    const K_AX_ERROR_SUCCESS: i32 = 0;

    let attr = CFString::new(attribute);
    let mut value: *const std::ffi::c_void = std::ptr::null();
    let err = copy_attr(element, attr.as_concrete_TypeRef(), &mut value);
    if err != K_AX_ERROR_SUCCESS || value.is_null() {
        return None;
    }
    let cf_type = CFType::wrap_under_create_rule(value as _);
    cf_type
        .downcast::<CFString>()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

// --- Non-macOS stub ---

#[cfg(target_os = "windows")]
pub struct WindowTextCapture;

#[cfg(target_os = "windows")]
impl WindowTextCapture {
    pub fn capture_visible_windows(exclude_pid: Option<u32>) -> Vec<WindowText> {
        use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
            IsWindowVisible,
        };

        struct Context {
            results: Vec<WindowText>,
            exclude_pid: Option<u32>,
        }

        unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
            let ctx = &mut *(lparam.0 as *mut Context);
            if !IsWindowVisible(hwnd).as_bool() {
                return BOOL(1);
            }
            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if let Some(excl) = ctx.exclude_pid {
                if pid == excl {
                    return BOOL(1);
                }
            }
            let title_len = GetWindowTextLengthW(hwnd);
            if title_len == 0 || title_len > 16384 {
                return BOOL(1);
            }
            let mut title_buf = vec![0u16; (title_len + 1) as usize];
            let actual = GetWindowTextW(hwnd, &mut title_buf);
            if actual == 0 {
                return BOOL(1);
            }
            let title = String::from_utf16_lossy(&title_buf[..actual as usize]);
            let app_name = windows_process_name(pid).unwrap_or_default();
            ctx.results.push(WindowText {
                app_name,
                window_title: title,
                text_content: String::new(),
                pid,
            });
            BOOL(1)
        }

        let mut ctx = Context {
            results: Vec::new(),
            exclude_pid: exclude_pid,
        };
        unsafe {
            let _ = EnumWindows(
                Some(callback),
                LPARAM(&mut ctx as *mut Context as isize),
            );
        }
        ctx.results
    }
}

#[cfg(target_os = "windows")]
fn windows_process_name(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut path = [0u16; 1024];
        let mut size = path.len() as u32;
        let result = QueryFullProcessImageNameW(
            handle,
            Default::default(),
            windows::core::PWSTR(path.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(handle);
        result.ok()?;
        let exe_path = String::from_utf16_lossy(&path[..size as usize]);
        std::path::Path::new(&exe_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .map(String::from)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub struct WindowTextCapture;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl WindowTextCapture {
    pub fn capture_visible_windows(_exclude_pid: Option<u32>) -> Vec<WindowText> {
        Vec::new()
    }
}
