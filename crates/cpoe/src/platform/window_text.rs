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
    /// `exclude_pid` filters out the monitored application's own windows UNLESS
    /// `exclude_window_id` is provided, in which case only that specific window
    /// is excluded (allowing other windows from the same app to be read).
    /// Returns text from on-screen, layer-0 windows that expose AX text content.
    pub fn capture_visible_windows(
        exclude_pid: Option<u32>,
        exclude_window_id: Option<u32>,
    ) -> Vec<WindowText> {
        unsafe { capture_visible_windows_macos(exclude_pid, exclude_window_id) }
    }
}

#[cfg(target_os = "macos")]
unsafe fn capture_visible_windows_macos(
    exclude_pid: Option<u32>,
    exclude_window_id: Option<u32>,
) -> Vec<WindowText> {
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
    let key_number = CFString::from_static_string("kCGWindowNumber");

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

        // Read window number for exclusion filtering.
        let window_number = {
            let mut ptr: *const std::ffi::c_void = std::ptr::null();
            if CFDictionaryGetValueIfPresent(raw_dict, key_number.as_CFTypeRef(), &mut ptr) != 0
                && !ptr.is_null()
            {
                CFNumber::wrap_under_get_rule(ptr as core_foundation::number::CFNumberRef)
                    .to_i32()
                    .map(|n| n as u32)
            } else {
                None
            }
        };

        // When exclude_window_id is set, only skip that specific window
        // (allows reading other windows from the same app, e.g. two TextEdit docs).
        // Otherwise fall back to excluding all windows from the PID.
        if let Some(excl_wid) = exclude_window_id {
            if window_number == Some(excl_wid) {
                continue;
            }
        } else if let Some(excl) = exclude_pid {
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

        // Try to read text content via AX, targeting the specific window by title.
        let text_content = read_window_text_via_ax(
            pid,
            if window_title.is_empty() { None } else { Some(window_title.as_str()) },
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

/// Read text content from a specific window of an application via AX attributes.
///
/// When `target_title` is provided, enumerates AXWindows to find the matching
/// window by title. Falls back to AXFocusedWindow if no title match is found
/// or if `target_title` is None.
/// Tries AXValue first (text areas), then AXSelectedText.
#[cfg(target_os = "macos")]
unsafe fn read_window_text_via_ax(
    pid: i32,
    target_title: Option<&str>,
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

    // Try to find the specific window by title via AXWindows.
    // Read text while the array is alive to avoid use-after-free
    // (CFArrayGetValueAtIndex returns a Get-rule pointer).
    if let Some(title) = target_title {
        let attr_windows = CFString::new("AXWindows");
        let mut windows_value: *const std::ffi::c_void = std::ptr::null();
        let err = copy_attr(
            app_element,
            attr_windows.as_concrete_TypeRef(),
            &mut windows_value,
        );
        if err == K_AX_ERROR_SUCCESS && !windows_value.is_null() {
            use core_foundation_sys::array::{CFArrayGetCount, CFArrayGetValueAtIndex};
            let arr = windows_value as core_foundation_sys::array::CFArrayRef;
            let win_count = CFArrayGetCount(arr);
            let attr_title = CFString::new("AXTitle");
            let mut result: Option<String> = None;
            for j in 0..win_count {
                let win = CFArrayGetValueAtIndex(arr, j);
                if win.is_null() {
                    continue;
                }
                let mut title_value: *const std::ffi::c_void = std::ptr::null();
                let terr = copy_attr(
                    win as *mut _,
                    attr_title.as_concrete_TypeRef(),
                    &mut title_value,
                );
                if terr == K_AX_ERROR_SUCCESS && !title_value.is_null() {
                    use core_foundation::base::CFType;
                    let cf_type = CFType::wrap_under_create_rule(title_value as _);
                    #[allow(clippy::cmp_owned)]
                    if let Some(win_title) = cf_type.downcast::<CFString>() {
                        if win_title.to_string() == title {
                            // Read text now while the window ref is still valid.
                            result = try_ax_string(win as *mut _, copy_attr, "AXValue")
                                .or_else(|| try_ax_string(win as *mut _, copy_attr, "AXSelectedText"))
                                .or_else(|| find_text_in_children(win as *mut _, copy_attr));
                            break;
                        }
                    }
                }
            }
            CFRelease(windows_value as *mut _);
            if result.is_some() {
                CFRelease(app_element);
                return result;
            }
        }
    }

    // Fall back to focused window if no title match or no title provided.
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

    let result = try_ax_string(focused_window as *mut _, copy_attr, "AXValue")
        .or_else(|| try_ax_string(focused_window as *mut _, copy_attr, "AXSelectedText"))
        .or_else(|| find_text_in_children(focused_window as *mut _, copy_attr));

    CFRelease(focused_window as *mut _);
    CFRelease(app_element);
    result
}

/// Search immediate children of an AX element for text content.
/// Looks for AXTextArea or AXTextField children and reads their AXValue.
#[cfg(target_os = "macos")]
unsafe fn find_text_in_children(
    element: *mut std::ffi::c_void,
    copy_attr: unsafe extern "C" fn(
        *mut std::ffi::c_void,
        core_foundation_sys::string::CFStringRef,
        *mut *const std::ffi::c_void,
    ) -> i32,
) -> Option<String> {
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;
    use core_foundation_sys::array::{CFArrayGetCount, CFArrayGetValueAtIndex};
    use core_foundation_sys::base::CFRelease;

    const K_AX_ERROR_SUCCESS: i32 = 0;
    const MAX_DEPTH: u8 = 3;

    fn search_recursive(
        element: *mut std::ffi::c_void,
        copy_attr: unsafe extern "C" fn(
            *mut std::ffi::c_void,
            core_foundation_sys::string::CFStringRef,
            *mut *const std::ffi::c_void,
        ) -> i32,
        depth: u8,
    ) -> Option<String> {
        if depth >= MAX_DEPTH {
            return None;
        }
        unsafe {
            let attr_role = CFString::new("AXRole");
            let mut role_value: *const std::ffi::c_void = std::ptr::null();
            let err = copy_attr(element, attr_role.as_concrete_TypeRef(), &mut role_value);
            if err == K_AX_ERROR_SUCCESS && !role_value.is_null() {
                use core_foundation::base::CFType;
                let cf_type = CFType::wrap_under_create_rule(role_value as _);
                if let Some(role_str) = cf_type.downcast::<CFString>() {
                    let role = role_str.to_string();
                    if role == "AXTextArea" || role == "AXTextField" {
                        if let Some(text) = try_ax_string(element, copy_attr, "AXValue") {
                            if text.len() >= 50 {
                                return Some(text);
                            }
                        }
                    }
                }
            }

            let attr_children = CFString::new("AXChildren");
            let mut children_value: *const std::ffi::c_void = std::ptr::null();
            let err = copy_attr(element, attr_children.as_concrete_TypeRef(), &mut children_value);
            if err != K_AX_ERROR_SUCCESS || children_value.is_null() {
                return None;
            }
            let arr = children_value as core_foundation_sys::array::CFArrayRef;
            let count = CFArrayGetCount(arr);
            let limit = count.min(20);
            let mut result = None;
            for j in 0..limit {
                let child = CFArrayGetValueAtIndex(arr, j);
                if child.is_null() {
                    continue;
                }
                if let Some(text) = search_recursive(child as *mut _, copy_attr, depth + 1) {
                    result = Some(text);
                    break;
                }
            }
            CFRelease(children_value as *mut _);
            result
        }
    }

    search_recursive(element, copy_attr, 0)
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
    pub fn capture_visible_windows(exclude_pid: Option<u32>, _exclude_window_id: Option<u32>) -> Vec<WindowText> {
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
    pub fn capture_visible_windows(_exclude_pid: Option<u32>, _exclude_window_id: Option<u32>) -> Vec<WindowText> {
        Vec::new()
    }
}
