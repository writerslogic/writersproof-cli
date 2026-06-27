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

    /// Capture text from a specific application's focused window by PID.
    pub fn capture_text_for_pid(pid: u32) -> Option<String> {
        unsafe { capture_text_for_pid_macos(pid) }
    }

    /// Capture text from an application's focused window by bundle ID.
    ///
    /// Resolves the bundle ID to a running PID via `NSRunningApplication`,
    /// then reads text from the focused window via Accessibility.
    pub fn capture_text_for_bundle_id(bundle_id: &str) -> Option<String> {
        let pid = running_pid_for_bundle_id(bundle_id)?;
        Self::capture_text_for_pid(pid)
    }

    /// Capture text from a specific window of an application, identified by
    /// bundle ID and window title. When `title` is provided, targets that
    /// specific window instead of the focused window; falls back to focused
    /// window if no title match is found and `title` is `None`.
    pub fn capture_text_for_bundle_id_and_title(
        bundle_id: &str,
        title: Option<&str>,
    ) -> Option<String> {
        let pid = running_pid_for_bundle_id(bundle_id)?;
        unsafe {
            #[link(name = "ApplicationServices", kind = "framework")]
            extern "C" {
                fn AXUIElementCreateApplication(pid: i32) -> *mut std::ffi::c_void;
                fn AXUIElementCopyAttributeValue(
                    element: *mut std::ffi::c_void,
                    attribute: core_foundation_sys::string::CFStringRef,
                    value: *mut *const std::ffi::c_void,
                ) -> i32;
            }
            read_window_text_via_ax(
                pid as i32,
                title,
                AXUIElementCreateApplication,
                AXUIElementCopyAttributeValue,
            )
        }
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

    // Only fall back to focused window if no title was provided.
    // When a title IS provided but didn't match, the window is unreachable via AX —
    // falling back to AXFocusedWindow would read the typing target (self-match).
    if target_title.is_some() {
        CFRelease(app_element);
        return None;
    }
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

#[cfg(target_os = "macos")]
unsafe fn capture_text_for_pid_macos(pid: u32) -> Option<String> {
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXUIElementCreateApplication(pid: i32) -> *mut std::ffi::c_void;
        fn AXUIElementCopyAttributeValue(
            element: *mut std::ffi::c_void,
            attribute: core_foundation_sys::string::CFStringRef,
            value: *mut *const std::ffi::c_void,
        ) -> i32;
    }

    // Read text from the app's focused window via AX.
    read_window_text_via_ax(
        pid as i32,
        None,
        AXUIElementCreateApplication,
        AXUIElementCopyAttributeValue,
    )
}

/// Resolve a bundle ID to the PID of a running application via NSRunningApplication.
#[cfg(target_os = "macos")]
fn running_pid_for_bundle_id(bundle_id: &str) -> Option<u32> {
    use objc::runtime::{Class, Object};

    unsafe {
        let pool_cls = Class::get("NSAutoreleasePool")?;
        let ra_cls = Class::get("NSRunningApplication")?;
        let pool: *mut Object = msg_send![pool_cls, new];

        let ns_bid = nsstring_from_str(bundle_id);
        let running: *mut Object =
            msg_send![ra_cls, runningApplicationsWithBundleIdentifier: ns_bid];
        if running.is_null() {
            let _: () = msg_send![pool, drain];
            return None;
        }
        let count: usize = msg_send![running, count];
        if count == 0 {
            let _: () = msg_send![pool, drain];
            return None;
        }
        let app: *mut Object = msg_send![running, firstObject];
        let pid: i32 = msg_send![app, processIdentifier];
        let _: () = msg_send![pool, drain];
        if pid > 0 { Some(pid as u32) } else { None }
    }
}

/// Create an NSString from a Rust &str.
#[cfg(target_os = "macos")]
unsafe fn nsstring_from_str(s: &str) -> *mut objc::runtime::Object {
    if s.len() > 4096 {
        return std::ptr::null_mut();
    }
    let cls = match objc::runtime::Class::get("NSString") {
        Some(c) => c,
        None => return std::ptr::null_mut(),
    };
    let ptr: *const u8 = s.as_ptr();
    let len: usize = s.len();
    msg_send![cls, stringWithBytes:ptr length:len encoding:4u64]
}

// --- Non-macOS stub ---

#[cfg(target_os = "windows")]
pub struct WindowTextCapture;

#[cfg(target_os = "windows")]
impl WindowTextCapture {
    pub fn capture_text_for_pid(_pid: u32) -> Option<String> {
        None
    }

    pub fn capture_text_for_bundle_id(_bundle_id: &str) -> Option<String> {
        None
    }

    pub fn capture_text_for_bundle_id_and_title(
        _bundle_id: &str,
        _title: Option<&str>,
    ) -> Option<String> {
        None
    }

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

// ---------------------------------------------------------------------------
// Linux X11 implementation
// ---------------------------------------------------------------------------
//
// X11 exposes window *titles* (via `_NET_WM_NAME` / `WM_NAME`) and the owning
// PID (via `_NET_WM_PID`), but -- unlike the macOS Accessibility API -- it
// offers no way to read the text *content* of another application's windows.
// So the text-content readers below return `None`, and `capture_visible_windows`
// enumerates managed top-level windows (`_NET_CLIENT_LIST`) with their titles,
// app names, and PIDs, leaving `text_content` empty. The active-window title
// path used for focus tracking (`_NET_ACTIVE_WINDOW` -> `_NET_WM_NAME`) lives in
// `sentinel/linux_focus.rs`; this type covers the cross-window enumeration API.
#[cfg(all(target_os = "linux", feature = "x11"))]
#[derive(Debug)]
pub struct WindowTextCapture;

#[cfg(all(target_os = "linux", feature = "x11"))]
impl WindowTextCapture {
    /// X11 has no API to read another window's text content.
    pub fn capture_text_for_pid(_pid: u32) -> Option<String> {
        None
    }

    /// X11 has no API to read another window's text content.
    pub fn capture_text_for_bundle_id(_bundle_id: &str) -> Option<String> {
        None
    }

    /// X11 has no API to read another window's text content.
    pub fn capture_text_for_bundle_id_and_title(
        _bundle_id: &str,
        _title: Option<&str>,
    ) -> Option<String> {
        None
    }

    /// Enumerate managed top-level windows (`_NET_CLIENT_LIST`) and read each
    /// window's title (`_NET_WM_NAME`, falling back to `WM_NAME`) and owning
    /// process name. `text_content` is always empty on X11.
    ///
    /// `exclude_pid` drops windows owned by that PID, unless `exclude_window_id`
    /// is provided, in which case only that specific window is dropped (matching
    /// the macOS contract).
    pub fn capture_visible_windows(
        exclude_pid: Option<u32>,
        exclude_window_id: Option<u32>,
    ) -> Vec<WindowText> {
        linux_x11::capture_visible_windows(exclude_pid, exclude_window_id).unwrap_or_default()
    }
}

#[cfg(all(target_os = "linux", feature = "x11"))]
mod linux_x11 {
    use super::WindowText;
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{Atom, AtomEnum, ConnectionExt, Window};
    use x11rb::rust_connection::RustConnection;

    /// Cap on the number of windows read from `_NET_CLIENT_LIST` (in 32-bit
    /// units passed to `GetProperty`); far above any real desktop's window count.
    const MAX_WINDOWS: u32 = 1024;

    struct X11Ctx {
        conn: RustConnection,
        root: Window,
        net_client_list: Atom,
        net_wm_name: Atom,
        net_wm_pid: Atom,
        wm_name: Atom,
    }

    impl X11Ctx {
        fn connect() -> Option<Self> {
            let (conn, screen_num) = RustConnection::connect(None).ok()?;
            let root = conn.setup().roots.get(screen_num)?.root;
            Some(Self {
                net_client_list: intern(&conn, b"_NET_CLIENT_LIST")?,
                net_wm_name: intern(&conn, b"_NET_WM_NAME")?,
                net_wm_pid: intern(&conn, b"_NET_WM_PID")?,
                wm_name: intern(&conn, b"WM_NAME")?,
                conn,
                root,
            })
        }

        fn client_list(&self) -> Vec<Window> {
            self.conn
                .get_property(false, self.root, self.net_client_list, AtomEnum::ANY, 0, MAX_WINDOWS)
                .ok()
                .and_then(|c| c.reply().ok())
                .and_then(|r| r.value32().map(|it| it.collect()))
                .unwrap_or_default()
        }

        /// Read the window title, preferring UTF-8 `_NET_WM_NAME` over `WM_NAME`.
        fn window_title(&self, window: Window) -> Option<String> {
            if let Some(title) = self.text_property(window, self.net_wm_name) {
                if !title.is_empty() {
                    return Some(title);
                }
            }
            self.text_property(window, self.wm_name)
                .filter(|t| !t.is_empty())
        }

        fn text_property(&self, window: Window, property: Atom) -> Option<String> {
            let reply = self
                .conn
                .get_property(false, window, property, AtomEnum::ANY, 0, 1024)
                .ok()?
                .reply()
                .ok()?;
            if reply.value_len == 0 {
                return None;
            }
            Some(String::from_utf8_lossy(&reply.value).into_owned())
        }

        fn window_pid(&self, window: Window) -> Option<u32> {
            self.conn
                .get_property(false, window, self.net_wm_pid, AtomEnum::ANY, 0, 1)
                .ok()?
                .reply()
                .ok()?
                .value32()?
                .next()
        }
    }

    fn intern(conn: &RustConnection, name: &[u8]) -> Option<Atom> {
        conn.intern_atom(false, name)
            .ok()?
            .reply()
            .ok()
            .map(|r| r.atom)
    }

    fn process_name(pid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
    }

    pub(super) fn capture_visible_windows(
        exclude_pid: Option<u32>,
        exclude_window_id: Option<u32>,
    ) -> Option<Vec<WindowText>> {
        let ctx = X11Ctx::connect()?;
        let mut out = Vec::new();
        for window in ctx.client_list() {
            let pid = ctx.window_pid(window);
            // Skip the monitored app's own windows. When a specific window id is
            // named, only that window is skipped (so sibling windows of the same
            // app are still read); otherwise every window of the PID is skipped.
            if let Some(excl_pid) = exclude_pid {
                let skip = match exclude_window_id {
                    Some(excl_win) => window == excl_win,
                    None => pid == Some(excl_pid),
                };
                if skip {
                    continue;
                }
            }
            let Some(title) = ctx.window_title(window) else {
                continue;
            };
            out.push(WindowText {
                app_name: pid.and_then(process_name).unwrap_or_default(),
                window_title: title,
                // X11 cannot read window text content; transcription detection
                // (which requires content) is a no-op on this platform.
                text_content: String::new(),
                pid: pid.unwrap_or(0),
            });
        }
        Some(out)
    }
}

// Fallback stub: Linux without the `x11` feature, plus any other non-macOS,
// non-Windows unix. Cross-window text/title capture is unavailable.
#[cfg(all(
    not(any(target_os = "macos", target_os = "windows")),
    not(all(target_os = "linux", feature = "x11"))
))]
#[derive(Debug)]
pub struct WindowTextCapture;

#[cfg(all(
    not(any(target_os = "macos", target_os = "windows")),
    not(all(target_os = "linux", feature = "x11"))
))]
impl WindowTextCapture {
    pub fn capture_text_for_pid(_pid: u32) -> Option<String> {
        None
    }

    pub fn capture_text_for_bundle_id(_bundle_id: &str) -> Option<String> {
        None
    }

    pub fn capture_text_for_bundle_id_and_title(
        _bundle_id: &str,
        _title: Option<&str>,
    ) -> Option<String> {
        None
    }

    pub fn capture_visible_windows(
        _exclude_pid: Option<u32>,
        _exclude_window_id: Option<u32>,
    ) -> Vec<WindowText> {
        Vec::new()
    }
}
