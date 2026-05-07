// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::focus::*;
use super::types::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use objc::runtime::Object;
use std::sync::Arc;
use std::time::SystemTime;

/// Bundle IDs of system UI processes that briefly become frontmost during
/// Mission Control, Stage Manager, and full-screen transitions. Returning
/// `None` for these lets the debounce timer suppress spurious FocusLost events.
const TRANSIENT_BUNDLES: &[&str] = &[
    "com.apple.dock",
    "com.apple.exposelauncher",
    "com.apple.systemuiserver",
];

#[derive(Debug)]
/// macOS focus monitor using NSWorkspace and Accessibility APIs.
pub struct MacOSFocusMonitor {
    _config: Arc<SentinelConfig>,
}

impl MacOSFocusMonitor {
    pub fn new(config: Arc<SentinelConfig>) -> Self {
        Self { _config: config }
    }

    pub fn new_monitor(config: Arc<SentinelConfig>) -> Box<dyn SentinelFocusTracker> {
        let provider = Arc::new(Self::new(Arc::clone(&config)));
        Box::new(PollingSentinelFocusTracker::new(provider, config))
    }

    fn get_active_window_info(&self) -> Option<WindowInfo> {
        // Wrap in an autorelease pool so Objective-C temporaries are freed
        // promptly when called from a tokio worker thread (which has no
        // default NSAutoreleasePool).
        let pool: *mut Object = unsafe { msg_send![class!(NSAutoreleasePool), new] };
        let result = unsafe {
            let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
            let active_app: *mut Object = msg_send![workspace, frontmostApplication];

            if active_app.is_null() {
                let _: () = msg_send![pool, drain];
                return None;
            }

            let name: *mut Object = msg_send![active_app, localizedName];
            let bundle_id: *mut Object = msg_send![active_app, bundleIdentifier];
            let pid: i32 = msg_send![active_app, processIdentifier];

            let app_name = nsstring_to_string(name);
            let bundle_id_str = nsstring_to_string(bundle_id);

            // Filter transient system UI processes (Mission Control, Stage Manager)
            if TRANSIENT_BUNDLES.contains(&bundle_id_str.as_str()) {
                let _: () = msg_send![pool, drain];
                return None;
            }

            // Try AX first (works when Accessibility permission is granted),
            // fall back to CGWindowList (works in App Sandbox without special perms).
            let doc_path = self.get_document_path_via_ax(pid);
            let (cg_title, cg_window_number) = self.get_cgwindow_info(pid);
            let window_title = self
                .get_window_title_via_ax(pid)
                .or(cg_title);
            let title_str = window_title.unwrap_or_default();

            super::trace!(
                "[AX_PROBE] app={} bundle={} ax_path={:?} title={:?}",
                app_name,
                bundle_id_str,
                doc_path,
                title_str
            );

            let doc_path = doc_path.or_else(|| {
                let inferred = super::types::infer_document_path_from_title_with_bundle(
                    &title_str,
                    Some(&bundle_id_str),
                )?;
                // Only use inferred paths that are absolute. Relative paths
                // (bare filenames like "essay.txt") cannot be resolved to real
                // files, causing hash failures and path mismatches on export.
                // The sentinel's title:// fallback handles bare filenames.
                if std::path::Path::new(&inferred).is_absolute() {
                    Some(inferred)
                } else {
                    None
                }
            });

            Some(WindowInfo {
                is_document: doc_path.is_some(),
                path: doc_path,
                application: if !bundle_id_str.is_empty() {
                    bundle_id_str
                } else {
                    app_name.clone()
                },
                title: ObfuscatedString::new(&title_str),
                pid: Some(pid as u32),
                timestamp: SystemTime::now(),
                is_unsaved: false,
                project_root: None,
                window_number: cg_window_number,
            })
        };
        unsafe {
            let _: () = msg_send![pool, drain];
        }
        result
    }

    /// Query the focused window's `AXDocument` attribute for its `file://` URL.
    /// Falls back to `AXURL` on the focused element (S10: WKWebView-hosted local content).
    fn get_document_path_via_ax(&self, pid: i32) -> Option<String> {
        if let Some(raw) = self.query_focused_window_attribute(pid, "AXDocument") {
            if let Some(path) = raw.strip_prefix("file://") {
                if let Ok(decoded) = urlencoding::decode(path) {
                    let owned = decoded.into_owned();
                    if !owned.is_empty() {
                        return Some(owned);
                    }
                }
            }
        }
        // S10: When AXDocument is absent (Electron/WKWebView apps), query AXURL
        // on the focused element. Only accept file:// URLs — https:// documents
        // are handled by the browser extension content script instead.
        let url_raw = self.query_focused_element_attribute(pid, "AXURL")?;
        if let Some(path) = url_raw.strip_prefix("file://") {
            if let Ok(decoded) = urlencoding::decode(path) {
                let owned = decoded.into_owned();
                if !owned.is_empty() {
                    return Some(owned);
                }
            }
        }
        None
    }

    /// Query the focused window's `AXTitle` attribute.
    fn get_window_title_via_ax(&self, pid: i32) -> Option<String> {
        let title = self.query_focused_window_attribute(pid, "AXTitle")?;
        if !title.is_empty() {
            Some(title)
        } else {
            None
        }
    }

    /// Query CGWindowListCopyWindowInfo for the topmost layer-0 window of a pid.
    /// Returns (window_title, window_number). Works in App Sandbox without
    /// Accessibility permission.
    fn get_cgwindow_info(&self, pid: i32) -> (Option<String>, Option<u32>) {
        unsafe {
            use core_foundation::base::TCFType;
            use core_foundation::string::CFString;
            use core_foundation_sys::dictionary::CFDictionaryGetValueIfPresent;

            #[link(name = "CoreGraphics", kind = "framework")]
            extern "C" {
                fn CGWindowListCopyWindowInfo(
                    option: u32,
                    relative_to_window: u32,
                ) -> core_foundation_sys::array::CFArrayRef;
            }

            // kCGWindowListOptionOnScreenOnly = 1, kCGNullWindowID = 0
            let list = CGWindowListCopyWindowInfo(1, 0);
            if list.is_null() {
                return (None, None);
            }

            let count = core_foundation_sys::array::CFArrayGetCount(list);
            let key_pid = CFString::from_static_string("kCGWindowOwnerPID");
            let key_name = CFString::from_static_string("kCGWindowName");
            let key_layer = CFString::from_static_string("kCGWindowLayer");
            let key_number = CFString::from_static_string("kCGWindowNumber");

            for i in 0..count {
                let raw_dict = core_foundation_sys::array::CFArrayGetValueAtIndex(list, i)
                    as core_foundation_sys::dictionary::CFDictionaryRef;
                if raw_dict.is_null() {
                    continue;
                }

                // Only look at layer 0 (normal windows)
                let mut layer_ptr: *const std::ffi::c_void = std::ptr::null();
                if CFDictionaryGetValueIfPresent(raw_dict, key_layer.as_CFTypeRef(), &mut layer_ptr)
                    != 0
                    && !layer_ptr.is_null()
                {
                    let layer_num = core_foundation::number::CFNumber::wrap_under_get_rule(
                        layer_ptr as core_foundation::number::CFNumberRef,
                    );
                    if layer_num.to_i32().unwrap_or(-1) != 0 {
                        continue;
                    }
                }

                let mut pid_ptr: *const std::ffi::c_void = std::ptr::null();
                if CFDictionaryGetValueIfPresent(raw_dict, key_pid.as_CFTypeRef(), &mut pid_ptr)
                    == 0
                    || pid_ptr.is_null()
                {
                    continue;
                }
                let pid_num = core_foundation::number::CFNumber::wrap_under_get_rule(
                    pid_ptr as core_foundation::number::CFNumberRef,
                );
                if pid_num.to_i32().unwrap_or(-1) != pid {
                    continue;
                }

                // Extract window number (kCGWindowNumber)
                let mut num_ptr: *const std::ffi::c_void = std::ptr::null();
                let win_num = if CFDictionaryGetValueIfPresent(
                    raw_dict,
                    key_number.as_CFTypeRef(),
                    &mut num_ptr,
                ) != 0
                    && !num_ptr.is_null()
                {
                    let n = core_foundation::number::CFNumber::wrap_under_get_rule(
                        num_ptr as core_foundation::number::CFNumberRef,
                    );
                    n.to_i32().map(|v| v as u32)
                } else {
                    None
                };

                // Extract window title
                let mut name_ptr: *const std::ffi::c_void = std::ptr::null();
                let title = if CFDictionaryGetValueIfPresent(
                    raw_dict,
                    key_name.as_CFTypeRef(),
                    &mut name_ptr,
                ) != 0
                    && !name_ptr.is_null()
                {
                    let name = CFString::wrap_under_get_rule(
                        name_ptr as core_foundation::string::CFStringRef,
                    );
                    let s = name.to_string();
                    if s.is_empty() { None } else { Some(s) }
                } else {
                    None
                };

                core_foundation_sys::base::CFRelease(list as _);
                return (title, win_num);
            }

            core_foundation_sys::base::CFRelease(list as _);
            (None, None)
        }
    }

    /// Query an arbitrary accessibility attribute from the focused window of a given pid.
    fn query_focused_window_attribute(&self, pid: i32, attribute: &str) -> Option<String> {
        unsafe {
            let app = ax_create_application(pid)?;
            let window = match ax_child(app, "AXFocusedWindow") {
                Some(w) => w,
                None => { ax_release(app); return None; }
            };
            let result = ax_read_string(window, attribute);
            ax_release(window);
            ax_release(app);
            result
        }
    }

    /// Query an attribute from the focused UI element (not the focused window).
    /// Used for S10: reading `AXURL` from a WKWebView/web area element.
    fn query_focused_element_attribute(&self, pid: i32, attribute: &str) -> Option<String> {
        unsafe {
            let app = ax_create_application(pid)?;
            let elem = match ax_child(app, "AXFocusedUIElement") {
                Some(e) => e,
                None => { ax_release(app); return None; }
            };
            let result = ax_read_string(elem, attribute);
            ax_release(elem);
            ax_release(app);
            result
        }
    }
}

impl WindowProvider for MacOSFocusMonitor {
    fn get_active_window(&self) -> Option<WindowInfo> {
        self.get_active_window_info()
    }
}

// ---------------------------------------------------------------------------
// Shared AX helpers used by query_focused_window_attribute and
// query_focused_element_attribute to avoid duplicating extern "C" blocks.
// ---------------------------------------------------------------------------

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXUIElementCreateApplication(pid: i32) -> *mut std::ffi::c_void;
    fn AXUIElementCopyAttributeValue(
        element: *mut std::ffi::c_void,
        attribute: core_foundation::string::CFStringRef,
        value: *mut *const std::ffi::c_void,
    ) -> i32;
    fn CFRelease(cf: *mut std::ffi::c_void);
}

/// Create an AXUIElement for a process, returning `None` if the pid is invalid.
unsafe fn ax_create_application(pid: i32) -> Option<*mut std::ffi::c_void> {
    let el = AXUIElementCreateApplication(pid);
    if el.is_null() { None } else { Some(el) }
}

/// Copy a single AX attribute from `element` as a raw CF pointer.
/// Returns `None` on any AX error or when the attribute value is null.
unsafe fn ax_child(
    element: *mut std::ffi::c_void,
    attribute: &str,
) -> Option<*mut std::ffi::c_void> {
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;
    let attr = CFString::new(attribute);
    let mut value: *const std::ffi::c_void = std::ptr::null();
    let err = AXUIElementCopyAttributeValue(element, attr.as_concrete_TypeRef(), &mut value);
    if err == 0 && !value.is_null() { Some(value as *mut _) } else { None }
}

/// Read an AX attribute from `element` as a `String`.
unsafe fn ax_read_string(
    element: *mut std::ffi::c_void,
    attribute: &str,
) -> Option<String> {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::string::CFString;
    let child = ax_child(element, attribute)?;
    let cf = CFType::wrap_under_create_rule(child as _);
    cf.downcast::<CFString>().map(|s| s.to_string())
}

/// Release a Core Foundation object obtained via a `Copy` or `Create` rule.
unsafe fn ax_release(ptr: *mut std::ffi::c_void) {
    if !ptr.is_null() {
        CFRelease(ptr);
    }
}

unsafe fn nsstring_to_string(ns_str: *mut Object) -> String {
    if ns_str.is_null() {
        return String::new();
    }
    let char_ptr: *const std::os::raw::c_char = msg_send![ns_str, UTF8String];
    if char_ptr.is_null() {
        return String::new();
    }
    std::ffi::CStr::from_ptr(char_ptr)
        .to_string_lossy()
        .into_owned()
}

/// Check if accessibility permissions are granted (does not prompt).
pub fn check_accessibility_permissions() -> bool {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;

    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXIsProcessTrustedWithOptions(
            options: core_foundation::dictionary::CFDictionaryRef,
        ) -> bool;
    }

    let key = CFString::new("AXTrustedCheckOptionPrompt");
    let value = CFBoolean::false_value();
    let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

    unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
}

/// Request accessibility permissions (shows system prompt dialog).
pub fn request_accessibility_permissions() -> bool {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;

    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXIsProcessTrustedWithOptions(
            options: core_foundation::dictionary::CFDictionaryRef,
        ) -> bool;
    }

    let key = CFString::new("AXTrustedCheckOptionPrompt");
    let value = CFBoolean::true_value();
    let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

    unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
}
