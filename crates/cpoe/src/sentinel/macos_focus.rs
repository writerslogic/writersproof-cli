// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::focus::*;
use super::types::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use objc::runtime::Object;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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

            log::debug!(
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
                log::debug!("[AX_PROBE] title inferred: {:?} (absolute={})", inferred, std::path::Path::new(&inferred).is_absolute());
                if std::path::Path::new(&inferred).is_absolute() {
                    return Some(inferred);
                }
                let open_docs =
                    super::process_files::open_documents_for_pid(pid as u32);
                log::debug!("[AX_PROBE] FD scan: {} open docs for pid {}", open_docs.len(), pid);
                if let Some(matched) = open_docs.iter().find(|f| {
                    f.path
                        .file_name()
                        .map(|n| n.to_string_lossy().eq_ignore_ascii_case(&inferred))
                        .unwrap_or(false)
                }) {
                    log::debug!("[AX_PROBE] FD match: {:?}", matched.path);
                    return Some(matched.path.to_string_lossy().into_owned());
                }
                log::debug!("[AX_PROBE] no FD match, using title:// fallback");
                Some(format!("title://{}/{}", bundle_id_str, inferred))
            });

            // Last resort: enumerate open file descriptors to find documents.
            let doc_path = doc_path.or_else(|| {
                log::debug!("[AX_PROBE] last resort FD scan for pid {}", pid);
                let open_docs =
                    super::process_files::open_documents_for_pid(pid as u32);
                let found = open_docs
                    .into_iter()
                    .find(|f| f.writable)
                    .map(|f| f.path.to_string_lossy().into_owned());
                log::debug!("[AX_PROBE] FD writable result: {:?}", found);
                found
            });

            let doc_path = doc_path.or_else(|| {
                if !bundle_id_str.is_empty() {
                    let suffix = if title_str.is_empty() {
                        "untitled".to_string()
                    } else {
                        title_str.clone()
                    };
                    log::debug!("[AX_PROBE] final title:// fallback: {}/{}", bundle_id_str, suffix);
                    Some(format!("title://{}/{}", bundle_id_str, suffix))
                } else {
                    None
                }
            });

            log::debug!("[AX_PROBE] final doc_path={:?}", doc_path);

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

    /// Query AXDocument on the focused window and element, then AXURL on the
    /// focused element. Some apps (multi-window editors, Electron) expose
    /// AXDocument on the element but not the window.
    fn get_document_path_via_ax(&self, pid: i32) -> Option<String> {
        // Try AXDocument on the focused window first (native Cocoa apps).
        for attr_source in &[
            (true, "AXDocument"),   // focused window
            (false, "AXDocument"),  // focused element
        ] {
            let raw = if attr_source.0 {
                self.query_focused_window_attribute(pid, attr_source.1)
            } else {
                self.query_focused_element_attribute(pid, attr_source.1)
            };
            log::debug!(
                "[AX_DOC] source={} attr={} raw={:?}",
                if attr_source.0 { "window" } else { "element" },
                attr_source.1,
                raw
            );
            if let Some(raw) = raw {
                if let Some(path) = raw.strip_prefix("file://") {
                    if let Ok(decoded) = urlencoding::decode(path) {
                        let owned = decoded.into_owned();
                        if !owned.is_empty() {
                            return Some(owned);
                        }
                    }
                }
            }
        }
        // AXURL on the focused element — handles WKWebView/web content.
        // Only accept file:// URLs; https:// is handled by the browser extension.
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

/// Resolve a PID to its bundle identifier via NSRunningApplication.
/// Used by ES file-open events to verify the opener matches the focused app.
pub fn bundle_id_for_pid(pid: i32) -> Option<String> {
    unsafe {
        let pool: *mut Object = msg_send![class!(NSAutoreleasePool), new];
        let cls = class!(NSRunningApplication);
        let app: *mut Object = msg_send![cls, runningApplicationWithProcessIdentifier: pid];
        let result = if !app.is_null() {
            let bid: *mut Object = msg_send![app, bundleIdentifier];
            if !bid.is_null() {
                Some(nsstring_to_string(bid))
            } else {
                None
            }
        } else {
            None
        };
        let _: () = msg_send![pool, drain];
        result
    }
}

// ---------------------------------------------------------------------------
// AXObserver-based push notification focus provider.
// ---------------------------------------------------------------------------

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXObserverCreate(
        application: i32,
        callback: AXObserverCallback,
        observer: *mut *mut std::ffi::c_void,
    ) -> i32;
    fn AXObserverAddNotification(
        observer: *mut std::ffi::c_void,
        element: *mut std::ffi::c_void,
        notification: core_foundation::string::CFStringRef,
        refcon: *mut std::ffi::c_void,
    ) -> i32;
    fn AXObserverRemoveNotification(
        observer: *mut std::ffi::c_void,
        element: *mut std::ffi::c_void,
        notification: core_foundation::string::CFStringRef,
    ) -> i32;
    fn AXObserverGetRunLoopSource(
        observer: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
}

type AXObserverCallback = extern "C" fn(
    *mut std::ffi::c_void,  // observer
    *mut std::ffi::c_void,  // element
    core_foundation::string::CFStringRef, // notification
    *mut std::ffi::c_void,  // refcon
);

/// Shared state passed through the AXObserver callback refcon pointer.
struct AXObserverRefcon {
    provider: Arc<MacOSFocusMonitor>,
    tx: std::sync::mpsc::Sender<FocusEvent>,
}

extern "C" fn ax_observer_callback(
    _observer: *mut std::ffi::c_void,
    _element: *mut std::ffi::c_void,
    _notification: core_foundation::string::CFStringRef,
    refcon: *mut std::ffi::c_void,
) {
    if refcon.is_null() {
        return;
    }
    // SAFETY: refcon is a raw pointer to a leaked Box<AXObserverRefcon> that
    // outlives the observer. We borrow it immutably here; the Box is only
    // reclaimed when the observer thread is torn down.
    let ctx = unsafe { &*(refcon as *const AXObserverRefcon) };
    if let Some(info) = ctx.provider.get_active_window() {
        let event = FocusEvent {
            event_type: FocusEventType::FocusGained,
            path: info.path.clone().unwrap_or_default(),
            shadow_id: String::new(),
            app_bundle_id: info.application.clone(),
            app_name: info.application.clone(),
            window_title: info.title.clone(),
            timestamp: SystemTime::now(),
            window_id: info.window_number,
        };
        let _ = ctx.tx.send(event);
    }
}

/// AXObserver-based focus provider that receives push notifications from
/// the Accessibility subsystem instead of polling.
#[derive(Debug)]
pub struct AXObserverFocusProvider {
    provider: Arc<MacOSFocusMonitor>,
    running: Arc<AtomicBool>,
    tx: std::sync::mpsc::Sender<FocusEvent>,
    rx: Mutex<Option<std::sync::mpsc::Receiver<FocusEvent>>>,
    thread_handle: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl AXObserverFocusProvider {
    /// Try to create an AXObserver provider. Returns `None` if accessibility
    /// is not available or the frontmost app cannot be observed.
    pub fn try_new(provider: Arc<MacOSFocusMonitor>) -> Option<Self> {
        if !check_accessibility_permissions() {
            log::info!("AXObserver: accessibility not granted, skipping");
            return None;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        Some(Self {
            provider,
            running: Arc::new(AtomicBool::new(false)),
            tx,
            rx: Mutex::new(Some(rx)),
            thread_handle: Mutex::new(None),
        })
    }

    /// Take the receiver end of the focus event channel. Can only be called once.
    pub fn take_receiver(&self) -> Option<std::sync::mpsc::Receiver<FocusEvent>> {
        self.rx.lock().ok()?.take()
    }

    /// Start the AXObserver run loop thread. Subscribes to workspace
    /// activation notifications and creates/tears down per-app AXObservers.
    pub fn start(&self) -> bool {
        if self.running.swap(true, Ordering::AcqRel) {
            return true; // already running
        }

        let running = Arc::clone(&self.running);
        let provider = Arc::clone(&self.provider);
        let tx = self.tx.clone();

        let handle = std::thread::Builder::new()
            .name("ax-observer".into())
            .spawn(move || {
                ax_observer_run_loop(running, provider, tx);
            });

        match handle {
            Ok(h) => {
                if let Ok(mut guard) = self.thread_handle.lock() {
                    *guard = Some(h);
                }
                true
            }
            Err(e) => {
                log::warn!("AXObserver: failed to spawn thread: {e}");
                self.running.store(false, Ordering::Release);
                false
            }
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);
        // The run loop thread will exit when it sees running=false.
        // We wake the CFRunLoop so it does not block indefinitely.
        // The thread checks `running` after each CFRunLoopRunInMode interval.
    }
}

impl Drop for AXObserverFocusProvider {
    fn drop(&mut self) {
        self.stop();
        if let Ok(mut guard) = self.thread_handle.lock() {
            if let Some(h) = guard.take() {
                let _ = h.join();
            }
        }
    }
}

/// Main run loop for the AXObserver thread. Monitors NSWorkspace for app
/// activation changes and maintains an AXObserver for the frontmost app.
fn ax_observer_run_loop(
    running: Arc<AtomicBool>,
    provider: Arc<MacOSFocusMonitor>,
    tx: std::sync::mpsc::Sender<FocusEvent>,
) {
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;

    let kax_focused_window = CFString::from_static_string("AXFocusedWindowChanged");
    let kax_title_changed = CFString::from_static_string("AXTitleChanged");

    let mut current_pid: i32 = -1;
    let mut current_observer: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut current_app_element: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut current_refcon: *mut AXObserverRefcon = std::ptr::null_mut();

    // Tear down the current observer (if any).
    let teardown = |observer: &mut *mut std::ffi::c_void,
                        app_el: &mut *mut std::ffi::c_void,
                        refcon: &mut *mut AXObserverRefcon| {
        if !observer.is_null() && !app_el.is_null() {
            unsafe {
                // Best-effort removal; errors are non-fatal.
                let _ = AXObserverRemoveNotification(
                    *observer,
                    *app_el,
                    kax_focused_window.as_concrete_TypeRef(),
                );
                let _ = AXObserverRemoveNotification(
                    *observer,
                    *app_el,
                    kax_title_changed.as_concrete_TypeRef(),
                );
            }
        }
        if !observer.is_null() {
            unsafe { CFRelease(*observer); }
        }
        if !app_el.is_null() {
            unsafe { CFRelease(*app_el); }
        }
        if !refcon.is_null() {
            // SAFETY: We leaked this Box in setup; reclaim it now.
            let _ = unsafe { Box::from_raw(*refcon) };
        }
        *observer = std::ptr::null_mut();
        *app_el = std::ptr::null_mut();
        *refcon = std::ptr::null_mut();
    };

    while running.load(Ordering::Acquire) {
        // Determine frontmost app PID via NSWorkspace.
        let pid = unsafe {
            let pool: *mut Object = msg_send![class!(NSAutoreleasePool), new];
            let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
            let app: *mut Object = msg_send![workspace, frontmostApplication];
            let p: i32 = if app.is_null() { -1 } else { msg_send![app, processIdentifier] };
            let _: () = msg_send![pool, drain];
            p
        };

        if pid > 0 && pid != current_pid {
            // Frontmost app changed; tear down old observer and create new one.
            teardown(&mut current_observer, &mut current_app_element, &mut current_refcon);
            current_pid = pid;

            let refcon_box = Box::new(AXObserverRefcon {
                provider: Arc::clone(&provider),
                tx: tx.clone(),
            });
            current_refcon = Box::into_raw(refcon_box);

            let mut observer: *mut std::ffi::c_void = std::ptr::null_mut();
            // SAFETY: AXObserverCreate writes to `observer` on success (return 0).
            let err = unsafe {
                AXObserverCreate(pid, ax_observer_callback, &mut observer)
            };
            if err != 0 || observer.is_null() {
                log::debug!("AXObserver: cannot observe pid {pid} (err={err})");
                // Reclaim the refcon we just leaked.
                let _ = unsafe { Box::from_raw(current_refcon) };
                current_refcon = std::ptr::null_mut();
                current_pid = -1;
                // Sleep briefly before retrying to avoid busy-looping.
                std::thread::sleep(std::time::Duration::from_millis(500));
                continue;
            }

            // SAFETY: AXUIElementCreateApplication returns a retained CF object.
            let app_element = unsafe { AXUIElementCreateApplication(pid) };
            if app_element.is_null() {
                log::debug!("AXObserver: cannot create element for pid {pid}");
                unsafe { CFRelease(observer); }
                let _ = unsafe { Box::from_raw(current_refcon) };
                current_refcon = std::ptr::null_mut();
                current_pid = -1;
                std::thread::sleep(std::time::Duration::from_millis(500));
                continue;
            }

            unsafe {
                AXObserverAddNotification(
                    observer,
                    app_element,
                    kax_focused_window.as_concrete_TypeRef(),
                    current_refcon as *mut std::ffi::c_void,
                );
                AXObserverAddNotification(
                    observer,
                    app_element,
                    kax_title_changed.as_concrete_TypeRef(),
                    current_refcon as *mut std::ffi::c_void,
                );

                let source = AXObserverGetRunLoopSource(observer);
                if !source.is_null() {
                    core_foundation_sys::runloop::CFRunLoopAddSource(
                        core_foundation_sys::runloop::CFRunLoopGetCurrent(),
                        source as core_foundation_sys::runloop::CFRunLoopSourceRef,
                        core_foundation_sys::runloop::kCFRunLoopDefaultMode,
                    );
                }
            }

            current_observer = observer;
            current_app_element = app_element;
            log::debug!("AXObserver: now observing pid {pid}");
        }

        // Run the CFRunLoop for a short interval, then check for app changes.
        // SAFETY: CFRunLoopRunInMode is safe to call on the current thread's run loop.
        unsafe {
            core_foundation_sys::runloop::CFRunLoopRunInMode(
                core_foundation_sys::runloop::kCFRunLoopDefaultMode,
                0.5, // 500ms
                0,   // returnAfterSourceHandled = false
            );
        }
    }

    // Clean up on exit.
    teardown(&mut current_observer, &mut current_app_element, &mut current_refcon);
    log::debug!("AXObserver: run loop exited");
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
