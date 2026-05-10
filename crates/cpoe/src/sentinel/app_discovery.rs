// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Auto-discovery of writing application metadata.
//!
//! Probes an installed application by bundle ID and returns inferred storage
//! pattern, container paths, and a confidence level. Used by the user app
//! registry to pre-fill metadata when the user adds a custom app.

use super::app_registry::{ProbeConfidence, StoragePattern};
#[cfg(target_os = "macos")]
use core_foundation::base::TCFType;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Result of probing an application by bundle ID.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub display_name: String,
    pub storage: StoragePattern,
    pub container_paths: Vec<String>,
    pub needs_title_inference: bool,
    pub confidence: ProbeConfidence,
}

/// Probe an installed application by bundle ID.
///
/// Evaluates filesystem heuristics (and on macOS, AX accessibility) to infer
/// how the app stores documents. Times out after 2 seconds; failures downgrade
/// confidence to [`ProbeConfidence::Low`] rather than returning an error.
pub fn probe_app(bundle_id: &str) -> ProbeResult {
    let default = ProbeResult {
        display_name: bundle_id.to_string(),
        storage: StoragePattern::FileBased,
        container_paths: Vec::new(),
        needs_title_inference: false,
        confidence: ProbeConfidence::Low,
    };

    if bundle_id.is_empty() {
        return default;
    }

    // Run platform-specific probing with a timeout.
    let (tx, rx) = std::sync::mpsc::channel();
    let bid = bundle_id.to_string();
    if let Err(e) = std::thread::Builder::new()
        .name("app-probe".into())
        .spawn(move || {
            let result = platform_probe(&bid);
            let _ = tx.send(result);
        })
    {
        log::warn!("Failed to spawn app probe thread: {e}");
        return default;
    }

    match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => result,
        Err(_) => {
            log::warn!("app probe timed out for {bundle_id}");
            default
        }
    }
}

// ---------------------------------------------------------------------------
// macOS probing
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn platform_probe(bundle_id: &str) -> ProbeResult {
    let mut result = ProbeResult {
        display_name: bundle_id.to_string(),
        storage: StoragePattern::FileBased,
        container_paths: Vec::new(),
        needs_title_inference: false,
        confidence: ProbeConfidence::Low,
    };

    // Step 1: Find app bundle path and read display name.
    let bundle_path = find_app_bundle(bundle_id);
    if let Some(ref path) = bundle_path {
        if let Some(name) = read_bundle_display_name(path) {
            result.display_name = name;
        }
        if is_electron_app(path) || is_ios_app_on_mac(path) {
            result.needs_title_inference = true;
        }
    }

    // Step 2: Check for group containers.
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return result,
    };

    let group_ids = bundle_path
        .as_deref()
        .map(read_app_group_ids)
        .unwrap_or_default();

    for gid in &group_ids {
        let container = home.join("Library/Group Containers").join(gid);
        if container.is_dir() {
            let rel = format!("Library/Group Containers/{gid}");
            result.container_paths.push(rel);
            result.storage = StoragePattern::ContainerBased;
            result.confidence = ProbeConfidence::Medium;
        }
    }

    // Step 3: Check for iCloud Mobile Documents.
    let munged = bundle_id.replace(['.', '-'], "~");
    let mobile_docs = home.join("Library/Mobile Documents").join(&munged);
    if mobile_docs.is_dir() {
        let rel = format!("Library/Mobile Documents/{munged}");
        result.container_paths.push(rel);
        if result.storage == StoragePattern::FileBased {
            result.storage = StoragePattern::CloudLibrary;
            result.confidence = ProbeConfidence::Medium;
        }
    }

    // Step 4: Check for SQLite in any discovered containers.
    if !result.container_paths.is_empty() && has_sqlite_files(&home, &result.container_paths) {
        result.storage = StoragePattern::DatabaseBacked;
    }

    // Step 5: If app is running, try AX probe for High confidence.
    if let Some(ax) = try_ax_probe(bundle_id) {
        if !ax.needs_title_inference {
            result.needs_title_inference = false;
        }
        result.confidence = ProbeConfidence::High;
    }

    // Step 6: Check Info.plist for writing-relevant document type UTIs.
    // Upgrades confidence from Low to Medium when writing UTIs are found.
    if let Some(ref bp) = bundle_path {
        if has_writing_uti_in_plist(bp) && result.confidence != ProbeConfidence::High {
            result.confidence = ProbeConfidence::Medium;
        }
    }

    result
}

/// Find an app's bundle path by checking standard locations.
#[cfg(target_os = "macos")]
fn find_app_bundle(bundle_id: &str) -> Option<PathBuf> {
    // Use NSWorkspace to resolve bundle ID → URL (most reliable).
    let path = nsworkspace_url_for_bundle_id(bundle_id);
    if path.is_some() {
        return path;
    }
    // Fallback: scan standard app directories.
    let candidates = [
        PathBuf::from("/Applications"),
        PathBuf::from("/System/Applications"),
        dirs::home_dir()
            .unwrap_or_default()
            .join("Applications"),
    ];
    for dir in &candidates {
        if let Some(found) = scan_dir_for_bundle_id(dir, bundle_id) {
            return Some(found);
        }
    }
    None
}

/// Use NSWorkspace to resolve a bundle ID to a file path.
#[cfg(target_os = "macos")]
fn nsworkspace_url_for_bundle_id(bundle_id: &str) -> Option<PathBuf> {
    use objc::runtime::{Class, Object};
    unsafe {
        // Class::get returns None in test binaries where AppKit isn't linked.
        let pool_cls = Class::get("NSAutoreleasePool")?;
        let ws_cls = Class::get("NSWorkspace")?;
        let pool: *mut Object = msg_send![pool_cls, new];
        let workspace: *mut Object = msg_send![ws_cls, sharedWorkspace];
        let ns_bid = nsstring_from_str(bundle_id);
        let url: *mut Object = msg_send![workspace, URLForApplicationWithBundleIdentifier: ns_bid];
        let result = if !url.is_null() {
            let path_obj: *mut Object = msg_send![url, path];
            if !path_obj.is_null() {
                Some(PathBuf::from(nsstring_to_rust(path_obj)))
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

/// Scan a directory for .app bundles matching a bundle ID.
#[cfg(target_os = "macos")]
fn scan_dir_for_bundle_id(dir: &Path, bundle_id: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("app") {
            continue;
        }
        let plist = bundle_plist_path(&path);
        if let Some(bid) = read_plist_string(&plist, "CFBundleIdentifier") {
            if bid.eq_ignore_ascii_case(bundle_id) {
                return Some(path);
            }
        }
    }
    None
}

/// Return the Info.plist path for a bundle, handling both macOS-style
/// (`Contents/Info.plist`) and iOS-on-Mac-style (`WrappedBundle/Info.plist`).
#[cfg(target_os = "macos")]
fn bundle_plist_path(bundle_path: &Path) -> PathBuf {
    let contents_plist = bundle_path.join("Contents/Info.plist");
    if contents_plist.is_file() {
        return contents_plist;
    }
    let wrapped_plist = bundle_path.join("WrappedBundle/Info.plist");
    if wrapped_plist.is_file() {
        return wrapped_plist;
    }
    contents_plist
}

/// Return true if this is an iPhone/iPad app running natively on an Apple
/// Silicon Mac (not a Catalyst app, which has a normal Contents/ structure).
#[cfg(target_os = "macos")]
fn is_ios_app_on_mac(bundle_path: &Path) -> bool {
    bundle_path.join("WrappedBundle/Info.plist").is_file()
        && !bundle_path.join("Contents/Info.plist").is_file()
}

/// Read the display name from an app bundle's Info.plist.
#[cfg(target_os = "macos")]
fn read_bundle_display_name(bundle_path: &Path) -> Option<String> {
    let plist = bundle_plist_path(bundle_path);
    read_plist_string(&plist, "CFBundleDisplayName")
        .or_else(|| read_plist_string(&plist, "CFBundleName"))
}

/// Check whether the bundle contains the Electron framework.
#[cfg(target_os = "macos")]
fn is_electron_app(bundle_path: &Path) -> bool {
    bundle_path
        .join("Contents/Frameworks/Electron Framework.framework")
        .is_dir()
}

/// Return true if the app bundle's Info.plist declares writing-relevant document UTIs.
///
/// Used as a lightweight signal to upgrade probe confidence from Low to Medium
/// when no other heuristics matched (app not running, no container/iCloud directories).
#[cfg(target_os = "macos")]
fn has_writing_uti_in_plist(bundle_path: &Path) -> bool {
    let plist_path = bundle_plist_path(bundle_path);
    let contents = match std::fs::read_to_string(&plist_path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    const WRITING_INDICATORS: &[&str] = &[
        "public.rtf",
        "net.daringfireball.markdown",
        "public.plain-text",
        "public.utf8-plain-text",
        "org.openxmlformats.wordprocessingml.document",
        "NSStringPboardType",
    ];
    if WRITING_INDICATORS.iter().any(|indicator| contents.contains(indicator)) {
        return true;
    }
    // S13: An app that registers NSServices with NSSendTypes accepts text from other
    // apps — a reliable indicator of a writing or editing app.
    contents.contains("NSServices") && contents.contains("NSSendTypes")
}

/// Scan ~/Library/Group Containers/ for directories associated with this app.
///
/// Uses the bundle ID from Info.plist (via `bundle_path`) to match group
/// container names by whole dot-component matching, avoiding false positives
/// from substring overlap (e.g., "word" inside "1password").
#[cfg(target_os = "macos")]
fn read_app_group_ids(bundle_path: &Path) -> Vec<String> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    let gc_dir = home.join("Library/Group Containers");
    let entries = match std::fs::read_dir(&gc_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    // Read the actual bundle ID from Info.plist for matching accuracy.
    let plist = bundle_plist_path(bundle_path);
    let bid = read_plist_string(&plist, "CFBundleIdentifier")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if bid.is_empty() {
        return Vec::new();
    }
    // Split into dot-components for whole-component matching.
    let bid_components: Vec<&str> = bid.split('.').collect();

    let mut groups = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let name_lower = name_str.to_ascii_lowercase();
        // Split the container name on '.' and check for whole-component overlap.
        // e.g., "UBF8T346G9.com.microsoft.Office" matches "com.microsoft.Word"
        // because "com" and "microsoft" are shared components.
        // Require at least 2 matching components (>= 3 chars each) to avoid
        // false positives on generic components like "com".
        let container_parts: Vec<&str> = name_lower.split('.').collect();
        let matching_components = bid_components
            .iter()
            .filter(|part| part.len() >= 3 && container_parts.contains(part))
            .count();
        if matching_components >= 2 && entry.path().is_dir() {
            groups.push(name_str.into_owned());
        }
    }
    groups
}

/// Check if any container directory contains SQLite database files.
fn has_sqlite_files(home: &Path, container_paths: &[String]) -> bool {
    for rel in container_paths {
        let abs = home.join(rel);
        if let Ok(walker) = walk_dir_shallow(&abs, 3) {
            for path in walker {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if matches!(ext, "sqlite" | "sqlite3" | "db" | "sqlite-wal") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Walk a directory up to `max_depth` levels, yielding file paths.
fn walk_dir_shallow(dir: &Path, max_depth: usize) -> std::io::Result<Vec<PathBuf>> {
    let mut results = Vec::new();
    walk_dir_inner(dir, max_depth, &mut results)?;
    Ok(results)
}

fn walk_dir_inner(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if depth == 0 {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            out.push(path);
        } else if path.is_dir() {
            walk_dir_inner(&path, depth - 1, out)?;
        }
    }
    Ok(())
}

/// Try an AX probe on a running application.
#[cfg(target_os = "macos")]
fn try_ax_probe(bundle_id: &str) -> Option<AxProbeResult> {
    use objc::runtime::{Class, Object};
    unsafe {
        let pool_cls = Class::get("NSAutoreleasePool")?;
        let ra_cls = Class::get("NSRunningApplication")?;
        let pool: *mut Object = msg_send![pool_cls, new];

        // Get running applications with this bundle ID.
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

        // App is running — try AX query on its PID.
        let app: *mut Object = msg_send![running, firstObject];
        let pid: i32 = msg_send![app, processIdentifier];

        let ax_app = AXUIElementCreateApplication(pid);
        if ax_app.is_null() {
            let _: () = msg_send![pool, drain];
            return Some(AxProbeResult {
                needs_title_inference: true,
            });
        }

        // Try to get the focused window's AXDocument attribute.
        let key_focused = core_foundation::string::CFString::from_static_string("AXFocusedWindow");
        let mut window_ref: core_foundation_sys::base::CFTypeRef = std::ptr::null();
        let err = AXUIElementCopyAttributeValue(
            ax_app,
            key_focused.as_concrete_TypeRef(),
            &mut window_ref,
        );
        if err != 0 || window_ref.is_null() {
            core_foundation_sys::base::CFRelease(ax_app as _);
            let _: () = msg_send![pool, drain];
            return Some(AxProbeResult {
                needs_title_inference: true,
            });
        }

        let key_doc = core_foundation::string::CFString::from_static_string("AXDocument");
        let mut doc_ref: core_foundation_sys::base::CFTypeRef = std::ptr::null();
        let err = AXUIElementCopyAttributeValue(
            window_ref as *mut _,
            key_doc.as_concrete_TypeRef(),
            &mut doc_ref,
        );

        let has_doc = err == 0 && !doc_ref.is_null();
        if !doc_ref.is_null() {
            core_foundation_sys::base::CFRelease(doc_ref);
        }
        core_foundation_sys::base::CFRelease(window_ref);
        core_foundation_sys::base::CFRelease(ax_app as _);
        let _: () = msg_send![pool, drain];

        Some(AxProbeResult {
            needs_title_inference: !has_doc,
        })
    }
}

#[cfg(target_os = "macos")]
struct AxProbeResult {
    needs_title_inference: bool,
}

// AX FFI declarations (ApplicationServices framework, already linked).
#[cfg(target_os = "macos")]
extern "C" {
    fn AXUIElementCreateApplication(pid: i32) -> *mut std::ffi::c_void;
    fn AXUIElementCopyAttributeValue(
        element: *mut std::ffi::c_void,
        attribute: core_foundation_sys::string::CFStringRef,
        value: *mut core_foundation_sys::base::CFTypeRef,
    ) -> i32;
}

// ---------------------------------------------------------------------------
// macOS ObjC helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
unsafe fn nsstring_from_str(s: &str) -> *mut objc::runtime::Object {
    let ns_string_class = match objc::runtime::Class::get("NSString") {
        Some(cls) => cls,
        None => return std::ptr::null_mut(),
    };
    let utf8: *const u8 = s.as_ptr();
    let len: usize = s.len();
    msg_send![ns_string_class, stringWithBytes:utf8 length:len encoding:4u64] // NSUTF8StringEncoding = 4
}

#[cfg(target_os = "macos")]
unsafe fn nsstring_to_rust(ns: *mut objc::runtime::Object) -> String {
    if ns.is_null() {
        return String::new();
    }
    let bytes: *const u8 = msg_send![ns, UTF8String];
    if bytes.is_null() {
        return String::new();
    }
    let c_str = std::ffi::CStr::from_ptr(bytes as *const std::ffi::c_char);
    c_str.to_string_lossy().into_owned()
}

/// Read a string value from an Info.plist via `plutil -convert json`.
#[cfg(target_os = "macos")]
fn read_plist_string(plist_path: &Path, key: &str) -> Option<String> {
    if !plist_path.is_file() {
        return None;
    }
    let output = std::process::Command::new("plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(plist_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let val: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    val.get(key)?.as_str().map(String::from)
}

// ---------------------------------------------------------------------------
// Windows probing
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn platform_probe(bundle_id: &str) -> ProbeResult {
    // Windows: check for Electron marker in Program Files paths.
    let mut result = ProbeResult {
        display_name: bundle_id.to_string(),
        storage: StoragePattern::FileBased,
        container_paths: Vec::new(),
        needs_title_inference: false,
        confidence: ProbeConfidence::Low,
    };

    // Try to find the executable via registry or PATH.
    if let Some(exe_dir) = find_windows_app_dir(bundle_id) {
        if let Some(name) = exe_dir.file_stem().and_then(|s| s.to_str()) {
            result.display_name = name.to_string();
        }
        if exe_dir.join("resources/electron.asar").exists()
            || exe_dir.join("Electron Framework.framework").exists()
        {
            result.needs_title_inference = true;
            result.confidence = ProbeConfidence::Medium;
        }
    }

    result
}

#[cfg(target_os = "windows")]
fn find_windows_app_dir(_bundle_id: &str) -> Option<PathBuf> {
    // Placeholder: registry lookup or PATH scan.
    // Windows apps don't use bundle IDs; this would need a mapping.
    None
}

// ---------------------------------------------------------------------------
// Linux probing
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn platform_probe(bundle_id: &str) -> ProbeResult {
    let mut result = ProbeResult {
        display_name: bundle_id.to_string(),
        storage: StoragePattern::FileBased,
        container_paths: Vec::new(),
        needs_title_inference: false,
        confidence: ProbeConfidence::Low,
    };

    // Check .desktop files for display name and Electron marker.
    if let Some(desktop) = find_desktop_file(bundle_id) {
        if let Some(name) = read_desktop_name(&desktop) {
            result.display_name = name;
        }
        if let Ok(contents) = std::fs::read_to_string(&desktop) {
            if contents.contains("electron") || contents.contains("Electron") {
                result.needs_title_inference = true;
                result.confidence = ProbeConfidence::Medium;
            }
        }
    }

    result
}

#[cfg(target_os = "linux")]
fn find_desktop_file(bundle_id: &str) -> Option<PathBuf> {
    let dirs = [
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
        dirs::home_dir()
            .unwrap_or_default()
            .join(".local/share/applications"),
    ];
    let target = format!("{bundle_id}.desktop");
    for dir in &dirs {
        let path = dir.join(&target);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_desktop_name(path: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        if let Some(name) = line.strip_prefix("Name=") {
            return Some(name.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Fallback for other platforms
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn platform_probe(bundle_id: &str) -> ProbeResult {
    ProbeResult {
        display_name: bundle_id.to_string(),
        storage: StoragePattern::FileBased,
        container_paths: Vec::new(),
        needs_title_inference: false,
        confidence: ProbeConfidence::Low,
    }
}

// ---------------------------------------------------------------------------
// Runtime text-editing detection
// ---------------------------------------------------------------------------

/// Result of probing a running app for editable text elements.
#[derive(Debug, Clone)]
pub struct RuntimeTextProbe {
    /// Whether the app has at least one editable text area.
    pub has_editable_text: bool,
    /// Number of editable text elements found.
    pub text_area_count: usize,
}

/// Cache of negative probe results to avoid re-probing non-writing apps.
/// Maps bundle_id → expiry time.
static NEGATIVE_CACHE: std::sync::Mutex<Option<std::collections::HashMap<String, SystemTime>>> =
    std::sync::Mutex::new(None);

/// Duration to cache negative probe results (5 minutes).
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(300);

/// Probe a running application for editable text elements via accessibility APIs.
///
/// On macOS, walks the accessibility tree looking for AXTextArea / AXTextField roles.
/// Returns `None` if the app was recently probed and found to have no editable text
/// (negative cache hit), or if probing fails.
pub fn probe_runtime_text_editing(
    bundle_id: &str,
    pid: u32,
) -> Option<RuntimeTextProbe> {
    // Check negative cache.
    {
        let mut guard = match NEGATIVE_CACHE.lock() {
            Ok(g) => g,
            Err(p) => {
                log::warn!("probe_runtime: negative cache poisoned, recovering");
                p.into_inner()
            }
        };
        let cache = guard.get_or_insert_with(std::collections::HashMap::new);
        if let Some(&expiry) = cache.get(bundle_id) {
            if SystemTime::now() < expiry {
                return None;
            }
            cache.remove(bundle_id);
        }
    }

    let result = platform_probe_text_editing(pid);

    // Cache negative results.
    if !result.has_editable_text {
        if let Ok(mut guard) = NEGATIVE_CACHE.lock() {
            let cache = guard.get_or_insert_with(std::collections::HashMap::new);
            if let Some(expiry) = SystemTime::now().checked_add(NEGATIVE_CACHE_TTL) {
                cache.insert(bundle_id.to_string(), expiry);
            }
            // Bound cache size to prevent unbounded growth.
            if cache.len() > 500 {
                let now = SystemTime::now();
                cache.retain(|_, v| *v > now);
            }
        }
        return None;
    }

    Some(result)
}

#[cfg(target_os = "macos")]
fn platform_probe_text_editing(pid: u32) -> RuntimeTextProbe {
    use objc::runtime::Object;

    let mut count = 0usize;

    unsafe {
        let pool: *mut Object = msg_send![class!(NSAutoreleasePool), new];

        let app_element = AXUIElementCreateApplication(pid as i32);
        if app_element.is_null() {
            let _: () = msg_send![pool, drain];
            return RuntimeTextProbe {
                has_editable_text: false,
                text_area_count: 0,
            };
        }

        // Get the focused window.
        let mut focused_window: core_foundation_sys::base::CFTypeRef = std::ptr::null();
        let attr_name = core_foundation::string::CFString::new("AXFocusedWindow");
        let err = AXUIElementCopyAttributeValue(
            app_element,
            attr_name.as_concrete_TypeRef(),
            &mut focused_window,
        );

        let element_to_check = if err == 0 && !focused_window.is_null() {
            focused_window as *mut std::ffi::c_void
        } else {
            app_element
        };

        // Check the role of the focused UI element.
        let mut focused_element: core_foundation_sys::base::CFTypeRef = std::ptr::null();
        let focused_attr = core_foundation::string::CFString::new("AXFocusedUIElement");
        let err2 = AXUIElementCopyAttributeValue(
            element_to_check,
            focused_attr.as_concrete_TypeRef(),
            &mut focused_element,
        );

        if err2 == 0 && !focused_element.is_null() {
            if is_editable_text_role(focused_element as *mut std::ffi::c_void) {
                count += 1;
            }
            core_foundation_sys::base::CFRelease(focused_element);
        }

        if !focused_window.is_null()
            && !std::ptr::eq(focused_window, app_element as *const std::ffi::c_void)
        {
            core_foundation_sys::base::CFRelease(focused_window);
        }
        core_foundation_sys::base::CFRelease(app_element as _);
        let _: () = msg_send![pool, drain];
    }

    RuntimeTextProbe {
        has_editable_text: count > 0,
        text_area_count: count,
    }
}

#[cfg(target_os = "macos")]
unsafe fn is_editable_text_role(element: *mut std::ffi::c_void) -> bool {
    let mut role_value: core_foundation_sys::base::CFTypeRef = std::ptr::null();
    let role_attr = core_foundation::string::CFString::new("AXRole");
    let err = AXUIElementCopyAttributeValue(
        element,
        role_attr.as_concrete_TypeRef(),
        &mut role_value,
    );
    if err != 0 || role_value.is_null() {
        return false;
    }

    let type_id = core_foundation_sys::base::CFGetTypeID(role_value);
    let string_type_id = core_foundation_sys::string::CFStringGetTypeID();
    if type_id != string_type_id {
        core_foundation_sys::base::CFRelease(role_value);
        return false;
    }

    let cf_str = core_foundation::string::CFString::wrap_under_get_rule(
        role_value as core_foundation_sys::string::CFStringRef,
    );
    let role = cf_str.to_string();
    core_foundation_sys::base::CFRelease(role_value);

    matches!(
        role.as_str(),
        "AXTextArea" | "AXTextField" | "AXWebArea" | "AXStaticText"
    )
}

// AX FFI: reuses declarations from the existing extern block above (line ~454).

#[cfg(not(target_os = "macos"))]
fn platform_probe_text_editing(_pid: u32) -> RuntimeTextProbe {
    RuntimeTextProbe {
        has_editable_text: false,
        text_area_count: 0,
    }
}

// ---------------------------------------------------------------------------
// Recent document discovery
// ---------------------------------------------------------------------------

/// Scan common directories for recently modified files matching allowed extensions.
///
/// Returns up to 20 results sorted by modification time (most recent first).
/// Skips symlinks, hidden files, and files that cannot be read.
pub fn discover_recent_documents(
    dirs: &[&Path],
    max_age_hours: u64,
    allowed_extensions: &[String],
) -> Vec<PathBuf> {
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(max_age_hours.saturating_mul(3600)))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let max_results = 20;

    let mut candidates: Vec<(SystemTime, PathBuf)> = Vec::new();

    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Skip hidden files and symlinks.
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with('.'))
            {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !meta.is_file() {
                continue;
            }
            let mtime = match meta.modified() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if mtime < cutoff {
                continue;
            }
            // Filter by allowed extensions (empty list = allow all).
            if !allowed_extensions.is_empty() {
                let ext_match = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|ext| {
                        allowed_extensions
                            .iter()
                            .any(|a| a.eq_ignore_ascii_case(ext))
                    });
                if !ext_match {
                    continue;
                }
            }
            candidates.push((mtime, path));
        }
    }

    // Sort most recent first.
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    candidates.truncate(max_results);
    candidates.into_iter().map(|(_, p)| p).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_empty_bundle_id() {
        let r = probe_app("");
        assert_eq!(r.confidence, ProbeConfidence::Low);
        assert_eq!(r.storage, StoragePattern::FileBased);
    }

    #[test]
    fn test_probe_nonexistent_app() {
        let r = probe_app("com.nonexistent.app.that.surely.does.not.exist");
        assert_eq!(r.confidence, ProbeConfidence::Low);
    }

    #[test]
    fn test_probe_timeout_graceful() {
        // Probing should never panic or hang regardless of input.
        let r = probe_app("com.example.TimeoutTest");
        assert!(matches!(
            r.confidence,
            ProbeConfidence::Low | ProbeConfidence::Medium | ProbeConfidence::High
        ));
    }

    #[test]
    fn test_has_sqlite_files_empty() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!has_sqlite_files(tmp.path(), &[]));
    }

    #[test]
    fn test_has_sqlite_files_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let container = tmp.path().join("Library/Group Containers/test.group");
        std::fs::create_dir_all(&container).unwrap();
        std::fs::write(container.join("data.sqlite"), b"fake").unwrap();
        assert!(has_sqlite_files(
            tmp.path(),
            &["Library/Group Containers/test.group".to_string()]
        ));
    }

    #[test]
    fn test_walk_dir_shallow_depth_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let deep = tmp.path().join("a/b/c/d");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("file.db"), b"x").unwrap();

        // Depth 3 should not reach a/b/c/d/ (that's depth 4).
        let found = walk_dir_shallow(tmp.path(), 3).unwrap();
        assert!(found.iter().all(|p| !p.ends_with("file.db")));

        // Depth 5 should find it.
        let found = walk_dir_shallow(tmp.path(), 5).unwrap();
        assert!(found.iter().any(|p| p.ends_with("file.db")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_is_electron_app_false_for_nonexistent() {
        assert!(!is_electron_app(Path::new("/nonexistent.app")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_probe_returns_valid_result() {
        // Even without AppKit linked in test binaries, probe must not panic.
        let r = probe_app("com.apple.TextEdit");
        assert!(!r.display_name.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_scan_finds_app_in_system_applications() {
        use std::path::Path;
        // TextEdit lives in /System/Applications on modern macOS.
        let sys_apps = Path::new("/System/Applications");
        if sys_apps.is_dir() {
            let found = scan_dir_for_bundle_id(sys_apps, "com.apple.TextEdit");
            assert!(found.is_some(), "TextEdit should be in /System/Applications");
            assert!(found.unwrap().join("Contents/Info.plist").exists());
        }
    }

    #[test]
    fn test_discover_recent_documents_basic() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("essay.md"), b"hello").unwrap();
        std::fs::write(tmp.path().join("notes.txt"), b"world").unwrap();
        std::fs::write(tmp.path().join("image.png"), b"img").unwrap();

        let exts = vec!["md".to_string(), "txt".to_string()];
        let dirs = [tmp.path()];
        let dir_refs: Vec<&Path> = dirs.iter().map(|d| *d).collect();
        let results = discover_recent_documents(&dir_refs, 1, &exts);

        assert_eq!(results.len(), 2);
        // Both should be .md or .txt
        for r in &results {
            let ext = r.extension().unwrap().to_str().unwrap();
            assert!(ext == "md" || ext == "txt");
        }
    }

    #[test]
    fn test_discover_recent_documents_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = [tmp.path()];
        let dir_refs: Vec<&Path> = dirs.iter().map(|d| *d).collect();
        let results = discover_recent_documents(&dir_refs, 1, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_discover_recent_documents_max_20() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..30 {
            std::fs::write(tmp.path().join(format!("file{i}.txt")), b"x").unwrap();
        }
        let dirs = [tmp.path()];
        let dir_refs: Vec<&Path> = dirs.iter().map(|d| *d).collect();
        let results = discover_recent_documents(&dir_refs, 1, &[]);
        assert_eq!(results.len(), 20);
    }

    #[test]
    fn test_discover_recent_documents_skips_hidden() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".hidden.md"), b"secret").unwrap();
        std::fs::write(tmp.path().join("visible.md"), b"public").unwrap();

        let dirs = [tmp.path()];
        let dir_refs: Vec<&Path> = dirs.iter().map(|d| *d).collect();
        let results = discover_recent_documents(&dir_refs, 1, &[]);
        assert_eq!(results.len(), 1);
        assert!(results[0].file_name().unwrap().to_str().unwrap() == "visible.md");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_read_bundle_display_name() {
        let te = std::path::Path::new("/System/Applications/TextEdit.app");
        if te.is_dir() {
            let name = read_bundle_display_name(te);
            assert!(name.is_some());
            assert!(!name.unwrap().is_empty());
        }
    }
}
