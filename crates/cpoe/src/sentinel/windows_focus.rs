// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::focus::*;
use super::types::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationValuePattern, UIA_ValuePatternId,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::Foundation::HWND;

pub struct WindowsFocusMonitor {
    config: Arc<SentinelConfig>,
}

impl WindowsFocusMonitor {
    pub fn new(config: Arc<SentinelConfig>) -> Self {
        Self { config }
    }

    pub fn new_monitor(config: Arc<SentinelConfig>) -> Box<dyn SentinelFocusTracker> {
        let provider = Arc::new(Self::new(Arc::clone(&config)));
        Box::new(PollingSentinelFocusTracker::new(provider, config))
    }
}

impl WindowProvider for WindowsFocusMonitor {
    fn get_active_window(&self) -> Option<WindowInfo> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() {
                return None;
            }

            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));

            let path = get_process_path(pid)?;
            let app_name = Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            let mut title_buf = [0u16; 512];
            let len = GetWindowTextW(hwnd, &mut title_buf);
            let title = String::from_utf16_lossy(&title_buf[..len as usize]);

            // Try UI Automation first for reliable document path detection.
            let doc_path = uia_get_document_path(hwnd)
                .or_else(|| super::types::infer_document_path_from_title(&title));

            Some(WindowInfo {
                is_document: doc_path.is_some(),
                path: doc_path,
                application: app_name,
                title: ObfuscatedString::new(&title),
                pid: Some(pid),
                timestamp: SystemTime::now(),
                is_unsaved: false,
                project_root: None,
                window_number: None,
            })
        }
    }
}

/// Query the focused element's Value pattern for a document file path via UI Automation.
///
/// Many editors (Word, Notepad++, Visual Studio) expose the current file path
/// through `IUIAutomationValuePattern`. This is more reliable than parsing
/// window titles, which vary by app and locale.
/// Ensure COM is initialized once per thread (no matching CoUninitialize needed
/// because the polling thread runs for the sentinel's lifetime).
fn ensure_com_initialized() {
    use std::cell::Cell;
    thread_local! { static COM_INIT: Cell<bool> = const { Cell::new(false) }; }
    COM_INIT.with(|init| {
        if !init.get() {
            unsafe { let _ = CoInitializeEx(None, COINIT_MULTITHREADED); }
            init.set(true);
        }
    });
}

fn uia_get_document_path(hwnd: HWND) -> Option<String> {
    unsafe {
        ensure_com_initialized();

        let automation: IUIAutomation =
            CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER).ok()?;
        let element = automation.ElementFromHandle(hwnd).ok()?;
        let pattern = element
            .GetCurrentPattern(UIA_ValuePatternId)
            .ok()?;
        let value_pattern: IUIAutomationValuePattern = pattern.cast().ok()?;
        let value = value_pattern.CurrentValue().ok()?;
        let text = value.to_string();
        if text.is_empty() {
            return None;
        }
        // Only accept values that look like file paths.
        if text.contains('\\') || text.contains('/') || text.contains(':') {
            let path = Path::new(&text);
            if path.is_absolute() {
                return Some(text);
            }
        }
        None
    }
}

fn get_process_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut path = [0u16; 1024];
        let mut size = path.len() as u32;
        let result = QueryFullProcessImageNameW(
            handle,
            Default::default(),
            PWSTR(path.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(handle);
        result.ok()?;
        Some(String::from_utf16_lossy(&path[..size as usize]))
    }
}
