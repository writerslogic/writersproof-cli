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

            let doc_path = super::types::infer_document_path_from_title(&title);

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
