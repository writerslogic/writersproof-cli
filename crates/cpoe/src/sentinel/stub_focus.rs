// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::error::{Result, SentinelError};
use super::focus::{PollingSentinelFocusTracker, SentinelFocusTracker, WindowProvider};
use super::types::*;
use crate::config::SentinelConfig;
use crate::crypto::ObfuscatedString;
use crate::MutexRecover;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::mpsc;

/// Degraded focus monitor for Linux/non-macOS/non-Windows platforms.
///
/// Without X11/Wayland, precise window tracking is unavailable. Falls back to
/// terminal/session heuristics via env vars and `/proc`.
pub struct StubSentinelFocusTracker {
    _config: Arc<SentinelConfig>,
    focus_rx: Arc<Mutex<Option<mpsc::Receiver<FocusEvent>>>>,
    change_rx: Arc<Mutex<Option<mpsc::Receiver<ChangeEvent>>>>,
    change_tx: mpsc::Sender<ChangeEvent>,
}

impl StubSentinelFocusTracker {
    pub fn new(config: Arc<SentinelConfig>) -> Self {
        let (_focus_tx, focus_rx) = mpsc::channel(1);
        let (change_tx, change_rx) = mpsc::channel(1);
        Self {
            _config: config,
            focus_rx: Arc::new(Mutex::new(Some(focus_rx))),
            change_rx: Arc::new(Mutex::new(Some(change_rx))),
            change_tx,
        }
    }

    /// Create a polling-based monitor using process/env heuristics.
    pub fn new_monitor(config: Arc<SentinelConfig>) -> Box<dyn SentinelFocusTracker> {
        let provider = Arc::new(LinuxWindowProvider);
        Box::new(PollingSentinelFocusTracker::new(provider, config))
    }
}

/// Window provider using Linux process heuristics via env vars and `/proc`.
struct LinuxWindowProvider;

impl LinuxWindowProvider {
    /// Detect terminal emulator or parent application name.
    fn detect_terminal_app() -> String {
        if let Ok(term_program) = std::env::var("TERM_PROGRAM") {
            return term_program;
        }
        if let Ok(term) = std::env::var("TERM") {
            return term;
        }
        if let Ok(ppid_status) = std::fs::read_to_string("/proc/self/status") {
            for line in ppid_status.lines() {
                if let Some(ppid) = line.strip_prefix("PPid:\t") {
                    let ppid = ppid.trim();
                    let comm_path = format!("/proc/{}/comm", ppid);
                    if let Ok(comm) = std::fs::read_to_string(comm_path) {
                        return comm.trim().to_string();
                    }
                }
            }
        }
        "unknown".to_string()
    }
}

impl WindowProvider for LinuxWindowProvider {
    fn get_active_window(&self) -> Option<WindowInfo> {
        let app_name = Self::detect_terminal_app();

        let cwd = std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        Some(WindowInfo {
            path: None,
            application: app_name.clone(),
            title: ObfuscatedString::new(&app_name),
            pid: Some(std::process::id()),
            timestamp: SystemTime::now(),
            is_document: false,
            is_unsaved: false,
            project_root: cwd,
            window_number: None,
        })
    }
}

impl SentinelFocusTracker for StubSentinelFocusTracker {
    fn start(&self) -> Result<()> {
        log::info!("Starting degraded focus monitor (no X11/Wayland integration)");
        log::info!("Witnessing will work but without precise window focus tracking");
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        Ok(())
    }

    fn active_window(&self) -> Option<WindowInfo> {
        LinuxWindowProvider.get_active_window()
    }

    fn available(&self) -> (bool, String) {
        (
            true,
            "Degraded focus monitoring (no X11/Wayland). Witnessing works without precise focus tracking.".to_string(),
        )
    }

    fn focus_events(&self) -> Result<mpsc::Receiver<FocusEvent>> {
        self.focus_rx
            .lock_recover()
            .take()
            .ok_or_else(|| SentinelError::Channel("Focus receiver already consumed".into()))
    }

    fn change_events(&self) -> Result<mpsc::Receiver<ChangeEvent>> {
        self.change_rx
            .lock_recover()
            .take()
            .ok_or_else(|| SentinelError::Channel("Change receiver already consumed".into()))
    }

    fn change_sender(&self) -> mpsc::Sender<ChangeEvent> {
        self.change_tx.clone()
    }
}
