// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::core::EVENT_CHANNEL_BUFFER;
use super::error::{Result, SentinelError};
use super::focus::SentinelFocusTracker;
use super::types::{ChangeEvent, FocusEvent};
use super::Sentinel;
#[allow(unused_imports)]
use crate::platform::{KeystrokeCapture, MouseCapture};
use crate::MutexRecover;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

impl Sentinel {
    /// Create the platform focus monitor, verify availability, start it,
    /// and return the monitor along with its event receivers.
    #[allow(clippy::type_complexity)]
    pub(super) fn setup_focus_tracker(
        &self,
    ) -> Result<(
        Box<dyn SentinelFocusTracker>,
        mpsc::Receiver<FocusEvent>,
        mpsc::Receiver<ChangeEvent>,
    )> {
        #[cfg(target_os = "macos")]
        let focus_monitor: Box<dyn SentinelFocusTracker> =
            super::macos_focus::MacOSFocusMonitor::new_monitor(self.config.clone());

        #[cfg(target_os = "windows")]
        let focus_monitor: Box<dyn SentinelFocusTracker> =
            super::windows_focus::WindowsFocusMonitor::new_monitor(self.config.clone());

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let focus_monitor: Box<dyn SentinelFocusTracker> = Box::new(
            super::stub_focus::StubSentinelFocusTracker::new(self.config.clone()),
        );

        let (available, reason) = focus_monitor.available();
        if !available {
            return Err(SentinelError::NotAvailable(reason));
        }

        focus_monitor.start()?;

        let focus_rx = focus_monitor.focus_events()?;
        let change_rx = focus_monitor.change_events()?;

        Ok((focus_monitor, focus_rx, change_rx))
    }

    /// Initialize keystroke capture, spawn a bridge thread forwarding
    /// events into the returned async receiver, and start HID capture
    /// for dual-layer validation.
    pub(super) fn setup_keystroke_bridge(
        &self,
        running: &Arc<AtomicBool>,
    ) -> mpsc::Receiver<crate::platform::KeystrokeEvent> {
        let (keystroke_tx, keystroke_rx) =
            tokio::sync::mpsc::channel::<crate::platform::KeystrokeEvent>(EVENT_CHANNEL_BUFFER);
        let keystroke_running = Arc::clone(running);

        let capture_result = self.platform.create_keystroke_capture();

        let keystroke_active = Arc::clone(&self.keystroke_capture_active);
        let keystroke_capture_store = Arc::clone(&self.keystroke_capture);
        match capture_result {
            Ok(mut keystroke_capture) => match keystroke_capture.start() {
                Ok(sync_rx) => {
                    keystroke_active.store(true, Ordering::SeqCst);
                    *keystroke_capture_store.lock_recover() = Some(keystroke_capture);
                    let sync_rx: std::sync::mpsc::Receiver<crate::platform::KeystrokeEvent> =
                        sync_rx;
                    let handle = std::thread::spawn(move || {
                        #[cfg(debug_assertions)]
                        let mut bridge_count: u64 = 0;
                        let mut dropped_count: u64 = 0;
                        while keystroke_running.load(Ordering::SeqCst) {
                            match sync_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                                Ok(event) => {
                                    #[cfg(debug_assertions)]
                                    {
                                        bridge_count += 1;
                                        if bridge_count % 100 == 0 {
                                            log::debug!(
                                                "keystroke bridge: forwarded {bridge_count}"
                                            );
                                        }
                                    }
                                    if let Err(e) = keystroke_tx.try_send(event) {
                                        match e {
                                            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                                                dropped_count += 1;
                                                if dropped_count == 1
                                                    || dropped_count.is_power_of_two()
                                                {
                                                    log::warn!(
                                                        "keystroke channel full, \
                                                         {} events dropped",
                                                        dropped_count
                                                    );
                                                }
                                            }
                                            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                                                log::debug!("keystroke channel closed");
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            }
                        }
                    });
                    self.bridge_threads.lock_recover().push(handle);
                }
                Err(e) => {
                    log::warn!("Keystroke capture failed to start: {e}; running in degraded mode");
                }
            },
            Err(e) => {
                log::warn!(
                    "Keystroke capture unavailable: {e}; \
                     running in degraded mode (focus-only)"
                );
            }
        }

        // Start IOKit HID capture for dual-layer keystroke validation.
        // This runs alongside CGEventTap; HID provides hardware ground truth.
        super::start_hid_capture();

        keystroke_rx
    }

    /// Initialize mouse capture and spawn a bridge thread forwarding
    /// events into the returned async receiver.
    pub(super) fn setup_mouse_bridge(
        &self,
        running: &Arc<AtomicBool>,
    ) -> mpsc::Receiver<crate::platform::MouseEvent> {
        let (mouse_tx, mouse_rx) =
            tokio::sync::mpsc::channel::<crate::platform::MouseEvent>(EVENT_CHANNEL_BUFFER);
        let mouse_running = Arc::clone(running);

        let capture_result = self.platform.create_mouse_capture();

        let mouse_capture_store = Arc::clone(&self.mouse_capture);
        match capture_result {
            Ok(mut mouse_capture) => match mouse_capture.start() {
                Ok(sync_rx) => {
                    *mouse_capture_store.lock_recover() = Some(mouse_capture);
                    let sync_rx: std::sync::mpsc::Receiver<crate::platform::MouseEvent> = sync_rx;
                    let handle = std::thread::spawn(move || {
                        while mouse_running.load(Ordering::SeqCst) {
                            match sync_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                                Ok(event) => {
                                    if let Err(e) = mouse_tx.try_send(event) {
                                        match e {
                                            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                                                log::debug!("mouse channel full, dropping event");
                                            }
                                            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                                                log::debug!("mouse channel closed");
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            }
                        }
                    });
                    self.bridge_threads.lock_recover().push(handle);
                }
                Err(e) => {
                    log::warn!("Mouse capture failed to start: {e}; running in degraded mode");
                }
            },
            Err(e) => {
                log::warn!(
                    "Mouse capture unavailable: {e}; \
                     running in degraded mode"
                );
            }
        }

        mouse_rx
    }
}
