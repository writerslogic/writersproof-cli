// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Windows fingerprint capture — subscribes to `WindowsKeystrokeCapture` events
//! and converts them into `SimpleJitterSample` for the global fingerprint
//! accumulator.
//!
//! Only active when the sentinel is NOT feeding (`sentinel_is_feeding() == false`),
//! preventing IKI distribution corruption from duplicate timestamped samples.
//!
//! This module is compiled only on Windows (gated in `mod.rs`).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::platform::{KeyEventType, KeystrokeCapture, KeystrokeEvent};
use crate::RwLockRecover;

const QUALITY_GATE_MIN_KEYSTROKES: usize = 3;

const QUALITY_GATE_WINDOW_NS: i64 = 2_000_000_000;

pub(crate) struct WindowsFingerprintCapture {
    running: Arc<AtomicBool>,
    last_keydown_ts_ns: i64,
    last_keyup_ts_ns: i64,
    pending_downs: HashMap<u16, i64>,
    burst_buffer: VecDeque<i64>,
}

impl WindowsFingerprintCapture {
    fn new(running: Arc<AtomicBool>) -> Self {
        Self {
            running,
            last_keydown_ts_ns: 0,
            last_keyup_ts_ns: 0,
            pending_downs: HashMap::new(),
            burst_buffer: VecDeque::new(),
        }
    }

    fn quality_gate_passes(&mut self, ts_ns: i64) -> bool {
        self.burst_buffer.push_back(ts_ns);

        let cutoff = ts_ns.saturating_sub(QUALITY_GATE_WINDOW_NS);
        while self.burst_buffer.front().is_some_and(|&t| t < cutoff) {
            self.burst_buffer.pop_front();
        }

        self.burst_buffer.len() >= QUALITY_GATE_MIN_KEYSTROKES
    }

    fn process_event(&mut self, event: &KeystrokeEvent) {
        if event.event_type == KeyEventType::Up {
            self.pending_downs.remove(&event.keycode);
            self.last_keyup_ts_ns = event.timestamp_ns;
            return;
        }

        // keyDown dedup.
        if event.timestamp_ns == self.last_keydown_ts_ns {
            return;
        }

        // Evict stale pending-downs (keys held > 10 s are likely stuck).
        self.pending_downs.retain(|_, ts| {
            *ts > 0 && event.timestamp_ns.saturating_sub(*ts) < 10_000_000_000
        });
        if self.pending_downs.len() < 256 {
            self.pending_downs.insert(event.keycode, event.timestamp_ns);
        }

        let duration_since_last_ns: u64 = if self.last_keydown_ts_ns > 0 {
            crate::utils::ns_elapsed(event.timestamp_ns, self.last_keydown_ts_ns)
        } else {
            0
        };

        let flight_time_ns: Option<u64> = if self.last_keyup_ts_ns > 0 {
            Some(crate::utils::ns_elapsed(
                event.timestamp_ns,
                self.last_keyup_ts_ns,
            ))
        } else {
            None
        };

        self.last_keydown_ts_ns = event.timestamp_ns;

        if !self.quality_gate_passes(event.timestamp_ns) {
            return;
        }

        let sample = crate::jitter::SimpleJitterSample {
            timestamp_ns: event.timestamp_ns,
            duration_since_last_ns,
            zone: event.zone,
            dwell_time_ns: None,
            flight_time_ns,
        };

        super::global::get_global_accumulator()
            .write_recover()
            .add_sample(&sample);
    }

    /// Consume events from the receiver until stopped or the channel closes.
    fn run(mut self, rx: std::sync::mpsc::Receiver<KeystrokeEvent>) {
        log::debug!("WindowsFingerprintCapture: consumer loop started");

        while self.running.load(Ordering::SeqCst) {
            // Use recv_timeout so we can periodically check `running`.
            match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(event) => {
                    if super::global::sentinel_is_feeding() {
                        continue;
                    }
                    self.process_event(&event);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    log::info!(
                        "WindowsFingerprintCapture: channel disconnected; exiting"
                    );
                    break;
                }
            }
        }

        log::debug!("WindowsFingerprintCapture: consumer loop stopped");
    }
}

pub(crate) struct CaptureHandle {
    pub running: Arc<AtomicBool>,
    capture: std::sync::Mutex<Option<crate::platform::windows::WindowsKeystrokeCapture>>,
    consumer_thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

pub(crate) fn start_capture() -> crate::error::Result<CaptureHandle> {
    // Check if sentinel is already running its own capture. On Windows,
    // CAPTURE_ACTIVE is a singleton guard so we cannot install two
    // WH_KEYBOARD_LL hooks via WindowsKeystrokeCapture simultaneously.
    // Return a clear error so the FFI layer can report it gracefully.
    if super::global::sentinel_is_feeding() {
        return Err(crate::error::Error::platform(
            "Cannot start fingerprint capture while sentinel is active; \
             the sentinel already feeds the accumulator"
                .into(),
        ));
    }

    let mut capture = crate::platform::windows::WindowsKeystrokeCapture::new()
        .map_err(|e| crate::error::Error::platform(format!(
            "Failed to create WindowsKeystrokeCapture: {e}"
        )))?;

    let rx = capture.start()
        .map_err(|e| crate::error::Error::platform(format!(
            "Failed to start WindowsKeystrokeCapture: {e}"
        )))?;

    let running = Arc::new(AtomicBool::new(true));
    let fp_capture = WindowsFingerprintCapture::new(Arc::clone(&running));

    let consumer = std::thread::Builder::new()
        .name("fp-capture-win".into())
        .spawn(move || fp_capture.run(rx))
        .map_err(|e| crate::error::Error::platform(format!(
            "Failed to spawn fingerprint consumer thread: {e}"
        )))?;

    log::info!("WindowsFingerprintCapture: started");
    Ok(CaptureHandle {
        running,
        capture: std::sync::Mutex::new(Some(capture)),
        consumer_thread: std::sync::Mutex::new(Some(consumer)),
    })
}

pub(crate) fn stop_capture(handle: &CaptureHandle) {
    handle.running.store(false, Ordering::SeqCst);

    // Stop the keyboard hook first so the channel closes and the consumer exits.
    if let Ok(mut guard) = handle.capture.lock() {
        if let Some(ref mut cap) = *guard {
            if let Err(e) = cap.stop() {
                log::warn!("WindowsFingerprintCapture: failed to stop hook: {e}");
            }
        }
        *guard = None;
    }

    // Join the consumer thread.
    if let Ok(mut guard) = handle.consumer_thread.lock() {
        if let Some(thread) = guard.take() {
            let _ = thread.join();
        }
    }

    log::info!("WindowsFingerprintCapture: stop completed");
}
