// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FingerprintCapture — subscribes to SharedKeystrokeTap and converts
//! `KeystrokeEvent` into `SimpleJitterSample` for the global fingerprint
//! accumulator.
//!
//! Only active when the sentinel is NOT feeding (`sentinel_is_feeding() == false`),
//! preventing IKI distribution corruption from duplicate timestamped samples.
//!
//! This module is compiled only on macOS (gated in `mod.rs`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::platform::{KeyEventType, KeystrokeEvent};
use crate::RwLockRecover;


const QUALITY_GATE_MIN_KEYSTROKES: usize = 3;

const QUALITY_GATE_WINDOW_NS: i64 = 2_000_000_000;

const PID_CACHE_TTL_SECS: u64 = 60;


const EXCLUDED_BUNDLES: &[&str] = &[
    "com.apple.Terminal",
    "com.googlecode.iterm2",
    "dev.warp.Warp-Stable",
    "com.agilebits.onepassword7",
    "com.1password.1password",
    "com.apple.keychainaccess",
    "com.apple.systempreferences",
    "com.apple.Passwords",
];


#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn IsSecureEventInputEnabled() -> bool;
}


fn secure_event_input_is_active() -> bool {
    // Safety: pure CoreGraphics query, no side-effects, safe from any thread.
    unsafe { IsSecureEventInputEnabled() }
}


pub(crate) struct FingerprintCapture {
    running: Arc<AtomicBool>,
    cancel: Arc<tokio::sync::Notify>,
    last_keydown_ts_ns: i64,
    last_keyup_ts_ns: i64,
    pending_downs: HashMap<u16, i64>,
    excluded_bundles: HashSet<String>,
    pid_cache: HashMap<i32, (String, std::time::Instant)>,
    burst_buffer: VecDeque<i64>,
}

impl FingerprintCapture {
    fn new(running: Arc<AtomicBool>, cancel: Arc<tokio::sync::Notify>) -> Self {
        let excluded_bundles = EXCLUDED_BUNDLES
            .iter()
            .map(|s| s.to_string())
            .collect::<HashSet<_>>();

        Self {
            running,
            cancel,
            last_keydown_ts_ns: 0,
            last_keyup_ts_ns: 0,
            pending_downs: HashMap::new(),
            excluded_bundles,
            pid_cache: HashMap::new(),
            burst_buffer: VecDeque::new(),
        }
    }

    fn bundle_id_for_pid(&mut self, pid: i32) -> Option<&str> {
        let now = std::time::Instant::now();

        self.pid_cache.retain(|_, (_, cached_at)| {
            now.duration_since(*cached_at).as_secs() < PID_CACHE_TTL_SECS
        });

        self.pid_cache.entry(pid).or_insert_with(|| {
            let b = crate::sentinel::macos_focus::bundle_id_for_pid(pid)
                .unwrap_or_default();
            (b, now)
        });

        self.pid_cache.get(&pid).map(|(b, _)| b.as_str())
    }

    fn is_excluded(&mut self, event: &KeystrokeEvent) -> bool {
        if event.target_pid <= 0 {
            return false;
        }
        let bid = self.bundle_id_for_pid(event.target_pid).map(str::to_owned);
        match bid {
            Some(b) => self.excluded_bundles.contains(&b),
            None => false,
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

    async fn run(mut self, mut rx: tokio::sync::broadcast::Receiver<KeystrokeEvent>) {
        log::debug!("FingerprintCapture: consumer loop started");

        loop {
            tokio::select! {
                _ = self.cancel.notified() => {
                    log::debug!("FingerprintCapture: cancel signal received");
                    break;
                }
                result = rx.recv() => {
                    match result {
                        Ok(event) => {
                            if super::global::sentinel_is_feeding() {
                                continue;
                            }
                            if secure_event_input_is_active() {
                                continue;
                            }
                            if self.is_excluded(&event) {
                                continue;
                            }
                            self.process_event(&event);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            log::warn!("FingerprintCapture: broadcast lagged by {n} events; resuming");
                            self.last_keydown_ts_ns = 0;
                            self.last_keyup_ts_ns = 0;
                            self.pending_downs.clear();
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            log::info!("FingerprintCapture: broadcast channel closed; exiting");
                            break;
                        }
                    }
                }
            }
        }

        log::debug!("FingerprintCapture: consumer loop stopped");
    }
}


pub(crate) struct CaptureHandle {
    pub running: Arc<AtomicBool>,
    pub cancel: Arc<tokio::sync::Notify>,
}

pub(crate) fn start_capture(
    rt: &tokio::runtime::Runtime,
) -> crate::error::Result<CaptureHandle> {
    let tap = crate::platform::macos::shared_tap::get_or_start_shared_tap()?;
    let rx = tap.subscribe();

    let running = Arc::new(AtomicBool::new(true));
    let cancel = Arc::new(tokio::sync::Notify::new());
    let capture = FingerprintCapture::new(Arc::clone(&running), Arc::clone(&cancel));

    rt.spawn(capture.run(rx));

    log::info!("FingerprintCapture: started");
    Ok(CaptureHandle { running, cancel })
}

pub(crate) fn stop_capture(handle: &CaptureHandle) {
    handle.running.store(false, Ordering::SeqCst);
    handle.cancel.notify_one();
    log::info!("FingerprintCapture: stop requested");
}
