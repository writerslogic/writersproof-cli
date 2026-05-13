// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Keystroke monitoring with CGEventTap: KeystrokeMonitor and MacOSKeystrokeCapture.

use super::ffi::*;
use super::synthetic::verify_event_source;
use super::{EventVerificationResult, HidDeviceInfo, KeystrokeEvent, SyntheticStats};
use crate::platform::KeystrokeCapture;
use crate::MutexRecover;
use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use crate::jitter::SimpleJitterSession;

/// Bounded capacity for the keystroke channel (~5 s at 100 WPM with key-up events).
const KEYSTROKE_CHANNEL_CAPACITY: usize = 512;

/// Global counter for debug file writes (only write every 100th keystroke).
#[cfg(debug_assertions)]
static DEBUG_KEYSTROKE_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Global counter for tap-disabled-by-timeout events (for diagnostics).
static TAP_DISABLED_COUNT: AtomicU64 = AtomicU64::new(0);
/// Global counter for keystroke events dropped due to a full channel.
static DROPPED_KEYSTROKE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Write a debug line to `$CPOE_DATA_DIR/keystroke_debug.txt` (append mode).
/// Only active in debug builds to avoid I/O and string formatting in the hot path.
#[cfg(debug_assertions)]
fn debug_write_keystroke(tag: &str, count: u64) {
    let n = DEBUG_KEYSTROKE_COUNTER.fetch_add(1, Ordering::Relaxed);
    if n % 100 != 0 {
        return;
    }
    let dir = match std::env::var("CPOE_DATA_DIR") {
        Ok(d) => d,
        Err(_) => return,
    };
    // Reject traversal attempts and relative paths from the env var.
    let dir_path = std::path::Path::new(&dir);
    if dir.contains("..") || !dir_path.is_absolute() {
        return;
    }
    let path = dir_path.join("keystroke_debug.txt");
    if let Ok(mut f) = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
    } {
        use std::io::Write;
        let now = chrono::Utc::now();
        let _ = writeln!(f, "[{now}] {tag}: event #{n}, total_count={count}");
    }
}

#[cfg(not(debug_assertions))]
#[inline(always)]
fn debug_write_keystroke(_tag: &str, _count: u64) {}

#[derive(Debug)]
/// Thread-safe handle to a CFRunLoop that can be stopped from another thread.
/// SAFETY: CFRunLoopStop is documented as thread-safe in Apple's documentation.
pub struct RunLoopHandle(pub(super) *mut std::ffi::c_void);
unsafe impl Send for RunLoopHandle {}
unsafe impl Sync for RunLoopHandle {}

/// Holds CF objects created by CGEventTap. Resources are released automatically
/// via `CfGuard` when this struct is dropped after the run loop has exited.
struct EventTapResources {
    run_loop: *mut std::ffi::c_void,
    #[allow(dead_code)] // Held for RAII release via CfGuard::Drop
    tap: CfGuard,
    #[allow(dead_code)] // Held for RAII release via CfGuard::Drop
    source: CfGuard,
}
// SAFETY: EventTapResources is only accessed under a Mutex. The CF objects it
// holds are safe to release from any thread after the run loop has exited.
unsafe impl Send for EventTapResources {}
unsafe impl Sync for EventTapResources {}

// ---------------------------------------------------------------------------
// EventTapRunner: shared CGEventTap lifecycle (create, run loop, stop, release)
// ---------------------------------------------------------------------------

/// Manages the CGEventTap lifecycle. Both `KeystrokeMonitor` and
/// `MacOSKeystrokeCapture` compose this to avoid duplicating the ~80 lines
/// of tap creation, run-loop management, ready signaling, and cleanup.
struct EventTapRunner {
    thread: Option<std::thread::JoinHandle<()>>,
    run_loop: Arc<Mutex<Option<RunLoopHandle>>>,
    tap_resources: Arc<Mutex<Option<EventTapResources>>>,
}

impl EventTapRunner {
    /// Spawn a thread that creates a CGEventTap, installs it on a run loop,
    /// and calls `tap_cb` for each event. Returns after the tap is confirmed
    /// ready (or times out after 5 s).
    fn start(mut tap_cb: TapCallback) -> Result<Self> {
        let (ready_tx, ready_rx) = mpsc::channel();

        let run_loop: Arc<Mutex<Option<RunLoopHandle>>> = Arc::new(Mutex::new(None));
        let run_loop_clone = Arc::clone(&run_loop);
        let tap_resources: Arc<Mutex<Option<EventTapResources>>> = Arc::new(Mutex::new(None));
        let tap_resources_clone = Arc::clone(&tap_resources);

        let thread = std::thread::spawn(move || {
            // SAFETY: `tap_cb` lives on this thread's stack frame. The raw pointer
            // passed to CGEventTapCreate is only dereferenced by the run loop on
            // this same thread. CFRunLoopRun() blocks until CFRunLoopStop() is
            // called from stop(). After CFRunLoopRun returns, `tap_cb` is dropped
            // normally. stop() calls CFRelease(tap) only after joining this thread,
            // so macOS cannot invoke the callback after `tap_cb` is dropped.
            unsafe {
                let tap = match CfGuard::new(CGEventTapCreate(
                    K_CG_HID_EVENT_TAP,
                    K_CG_HEAD_INSERT_EVENT_TAP,
                    K_CG_EVENT_TAP_OPTION_LISTEN_ONLY,
                    cg_event_mask_bit(K_CG_EVENT_KEY_DOWN) | cg_event_mask_bit(K_CG_EVENT_KEY_UP),
                    event_tap_trampoline,
                    &mut tap_cb as *mut TapCallback as *mut std::ffi::c_void,
                )) {
                    Some(t) => t,
                    None => {
                        let _ = ready_tx.send(Err(anyhow!("Failed to create CGEventTap")));
                        return;
                    }
                };

                let source = match CfGuard::new(CFMachPortCreateRunLoopSource(
                    std::ptr::null_mut(),
                    tap.as_ptr(),
                    0,
                )) {
                    Some(s) => s,
                    None => {
                        let _ = ready_tx.send(Err(anyhow!("Failed to create runloop source")));
                        return;
                    }
                };

                let rl_ref = CFRunLoopGetCurrent();
                CFRetain(rl_ref);
                *run_loop_clone.lock_recover() = Some(RunLoopHandle(rl_ref));
                CFRunLoopAddSource(rl_ref, source.as_ptr(), kCFRunLoopCommonModes);
                CGEventTapEnable(tap.as_ptr(), true);
                *tap_resources_clone.lock_recover() = Some(EventTapResources {
                    run_loop: rl_ref,
                    tap,
                    source,
                });
                let _ = ready_tx.send(Ok(()));
                CFRunLoopRun();
            }
        });

        match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Self {
                thread: Some(thread),
                run_loop,
                tap_resources,
            }),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(anyhow!("CGEventTap initialization timed out after 5s")),
        }
    }

    /// Stop the run loop, join the thread, and release all CF resources.
    fn stop(&mut self) {
        let rl_ptr = self.run_loop.lock_recover().take().map(|h| h.0);
        if let Some(p) = rl_ptr {
            // SAFETY: CFRunLoopStop is documented as thread-safe; p was obtained
            // from CFRunLoopGetCurrent + CFRetain in the start() thread.
            unsafe {
                CFRunLoopStop(p);
            }
        }
        let mut thread_joined = false;
        if let Some(thread) = self.thread.take() {
            // Poll with timeout instead of blocking indefinitely on join.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                if thread.is_finished() {
                    let _ = thread.join();
                    thread_joined = true;
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    log::warn!("EventTapRunner thread did not finish within 3s; detaching");
                    // Intentionally leak tap_resources: the detached thread may
                    // still be inside CFRunLoopRun, so releasing CF objects now
                    // would be a use-after-free.
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        } else {
            // No thread was running; safe to release resources.
            thread_joined = true;
        }
        if thread_joined {
            if let Some(res) = self.tap_resources.lock_recover().take() {
                // run_loop was obtained via CFRunLoopGetCurrent + CFRetain;
                // tap and source are released automatically via CfGuard.
                unsafe { CFRelease(res.run_loop) };
            }
        }
    }
}

impl Drop for EventTapRunner {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Build the `TapCallback` that wraps verification, counting, timeout
/// re-enable, and dispatches to `on_keystroke` for hardware events.
fn build_monitor_tap_callback<F>(
    tap_ptr: Arc<AtomicPtr<std::ffi::c_void>>,
    tap_alive: Arc<AtomicBool>,
    ks_count: Arc<AtomicU64>,
    ver_count: Arc<AtomicU64>,
    rej_count: Arc<AtomicU64>,
    mut on_keystroke: F,
) -> TapCallback
where
    F: FnMut(*mut std::ffi::c_void, EventVerificationResult) + Send + 'static,
{
    Box::new(move |event: *mut std::ffi::c_void, event_type: u32| {
        if event_type == K_CG_EVENT_TAP_DISABLED_BY_TIMEOUT {
            let ptr = tap_ptr.load(Ordering::SeqCst);
            if !ptr.is_null() {
                // SAFETY: ptr is a valid CFMachPortRef obtained from CGEventTapCreate;
                // re-enabling a timed-out tap is the documented recovery pattern.
                unsafe { CGEventTapEnable(ptr, true) };
                let enabled = unsafe { CGEventTapIsEnabled(ptr) };
                if !enabled {
                    log::error!("CGEventTap re-enable failed after timeout; marking tap as dead");
                    tap_alive.store(false, Ordering::SeqCst);
                }
            } else {
                tap_alive.store(false, Ordering::SeqCst);
            }
            let n = TAP_DISABLED_COUNT.fetch_add(1, Ordering::Relaxed);
            log::warn!(
                "CGEventTap disabled by timeout, re-enabled (count={})",
                n + 1
            );
            return;
        }

        if event_type == K_CG_EVENT_KEY_DOWN || event_type == K_CG_EVENT_KEY_UP {
            // SAFETY: event is a valid CGEventRef provided by the run loop callback.
            let verification = unsafe { verify_event_source(event) };

            match verification {
                EventVerificationResult::Synthetic => {
                    rej_count.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                EventVerificationResult::Hardware => {
                    ver_count.fetch_add(1, Ordering::Relaxed);
                }
                EventVerificationResult::Suspicious => {}
            }

            if event_type == K_CG_EVENT_KEY_DOWN {
                let count = ks_count.fetch_add(1, Ordering::Relaxed) + 1;
                debug_write_keystroke("tap_cb", count);
            }
            on_keystroke(event, verification);
        }
    })
}

// ---------------------------------------------------------------------------
// KeystrokeInfo / KeystrokeCallback
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct KeystrokeInfo {
    pub timestamp_ns: i64,
    pub keycode: i64,
    pub zone: u8,
    pub verification: EventVerificationResult,
    pub device_hint: Option<HidDeviceInfo>,
}

pub type KeystrokeCallback = Arc<dyn Fn(KeystrokeInfo) + Send + Sync>;

// ---------------------------------------------------------------------------
// KeystrokeMonitor
// ---------------------------------------------------------------------------

pub struct KeystrokeMonitor {
    runner: EventTapRunner,
    tap_alive: Arc<AtomicBool>,
    keystroke_count: Arc<AtomicU64>,
    verified_count: Arc<AtomicU64>,
    rejected_count: Arc<AtomicU64>,
}

impl KeystrokeMonitor {
    pub fn start(session: Arc<Mutex<SimpleJitterSession>>) -> Result<Self> {
        Self::start_with_callback(session, None)
    }

    pub fn start_with_callback(
        session: Arc<Mutex<SimpleJitterSession>>,
        callback: Option<KeystrokeCallback>,
    ) -> Result<Self> {
        let session_clone = Arc::clone(&session);

        let keystroke_count = Arc::new(AtomicU64::new(0));
        let verified_count = Arc::new(AtomicU64::new(0));
        let rejected_count = Arc::new(AtomicU64::new(0));
        let tap_ptr = Arc::new(AtomicPtr::new(std::ptr::null_mut()));
        let tap_alive = Arc::new(AtomicBool::new(true));
        let clock = MachToWallClock::calibrate();

        let tap_cb = build_monitor_tap_callback(
            Arc::clone(&tap_ptr),
            Arc::clone(&tap_alive),
            Arc::clone(&keystroke_count),
            Arc::clone(&verified_count),
            Arc::clone(&rejected_count),
            move |event, verification| {
                let now = unsafe { clock.to_utc_ns(CGEventGetTimestamp(event)) };
                // SAFETY: event is a valid CGEventRef; K_CG_KEYBOARD_EVENT_KEYCODE
                // is a valid field constant for key events.
                let keycode =
                    unsafe { CGEventGetIntegerValueField(event, K_CG_KEYBOARD_EVENT_KEYCODE) };
                let keycode_u16 = u16::try_from(keycode).unwrap_or(0xFF);
                let zone_i = crate::jitter::keycode_to_zone(keycode_u16);
                let zone = if zone_i >= 0 { zone_i as u8 } else { 0xFF };

                session_clone.lock_recover().add_sample(now, zone);

                if let Some(ref cb) = callback {
                    cb(KeystrokeInfo {
                        timestamp_ns: now,
                        keycode,
                        zone,
                        verification,
                        device_hint: None,
                    });
                }
            },
        );

        let runner = EventTapRunner::start(tap_cb)?;
        // Store tap pointer so the callback can re-enable after timeout.
        // The tap handle is inside runner.tap_resources; extract it once.
        if let Some(ref res) = *runner.tap_resources.lock_recover() {
            tap_ptr.store(res.tap.as_ptr(), Ordering::SeqCst);
        }

        Ok(Self {
            runner,
            tap_alive,
            keystroke_count,
            verified_count,
            rejected_count,
        })
    }

    pub fn keystroke_count(&self) -> u64 {
        self.keystroke_count.load(Ordering::SeqCst)
    }

    pub fn verified_count(&self) -> u64 {
        self.verified_count.load(Ordering::SeqCst)
    }

    pub fn rejected_count(&self) -> u64 {
        self.rejected_count.load(Ordering::SeqCst)
    }

    pub fn synthetic_injection_detected(&self) -> bool {
        self.rejected_count.load(Ordering::SeqCst) > 0
    }

    pub fn is_tap_alive(&self) -> bool {
        self.tap_alive.load(Ordering::SeqCst)
    }

    #[cfg(feature = "cpoe_jitter")]
    pub fn start_with_hybrid(
        session: Arc<Mutex<crate::cpoe_jitter_bridge::HybridJitterSession>>,
    ) -> Result<Self> {
        Self::start_with_hybrid_callback(session, None)
    }

    #[cfg(feature = "cpoe_jitter")]
    pub fn start_with_hybrid_callback(
        session: Arc<Mutex<crate::cpoe_jitter_bridge::HybridJitterSession>>,
        callback: Option<KeystrokeCallback>,
    ) -> Result<Self> {
        let session_clone = Arc::clone(&session);

        let keystroke_count = Arc::new(AtomicU64::new(0));
        let verified_count = Arc::new(AtomicU64::new(0));
        let rejected_count = Arc::new(AtomicU64::new(0));
        let tap_ptr = Arc::new(AtomicPtr::new(std::ptr::null_mut()));
        let tap_alive = Arc::new(AtomicBool::new(true));
        let clock = MachToWallClock::calibrate();

        let tap_cb = build_monitor_tap_callback(
            Arc::clone(&tap_ptr),
            Arc::clone(&tap_alive),
            Arc::clone(&keystroke_count),
            Arc::clone(&verified_count),
            Arc::clone(&rejected_count),
            move |event, verification| {
                let keycode_raw =
                    unsafe { CGEventGetIntegerValueField(event, K_CG_KEYBOARD_EVENT_KEYCODE) };
                let keycode = u16::try_from(keycode_raw).unwrap_or(0xFF);
                let zone = crate::jitter::keycode_to_zone(keycode);

                let _ = session_clone.lock_recover().record_keystroke(keycode);

                if let Some(ref cb) = callback {
                    let now = unsafe { clock.to_utc_ns(CGEventGetTimestamp(event)) };
                    cb(KeystrokeInfo {
                        timestamp_ns: now,
                        keycode: keycode as i64,
                        zone: if zone >= 0 { zone as u8 } else { 0xFF },
                        verification,
                        device_hint: None,
                    });
                }
            },
        );

        let runner = EventTapRunner::start(tap_cb)?;
        if let Some(ref res) = *runner.tap_resources.lock_recover() {
            tap_ptr.store(res.tap.as_ptr(), Ordering::SeqCst);
        }

        Ok(Self {
            runner,
            tap_alive,
            keystroke_count,
            verified_count,
            rejected_count,
        })
    }

    pub fn stop(&mut self) {
        self.runner.stop();
    }

    pub fn run_loop_handle(&self) -> &Arc<Mutex<Option<RunLoopHandle>>> {
        &self.runner.run_loop
    }
}

impl Drop for KeystrokeMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// MacOSKeystrokeCapture (KeystrokeCapture trait impl)
// ---------------------------------------------------------------------------

pub struct MacOSKeystrokeCapture {
    running: Arc<AtomicBool>,
    tap_alive: Arc<AtomicBool>,
    sender: Option<mpsc::SyncSender<KeystrokeEvent>>,
    runner: Option<EventTapRunner>,
    strict_mode: bool,
    total_events: Arc<AtomicU64>,
    verified_hardware: Arc<AtomicU64>,
    rejected_synthetic: Arc<AtomicU64>,
}

impl MacOSKeystrokeCapture {
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            tap_alive: Arc::new(AtomicBool::new(false)),
            sender: None,
            runner: None,
            strict_mode: true,
            total_events: Arc::new(AtomicU64::new(0)),
            verified_hardware: Arc::new(AtomicU64::new(0)),
            rejected_synthetic: Arc::new(AtomicU64::new(0)),
        })
    }
}

impl KeystrokeCapture for MacOSKeystrokeCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<KeystrokeEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Keystroke capture already running"));
        }

        let (tx, rx): (
            mpsc::SyncSender<KeystrokeEvent>,
            mpsc::Receiver<KeystrokeEvent>,
        ) = mpsc::sync_channel(KEYSTROKE_CHANNEL_CAPACITY);
        self.sender = Some(tx.clone());

        let running = Arc::clone(&self.running);
        let tap_alive = Arc::clone(&self.tap_alive);
        let total_events = Arc::clone(&self.total_events);
        let verified_hardware = Arc::clone(&self.verified_hardware);
        let rejected_synthetic = Arc::clone(&self.rejected_synthetic);
        let strict = self.strict_mode;
        let tap_ptr = Arc::new(AtomicPtr::new(std::ptr::null_mut()));
        let tap_ptr_cb = Arc::clone(&tap_ptr);
        let clock = MachToWallClock::calibrate();

        running.store(true, Ordering::SeqCst);
        tap_alive.store(true, Ordering::SeqCst);

        let tap_cb: TapCallback = Box::new(move |event: *mut std::ffi::c_void, event_type: u32| {
            if !running.load(Ordering::SeqCst) {
                return;
            }

            if event_type == K_CG_EVENT_TAP_DISABLED_BY_TIMEOUT {
                let ptr: *mut std::ffi::c_void = tap_ptr_cb.load(Ordering::SeqCst);
                if !ptr.is_null() {
                    // SAFETY: ptr is a valid CFMachPortRef from CGEventTapCreate;
                    // re-enabling a timed-out tap is the documented recovery pattern.
                    unsafe { CGEventTapEnable(ptr, true) };
                    let enabled = unsafe { CGEventTapIsEnabled(ptr) };
                    if !enabled {
                        log::error!(
                            "CGEventTap re-enable failed after timeout; marking tap as dead"
                        );
                        tap_alive.store(false, Ordering::SeqCst);
                    }
                } else {
                    tap_alive.store(false, Ordering::SeqCst);
                }
                let n = TAP_DISABLED_COUNT.fetch_add(1, Ordering::Relaxed);
                log::warn!(
                    "CGEventTap disabled by timeout, re-enabled (count={})",
                    n + 1
                );
                return;
            }

            if event_type == K_CG_EVENT_KEY_DOWN || event_type == K_CG_EVENT_KEY_UP {
                // SAFETY: event is a valid CGEventRef provided by the run loop callback.
                let verification = unsafe { verify_event_source(event) };

                let is_hardware = match verification {
                    EventVerificationResult::Hardware => true,
                    EventVerificationResult::Suspicious => !strict,
                    EventVerificationResult::Synthetic => false,
                };

                total_events.fetch_add(1, Ordering::Relaxed);
                if is_hardware {
                    verified_hardware.fetch_add(1, Ordering::Relaxed);
                } else {
                    rejected_synthetic.fetch_add(1, Ordering::Relaxed);
                    return;
                }

                // Use kernel event timestamp for IKI precision instead of
                // wall-clock time (avoids CFRunLoop scheduling jitter).
                let now = unsafe { clock.to_utc_ns(CGEventGetTimestamp(event)) };
                // SAFETY: event is a valid CGEventRef for a key event.
                let keycode = u16::try_from(unsafe {
                    CGEventGetIntegerValueField(event, K_CG_KEYBOARD_EVENT_KEYCODE)
                })
                .unwrap_or(0xFF);
                let zone = crate::jitter::keycode_to_zone(keycode);

                // Extract composed Unicode text from the key event.
                let mut uni_buf = [0u16; 8];
                let mut uni_len: libc::c_ulong = 0;
                // SAFETY: event is a valid CGEventRef; buffer is stack-allocated.
                unsafe {
                    CGEventKeyboardGetUnicodeString(
                        event,
                        uni_buf.len() as libc::c_ulong,
                        &mut uni_len,
                        uni_buf.as_mut_ptr(),
                    );
                }
                let uni_len = (uni_len as usize).min(uni_buf.len());
                let (char_value, composed_text) = if uni_len > 0 {
                    let decoded = String::from_utf16_lossy(&uni_buf[..uni_len]);
                    let first_char = decoded.chars().next();
                    if decoded.chars().count() > 1 {
                        (first_char, Some(decoded))
                    } else {
                        (first_char, None)
                    }
                } else {
                    (None, None)
                };

                let keystroke = KeystrokeEvent {
                    timestamp_ns: now,
                    keycode,
                    zone: if zone >= 0 { zone as u8 } else { 0xFF },
                    event_type: if event_type == K_CG_EVENT_KEY_DOWN {
                        crate::platform::KeyEventType::Down
                    } else {
                        crate::platform::KeyEventType::Up
                    },
                    char_value,
                    composed_text,
                    is_hardware: true,
                    device_id: None,
                    transport_type: None,
                };

                if event_type == K_CG_EVENT_KEY_DOWN {
                    debug_write_keystroke("capture_tx", total_events.load(Ordering::Relaxed));
                }
                match tx.try_send(keystroke) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(_)) => {
                        let prev = DROPPED_KEYSTROKE_COUNT.fetch_add(1, Ordering::Relaxed);
                        if prev % 100 == 0 {
                            log::warn!(
                                "CGEventTap keystroke channel full; dropped events={}",
                                prev + 1
                            );
                        }
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        running.store(false, Ordering::SeqCst);
                    }
                }
            }
        });

        let runner = EventTapRunner::start(tap_cb)?;
        if let Some(ref res) = *runner.tap_resources.lock_recover() {
            tap_ptr.store(res.tap.as_ptr(), Ordering::SeqCst);
        }
        self.runner = Some(runner);
        Ok(rx)
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.tap_alive.store(false, Ordering::SeqCst);
        self.sender = None;
        if let Some(ref mut runner) = self.runner {
            runner.stop();
        }
        self.runner = None;
        Ok(())
    }

    fn synthetic_stats(&self) -> SyntheticStats {
        SyntheticStats {
            total_events: self.total_events.load(Ordering::Relaxed),
            verified_hardware: self.verified_hardware.load(Ordering::Relaxed),
            rejected_synthetic: self.rejected_synthetic.load(Ordering::Relaxed),
            ..SyntheticStats::default()
        }
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    fn get_strict_mode(&self) -> bool {
        self.strict_mode
    }

    fn is_tap_alive(&self) -> bool {
        self.tap_alive.load(Ordering::SeqCst)
    }
}

impl Drop for MacOSKeystrokeCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

impl std::fmt::Debug for KeystrokeMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeystrokeMonitor").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for MacOSKeystrokeCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacOSKeystrokeCapture")
            .finish_non_exhaustive()
    }
}
