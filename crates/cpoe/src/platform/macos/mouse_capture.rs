// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! macOS mouse capture using CGEventTap for idle jitter and steganography.

use super::ffi::*;
use super::keystroke::RunLoopHandle;
use crate::platform::{MouseCapture, MouseEvent, MouseIdleStats, MouseStegoParams};
use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};

use crate::DateTimeNanosExt;
use crate::MutexRecover;
use crate::RwLockRecover;

/// Holds CF objects created by the mouse CGEventTap. Resources are released
/// automatically via `CfGuard` when this struct is dropped.
struct MouseTapResources {
    run_loop: *mut std::ffi::c_void,
    tap: CfGuard,
    source: CfGuard,
}
unsafe impl Send for MouseTapResources {}
unsafe impl Sync for MouseTapResources {}

/// macOS mouse capture implementation using CGEventTap.
pub struct MacOSMouseCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<MouseEvent>>,
    thread: Option<std::thread::JoinHandle<()>>,
    idle_stats: Arc<RwLock<MouseIdleStats>>,
    stego_params: MouseStegoParams,
    idle_only_mode: bool,
    last_position: Arc<RwLock<(f64, f64)>>,
    keyboard_active: Arc<AtomicBool>,
    last_keystroke_time: Arc<RwLock<std::time::Instant>>,
    run_loop: Arc<Mutex<Option<RunLoopHandle>>>,
    tap_resources: Arc<Mutex<Option<MouseTapResources>>>,
}

impl MacOSMouseCapture {
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
            idle_stats: Arc::new(RwLock::new(MouseIdleStats::new())),
            stego_params: MouseStegoParams::default(),
            idle_only_mode: true,
            last_position: Arc::new(RwLock::new((0.0, 0.0))),
            keyboard_active: Arc::new(AtomicBool::new(false)),
            last_keystroke_time: Arc::new(RwLock::new(std::time::Instant::now())),
            run_loop: Arc::new(Mutex::new(None)),
            tap_resources: Arc::new(Mutex::new(None)),
        })
    }

    /// Notify the mouse capture that a keystroke occurred.
    ///
    /// This is used to detect idle periods for mouse jitter capture.
    pub fn notify_keystroke(&self) {
        self.keyboard_active.store(true, Ordering::SeqCst);
        *self.last_keystroke_time.write_recover() = std::time::Instant::now();
    }
}

impl MouseCapture for MacOSMouseCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<MouseEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Mouse capture already running"));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        let running = Arc::clone(&self.running);
        let idle_stats = Arc::clone(&self.idle_stats);
        let last_position = Arc::clone(&self.last_position);
        let keyboard_active = Arc::clone(&self.keyboard_active);
        let last_keystroke_time = Arc::clone(&self.last_keystroke_time);
        let idle_only_mode = self.idle_only_mode;
        let run_loop = Arc::clone(&self.run_loop);
        let tap_resources = Arc::clone(&self.tap_resources);

        running.store(true, Ordering::SeqCst);

        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();

        let clock = MachToWallClock::calibrate();
        let thread = std::thread::spawn(move || {
            let mut tap_cb: TapCallback =
                Box::new(move |event: *mut std::ffi::c_void, event_type: u32| {
                    if !running.load(Ordering::SeqCst) {
                        return;
                    }

                    if event_type == K_CG_EVENT_MOUSE_MOVED {
                        let should_capture = if idle_only_mode {
                            if let Ok(time) = last_keystroke_time.read() {
                                time.elapsed() < std::time::Duration::from_secs(2)
                            } else {
                                false
                            }
                        } else {
                            true
                        };

                        if !should_capture {
                            return;
                        }

                        let now = unsafe { clock.to_utc_ns(CGEventGetTimestamp(event)) };

                        let location = unsafe { CGEventGetLocation(event) };
                        let x = location.x;
                        let y = location.y;

                        let (dx, dy) = {
                            let mut last_pos = last_position.write_recover();
                            let delta = (x - last_pos.0, y - last_pos.1);
                            *last_pos = (x, y);
                            delta
                        };

                        let is_idle = !keyboard_active.load(Ordering::SeqCst);
                        let mouse_event = if is_idle {
                            MouseEvent::idle_jitter(now, x, y, dx, dy)
                        } else {
                            MouseEvent::new(now, x, y, dx, dy)
                        };

                        if mouse_event.is_micro_movement() && is_idle {
                            idle_stats.write_recover().record(&mouse_event);
                        }

                        let _ = tx.send(mouse_event);

                        if !idle_only_mode {
                            keyboard_active.store(false, Ordering::SeqCst);
                        }
                    }
                });

            unsafe {
                let tap = match CfGuard::new(CGEventTapCreate(
                    K_CG_HID_EVENT_TAP,
                    K_CG_HEAD_INSERT_EVENT_TAP,
                    K_CG_EVENT_TAP_OPTION_LISTEN_ONLY,
                    cg_event_mask_bit(K_CG_EVENT_MOUSE_MOVED),
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
                *run_loop.lock_recover() = Some(RunLoopHandle(rl_ref));
                CFRunLoopAddSource(rl_ref, source.as_ptr(), kCFRunLoopCommonModes);
                CGEventTapEnable(tap.as_ptr(), true);
                {
                    let mut res = tap_resources.lock_recover();
                    *res = Some(MouseTapResources {
                        run_loop: rl_ref,
                        tap,
                        source,
                    });
                }
                let _ = ready_tx.send(Ok(()));
                CFRunLoopRun();
            }
        });

        match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(())) => {
                self.thread = Some(thread);
                Ok(rx)
            }
            Ok(Err(err)) => {
                self.running.store(false, Ordering::SeqCst);
                self.sender = None;
                Err(err)
            }
            Err(_) => {
                self.running.store(false, Ordering::SeqCst);
                self.sender = None;
                Err(anyhow!(
                    "Mouse CGEventTap initialization timed out after 5s"
                ))
            }
        }
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;
        // Take the run_loop handle to stop it, but defer CFRelease until after thread exits
        let ptr = self.run_loop.lock_recover().take().map(|h| h.0);
        if let Some(p) = ptr {
            unsafe {
                CFRunLoopStop(p);
            }
        }
        let mut thread_joined = false;
        if let Some(thread) = self.thread.take() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                if thread.is_finished() {
                    let _ = thread.join();
                    thread_joined = true;
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    log::warn!("Mouse capture thread did not finish within 3s; detaching");
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
            // tap and source are released automatically via CfGuard;
            // run_loop was obtained via CFRunLoopGetCurrent + CFRetain.
            if let Some(res) = self.tap_resources.lock_recover().take() {
                unsafe { CFRelease(res.run_loop) };
            } else if let Some(p) = ptr {
                // Fallback: release run loop if tap_resources wasn't populated
                unsafe { CFRelease(p) };
            }
        }
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn idle_stats(&self) -> MouseIdleStats {
        self.idle_stats.read_recover().clone()
    }

    fn reset_idle_stats(&mut self) {
        *self.idle_stats.write_recover() = MouseIdleStats::new();
    }

    fn set_stego_params(&mut self, params: MouseStegoParams) {
        self.stego_params = params;
    }

    fn get_stego_params(&self) -> MouseStegoParams {
        self.stego_params.clone()
    }

    fn set_idle_only_mode(&mut self, enabled: bool) {
        self.idle_only_mode = enabled;
    }

    fn is_idle_only_mode(&self) -> bool {
        self.idle_only_mode
    }
}

impl Drop for MacOSMouseCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

impl std::fmt::Debug for MacOSMouseCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacOSMouseCapture").finish_non_exhaustive()
    }
}
