// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! IOKit HID Manager keystroke capture for hardware-verified event counting.
//!
//! Registers an input value callback on all connected keyboards via IOKit HID.
//! Events arrive from the kernel HID driver and cannot be spoofed by user-space
//! event injection (CGEventPost, CGEventTapCreate). The count of HID keyDown
//! events serves as ground truth for dual-layer validation in `synthetic.rs`.

use super::ffi::*;
use core_foundation_sys::base::kCFAllocatorDefault;
use core_foundation_sys::dictionary::{CFDictionaryCreateMutable, CFDictionaryRef};
use core_foundation_sys::number::{kCFNumberSInt32Type, CFNumberCreate};
use core_foundation_sys::string::CFStringCreateWithCString;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Shared state between the HID callback and the owning thread.
struct HidCaptureContext {
    key_down_count: AtomicU64,
    key_up_count: AtomicU64,
    /// Mach timebase numerator for converting IOHIDValueGetTimeStamp to nanoseconds.
    #[allow(dead_code)]
    timebase_numer: u32,
    /// Mach timebase denominator for converting IOHIDValueGetTimeStamp to nanoseconds.
    #[allow(dead_code)]
    timebase_denom: u32,
}

/// Handles for CFRunLoop and IOHIDManager that the worker thread sends back
/// so that stop() can perform proper cleanup from the owning thread.
struct HidThreadHandles {
    run_loop: *mut std::ffi::c_void,
    manager: CfGuard,
}

// The raw pointers are CF objects retained by the worker thread; they are
// safe to send because stop() synchronizes via thread join after CFRunLoopStop.
unsafe impl Send for HidThreadHandles {}

/// IOKit HID Manager keystroke capture for dual-layer validation.
///
/// Runs on a dedicated thread with its own CFRunLoop, following the same
/// pattern as `EventTapRunner` in `keystroke.rs`.
pub struct HidInputCapture {
    context: Arc<HidCaptureContext>,
    running: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    handles: Arc<Mutex<Option<HidThreadHandles>>>,
}

impl HidInputCapture {
    /// Start HID capture on a background thread.
    ///
    /// Returns `None` if the HID manager could not be created or opened.
    pub fn start() -> Option<Self> {
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        // SAFETY: mach_timebase_info writes to a valid stack-allocated struct.
        unsafe {
            mach_timebase_info(&mut info);
        }
        if info.denom == 0 {
            log::warn!("mach_timebase_info returned zero denominator");
            return None;
        }

        let context = Arc::new(HidCaptureContext {
            key_down_count: AtomicU64::new(0),
            key_up_count: AtomicU64::new(0),
            timebase_numer: info.numer,
            timebase_denom: info.denom,
        });
        let running = Arc::new(AtomicBool::new(false));
        let handles: Arc<Mutex<Option<HidThreadHandles>>> = Arc::new(Mutex::new(None));

        // Increment the Arc strong count for the C callback. The matching
        // decrement happens in stop() after the run loop has exited.
        // Cast to usize to cross the thread boundary (raw pointers are !Send).
        let ctx_addr = Arc::into_raw(Arc::clone(&context)) as usize;

        let running_clone = Arc::clone(&running);
        let handles_clone = Arc::clone(&handles);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let thread = std::thread::Builder::new()
            .name("cpoe-hid-capture".into())
            .spawn(move || {
                let ctx_ptr = ctx_addr as *const HidCaptureContext;
                // SAFETY: ctx_ptr was obtained from Arc::into_raw; run_hid_loop's
                // safety contract is satisfied (dedicated thread, valid pointer).
                let result = unsafe { run_hid_loop(ctx_ptr) };
                match result {
                    Some((manager, run_loop)) => {
                        *handles_clone.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some(HidThreadHandles { run_loop, manager });
                        running_clone.store(true, Ordering::SeqCst);
                        let _ = ready_tx.send(true);
                        // SAFETY: CFRunLoopRun blocks on the current thread's run loop
                        // until CFRunLoopStop is called from stop().
                        unsafe { CFRunLoopRun() };
                    }
                    None => {
                        let _ = ready_tx.send(false);
                    }
                }
                running_clone.store(false, Ordering::SeqCst);
            })
            .ok()?;

        let ok = ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or(false);
        if !ok {
            log::warn!("HID capture thread failed to start");
            // SAFETY: We incremented the strong count via Arc::into_raw(Arc::clone(&context))
            // in start(); the thread failed, so we must reclaim to avoid a leak.
            unsafe { Arc::decrement_strong_count(Arc::as_ptr(&context)) };
            return None;
        }

        Some(Self {
            context,
            running,
            thread: Some(thread),
            handles,
        })
    }

    /// Number of hardware keyDown events observed.
    pub fn key_down_count(&self) -> u64 {
        self.context.key_down_count.load(Ordering::Relaxed)
    }

    /// Number of hardware keyUp events observed.
    pub fn key_up_count(&self) -> u64 {
        self.context.key_up_count.load(Ordering::Relaxed)
    }

    /// Whether the HID capture thread is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop HID capture, clean up resources, and join the thread.
    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            // Already stopped or never started.
            if let Some(handle) = self.thread.take() {
                let _ = handle.join();
            }
            return;
        }

        // Take the handles and perform cleanup from this thread.
        let thread_handles = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();

        if let Some(h) = thread_handles {
            // SAFETY: h.manager and h.run_loop are valid CF objects created by
            // run_hid_loop. We replace the callback with a no-op first, then
            // unschedule, close, and release before stopping the run loop.
            unsafe {
                IOHIDManagerRegisterInputValueCallback(
                    h.manager.as_ptr(),
                    hid_input_callback_noop,
                    std::ptr::null_mut(),
                );
                IOHIDManagerUnscheduleFromRunLoop(
                    h.manager.as_ptr(),
                    h.run_loop,
                    kCFRunLoopCommonModes,
                );
                IOHIDManagerClose(h.manager.as_ptr(), K_IO_HID_OPTIONS_TYPE_NONE);
                // h.manager released on drop via CfGuard

                CFRunLoopStop(h.run_loop);
            }
        }

        // Join the worker thread (should return promptly after CFRunLoopStop).
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }

        // Reclaim the Arc ref we leaked for the C callback. The callback is now
        // unregistered and the thread has exited, so no more accesses are possible.
        // We reconstruct the Arc from context's raw pointer. Since we incremented
        // the count in start() via Arc::into_raw(Arc::clone(&context)), we need to
        // decrement it by reconstructing and dropping.
        //
        // SAFETY: The callback has been replaced with a no-op and the run loop
        // has stopped, so the raw pointer is no longer accessed by C code.
        unsafe {
            Arc::decrement_strong_count(Arc::as_ptr(&self.context));
        }
    }
}

impl Drop for HidInputCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// No-op callback used to replace the real callback during shutdown,
/// ensuring no events fire against freed context.
extern "C" fn hid_input_callback_noop(
    _context: *mut std::ffi::c_void,
    _result: i32,
    _sender: *mut std::ffi::c_void,
    _value: *mut std::ffi::c_void,
) {
}

/// Set up IOHIDManager, register callback, and schedule on current thread's run loop.
///
/// Returns `Some((manager_guard, run_loop))` on success so stop() can clean up.
/// The `CfGuard` owns the manager; `run_loop` is a borrowed `CFRunLoopGetCurrent()`.
///
/// # Safety
///
/// Must be called on the dedicated HID thread. `ctx_raw` must be a pointer
/// obtained from `Arc::into_raw` that will be reclaimed by the caller.
unsafe fn run_hid_loop(
    ctx_raw: *const HidCaptureContext,
) -> Option<(CfGuard, *mut std::ffi::c_void)> {
    let manager = CfGuard::new(IOHIDManagerCreate(
        kCFAllocatorDefault,
        K_IO_HID_OPTIONS_TYPE_NONE,
    ))?;

    // Build matching dictionary for keyboard devices (usage page 0x01, usage 0x06).
    let matching = CfGuard::new(
        CFDictionaryCreateMutable(
            kCFAllocatorDefault,
            2,
            &core_foundation_sys::dictionary::kCFTypeDictionaryKeyCallBacks,
            &core_foundation_sys::dictionary::kCFTypeDictionaryValueCallBacks,
        ) as *mut _,
    )?;

    let page_key = CfGuard::new(cfstr(K_IO_HID_DEVICE_USAGE_PAGE_KEY));
    let usage_key = CfGuard::new(cfstr(K_IO_HID_DEVICE_USAGE_KEY));
    let page_val = CfGuard::new(cfnum(K_HID_PAGE_GENERIC_DESKTOP));
    let usage_val = CfGuard::new(cfnum(K_HID_USAGE_GD_KEYBOARD));

    let (page_key, usage_key, page_val, usage_val) = match (page_key, usage_key, page_val, usage_val)
    {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => return None,
    };

    core_foundation_sys::dictionary::CFDictionarySetValue(
        matching.as_ptr() as *mut _,
        page_key.as_ptr() as *const _,
        page_val.as_ptr() as *const _,
    );
    core_foundation_sys::dictionary::CFDictionarySetValue(
        matching.as_ptr() as *mut _,
        usage_key.as_ptr() as *const _,
        usage_val.as_ptr() as *const _,
    );

    IOHIDManagerSetDeviceMatching(manager.as_ptr(), matching.as_ptr() as CFDictionaryRef);
    drop((matching, page_key, usage_key, page_val, usage_val));

    let result = IOHIDManagerOpen(manager.as_ptr(), K_IO_HID_OPTIONS_TYPE_NONE);
    if result != 0 {
        log::error!("IOHIDManagerOpen failed: {result}");
        return None;
    }

    // Register callback with the Arc raw pointer. The Arc ref count was
    // incremented by the caller via Arc::into_raw; it will be decremented
    // in stop() after the callback is unregistered.
    IOHIDManagerRegisterInputValueCallback(
        manager.as_ptr(),
        hid_input_callback,
        ctx_raw as *mut std::ffi::c_void,
    );

    let run_loop = CFRunLoopGetCurrent();
    IOHIDManagerScheduleWithRunLoop(manager.as_ptr(), run_loop, kCFRunLoopCommonModes);

    Some((manager, run_loop))
}

/// C callback invoked by IOKit for each HID input value.
///
/// # Safety
///
/// `context` must be a valid `*const HidCaptureContext` with a live Arc ref.
/// `value` must be a valid `IOHIDValueRef`.
extern "C" fn hid_input_callback(
    context: *mut std::ffi::c_void,
    _result: i32,
    _sender: *mut std::ffi::c_void,
    value: *mut std::ffi::c_void,
) {
    if context.is_null() || value.is_null() {
        return;
    }

    // SAFETY: context is a valid *const HidCaptureContext with a live Arc ref
    // (guaranteed by the into_raw/decrement_strong_count pairing in start/stop).
    // value is a valid IOHIDValueRef provided by IOKit.
    unsafe {
        let element = IOHIDValueGetElement(value);
        if element.is_null() {
            return;
        }

        let usage_page = IOHIDElementGetUsagePage(element);
        let usage = IOHIDElementGetUsage(element);

        // Filter: only keyboard/keypad usage page (0x07), standard key range.
        // Usages 0x04..=0xE7 cover letters, digits, punctuation, modifiers.
        if usage_page != K_HID_PAGE_KEYBOARD_OR_KEYPAD {
            return;
        }
        if !(0x04..=0xE7).contains(&usage) {
            return;
        }

        let int_value = IOHIDValueGetIntegerValue(value);
        let ctx = &*(context as *const HidCaptureContext);

        if int_value == 1 {
            ctx.key_down_count.fetch_add(1, Ordering::Relaxed);
        } else if int_value == 0 {
            ctx.key_up_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Create a CFString from a Rust string. Caller must CFRelease.
unsafe fn cfstr(s: &str) -> *mut std::ffi::c_void {
    let c = match CString::new(s) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    CFStringCreateWithCString(
        kCFAllocatorDefault,
        c.as_ptr(),
        core_foundation_sys::string::kCFStringEncodingUTF8,
    ) as *mut _
}

/// Create a CFNumber from an i32. Caller must CFRelease.
unsafe fn cfnum(v: i32) -> *mut std::ffi::c_void {
    CFNumberCreate(
        kCFAllocatorDefault,
        kCFNumberSInt32Type,
        &v as *const _ as *const _,
    ) as *mut _
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mach_timebase_info() {
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        let ret = unsafe { mach_timebase_info(&mut info) };
        assert_eq!(ret, 0);
        assert!(info.numer > 0);
        assert!(info.denom > 0);
    }

    #[test]
    fn test_mach_absolute_time_monotonic() {
        let t1 = unsafe { mach_absolute_time() };
        let t2 = unsafe { mach_absolute_time() };
        assert!(t2 >= t1);
    }
}

impl std::fmt::Debug for HidInputCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HidInputCapture").finish_non_exhaustive()
    }
}
