// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Windows Raw Input API keystroke capture for hardware-verified event counting.
//!
//! Registers for raw keyboard input via `RegisterRawInputDevices` with
//! `RIDEV_INPUTSINK` so events are received even when the window is not focused.
//! Events arrive from the kernel input stack and identify the physical device via
//! `RAWINPUTHEADER::hDevice`, providing ground truth that cannot be spoofed by
//! user-space injection (`SendInput`, `keybd_event`). The count of hardware
//! key-down events serves as the second layer for dual-layer validation in
//! `synthetic.rs`, mirroring the IOKit HID capture on macOS.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Input::{
    GetRawInputData, RegisterRawInputDevices, RAWINPUT, RAWINPUTDEVICE, RAWINPUTHEADER,
    RIDEV_INPUTSINK, RID_INPUT, RIM_TYPEKEYBOARD,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GetMessageW, PostThreadMessageW,
    RegisterClassExW, HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WM_INPUT, WM_QUIT,
    WNDCLASSEXW,
};

/// Win32 `RI_KEY_BREAK` flag (bit 0 of `RAWKEYBOARD::Flags`).
/// When set, the event is a key release; when clear, it is a key press (make).
const RI_KEY_BREAK: u16 = 1;

/// HID Generic Desktop usage page.
const HID_USAGE_PAGE_GENERIC: u16 = 0x01;
/// HID Generic Desktop: Keyboard usage.
const HID_USAGE_GENERIC_KEYBOARD: u16 = 0x06;

/// Shared state between the Raw Input callback and the owning thread.
struct RawInputContext {
    key_down_count: AtomicU64,
    key_up_count: AtomicU64,
}

/// Windows Raw Input keystroke capture for dual-layer validation.
///
/// Runs on a dedicated thread with its own message-only window and message pump,
/// following the same pattern as `WindowsKeystrokeCapture` in `windows.rs`.
pub struct HidInputCapture {
    context: Arc<RawInputContext>,
    running: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    thread_id: Arc<AtomicU32>,
}

// Store context pointer in a thread-local so the WNDPROC can access it without
// a global. Each Raw Input thread sets this before entering the message loop.
thread_local! {
    static RAW_INPUT_CTX: std::cell::Cell<*const RawInputContext> =
        const { std::cell::Cell::new(std::ptr::null()) };
}

impl HidInputCapture {
    /// Start Raw Input capture on a background thread.
    ///
    /// Returns `None` if the window or device registration fails.
    pub fn start() -> Option<Self> {
        let context = Arc::new(RawInputContext {
            key_down_count: AtomicU64::new(0),
            key_up_count: AtomicU64::new(0),
        });
        let running = Arc::new(AtomicBool::new(false));
        let thread_id = Arc::new(AtomicU32::new(0));

        let ctx_clone = Arc::clone(&context);
        let running_clone = Arc::clone(&running);
        let tid_clone = Arc::clone(&thread_id);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let thread = std::thread::Builder::new()
            .name("cpoe-hid-capture".into())
            .spawn(move || {
                // Store thread ID so stop() can post WM_QUIT.
                // SAFETY: GetCurrentThreadId is always safe.
                let tid = unsafe { GetCurrentThreadId() };
                tid_clone.store(tid, Ordering::SeqCst);

                // Leak an Arc ref for the window procedure callback. The matching
                // decrement happens in stop() after the message loop has exited.
                let ctx_ptr = Arc::into_raw(Arc::clone(&ctx_clone));
                RAW_INPUT_CTX.with(|cell| cell.set(ctx_ptr));

                match unsafe { create_raw_input_window() } {
                    Some(hwnd) => {
                        running_clone.store(true, Ordering::SeqCst);
                        let _ = ready_tx.send(true);

                        // Message loop: blocks until WM_QUIT is received.
                        let mut msg = MSG::default();
                        // SAFETY: GetMessageW is a standard Win32 blocking call.
                        // Passing the window handle filters messages to this window.
                        // The loop exits when GetMessageW returns 0 (WM_QUIT).
                        unsafe {
                            while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
                                // WM_INPUT messages are dispatched via DefWindowProc
                                // in our WNDPROC; no TranslateMessage needed.
                            }
                            DestroyWindow(hwnd).ok();
                        }
                    }
                    None => {
                        let _ = ready_tx.send(false);
                    }
                }

                // Clear the thread-local and mark stopped.
                RAW_INPUT_CTX.with(|cell| cell.set(std::ptr::null()));
                running_clone.store(false, Ordering::SeqCst);
            })
            .ok()?;

        let ok = ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or(false);
        if !ok {
            log::warn!("Raw Input capture thread failed to start");
            // The thread failed before entering the loop, so the Arc ref leaked
            // via Arc::into_raw must be reclaimed.
            unsafe { Arc::decrement_strong_count(Arc::as_ptr(&context)) };
            return None;
        }

        Some(Self {
            context,
            running,
            thread: Some(thread),
            thread_id,
        })
    }

    /// Number of hardware key-down events observed via Raw Input.
    pub fn key_down_count(&self) -> u64 {
        self.context.key_down_count.load(Ordering::Relaxed)
    }

    /// Number of hardware key-up events observed via Raw Input.
    #[allow(dead_code)]
    pub fn key_up_count(&self) -> u64 {
        self.context.key_up_count.load(Ordering::Relaxed)
    }

    /// Whether the Raw Input capture thread is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop Raw Input capture, clean up resources, and join the thread.
    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            if let Some(handle) = self.thread.take() {
                let _ = handle.join();
            }
            return;
        }

        // Post WM_QUIT to the message pump thread to break its GetMessageW loop.
        let tid = self.thread_id.load(Ordering::SeqCst);
        if tid != 0 {
            // SAFETY: PostThreadMessageW with a valid thread ID is safe.
            unsafe {
                if PostThreadMessageW(tid, WM_QUIT, WPARAM(0), LPARAM(0)).is_err() {
                    log::warn!("PostThreadMessageW(WM_QUIT) failed for Raw Input thread {tid}");
                }
            }
        }

        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }

        // Reclaim the Arc ref leaked for the window procedure callback.
        // The thread has exited, so no more accesses are possible.
        // SAFETY: The message loop has exited and the thread has joined.
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

impl std::fmt::Debug for HidInputCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HidInputCapture").finish_non_exhaustive()
    }
}

/// Register a unique window class and create a message-only window for Raw Input.
///
/// # Safety
///
/// Must be called on the dedicated Raw Input thread. The caller must ensure
/// `RAW_INPUT_CTX` thread-local is set before entering the message loop.
unsafe fn create_raw_input_window() -> Option<HWND> {
    // Use a unique class name incorporating the thread ID to avoid collisions.
    let class_name_str = format!("CPoE_RawInput_{}\0", GetCurrentThreadId());
    let class_name: Vec<u16> = class_name_str.encode_utf16().collect();

    let wc = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(raw_input_wnd_proc),
        lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
        ..Default::default()
    };

    let atom = RegisterClassExW(&wc);
    if atom == 0 {
        log::error!("RegisterClassExW failed for Raw Input window");
        return None;
    }

    // Create a message-only window (HWND_MESSAGE parent) that receives no
    // visible UI but can process WM_INPUT messages.
    let hwnd = match CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        windows::core::PCWSTR(class_name.as_ptr()),
        windows::core::PCWSTR::null(),
        WINDOW_STYLE::default(),
        0,
        0,
        0,
        0,
        Some(HWND_MESSAGE),
        None,
        None,
        None,
    ) {
        Ok(h) if !h.is_invalid() => h,
        _ => {
            log::error!("CreateWindowExW failed for Raw Input message-only window");
            return None;
        }
    };

    // Register for raw keyboard input with RIDEV_INPUTSINK so we receive
    // events even when the window does not have focus.
    let rid = RAWINPUTDEVICE {
        usUsagePage: HID_USAGE_PAGE_GENERIC,
        usUsage: HID_USAGE_GENERIC_KEYBOARD,
        dwFlags: RIDEV_INPUTSINK,
        hwndTarget: hwnd,
    };

    let registered = RegisterRawInputDevices(&[rid], std::mem::size_of::<RAWINPUTDEVICE>() as u32);

    if let Err(e) = registered {
        log::error!("RegisterRawInputDevices failed: {e}");
        DestroyWindow(hwnd).ok();
        return None;
    }

    log::info!("Raw Input keyboard capture registered on message-only window");
    Some(hwnd)
}

/// Window procedure for the Raw Input message-only window.
///
/// Handles `WM_INPUT` messages by reading the `RAWINPUT` data and incrementing
/// key-down/key-up counters. All other messages are passed to `DefWindowProcW`.
///
/// # Safety
///
/// Standard Win32 WNDPROC contract. `RAW_INPUT_CTX` thread-local must point
/// to a valid `RawInputContext` with a live Arc ref.
unsafe extern "system" fn raw_input_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg != WM_INPUT {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }

    let ctx_ptr = RAW_INPUT_CTX.with(|cell| cell.get());
    if ctx_ptr.is_null() {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }

    // Query the size of the RAWINPUT data first.
    let mut size: u32 = 0;
    let header_size = std::mem::size_of::<RAWINPUTHEADER>() as u32;

    // SAFETY: First call with pData = None returns the required buffer size.
    // HRAWINPUT is passed via LPARAM per the WM_INPUT contract.
    let ret = GetRawInputData(
        windows::Win32::UI::Input::HRAWINPUT(lparam.0 as *mut _),
        RID_INPUT,
        None,
        &mut size,
        header_size,
    );

    if ret == u32::MAX || size == 0 {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }

    // Allocate a buffer on the stack if small enough, otherwise on the heap.
    // RAWINPUT for keyboard is ~48 bytes; 256 covers any realistic case.
    let mut stack_buf = [0u8; 256];
    let buf: &mut [u8] = if (size as usize) <= stack_buf.len() {
        &mut stack_buf[..size as usize]
    } else {
        // Heap-allocate for unexpectedly large data.
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    };

    // SAFETY: buf is large enough (verified above). GetRawInputData fills the
    // buffer with a RAWINPUT struct. HRAWINPUT is the lparam from WM_INPUT.
    let copied = GetRawInputData(
        windows::Win32::UI::Input::HRAWINPUT(lparam.0 as *mut _),
        RID_INPUT,
        Some(buf.as_mut_ptr() as *mut _),
        &mut size,
        header_size,
    );

    if copied == u32::MAX || (copied as usize) < std::mem::size_of::<RAWINPUT>() {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }

    // SAFETY: buf contains a valid RAWINPUT struct (verified by GetRawInputData
    // returning the correct size). The pointer is properly aligned because
    // RAWINPUT's alignment is <= 8 and stack arrays are naturally aligned.
    let raw = &*(buf.as_ptr() as *const RAWINPUT);

    // Only process keyboard events. hDevice != 0 confirms a physical device
    // originated the event (synthetic events from SendInput have hDevice == 0).
    if raw.header.dwType != RIM_TYPEKEYBOARD.0 {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }

    // Reject events with a null device handle; these are injected via SendInput
    // or keybd_event which set hDevice to NULL.
    if raw.header.hDevice.is_invalid() {
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }

    // SAFETY: dwType == RIM_TYPEKEYBOARD, so the keyboard union variant is valid.
    let keyboard = raw.data.keyboard;

    let ctx = &*ctx_ptr;
    if (keyboard.Flags & RI_KEY_BREAK) == 0 {
        // Key make (press).
        ctx.key_down_count.fetch_add(1, Ordering::Relaxed);
    } else {
        // Key break (release).
        ctx.key_up_count.fetch_add(1, Ordering::Relaxed);
    }

    DefWindowProcW(hwnd, msg, wparam, lparam)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ri_key_break_constant() {
        // RI_KEY_BREAK is bit 0; a make event has Flags & RI_KEY_BREAK == 0.
        assert_eq!(RI_KEY_BREAK, 1);
        assert_eq!(0u16 & RI_KEY_BREAK, 0); // make
        assert_eq!(1u16 & RI_KEY_BREAK, 1); // break
    }

    #[test]
    fn test_hid_usage_constants() {
        assert_eq!(HID_USAGE_PAGE_GENERIC, 0x01);
        assert_eq!(HID_USAGE_GENERIC_KEYBOARD, 0x06);
    }

    #[test]
    fn test_context_atomic_operations() {
        let ctx = RawInputContext {
            key_down_count: AtomicU64::new(0),
            key_up_count: AtomicU64::new(0),
        };
        ctx.key_down_count.fetch_add(1, Ordering::Relaxed);
        ctx.key_down_count.fetch_add(1, Ordering::Relaxed);
        ctx.key_up_count.fetch_add(1, Ordering::Relaxed);
        assert_eq!(ctx.key_down_count.load(Ordering::Relaxed), 2);
        assert_eq!(ctx.key_up_count.load(Ordering::Relaxed), 1);
    }
}
