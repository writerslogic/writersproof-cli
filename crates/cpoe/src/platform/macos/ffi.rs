// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI bindings for IOKit HID, Accessibility API, and CGEvent constants.

use core_foundation_sys::base::{CFAllocatorRef, CFIndex, CFTypeID, CFTypeRef};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;

#[allow(dead_code)]
#[link(name = "IOKit", kind = "framework")]
extern "C" {
    pub fn IOHIDManagerCreate(allocator: CFAllocatorRef, options: u32) -> *mut std::ffi::c_void;
    pub fn IOHIDManagerSetDeviceMatching(manager: *mut std::ffi::c_void, matching: CFDictionaryRef);
    pub fn IOHIDManagerCopyDevices(manager: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    pub fn IOHIDManagerOpen(manager: *mut std::ffi::c_void, options: u32) -> i32;
    pub fn IOHIDManagerClose(manager: *mut std::ffi::c_void, options: u32) -> i32;
    pub fn IOHIDManagerScheduleWithRunLoop(
        manager: *mut std::ffi::c_void,
        run_loop: *mut std::ffi::c_void,
        mode: CFStringRef,
    );
    pub fn IOHIDManagerUnscheduleFromRunLoop(
        manager: *mut std::ffi::c_void,
        run_loop: *mut std::ffi::c_void,
        mode: CFStringRef,
    );
    pub fn IOHIDManagerRegisterInputValueCallback(
        manager: *mut std::ffi::c_void,
        callback: extern "C" fn(
            *mut std::ffi::c_void,
            i32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
        ),
        context: *mut std::ffi::c_void,
    );

    pub fn IOHIDDeviceGetProperty(device: *mut std::ffi::c_void, key: CFStringRef) -> CFTypeRef;

    pub fn CFSetGetCount(set: *mut std::ffi::c_void) -> CFIndex;
    pub fn CFSetGetValues(set: *mut std::ffi::c_void, values: *mut *const std::ffi::c_void);
    pub fn CFRelease(cf: *mut std::ffi::c_void);
    pub fn CFRetain(cf: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    pub fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    pub fn CFStringGetTypeID() -> CFTypeID;
    pub fn CFURLGetTypeID() -> CFTypeID;
    pub fn CFRunLoopGetCurrent() -> *mut std::ffi::c_void;
    pub fn CFRunLoopStop(rl: *mut std::ffi::c_void);

    pub fn IOHIDValueGetElement(value: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    pub fn IOHIDValueGetIntegerValue(value: *mut std::ffi::c_void) -> CFIndex;
    pub fn IOHIDValueGetTimeStamp(value: *mut std::ffi::c_void) -> u64;
    pub fn IOHIDElementGetUsagePage(element: *mut std::ffi::c_void) -> u32;
    pub fn IOHIDElementGetUsage(element: *mut std::ffi::c_void) -> u32;
}

#[repr(C)]
pub struct MachTimebaseInfo {
    pub numer: u32,
    pub denom: u32,
}

#[allow(dead_code)]
extern "C" {
    pub fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
    pub fn mach_absolute_time() -> u64;
}

/// Snapshot of the wall-clock ↔ mach_absolute_time offset, taken once at
/// capture start. Applying this to kernel event timestamps yields UTC
/// nanoseconds with kernel-level precision (no CFRunLoop scheduling jitter).
pub struct MachToWallClock {
    /// UTC nanoseconds at calibration time.
    utc_ns: i64,
    /// mach_absolute_time() at calibration time (already in nanoseconds on Apple Silicon;
    /// on Intel, pre-converted via timebase ratio).
    mach_ns: u64,
    /// Timebase numerator (for mach ticks → nanoseconds conversion).
    numer: u32,
    /// Timebase denominator.
    denom: u32,
}

impl MachToWallClock {
    /// Calibrate the offset between wall-clock and monotonic time.
    /// Call once at capture start; reuse for all events in the session.
    pub fn calibrate() -> Self {
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        unsafe { mach_timebase_info(&mut info) };
        // If timebase query fails, default to 1:1 (correct on Apple Silicon).
        if info.denom == 0 {
            info.numer = 1;
            info.denom = 1;
        }
        let mach_ticks = unsafe { mach_absolute_time() };
        let mach_ns = mach_ticks as u128 * info.numer as u128 / info.denom as u128;
        let utc_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        Self {
            utc_ns,
            mach_ns: mach_ns as u64,
            numer: info.numer,
            denom: info.denom,
        }
    }

    /// Convert a kernel event timestamp (mach absolute time nanoseconds,
    /// as returned by `CGEventGetTimestamp`) to UTC nanoseconds.
    pub fn to_utc_ns(&self, event_mach_ns: u64) -> i64 {
        let delta = event_mach_ns as i128 - self.mach_ns as i128;
        (self.utc_ns as i128 + delta) as i64
    }

    /// Convert a raw mach_absolute_time tick value (as returned by
    /// `IOHIDValueGetTimeStamp`) to UTC nanoseconds.
    pub fn ticks_to_utc_ns(&self, mach_ticks: u64) -> i64 {
        let mach_ns = mach_ticks as u128 * self.numer as u128 / self.denom as u128;
        self.to_utc_ns(mach_ns as u64)
    }
}

pub const K_HID_PAGE_GENERIC_DESKTOP: i32 = 0x01;
#[allow(dead_code)]
pub const K_HID_PAGE_KEYBOARD_OR_KEYPAD: u32 = 0x07;
pub const K_HID_USAGE_GD_KEYBOARD: i32 = 0x06;
pub const K_IO_HID_OPTIONS_TYPE_NONE: u32 = 0;

pub const K_IO_HID_DEVICE_USAGE_PAGE_KEY: &str = "DeviceUsagePage";
pub const K_IO_HID_DEVICE_USAGE_KEY: &str = "DeviceUsage";
pub const K_IO_HID_VENDOR_ID_KEY: &str = "VendorID";
pub const K_IO_HID_PRODUCT_ID_KEY: &str = "ProductID";
pub const K_IO_HID_PRODUCT_KEY: &str = "Product";
pub const K_IO_HID_MANUFACTURER_KEY: &str = "Manufacturer";
pub const K_IO_HID_SERIAL_NUMBER_KEY: &str = "SerialNumber";
pub const K_IO_HID_TRANSPORT_KEY: &str = "Transport";

#[allow(dead_code)]
#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    pub fn AXIsProcessTrusted() -> bool;
    pub fn AXIsProcessTrustedWithOptions(options: CFDictionaryRef) -> bool;
    pub fn CGPreflightListenEventAccess() -> bool;
    pub fn CGRequestListenEventAccess() -> bool;

}

// CGEventField constants (values from Apple's CGEventTypes.h)
pub const K_CG_EVENT_SOURCE_STATE_ID: u32 = 45;
pub const K_CG_KEYBOARD_EVENT_KEYBOARD_TYPE: u32 = 10;
pub const K_CG_KEYBOARD_EVENT_KEYCODE: u32 = 9;
pub const K_CG_EVENT_SOURCE_UNIX_PROCESS_ID: u32 = 41;

pub const K_CG_EVENT_SOURCE_STATE_PRIVATE: i64 = -1;
pub const K_CG_EVENT_SOURCE_STATE_HID_SYSTEM: i64 = 1;

// CGEventTap constants (values from Apple's CGEventTypes.h / Quartz Event Services)
pub const K_CG_HID_EVENT_TAP: u32 = 0;
pub const K_CG_HEAD_INSERT_EVENT_TAP: u32 = 0;
pub const K_CG_EVENT_TAP_OPTION_LISTEN_ONLY: u32 = 0x00000001;
pub const K_CG_EVENT_KEY_DOWN: u32 = 10;
pub const K_CG_EVENT_KEY_UP: u32 = 11;
pub const K_CG_EVENT_MOUSE_MOVED: u32 = 5;
/// macOS sends this event_type when it disables the tap due to callback latency.
pub const K_CG_EVENT_TAP_DISABLED_BY_TIMEOUT: u32 = 0xFFFFFFFE;

pub const fn cg_event_mask_bit(event_type: u32) -> u64 {
    1u64 << event_type
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CGPoint {
    pub x: f64,
    pub y: f64,
}

pub type CGEventTapCallBack = unsafe extern "C" fn(
    proxy: *mut std::ffi::c_void,
    event_type: u32,
    event: *mut std::ffi::c_void,
    user_info: *mut std::ffi::c_void,
) -> *mut std::ffi::c_void;

#[allow(dead_code)]
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    pub fn CGEventTapCreate(
        tap: u32,
        place: u32,
        options: u32,
        events_of_interest: u64,
        callback: CGEventTapCallBack,
        user_info: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;

    pub fn CGEventTapEnable(tap: *mut std::ffi::c_void, enable: bool);
    pub fn CGEventTapIsEnabled(tap: *mut std::ffi::c_void) -> bool;
    pub fn CGEventGetTimestamp(event: *mut std::ffi::c_void) -> u64;
    pub fn CGEventGetIntegerValueField(event: *mut std::ffi::c_void, field: u32) -> i64;
    pub fn CGEventGetLocation(event: *mut std::ffi::c_void) -> CGPoint;
    /// SAFETY: `unicode_string` must point to a buffer of at least
    /// `max_string_length` u16 elements. The caller MUST clamp
    /// `*actual_string_length` to `max_string_length` before using it
    /// as a slice index, since the kernel may report a longer composed
    /// string than the buffer can hold.
    pub fn CGEventKeyboardGetUnicodeString(
        event: *mut std::ffi::c_void,
        max_string_length: libc::c_ulong,
        actual_string_length: *mut libc::c_ulong,
        unicode_string: *mut u16,
    );
}

extern "C" {
    pub fn CFMachPortCreateRunLoopSource(
        allocator: CFAllocatorRef,
        port: *mut std::ffi::c_void,
        order: CFIndex,
    ) -> *mut std::ffi::c_void;

    pub fn CFRunLoopAddSource(
        rl: *mut std::ffi::c_void,
        source: *mut std::ffi::c_void,
        mode: CFStringRef,
    );

    pub fn CFRunLoopRun();

    pub static kCFRunLoopCommonModes: CFStringRef;
}

/// Callback type for CGEventTap user callbacks.
pub type TapCallback = Box<dyn FnMut(*mut std::ffi::c_void, u32) + Send>;

/// C trampoline for CGEventTap callbacks.
///
/// SAFETY: `user_info` must be a valid `*mut TapCallback` that outlives the event tap.
/// The caller must ensure the `TapCallback` is not dropped until after the event tap
/// is invalidated (via `CGEventTapEnable(tap, false)`) and the run loop thread has
/// been joined, so that no further callbacks can fire against freed memory.
pub unsafe extern "C" fn event_tap_trampoline(
    _proxy: *mut std::ffi::c_void,
    event_type: u32,
    event: *mut std::ffi::c_void,
    user_info: *mut std::ffi::c_void,
) -> *mut std::ffi::c_void {
    if !user_info.is_null() && !event.is_null() {
        // catch_unwind prevents panics from unwinding through the extern "C"
        // boundary, which is undefined behavior.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let callback = &mut *(user_info as *mut TapCallback);
            callback(event, event_type);
        }));
        if result.is_err() {
            log::error!("panic caught in CGEventTap callback; returning event unchanged");
        }
    }
    event
}
