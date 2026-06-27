// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use std::sync::atomic::{AtomicBool, Ordering};

static HARDENED: AtomicBool = AtomicBool::new(false);

pub fn harden_process() {
    if HARDENED.swap(true, Ordering::SeqCst) {
    }
    #[cfg(target_os = "macos")]
    // SAFETY: ptrace(PT_DENY_ATTACH=31) is a well-defined macOS syscall that
    // prevents debugger attachment. All arguments are constants; no memory is
    // accessed. The return value is intentionally ignored (fails if already denied).
    unsafe {
        libc::ptrace(31, 0, std::ptr::null_mut(), 0);
    }
}

pub fn is_debugger_present() -> bool {
    #[cfg(target_os = "macos")]
    // SAFETY: sysctl(KERN_PROC_PID) writes a kinfo_proc struct into `buf`.
    // On macOS arm64/x86_64, kinfo_proc is <=648 bytes and p_flag is at byte
    // offset 16 within kp_proc (verified against XNU headers). We check the
    // return value and only read p_flag on success. The buffer is stack-local.
    unsafe {
        use libc::{c_int, sysctl, CTL_KERN, KERN_PROC, KERN_PROC_PID};
        let mut mib: [c_int; 4] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, libc::getpid()];
        let mut buf = [0u8; 648];
        let mut size = buf.len();
        if sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr() as *mut _,
            &mut size,
            std::ptr::null_mut(),
            0,
        ) == 0
        {
            // p_flag is at offset 16 in extern_proc (kp_proc), which starts at offset 0
            let p_flag = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
            return (p_flag & 0x00000800) != 0; // P_TRACED
        }
        false
    }
    #[cfg(target_os = "windows")]
    // SAFETY: IsDebuggerPresent is a stable Windows API with no parameters
    // and no side effects. The FFI declaration matches the Win32 signature.
    unsafe {
        extern "system" {
            fn IsDebuggerPresent() -> i32;
        }
        IsDebuggerPresent() != 0
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    false
}
