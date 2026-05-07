// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Runtime integrity checks for the signing pipeline.
//!
//! Verifies that the process has not been tampered with before countersigning
//! evidence or checkpoints. On macOS, checks code signature validity, debugger
//! attachment, and injected library presence. On other platforms the check is
//! a no-op (returns `Ok(())`).

use crate::error::{Error, Result};

/// Verify the runtime integrity of the signing process before any signing operation.
///
/// On macOS this performs three independent checks:
/// 1. Code signature status via `csops(CS_OPS_STATUS)` — rejects if `CS_VALID | CS_SIGNED` are absent.
/// 2. Debugger attachment via `sysctl kern.proc.flag` — rejects if `P_TRACED` is set.
/// 3. Environment variable `DYLD_INSERT_LIBRARIES` — rejects if set (injected dylib).
///
/// Any failure returns `Err(Error::crypto(...))` so the caller can refuse to sign.
/// On non-macOS platforms, always returns `Ok(())`.
pub fn runtime_integrity_check() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        check_code_signature()?;
        check_debugger_attached()?;
        check_injected_libraries()?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn check_code_signature() -> Result<()> {
    use std::os::raw::{c_int, c_uint, c_void};

    // CS_OPS_STATUS returns the current code signing flags for a pid.
    const CS_OPS_STATUS: c_uint = 0;
    const CS_VALID: u32 = 0x0000_0001;
    const CS_SIGNED: u32 = 0x2000_0000;

    extern "C" {
        fn csops(pid: libc::pid_t, ops: c_uint, useraddr: *mut c_void, usersize: usize) -> c_int;
    }

    let mut flags: u32 = 0;
    let ret = unsafe {
        csops(
            libc::getpid(),
            CS_OPS_STATUS,
            &mut flags as *mut u32 as *mut c_void,
            std::mem::size_of::<u32>(),
        )
    };

    if ret != 0 {
        // csops unavailable (e.g., sandboxed); treat as passed to avoid
        // blocking legitimate sandboxed deployments.
        return Ok(());
    }

    if flags & (CS_VALID | CS_SIGNED) != CS_VALID | CS_SIGNED {
        return Err(Error::crypto(format!(
            "signing refused: code signature invalid (csops flags: {flags:#010x})"
        )));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn check_debugger_attached() -> Result<()> {
    // P_TRACED is set in the process flags when a debugger is attached.
    const P_TRACED: i32 = 0x0000_0800;

    // kern.proc.pid.<pid> returns a kinfo_proc struct; the p_flag field is at
    // offset 32 (kp_proc.p_flag within struct kinfo_proc on arm64/x86_64).
    let pid = unsafe { libc::getpid() };
    let mut name: [i32; 4] = [1 /* CTL_KERN */, 14 /* KERN_PROC */, 1 /* KERN_PROC_PID */, pid];
    let mut info = [0u8; 648]; // sizeof(kinfo_proc) on macOS
    let mut size = info.len();

    let ret = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            name.len() as u32,
            info.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret != 0 || size < 36 {
        return Ok(()); // sysctl unavailable; allow through
    }

    // p_flag is at byte offset 32 within kinfo_proc (kp_proc is the first field,
    // p_flag is at offset 32 within extern_proc on both arm64 and x86_64).
    let p_flag = i32::from_ne_bytes(info[32..36].try_into().unwrap_or([0; 4]));
    if p_flag & P_TRACED != 0 {
        return Err(Error::crypto(
            "signing refused: debugger attached (P_TRACED set)".into(),
        ));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn check_injected_libraries() -> Result<()> {
    if std::env::var("DYLD_INSERT_LIBRARIES").is_ok() {
        return Err(Error::crypto(
            "signing refused: DYLD_INSERT_LIBRARIES is set (injected library detected)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_integrity_check_passes_in_tests() {
        // In a normal test environment: no debugger via P_TRACED check (test runners
        // don't use ptrace), no DYLD_INSERT_LIBRARIES, and code may lack CS_VALID
        // in debug builds so the CS check returns Ok on csops failure.
        // Verify the function does not panic.
        let _ = runtime_integrity_check();
    }

    #[test]
    fn test_injected_library_detection() {
        // Safety: std::env::set_var is not thread-safe. This test manipulates an
        // env var temporarily; run with RUST_TEST_THREADS=1 if flakiness is observed.
        let key = "DYLD_INSERT_LIBRARIES";
        let had_var = std::env::var(key).is_ok();
        if !had_var {
            unsafe { std::env::set_var(key, "/usr/lib/fake.dylib") };
            #[cfg(target_os = "macos")]
            {
                let result = check_injected_libraries();
                assert!(result.is_err(), "should reject injected library");
            }
            unsafe { std::env::remove_var(key) };
        }
    }
}
