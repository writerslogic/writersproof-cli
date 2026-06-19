// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared memory locking utilities.

/// Lock the given memory range into physical memory to prevent it from being swapped.
pub fn mlock(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let addr = ptr as usize;
        let aligned_addr = addr & !(page_size - 1);
        let aligned_len = len + (addr - aligned_addr);
        let result = libc::mlock(aligned_addr as *const _, aligned_len);
        if result != 0 {
            log::warn!("mlock failed: {}", std::io::Error::last_os_error());
        }
    }
    #[cfg(not(unix))]
    let _ = (ptr, len);
}

/// Unlock a previously locked memory range.
pub fn munlock(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let addr = ptr as usize;
        let aligned_addr = addr & !(page_size - 1);
        let aligned_len = len + (addr - aligned_addr);
        let _ = libc::munlock(aligned_addr as *const _, aligned_len);
    }
    #[cfg(not(unix))]
    let _ = (ptr, len);
}
