// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use sha2::{Digest, Sha256};
use std::time::Instant;

/// Captured ambient entropy snapshot with virtualization detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbientEntropy {
    /// SHA-256 hash of combined ambient entropy sources.
    pub hash: [u8; 32],
    /// Whether a hypervisor was detected.
    pub is_virtualized: bool,
    /// Whether Secure Boot is active.
    pub secure_boot_active: bool,
}

/// Collector for ambient system entropy using zero process forks.
///
/// Combines ASLR stack randomization, high-resolution timing jitter,
/// and platform-specific kernel entropy harvesting.
#[derive(Debug)]
pub struct AmbientSensing;

impl AmbientSensing {
    /// Capture ambient entropy without spawning any child processes.
    pub fn capture() -> AmbientEntropy {
        let mut hasher = Sha256::new();
        hasher.update(b"cpoe-ambient-v3-ultra");

        // ASLR stack pointer entropy (changes every run)
        let stack_marker: u8 = 0;
        let stack_address = (&stack_marker as *const u8 as usize).to_be_bytes();
        hasher.update(stack_address);

        // High-resolution timing jitter (start)
        let now = Instant::now();
        hasher.update(now.elapsed().as_nanos().to_be_bytes());

        // Platform-specific kernel entropy
        Self::harvest_os_entropy(&mut hasher);

        // High-resolution timing jitter (end)
        hasher.update(now.elapsed().as_nanos().to_be_bytes());

        let (is_virtualized, secure_boot_active) = Self::evaluate_environment();

        AmbientEntropy {
            hash: hasher.finalize().into(),
            is_virtualized,
            secure_boot_active,
        }
    }

    #[cfg(target_os = "linux")]
    fn harvest_os_entropy(hasher: &mut Sha256) {
        if let Ok(stat) = std::fs::read_to_string("/proc/stat") {
            hasher.update(stat.as_bytes());
        }
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            hasher.update(meminfo.as_bytes());
        }
    }

    #[cfg(target_os = "macos")]
    fn harvest_os_entropy(hasher: &mut Sha256) {
        // Forkless: use sysctl for high-velocity VM stats instead of spawning processes.
        // kern.boottime provides per-boot entropy; hw.memsize is stable but unique per config.
        let mut buf = [0u8; 16];
        let mut size = buf.len();
        let mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
        unsafe {
            if libc::sysctl(
                mib.as_ptr() as *mut _,
                2,
                buf.as_mut_ptr() as *mut _,
                &mut size,
                std::ptr::null_mut(),
                0,
            ) == 0
            {
                hasher.update(&buf[..size]);
            }
        }
        let mut memsize: u64 = 0;
        let mut memsize_len = std::mem::size_of::<u64>();
        let mib2 = [libc::CTL_HW, libc::HW_MEMSIZE];
        unsafe {
            if libc::sysctl(
                mib2.as_ptr() as *mut _,
                2,
                &mut memsize as *mut _ as *mut _,
                &mut memsize_len,
                std::ptr::null_mut(),
                0,
            ) == 0
            {
                hasher.update(memsize.to_be_bytes());
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn harvest_os_entropy(hasher: &mut Sha256) {
        extern "system" {
            fn QueryPerformanceCounter(lpPerformanceCount: *mut i64) -> i32;
        }
        let mut count: i64 = 0;
        unsafe {
            if QueryPerformanceCounter(&mut count) != 0 {
                hasher.update(count.to_be_bytes());
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    fn harvest_os_entropy(_hasher: &mut Sha256) {}

    fn evaluate_environment() -> (bool, bool) {
        let mut is_vm = false;
        #[allow(unused_assignments)]
        let mut secure_boot = false;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if raw_cpuid::CpuId::new().get_hypervisor_info().is_some() {
                is_vm = true;
            }
        }

        #[cfg(target_os = "linux")]
        {
            if !is_vm {
                if let Ok(vendor) = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
                    let v = vendor.to_lowercase();
                    is_vm = v.contains("qemu") || v.contains("amazon ec2") || v.contains("vmware");
                }
            }
            if let Ok(bytes) = std::fs::read(
                "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            ) {
                secure_boot = bytes.get(4) == Some(&1);
            }
        }

        #[cfg(target_os = "macos")]
        {
            let mut buffer = [0u8; 128];
            let mut size = buffer.len();
            let mib = [libc::CTL_HW, libc::HW_MODEL];
            unsafe {
                if libc::sysctl(
                    mib.as_ptr() as *mut _,
                    2,
                    buffer.as_mut_ptr() as *mut _,
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                ) == 0
                {
                    let model = String::from_utf8_lossy(&buffer[..size]).to_lowercase();
                    if model.contains("virtual") || model.contains("vmware") {
                        is_vm = true;
                    }
                }
            }
            secure_boot = cfg!(target_arch = "aarch64");
        }

        (is_vm, secure_boot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ambient_entropy_nonzero() {
        let e = AmbientSensing::capture();
        assert_ne!(e.hash, [0u8; 32]);
    }

    #[test]
    fn test_entropy_avalanche() {
        let e1 = AmbientSensing::capture();
        let e2 = AmbientSensing::capture();
        assert_ne!(
            e1.hash, e2.hash,
            "Sequential captures should differ due to timing jitter"
        );
    }
}
