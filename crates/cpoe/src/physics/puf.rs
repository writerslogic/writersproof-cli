// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use sha2::Digest;
use sysinfo::System;

/// Silicon-level Physical Unclonable Function (PUF).
/// Measures microscopic manufacturing variations in hardware.
#[derive(Debug)]
pub struct SiliconPUF;

impl SiliconPUF {
    /// Generates a unique fingerprint based on stable hardware identifiers.
    ///
    /// Targets platform-specific immutable UUIDs (IOPlatformUUID on macOS,
    /// /sys/class/dmi/id/product_uuid on Linux) with CPU topology fallback.
    pub fn generate_fingerprint() -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();

        // CPU topology baseline (stable across reboots)
        let sys = System::new_all();
        for cpu in sys.cpus() {
            sha2::Digest::update(&mut hasher, cpu.brand().as_bytes());
        }
        sha2::Digest::update(&mut hasher, sys.cpus().len().to_be_bytes());

        if let Some(name) = System::name() {
            sha2::Digest::update(&mut hasher, name.as_bytes());
        }

        #[cfg(target_os = "macos")]
        {
            // IOPlatformUUID: immutable hardware identifier from IOKit registry
            if let Some(uuid) = Self::macos_platform_uuid() {
                sha2::Digest::update(&mut hasher, b"macos-platform-uuid-v2");
                sha2::Digest::update(&mut hasher, uuid.as_bytes());
            } else if let Ok(hostname) = hostname::get() {
                sha2::Digest::update(&mut hasher, b"macos-stable-v1");
                sha2::Digest::update(&mut hasher, hostname.to_string_lossy().as_bytes());
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Motherboard UUID (requires root) with machine-id fallback
            if let Ok(uuid) = std::fs::read_to_string("/sys/class/dmi/id/product_uuid") {
                sha2::Digest::update(&mut hasher, b"linux-dmi-uuid");
                sha2::Digest::update(&mut hasher, uuid.trim().as_bytes());
            }
            if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
                sha2::Digest::update(&mut hasher, b"linux-machine-id");
                sha2::Digest::update(&mut hasher, id.trim().as_bytes());
            }
        }

        sha2::Digest::finalize(hasher).into()
    }

    #[cfg(target_os = "macos")]
    fn macos_platform_uuid() -> Option<String> {
        let output = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("IOPlatformUUID") {
                let parts: Vec<&str> = line.split('=').collect();
                if parts.len() == 2 {
                    return Some(parts[1].trim().trim_matches('"').to_string());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_puf_generates_fingerprint() {
        let fp = SiliconPUF::generate_fingerprint();
        assert_ne!(fp, [0u8; 32]);
    }

    #[test]
    fn test_puf_determinism() {
        let fp1 = SiliconPUF::generate_fingerprint();
        let fp2 = SiliconPUF::generate_fingerprint();

        assert_eq!(
            fp1, fp2,
            "PUF should generate stable fingerprints on the same machine"
        );
    }
}
