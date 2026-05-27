// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::types::HardwareInfo;
use crate::tpm::TpmError;
use std::path::PathBuf;

pub(super) fn collect_hardware_info() -> HardwareInfo {
    HardwareInfo {
        uuid: hardware_uuid(),
        model: get_model_identifier(),
        os_version: get_os_version(),
        ..HardwareInfo::default()
    }
}

/// sysctl is safer than IOKit for model detection.
fn get_model_identifier() -> Option<String> {
    use std::process::Command;

    let output = Command::new("/usr/sbin/sysctl")
        .arg("-n")
        .arg("hw.model")
        .output()
        .ok()?;

    if output.status.success() {
        let model = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !model.is_empty() {
            return Some(model);
        }
    }

    None
}

fn get_os_version() -> Option<String> {
    use std::process::Command;

    let output = Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .ok()?;

    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !version.is_empty() {
            return Some(version);
        }
    }

    None
}

pub(super) fn is_secure_enclave_available() -> bool {
    if std::env::var("CPOE_DISABLE_SECURE_ENCLAVE").is_ok() {
        log::info!("Secure Enclave disabled via environment variable");
        return false;
    }

    use std::process::Command;

    let output = match Command::new("/usr/sbin/sysctl")
        .arg("-n")
        .arg("machdep.cpu.brand_string")
        .output()
    {
        Ok(out) => out,
        Err(_) => return false,
    };

    if !output.status.success() {
        return false;
    }

    let cpu_brand = String::from_utf8_lossy(&output.stdout);
    let has_apple_silicon = cpu_brand.contains("Apple");

    if !has_apple_silicon {
        if std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok() {
            log::info!("Skipping T2 detection in CI environment");
            return false;
        }

        let t2_check = Command::new("/usr/sbin/ioreg")
            .args(["-l", "-d1", "-c", "AppleT2Controller"])
            .output();

        if let Ok(out) = t2_check {
            if out.status.success() {
                let ioreg_output = String::from_utf8_lossy(&out.stdout);
                if !ioreg_output.contains("AppleT2Controller") {
                    return false;
                }
            }
        } else {
            return false;
        }
    }

    let security_check = Command::new("/usr/bin/security")
        .args(["list-keychains"])
        .output();

    match security_check {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

pub(super) fn hardware_uuid() -> Option<String> {
    use std::process::Command;

    let output = Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("IOPlatformUUID") {
                if let Some(start) = line.rfind('"') {
                    let before_last = &line[..start];
                    if let Some(uuid_start) = before_last.rfind('"') {
                        let uuid = &before_last[uuid_start + 1..];
                        if !uuid.is_empty() && uuid.contains('-') {
                            return Some(uuid.to_string());
                        }
                    }
                }
            }
        }
    }

    let output = Command::new("/usr/sbin/sysctl")
        .arg("-n")
        .arg("kern.uuid")
        .output()
        .ok()?;

    if output.status.success() {
        let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !uuid.is_empty() {
            return Some(uuid);
        }
    }

    None
}

pub(super) fn writersproof_dir() -> Result<PathBuf, TpmError> {
    crate::utils::get_legacy_data_dir()
        .ok_or_else(|| TpmError::Configuration("cannot determine home directory".into()))
}
