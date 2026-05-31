// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use base64::Engine;

use crate::ffi::helpers::{detect_attestation_tier_info, get_data_dir};
use crate::ffi::types::{
    catch_ffi_panic, FfiAttestationInfo, FfiAttestationResponse, FfiDeviceKey, FfiResult,
};
use authorproof_protocol::rfc::wire_types::AttestationTier;

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_attestation_info() -> FfiAttestationInfo {
    catch_ffi_panic!(FfiAttestationInfo {
        tier: 0,
        tier_label: String::new(),
        provider_type: String::new(),
        hardware_bound: false,
        supports_sealing: false,
        has_monotonic_counter: false,
        has_secure_clock: false,
        device_id: String::new(),
    }, {
    log::debug!("ffi_get_attestation_info");
    let (_, tier_num, tier_label) = detect_attestation_tier_info();

    let provider = crate::tpm::detect_provider();
    let caps = provider.capabilities();
    FfiAttestationInfo {
        tier: tier_num,
        tier_label,
        provider_type: provider.device_id(),
        hardware_bound: caps.hardware_backed && caps.supports_sealing,
        supports_sealing: caps.supports_sealing,
        has_monotonic_counter: caps.monotonic_counter,
        has_secure_clock: caps.secure_clock,
        device_id: provider.device_id(),
    }
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_reseal_identity() -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    log::debug!("ffi_reseal_identity");
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiResult::err("Could not determine data directory".to_string());
        }
    };

    let store = crate::sealed_identity::SealedIdentityStore::auto_detect(&data_dir);

    if !store.is_bound() {
        return FfiResult::err("No sealed identity found on this device".to_string());
    }

    let puf_seed_path = data_dir.join("puf_seed");
    let puf = match crate::keyhierarchy::SoftwarePUF::new_with_path(&puf_seed_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult::err(format!("Failed to initialize PUF: {}", e));
        }
    };

    match store.reseal(&puf) {
        Ok(()) => FfiResult::ok("Identity re-sealed under current platform state".to_string()),
        Err(e) => FfiResult::err(format!("Reseal failed: {}", e)),
    }
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_is_hardware_bound() -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_is_hardware_bound");
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => return false,
    };

    let store = crate::sealed_identity::SealedIdentityStore::auto_detect(&data_dir);
    if !store.is_bound() {
        return false;
    }

    store.attestation_tier() == AttestationTier::HardwareBound
        || store.attestation_tier() == AttestationTier::HardwareHardened
    })
}

/// Sign a server-issued attestation challenge with the device key.
///
/// Returns both the raw signature and a COSE_Sign1 envelope per
/// draft-condrey-rats-pop §4.3 (device attestation uses COSE_Sign1 with the
/// platform attestation object as payload).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sign_attestation_challenge(challenge_b64: String) -> FfiAttestationResponse {
    catch_ffi_panic!(FfiAttestationResponse {
        success: false,
        signature_b64: String::new(),
        public_key_b64: String::new(),
        cose_sign1_b64: String::new(),
        device_id: String::new(),
        model: String::new(),
        os_version: String::new(),
        error_message: Some("engine internal error".to_string()),
    }, {
    log::debug!("ffi_sign_attestation_challenge: challenge_b64_len={}", challenge_b64.len());
    // Reject oversized challenges before decoding (challenge should be ~32–64 bytes,
    // base64-encoded ≈ 44–88 chars; cap at 4KB to prevent memory DoS).
    const MAX_CHALLENGE_B64_LEN: usize = 4096;
    if challenge_b64.len() > MAX_CHALLENGE_B64_LEN {
        return FfiAttestationResponse {
            success: false,
            signature_b64: String::new(),
            public_key_b64: String::new(),
            cose_sign1_b64: String::new(),
            device_id: String::new(),
            model: String::new(),
            os_version: String::new(),
            error_message: Some(format!(
                "Challenge too large: {} bytes (max {})",
                challenge_b64.len(),
                MAX_CHALLENGE_B64_LEN
            )),
        };
    }
    let challenge = match base64::engine::general_purpose::STANDARD.decode(&challenge_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return FfiAttestationResponse {
                success: false,
                signature_b64: String::new(),
                public_key_b64: String::new(),
                cose_sign1_b64: String::new(),
                device_id: String::new(),
                model: String::new(),
                os_version: String::new(),
                error_message: Some(format!("Invalid base64 challenge: {e}")),
            };
        }
    };

    let provider = crate::tpm::detect_provider();

    let signature = match provider.sign(&challenge) {
        Ok(sig) => sig,
        Err(e) => {
            return FfiAttestationResponse {
                success: false,
                signature_b64: String::new(),
                public_key_b64: String::new(),
                cose_sign1_b64: String::new(),
                device_id: provider.device_id(),
                model: get_model(),
                os_version: get_os_version(),
                error_message: Some(format!("Signing failed: {e}")),
            };
        }
    };

    let public_key = provider.public_key();
    let b64 = &base64::engine::general_purpose::STANDARD;

    // Build COSE_Sign1 envelope wrapping the challenge as payload.
    let tpm_signer = crate::tpm::TpmSigner::new(provider.clone());
    let cose_sign1_b64 =
        match authorproof_protocol::crypto::sign_evidence_cose(&challenge, &tpm_signer) {
            Ok(cose_bytes) => b64.encode(&cose_bytes),
            Err(e) => {
                return FfiAttestationResponse {
                    success: false,
                    signature_b64: b64.encode(&signature),
                    public_key_b64: b64.encode(&public_key),
                    cose_sign1_b64: String::new(),
                    device_id: provider.device_id(),
                    model: get_model(),
                    os_version: get_os_version(),
                    error_message: Some(format!("COSE_Sign1 envelope creation failed: {e}")),
                };
            }
        };

    FfiAttestationResponse {
        success: true,
        signature_b64: b64.encode(&signature),
        public_key_b64: b64.encode(&public_key),
        cose_sign1_b64,
        device_id: provider.device_id(),
        model: get_model(),
        os_version: get_os_version(),
        error_message: None,
    }
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_device_public_key() -> FfiDeviceKey {
    catch_ffi_panic!(FfiDeviceKey {
        public_key_b64: String::new(),
        device_id: String::new(),
        hardware_bound: false,
    }, {
    log::debug!("ffi_get_device_public_key");
    let provider = crate::tpm::detect_provider();
    let caps = provider.capabilities();
    let public_key = provider.public_key();

    FfiDeviceKey {
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(&public_key),
        device_id: provider.device_id(),
        hardware_bound: caps.hardware_backed && caps.supports_sealing,
    }
    })
}

/// Run a shell command in a background thread with a 2-second timeout.
/// Returns `None` if the command fails or times out.
///
/// Results are cached by callers via `OnceLock`, so this only blocks once per
/// process lifetime. Safe to call from FFI init paths; the spawned thread
/// prevents the shell command from blocking the calling thread beyond the
/// timeout.
fn run_command_with_timeout(cmd: &'static str, args: &'static [&'static str]) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    if let Err(e) = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
        let result = std::process::Command::new(cmd)
            .args(args)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string());
        if tx.send(result).is_err() {
            log::debug!("attestation channel send failed (receiver timed out)");
        }
    }) {
        log::warn!("attestation thread spawn failed: {e}");
        return None;
    }
    rx.recv_timeout(std::time::Duration::from_secs(2))
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
}

/// Populate OnceLock caches for device model and OS version.
/// Called from a background thread during ffi_init to avoid priority inversion
/// when ffi_sign_attestation_challenge runs on a high-QoS thread.
pub(super) fn prewarm_device_info() {
    let _ = get_model();
    let _ = get_os_version();
}

fn get_model() -> String {
    static CACHED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CACHED
        .get_or_init(|| {
            #[cfg(target_os = "macos")]
            {
                run_command_with_timeout("/usr/sbin/sysctl", &["-n", "hw.model"])
                    .unwrap_or_else(|| "Mac".to_string())
            }
            #[cfg(target_os = "windows")]
            {
                read_registry_string(
                    "HARDWARE\\DESCRIPTION\\System\\BIOS",
                    "SystemProductName",
                )
                .unwrap_or_else(|| "Windows PC".to_string())
            }
            #[cfg(target_os = "linux")]
            {
                "Linux PC".to_string()
            }
        })
        .clone()
}

fn get_os_version() -> String {
    static CACHED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CACHED
        .get_or_init(|| {
            #[cfg(target_os = "macos")]
            {
                run_command_with_timeout("/usr/bin/sw_vers", &["-productVersion"])
                    .map(|v| format!("macOS {v}"))
                    .unwrap_or_else(|| "macOS".to_string())
            }
            #[cfg(target_os = "windows")]
            {
                let product = read_registry_string(
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                    "ProductName",
                );
                let build = read_registry_string(
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                    "CurrentBuildNumber",
                );
                match (product, build) {
                    (Some(p), Some(b)) => format!("{p} (Build {b})"),
                    (Some(p), None) => p,
                    _ => "Windows".to_string(),
                }
            }
            #[cfg(target_os = "linux")]
            {
                "Linux".to_string()
            }
        })
        .clone()
}

#[cfg(target_os = "windows")]
fn read_registry_string(subkey: &str, value_name: &str) -> Option<String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_SZ, REG_VALUE_TYPE,
    };

    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let value_wide: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut hkey = HKEY::default();
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(subkey_wide.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
        .ok()?;

        let mut buf = [0u16; 512];
        let mut size = (buf.len() * 2) as u32;
        let mut kind = REG_VALUE_TYPE::default();
        let result = RegQueryValueExW(
            hkey,
            windows::core::PCWSTR(value_wide.as_ptr()),
            None,
            Some(&mut kind),
            Some(buf.as_mut_ptr() as *mut u8),
            Some(&mut size),
        );
        let _ = RegCloseKey(hkey);
        result.ok()?;
        if kind != REG_SZ || size < 2 {
            return None;
        }
        let char_count = (size as usize / 2).saturating_sub(1);
        let s = String::from_utf16_lossy(&buf[..char_count]);
        if s.is_empty() { None } else { Some(s) }
    }
}
