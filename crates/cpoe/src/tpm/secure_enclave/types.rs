// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::Utc;
use security_framework_sys::base::SecKeyRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

pub(super) const SE_KEY_TAG: &str = "com.writerslogic.secureenclave.signing";
pub(super) const SE_ATTESTATION_KEY_TAG: &str = "com.writerslogic.secureenclave.attestation";

/// Self-attestation proof binding a public key to this device.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAttestation {
    pub version: u32,
    /// X9.62 format.
    pub public_key: Vec<u8>,
    pub device_id: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub attestation_proof: Vec<u8>,
    pub signature: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Metadata about a Secure Enclave key.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureEnclaveKeyInfo {
    pub tag: String,
    /// X9.62 format.
    pub public_key: Vec<u8>,
    pub created_at: Option<chrono::DateTime<Utc>>,
    pub hardware_backed: bool,
    pub key_size: u32,
}

pub(super) struct SecureEnclaveState {
    pub(super) key_ref: SecKeyRef,
    pub(super) attestation_key_ref: Option<SecKeyRef>,
    pub(super) device_id: String,
    pub(super) public_key: Vec<u8>,
    pub(super) attestation_public_key: Option<Vec<u8>>,
    pub(super) counter: u64,
    pub(super) counter_file: PathBuf,
    pub(super) start_time: SystemTime,
    pub(super) hardware_info: HardwareInfo,
}

#[derive(Debug, Clone, Default)]
pub(super) struct HardwareInfo {
    pub(super) uuid: Option<String>,
    pub(super) model: Option<String>,
    pub(super) se_available: bool,
    pub(super) os_version: Option<String>,
}

/// macOS Secure Enclave TPM provider (ECDSA P-256).
pub struct SecureEnclaveProvider {
    pub(super) state: Mutex<SecureEnclaveState>,
    pub(super) cached_device_id: String,
    pub(super) cached_public_key: Vec<u8>,
}

// SAFETY: SecKeyRef (Security.framework key objects) are thread-safe for signing
// operations per Apple documentation. The Mutex<SecureEnclaveState> provides
// exclusive access to mutable state.
unsafe impl Send for SecureEnclaveProvider {}
unsafe impl Sync for SecureEnclaveProvider {}

impl Drop for SecureEnclaveState {
    fn drop(&mut self) {
        // Release the primary signing key reference.
        if !self.key_ref.is_null() {
            unsafe {
                core_foundation_sys::base::CFRelease(self.key_ref as *mut std::ffi::c_void);
            }
        }
        // Release the attestation key reference, if present.
        if let Some(att_ref) = self.attestation_key_ref {
            if !att_ref.is_null() {
                unsafe {
                    core_foundation_sys::base::CFRelease(att_ref as *mut std::ffi::c_void);
                }
            }
        }
    }
}
