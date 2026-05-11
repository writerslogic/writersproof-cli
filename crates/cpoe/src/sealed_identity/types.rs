// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::keyhierarchy::KeyHierarchyError;
use crate::tpm::TpmError;

/// Errors from sealed identity operations (seal, unseal, anti-rollback).
#[derive(Debug, thiserror::Error)]
pub enum SealedIdentityError {
    /// No TPM or Secure Enclave provider detected.
    #[error("no TPM provider available")]
    NoProvider,
    #[error("sealing failed: {0}")]
    SealFailed(String),
    #[error("unsealing failed: {0}")]
    UnsealFailed(String),
    /// Monotonic counter regression detected (replay/rollback attack).
    #[error("rollback detected (counter {current} < last known {last_known})")]
    RollbackDetected { current: u64, last_known: u64 },
    #[error("reboot detected during session")]
    RebootDetected,
    /// Sealed blob failed integrity check or has invalid structure.
    #[error("blob corrupted")]
    BlobCorrupted,
    #[error("key hierarchy error: {0}")]
    KeyHierarchy(#[from] KeyHierarchyError),
    #[error("TPM error: {0}")]
    Tpm(#[from] TpmError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Persistent sealed identity blob stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SealedBlob {
    pub version: u32,
    pub provider_type: String,
    pub device_id: String,
    pub sealed_seed: Vec<u8>,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub sealed_at: DateTime<Utc>,
    pub counter_at_seal: Option<u64>,
    pub last_known_counter: Option<u64>,
    pub boot_count_at_seal: Option<u32>,
    pub restart_count_at_seal: Option<u32>,
    /// HMAC-SHA256 over all other fields, keyed from machine_salt.
    #[serde(default)]
    pub integrity_hmac: Option<Vec<u8>>,
}

impl Drop for SealedBlob {
    fn drop(&mut self) {
        self.sealed_seed.zeroize();
    }
}

pub const SEALED_BLOB_VERSION: u32 = 1;
pub const SEALED_BLOB_FILENAME: &str = "identity.sealed";
