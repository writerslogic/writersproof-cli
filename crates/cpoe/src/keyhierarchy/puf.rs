// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::Utc;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::physics::puf::SiliconPUF;

use super::error::KeyHierarchyError;
use super::types::PufProvider;

const SOFTWARE_PUF_SEED_NAME: &str = "puf_seed";

/// Software-based PUF using a persisted random seed for key derivation.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SoftwarePUF {
    device_id: String,
    #[zeroize(skip)]
    seed_path: PathBuf,
    seed: Vec<u8>,
}

impl SoftwarePUF {
    /// Create a new software PUF using the default data directory.
    pub fn new() -> Result<Self, KeyHierarchyError> {
        let seed_path = writersproof_dir().join(SOFTWARE_PUF_SEED_NAME);
        Self::new_with_path(seed_path)
    }

    /// Create a new software PUF with a custom seed file path.
    pub fn new_with_path(seed_path: impl AsRef<Path>) -> Result<Self, KeyHierarchyError> {
        let seed_path = seed_path.as_ref().to_path_buf();
        let mut puf = SoftwarePUF {
            device_id: String::new(),
            seed: Vec::new(),
            seed_path,
        };
        puf.load_or_create_seed()?;
        Ok(puf)
    }

    /// Create a software PUF from an existing 32-byte seed and device ID.
    pub fn new_from_seed(
        device_id: impl Into<String>,
        seed: Vec<u8>,
    ) -> Result<Self, KeyHierarchyError> {
        if seed.len() != 32 {
            return Err(KeyHierarchyError::Crypto(format!(
                "PUF seed must be 32 bytes, got {}",
                seed.len()
            )));
        }
        Ok(SoftwarePUF {
            device_id: device_id.into(),
            seed,
            seed_path: PathBuf::new(),
        })
    }

    fn load_or_create_seed(&mut self) -> Result<(), KeyHierarchyError> {
        if let Ok(Some(seed)) = crate::identity::SecureStorage::load_seed() {
            let mut seed = seed;
            if seed.len() == 32 {
                self.seed = std::mem::take(&mut *seed);
                self.device_id = self.compute_device_id();
                return Ok(());
            }
        }

        if let Ok(data) = fs::read(&self.seed_path) {
            let mut data = Zeroizing::new(data);
            if data.len() == 32 {
                if let Err(e) = crate::identity::SecureStorage::save_seed(&data) {
                    log::warn!("Failed to migrate PUF seed to secure storage: {e}");
                } else {
                    // Only delete the file if the keychain is actually functional.
                    // When CPOE_NO_KEYCHAIN=1, save returns Ok but doesn't persist,
                    // so the file must be kept as the only copy of the seed.
                    if !crate::identity::SecureStorage::is_keychain_disabled() {
                        let _ = fs::remove_file(&self.seed_path);
                    }
                }
                self.seed = std::mem::take(&mut *data);
                self.device_id = self.compute_device_id();
                return Ok(());
            }
        }

        let seed = self.generate_seed()?;

        // Always write to file to ensure persistence when keychain is
        // disabled or unavailable. SecureStorage is an additional copy.
        let parent = self.seed_path.parent().unwrap_or(std::path::Path::new("."));
        fs::create_dir_all(parent)?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        std::io::Write::write_all(&mut tmp, &seed)?;
        tmp.as_file().sync_all()?;
        crate::crypto::restrict_permissions(tmp.path(), 0o600)?;
        tmp.persist(&self.seed_path).map_err(|e| e.error)?;

        if let Err(e) = crate::identity::SecureStorage::save_seed(&seed) {
            log::warn!("Secure storage unavailable ({e}), using file-based storage");
        }

        self.seed = seed;
        self.device_id = self.compute_device_id();
        Ok(())
    }

    fn generate_seed(&self) -> Result<Vec<u8>, KeyHierarchyError> {
        let mut hasher = Sha256::new();

        let mut random_bytes = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut *random_bytes);
        hasher.update(*random_bytes);
        hasher.update(b"cpoe-software-puf-v1");

        // NOTE: hostname and home_dir are user-controlled and provide weak
        // device binding. The hardware UUID (IOPlatformUUID on macOS,
        // /etc/machine-id on Linux) is a stronger signal but still not
        // tamper-proof without TPM attestation. The 32 random bytes above
        // are the primary entropy source; these inputs add device affinity.
        if let Ok(hostname) = hostname::get() {
            hasher.update(hostname.to_string_lossy().as_bytes());
        }

        if let Some(home) = dirs::home_dir() {
            hasher.update(home.to_string_lossy().as_bytes());
        }

        if let Ok(exe) = std::env::current_exe() {
            hasher.update(exe.to_string_lossy().as_bytes());
        }

        // Mix in platform-level machine identifier when available.
        if let Some(machine_id) = Self::read_machine_id() {
            hasher.update(machine_id.as_bytes());
        }

        hasher.update(std::env::consts::OS.as_bytes());
        hasher.update(std::env::consts::ARCH.as_bytes());
        hasher.update(Utc::now().to_rfc3339().as_bytes());

        Ok(hasher.finalize().to_vec())
    }

    fn read_machine_id() -> Option<String> {
        #[cfg(target_os = "macos")]
        {
            let output = std::process::Command::new("/usr/sbin/sysctl")
                .args(["-n", "kern.uuid"])
                .output()
                .ok()?;
            if output.status.success() {
                let id = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                if !id.is_empty() {
                    return Some(id);
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok(id) = fs::read_to_string("/etc/machine-id") {
                let id = id.trim().to_owned();
                if !id.is_empty() {
                    return Some(id);
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("wmic")
                .args(["csproduct", "get", "UUID"])
                .output()
                .ok()?;
            if output.status.success() {
                for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
                    let id = line.trim().to_owned();
                    if !id.is_empty() {
                        return Some(id);
                    }
                }
            }
        }
        None
    }

    fn compute_device_id(&self) -> String {
        let digest = Sha256::digest(&self.seed);
        format!("swpuf-{}", hex::encode(&digest[0..4]))
    }

    /// Return a zeroizing clone of the raw seed bytes.
    pub fn seed(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.seed.clone())
    }

    /// Return the filesystem path where the seed is stored.
    pub fn seed_path(&self) -> PathBuf {
        self.seed_path.clone()
    }

    /// Return the seed as a fixed-size 32-byte zeroizing array.
    pub fn get_seed(&self) -> Zeroizing<[u8; 32]> {
        let mut arr = Zeroizing::new([0u8; 32]);
        if self.seed.len() == 32 {
            arr.copy_from_slice(&self.seed);
        }
        arr
    }

    /// Encode the seed as a BIP-39 mnemonic phrase for backup/recovery, zeroized on drop.
    pub fn get_mnemonic(&self) -> Result<Zeroizing<String>, KeyHierarchyError> {
        crate::identity::mnemonic::MnemonicHandler::entropy_to_phrase(&self.seed)
            .map_err(|e| KeyHierarchyError::Crypto(e.to_string()))
    }

    /// Recover a software PUF from a BIP-39 mnemonic phrase.
    pub fn recover_from_mnemonic(
        seed_path: &Path,
        phrase: &str,
    ) -> Result<Self, KeyHierarchyError> {
        let entropy = crate::identity::mnemonic::MnemonicHandler::phrase_to_entropy(phrase)
            .map_err(|e| KeyHierarchyError::Crypto(e.to_string()))?;

        if entropy.len() != 16 && entropy.len() != 32 {
            return Err(KeyHierarchyError::Crypto("Invalid entropy length".into()));
        }

        let seed = if entropy.len() == 32 {
            entropy.to_vec()
        } else {
            Sha256::digest(&entropy).to_vec()
        };

        // Always write to the file to ensure recovery survives even when
        // SecureStorage silently no-ops (e.g., CPOE_NO_KEYCHAIN=1).
        let parent = seed_path.parent().unwrap_or(std::path::Path::new("."));
        fs::create_dir_all(parent)?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        std::io::Write::write_all(&mut tmp, &seed)?;
        tmp.as_file().sync_all()?;
        crate::crypto::restrict_permissions(tmp.path(), 0o600)?;
        tmp.persist(seed_path).map_err(|e| e.error)?;

        // Also persist to SecureStorage if available (additional copy).
        if let Err(e) = crate::identity::SecureStorage::save_seed(&seed) {
            log::warn!("Secure storage unavailable ({e}), using file-based storage");
        }

        Self::new_with_path(seed_path)
    }
}

impl PufProvider for SoftwarePUF {
    fn get_response(&self, challenge: &[u8]) -> Result<Vec<u8>, KeyHierarchyError> {
        if self.seed.is_empty() {
            return Err(KeyHierarchyError::SoftwarePUFInit);
        }

        let hk = Hkdf::<Sha256>::new(Some(challenge), &self.seed);
        let mut response = [0u8; 32];
        hk.expand(b"puf-response-v1", &mut response)
            .map_err(|_| KeyHierarchyError::Crypto("HKDF expand failed".to_string()))?;
        Ok(response.to_vec())
    }

    fn device_id(&self) -> String {
        self.device_id.clone()
    }
}

/// Returns the preferred PUF provider: hardware-based (SiliconPUF) when available,
/// falling back to software PUF (random seed persisted to disk).
///
/// Hardware PUF derives identity from stable hardware identifiers (CPU, system info),
/// providing deterministic machine identity without persistent state.
pub fn get_or_create_puf() -> Result<Box<dyn PufProvider>, KeyHierarchyError> {
    Ok(Box::new(HardwarePUF::new()?))
}

fn writersproof_dir() -> PathBuf {
    crate::utils::get_legacy_data_dir()
        .unwrap_or_else(|| PathBuf::from(".writersproof"))
}

struct HardwarePUF {
    device_id: String,
    seed: crate::crypto::ProtectedKey<32>,
}

impl HardwarePUF {
    fn new() -> Result<Self, KeyHierarchyError> {
        let seed = SiliconPUF::generate_fingerprint();
        let digest = Sha256::digest(seed);
        let device_id = format!("puf-{}", hex::encode(&digest[0..4]));
        Ok(Self {
            device_id,
            seed: crate::crypto::ProtectedKey::new(seed),
        })
    }
}

impl PufProvider for HardwarePUF {
    fn get_response(&self, challenge: &[u8]) -> Result<Vec<u8>, KeyHierarchyError> {
        let hk = Hkdf::<Sha256>::new(Some(challenge), self.seed.as_bytes());
        let mut response = [0u8; 32];
        hk.expand(b"puf-response-v1", &mut response)
            .map_err(|_| KeyHierarchyError::Crypto("HKDF expand failed".to_string()))?;
        Ok(response.to_vec())
    }

    fn device_id(&self) -> String {
        self.device_id.clone()
    }
}
