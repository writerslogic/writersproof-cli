// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::error::{Result, SentinelError};
use crate::crypto::ObfuscatedString;
use crate::RwLockRecover;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

/// Shadow buffer for tracking unsaved document content.
/// Each buffer holds an ephemeral encryption key in memory; content is
/// encrypted with ChaCha20-Poly1305 before writing to disk.
#[derive(Debug, Clone)]
struct ShadowBuffer {
    id: String,
    app_name: String,
    window_title: ObfuscatedString,
    path: PathBuf,
    _created_at: SystemTime,
    updated_at: SystemTime,
    _size: i64,
    /// Ephemeral 256-bit key for encrypting shadow content at rest.
    /// Lives only in process memory; lost on process exit (shadow files become unreadable).
    ephemeral_key: Zeroizing<[u8; 32]>,
}

#[derive(Debug)]
/// Manages shadow buffers for unsaved documents
pub struct ShadowManager {
    base_dir: PathBuf,
    shadows: RwLock<HashMap<String, ShadowBuffer>>,
}

impl ShadowManager {
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;

        Ok(Self {
            base_dir,
            shadows: RwLock::new(HashMap::new()),
        })
    }

    pub fn create(&self, app_name: &str, window_title: &str) -> Result<String> {
        use rand::Rng;
        let mut rng = rand::rng();
        let id_bytes: [u8; 16] = rng.random();
        let id = hex::encode(id_bytes);

        let path = self.base_dir.join(format!("{}.shadow", id));
        File::create(&path)?;

        let mut key = Zeroizing::new([0u8; 32]);
        rng.fill(key.as_mut());

        let shadow = ShadowBuffer {
            id: id.clone(),
            app_name: app_name.to_string(),
            window_title: ObfuscatedString::new(window_title),
            path,
            _created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
            _size: 0,
            ephemeral_key: key,
        };

        self.shadows.write_recover().insert(id.clone(), shadow);

        Ok(id)
    }

    /// Write shadow content to the shadow directory on disk.
    ///
    /// Content is encrypted with ChaCha20-Poly1305 using an ephemeral per-buffer
    /// key held only in process memory. The key is zeroized on drop and never
    /// persisted, so shadow files become unreadable after process exit.
    pub fn update(&self, id: &str, content: &[u8]) -> Result<()> {
        let (path, key) = {
            let shadows = self.shadows.read_recover();
            let s = shadows
                .get(id)
                .ok_or_else(|| SentinelError::ShadowNotFound(id.to_string()))?;
            (s.path.clone(), s.ephemeral_key.clone())
        };

        // Nonce: first 12 bytes of SHA-256(shadow_id || update_timestamp).
        // Not reused across updates because the timestamp changes each time.
        let nonce_input = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(id.as_bytes());
            h.update(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .to_le_bytes(),
            );
            h.finalize()
        };
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_input[..12]);

        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*key));
        let ciphertext = cipher
            .encrypt(nonce, content)
            .map_err(|e| SentinelError::Serialization(format!("shadow encrypt: {e}")))?;

        // Write nonce (12 bytes) || ciphertext to disk.
        let mut blob = Vec::with_capacity(12 + ciphertext.len());
        blob.extend_from_slice(&nonce_input[..12]);
        blob.extend_from_slice(&ciphertext);
        fs::write(&path, &blob)?;

        let mut shadows = self.shadows.write_recover();
        if let Some(shadow) = shadows.get_mut(id) {
            shadow.updated_at = SystemTime::now();
            shadow._size = i64::try_from(content.len()).unwrap_or(i64::MAX);
        }

        Ok(())
    }

    pub fn get_path(&self, id: &str) -> Option<PathBuf> {
        self.shadows.read_recover().get(id).map(|s| s.path.clone())
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let path = self.shadows.write_recover().remove(id).map(|s| s.path);
        if let Some(path) = path {
            if let Err(e) = fs::remove_file(&path) {
                log::debug!("shadow file remove: {e}");
            }
        }
        Ok(())
    }

    /// Migrate a shadow buffer to a real file path when the document is saved.
    pub fn migrate(&self, id: &str, _new_path: &str) -> Result<()> {
        let path = self.shadows.write_recover().remove(id).map(|s| s.path);
        if let Some(path) = path {
            if let Err(e) = fs::remove_file(&path) {
                log::debug!("shadow file remove: {e}");
            }
        }
        Ok(())
    }

    pub fn cleanup_all(&self) {
        let paths: Vec<PathBuf> = {
            let mut shadows = self.shadows.write_recover();
            let paths = shadows.values().map(|s| s.path.clone()).collect();
            shadows.clear();
            paths
        };
        for path in &paths {
            if let Err(e) = fs::remove_file(path) {
                log::debug!("shadow cleanup: {e}");
            }
        }
    }

    pub fn cleanup_old(&self, max_age: Duration) -> u32 {
        let cutoff = SystemTime::now() - max_age;
        let to_remove: Vec<(String, PathBuf)> = {
            let shadows = self.shadows.read_recover();
            shadows
                .iter()
                .filter(|(_, s)| s.updated_at < cutoff)
                .map(|(id, s)| (id.clone(), s.path.clone()))
                .collect()
        };

        for (_, path) in &to_remove {
            if let Err(e) = fs::remove_file(path) {
                log::debug!("shadow cleanup: {e}");
            }
        }

        let mut shadows = self.shadows.write_recover();
        for (id, _) in &to_remove {
            shadows.remove(id);
        }

        to_remove.len() as u32
    }

    /// List active shadow buffers. Window titles are returned in their
    /// obfuscated form (`***OBFUSCATED***`) to avoid leaking plaintext
    /// through diagnostic or IPC surfaces. Callers that genuinely need
    /// the plaintext title should retrieve the shadow by ID and call
    /// `reveal()` explicitly.
    pub fn list(&self) -> Vec<(String, String, String)> {
        self.shadows
            .read_recover()
            .values()
            .map(|s| {
                (
                    s.id.clone(),
                    s.app_name.clone(),
                    format!("{:?}", s.window_title),
                )
            })
            .collect()
    }
}
