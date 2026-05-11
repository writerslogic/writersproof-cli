// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Disk-backed offline attestation queue.
//!
//! When the WritersProof service is unreachable, attestation requests are
//! serialized to `~/.writersproof/queue/` as individual JSON files. The queue
//! can be drained when connectivity is restored.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};

use super::client::WritersProofClient;
use super::types::{AttestResponse, QueuedAttestation};
use crate::error::{Error, Result};

/// Write data to a temp file in the same directory, then rename for atomicity (EH-016).
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    crate::crypto::atomic_write(path, data)?;
    Ok(())
}

#[derive(Debug)]
/// Disk-backed attestation queue.
pub struct OfflineQueue {
    queue_dir: PathBuf,
}

impl OfflineQueue {
    /// Create a queue backed by `queue_dir`, creating it if needed.
    pub fn new(queue_dir: &Path) -> Result<Self> {
        fs::create_dir_all(queue_dir)?;
        Ok(Self {
            queue_dir: queue_dir.to_path_buf(),
        })
    }

    /// Return `~/.writersproof/queue/`.
    pub fn default_dir() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::checkpoint("cannot determine home directory for queue path"))?;
        Ok(home.join(".writersproof").join("queue"))
    }

    /// Enqueue an attestation for later submission.
    pub fn enqueue(
        &self,
        evidence_cbor: &[u8],
        nonce: Option<&[u8; 32]>,
        hardware_key_id: &str,
        signing_key: &SigningKey,
    ) -> Result<String> {
        // Include DST and random nonce in signed payload to prevent replay (EH-015).
        let queue_nonce: [u8; 16] = rand::random();
        let mut sign_buf = Vec::with_capacity(
            b"cpoe-queue-sign-v1".len() + queue_nonce.len() + evidence_cbor.len(),
        );
        sign_buf.extend_from_slice(b"cpoe-queue-sign-v1");
        sign_buf.extend_from_slice(&queue_nonce);
        sign_buf.extend_from_slice(evidence_cbor);
        let signature = signing_key.sign(&sign_buf);
        let id = format!(
            "{}-{}",
            Utc::now().format("%Y%m%d%H%M%S"),
            hex::encode(rand::random::<[u8; 8]>())
        );

        let entry = QueuedAttestation {
            id: id.clone(),
            evidence_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                evidence_cbor,
            ),
            nonce: nonce.map(hex::encode),
            hardware_key_id: hardware_key_id.to_string(),
            signature: crate::utils::crypto_types::Ed25519Sig::from(signature).to_hex(),
            queue_nonce: Some(hex::encode(queue_nonce)),
            retry_count: 0,
            last_error: None,
            created_at: Utc::now().to_rfc3339(),
        };

        let path = self.queue_dir.join(format!("{id}.json"));
        let data = serde_json::to_vec_pretty(&entry)
            .map_err(|e| Error::checkpoint(format!("queue serialize failed: {e}")))?;
        atomic_write(&path, &data)?;

        Ok(id)
    }

    /// Maximum number of queue entries returned by `list()`.
    const MAX_LIST_ENTRIES: usize = 1000;

    /// List queued entries, sorted by creation time, capped at 1000.
    pub fn list(&self) -> Result<Vec<QueuedAttestation>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.queue_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                match fs::read(&path) {
                    Ok(data) => match serde_json::from_slice::<QueuedAttestation>(&data) {
                        Ok(queued) => entries.push(queued),
                        Err(e) => log::warn!("Malformed queue entry {}: {e}", path.display()),
                    },
                    Err(e) => {
                        log::warn!("Failed to read queue entry {}: {e}", path.display());
                        continue;
                    }
                }
            }
            if entries.len() >= Self::MAX_LIST_ENTRIES {
                log::warn!(
                    "Queue list capped at {} entries; remaining entries skipped",
                    Self::MAX_LIST_ENTRIES
                );
                break;
            }
        }
        entries.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(entries)
    }

    /// Return the number of queued entries.
    pub fn len(&self) -> Result<usize> {
        Ok(self.list()?.len())
    }

    /// Return `true` if the queue contains no entries.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Submit all queued entries via `client`, fetching fresh nonces for each.
    ///
    /// Successful entries are removed; failed entries stay with incremented
    /// `retry_count` and the error recorded.
    pub async fn drain(
        &self,
        client: &WritersProofClient,
        signing_key: &SigningKey,
    ) -> Result<Vec<AttestResponse>> {
        let entries = self.list()?;
        let mut results = Vec::new();

        for mut entry in entries {
            let evidence = match base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &entry.evidence_b64,
            ) {
                Ok(v) => v,
                Err(e) => {
                    self.update_entry_error(&mut entry, &format!("base64 decode failed: {e}"))?;
                    continue;
                }
            };

            let nonce = match client.request_nonce(&entry.hardware_key_id).await {
                Ok(resp) => {
                    let n = hex::decode(&resp.nonce)
                        .map_err(|e| Error::crypto(format!("nonce decode: {e}")))?;
                    if n.len() != 32 {
                        self.update_entry_error(&mut entry, "invalid nonce length")?;
                        continue;
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&n);
                    arr
                }
                Err(e) => {
                    self.update_entry_error(&mut entry, &e.to_string())?;
                    continue;
                }
            };

            match client
                .attest(&evidence, &nonce, &entry.hardware_key_id, signing_key)
                .await
            {
                Ok(resp) => {
                    self.remove_entry(&entry.id)?;
                    results.push(resp);
                }
                Err(e) => {
                    self.update_entry_error(&mut entry, &e.to_string())?;
                }
            }
        }

        Ok(results)
    }

    /// Reject IDs with non-alphanumeric chars to prevent path traversal.
    fn validate_id(id: &str) -> Result<()> {
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::validation(format!("invalid queue entry ID: {id:?}")));
        }
        Ok(())
    }

    /// Remove a queued entry by ID.
    pub fn remove_entry(&self, id: &str) -> Result<()> {
        Self::validate_id(id)?;
        let path = self.queue_dir.join(format!("{id}.json"));
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    fn update_entry_error(&self, entry: &mut QueuedAttestation, error: &str) -> Result<()> {
        Self::validate_id(&entry.id)?;
        entry.retry_count += 1;
        entry.last_error = Some(error.to_string());

        let path = self.queue_dir.join(format!("{}.json", entry.id));
        let data = serde_json::to_vec_pretty(entry)
            .map_err(|e| Error::checkpoint(format!("queue update serialize failed: {e}")))?;
        atomic_write(&path, &data)?;
        Ok(())
    }

    // --- Text attestation queue (separate subdirectory) ---

    fn text_dir(&self) -> Result<PathBuf> {
        let dir = self.queue_dir.join("text");
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Queue a text attestation for later submission.
    pub fn enqueue_text_attestation(
        &self,
        request: super::types::TextAttestationRequest,
    ) -> Result<String> {
        let id = format!(
            "{}-{}",
            Utc::now().format("%Y%m%d%H%M%S"),
            hex::encode(rand::random::<[u8; 4]>())
        );

        let entry = super::types::QueuedTextAttestation {
            id: id.clone(),
            request,
            retry_count: 0,
            last_error: None,
            created_at: Utc::now().to_rfc3339(),
        };

        let dir = self.text_dir()?;
        let path = dir.join(format!("{id}.json"));
        let data = serde_json::to_vec_pretty(&entry)
            .map_err(|e| Error::checkpoint(format!("text queue serialize: {e}")))?;
        atomic_write(&path, &data)?;
        Ok(id)
    }

    /// List queued text attestations.
    pub fn list_text_attestations(&self) -> Result<Vec<super::types::QueuedTextAttestation>> {
        let dir = match self.text_dir() {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };
        let mut entries = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match fs::read(&path) {
                Ok(data) => match serde_json::from_slice(&data) {
                    Ok(queued) => entries.push(queued),
                    Err(e) => log::warn!("Malformed text queue entry {}: {e}", path.display()),
                },
                Err(e) => log::warn!("Failed to read text queue entry {}: {e}", path.display()),
            }
            if entries.len() >= Self::MAX_LIST_ENTRIES {
                break;
            }
        }
        entries
            .sort_by(|a: &super::types::QueuedTextAttestation, b| a.created_at.cmp(&b.created_at));
        Ok(entries)
    }

    /// Maximum retry attempts before an entry is discarded.
    const MAX_TEXT_RETRIES: u32 = 10;

    /// Submit queued text attestations via `client`.
    ///
    /// Skips entries that haven't reached their backoff window yet.
    /// Entries exceeding MAX_TEXT_RETRIES are removed. Returns
    /// `(successful_count, discarded_count)`.
    pub async fn drain_text_attestations(
        &self,
        client: &WritersProofClient,
    ) -> Result<(usize, usize)> {
        let entries = self.list_text_attestations()?;
        let mut success_count = 0;
        let mut discard_count = 0;
        let now = Utc::now();

        for mut entry in entries {
            // Remove entries that exceeded max retries.
            if entry.retry_count >= Self::MAX_TEXT_RETRIES {
                log::warn!(
                    "Discarding text attestation {} after {} retries (last error: {})",
                    entry.id,
                    entry.retry_count,
                    entry.last_error.as_deref().unwrap_or("unknown")
                );
                Self::validate_id(&entry.id)?;
                let path = self.text_dir()?.join(format!("{}.json", entry.id));
                if path.exists() {
                    fs::remove_file(&path)?;
                }
                discard_count += 1;
                continue;
            }

            // Exponential backoff: wait 2^retry_count seconds (1s, 2s, 4s, 8s, ... 512s max).
            if entry.retry_count > 0 {
                if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&entry.created_at) {
                    let backoff_secs = 1i64 << entry.retry_count.min(9);
                    let earliest_retry = created
                        + chrono::Duration::seconds(backoff_secs * entry.retry_count as i64);
                    if now < earliest_retry {
                        continue;
                    }
                }
            }

            match client.submit_text_attestation(entry.request.clone()).await {
                Ok(_) => {
                    Self::validate_id(&entry.id)?;
                    let path = self.text_dir()?.join(format!("{}.json", entry.id));
                    if path.exists() {
                        fs::remove_file(&path)?;
                    }
                    success_count += 1;
                }
                Err(e) => {
                    entry.retry_count += 1;
                    entry.last_error = Some(e.to_string());
                    Self::validate_id(&entry.id)?;
                    let path = self.text_dir()?.join(format!("{}.json", entry.id));
                    let data = serde_json::to_vec_pretty(&entry)
                        .map_err(|e| Error::checkpoint(format!("text queue update: {e}")))?;
                    atomic_write(&path, &data)?;
                }
            }
        }

        Ok((success_count, discard_count))
    }

    /// Number of queued text attestations.
    pub fn text_attestation_count(&self) -> Result<usize> {
        Ok(self.list_text_attestations()?.len())
    }

    // --- Anchor queue (separate subdirectory) ---

    fn anchor_dir(&self) -> Result<PathBuf> {
        let dir = self.queue_dir.join("anchors");
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Queue a failed anchor request for later submission.
    pub fn enqueue_anchor(
        &self,
        evidence_hash: String,
        signature: String,
        tier: Option<String>,
    ) -> Result<String> {
        let id = format!(
            "{}-{}",
            Utc::now().format("%Y%m%d%H%M%S"),
            hex::encode(rand::random::<[u8; 4]>())
        );

        let entry = super::types::QueuedAnchorRequest {
            id: id.clone(),
            evidence_hash,
            signature,
            tier,
            retry_count: 0,
            last_error: None,
            created_at: Utc::now().to_rfc3339(),
        };

        let dir = self.anchor_dir()?;
        let path = dir.join(format!("{id}.json"));
        let data = serde_json::to_vec_pretty(&entry)
            .map_err(|e| Error::checkpoint(format!("anchor queue serialize: {e}")))?;
        atomic_write(&path, &data)?;
        Ok(id)
    }

    /// List queued anchor requests.
    pub fn list_anchors(&self) -> Result<Vec<super::types::QueuedAnchorRequest>> {
        let dir = match self.anchor_dir() {
            Ok(d) => d,
            Err(_) => return Ok(Vec::new()),
        };
        let mut entries = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match fs::read(&path) {
                Ok(data) => match serde_json::from_slice(&data) {
                    Ok(queued) => entries.push(queued),
                    Err(e) => log::warn!("Malformed anchor queue entry {}: {e}", path.display()),
                },
                Err(e) => log::warn!("Failed to read anchor queue entry {}: {e}", path.display()),
            }
            if entries.len() >= Self::MAX_LIST_ENTRIES {
                break;
            }
        }
        entries.sort_by(|a: &super::types::QueuedAnchorRequest, b| a.created_at.cmp(&b.created_at));
        Ok(entries)
    }

    /// Maximum retry attempts before a queued anchor is discarded.
    const MAX_ANCHOR_RETRIES: u32 = 5;

    /// Submit queued anchor requests via `client`.
    ///
    /// Skips entries that haven't reached their backoff window yet.
    /// Entries exceeding MAX_ANCHOR_RETRIES are removed. Returns
    /// `(successful_count, discarded_count)`.
    pub async fn drain_anchors(&self, client: &WritersProofClient) -> Result<(usize, usize)> {
        let entries = self.list_anchors()?;
        let mut success_count = 0;
        let mut discard_count = 0;
        let now = Utc::now();

        for mut entry in entries {
            if entry.retry_count >= Self::MAX_ANCHOR_RETRIES {
                log::warn!(
                    "Discarding anchor {} after {} retries (last error: {})",
                    entry.id,
                    entry.retry_count,
                    entry.last_error.as_deref().unwrap_or("unknown")
                );
                Self::validate_id(&entry.id)?;
                let path = self.anchor_dir()?.join(format!("{}.json", entry.id));
                if path.exists() {
                    fs::remove_file(&path)?;
                }
                discard_count += 1;
                continue;
            }

            // Exponential backoff: wait 2^retry_count seconds (1s, 2s, 4s, 8s, 16s).
            if entry.retry_count > 0 {
                if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&entry.created_at) {
                    let backoff_secs = 1i64 << entry.retry_count.min(9);
                    let earliest_retry = created
                        + chrono::Duration::seconds(backoff_secs * entry.retry_count as i64);
                    if now < earliest_retry {
                        continue;
                    }
                }
            }

            let req = super::types::AnchorRequest {
                evidence_hash: entry.evidence_hash.clone(),
                author_did: String::new(),
                signature: entry.signature.clone(),
                metadata: Some(super::types::AnchorMetadata {
                    document_name: None,
                    tier: entry.tier.clone(),
                }),
            };

            match client.anchor(req).await {
                Ok(_) => {
                    Self::validate_id(&entry.id)?;
                    let path = self.anchor_dir()?.join(format!("{}.json", entry.id));
                    if path.exists() {
                        fs::remove_file(&path)?;
                    }
                    success_count += 1;
                }
                Err(e) => {
                    entry.retry_count += 1;
                    entry.last_error = Some(e.to_string());
                    Self::validate_id(&entry.id)?;
                    let path = self.anchor_dir()?.join(format!("{}.json", entry.id));
                    let data = serde_json::to_vec_pretty(&entry)
                        .map_err(|e| Error::checkpoint(format!("anchor queue update: {e}")))?;
                    atomic_write(&path, &data)?;
                }
            }
        }

        Ok((success_count, discard_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_queue_enqueue_and_list() {
        let dir = TempDir::new().unwrap();
        let queue = OfflineQueue::new(dir.path()).unwrap();

        let key = SigningKey::from_bytes(&[0x42; 32]);
        let evidence = b"test-evidence-cbor";
        let nonce = [0xAA; 32];

        let id = queue
            .enqueue(evidence, Some(&nonce), "hw-key-1", &key)
            .unwrap();
        assert!(!id.is_empty());

        let entries = queue.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hardware_key_id, "hw-key-1");
        assert_eq!(entries[0].retry_count, 0);
    }

    #[test]
    fn test_queue_multiple_entries() {
        let dir = TempDir::new().unwrap();
        let queue = OfflineQueue::new(dir.path()).unwrap();
        let key = SigningKey::from_bytes(&[0x42; 32]);

        for i in 0..3 {
            queue
                .enqueue(&[i], None, &format!("hw-key-{i}"), &key)
                .unwrap();
        }

        assert_eq!(queue.len().unwrap(), 3);
        assert!(!queue.is_empty().unwrap());
    }

    #[test]
    fn test_queue_remove_entry() {
        let dir = TempDir::new().unwrap();
        let queue = OfflineQueue::new(dir.path()).unwrap();
        let key = SigningKey::from_bytes(&[0x42; 32]);

        let id = queue.enqueue(b"data", None, "hw-1", &key).unwrap();
        assert_eq!(queue.len().unwrap(), 1);

        queue.remove_entry(&id).unwrap();
        assert_eq!(queue.len().unwrap(), 0);
    }

    #[test]
    fn test_queue_persistence() {
        let dir = TempDir::new().unwrap();
        let key = SigningKey::from_bytes(&[0x42; 32]);

        {
            let queue = OfflineQueue::new(dir.path()).unwrap();
            queue.enqueue(b"data1", None, "hw-1", &key).unwrap();
        }

        {
            let queue = OfflineQueue::new(dir.path()).unwrap();
            assert_eq!(queue.len().unwrap(), 1);
        }
    }

    #[test]
    fn test_queue_without_nonce() {
        let dir = TempDir::new().unwrap();
        let queue = OfflineQueue::new(dir.path()).unwrap();
        let key = SigningKey::from_bytes(&[0x42; 32]);

        let id = queue.enqueue(b"data", None, "hw-1", &key).unwrap();
        let entries = queue.list().unwrap();
        assert!(entries[0].nonce.is_none());
        let _ = id;
    }
}
