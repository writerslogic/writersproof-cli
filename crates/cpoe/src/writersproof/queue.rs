// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Disk-backed offline attestation queue.
//!
//! When the WritersProof service is unreachable, attestation requests are
//! serialized to `~/.writersproof/queue/` as individual JSON files. The queue
//! can be drained when connectivity is restored.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;

use super::api_trait::WritersProofApi;
use crate::error::{Error, Result};

/// Write data to a temp file in the same directory, then rename for atomicity (EH-016).
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    crate::crypto::atomic_write(path, data)?;
    #[cfg(unix)]
    crate::crypto::restrict_permissions(path, 0o600)?;
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

    /// Maximum number of queue entries returned by listing operations.
    const MAX_LIST_ENTRIES: usize = 1000;

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
        log::debug!(
            "enqueue_text_attestation: content_hash={}",
            request.content_hash
        );
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
        log::debug!("enqueue_text_attestation: queued as {id}");
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
        client: &dyn WritersProofApi,
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
                        if let Err(e) = fs::remove_file(&path) {
                            log::warn!(
                                "text attestation {} submitted but queue file removal failed: {e}",
                                entry.id
                            );
                        }
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
    pub async fn drain_anchors(&self, client: &dyn WritersProofApi) -> Result<(usize, usize)> {
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

