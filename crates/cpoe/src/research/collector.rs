// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::Utc;
use std::fs;
use std::time::Duration;

use crate::config::ResearchConfig;
use crate::jitter::Evidence;

use super::types::{
    AnonymizedSession, ResearchDataExport, UploadResponse, UploadResult, CPOE_VERSION,
    MIN_SESSIONS_FOR_UPLOAD, RESEARCH_UPLOAD_URL,
};

#[derive(Debug)]
/// Collects anonymized sessions and manages disk persistence / upload.
pub struct ResearchCollector {
    pub(crate) config: ResearchConfig,
    pub(crate) sessions: Vec<AnonymizedSession>,
}

impl ResearchCollector {
    /// Create a collector with the given research configuration.
    pub fn new(config: ResearchConfig) -> Self {
        Self {
            config,
            sessions: Vec::new(),
        }
    }

    /// Anonymize and enqueue a session (no-op if disabled or below min samples).
    pub fn add_session(&mut self, evidence: &Evidence) {
        if !self.config.contribute_to_research {
            return;
        }

        if evidence.samples.len() < self.config.min_samples_per_session {
            return;
        }

        let anonymized = AnonymizedSession::from_evidence(evidence);
        self.sessions.push(anonymized);

        if self.sessions.len() > self.config.max_sessions {
            let excess = self.sessions.len() - self.config.max_sessions;
            self.sessions.drain(..excess);
        }
    }

    /// Build a serializable export envelope from all buffered sessions.
    pub fn export(&self) -> ResearchDataExport {
        ResearchDataExport {
            version: 1,
            exported_at: Utc::now(),
            consent_confirmed: self.config.contribute_to_research,
            sessions: self.sessions.clone(),
        }
    }

    /// Serialize all buffered sessions to pretty-printed JSON.
    pub fn export_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.export()).map_err(|e| e.to_string())
    }

    /// Persist buffered sessions to a timestamped JSON file on disk.
    pub fn save(&self) -> Result<(), String> {
        if self.sessions.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(&self.config.research_data_dir).map_err(|e| e.to_string())?;

        let export = self.export();
        let filename = format!("research_{}.json", Utc::now().format("%Y%m%d_%H%M%S"));
        let path = self.config.research_data_dir.join(filename);

        let json = serde_json::to_string_pretty(&export).map_err(|e| e.to_string())?;
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, json).map_err(|e| e.to_string())?;
        fs::rename(&tmp_path, &path).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Load previously saved sessions from the research data directory.
    pub fn load(&mut self) -> Result<(), String> {
        if !self.config.research_data_dir.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(&self.config.research_data_dir).map_err(|e| e.to_string())?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                match fs::read_to_string(&path) {
                    Ok(content) => match serde_json::from_str::<ResearchDataExport>(&content) {
                        Ok(export) => {
                            for session in export.sessions {
                                self.sessions.push(session);
                            }
                        }
                        Err(e) => {
                            log::warn!("research: skipping malformed file {:?}: {e}", path);
                        }
                    },
                    Err(e) => {
                        log::warn!("research: failed to read {:?}: {e}", path);
                    }
                }
            }
        }

        if self.sessions.len() > self.config.max_sessions {
            let excess = self.sessions.len() - self.config.max_sessions;
            self.sessions.drain(..excess);
        }

        Ok(())
    }

    /// Clear all buffered sessions and delete the research data directory.
    pub fn clear(&mut self) -> Result<(), String> {
        self.sessions.clear();

        if self.config.research_data_dir.exists() {
            fs::remove_dir_all(&self.config.research_data_dir).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    /// Upload buffered sessions to the research endpoint; clear on success.
    ///
    /// No authentication header is sent intentionally. The endpoint is a Supabase
    /// insert-only table with Row Level Security that grants only INSERT to the
    /// `anon` role; there is no read access. All submitted data is anonymized
    /// (no user identifiers, no raw keystrokes).
    pub async fn upload(&mut self) -> Result<UploadResult, String> {
        if !self.config.contribute_to_research {
            return Err("Research contribution not enabled".to_string());
        }

        if self.sessions.is_empty() {
            return Ok(UploadResult {
                sessions_uploaded: 0,
                samples_uploaded: 0,
                message: "No sessions to upload".to_string(),
            });
        }

        if self.sessions.len() < MIN_SESSIONS_FOR_UPLOAD {
            return Ok(UploadResult {
                sessions_uploaded: 0,
                samples_uploaded: 0,
                message: format!(
                    "Waiting for more sessions ({}/{})",
                    self.sessions.len(),
                    MIN_SESSIONS_FOR_UPLOAD
                ),
            });
        }

        let export = self.export();
        let result = Self::send_export(&export).await?;
        if result.sessions_uploaded > 0 {
            self.clear_after_upload();
        }
        Ok(result)
    }

    /// Return `true` if research is enabled and enough sessions are buffered.
    pub fn should_upload(&self) -> bool {
        self.config.contribute_to_research && self.sessions.len() >= MIN_SESSIONS_FOR_UPLOAD
    }

    /// Export sessions if upload conditions are met; returns `None` otherwise.
    /// Used by the uploader to snapshot data before releasing the mutex for the HTTP call.
    pub fn take_export_if_ready(&self) -> Option<ResearchDataExport> {
        if self.should_upload() { Some(self.export()) } else { None }
    }

    /// Clear buffered sessions and disk data after a successful upload.
    pub fn clear_after_upload(&mut self) {
        self.sessions.clear();
        if self.config.research_data_dir.exists() {
            if let Err(e) = fs::remove_dir_all(&self.config.research_data_dir) {
                log::warn!("Failed to clean up research dir: {e}");
            }
        }
    }

    /// Perform the HTTP upload of an already-exported payload.
    /// Split from `upload()` so callers can release the collector mutex before awaiting.
    pub async fn send_export(export: &ResearchDataExport) -> Result<UploadResult, String> {
        static HTTP_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
        let client = HTTP_CLIENT.get_or_init(reqwest::Client::new);

        let response = client
            .post(RESEARCH_UPLOAD_URL)
            .header("Content-Type", "application/json")
            .header("X-CPoE-Version", CPOE_VERSION)
            .json(export)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("Upload failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Upload failed with status {}: {}", status, body));
        }

        let result: UploadResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(UploadResult {
            sessions_uploaded: result.uploaded,
            samples_uploaded: result.samples,
            message: result.message,
        })
    }
}
