// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Explicit consent management for style fingerprinting.
//!
//! Grant: `cpoe fingerprint enable-style` -- displays explanation,
//! records timestamped consent.
//!
//! Revoke: `cpoe fingerprint disable-style` -- deletes all stored
//! style data and records revocation timestamp.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsentStatus {
    NotRequested,
    Granted,
    Denied,
    Revoked,
}

impl ConsentStatus {
    pub fn is_granted(&self) -> bool {
        matches!(self, ConsentStatus::Granted)
    }
}

/// Timestamped consent decision with audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub status: ConsentStatus,
    pub first_requested: Option<DateTime<Utc>>,
    pub granted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub consent_version: String,
    /// SHA-256 of explanation text shown at grant time
    pub explanation_hash: String,
}

impl Default for ConsentRecord {
    fn default() -> Self {
        Self {
            status: ConsentStatus::NotRequested,
            first_requested: None,
            granted_at: None,
            revoked_at: None,
            consent_version: CONSENT_VERSION.to_string(),
            explanation_hash: String::new(),
        }
    }
}

/// Bump when `CONSENT_EXPLANATION` text changes.
pub const CONSENT_VERSION: &str = "1.0.0";

pub const CONSENT_EXPLANATION: &str = r#"
STYLE FINGERPRINTING CONSENT

CPoE can optionally analyze your WRITING STYLE to create a unique
fingerprint that helps verify you are the author of your documents.

WHAT IS COLLECTED:
- Word length patterns (how long your words typically are)
- Punctuation habits (comma, period usage frequency)
- Writing rhythm (hashed patterns, NOT actual text)
- Correction behavior (backspace usage patterns)

WHAT IS NOT COLLECTED:
- The actual text you type
- Specific words or phrases
- Document contents
- Passwords or sensitive information

This data is:
- Stored LOCALLY on your device only
- ENCRYPTED at rest
- NEVER transmitted to any server
- Completely DELETABLE by revoking consent

Style fingerprinting is OPTIONAL. Activity fingerprinting (typing rhythm)
works without this and does not capture any content information.

Do you consent to style fingerprinting? [y/N]
"#;

#[derive(Debug)]
/// Persists consent state to `style_consent.json`.
pub struct ConsentManager {
    consent_file: PathBuf,
    record: ConsentRecord,
}

impl ConsentManager {
    /// Load existing consent record from `base_path`, or initialize default.
    pub fn new(base_path: &Path) -> Result<Self> {
        let consent_file = base_path.join("style_consent.json");

        let mut record: ConsentRecord = if consent_file.exists() {
            let contents = fs::read_to_string(&consent_file)?;
            serde_json::from_str(&contents)?
        } else {
            ConsentRecord::default()
        };

        // If the consent explanation changed (version bump), force re-consent
        // so the user sees the updated terms before data collection continues.
        if record.status == ConsentStatus::Granted && record.consent_version != CONSENT_VERSION {
            log::warn!(
                "Consent version mismatch (stored={}, current={}), requiring re-consent",
                record.consent_version,
                CONSENT_VERSION,
            );
            record.status = ConsentStatus::NotRequested;
        }

        Ok(Self {
            consent_file,
            record,
        })
    }

    pub fn status(&self) -> ConsentStatus {
        self.record.status
    }

    pub fn has_style_consent(&self) -> Result<bool> {
        Ok(self.record.status.is_granted())
    }

    pub fn record(&self) -> &ConsentRecord {
        &self.record
    }

    /// Begin consent flow. Returns `Ok(false)` to indicate consent is not yet
    /// granted. Caller must display `CONSENT_EXPLANATION` and call
    /// `grant_consent`/`deny_consent` based on user input.
    pub fn begin_consent_request(&mut self) -> Result<bool> {
        if self.record.first_requested.is_none() {
            self.record.first_requested = Some(Utc::now());
            self.save()?;
        }

        Ok(false)
    }

    /// Record consent grant with timestamp and explanation hash.
    pub fn grant_consent(&mut self) -> Result<()> {
        self.record.status = ConsentStatus::Granted;
        self.record.granted_at = Some(Utc::now());
        self.record.consent_version = CONSENT_VERSION.to_string();
        self.record.explanation_hash = hash_explanation();
        self.save()?;
        Ok(())
    }

    pub fn deny_consent(&mut self) -> Result<()> {
        self.record.status = ConsentStatus::Denied;
        self.save()?;
        Ok(())
    }

    /// Revoke consent. Caller is responsible for deleting style data.
    pub fn revoke_consent(&mut self) -> Result<()> {
        if self.record.status != ConsentStatus::Granted {
            return Err(anyhow!("Cannot revoke consent that was not granted"));
        }

        self.record.status = ConsentStatus::Revoked;
        self.record.revoked_at = Some(Utc::now());
        self.save()?;
        Ok(())
    }

    pub fn get_explanation(&self) -> &'static str {
        CONSENT_EXPLANATION
    }

    pub fn get_version(&self) -> &str {
        CONSENT_VERSION
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.consent_file.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(&self.record)?;
        let tmp_path = self.consent_file.with_extension("json.tmp");
        fs::write(&tmp_path, json)?;
        let f = std::fs::File::open(&tmp_path)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp_path, &self.consent_file)?;
        Ok(())
    }

    pub fn delete_record(&self) -> Result<()> {
        if self.consent_file.exists() {
            fs::remove_file(&self.consent_file)?;
        }
        Ok(())
    }
}

/// SHA-256 hex digest of `CONSENT_EXPLANATION` for audit trail.
fn hash_explanation() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(CONSENT_EXPLANATION.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn format_consent_status(status: ConsentStatus) -> &'static str {
    match status {
        ConsentStatus::NotRequested => "Not requested",
        ConsentStatus::Granted => "Granted",
        ConsentStatus::Denied => "Denied",
        ConsentStatus::Revoked => "Revoked",
    }
}

/// Multi-line CLI-friendly representation.
pub fn format_consent_record(record: &ConsentRecord) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Status: {}", format_consent_status(record.status)));

    if let Some(first) = record.first_requested {
        lines.push(format!(
            "First requested: {}",
            first.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    if let Some(granted) = record.granted_at {
        lines.push(format!(
            "Granted at: {}",
            granted.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    if let Some(revoked) = record.revoked_at {
        lines.push(format!(
            "Revoked at: {}",
            revoked.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    lines.push(format!("Consent version: {}", record.consent_version));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_consent_status_default() {
        let record = ConsentRecord::default();
        assert_eq!(record.status, ConsentStatus::NotRequested);
        assert!(!record.status.is_granted());
    }

    #[test]
    fn test_consent_manager_creation() {
        let dir = tempdir().unwrap();
        let manager = ConsentManager::new(dir.path()).unwrap();
        assert_eq!(manager.status(), ConsentStatus::NotRequested);
    }

    #[test]
    fn test_grant_and_revoke_consent() {
        let dir = tempdir().unwrap();
        let mut manager = ConsentManager::new(dir.path()).unwrap();

        manager.grant_consent().unwrap();
        assert_eq!(manager.status(), ConsentStatus::Granted);
        assert!(manager.has_style_consent().unwrap());

        manager.revoke_consent().unwrap();
        assert_eq!(manager.status(), ConsentStatus::Revoked);
        assert!(!manager.has_style_consent().unwrap());
    }

    #[test]
    fn test_consent_persistence() {
        let dir = tempdir().unwrap();

        {
            let mut manager = ConsentManager::new(dir.path()).unwrap();
            manager.grant_consent().unwrap();
        }

        {
            let manager = ConsentManager::new(dir.path()).unwrap();
            assert_eq!(manager.status(), ConsentStatus::Granted);
        }
    }

    #[test]
    fn test_hash_explanation() {
        let hash = hash_explanation();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA256 hex
    }
}
