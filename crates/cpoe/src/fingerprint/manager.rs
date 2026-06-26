// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::config::FingerprintConfig;
use crate::fingerprint::activity::{ActivityFingerprint, ActivityFingerprintAccumulator};
use crate::fingerprint::author::{AuthorFingerprint, ProfileId};
use crate::fingerprint::comparison::{self, FingerprintComparison};
use crate::fingerprint::consent::ConsentManager;
use crate::fingerprint::storage::{FingerprintSnapshot, FingerprintStorage, StoredProfile};
use crate::fingerprint::voice::{StyleCollector, StyleFingerprint};
use crate::utils::lock::RwLockRecover;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// How many accumulator samples must pass between EMA consolidation rounds.
const CONSOLIDATION_INTERVAL: usize = 200;

/// File name for the persisted canonical profile relative to the storage path.
const CANONICAL_PROFILE_FILE: &str = "canonical_profile.json";

#[derive(Debug)]
pub struct FingerprintManager {
    pub(crate) config: FingerprintConfig,
    pub(crate) storage: FingerprintStorage,
    pub(crate) consent_manager: ConsentManager,
    pub(crate) activity_accumulator: ActivityFingerprintAccumulator,
    pub(crate) style_collector: Option<StyleCollector>,
    pub(crate) current_profile_id: Option<ProfileId>,
    last_snapshot_samples: usize,
    /// Long-lived EMA-merged canonical author profile, persisted across sessions.
    pub(crate) canonical_profile: Option<AuthorFingerprint>,
    /// Number of EMA consolidation rounds completed so far.
    consolidation_count: u32,
    /// Sample count at which the last consolidation occurred.
    last_consolidation_samples: usize,
}

impl FingerprintManager {
    pub fn new(storage_path: &Path) -> Result<Self> {
        log::debug!(
            "FingerprintManager::new: storage_path={}",
            storage_path.display()
        );
        let storage = FingerprintStorage::new(storage_path)?;
        let consent_manager = ConsentManager::new(storage_path)?;
        let canonical_profile = load_canonical_profile(storage_path);

        Ok(Self {
            config: FingerprintConfig::default(),
            storage,
            consent_manager,
            activity_accumulator: ActivityFingerprintAccumulator::new(),
            style_collector: None,
            current_profile_id: None,
            last_snapshot_samples: 0,
            consolidation_count: canonical_profile
                .as_ref()
                .map(|c| (c.sample_count / CONSOLIDATION_INTERVAL as u64) as u32)
                .unwrap_or(0),
            canonical_profile,
            last_consolidation_samples: 0,
        })
    }

    pub fn with_config(config: FingerprintConfig) -> Result<Self> {
        log::debug!(
            "FingerprintManager::with_config: storage_path={}",
            config.storage_path.display()
        );
        let storage = FingerprintStorage::new(&config.storage_path)?;
        let consent_manager = ConsentManager::new(&config.storage_path)?;
        let canonical_profile = load_canonical_profile(&config.storage_path);

        let style_collector = if config.style_enabled && consent_manager.has_style_consent()? {
            Some(StyleCollector::new())
        } else {
            None
        };

        Ok(Self {
            config,
            storage,
            consent_manager,
            activity_accumulator: ActivityFingerprintAccumulator::new(),
            style_collector,
            current_profile_id: None,
            last_snapshot_samples: 0,
            consolidation_count: canonical_profile
                .as_ref()
                .map(|c| (c.sample_count / CONSOLIDATION_INTERVAL as u64) as u32)
                .unwrap_or(0),
            canonical_profile,
            last_consolidation_samples: 0,
        })
    }

    pub fn config(&self) -> &FingerprintConfig {
        &self.config
    }

    pub fn is_activity_enabled(&self) -> bool {
        self.config.activity_enabled
    }

    pub fn is_style_enabled(&self) -> bool {
        self.config.style_enabled && self.style_collector.is_some()
    }

    pub fn enable_activity(&mut self) {
        self.config.activity_enabled = true;
    }

    pub fn disable_activity(&mut self) {
        self.config.activity_enabled = false;
    }

    pub fn request_style_consent(&mut self) -> Result<bool> {
        log::debug!("FingerprintManager::request_style_consent");
        let granted = self.consent_manager.begin_consent_request()?;
        if granted {
            self.enable_style_internal()?;
        }
        Ok(granted)
    }

    pub fn enable_style(&mut self) -> Result<()> {
        log::debug!("FingerprintManager::enable_style");
        if !self.consent_manager.has_style_consent()? {
            return Err(anyhow::anyhow!(
                "Style fingerprinting requires consent. Call request_style_consent() first."
            ));
        }
        self.enable_style_internal()
    }

    fn enable_style_internal(&mut self) -> Result<()> {
        self.config.style_enabled = true;
        if self.style_collector.is_none() {
            self.style_collector = Some(StyleCollector::new());
        }
        if let Some(ref mut collector) = self.style_collector {
            collector.set_consent(true);
        }
        Ok(())
    }

    pub fn disable_style(&mut self) -> Result<()> {
        log::debug!("FingerprintManager::disable_style");
        self.config.style_enabled = false;
        self.style_collector = None;
        self.consent_manager.revoke_consent()?;
        self.storage.delete_all_style_data()?;
        Ok(())
    }

    pub fn record_activity_sample(&mut self, sample: &crate::jitter::SimpleJitterSample) {
        if !self.config.activity_enabled {
            return;
        }
        self.activity_accumulator.add_sample(sample);

        let count = self.activity_accumulator.sample_count();
        if count.saturating_sub(self.last_snapshot_samples) >= 50 {
            self.take_snapshot();
            self.last_snapshot_samples = count;
        }
        if count.saturating_sub(self.last_consolidation_samples) >= CONSOLIDATION_INTERVAL {
            self.maybe_consolidate();
            self.last_consolidation_samples = count;
        }
    }

    pub fn record_keystroke_for_style(&mut self, keycode: u16, char_value: Option<char>) {
        if let Some(ref mut collector) = self.style_collector {
            collector.record_keystroke(keycode, char_value);
        }
    }

    pub fn current_activity_fingerprint(&self) -> Arc<ActivityFingerprint> {
        // Read from the global accumulator which is fed by sentinel keystroke
        // injection and background fingerprint capture. The manager's local
        // accumulator is only used for snapshot/consolidation bookkeeping.
        let global = crate::fingerprint::global::get_global_accumulator();
        let guard = global.read_recover();
        if guard.sample_count() > 0 {
            return guard.current_fingerprint();
        }
        // Fall back to local accumulator (used in tests and when global is empty).
        self.activity_accumulator.current_fingerprint()
    }

    pub fn current_style_fingerprint(&self) -> Option<StyleFingerprint> {
        self.style_collector
            .as_ref()
            .map(|c| c.current_fingerprint())
    }

    pub fn current_author_fingerprint(&self) -> AuthorFingerprint {
        let activity = self.current_activity_fingerprint();
        let mut fingerprint = if let Some(ref id) = self.current_profile_id {
            AuthorFingerprint::with_id(id.clone(), (*activity).clone())
        } else {
            AuthorFingerprint::new((*activity).clone())
        };

        if let Some(style) = self.current_style_fingerprint() {
            fingerprint = fingerprint.with_style(style);
        }

        fingerprint.sample_count = self.activity_accumulator.sample_count() as u64;
        fingerprint.update_confidence();
        fingerprint
    }

    fn take_snapshot(&mut self) {
        let fp = self.current_author_fingerprint();
        let activity = self.current_activity_fingerprint();

        let iki_mean = activity.iki_distribution.mean;
        let iki_std = activity.iki_distribution.std_dev;
        let iki_cv = if iki_mean > 0.0 {
            (iki_std / iki_mean).clamp(0.0, 1.0)
        } else {
            1.0
        };

        let zone_entropy = {
            let freqs = &activity.zone_profile.zone_frequencies;
            let e: f64 = freqs
                .iter()
                .filter(|&&f| f > 0.0)
                .map(|&f| -f * f.ln())
                .sum();
            let max_entropy = (8.0_f64).ln();
            if max_entropy > 0.0 {
                (e / max_entropy).clamp(0.0, 1.0)
            } else {
                0.0
            }
        };

        let correction_rate = self
            .current_style_fingerprint()
            .map(|s| s.correction_rate)
            .unwrap_or(0.0);

        let hurst = activity.hurst_exponent.unwrap_or(0.5);

        let dimensions = vec![
            (
                "typing_speed".into(),
                (activity.session_signature.mean_typing_speed / 120.0).clamp(0.0, 1.0),
            ),
            ("consistency".into(), 1.0 - iki_cv),
            (
                "pause_depth".into(),
                (activity.pause_signature.thinking_pause_mean / 5000.0).clamp(0.0, 1.0),
            ),
            ("correction_rate".into(), correction_rate),
            ("zone_diversity".into(), zone_entropy),
            ("rhythm".into(), hurst),
        ];

        let snapshot = FingerprintSnapshot {
            sample_count: fp.sample_count,
            timestamp: chrono::Utc::now().timestamp(),
            dimensions,
        };
        self.storage.save_snapshot(snapshot);
    }

    pub fn get_snapshots(&self) -> &[FingerprintSnapshot] {
        self.storage.get_snapshots()
    }

    fn maybe_consolidate(&mut self) {
        let window = self.current_author_fingerprint();
        let alpha = 1.0 / (1.0 + (self.consolidation_count + 1) as f64 * 0.5);
        match &mut self.canonical_profile {
            Some(canonical) => {
                canonical.update_with_ema(&window, alpha);
            }
            None => {
                self.canonical_profile = Some(window);
            }
        }
        self.consolidation_count += 1;
        if let Some(ref canonical) = self.canonical_profile {
            save_canonical_profile(&self.config.storage_path, canonical);
        }
    }

    pub fn canonical_or_current_fingerprint(&self) -> AuthorFingerprint {
        match &self.canonical_profile {
            Some(canonical) => canonical.clone(),
            None => self.current_author_fingerprint(),
        }
    }

    pub fn save_current(&mut self) -> Result<ProfileId> {
        log::debug!("FingerprintManager::save_current");
        let fingerprint = self.current_author_fingerprint();
        let id = fingerprint.id.clone();
        self.storage.save(&fingerprint)?;
        self.current_profile_id = Some(id.clone());
        Ok(id)
    }

    pub fn load(&self, id: &ProfileId) -> Result<AuthorFingerprint> {
        log::debug!("FingerprintManager::load: id={}", id);
        self.storage.load(id)
    }

    pub fn list_profiles(&self) -> Result<Vec<StoredProfile>> {
        log::debug!("FingerprintManager::list_profiles");
        self.storage.list_profiles()
    }

    pub fn compare(&self, id1: &ProfileId, id2: &ProfileId) -> Result<FingerprintComparison> {
        log::debug!("FingerprintManager::compare: id1={}, id2={}", id1, id2);
        let fp1 = self.storage.load(id1)?;
        let fp2 = self.storage.load(id2)?;
        Ok(comparison::compare_fingerprints(&fp1, &fp2))
    }

    pub fn delete(&mut self, id: &ProfileId) -> Result<()> {
        log::debug!("FingerprintManager::delete: id={}", id);
        self.storage.delete(id)?;
        if self.current_profile_id.as_ref() == Some(id) {
            self.current_profile_id = None;
        }
        Ok(())
    }

    pub fn reset_session(&mut self) {
        log::debug!("FingerprintManager::reset_session");
        self.activity_accumulator.reset();
        self.last_snapshot_samples = 0;
        self.last_consolidation_samples = 0;
        if let Some(ref mut collector) = self.style_collector {
            collector.reset();
        }
        // canonical_profile intentionally preserved across session resets
    }

    pub fn reset(&mut self) {
        log::debug!("FingerprintManager::reset");
        self.reset_session();
        self.canonical_profile = None;
        self.consolidation_count = 0;
        let path = self.config.storage_path.join(CANONICAL_PROFILE_FILE);
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                log::warn!("Failed to delete canonical profile: {e}");
            }
        }
    }

    #[cfg(feature = "cpoe_jitter")]
    pub fn current_author_fingerprint_with_phys_ratio(&self, phys_ratio: f64) -> AuthorFingerprint {
        log::debug!(
            "FingerprintManager::current_author_fingerprint_with_phys_ratio: phys_ratio={}",
            phys_ratio
        );
        let mut activity = (*self.current_activity_fingerprint()).clone();
        activity.set_phys_ratio(phys_ratio);

        let mut fingerprint = if let Some(ref id) = self.current_profile_id {
            AuthorFingerprint::with_id(id.clone(), activity)
        } else {
            AuthorFingerprint::new(activity)
        };

        if let Some(style) = self.current_style_fingerprint() {
            fingerprint = fingerprint.with_style(style);
        }

        fingerprint.sample_count = self.global_activity_sample_count() as u64;
        fingerprint.update_confidence();
        fingerprint
    }

    /// Return the activity sample count from the global accumulator, falling
    /// back to the local one (tests / no sentinel).
    fn global_activity_sample_count(&self) -> usize {
        let global = crate::fingerprint::global::get_global_accumulator();
        let count = global.read_recover().sample_count();
        if count > 0 {
            count
        } else {
            self.activity_accumulator.sample_count()
        }
    }

    pub fn status(&self) -> FingerprintStatus {
        FingerprintStatus {
            activity_enabled: self.config.activity_enabled,
            style_enabled: self.config.style_enabled,
            style_consent: self.consent_manager.has_style_consent().unwrap_or(false),
            current_profile_id: self.current_profile_id.clone(),
            activity_samples: self.global_activity_sample_count(),
            style_samples: self
                .style_collector
                .as_ref()
                .map(|c| c.sample_count())
                .unwrap_or(0),
            confidence: self.current_author_fingerprint().confidence,
            phys_ratio: None,
        }
    }

    #[cfg(feature = "cpoe_jitter")]
    pub fn status_with_phys_ratio(&self, phys_ratio: f64) -> FingerprintStatus {
        let mut status = self.status();
        status.phys_ratio = Some(phys_ratio);
        status
    }
}

fn load_canonical_profile(storage_path: &Path) -> Option<AuthorFingerprint> {
    let path = storage_path.join(CANONICAL_PROFILE_FILE);
    if !path.exists() {
        return None;
    }
    match std::fs::read_to_string(&path) {
        Ok(json) => match serde_json::from_str(&json) {
            Ok(fp) => Some(fp),
            Err(e) => {
                log::warn!("Failed to deserialize canonical profile: {e}");
                None
            }
        },
        Err(e) => {
            log::warn!("Failed to read canonical profile: {e}");
            None
        }
    }
}

fn save_canonical_profile(storage_path: &Path, fingerprint: &AuthorFingerprint) {
    let path = storage_path.join(CANONICAL_PROFILE_FILE);
    let json = match serde_json::to_string_pretty(fingerprint) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("Failed to serialize canonical profile: {e}");
            return;
        }
    };
    let tmp = match tempfile::NamedTempFile::new_in(storage_path) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("Failed to create tempfile for canonical profile: {e}");
            return;
        }
    };
    if let Err(e) = std::io::Write::write_all(&mut tmp.as_file(), json.as_bytes()) {
        log::warn!("Failed to write canonical profile tempfile: {e}");
        return;
    }
    if let Err(e) = tmp.as_file().sync_all() {
        log::warn!("Failed to fsync canonical profile: {e}");
        return;
    }
    if let Err(e) = tmp.persist(&path) {
        log::warn!("Failed to persist canonical profile: {e}");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintStatus {
    pub activity_enabled: bool,
    #[serde(alias = "voice_enabled")]
    pub style_enabled: bool,
    #[serde(alias = "voice_consent")]
    pub style_consent: bool,
    pub current_profile_id: Option<ProfileId>,
    pub activity_samples: usize,
    #[serde(alias = "voice_samples")]
    pub style_samples: usize,
    pub confidence: f64,
    #[serde(default)]
    pub phys_ratio: Option<f64>,
}
