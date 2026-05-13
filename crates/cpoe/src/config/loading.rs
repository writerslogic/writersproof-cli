// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::defaults;
use super::types::*;
use anyhow::Result;
use std::fs;
use std::path::Path;

impl CpopConfig {
    /// Load config from `data_dir/writersproof.json`, falling back to defaults and legacy files.
    ///
    /// AUD-140: Reads the file directly instead of checking exists() first to avoid TOCTOU.
    /// AUD-141: Distinguishes file-not-found (fall through to defaults) from parse errors
    /// (propagated to caller).
    pub fn load_or_default(data_dir: &Path) -> Result<Self> {
        let config_path = data_dir.join("writersproof.json");

        match fs::read_to_string(&config_path) {
            Ok(raw) => {
                let mut config: CpopConfig = serde_json::from_str(&raw).map_err(|e| {
                    anyhow::anyhow!("failed to parse {}: {}", config_path.display(), e)
                })?;
                config.data_dir = data_dir.to_path_buf();
                config.beacons.sanitize();
                config.validate()?;
                return Ok(config);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Fall through to legacy / default path
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to read {}: {}",
                    config_path.display(),
                    e
                ));
            }
        }

        let mut config = Self::default_with_dir(data_dir);
        let cli_path = data_dir.join("config.json");
        let gui_path = data_dir.join("engine_config.json");

        match fs::read_to_string(&cli_path) {
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(val) => {
                    if let Some(vdf) = val.get("vdf") {
                        let parsed = vdf
                            .get("iterations_per_second")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(config.vdf.iterations_per_second);
                        if parsed == 0 {
                            log::warn!(
                                "legacy {}: vdf.iterations_per_second is 0; using default",
                                cli_path.display()
                            );
                        } else {
                            config.vdf.iterations_per_second = parsed;
                        }
                    }
                }
                Err(e) => {
                    log::warn!(
                        "failed to parse legacy {}; settings will use defaults: {}",
                        cli_path.display(),
                        e
                    );
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                log::warn!("failed to read legacy {}: {}", cli_path.display(), e);
            }
        }

        match fs::read_to_string(&gui_path) {
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(val) => {
                    config.retention_days = val
                        .get("retention_days")
                        .and_then(|v| v.as_u64())
                        .map(|v| v.min(u32::MAX as u64) as u32)
                        .unwrap_or(config.retention_days);
                    if let Some(dirs) = val.get("watch_dirs").and_then(|v| v.as_array()) {
                        config.watch_dirs = dirs
                            .iter()
                            .filter_map(|v| v.as_str().map(std::path::PathBuf::from))
                            .collect();
                    }
                }
                Err(e) => {
                    log::warn!(
                        "failed to parse legacy {}; settings will use defaults: {}",
                        gui_path.display(),
                        e
                    );
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                log::warn!("failed to read legacy {}: {}", gui_path.display(), e);
            }
        }

        config.persist()?;
        Ok(config)
    }

    /// Create default config rooted at the given data directory.
    pub fn default_with_dir(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            watch_dirs: defaults::default_watch_dirs(),
            retention_days: 30,
            presence: PresenceConfig::default(),
            vdf: VdfConfig::default(),
            sentinel: SentinelConfig::default(),
            research: ResearchConfig {
                research_data_dir: data_dir.join("research"),
                ..Default::default()
            },
            fingerprint: FingerprintConfig {
                storage_path: data_dir.join("fingerprints"),
                ..Default::default()
            },
            privacy: PrivacyConfig::default(),
            writersproof: WritersProofConfig::default(),
            beacons: BeaconConfig::default(),
            trust_bundle: crate::config::TrustBundleConfig::default(),
        }
    }

    /// Write config to `writersproof.json` atomically with restrictive permissions (0600 on Unix).
    ///
    /// Uses write-to-temp + rename so a crash mid-write cannot corrupt the config.
    pub fn persist(&self) -> Result<()> {
        fs::create_dir_all(&self.data_dir)?;
        let config_path = self.data_dir.join("writersproof.json");
        let raw = serde_json::to_string_pretty(self)?;

        crate::crypto::atomic_write(&config_path, raw.as_bytes())?;
        crate::crypto::restrict_permissions(&config_path, 0o600)?;
        Ok(())
    }
}
