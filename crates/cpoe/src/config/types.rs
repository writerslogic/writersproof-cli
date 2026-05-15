// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::defaults;
use crate::error::{Error, Result};
use crate::vdf::params::Parameters as VdfParameters;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Top-level engine configuration with subsystem settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CpopConfig {
    pub data_dir: PathBuf,
    pub watch_dirs: Vec<PathBuf>,
    pub retention_days: u32,
    pub presence: PresenceConfig,
    pub vdf: VdfConfig,
    pub sentinel: SentinelConfig,
    pub research: ResearchConfig,
    pub fingerprint: FingerprintConfig,
    pub privacy: PrivacyConfig,
    pub writersproof: WritersProofConfig,
    pub beacons: BeaconConfig,
    pub trust_bundle: TrustBundleConfig,
}

impl Default for CpopConfig {
    fn default() -> Self {
        Self {
            data_dir: defaults::default_data_dir(),
            watch_dirs: defaults::default_watch_dirs(),
            retention_days: 30,
            presence: PresenceConfig::default(),
            vdf: VdfConfig::default(),
            sentinel: SentinelConfig::default(),
            research: ResearchConfig::default(),
            fingerprint: FingerprintConfig::default(),
            privacy: PrivacyConfig::default(),
            writersproof: WritersProofConfig::default(),
            beacons: BeaconConfig::default(),
            trust_bundle: TrustBundleConfig::default(),
        }
    }
}

/// WritersProof external trust anchor integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WritersProofConfig {
    pub enabled: bool,
    pub base_url: String,
    /// Auto-submit evidence on export
    pub auto_attest: bool,
    /// Queue attestations when offline
    pub offline_queue: bool,
}

impl Default for WritersProofConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: crate::writersproof::client::DEFAULT_API_URL.to_string(),
            auto_attest: false,
            offline_queue: true,
        }
    }
}

/// Temporal beacon configuration.
///
/// When enabled, the system fetches drand and NIST beacon values from
/// WritersProof at each checkpoint, anchoring evidence to publicly
/// verifiable timestamps. This is the mechanism behind T3/T4 security levels.
///
/// Beacons are enabled by default. Disabling caps the maximum security level at T2.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BeaconConfig {
    /// Enable temporal beacon feature globally. Default: true.
    /// When false, drand and NIST beacon fetches are skipped entirely
    /// and the maximum achievable security level is T2 (Standard).
    pub enabled: bool,
    /// Timeout per beacon fetch in seconds. Default: 5.
    pub timeout_secs: u64,
    /// Retry attempts before marking beacon source unavailable. Default: 2.
    pub retries: u32,
    /// Roughtime dual-anchor configuration.
    pub roughtime: RoughtimeConfig,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 5,
            retries: 2,
            roughtime: RoughtimeConfig::default(),
        }
    }
}

impl BeaconConfig {
    /// Clamp timeout and retry values to safe ranges.
    pub fn sanitize(&mut self) {
        self.timeout_secs = self.timeout_secs.clamp(1, 300);
        self.retries = self.retries.clamp(0, 10);
        self.roughtime.sanitize();
    }
}

/// Configuration for Roughtime dual-anchor temporal validation.
///
/// The Roughtime quorum timestamp is compared against an RFC 3161 TSA timestamp.
/// When they disagree beyond `tolerance_secs`, the evidence packet is marked with
/// `time_anchor_disagreement = true` and the dual-anchor proof is omitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RoughtimeConfig {
    /// Enable Roughtime dual-anchor validation. Default: true.
    pub enabled: bool,
    /// Maximum allowed disagreement between RFC 3161 and Roughtime in seconds.
    /// Set to 0 to use the auto-calibrated value (mean + 3σ, capped at 180s).
    /// Default: 0 (auto-calibrate).
    pub tolerance_secs: u64,
    /// Roughtime server list. Each entry is `"name|address|base64_pubkey"`.
    /// When empty, the built-in defaults (Cloudflare, int08h, roughtime.se, txryan) are used.
    pub servers: Vec<String>,
}

impl Default for RoughtimeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tolerance_secs: 0,
            servers: Vec::new(),
        }
    }
}

impl RoughtimeConfig {
    /// Clamp tolerance to at most 180 seconds (the production cap).
    pub fn sanitize(&mut self) {
        if self.tolerance_secs > 180 {
            self.tolerance_secs = 180;
        }
    }

    /// Effective tolerance: the configured value, or the production cap when 0.
    ///
    /// A value of 0 signals "use auto-calibrated tolerance". At runtime the
    /// calibration path sets the actual value; this fallback prevents a zero
    /// tolerance from rejecting all anchors if calibration has not run yet.
    pub fn effective_tolerance(&self) -> u64 {
        if self.tolerance_secs == 0 {
            180
        } else {
            self.tolerance_secs
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FingerprintConfig {
    /// Typing dynamics (captures HOW you type, not WHAT)
    pub activity_enabled: bool,
    /// Writing style analysis (requires explicit consent)
    #[serde(alias = "voice_enabled")]
    pub style_enabled: bool,
    pub retention_days: u32,
    /// Minimum samples before creating a profile
    pub min_samples: u32,
    pub storage_path: PathBuf,
    /// Sessions before anomaly detection activates (Bootstrap → Advisory boundary).
    /// During Bootstrap, IDENTITY_ANOMALY signals are suppressed entirely.
    /// Default: 5.
    pub bootstrap_sessions: u32,
    /// Sessions before full anomaly enforcement begins (Advisory → Enforced boundary).
    /// During Advisory, anomaly flags are recorded but do not block export.
    /// Must be > bootstrap_sessions. Default: 10.
    pub advisory_sessions: u32,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            activity_enabled: true,
            style_enabled: false,
            retention_days: 365,
            min_samples: 100,
            storage_path: dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".writersproof")
                .join("fingerprints"),
            bootstrap_sessions: 5,
            advisory_sessions: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivacyConfig {
    /// Skip password fields and similar sensitive inputs
    pub detect_sensitive_fields: bool,
    pub hash_urls: bool,
    pub obfuscate_titles: bool,
    /// Apps that are never tracked
    pub excluded_apps: Vec<String>,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            detect_sensitive_fields: true,
            hash_urls: true,
            obfuscate_titles: true,
            excluded_apps: vec![
                "1Password".to_string(),
                "Keychain Access".to_string(),
                "System Preferences".to_string(),
                "Terminal".to_string(),
            ],
        }
    }
}

/// Opt-in anonymous research data contribution (anonymized jitter timing).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResearchConfig {
    /// Must be explicitly enabled by user
    pub contribute_to_research: bool,
    pub research_data_dir: PathBuf,
    pub max_sessions: usize,
    pub min_samples_per_session: usize,
    /// Default: 4 hours
    pub upload_interval_secs: u64,
    pub auto_upload: bool,
}

impl Default for ResearchConfig {
    fn default() -> Self {
        Self {
            contribute_to_research: false,
            research_data_dir: dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".writersproof")
                .join("research"),
            max_sessions: 100,
            min_samples_per_session: 10,
            upload_interval_secs: 4 * 60 * 60,
            auto_upload: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PresenceConfig {
    pub challenge_interval_secs: u64,
    pub response_window_secs: u64,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            challenge_interval_secs: 600,
            response_window_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VdfConfig {
    pub iterations_per_second: u64,
    pub min_iterations: u64,
    pub max_iterations: u64,
}

impl Default for VdfConfig {
    fn default() -> Self {
        Self {
            iterations_per_second: 1_000_000,
            min_iterations: 100_000,
            max_iterations: 3_600_000_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelConfig {
    pub auto_start: bool,
    pub heartbeat_interval_secs: u64,
    pub checkpoint_interval_secs: u64,
    pub writersproof_dir: PathBuf,
    pub shadow_dir: PathBuf,
    pub wal_dir: PathBuf,
    pub watch_paths: Vec<PathBuf>,
    pub recursive_watch: bool,

    pub idle_timeout_secs: u64,
    pub idle_check_interval_secs: u64,
    pub allowed_apps: Vec<String>,
    pub blocked_apps: Vec<String>,
    pub track_unknown_apps: bool,
    pub excluded_paths: Vec<PathBuf>,
    pub allowed_extensions: Vec<String>,
    pub hash_on_focus: bool,
    pub hash_on_save: bool,
    pub poll_interval_ms: u64,
    /// Delay (ms) before confirming FocusLost. Suppresses transient focus
    /// bounces during Mission Control, Stage Manager, and full-screen transitions.
    /// 0 = disabled (legacy). Default: 150.
    pub focus_debounce_ms: u64,
    /// When true, a copy of the tracked file is saved at each auto-checkpoint.
    pub snapshots_enabled: bool,
    /// When true, evidence signing is refused if the platform Secure Enclave or
    /// TPM is unavailable and the session would fall back to software-only attestation.
    pub require_hardware_attestation: bool,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        let writersproof_dir = {
            #[cfg(target_os = "macos")]
            {
                // Must match ffi/helpers.rs get_data_dir() and EngineService.swift dataDirectoryPath
                dirs::home_dir()
                    .map(|h| h.join("Library/Application Support/WritersProof"))
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
            }
            #[cfg(not(target_os = "macos"))]
            {
                dirs::data_local_dir()
                    .map(|d| d.join("CPoE"))
                    .unwrap_or_else(|| {
                        dirs::home_dir()
                            .unwrap_or_else(|| std::path::PathBuf::from("."))
                            .join(".writersproof")
                    })
            }
        };

        Self {
            auto_start: false,
            heartbeat_interval_secs: 60,
            checkpoint_interval_secs: 60,
            writersproof_dir: writersproof_dir.clone(),
            shadow_dir: writersproof_dir.join("shadow"),
            wal_dir: writersproof_dir.join("sentinel").join("wal"),
            watch_paths: Vec::new(),
            recursive_watch: true,
            idle_timeout_secs: 1800,
            idle_check_interval_secs: 60,
            allowed_apps: Vec::new(),
            blocked_apps: vec![
                // File managers
                "com.apple.finder".to_string(),
                "explorer".to_string(),
                // WritersProof itself (should not self-monitor)
                "com.writerslogic.witnessd".to_string(),
                "com.writerslogic.cpoe".to_string(),
                // Terminals (not document editors)
                "com.apple.Terminal".to_string(),
                "com.github.wez.wezterm".to_string(),
                "net.kovidgoyal.kitty".to_string(),
                "io.alacritty".to_string(),
                "org.gnome.Terminal".to_string(),
                "org.kde.konsole".to_string(),
                // System overlays (not document contexts)
                "com.apple.Spotlight".to_string(),
                "com.apple.notificationcenterui".to_string(),
            ],
            track_unknown_apps: true,
            excluded_paths: {
                let home = dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("/nonexistent"));
                let lib = home.join("Library");
                vec![
                PathBuf::from("/tmp"),
                PathBuf::from("/var"),
                PathBuf::from("/private/tmp"),
                // Exclude ~/Library subdirectories that contain caches, state,
                // and framework data — but NOT ~/Library/Mobile Documents which
                // is iCloud Drive (Desktop & Documents folders live there when
                // iCloud sync is enabled).
                lib.join("Application Support"),
                lib.join("Caches"),
                lib.join("Preferences"),
                lib.join("Logs"),
                lib.join("Cookies"),
                lib.join("Containers"),
                lib.join("Group Containers"),
                lib.join("Saved Application State"),
                lib.join("Developer"),
                lib.join("Frameworks"),
                PathBuf::from("node_modules"),
                PathBuf::from(".git"),
                PathBuf::from("DerivedData"),
                PathBuf::from("build"),
                PathBuf::from("target"),
                PathBuf::from("dist"),
                PathBuf::from(".venv"),
            ]},
            allowed_extensions: vec![
                // Plain text
                "txt", "md", "markdown", "text", "rtf", // Writing apps
                "scriv", "scrivx", "fdx", "fountain", "mmd", // Document formats
                "doc", "docx", "odt", "pages", "wpd", "wri", "epub",
                // Presentation formats
                "key", "pptx", "ppt", // Publishing / layout
                "indd", "idml", // Novel / story writing
                "story", // Affinity suite
                "afpub", "afdesign", "afphoto", // Outlining / structured writing
                "opml", "itmz", "mm", // Screenplay / script formats
                "draft", // Markup
                "tex", "latex", "org", "rst", "adoc", "asciidoc", // Web writing
                "html", "htm", // Email
                "eml", "emlx", // Code (writers who code)
                "rs", "py", "js", "ts", "go", "java", "swift", "c", "cpp", "h", "rb", "php", "sh",
                "css", "json", "yaml", "yml", "toml", "xml",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            hash_on_focus: true,
            hash_on_save: true,
            poll_interval_ms: 100,
            focus_debounce_ms: 150,
            snapshots_enabled: false,
            require_hardware_attestation: false,
        }
    }
}

impl SentinelConfig {
    /// Set the root directory, deriving shadow and WAL paths from it.
    pub fn with_writersproof_dir(mut self, dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref().to_path_buf();
        self.shadow_dir = dir.join("shadow");
        self.wal_dir = dir.join("sentinel").join("wal");
        self.writersproof_dir = dir;
        self
    }

    /// Check whether an application is allowed for tracking by bundle ID or name.
    ///
    /// Comparisons are case-insensitive to handle platform differences (macOS
    /// bundle IDs are conventionally lowercase but not enforced; Windows app
    /// names vary in casing).
    pub fn is_app_allowed(&self, bundle_id: &str, app_name: &str) -> bool {
        log::trace!("is_app_allowed: bundle_id={bundle_id}, app_name={app_name}");
        for blocked in &self.blocked_apps {
            if blocked.eq_ignore_ascii_case(bundle_id) || blocked.eq_ignore_ascii_case(app_name) {
                return false;
            }
        }
        if self.allowed_apps.is_empty() {
            return self.track_unknown_apps;
        }
        for allowed in &self.allowed_apps {
            if allowed.eq_ignore_ascii_case(bundle_id) || allowed.eq_ignore_ascii_case(app_name) {
                return true;
            }
        }
        self.track_unknown_apps
    }

    /// Check whether a filesystem path is excluded from sentinel tracking.
    ///
    /// Absolute excluded paths match via `starts_with`. Single-component
    /// excluded paths (e.g. "node_modules") match any path component.
    pub fn is_path_excluded(&self, path: &Path) -> bool {
        log::trace!("is_path_excluded: path={}", path.display());
        for excluded in &self.excluded_paths {
            if path.starts_with(excluded) {
                return true;
            }
            // Single-component excludes match anywhere in the path.
            if excluded.components().count() == 1
                && path
                    .components()
                    .any(|c| c.as_os_str() == excluded.as_os_str())
            {
                return true;
            }
        }
        false
    }

    /// Check whether a file extension is in the allowed set.
    ///
    /// Empty `allowed_extensions` means all extensions are allowed.
    /// Extensionless files are always allowed (unsaved documents, Makefile, etc.).
    pub fn is_extension_allowed(&self, path: &Path) -> bool {
        log::trace!("is_extension_allowed: path={}", path.display());
        if self.allowed_extensions.is_empty() {
            return true;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => self
                .allowed_extensions
                .iter()
                .any(|a| a.eq_ignore_ascii_case(ext)),
            None => true,
        }
    }

    /// Validate sentinel config values (nonzero intervals, consistent bounds).
    pub fn validate(&self) -> Result<()> {
        log::debug!("SentinelConfig::validate called");
        fn require_nonzero(val: u64, name: &str) -> Result<()> {
            if val == 0 {
                return Err(Error::validation(format!("{name} must be > 0")));
            }
            Ok(())
        }

        require_nonzero(self.checkpoint_interval_secs, "checkpoint_interval_secs")?;
        require_nonzero(self.heartbeat_interval_secs, "heartbeat_interval_secs")?;
        require_nonzero(self.poll_interval_ms, "poll_interval_ms")?;
        require_nonzero(self.idle_check_interval_secs, "idle_check_interval_secs")?;

        if self.idle_timeout_secs < self.checkpoint_interval_secs {
            return Err(Error::validation(format!(
                "idle_timeout_secs ({}) must be >= checkpoint_interval_secs ({})",
                self.idle_timeout_secs, self.checkpoint_interval_secs
            )));
        }
        Ok(())
    }

    /// Create writersproof, shadow, and WAL directories if they don't exist.
    pub fn ensure_directories(&self) -> Result<()> {
        fs::create_dir_all(&self.writersproof_dir)?;
        fs::create_dir_all(&self.shadow_dir)?;
        fs::create_dir_all(&self.wal_dir)?;
        Ok(())
    }
}

impl CpopConfig {
    /// Validate all config values after load/deserialization.
    pub fn validate(&self) -> Result<()> {
        if self.retention_days == 0 {
            return Err(Error::validation("retention_days must be > 0"));
        }
        if self.vdf.iterations_per_second == 0 {
            return Err(Error::validation("vdf.iterations_per_second must be > 0"));
        }
        if self.vdf.min_iterations == 0 {
            return Err(Error::validation("vdf.min_iterations must be > 0"));
        }
        if self.vdf.max_iterations == 0 {
            return Err(Error::validation("vdf.max_iterations must be > 0"));
        }
        if self.vdf.min_iterations > self.vdf.max_iterations {
            return Err(Error::validation(format!(
                "vdf.min_iterations ({}) must be <= max_iterations ({})",
                self.vdf.min_iterations, self.vdf.max_iterations
            )));
        }
        if self.presence.challenge_interval_secs == 0 {
            return Err(Error::validation(
                "presence.challenge_interval_secs must be > 0",
            ));
        }
        if self.presence.response_window_secs == 0 {
            return Err(Error::validation(
                "presence.response_window_secs must be > 0",
            ));
        }
        if self.fingerprint.advisory_sessions <= self.fingerprint.bootstrap_sessions {
            return Err(Error::validation(format!(
                "fingerprint.advisory_sessions ({}) must be > bootstrap_sessions ({})",
                self.fingerprint.advisory_sessions, self.fingerprint.bootstrap_sessions
            )));
        }
        self.sentinel.validate()?;
        Ok(())
    }
}

impl From<CpopConfig> for VdfParameters {
    fn from(cfg: CpopConfig) -> Self {
        Self {
            iterations_per_second: cfg.vdf.iterations_per_second,
            min_iterations: cfg.vdf.min_iterations,
            max_iterations: cfg.vdf.max_iterations,
        }
    }
}

/// CA trust bundle configuration for WritersProof beacon attestation verification.
///
/// At startup the engine fetches a signed key manifest from `manifest_url` and
/// caches it at `local_cache_path`. If the fetch fails, the engine falls back to
/// the pinned bundle embedded in the binary. When `local_cache_path` exists and
/// is newer than `max_cache_age_secs`, the network fetch is skipped.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TrustBundleConfig {
    /// URL of the signed CA key manifest. Empty string disables remote fetch.
    pub manifest_url: String,
    /// Local path for caching the fetched manifest.
    pub local_cache_path: PathBuf,
    /// Maximum age of a cached manifest before a refresh is attempted (seconds).
    /// Default: 86400 (24 hours).
    pub max_cache_age_secs: u64,
    /// Fetch timeout in seconds. Default: 10.
    pub fetch_timeout_secs: u64,
}

impl Default for TrustBundleConfig {
    fn default() -> Self {
        let cache_dir = dirs::cache_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("WritersProof");
        Self {
            manifest_url: "https://writersproof.com/.well-known/ca-bundle.json".to_string(),
            local_cache_path: cache_dir.join("ca-bundle.json"),
            max_cache_age_secs: 86_400,
            fetch_timeout_secs: 10,
        }
    }
}

impl TrustBundleConfig {
    /// Clamp fetch timeout to a safe range (1–60 s).
    pub fn sanitize(&mut self) {
        self.fetch_timeout_secs = self.fetch_timeout_secs.clamp(1, 60);
    }
}
