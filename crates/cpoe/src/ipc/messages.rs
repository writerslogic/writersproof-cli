// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// 256 KB cap on IPC frames. Typical messages are <1KB (keystroke events,
/// status queries, session commands). 256KB is generous while limiting
/// allocation from untrusted length-prefix to a reasonable bound.
pub(crate) const MAX_MESSAGE_SIZE: usize = 256 * 1024;

/// Maximum concurrent IPC connections. Prevents local DoS via connection flooding.
pub(crate) const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Maximum plausible jitter interval: 1 minute in nanoseconds.
const MAX_JITTER_INTERVAL_NS: u64 = 60_000_000_000;

/// Maximum plausible absolute timestamp: year ~2100 in nanoseconds.
const MAX_TIMESTAMP_NS: i64 = 4_102_444_800_000_000_000;

/// Maximum length for short string fields (version, tier).
const MAX_SHORT_STRING: usize = 64;

/// Maximum length for message body fields (SystemAlert message).
const MAX_ALERT_MESSAGE: usize = 4096;

/// Maximum wall-clock skew for Pulse timestamps (5 minutes in nanoseconds).
///
/// Wall-clock (`SystemTime`) is used rather than monotonic time because Pulse
/// events arrive from external IPC clients that may run on different monotonic
/// bases. The 5-minute tolerance accommodates NTP drift, VM clock skew, and
/// moderate sleep/wake lag while still rejecting stale replays and far-future
/// injection attempts.
const MAX_PULSE_CLOCK_SKEW_NS: i64 = 5 * 60 * 1_000_000_000;

/// Reject paths with `..` components, relative paths, or paths that resolve
/// into system directories. Called on every PathBuf deserialized from an IPC
/// message before any handler touches the filesystem.
fn validate_ipc_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "Relative path rejected (must be absolute): '{}'",
            path.display()
        ));
    }

    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(format!("Path traversal rejected: '{}'", path.display()));
        }
    }

    // Reject Windows UNC paths which can embed traversal sequences.
    #[cfg(target_os = "windows")]
    {
        let s = path.to_string_lossy();
        if s.starts_with("\\\\") {
            return Err(format!("UNC paths rejected: '{}'", path.display()));
        }
        // Reject NTFS Alternate Data Streams (e.g. "file.txt:hidden:$DATA").
        // After the drive letter prefix (e.g. "C:"), any ':' indicates ADS.
        if s.chars().skip(2).any(|c| c == ':') {
            return Err(format!(
                "NTFS alternate data stream rejected: '{}'",
                path.display()
            ));
        }
    }

    // Canonicalize to resolve symlinks before the prefix check. Fall back to a
    // logically-resolved path (collapsing any `.` and `..` components) when the
    // target does not exist yet (e.g. a new document path). Using the raw path
    // directly would allow `/etc/../home/user/evil` to bypass prefix checks.
    let canonical: std::borrow::Cow<'_, Path> = match std::fs::canonicalize(path) {
        Ok(p) => std::borrow::Cow::Owned(p),
        Err(_) => {
            let mut stack: Vec<Component<'_>> = Vec::new();
            for component in path.components() {
                match component {
                    Component::ParentDir => {
                        // Don't pop past Prefix or RootDir (e.g. `C:\` or `/`).
                        match stack.last() {
                            Some(Component::Prefix(_) | Component::RootDir) | None => {}
                            _ => {
                                stack.pop();
                            }
                        }
                    }
                    Component::CurDir => {}
                    other => stack.push(other),
                }
            }
            let mut resolved = PathBuf::new();
            for part in stack {
                resolved.push(part);
            }
            std::borrow::Cow::Owned(resolved)
        }
    };

    // Symlink check on the canonical path (not the original) to avoid a
    // TOCTOU race where the symlink target changes between resolution and use.
    if canonical.is_symlink() {
        return Err(format!(
            "Symlink rejected at IPC boundary: '{}'",
            canonical.display()
        ));
    }

    // First line of defense at IPC boundary; sentinel::validate_path() does a
    // second check post-canonicalization.
    if is_blocked_system_path(&canonical)? {
        return Err("Access to system directory denied".to_string());
    }

    Ok(())
}

/// Blocked system directory prefixes for Unix platforms.
#[cfg(unix)]
pub(crate) const BLOCKED_UNIX_PREFIXES: &[&str] = &[
    "/etc/",
    "/var/root/",
    "/System/",
    "/Library/",
    "/proc/",
    "/dev/",
    "/sys/",
    "/root/",
    "/private/etc/",
    "/private/var/root/",
    "/boot/",
    "/sbin/",
    "/bin/",
    "/usr/",
];

/// Blocked system directory prefixes for Windows platforms.
#[cfg(target_os = "windows")]
pub(crate) const BLOCKED_WINDOWS_PREFIXES: &[&str] = &[
    r"c:\windows\",
    r"c:\program files\",
    r"c:\program files (x86)\",
    r"c:\programdata\",
];

/// Check whether a path falls under a blocked system directory.
///
/// Shared by both IPC-layer validation (`validate_ipc_path`) and
/// sentinel-layer validation (`validate_canonical_path`).
pub(crate) fn is_blocked_system_path(path: &Path) -> Result<bool, String> {
    #[cfg(unix)]
    {
        let s = path.to_string_lossy();
        // HFS+ (macOS default) is case-insensitive; compare lowercased on macOS.
        #[cfg(target_os = "macos")]
        let s_cmp = s.to_lowercase();
        #[cfg(not(target_os = "macos"))]
        let s_cmp = s.as_ref().to_owned();
        for prefix in BLOCKED_UNIX_PREFIXES {
            if s_cmp.starts_with(&prefix.to_lowercase()) {
                return Ok(true);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let s = path.to_string_lossy();
        let lower = s.to_lowercase();
        // Strip UNC extended-length, device namespace, and NT-style prefixes so
        // \\?\C:\Windows\..., \\?\UNC\..., \??\C:\..., and \\.\C:\... are all
        // caught. \\?\UNC\ must be checked before \\?\ to avoid partial strip.
        let normalized = lower
            .strip_prefix(r"\\?\unc\")
            .or_else(|| lower.strip_prefix(r"\\?\"))
            .or_else(|| lower.strip_prefix(r"\??\"))
            .or_else(|| lower.strip_prefix(r"\\.\"))
            .unwrap_or(&lower);
        for prefix in BLOCKED_WINDOWS_PREFIXES {
            if normalized.starts_with(prefix) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// IPC message protocol between the engine (Brain) and GUI (Face).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    /// Client initiates connection with its version string.
    Handshake { version: String },
    /// Begin witnessing a file at the given path.
    StartWitnessing { file_path: PathBuf },
    /// Stop witnessing a specific file, or all files if None.
    StopWitnessing { file_path: Option<PathBuf> },
    /// Request current daemon status.
    GetStatus,

    /// Request the session attestation nonce bound to TPM/TEE state.
    GetAttestationNonce,
    /// Export evidence with a verifier-provided nonce for replay prevention.
    ExportWithNonce {
        file_path: PathBuf,
        title: String,
        verifier_nonce: [u8; 32],
    },
    /// Verify evidence with optional nonce validation.
    VerifyWithNonce {
        evidence_path: PathBuf,
        expected_nonce: Option<[u8; 32]>,
    },

    /// Keystroke timing jitter sample from the GUI.
    Pulse(SimpleJitterSample),
    /// Notification that a checkpoint was persisted.
    CheckpointCreated { id: i64, hash: [u8; 32] },
    /// System-level alert forwarded to the GUI.
    SystemAlert { level: String, message: String },

    /// Keep-alive ping from client.
    Heartbeat,

    /// Generic success response with optional detail message.
    Ok { message: Option<String> },
    /// Generic error response with structured error code.
    Error { code: IpcErrorCode, message: String },
    /// Server acknowledges handshake with its version.
    HandshakeAck {
        version: String,
        server_version: String,
    },
    /// Server acknowledges heartbeat with current timestamp.
    HeartbeatAck { timestamp_ns: u64 },
    /// Daemon status: running state, tracked files, and uptime.
    StatusResponse {
        running: bool,
        tracked_files: Vec<String>,
        uptime_secs: u64,
    },
    /// Return the 32-byte attestation nonce for this session.
    AttestationNonceResponse { nonce: [u8; 32] },
    /// Result of a nonce-bound evidence export.
    NonceExportResponse {
        success: bool,
        output_path: Option<String>,
        packet_hash: Option<String>,
        verifier_nonce: Option<String>,
        attestation_nonce: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        attestation_report: Option<String>,
        error: Option<String>,
    },
    /// Result of a nonce-bound evidence verification.
    NonceVerifyResponse {
        valid: bool,
        nonce_valid: bool,
        checkpoint_count: u64,
        total_elapsed_time_secs: f64,
        verifier_nonce: Option<String>,
        attestation_nonce: Option<String>,
        errors: Vec<String>,
    },

    /// Verify an evidence packet at the given path.
    VerifyFile { path: PathBuf },
    /// Result of evidence file verification.
    VerifyFileResponse {
        success: bool,
        checkpoint_count: u32,
        signature_valid: bool,
        chain_integrity: bool,
        vdf_iterations_per_second: u64,
        error: Option<String>,
    },

    /// Export evidence for a file at the specified tier.
    ExportFile {
        path: PathBuf,
        tier: String,
        output: PathBuf,
    },
    /// Result of evidence file export.
    ExportFileResponse {
        success: bool,
        error: Option<String>,
    },

    /// Request forensic analysis of a tracked file.
    GetFileForensics { path: PathBuf },
    /// Forensic analysis results for a tracked file.
    ForensicsResponse {
        assessment_score: f64,
        risk_level: String,
        anomaly_count: u32,
        monotonic_append_ratio: f64,
        edit_entropy: f64,
        median_interval: f64,
        /// Biological cadence steadiness (0.0-1.0, higher = steadier typing rhythm)
        biological_cadence_score: f64,
        error: Option<String>,
    },

    /// Request composite process score for a tracked file.
    ComputeProcessScore { path: PathBuf },
    /// Composite process score breakdown.
    ProcessScoreResponse {
        residency: f64,
        sequence: f64,
        behavioral: f64,
        composite: f64,
        meets_threshold: bool,
        error: Option<String>,
    },

    /// Create a manual checkpoint for a tracked file.
    CreateFileCheckpoint { path: PathBuf, message: String },
    /// Result of checkpoint creation.
    CheckpointResponse {
        success: bool,
        hash: Option<String>,
        error: Option<String>,
    },

    /// Browser keystroke event from content script via native messaging.
    /// Used for dual-source validation (browser + OS-level keystroke correlation).
    BrowserKeystroke {
        /// Keystroke timestamp from `performance.now()` (milliseconds, browser-relative).
        timestamp_ms: f64,
        /// The `key` property from the browser KeyboardEvent (e.g., "a", "Enter").
        key: String,
        /// The `code` property from the browser KeyboardEvent (e.g., "KeyA", "Enter").
        code: String,
        /// Browser tab ID for session correlation.
        tab_id: u32,
    },
    /// Batch of browser keystroke events (sent every 500ms to avoid flooding).
    BrowserKeystrokeBatch {
        /// Array of (timestamp_ms, key, code) tuples.
        keystrokes: Vec<(f64, String, String)>,
        /// Browser tab ID for session correlation.
        tab_id: u32,
    },
}

impl IpcMessage {
    /// Validate all PathBuf fields in this message against traversal attacks,
    /// and bounds-check attacker-controlled numeric fields (e.g. Pulse jitter).
    /// Must be called immediately after deserialization, before dispatching to any handler.
    pub(crate) fn validate_paths(&self) -> Result<(), String> {
        match self {
            IpcMessage::Handshake { version } => {
                if version.len() > MAX_SHORT_STRING {
                    return Err("Handshake version too long".to_string());
                }
            }
            IpcMessage::SystemAlert { level, message } => {
                if level.len() > MAX_SHORT_STRING {
                    return Err("SystemAlert level too long".to_string());
                }
                if message.len() > MAX_ALERT_MESSAGE {
                    return Err("SystemAlert message too long".to_string());
                }
            }
            IpcMessage::StartWitnessing { file_path } => {
                validate_ipc_path(file_path)?;
            }
            IpcMessage::StopWitnessing { file_path: Some(p) } => {
                validate_ipc_path(p)?;
            }
            IpcMessage::ExportWithNonce {
                file_path, title, ..
            } => {
                validate_ipc_path(file_path)?;
                if title.len() > MAX_ALERT_MESSAGE {
                    return Err("ExportWithNonce title too long".to_string());
                }
            }
            IpcMessage::VerifyWithNonce { evidence_path, .. } => {
                validate_ipc_path(evidence_path)?;
            }
            IpcMessage::VerifyFile { path } => {
                validate_ipc_path(path)?;
            }
            IpcMessage::ExportFile {
                path, output, tier, ..
            } => {
                validate_ipc_path(path)?;
                validate_ipc_path(output)?;
                if tier.len() > MAX_SHORT_STRING {
                    return Err(format!(
                        "ExportFile tier too long: {} bytes (max {})",
                        tier.len(),
                        MAX_SHORT_STRING
                    ));
                }
            }
            IpcMessage::GetFileForensics { path } => {
                validate_ipc_path(path)?;
            }
            IpcMessage::ComputeProcessScore { path } => {
                validate_ipc_path(path)?;
            }
            IpcMessage::CreateFileCheckpoint { path, message } => {
                validate_ipc_path(path)?;
                if message.len() > MAX_ALERT_MESSAGE {
                    return Err(format!(
                        "CreateFileCheckpoint message too long: {} bytes (max {})",
                        message.len(),
                        MAX_ALERT_MESSAGE
                    ));
                }
            }
            IpcMessage::Pulse(sample) => {
                if sample.timestamp_ns < 0 || sample.timestamp_ns > MAX_TIMESTAMP_NS {
                    return Err(format!(
                        "Pulse timestamp_ns out of bounds: {}",
                        sample.timestamp_ns
                    ));
                }
                // Reject timestamps more than 5 minutes from wall clock to
                // prevent replay or far-future injection.
                {
                    let now_ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as i64)
                        .unwrap_or(0);
                    let skew = (sample.timestamp_ns as i128 - now_ns as i128).unsigned_abs();
                    if skew > MAX_PULSE_CLOCK_SKEW_NS as u128 {
                        return Err(format!(
                            "Pulse timestamp_ns too far from wall clock: {}",
                            sample.timestamp_ns
                        ));
                    }
                }
                if sample.duration_since_last_ns > MAX_JITTER_INTERVAL_NS {
                    return Err(format!(
                        "Pulse duration_since_last_ns out of bounds: {}",
                        sample.duration_since_last_ns
                    ));
                }
            }
            IpcMessage::BrowserKeystroke { key, code, .. } => {
                if key.len() > MAX_SHORT_STRING {
                    return Err("BrowserKeystroke key too long".to_string());
                }
                if code.len() > MAX_SHORT_STRING {
                    return Err("BrowserKeystroke code too long".to_string());
                }
            }
            IpcMessage::BrowserKeystrokeBatch { keystrokes, .. } => {
                if keystrokes.len() > 200 {
                    return Err(format!(
                        "BrowserKeystrokeBatch too large: {} (max 200)",
                        keystrokes.len()
                    ));
                }
                for (_, key, code) in keystrokes {
                    if key.len() > MAX_SHORT_STRING || code.len() > MAX_SHORT_STRING {
                        return Err("BrowserKeystrokeBatch entry too long".to_string());
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Structured error codes for IPC error responses.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IpcErrorCode {
    /// Unclassified error.
    Unknown = 0,
    /// Malformed or unrecognized message.
    InvalidMessage = 1,
    /// Referenced file does not exist.
    FileNotFound = 2,
    /// File is already being witnessed.
    AlreadyTracking = 3,
    /// File is not currently being witnessed.
    NotTracking = 4,
    /// Caller lacks permission for the requested operation.
    PermissionDenied = 5,
    /// Client/server protocol version incompatibility.
    VersionMismatch = 6,
    /// Unexpected internal failure.
    InternalError = 7,
    /// Supplied nonce is invalid or does not match.
    NonceInvalid = 8,
    /// Engine identity or subsystem not yet initialized.
    NotInitialized = 9,
    /// Request rejected due to rate limiting.
    RateLimited = 10,
}

/// Dispatch trait for handling incoming IPC messages and producing responses.
pub trait IpcMessageHandler: Send + Sync + 'static {
    /// Process an incoming message and return the response to send back.
    fn handle(&self, msg: IpcMessage) -> IpcMessage;
}
