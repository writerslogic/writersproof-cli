// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

/// Trait for FFI result types that can represent an error.
///
/// All FFI record types that carry `success: bool` + `error_message: Option<String>`
/// implement this so generic helpers can return the correct type on failure.
pub trait FfiErrResult {
    fn ffi_err(msg: impl Into<String>) -> Self;
}

/// Implement `FfiErrResult` for a struct that has `success: bool` and
/// `error_message: Option<String>` fields and derives `Default`.
///
/// Usage: `impl_ffi_err!(FfiArchiveResult);`
macro_rules! impl_ffi_err {
    ($ty:ty) => {
        impl $crate::ffi::types::FfiErrResult for $ty {
            #[allow(clippy::needless_update)]
            fn ffi_err(msg: impl Into<String>) -> Self {
                Self {
                    success: false,
                    error_message: Some(msg.into()),
                    ..Default::default()
                }
            }
        }
    };
}
pub(crate) use impl_ffi_err;

/// Unwrap a `Result<T, E>` inside an FFI function, returning the error as an
/// `FfiErrResult` implementor if the result is `Err`.
///
/// Usage: `let val = try_ffi!(some_result, ReturnType);`
macro_rules! try_ffi {
    ($expr:expr, $ret:ty) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return <$ret as $crate::ffi::types::FfiErrResult>::ffi_err(e.to_string()),
        }
    };
}
pub(crate) use try_ffi;

/// Wrap an FFI function body in `catch_unwind` to convert Rust panics into
/// error values rather than crashing the Swift process.
/// Usage: `catch_ffi_panic!(fallback_expr, { /* statements */ })`
/// where `fallback_expr` is the value returned on panic.
macro_rules! catch_ffi_panic {
    ($fallback:expr, { $($body:tt)* }) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { $($body)* })) {
            Ok(result) => result,
            Err(_) => $fallback,
        }
    };
}
pub(crate) use catch_ffi_panic;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiResult {
    pub success: bool,
    pub message: Option<String>,
    pub error_message: Option<String>,
    /// Machine-readable error code for structured matching on the Swift side.
    /// Well-known codes: "accessibility_permission", "input_monitoring_permission",
    /// "not_initialized", "not_running", "timeout", "data_dir".
    /// None on success or when no specific code applies.
    pub error_code: Option<String>,
}

impl FfiResult {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: Some(message.into()),
            error_message: None,
            error_code: None,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        let mut msg: String = message.into();
        msg.truncate(4096);
        Self {
            success: false,
            message: None,
            error_message: Some(msg),
            error_code: None,
        }
    }
    pub fn err_with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        let mut msg: String = message.into();
        msg.truncate(4096);
        Self {
            success: false,
            message: None,
            error_message: Some(msg),
            error_code: Some(code.into()),
        }
    }
}

impl FfiErrResult for FfiResult {
    fn ffi_err(msg: impl Into<String>) -> Self {
        Self::err(msg)
    }
}

/// Well-known FFI error codes for structured matching.
pub mod error_codes {
    pub const ACCESSIBILITY_PERMISSION: &str = "accessibility_permission";
    pub const INPUT_MONITORING_PERMISSION: &str = "input_monitoring_permission";
    pub const NOT_INITIALIZED: &str = "not_initialized";
    pub const NOT_RUNNING: &str = "not_running";
    pub const TIMEOUT: &str = "timeout";
    pub const DATA_DIR: &str = "data_dir";
}

/// Version and capability information returned by `ffi_engine_version`.
/// Swift checks `contract_version` against its own constant before calling `ffi_init`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiEngineVersion {
    /// Cargo package version string (e.g. "0.9.1").
    pub engine_version: String,
    /// Monotonically incrementing integer; bump whenever any FFI signature changes.
    /// Swift refuses to start if this doesn't match its compiled-in expectation.
    pub contract_version: u32,
    /// Compile-time feature flags that are active (e.g. "ffi", "cpoe_jitter").
    pub features: Vec<String>,
    /// "debug" or "release".
    pub build_profile: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiProcessScore {
    pub success: bool,
    pub residency: f64,
    pub sequence: f64,
    pub behavioral: f64,
    pub composite: f64,
    pub meets_threshold: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCalibrationResult {
    pub success: bool,
    pub iterations_per_second: u64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForensicResult {
    pub success: bool,
    pub assessment_score: f64,
    pub risk_level: String,
    pub anomaly_count: u32,
    pub monotonic_append_ratio: f64,
    pub edit_entropy: f64,
    pub median_interval: f64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiTrackedFile {
    pub path: String,
    pub last_checkpoint_ns: i64,
    pub checkpoint_count: i64,
    pub forensic_score: f64,
    pub risk_level: String,
    pub keystroke_count: u64,
    /// Whether this file meets the process score threshold for verification.
    /// Derived from the engine's forensic analysis; Swift should use this
    /// rather than re-deriving from forensic_score thresholds.
    pub meets_threshold: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiLogEntry {
    pub ordinal: u64,
    pub timestamp_ns: i64,
    pub content_hash: String,
    pub event_hash: String,
    pub file_size: i64,
    pub size_delta: i32,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiStatus {
    pub initialized: bool,
    pub data_dir: String,
    pub tracked_file_count: u32,
    pub total_checkpoints: u64,
    pub swf_iterations_per_second: u64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDashboardMetrics {
    pub success: bool,
    pub total_files: u32,
    pub total_checkpoints: u64,
    pub total_words_witnessed: u64,
    pub current_streak_days: u32,
    pub longest_streak_days: u32,
    pub active_days_30d: u32,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiActivityPoint {
    pub day_timestamp: i64,
    pub checkpoint_count: u32,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiAttestationInfo {
    pub tier: u8,
    pub tier_label: String,
    pub provider_type: String,
    pub hardware_bound: bool,
    pub supports_sealing: bool,
    pub has_monotonic_counter: bool,
    pub has_secure_clock: bool,
    pub device_id: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiAttestationResponse {
    pub success: bool,
    pub signature_b64: String,
    pub public_key_b64: String,
    /// COSE_Sign1 envelope wrapping the attestation payload, base64-encoded.
    /// Per draft-condrey-rats-pop, device attestation uses COSE_Sign1 as the
    /// outer envelope with the platform attestation object as payload.
    pub cose_sign1_b64: String,
    pub device_id: String,
    pub model: String,
    pub os_version: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDeviceKey {
    pub public_key_b64: String,
    pub device_id: String,
    pub hardware_bound: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiEphemeralSessionResult {
    pub success: bool,
    pub session_id: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiEphemeralFinalizeResult {
    pub success: bool,
    pub war_block: String,
    pub compact_ref: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiEphemeralStatusResult {
    pub success: bool,
    pub checkpoint_count: u64,
    pub keystroke_count: u64,
    pub elapsed_secs: f64,
    pub error_message: Option<String>,
}

/// OS-level permission state for sentinel keystroke capture.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum FfiPermissionState {
    /// Both Accessibility and Input Monitoring are granted.
    Full,
    /// Accessibility granted but Input Monitoring is not; keystroke capture unavailable.
    KeystrokeDegraded,
    /// All required permissions revoked; file-hash monitoring only.
    Revoked,
    /// Sentinel not initialized; permission state unknown.
    Unknown,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSentinelStatus {
    pub running: bool,
    pub tracked_file_count: u32,
    pub tracked_files: Vec<String>,
    pub uptime_secs: u64,
    pub keystroke_count: u64,
    pub focus_duration: String,
    pub permission_state: FfiPermissionState,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiWitnessingStatus {
    pub is_tracking: bool,
    pub document_path: Option<String>,
    pub keystroke_count: u64,
    pub elapsed_secs: f64,
    pub change_count: u64,
    pub save_count: u64,
    pub event_count: u64,
    pub forensic_score: f64,
    pub last_paste_chars: i64,
    pub event_confidence: f64,
    /// Whether the tracked document currently has window focus.
    pub document_has_focus: bool,
    /// Whether keystroke capture is active. When false, the sentinel is running
    /// in degraded (focus-only) mode — keystrokes are not being counted.
    pub keystroke_capture_active: bool,
    pub error_message: Option<String>,
    /// Ratio of editing keystrokes (delete, undo, cut, paste) to total keystrokes.
    pub editing_ratio: f64,
    /// Session activity classification: "composing", "editing", "mixed", or empty if insufficient data.
    pub session_activity: String,
    /// Total deletion keystrokes (backward + forward + word + line).
    pub total_deletions: u64,
    /// Number of undo operations in this session.
    pub undo_count: u64,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiPublishResult {
    pub success: bool,
    pub canonical_url: Option<String>,
    pub record_id: Option<String>,
    pub verification_passed: bool,
    pub checkpoint_count: u64,
    pub error_message: Option<String>,
}

crate::ffi::types::impl_ffi_err!(FfiPublishResult);

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiFingerprintStatus {
    pub style_enabled: bool,
    pub style_samples: u64,
    pub style_consent: bool,
    pub activity_enabled: bool,
    pub activity_samples: u64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiConsentResult {
    pub success: bool,
    pub consent_given: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiFingerprintSummary {
    pub success: bool,
    pub dimensions: Vec<FfiFingerprintDimension>,
    pub quality_score: f64,
    pub total_samples: u64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiFingerprintDimension {
    pub name: String,
    pub value: f64,
    pub confidence: f64,
    /// Human-readable representation for non-numeric dimensions
    /// (e.g., dominant_zone="Right Index (32%)", peak_hour="14").
    pub string_value: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiFingerprintVerification {
    pub success: bool,
    /// Overall similarity score (0.0-1.0).
    pub similarity: f64,
    /// Match probability (0.0-1.0). Currently mirrors similarity.
    pub match_probability: f64,
    /// Machine-readable verdict (e.g., "SameAuthor", "Inconclusive").
    pub verdict: String,
    /// Human-readable verdict description.
    pub verdict_description: String,
    /// Per-dimension similarity breakdown.
    pub components: Vec<FfiFingerprintDimension>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiFingerprintSnapshot {
    pub sample_count: u64,
    pub timestamp: i64,
    pub dimensions: Vec<FfiFingerprintDimension>,
}

/// Raw keystroke timing arrays for behavioral ML inference.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiKeystrokeTimingArrays {
    pub hold_times_ns: Vec<i64>,
    pub flight_times_ns: Vec<i64>,
    pub iki_ns: Vec<i64>,
    pub sample_count: u64,
}

/// A pair of documents detected as frequently co-edited.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCoEditedPair {
    pub path_a: String,
    pub path_b: String,
    pub switch_count: u32,
    pub avg_gap_ms: f64,
}
