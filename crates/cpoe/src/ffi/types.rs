// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

/// Trait for FFI result types that can represent an error.
///
/// All FFI record types that carry `success: bool` + `error_message: Option<String>`
/// implement this so generic helpers can return the correct type on failure.
pub trait FfiErrResult {
    fn ffi_err(msg: impl Into<String>) -> Self;
}

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

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiResult {
    pub success: bool,
    pub message: Option<String>,
    pub error_message: Option<String>,
}

impl FfiResult {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: Some(message.into()),
            error_message: None,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: None,
            error_message: Some(message.into()),
        }
    }
}

impl FfiErrResult for FfiResult {
    fn ffi_err(msg: impl Into<String>) -> Self {
        Self::err(msg)
    }
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
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiLogEntry {
    pub ordinal: u64,
    pub timestamp_ns: i64,
    pub content_hash: String,
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

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSentinelStatus {
    pub running: bool,
    pub tracked_file_count: u32,
    pub tracked_files: Vec<String>,
    pub uptime_secs: u64,
    pub keystroke_count: u64,
    pub focus_duration: String,
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
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiPublishResult {
    pub success: bool,
    pub canonical_url: Option<String>,
    pub record_id: Option<String>,
    pub verification_passed: bool,
    pub checkpoint_count: u64,
    pub error_message: Option<String>,
}

impl FfiErrResult for FfiPublishResult {
    fn ffi_err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            canonical_url: None,
            record_id: None,
            verification_passed: false,
            checkpoint_count: 0,
            error_message: Some(msg.into()),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiFingerprintStatus {
    pub voice_enabled: bool,
    pub voice_samples: u64,
    pub voice_consent: bool,
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
}
