// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI bindings for fingerprint management — status, consent, export.

use super::helpers::get_data_dir;
use super::types::{
    FfiConsentResult, FfiFingerprintDimension, FfiFingerprintStatus, FfiFingerprintSummary,
    FfiResult,
};
use crate::fingerprint::manager::FingerprintManager;
use std::sync::Mutex;

static FINGERPRINT_MANAGER: std::sync::OnceLock<Mutex<Option<FingerprintManager>>> =
    std::sync::OnceLock::new();

fn manager_lock() -> &'static Mutex<Option<FingerprintManager>> {
    FINGERPRINT_MANAGER.get_or_init(|| Mutex::new(None))
}

fn with_manager<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce(&mut FingerprintManager) -> Result<T, String>,
{
    let mut guard = manager_lock().lock().unwrap_or_else(|e| e.into_inner());

    if guard.is_none() {
        let data_dir = get_data_dir().ok_or("Cannot determine data directory")?;
        let fp_dir = data_dir.join("fingerprints");
        std::fs::create_dir_all(&fp_dir)
            .map_err(|e| format!("Failed to create fingerprint directory: {e}"))?;
        let mgr = FingerprintManager::new(&fp_dir)
            .map_err(|e| format!("Failed to initialize fingerprint manager: {e}"))?;
        *guard = Some(mgr);
    }

    let mgr = guard
        .as_mut()
        .ok_or("Fingerprint manager unexpectedly None after initialization")?;
    f(mgr)
}

/// Return fingerprint status: enabled flags and sample counts.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_fingerprint_status() -> FfiFingerprintStatus {
    match with_manager(|mgr| {
        let status = mgr.status();
        Ok(FfiFingerprintStatus {
            voice_enabled: status.voice_enabled,
            voice_samples: status.voice_samples as u64,
            voice_consent: status.voice_consent,
            activity_enabled: status.activity_enabled,
            activity_samples: status.activity_samples as u64,
        })
    }) {
        Ok(s) => s,
        Err(_) => FfiFingerprintStatus {
            voice_enabled: false,
            voice_samples: 0,
            voice_consent: false,
            activity_enabled: false,
            activity_samples: 0,
        },
    }
}

/// Return human-readable fingerprint dimensions with quality score.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_fingerprint_summary() -> FfiFingerprintSummary {
    match with_manager(|mgr| {
        let status = mgr.status();
        let activity = mgr.current_activity_fingerprint();

        let mut dimensions = vec![
            FfiFingerprintDimension {
                name: "typing_speed_wpm".into(),
                value: activity.session_signature.mean_typing_speed,
                confidence: status.confidence,
            },
            FfiFingerprintDimension {
                name: "iki_mean_ms".into(),
                value: activity.iki_distribution.mean,
                confidence: status.confidence,
            },
            FfiFingerprintDimension {
                name: "iki_std_dev_ms".into(),
                value: activity.iki_distribution.std_dev,
                confidence: status.confidence,
            },
            FfiFingerprintDimension {
                name: "sentence_pause_ms".into(),
                value: activity.pause_signature.sentence_pause_mean,
                confidence: status.confidence,
            },
            FfiFingerprintDimension {
                name: "thinking_pause_ms".into(),
                value: activity.pause_signature.thinking_pause_mean,
                confidence: status.confidence,
            },
        ];

        if let Some(ref voice) = mgr.current_voice_fingerprint() {
            dimensions.push(FfiFingerprintDimension {
                name: "avg_word_length".into(),
                value: voice.avg_word_length(),
                confidence: status.confidence,
            });
            dimensions.push(FfiFingerprintDimension {
                name: "correction_rate".into(),
                value: voice.correction_rate,
                confidence: status.confidence,
            });
        }

        let activity_quality = (status.activity_samples as f64 / 500.0).min(1.0);
        let total_samples = status.activity_samples as u64 + status.voice_samples as u64;

        Ok(FfiFingerprintSummary {
            success: true,
            dimensions,
            quality_score: activity_quality,
            total_samples,
            error_message: None,
        })
    }) {
        Ok(s) => s,
        Err(e) => FfiFingerprintSummary {
            success: false,
            dimensions: Vec::new(),
            quality_score: 0.0,
            total_samples: 0,
            error_message: Some(e),
        },
    }
}

/// Grant voice consent — calls ConsentManager::grant_consent().
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_grant_voice_consent() -> FfiConsentResult {
    match with_manager(|mgr| {
        mgr.consent_manager
            .grant_consent()
            .map_err(|e| format!("Failed to grant consent: {e}"))?;
        mgr.enable_voice()
            .map_err(|e| format!("Failed to enable voice: {e}"))?;
        Ok(FfiConsentResult {
            success: true,
            consent_given: true,
            error_message: None,
        })
    }) {
        Ok(r) => r,
        Err(e) => FfiConsentResult {
            success: false,
            consent_given: false,
            error_message: Some(e),
        },
    }
}

/// Revoke voice consent — calls FingerprintManager::disable_voice().
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_revoke_voice_consent() -> FfiResult {
    match with_manager(|mgr| {
        mgr.disable_voice()
            .map_err(|e| format!("Failed to revoke consent: {e}"))?;
        Ok(FfiResult::ok(
            "Voice fingerprinting disabled and data deleted",
        ))
    }) {
        Ok(r) => r,
        Err(e) => FfiResult::err(e),
    }
}

/// Reset all fingerprint data (activity + voice).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_reset_fingerprint() -> FfiResult {
    match with_manager(|mgr| {
        mgr.reset_session();
        let profiles = mgr
            .list_profiles()
            .map_err(|e| format!("Failed to list profiles: {e}"))?;
        for p in profiles {
            mgr.delete(&p.id)
                .map_err(|e| format!("Failed to delete profile {}: {e}", p.id))?;
        }
        Ok(FfiResult::ok("All fingerprint data reset"))
    }) {
        Ok(r) => r,
        Err(e) => FfiResult::err(e),
    }
}

/// Export fingerprint as JSON for cloud upload.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_fingerprint_json() -> FfiResult {
    match with_manager(|mgr| {
        let author_fp = mgr.current_author_fingerprint();
        let json = serde_json::to_string_pretty(&author_fp)
            .map_err(|e| format!("Serialization failed: {e}"))?;
        Ok(FfiResult::ok(json))
    }) {
        Ok(r) => r,
        Err(e) => FfiResult::err(e),
    }
}
