// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI bindings for fingerprint management — status, consent, export.

use super::helpers::get_data_dir;
use crate::RwLockRecover;
use super::types::{
    catch_ffi_panic, FfiConsentResult, FfiFingerprintDimension, FfiFingerprintSnapshot,
    FfiFingerprintStatus, FfiFingerprintSummary, FfiFingerprintVerification,
    FfiKeystrokeTimingArrays, FfiResult,
};
use crate::fingerprint::comparison;
use crate::fingerprint::manager::FingerprintManager;
use log::{debug, info};
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
    let mut guard = manager_lock().lock().map_err(|_| {
        log::error!("fingerprint mutex poisoned; refusing to use potentially corrupt state");
        "Fingerprint manager mutex poisoned".to_string()
    })?;

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

/// Feed a keystroke into the fingerprint manager for style analysis and snapshots.
/// Called from sentinel_inject after each keystroke event.
pub(crate) fn feed_fingerprint_keystroke(
    sample: &crate::jitter::SimpleJitterSample,
    keycode: u16,
    char_value: Option<char>,
) {
    let _ = with_manager(|mgr| {
        mgr.record_activity_sample(sample);
        mgr.record_keystroke_for_style(keycode, char_value);
        Ok(())
    });
}

/// Return fingerprint status: enabled flags and sample counts.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_fingerprint_status() -> FfiFingerprintStatus {
    catch_ffi_panic!(FfiFingerprintStatus {
        style_enabled: false,
        style_samples: 0,
        style_consent: false,
        activity_enabled: false,
        activity_samples: 0,
        maturity: "bootstrap".into(),
    }, {
    log::debug!("ffi_get_fingerprint_status");
    // Read live sample count from the global accumulator.
    let live_activity_samples = crate::fingerprint::global::get_global_accumulator()
        .read_recover()
        .sample_count() as u64;
    match with_manager(|mgr| {
        let status = mgr.status();
        let activity = mgr.current_activity_fingerprint();
        let cfg = &mgr.config();
        let maturity = crate::fingerprint::FingerprintMaturity::from_session_count(
            activity.session_signature.session_count,
            cfg.bootstrap_sessions,
            cfg.advisory_sessions,
        );
        Ok(FfiFingerprintStatus {
            style_enabled: status.style_enabled,
            style_samples: status.style_samples as u64,
            style_consent: status.style_consent,
            activity_enabled: status.activity_enabled,
            activity_samples: live_activity_samples,
            maturity: maturity.to_string().to_lowercase(),
        })
    }) {
        Ok(s) => s,
        Err(_) => FfiFingerprintStatus {
            style_enabled: false,
            style_samples: 0,
            style_consent: false,
            activity_enabled: false,
            activity_samples: 0,
            maturity: "bootstrap".into(),
        },
    }
    })
}

/// Return human-readable fingerprint dimensions with quality score.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_fingerprint_summary() -> FfiFingerprintSummary {
    catch_ffi_panic!(FfiFingerprintSummary {
        success: false,
        dimensions: vec![],
        quality_score: 0.0,
        total_samples: 0,
        dimension_confidence: None,
        circadian_pattern: Vec::new(),
        zone_frequencies: Vec::new(),
        zone_dwell_means: Vec::new(),
        error_message: Some("engine internal error".to_string()),
    }, {
    log::debug!("ffi_get_fingerprint_summary");
    match with_manager(|mgr| {
        let status = mgr.status();
        let activity = mgr.current_activity_fingerprint();

        let conf = status.confidence;

        let mut dimensions = vec![
            FfiFingerprintDimension {
                name: "typing_speed_wpm".into(),
                value: activity.session_signature.mean_typing_speed,
                confidence: conf,
                string_value: None,
            },
            FfiFingerprintDimension {
                name: "iki_mean_ms".into(),
                value: activity.iki_distribution.mean,
                confidence: conf,
                string_value: None,
            },
            FfiFingerprintDimension {
                name: "iki_std_dev_ms".into(),
                value: activity.iki_distribution.std_dev,
                confidence: conf,
                string_value: None,
            },
            FfiFingerprintDimension {
                name: "sentence_pause_ms".into(),
                value: activity.pause_signature.sentence_pause_mean,
                confidence: conf,
                string_value: None,
            },
            FfiFingerprintDimension {
                name: "thinking_pause_ms".into(),
                value: activity.pause_signature.thinking_pause_mean,
                confidence: conf,
                string_value: None,
            },
        ];

        // Dominant keyboard zone
        let dominant = activity.zone_profile.dominant_zone();
        let dominant_freq = activity
            .zone_profile
            .zone_frequencies
            .iter()
            .copied()
            .fold(0.0_f64, f64::max);
        dimensions.push(FfiFingerprintDimension {
            name: "dominant_zone".into(),
            value: dominant_freq,
            confidence: conf,
            string_value: Some(dominant),
        });

        // Peak activity hour from circadian pattern
        let (peak_idx, _) = activity
            .circadian_pattern
            .hourly_activity
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap_or((0, &0.0));
        dimensions.push(FfiFingerprintDimension {
            name: "peak_hour".into(),
            value: peak_idx as f64,
            confidence: conf,
            string_value: Some(format!("{:02}:00", peak_idx)),
        });

        // Typing speed coefficient of variation (std_dev / mean)
        let iki_mean = activity.iki_distribution.mean;
        let iki_std = activity.iki_distribution.std_dev;
        let typing_speed_cv = if iki_mean > 0.0 {
            iki_std / iki_mean
        } else {
            0.0
        };
        dimensions.push(FfiFingerprintDimension {
            name: "typing_speed_cv".into(),
            value: typing_speed_cv,
            confidence: conf,
            string_value: None,
        });

        if let Some(ref style) = mgr.current_style_fingerprint() {
            dimensions.push(FfiFingerprintDimension {
                name: "avg_word_length".into(),
                value: style.avg_word_length(),
                confidence: conf,
                string_value: None,
            });
            dimensions.push(FfiFingerprintDimension {
                name: "correction_rate".into(),
                value: style.correction_rate,
                confidence: conf,
                string_value: None,
            });
        }

        debug!("Fingerprint summary: {} dimensions", dimensions.len());

        let author = mgr.current_author_fingerprint();
        let quality_score = author.confidence;
        let total_samples = status.activity_samples as u64 + status.style_samples as u64;

        let dc = &activity.dimension_confidence;
        let dim_conf = super::types::FfiDimensionConfidence {
            iki: dc.iki,
            zone: dc.zone,
            pause: dc.pause,
            dwell: dc.dwell,
            flight: dc.flight,
            digraph: dc.digraph,
            hurst: dc.hurst,
            circadian: dc.circadian,
        };

        Ok(FfiFingerprintSummary {
            success: true,
            dimensions,
            quality_score,
            total_samples,
            dimension_confidence: Some(dim_conf),
            circadian_pattern: activity.circadian_pattern.hourly_activity.to_vec(),
            zone_frequencies: activity.zone_profile.zone_frequencies.to_vec(),
            zone_dwell_means: activity.zone_profile.zone_dwell_means.to_vec(),
            error_message: None,
        })
    }) {
        Ok(s) => s,
        Err(e) => FfiFingerprintSummary {
            success: false,
            dimensions: Vec::new(),
            quality_score: 0.0,
            total_samples: 0,
            dimension_confidence: None,
            circadian_pattern: Vec::new(),
            zone_frequencies: Vec::new(),
            zone_dwell_means: Vec::new(),
            error_message: Some(e),
        },
    }
    })
}

/// Grant style consent — calls ConsentManager::grant_consent().
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_grant_style_consent() -> FfiConsentResult {
    catch_ffi_panic!(FfiConsentResult {
        success: false,
        consent_given: false,
        error_message: Some("engine internal error".to_string()),
    }, {
    log::debug!("ffi_grant_style_consent");
    match with_manager(|mgr| {
        mgr.consent_manager
            .grant_consent()
            .map_err(|e| format!("Failed to grant consent: {e}"))?;
        mgr.enable_style()
            .map_err(|e| format!("Failed to enable style: {e}"))?;
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
    })
}

/// Revoke style consent — calls FingerprintManager::disable_style().
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_revoke_style_consent() -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_revoke_style_consent");
    match with_manager(|mgr| {
        mgr.disable_style()
            .map_err(|e| format!("Failed to revoke consent: {e}"))?;
        Ok(FfiResult::ok(
            "Style fingerprinting disabled and data deleted",
        ))
    }) {
        Ok(r) => r,
        Err(e) => FfiResult::err(e),
    }
    })
}

/// Reset all fingerprint data (activity + style).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_reset_fingerprint() -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_reset_fingerprint");
    match with_manager(|mgr| {
        mgr.reset();
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
    })
}

/// Export fingerprint as JSON for cloud upload.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_fingerprint_json() -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_export_fingerprint_json");
    match with_manager(|mgr| {
        let author_fp = mgr.current_author_fingerprint();
        let json = serde_json::to_string_pretty(&author_fp)
            .map_err(|e| format!("Serialization failed: {e}"))?;
        Ok(FfiResult::ok(json))
    }) {
        Ok(r) => r,
        Err(e) => FfiResult::err(e),
    }
    })
}

/// Compare current fingerprint against a stored profile.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_verify_fingerprint_match(
    profile_id: String,
) -> FfiFingerprintVerification {
    catch_ffi_panic!(FfiFingerprintVerification {
        success: false,
        similarity: 0.0,
        match_probability: 0.0,
        verdict: "Error".into(),
        verdict_description: "engine internal error".to_string(),
        components: vec![],
        error_message: Some("engine internal error".to_string()),
    }, {
    match with_manager(|mgr| {
        debug!("Verifying fingerprint match against profile {}", profile_id);

        let current = mgr.current_author_fingerprint();
        let stored = mgr
            .load(&profile_id)
            .map_err(|e| format!("Failed to load profile '{}': {e}", profile_id))?;

        let result = comparison::compare_fingerprints(&current, &stored);

        let components = vec![
            FfiFingerprintDimension {
                name: "iki_similarity".into(),
                value: result.components.iki_similarity,
                confidence: result.confidence,
                string_value: None,
            },
            FfiFingerprintDimension {
                name: "zone_similarity".into(),
                value: result.components.zone_similarity,
                confidence: result.confidence,
                string_value: None,
            },
            FfiFingerprintDimension {
                name: "pause_similarity".into(),
                value: result.components.pause_similarity,
                confidence: result.confidence,
                string_value: None,
            },
        ];

        info!(
            "Fingerprint verification: similarity={:.3}, verdict={:?}",
            result.similarity, result.verdict
        );

        Ok(FfiFingerprintVerification {
            success: true,
            similarity: result.similarity,
            match_probability: result.match_probability(),
            verdict: result.verdict.to_string(),
            verdict_description: result.verdict.description().to_string(),
            components,
            error_message: None,
        })
    }) {
        Ok(v) => v,
        Err(e) => FfiFingerprintVerification {
            success: false,
            similarity: 0.0,
            match_probability: 0.0,
            verdict: "Error".into(),
            verdict_description: e.clone(),
            components: Vec::new(),
            error_message: Some(e),
        },
    }
    })
}

/// List stored fingerprint profiles as a JSON array.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_list_fingerprint_profiles() -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    match with_manager(|mgr| {
        debug!("Listing fingerprint profiles");
        let profiles = mgr
            .list_profiles()
            .map_err(|e| format!("Failed to list profiles: {e}"))?;

        let entries: Vec<serde_json::Value> = profiles
            .iter()
            .map(|p| {
                serde_json::json!({
                    "id": p.id,
                    "name": p.name,
                    "created_at": p.created_at.to_rfc3339(),
                    "updated_at": p.updated_at.to_rfc3339(),
                    "sample_count": p.sample_count,
                    "confidence": p.confidence,
                    "has_style": p.has_style,
                    "file_size": p.file_size,
                })
            })
            .collect();

        let json = serde_json::to_string_pretty(&entries)
            .map_err(|e| format!("Serialization failed: {e}"))?;
        Ok(FfiResult::ok(json))
    }) {
        Ok(r) => r,
        Err(e) => FfiResult::err(e),
    }
    })
}

/// Return periodic fingerprint snapshots for evolution charting.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_fingerprint_history() -> Vec<FfiFingerprintSnapshot> {
    catch_ffi_panic!(vec![], {
    log::debug!("ffi_get_fingerprint_history");
    with_manager(|mgr| {
        let snapshots = mgr.get_snapshots();
        let result = snapshots
            .iter()
            .map(|s| FfiFingerprintSnapshot {
                sample_count: s.sample_count,
                timestamp: s.timestamp,
                dimensions: s
                    .dimensions
                    .iter()
                    .map(|(name, value)| FfiFingerprintDimension {
                        name: name.clone(),
                        value: *value,
                        confidence: 1.0,
                        string_value: None,
                    })
                    .collect(),
            })
            .collect();
        Ok(result)
    })
    .unwrap_or_default()
    })
}

#[cfg(target_os = "macos")]
static FINGERPRINT_CAPTURE_HANDLE: Mutex<Option<crate::fingerprint::capture::CaptureHandle>> =
    Mutex::new(None);

/// Start the standalone fingerprint capture consumer (macOS only).
/// No-op if sentinel is already feeding the accumulator.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_fingerprint_capture_start() -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_fingerprint_capture_start");
    let mut guard = FINGERPRINT_CAPTURE_HANDLE.lock().unwrap_or_else(|p| {
        log::warn!("FINGERPRINT_CAPTURE_HANDLE mutex poisoned, recovering");
        p.into_inner()
    });
    if guard.as_ref().is_some_and(|h| h.running.load(std::sync::atomic::Ordering::SeqCst)) {
        return FfiResult::ok("fingerprint capture already running");
    }
    // Ensure any previous (stopped but not yet exited) task is fully cancelled
    // before starting a new one, preventing brief double-consumer window.
    if let Some(old) = guard.take() {
        crate::fingerprint::capture::stop_capture(&old);
    }
    let rt = match super::sentinel::ffi_runtime() {
        Ok(r) => r,
        Err(e) => return FfiResult::err(e),
    };
    match crate::fingerprint::capture::start_capture(&rt) {
        Ok(handle) => {
            *guard = Some(handle);
            FfiResult::ok("fingerprint capture started")
        }
        Err(e) => FfiResult::err(format!("Failed to start fingerprint capture: {e}")),
    }
    })
}

/// Stop the standalone fingerprint capture consumer.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_fingerprint_capture_stop() -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_fingerprint_capture_stop");
    let mut guard = FINGERPRINT_CAPTURE_HANDLE.lock().unwrap_or_else(|p| {
        log::warn!("FINGERPRINT_CAPTURE_HANDLE mutex poisoned, recovering");
        p.into_inner()
    });
    if let Some(handle) = guard.take() {
        crate::fingerprint::capture::stop_capture(&handle);
        FfiResult::ok("fingerprint capture stopped")
    } else {
        FfiResult::ok("fingerprint capture was not running")
    }
    })
}

/// Return whether the standalone fingerprint capture consumer is active.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_fingerprint_capture_is_running() -> bool {
    catch_ffi_panic!(false, {
    FINGERPRINT_CAPTURE_HANDLE
        .lock()
        .unwrap_or_else(|p| {
            log::warn!("FINGERPRINT_CAPTURE_HANDLE mutex poisoned, recovering");
            p.into_inner()
        })
        .as_ref()
        .is_some_and(|h| h.running.load(std::sync::atomic::Ordering::SeqCst))
    })
}

/// Export the long-lived EMA-merged canonical fingerprint as pretty JSON, or None if
/// not yet established.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_canonical_fingerprint_json() -> Option<String> {
    catch_ffi_panic!(None, {
    with_manager(|mgr| {
        Ok(mgr.canonical_profile.as_ref().map(|fp| {
            serde_json::to_string_pretty(fp).unwrap_or_default()
        }))
    }).unwrap_or(None)
    })
}

/// Return raw HT, FT, and IKI arrays from the activity accumulator
/// for behavioral ML inference (dual-channel CNN).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_keystroke_timing_arrays() -> FfiKeystrokeTimingArrays {
    catch_ffi_panic!(FfiKeystrokeTimingArrays {
        hold_times_ns: Vec::new(),
        flight_times_ns: Vec::new(),
        iki_ns: Vec::new(),
        sample_count: 0,
    }, {
    log::debug!("ffi_get_keystroke_timing_arrays");
    use crate::RwLockRecover;

    let accumulator = crate::fingerprint::global::get_global_accumulator();
    let samples = accumulator.read_recover().samples();
    let count = samples.len() as u64;

    let hold_times_ns: Vec<i64> = samples
        .iter()
        .filter_map(|s| s.dwell_time_ns.map(|v| v as i64))
        .collect();
    let flight_times_ns: Vec<i64> = samples
        .iter()
        .filter_map(|s| s.flight_time_ns.map(|v| v as i64))
        .collect();
    let iki_ns: Vec<i64> = samples
        .iter()
        .map(|s| s.duration_since_last_ns as i64)
        .filter(|&v| v > 0)
        .collect();

    FfiKeystrokeTimingArrays {
        hold_times_ns,
        flight_times_ns,
        iki_ns,
        sample_count: count,
    }
    })
}
