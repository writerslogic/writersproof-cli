// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::types::{FfiCalibrationResult, FfiProcessScore};
use crate::forensics::provenance_metrics::ProvenanceMetrics;
use crate::vdf::Parameters;
use std::sync::Mutex;
use std::time::Duration;

use super::sentinel::get_sentinel;

/// Provenance metrics result returned to Swift.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiProvenanceMetrics {
    pub success: bool,
    pub total_fragments: u32,
    pub original_composition_pct: f64,
    pub sourced_unknown_pct: f64,
    pub sourced_verified_pct: f64,
    pub chain_depth: u32,
    pub source_trustworthiness: f64,
    pub authenticity_score: f64,
    pub source_sessions: Vec<FfiSourceSession>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSourceSession {
    pub session_id: String,
    pub app_bundle_id: String,
    pub fragment_count: u32,
    pub verified: bool,
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_provenance_metrics(session_id: String) -> FfiProvenanceMetrics {
    let store = match crate::ffi::helpers::open_store() {
        Ok(s) => s,
        Err(e) => {
            return FfiProvenanceMetrics {
                success: false,
                total_fragments: 0,
                original_composition_pct: 0.0,
                sourced_unknown_pct: 0.0,
                sourced_verified_pct: 0.0,
                chain_depth: 0,
                source_trustworthiness: 0.0,
                authenticity_score: 0.0,
                source_sessions: vec![],
                error_message: Some(e),
            };
        }
    };

    let fragments = match store.get_fragments_for_session(&session_id) {
        Ok(f) => f,
        Err(e) => {
            return FfiProvenanceMetrics {
                success: false,
                total_fragments: 0,
                original_composition_pct: 0.0,
                sourced_unknown_pct: 0.0,
                sourced_verified_pct: 0.0,
                chain_depth: 0,
                source_trustworthiness: 0.0,
                authenticity_score: 0.0,
                source_sessions: vec![],
                error_message: Some(format!("Failed to load fragments: {e}")),
            };
        }
    };

    let metrics = ProvenanceMetrics::compute(&fragments);

    FfiProvenanceMetrics {
        success: true,
        total_fragments: metrics.total_fragments as u32,
        original_composition_pct: metrics.original_composition_ratio * 100.0,
        sourced_unknown_pct: metrics.sourced_unknown_ratio * 100.0,
        sourced_verified_pct: metrics.sourced_verified_ratio * 100.0,
        chain_depth: metrics.chain_depth,
        source_trustworthiness: metrics.source_trustworthiness,
        authenticity_score: metrics.authenticity_score,
        source_sessions: metrics
            .source_sessions
            .iter()
            .map(|s| FfiSourceSession {
                session_id: s.session_id.clone(),
                app_bundle_id: s.app_bundle_id.clone().unwrap_or_default(),
                fragment_count: s.fragment_count as u32,
                verified: s.verified,
            })
            .collect(),
        error_message: None,
    }
}

/// Get provenance metrics for the active sentinel session on a document path.
/// Resolves the document path to a session_id via the sentinel, then delegates
/// to `ffi_get_provenance_metrics`.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_provenance_metrics_for_document(path: String) -> FfiProvenanceMetrics {
    let empty = FfiProvenanceMetrics {
        success: false,
        total_fragments: 0,
        original_composition_pct: 0.0,
        sourced_unknown_pct: 0.0,
        sourced_verified_pct: 0.0,
        chain_depth: 0,
        source_trustworthiness: 0.0,
        authenticity_score: 0.0,
        source_sessions: vec![],
        error_message: None,
    };

    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            return FfiProvenanceMetrics {
                error_message: Some(format!("Invalid path: {e}")),
                ..empty
            };
        }
    };

    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) => s,
        None => {
            return FfiProvenanceMetrics {
                error_message: Some("Sentinel not initialized".to_string()),
                ..empty
            };
        }
    };

    let session_id = match sentinel.session(&path) {
        Ok(s) => s.session_id,
        Err(_) => {
            return FfiProvenanceMetrics {
                error_message: Some(format!("No active session for: {path}")),
                ..empty
            };
        }
    };

    ffi_get_provenance_metrics(session_id)
}

static CALIBRATED_PARAMS: Mutex<Option<Parameters>> = Mutex::new(None);

pub(crate) fn calibrated_params() -> Option<Parameters> {
    *CALIBRATED_PARAMS.lock().unwrap_or_else(|e| {
        log::error!("calibrated params mutex poisoned: {e}");
        e.into_inner()
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_compute_process_score(path: String) -> FfiProcessScore {
    let (_path, _store, events) = match crate::ffi::helpers::load_events_for_path(&path) {
        Ok(v) => v,
        Err(e) => {
            return FfiProcessScore {
                success: false,
                residency: 0.0,
                sequence: 0.0,
                behavioral: 0.0,
                composite: 0.0,
                meets_threshold: false,
                error_message: Some(e),
            };
        }
    };

    if events.is_empty() {
        return FfiProcessScore {
            success: false,
            residency: 0.0,
            sequence: 0.0,
            behavioral: 0.0,
            composite: 0.0,
            meets_threshold: false,
            error_message: Some("No events found for this file".to_string()),
        };
    }

    let profile = crate::forensics::ForensicEngine::evaluate_authorship(&path, &events);

    let residency = if events.len() >= crate::forensics::MIN_EVENTS_FOR_RESIDENCY {
        1.0
    } else {
        events.len() as f64 / crate::forensics::MIN_EVENTS_FOR_RESIDENCY as f64
    };

    let sequence = (profile.metrics.edit_entropy.min(3.0) / 3.0 * 0.5)
        + ((1.0 - profile.metrics.monotonic_append_ratio.get()) * 0.5);

    let behavioral = if profile.assessment == crate::forensics::Assessment::Consistent {
        1.0
    } else {
        0.3
    };

    let composite = crate::forensics::PROCESS_SCORE_WEIGHT_RESIDENCY * residency
        + crate::forensics::PROCESS_SCORE_WEIGHT_SEQUENCE * sequence
        + crate::forensics::PROCESS_SCORE_WEIGHT_BEHAVIORAL * behavioral;
    let meets_threshold = composite >= crate::forensics::PROCESS_SCORE_PASS_THRESHOLD;

    FfiProcessScore {
        success: true,
        residency,
        sequence,
        behavioral,
        composite,
        meets_threshold,
        error_message: None,
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_calibrate_swf() -> FfiCalibrationResult {
    match crate::vdf::calibrate(Duration::from_secs(1)) {
        Ok(params) => {
            // Defense-in-depth: validate even though calibrate() now checks internally.
            let ips = params.iterations_per_second;
            let valid_range = crate::vdf::CALIBRATION_MIN_ITERS_PER_SEC
                ..=crate::vdf::CALIBRATION_MAX_ITERS_PER_SEC;
            if !valid_range.contains(&ips) {
                return FfiCalibrationResult {
                    success: false,
                    iterations_per_second: 0,
                    error_message: Some(format!(
                        "Calibration result out of bounds: {ips} iter/s \
                         (expected {}..={})",
                        crate::vdf::CALIBRATION_MIN_ITERS_PER_SEC,
                        crate::vdf::CALIBRATION_MAX_ITERS_PER_SEC,
                    )),
                };
            }
            {
                let mut cached = CALIBRATED_PARAMS.lock().unwrap_or_else(|e| {
                    log::error!("calibrated params mutex poisoned: {e}");
                    e.into_inner()
                });
                *cached = Some(params);
            }
            FfiCalibrationResult {
                success: true,
                iterations_per_second: ips,
                error_message: None,
            }
        }
        Err(e) => FfiCalibrationResult {
            success: false,
            iterations_per_second: 0,
            error_message: Some(format!("Calibration failed: {}", e)),
        },
    }
}
