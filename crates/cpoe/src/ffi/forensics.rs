// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::types::{catch_ffi_panic, try_ffi, FfiCalibrationResult, FfiProcessScore};
use crate::forensics::provenance_metrics::ProvenanceMetrics;
use crate::vdf::Parameters;
use std::sync::Mutex;
use std::time::Duration;

use super::sentinel::get_sentinel;

/// Provenance metrics result returned to Swift.
#[derive(Debug, Clone, Default)]
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

crate::ffi::types::impl_ffi_err!(FfiProvenanceMetrics);

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
    catch_ffi_panic!(@err FfiProvenanceMetrics, {
    log::debug!("ffi_get_provenance_metrics: session_id={}", session_id);
    let store = try_ffi!(crate::ffi::helpers::open_store(), FfiProvenanceMetrics);
    let fragments = try_ffi!(
        store.get_fragments_for_session(&session_id),
        FfiProvenanceMetrics
    );

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
    })
}

/// Get provenance metrics for the active sentinel session on a document path.
/// Resolves the document path to a session_id via the sentinel, then delegates
/// to `ffi_get_provenance_metrics`.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_provenance_metrics_for_document(path: String) -> FfiProvenanceMetrics {
    use crate::ffi::types::FfiErrResult;
    catch_ffi_panic!(@err FfiProvenanceMetrics, {
    log::debug!("ffi_get_provenance_metrics_for_document: path={}", path);

    let path = try_ffi!(
        crate::sentinel::helpers::validate_path(&path).map(|p| p.to_string_lossy().to_string()),
        FfiProvenanceMetrics
    );

    let sentinel_opt = get_sentinel();
    let sentinel = match sentinel_opt.as_ref() {
        Some(s) => s,
        None => return FfiProvenanceMetrics::ffi_err("Sentinel not initialized"),
    };

    let session_id = match sentinel.session(&path) {
        Ok(s) => s.session_id,
        Err(_) => return FfiProvenanceMetrics::ffi_err(format!("No active session for: {path}")),
    };

    ffi_get_provenance_metrics(session_id)
    })
}

/// A verified claim from the evidence packet.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiClaim {
    pub claim_type: String,
    pub description: String,
    pub confidence: String,
}

/// Returns which evidence claims are established for a tracked file.
///
/// Inspects the stored events and sentinel session to determine which of the
/// 11 claim types would be present in an exported evidence packet.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_evidence_claims(path: String) -> Vec<FfiClaim> {
    catch_ffi_panic!(Vec::new(), {
    log::debug!("ffi_get_evidence_claims: path={}", path);
    let (path, _store, events) =
        match crate::ffi::helpers::load_events_for_path(&path) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("ffi_get_evidence_claims: load_events failed: {e}");
                return Vec::new();
            }
        };
    if events.is_empty() {
        return Vec::new();
    }

    let mut claims = Vec::new();

    // ChainIntegrity: always present if events exist (chain is checked at export).
    claims.push(FfiClaim {
        claim_type: "ChainIntegrity".into(),
        description: "Content states form an unbroken cryptographic chain".into(),
        confidence: "cryptographic".into(),
    });

    // TimeElapsed: present if any checkpoint has VDF iterations.
    let has_vdf = events.iter().any(|e| e.vdf_iterations > 0);
    if has_vdf {
        claims.push(FfiClaim {
            claim_type: "TimeElapsed".into(),
            description: "Elapsed time bound by sequential work function proof".into(),
            confidence: "cryptographic".into(),
        });
    }

    // KeystrokesVerified: present if we have enough checkpoints with timing data.
    let checkpoint_count = events.len();
    if checkpoint_count >= 3 {
        claims.push(FfiClaim {
            claim_type: "KeystrokesVerified".into(),
            description: format!(
                "Keystroke timing data captured across {checkpoint_count} checkpoints"
            ),
            confidence: "behavioral".into(),
        });

        // BehaviorAnalyzed: requires enough data for forensic analysis.
        claims.push(FfiClaim {
            claim_type: "BehaviorAnalyzed".into(),
            description: "Behavioral timing patterns analyzed across checkpoints".into(),
            confidence: "statistical".into(),
        });
    }

    // Session-based claims: presence, context, dictation, key hierarchy.
    if let Some(sentinel) = get_sentinel() {
        if let Ok(session) = sentinel.session(&path) {
            if session.total_focus_ms > 0 {
                claims.push(FfiClaim {
                    claim_type: "PresenceVerified".into(),
                    description: "Author presence verified via focus monitoring".into(),
                    confidence: "observed".into(),
                });
            }
            if !session.focus_switches.is_empty() {
                claims.push(FfiClaim {
                    claim_type: "ContextsRecorded".into(),
                    description: "Application context periods recorded".into(),
                    confidence: "observed".into(),
                });
            }
            if !session.dictation_events.is_empty() {
                claims.push(FfiClaim {
                    claim_type: "DictationVerified".into(),
                    description: "Dictation events verified with plausibility scoring".into(),
                    confidence: "behavioral".into(),
                });
            }
        }
    }

    // HardwareAttested: check attestation tier.
    let (_, tier_num, _) = crate::ffi::helpers::detect_attestation_tier_info();
    if tier_num >= 3 {
        claims.push(FfiClaim {
            claim_type: "HardwareAttested".into(),
            description: "Signing key bound to hardware security module".into(),
            confidence: "cryptographic".into(),
        });
    }

    // ExternalAnchored: check for beacon attestations.
    let has_beacon = events.iter().any(|e| {
        e.context_note
            .as_ref()
            .map(|n| n.contains("beacon") || n.contains("drand"))
            .unwrap_or(false)
    });
    if has_beacon {
        claims.push(FfiClaim {
            claim_type: "ExternalAnchored".into(),
            description: "Evidence anchored to external time beacon".into(),
            confidence: "cryptographic".into(),
        });
    }

    claims
    })
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
    use crate::ffi::types::FfiErrResult;
    catch_ffi_panic!(@err FfiProcessScore, {
    log::debug!("ffi_compute_process_score: path={}", path);
    let (_path, _store, events) = try_ffi!(
        crate::ffi::helpers::load_events_for_path(&path),
        FfiProcessScore
    );

    if events.is_empty() {
        return FfiProcessScore::ffi_err("No events found for this file");
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
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_calibrate_swf() -> FfiCalibrationResult {
    use crate::ffi::types::FfiErrResult;
    catch_ffi_panic!(@err FfiCalibrationResult, {
    log::debug!("ffi_calibrate_swf");
    match crate::vdf::calibrate(Duration::from_secs(1)) {
        Ok(params) => {
            // Defense-in-depth: validate even though calibrate() now checks internally.
            let ips = params.iterations_per_second;
            let valid_range = crate::vdf::CALIBRATION_MIN_ITERS_PER_SEC
                ..=crate::vdf::CALIBRATION_MAX_ITERS_PER_SEC;
            if !valid_range.contains(&ips) {
                return FfiCalibrationResult::ffi_err(format!(
                    "Calibration result out of bounds: {ips} iter/s \
                     (expected {}..={})",
                    crate::vdf::CALIBRATION_MIN_ITERS_PER_SEC,
                    crate::vdf::CALIBRATION_MAX_ITERS_PER_SEC,
                ));
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
        Err(e) => FfiCalibrationResult::ffi_err(format!("Calibration failed: {e}")),
    }
    })
}
