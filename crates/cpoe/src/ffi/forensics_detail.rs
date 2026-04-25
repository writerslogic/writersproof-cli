// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::open_store;
use crate::utils::finite_or;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiForensicBreakdown {
    pub success: bool,
    pub monotonic_append_ratio: f64,
    pub edit_entropy: f64,
    pub median_interval: f64,
    pub mean_iki_ms: f64,
    pub std_dev_iki_ms: f64,
    pub coefficient_of_variation: f64,
    pub burst_count: u32,
    pub pause_count: u32,
    pub mean_bps: f64,
    pub max_bps: f64,
    pub hurst_exponent: Option<f64>,
    pub assessment_score: f64,
    pub perplexity_score: f64,
    pub risk_level: String,
    pub protocol_verdict: String,
    pub anomaly_count: u32,
    pub anomalies: Vec<FfiAnomaly>,
    /// Writing mode: "cognitive", "transcriptive", "mixed", or "insufficient".
    pub writing_mode: String,
    /// Composite cognitive score (0.0 = transcriptive, 1.0 = cognitive).
    pub writing_mode_score: f64,
    /// Confidence in writing mode classification (0.0-1.0).
    pub writing_mode_confidence: f64,
    /// Number of burst->delete->burst revision cycles detected.
    pub revision_cycle_count: u32,
    /// Fraction of keystrokes that are backspace/delete.
    pub correction_ratio: f64,
    /// CV of typing speed within bursts.
    pub burst_speed_cv: f64,
    /// Pause depth distribution: [sentence_fraction, paragraph_fraction, deep_fraction].
    pub pause_depth_distribution: Vec<f64>,
    /// Joint signal consistency: 0.0 = consistent, >0.5 = possible spoofing.
    pub spoofing_indicator: f64,
    /// Sentence initiation delay ratio (cognitive: 8-30x, transcriptive: 2-4x).
    pub sentence_initiation_ratio: f64,
    /// Lexical retrieval delay correlation (cognitive: >0.25, transcriptive: ~0).
    pub lrd_correlation: f64,
    /// IKI distribution modality (cognitive: multi-modal >0.7, transcriptive: <0.3).
    pub iki_modality_score: f64,
    /// Deviation from personal writing baseline (0 = normal, >0.6 = anomalous).
    pub baseline_deviation: f64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiAnomaly {
    pub timestamp_epoch_ms: Option<i64>,
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
}

impl FfiForensicBreakdown {
    fn error(msg: String) -> Self {
        Self {
            success: false,
            monotonic_append_ratio: 0.0,
            edit_entropy: 0.0,
            median_interval: 0.0,
            mean_iki_ms: 0.0,
            std_dev_iki_ms: 0.0,
            coefficient_of_variation: 0.0,
            burst_count: 0,
            pause_count: 0,
            mean_bps: 0.0,
            max_bps: 0.0,
            hurst_exponent: None,
            assessment_score: 0.0,
            perplexity_score: 0.0,
            risk_level: "unknown".to_string(),
            protocol_verdict: "unknown".to_string(),
            anomaly_count: 0,
            anomalies: Vec::new(),
            writing_mode: "insufficient".to_string(),
            writing_mode_score: 0.0,
            writing_mode_confidence: 0.0,
            revision_cycle_count: 0,
            correction_ratio: 0.0,
            burst_speed_cv: 0.0,
            pause_depth_distribution: vec![0.0, 0.0, 0.0],
            spoofing_indicator: 0.0,
            sentence_initiation_ratio: 0.0,
            lrd_correlation: 0.0,
            iki_modality_score: 0.0,
            baseline_deviation: 0.0,
            error_message: Some(msg),
        }
    }
}

/// Return a detailed forensic breakdown for a tracked file.
///
/// Runs both the authorship profile (anomaly detection) and the full forensic
/// metrics pipeline (cadence, velocity, behavioral fingerprint, etc.), returning
/// rich structured data suitable for native UI display.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_forensic_breakdown(path: String) -> FfiForensicBreakdown {
    let path = match crate::sentinel::helpers::validate_path(&path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => return FfiForensicBreakdown::error(e),
    };

    let store = match open_store() {
        Ok(s) => s,
        Err(e) => return FfiForensicBreakdown::error(e),
    };

    let events = match store.get_events_for_file(&path) {
        Ok(e) => e,
        Err(e) => return FfiForensicBreakdown::error(format!("Failed to load events: {}", e)),
    };

    if events.is_empty() {
        return FfiForensicBreakdown::error("No events found for this file".to_string());
    }

    let profile = crate::forensics::ForensicEngine::evaluate_authorship(&path, &events);
    let (mut metrics, _regions) = crate::ffi::helpers::run_full_forensics(&events);

    // Enrich writing mode with cognitive layer from live session if available.
    if let Some(sentinel) = super::sentinel::get_sentinel() {
        for session in sentinel.sessions() {
            if session.path == path {
                if let Some(layer) = session.cognitive.analyze() {
                    if let Some(ref mut wm) = metrics.writing_mode {
                        wm.cognitive_layer = Some(layer);
                    }
                }
                break;
            }
        }
    }

    let protocol_verdict = metrics.map_to_protocol_verdict();

    let anomalies: Vec<FfiAnomaly> = profile
        .anomalies
        .iter()
        .map(|a| FfiAnomaly {
            timestamp_epoch_ms: a.timestamp.map(|t| t.timestamp_millis()),
            anomaly_type: a.anomaly_type.to_string(),
            description: a.description.clone(),
            severity: a.severity.to_string(),
        })
        .collect();

    let mean_iki_ms = finite_or(metrics.cadence.mean_iki_ns / 1_000_000.0, 0.0);
    let std_dev_iki_ms = finite_or(metrics.cadence.std_dev_iki_ns / 1_000_000.0, 0.0);
    let cv = finite_or(metrics.cadence.coefficient_of_variation, 0.0);

    FfiForensicBreakdown {
        success: true,
        monotonic_append_ratio: profile.metrics.monotonic_append_ratio.get(),
        edit_entropy: profile.metrics.edit_entropy,
        median_interval: profile.metrics.median_interval,
        mean_iki_ms,
        std_dev_iki_ms,
        coefficient_of_variation: cv,
        burst_count: u32::try_from(metrics.cadence.burst_count).unwrap_or(u32::MAX),
        pause_count: u32::try_from(metrics.cadence.pause_count).unwrap_or(u32::MAX),
        mean_bps: finite_or(metrics.velocity.mean_bps, 0.0),
        max_bps: finite_or(metrics.velocity.max_bps, 0.0),
        hurst_exponent: metrics.hurst_exponent.filter(|h| h.is_finite()),
        assessment_score: finite_or(metrics.assessment_score.get(), 0.0),
        perplexity_score: finite_or(metrics.perplexity_score, 0.0),
        risk_level: metrics.risk_level.to_string().to_lowercase(),
        protocol_verdict: format!("{:?}", protocol_verdict),
        anomaly_count: u32::try_from(profile.anomalies.len()).unwrap_or(u32::MAX),
        anomalies,
        writing_mode: metrics
            .writing_mode
            .as_ref()
            .map(|wm| wm.mode.to_string())
            .unwrap_or_else(|| "insufficient".to_string()),
        writing_mode_score: metrics
            .writing_mode
            .as_ref()
            .map(|wm| wm.cognitive_score)
            .unwrap_or(0.0),
        writing_mode_confidence: metrics
            .writing_mode
            .as_ref()
            .map(|wm| wm.confidence)
            .unwrap_or(0.0),
        revision_cycle_count: metrics
            .writing_mode
            .as_ref()
            .map(|wm| wm.revision_pattern.revision_cycle_count as u32)
            .unwrap_or(0),
        correction_ratio: metrics.cadence.correction_ratio.get(),
        burst_speed_cv: metrics.cadence.burst_speed_cv,
        pause_depth_distribution: metrics.cadence.pause_depth_distribution.to_vec(),
        spoofing_indicator: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| cl.spoofing_indicator)
            .unwrap_or(0.0),
        sentence_initiation_ratio: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| cl.sentence_initiation_ratio)
            .unwrap_or(0.0),
        lrd_correlation: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| cl.lrd_correlation)
            .unwrap_or(0.0),
        iki_modality_score: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| cl.iki_modality_score)
            .unwrap_or(0.0),
        baseline_deviation: metrics
            .writing_mode
            .as_ref()
            .and_then(|wm| wm.cognitive_layer.as_ref())
            .map(|cl| cl.baseline_deviation)
            .unwrap_or(0.0),
        error_message: None,
    }
}
