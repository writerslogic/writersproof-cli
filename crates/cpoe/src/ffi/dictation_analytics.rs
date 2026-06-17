// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::types::catch_ffi_panic;
use crate::utils::finite_or;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDictationAnalytics {
    pub success: bool,
    pub total_events: u32,
    pub total_words: u32,
    pub total_chars: u32,
    pub total_duration_sec: f64,
    pub mean_wpm: f64,
    pub mean_confidence: f64,
    pub mean_plausibility: f64,
    pub min_plausibility: f64,
    pub dictation_ratio: f64,
    pub plausibility_timeline: Vec<FfiTimelinePoint>,
    pub speaker_segments: Vec<FfiSpeakerSegment>,
    pub multi_speaker_detected: bool,
    pub typed_score: f64,
    pub dictated_score: f64,
    pub composite_adjustment: f64,
    pub burst_timing_cv: f64,
    pub mean_interim_revisions_per_min: f64,
    pub mean_disfluency_density: f64,
    // -- Transcription detection signals --
    /// Composite transcription likelihood (0.0 = strongly cognitive, 1.0 = strongly transcriptive).
    /// Synthesizes 11 cadence-based transcription discriminators.
    pub transcription_likelihood: f64,
    /// CV of first 5 keystrokes after each cognitive pause (>1s).
    /// Cognitive >0.25; transcriptive <0.15.
    pub post_pause_cv: f64,
    /// Lag-1 autocorrelation of IKI sequence.
    /// Cognitive: -0.1 to 0.2; transcriptive: >0.3.
    pub iki_autocorrelation: f64,
    /// CV of inter-pause-gap lengths. AI-transcribed <0.15; genuine >0.3.
    pub structural_homogeneity: Option<f64>,
    /// Fraction of keystrokes preceded by a >2s pause.
    /// Composition ~0.03; transcription <0.003.
    pub planning_pause_rate: Option<f64>,
    /// Count of 500ms windows with <5ms IKI std dev. >3 = strong transcription signal.
    pub zero_variance_windows: u32,
    /// Fraction of keystrokes that are backspace/delete.
    /// Cognitive >0.05; transcriptive <0.02.
    pub correction_ratio: f64,
    /// CV of typing speed within bursts. Cognitive >0.25; transcriptive <0.15.
    pub burst_speed_cv: f64,
    /// Cross-hand timing ratio (cross-hand IKI stddev / same-hand).
    /// Cognitive >1.3; transcriptive <1.1.
    pub cross_hand_timing_ratio: f64,
    /// CV of key hold durations. Human >0.2; robotic <0.1.
    pub dwell_cv: f64,
    /// CV of release-to-press gaps. Human >0.3; robotic <0.1.
    pub flight_cv: f64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiTimelinePoint {
    pub timestamp_ms: i64,
    pub value: f64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiSpeakerSegment {
    pub segment_index: u32,
    pub start_ms: i64,
    pub end_ms: i64,
    pub word_count: u32,
    pub confidence_mean: f64,
    pub is_primary_speaker: bool,
    pub speaker_label: u8,
}

impl FfiDictationAnalytics {
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            total_events: 0,
            total_words: 0,
            total_chars: 0,
            total_duration_sec: 0.0,
            mean_wpm: 0.0,
            mean_confidence: 0.0,
            mean_plausibility: 0.0,
            min_plausibility: 1.0,
            dictation_ratio: 0.0,
            plausibility_timeline: Vec::new(),
            speaker_segments: Vec::new(),
            multi_speaker_detected: false,
            typed_score: 0.0,
            dictated_score: 0.0,
            composite_adjustment: 0.0,
            burst_timing_cv: 0.0,
            mean_interim_revisions_per_min: 0.0,
            mean_disfluency_density: 0.0,
            transcription_likelihood: 0.0,
            post_pause_cv: 0.0,
            iki_autocorrelation: 0.0,
            structural_homogeneity: None,
            planning_pause_rate: None,
            zero_variance_windows: 0,
            correction_ratio: 0.0,
            burst_speed_cv: 0.0,
            cross_hand_timing_ratio: 0.0,
            dwell_cv: 0.0,
            flight_cv: 0.0,
            error_message: Some(msg.into()),
        }
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_dictation_analytics(path: String) -> FfiDictationAnalytics {
    catch_ffi_panic!(FfiDictationAnalytics::err("engine internal error"), {
        log::debug!("ffi_get_dictation_analytics: path={}", path);
        if path.len() > 4096 {
            return FfiDictationAnalytics::err("path too long");
        }
        if path.is_empty() {
            return FfiDictationAnalytics::err("path is empty");
        }

        let sentinel = match super::sentinel::get_running_sentinel() {
            Some(s) => s,
            None => return FfiDictationAnalytics::err("Sentinel not running"),
        };

        let session = match sentinel.session(&path) {
            Ok(s) => s,
            Err(_) => return FfiDictationAnalytics::err("No active session for path"),
        };

        let events = &session.dictation_events;
        if events.is_empty() {
            return FfiDictationAnalytics::err("No dictation events in session");
        }

        let total_session_words = session.cognitive.word_boundary_count() as u32;
        let dictated_word_sum: u32 = events.iter().map(|e| e.word_count).sum();
        let typed_words = total_session_words.saturating_sub(dictated_word_sum);

        let analytics =
            crate::forensics::dictation::compute_dictation_analytics(events, typed_words);

        let scoring = crate::forensics::dictation::apply_dictation_adjustment(
            1.0,
            events,
            typed_words,
            analytics.multi_speaker_detected,
        );

        let timeline: Vec<FfiTimelinePoint> = analytics
            .plausibility_timeline
            .iter()
            .map(|(ts, val)| FfiTimelinePoint {
                timestamp_ms: ts / 1_000_000,
                value: *val,
            })
            .collect();

        let segments: Vec<FfiSpeakerSegment> = analytics
            .speaker_segments
            .iter()
            .map(|s| FfiSpeakerSegment {
                segment_index: s.segment_index,
                start_ms: s.start_ns / 1_000_000,
                end_ms: s.end_ns / 1_000_000,
                word_count: s.word_count,
                confidence_mean: s.confidence_mean as f64,
                is_primary_speaker: s.is_primary_speaker,
                speaker_label: s.speaker_label,
            })
            .collect();

        // Cadence analysis from the session's jitter ring for transcription signals.
        let jitter_samples = session.jitter_ring.as_slice();
        let cadence = if jitter_samples.len() >= 10 {
            Some(crate::forensics::analyze_cadence(&jitter_samples))
        } else {
            None
        };

        let (post_pause_cv, iki_autocorrelation, structural_homogeneity, planning_pause_rate,
             zero_variance_windows, correction_ratio, burst_speed_cv, cross_hand_timing_ratio,
             dwell_cv, flight_cv) = if let Some(ref cm) = cadence {
            (
                finite_or(cm.post_pause_cv, 0.0),
                finite_or(cm.iki_autocorrelation, 0.0),
                cm.structural_homogeneity_score.filter(|v| v.is_finite()),
                cm.planning_pause_rate.filter(|v| v.is_finite()),
                cm.zero_variance_windows as u32,
                finite_or(cm.correction_ratio.get(), 0.0),
                finite_or(cm.burst_speed_cv, 0.0),
                finite_or(cm.cross_hand_timing_ratio, 0.0),
                finite_or(cm.dwell_cv, 0.0),
                finite_or(cm.flight_cv, 0.0),
            )
        } else {
            (0.0, 0.0, None, None, 0, 0.0, 0.0, 0.0, 0.0, 0.0)
        };

        let transcription_likelihood = compute_transcription_likelihood(
            &cadence, analytics.burst_timing_cv, analytics.mean_plausibility,
        );

        FfiDictationAnalytics {
            success: true,
            total_events: analytics.total_dictation_events,
            total_words: analytics.total_dictated_words,
            total_chars: analytics.total_dictated_chars,
            total_duration_sec: analytics.total_duration_sec,
            mean_wpm: analytics.mean_wpm,
            mean_confidence: analytics.mean_confidence,
            mean_plausibility: analytics.mean_plausibility,
            min_plausibility: analytics.min_plausibility,
            dictation_ratio: analytics.dictation_ratio_words,
            plausibility_timeline: timeline,
            speaker_segments: segments,
            multi_speaker_detected: analytics.multi_speaker_detected,
            typed_score: scoring.typed_score,
            dictated_score: scoring.dictated_score,
            composite_adjustment: scoring.composite_adjustment,
            burst_timing_cv: analytics.burst_timing_cv,
            mean_interim_revisions_per_min: analytics.mean_interim_revisions_per_min,
            mean_disfluency_density: analytics.mean_disfluency_per_min,
            transcription_likelihood,
            post_pause_cv,
            iki_autocorrelation,
            structural_homogeneity,
            planning_pause_rate,
            zero_variance_windows,
            correction_ratio,
            burst_speed_cv,
            cross_hand_timing_ratio,
            dwell_cv,
            flight_cv,
            error_message: None,
        }
    })
}

/// Compute a composite transcription likelihood from the strongest cadence signals.
///
/// Returns 0.0 (strongly cognitive/original) to 1.0 (strongly transcriptive).
/// Each signal is mapped to a 0-1 suspicion value via its known cognitive/transcriptive
/// thresholds, then combined with evidence-weighted averaging.
fn compute_transcription_likelihood(
    cadence: &Option<crate::forensics::types::CadenceMetrics>,
    dictation_burst_cv: f64,
    mean_plausibility: f64,
) -> f64 {
    let cm = match cadence {
        Some(c) => c,
        None => return 0.0,
    };

    // Each signal → suspicion ∈ [0, 1] where 1 = transcriptive.
    // Linear interpolation between cognitive and transcriptive thresholds.
    let mut signals: Vec<(f64, f64)> = Vec::new(); // (suspicion, weight)

    // 1. IKI autocorrelation: cognitive -0.1 to 0.2, transcriptive >0.3
    if cm.iki_autocorrelation.is_finite() {
        let s = ((cm.iki_autocorrelation + 0.1) / 0.40).clamp(0.0, 1.0);
        signals.push((s, 0.18));
    }

    // 2. Burst speed CV: cognitive >0.25, transcriptive <0.15
    if cm.burst_speed_cv.is_finite() && cm.burst_count >= 3 {
        let s = 1.0 - ((cm.burst_speed_cv - 0.10) / 0.20).clamp(0.0, 1.0);
        signals.push((s, 0.15));
    }

    // 3. Post-pause CV: cognitive >0.25, transcriptive <0.15
    if cm.post_pause_cv.is_finite() && cm.pause_count >= 3 {
        let s = 1.0 - ((cm.post_pause_cv - 0.10) / 0.20).clamp(0.0, 1.0);
        signals.push((s, 0.15));
    }

    // 4. Correction ratio: cognitive >0.05, transcriptive <0.02
    {
        let cr = cm.correction_ratio.get();
        if cr.is_finite() {
            let s = 1.0 - ((cr - 0.01) / 0.05).clamp(0.0, 1.0);
            signals.push((s, 0.12));
        }
    }

    // 5. Planning pause rate: composition ~0.03, transcription <0.003
    // Recalibrated from field data: forward-flowing writers average ~1.3% in prose,
    // original diary calibration (6.2%) was too high for fast typists.
    if let Some(ppr) = cm.planning_pause_rate {
        if ppr.is_finite() {
            let s = 1.0 - ((ppr - 0.002) / 0.028).clamp(0.0, 1.0);
            signals.push((s, 0.08));
        }
    }

    // 6. Structural homogeneity: genuine >0.30, AI-transcribed <0.15
    if let Some(sh) = cm.structural_homogeneity_score {
        if sh.is_finite() {
            let s = 1.0 - ((sh - 0.10) / 0.25).clamp(0.0, 1.0);
            signals.push((s, 0.10));
        }
    }

    // 7. Zero-variance windows: any >0 is suspicious, >3 is strong
    {
        let s = (cm.zero_variance_windows as f64 / 3.0).clamp(0.0, 1.0);
        signals.push((s, 0.08));
    }

    // 8. Dictation burst timing CV (from speech events, not cadence): TTS <0.15
    if dictation_burst_cv.is_finite() && dictation_burst_cv >= 0.0 {
        let s = 1.0 - ((dictation_burst_cv - 0.10) / 0.40).clamp(0.0, 1.0);
        signals.push((s, 0.07));
    }

    // 9. Dwell CV (key hold duration variation): human >0.2, robotic <0.1
    if cm.dwell_cv.is_finite() && cm.dwell_cv >= 0.0 {
        let s = 1.0 - ((cm.dwell_cv - 0.05) / 0.20).clamp(0.0, 1.0);
        signals.push((s, 0.05));
    }

    // 10. Flight CV (release-to-press gap variation): human >0.3, robotic <0.1
    if cm.flight_cv.is_finite() && cm.flight_cv >= 0.0 {
        let s = 1.0 - ((cm.flight_cv - 0.05) / 0.30).clamp(0.0, 1.0);
        signals.push((s, 0.05));
    }

    // 11. Cross-hand timing ratio: cognitive >1.3, transcriptive <1.1
    if cm.cross_hand_timing_ratio.is_finite() && cm.cross_hand_timing_ratio > 0.0 {
        let s = 1.0 - ((cm.cross_hand_timing_ratio - 1.0) / 0.4).clamp(0.0, 1.0);
        signals.push((s, 0.05));
    }

    if signals.is_empty() {
        return 0.0;
    }

    let total_weight: f64 = signals.iter().map(|(_, w)| w).sum();
    let weighted_sum: f64 = signals.iter().map(|(s, w)| s * w).sum();
    let composite = if total_weight > 0.0 {
        weighted_sum / total_weight
    } else {
        0.0
    };

    // Low dictation plausibility strengthens transcription suspicion.
    let plausibility_boost = if mean_plausibility < 0.3 {
        (0.3 - mean_plausibility.max(0.0)) * 0.2
    } else {
        0.0
    };

    (composite + plausibility_boost).clamp(0.0, 1.0)
}
