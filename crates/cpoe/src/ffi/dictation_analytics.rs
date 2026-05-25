// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::types::catch_ffi_panic;

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
            error_message: None,
        }
    })
}
