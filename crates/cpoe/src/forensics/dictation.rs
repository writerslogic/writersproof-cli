// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Dictation plausibility scoring: detect forged or implausible speech-to-text events.

use crate::evidence::DictationEvent;

/// Normal dictation WPM upper bound (fast but plausible).
const WPM_FAST_THRESHOLD: f64 = 200.0;

/// WPM above this is highly suspicious (sped-up playback or injection).
const WPM_SUSPICIOUS_THRESHOLD: f64 = 250.0;

/// Slow sustained dictation threshold (below this for >10 words is unusual).
const WPM_SLOW_THRESHOLD: f64 = 40.0;

/// Minimum word count to apply slow-speech penalty.
const SLOW_SPEECH_MIN_WORDS: u32 = 10;

/// Minimum duration (seconds) below which high word counts are suspicious.
const MIN_DURATION_SEC: f64 = 2.0;

/// Word count threshold for short-duration suspicion.
const SHORT_DURATION_WORD_LIMIT: u32 = 20;

/// Duration (seconds) above which dictation is uncommon.
const LONG_DURATION_SEC: f64 = 3600.0;

/// Penalty for WPM above suspicious threshold.
const PENALTY_SUSPICIOUS_WPM: f64 = 0.1;

/// Penalty for WPM above fast threshold.
const PENALTY_FAST_WPM: f64 = 0.5;

/// Penalty for slow sustained dictation.
const PENALTY_SLOW_WPM: f64 = 0.6;

/// Penalty for too many words in too short a window.
const PENALTY_SHORT_BURST: f64 = 0.2;

/// Penalty for very long dictation session.
const PENALTY_LONG_SESSION: f64 = 0.7;

/// Penalty for missing microphone activity.
const PENALTY_NO_MIC: f64 = 0.3;

/// Penalty for zero/near-zero WPM on a non-empty utterance (likely injected text).
const PENALTY_ZERO_WPM: f64 = 0.15;

/// WPM below this is considered effectively zero (injected text with no timing).
const WPM_ZERO_THRESHOLD: f64 = 0.1;

/// IORegistry transport type value for a virtual (non-hardware) audio device.
const AUDIO_TRANSPORT_VIRTUAL: u8 = 7;

/// SFSpeechRecognizer confidence stddev below which TTS injection is suspected.
/// Live speech: 0.08–0.18. TTS through any path: typically <0.04.
const CONFIDENCE_STDDEV_TTS_THRESHOLD: f32 = 0.04;

/// Minimum fragment count before applying the confidence variance check.
const CONFIDENCE_MIN_FRAGMENTS: u32 = 3;

/// Keystroke count during dictation above which concurrent typing is flagged.
const KEYSTROKE_CONCURRENT_SUSPICIOUS: u32 = 10;

/// Cross-window text similarity above which copy-transcription is suspected.
const CROSS_WINDOW_SIMILARITY_THRESHOLD: f32 = 0.70;

/// Ambient noise floor (dBFS) below which an anechoic/TTS environment is suspected.
/// Sentinel marks the field -100.0 when no measurement was taken; exclude that.
const AMBIENT_SILENCE_THRESHOLD: f32 = -75.0;

/// Penalty for virtual (non-hardware) audio input device.
const PENALTY_VIRTUAL_DEVICE: f64 = 0.05;

/// Penalty for TTS-like uniform confidence scores.
const PENALTY_TTS_CONFIDENCE: f64 = 0.1;

/// Penalty for concurrent audio output during dictation (possible replay).
const PENALTY_SPEAKER_ACTIVE: f64 = 0.2;

/// Penalty for significant concurrent keystroke activity during dictation.
const PENALTY_KEYSTROKES_CONCURRENT: f64 = 0.3;

/// Penalty for text that closely matches visible screen content (copy-transcription).
const PENALTY_CROSS_WINDOW_COPY: f64 = 0.15;

/// Penalty for near-silent ambient environment (suggests TTS or anechoic recording).
const PENALTY_ANECHOIC: f64 = 0.25;

/// Penalty for zero interim revisions on a multi-fragment session (TTS hallmark).
const PENALTY_ZERO_REVISIONS: f64 = 0.15;

/// Minimum fragments before applying the zero-revision check.
const REVISION_MIN_FRAGMENTS: u32 = 3;

/// Penalty for zero disfluencies on sustained speech (TTS hallmark).
const PENALTY_ZERO_DISFLUENCY: f64 = 0.2;

/// Minimum word count before applying the zero-disfluency check.
const DISFLUENCY_MIN_WORDS: u32 = 20;

/// Assess whether a dictation event is plausible (not forged).
///
/// Returns a score in `[0.0, 1.0]` where 1.0 = fully plausible and
/// values below 0.3 indicate likely forgery or injection.
pub fn score_dictation_plausibility(event: &DictationEvent) -> f64 {
    let mut score = 1.0;

    // WPM check: normal dictation is 80-200 WPM.
    // Above 250 is suspicious (sped-up playback), above 200 is somewhat fast,
    // below 40 for sustained speech (>10 words) is unusually slow.
    // Zero WPM with actual words is a strong forgery signal (injected text, no timing).
    if event.word_count > 0 && event.words_per_minute < WPM_ZERO_THRESHOLD {
        score *= PENALTY_ZERO_WPM;
    } else if event.words_per_minute > WPM_SUSPICIOUS_THRESHOLD {
        score *= PENALTY_SUSPICIOUS_WPM;
    } else if event.words_per_minute > WPM_FAST_THRESHOLD {
        score *= PENALTY_FAST_WPM;
    } else if event.words_per_minute < WPM_SLOW_THRESHOLD
        && event.word_count > SLOW_SPEECH_MIN_WORDS
    {
        score *= PENALTY_SLOW_WPM;
    }

    // Duration check: dictation sessions are typically 10s-10min.
    let duration_sec = crate::utils::ns_to_secs(event.end_ns.saturating_sub(event.start_ns));
    if duration_sec < MIN_DURATION_SEC && event.word_count > SHORT_DURATION_WORD_LIMIT {
        score *= PENALTY_SHORT_BURST;
    }
    if duration_sec > LONG_DURATION_SEC {
        score *= PENALTY_LONG_SESSION;
    }

    // Mic check: if mic wasn't active, this might be injected.
    if !event.mic_active {
        score *= PENALTY_NO_MIC;
    }

    // Hardware audio check: virtual input device cannot be trusted as a live mic.
    if event.audio_transport_type == AUDIO_TRANSPORT_VIRTUAL {
        score *= PENALTY_VIRTUAL_DEVICE;
    }

    // Confidence variance: TTS produces unnaturally uniform scores.
    if event.fragment_count >= CONFIDENCE_MIN_FRAGMENTS
        && event.confidence_stddev < CONFIDENCE_STDDEV_TTS_THRESHOLD
    {
        score *= PENALTY_TTS_CONFIDENCE;
    }

    // Concurrent speaker output: possible replay attack.
    if event.speaker_output_active {
        score *= PENALTY_SPEAKER_ACTIVE;
    }

    // Concurrent keystroke activity: user typing while "dictating" is suspicious.
    if event.keystrokes_during_dictation > KEYSTROKE_CONCURRENT_SUSPICIOUS {
        score *= PENALTY_KEYSTROKES_CONCURRENT;
    }

    // Cross-window novelty: text closely matches visible screen content.
    if event.cross_window_similarity > CROSS_WINDOW_SIMILARITY_THRESHOLD {
        score *= PENALTY_CROSS_WINDOW_COPY;
    }

    // Ambient noise floor: near-silence suggests TTS or anechoic recording environment.
    // -100.0 is the sentinel "not measured" value; skip the check in that case.
    if event.ambient_noise_db > -100.0 && event.ambient_noise_db < AMBIENT_SILENCE_THRESHOLD {
        score *= PENALTY_ANECHOIC;
    }

    // Zero interim revisions: real speech produces continuous recognition updates.
    // TTS through dictation produces clean audio with zero mid-recognition revisions.
    if event.fragment_count >= REVISION_MIN_FRAGMENTS && event.interim_revision_count == 0 {
        score *= PENALTY_ZERO_REVISIONS;
    }

    // Zero disfluencies: real speakers produce self-repairs (word retractions)
    // on sustained speech. TTS never triggers recognizer retractions.
    if event.word_count >= DISFLUENCY_MIN_WORDS && event.disfluency_count == 0 {
        score *= PENALTY_ZERO_DISFLUENCY;
    }

    crate::utils::Probability::clamp(score).get()
}

// ---------------------------------------------------------------------------
// Pro-tier analytics: aggregation, multi-speaker clustering, scoring component
// ---------------------------------------------------------------------------

/// Confidence break threshold (2 stddev) for detecting speaker changes.
const SPEAKER_CONFIDENCE_BREAK: f32 = 0.15;

/// Ambient noise shift (dB) for detecting environment changes.
const SPEAKER_NOISE_BREAK_DB: f32 = 10.0;

/// Temporal gap (nanoseconds) above which a new speaker segment starts.
const SPEAKER_GAP_NS: i64 = 5 * 60 * 1_000_000_000; // 5 minutes

/// A segment of dictation attributed to a single speaker.
#[derive(Debug, Clone)]
pub struct SpeakerSegment {
    pub segment_index: u32,
    pub start_ns: i64,
    pub end_ns: i64,
    pub word_count: u32,
    pub device_uid_hash: [u8; 8],
    pub confidence_mean: f32,
    pub ambient_noise_db: f32,
    pub is_primary_speaker: bool,
    pub speaker_label: u8,
}

/// Aggregated dictation analytics for a document session.
#[derive(Debug, Clone)]
pub struct DictationAnalytics {
    pub total_dictation_events: u32,
    pub total_dictated_words: u32,
    pub total_dictated_chars: u32,
    pub total_duration_sec: f64,
    pub mean_wpm: f64,
    pub mean_confidence: f64,
    pub mean_plausibility: f64,
    pub min_plausibility: f64,
    pub plausibility_timeline: Vec<(i64, f64)>,
    pub speaker_segments: Vec<SpeakerSegment>,
    pub dictation_ratio_words: f64,
    pub multi_speaker_detected: bool,
    /// CV of inter-burst timing (gaps between dictation events). High = real, low = TTS.
    pub burst_timing_cv: f64,
    /// Mean interim recognition revisions per minute across all events.
    pub mean_interim_revisions_per_min: f64,
    /// Mean disfluency (self-repair) cycles per minute across all events.
    pub mean_disfluency_per_min: f64,
}

/// Compute aggregated analytics over a session's dictation events.
pub fn compute_dictation_analytics(
    events: &[DictationEvent],
    total_typed_words: u32,
) -> DictationAnalytics {
    if events.is_empty() {
        return DictationAnalytics {
            total_dictation_events: 0,
            total_dictated_words: 0,
            total_dictated_chars: 0,
            total_duration_sec: 0.0,
            mean_wpm: 0.0,
            mean_confidence: 0.0,
            mean_plausibility: 0.0,
            min_plausibility: 1.0,
            plausibility_timeline: Vec::new(),
            speaker_segments: Vec::new(),
            dictation_ratio_words: 0.0,
            multi_speaker_detected: false,
            burst_timing_cv: 0.0,
            mean_interim_revisions_per_min: 0.0,
            mean_disfluency_per_min: 0.0,
        };
    }

    let mut total_words = 0u32;
    let mut total_chars = 0u32;
    let mut total_duration_ns = 0i64;
    let mut wpm_sum = 0.0;
    let mut conf_sum = 0.0f64;
    let mut plaus_sum = 0.0;
    let mut min_plaus = 1.0f64;
    let mut timeline = Vec::with_capacity(events.len());
    let mut total_revisions = 0u32;
    let mut total_disfluencies = 0u32;

    for ev in events {
        total_words = total_words.saturating_add(ev.word_count);
        total_chars = total_chars.saturating_add(ev.char_count);
        total_duration_ns += ev.end_ns.saturating_sub(ev.start_ns);
        wpm_sum += if ev.words_per_minute.is_finite() { ev.words_per_minute } else { 0.0 };
        conf_sum += if (ev.confidence_mean as f64).is_finite() { ev.confidence_mean as f64 } else { 0.0 };
        let plaus = score_dictation_plausibility(ev);
        plaus_sum += plaus;
        if plaus < min_plaus {
            min_plaus = plaus;
        }
        timeline.push((ev.start_ns, plaus));
        total_revisions += ev.interim_revision_count;
        total_disfluencies += ev.disfluency_count;
    }

    let n = events.len() as f64;
    let total_all_words = total_words.saturating_add(total_typed_words);
    let segments = cluster_speaker_segments(events);
    let multi = segments.iter().any(|s| s.speaker_label > 0);
    let total_duration_sec = crate::utils::ns_to_secs(total_duration_ns);
    let total_duration_min = total_duration_sec / 60.0;

    // Burst timing CV: coefficient of variation of gaps between consecutive events.
    let burst_timing_cv = if events.len() >= 2 {
        let mut gaps: Vec<f64> = Vec::with_capacity(events.len() - 1);
        for pair in events.windows(2) {
            let gap_ns = pair[1].start_ns.saturating_sub(pair[0].end_ns);
            gaps.push(gap_ns as f64);
        }
        let cv = crate::utils::coefficient_of_variation(&gaps);
        if cv > 0.0 {
            cv
        } else {
            0.0
        }
    } else {
        0.0
    };

    // Per-minute rates for revision and disfluency density.
    let mean_revisions_per_min = if total_duration_min > 0.0 {
        total_revisions as f64 / total_duration_min
    } else {
        0.0
    };
    let mean_disfluency_per_min = if total_duration_min > 0.0 {
        total_disfluencies as f64 / total_duration_min
    } else {
        0.0
    };

    DictationAnalytics {
        total_dictation_events: events.len() as u32,
        total_dictated_words: total_words,
        total_dictated_chars: total_chars,
        total_duration_sec,
        mean_wpm: wpm_sum / n,
        mean_confidence: conf_sum / n,
        mean_plausibility: plaus_sum / n,
        min_plausibility: min_plaus,
        plausibility_timeline: timeline,
        speaker_segments: segments,
        dictation_ratio_words: if total_all_words > 0 {
            total_words as f64 / total_all_words as f64
        } else {
            0.0
        },
        multi_speaker_detected: multi,
        burst_timing_cv,
        mean_interim_revisions_per_min: mean_revisions_per_min,
        mean_disfluency_per_min,
    }
}

/// Cluster dictation events into speaker segments.
///
/// Groups by `device_uid_hash` (different mic = different speaker), then splits
/// within the same device on statistical breaks in confidence or ambient noise,
/// or temporal gaps exceeding 5 minutes.
pub fn cluster_speaker_segments(events: &[DictationEvent]) -> Vec<SpeakerSegment> {
    if events.is_empty() {
        return Vec::new();
    }

    let mut segments: Vec<SpeakerSegment> = Vec::new();
    let mut seg_start = 0usize;

    for i in 1..events.len() {
        let prev = &events[i - 1];
        let curr = &events[i];

        let device_change = prev.device_uid_hash != curr.device_uid_hash;
        let conf_diff = (prev.confidence_mean - curr.confidence_mean).abs();
        let conf_break = conf_diff.is_finite() && conf_diff > SPEAKER_CONFIDENCE_BREAK;
        let noise_diff = (prev.ambient_noise_db - curr.ambient_noise_db).abs();
        let noise_break = prev.ambient_noise_db > -100.0
            && curr.ambient_noise_db > -100.0
            && noise_diff.is_finite()
            && noise_diff > SPEAKER_NOISE_BREAK_DB;
        let gap = curr.start_ns.saturating_sub(prev.end_ns) > SPEAKER_GAP_NS;

        if device_change || conf_break || noise_break || gap {
            segments.push(build_segment(&events[seg_start..i], segments.len() as u32));
            seg_start = i;
        }
    }
    segments.push(build_segment(&events[seg_start..], segments.len() as u32));

    // Assign speaker labels: same device_uid_hash = same speaker.
    let mut uid_to_label: std::collections::HashMap<[u8; 8], u8> = std::collections::HashMap::new();
    let mut next_label = 0u8;
    let mut max_words = 0u32;
    let mut primary_label = 0u8;

    for seg in &mut segments {
        let label = *uid_to_label.entry(seg.device_uid_hash).or_insert_with(|| {
            let l = next_label;
            next_label = next_label.saturating_add(1);
            l
        });
        seg.speaker_label = label;
        if seg.word_count > max_words {
            max_words = seg.word_count;
            primary_label = label;
        }
    }
    for seg in &mut segments {
        seg.is_primary_speaker = seg.speaker_label == primary_label;
    }

    segments
}

fn build_segment(events: &[DictationEvent], index: u32) -> SpeakerSegment {
    let first = &events[0];
    let last = &events[events.len() - 1];
    let word_count: u32 = events.iter().map(|e| e.word_count).sum();
    let conf_sum: f32 = events.iter().map(|e| e.confidence_mean).sum();
    let noise_sum: f32 = events
        .iter()
        .filter(|e| e.ambient_noise_db > -100.0)
        .map(|e| e.ambient_noise_db)
        .sum();
    let noise_count = events
        .iter()
        .filter(|e| e.ambient_noise_db > -100.0)
        .count();

    SpeakerSegment {
        segment_index: index,
        start_ns: first.start_ns,
        end_ns: last.end_ns,
        word_count,
        device_uid_hash: first.device_uid_hash,
        confidence_mean: if events.is_empty() {
            0.0
        } else {
            conf_sum / events.len() as f32
        },
        ambient_noise_db: if noise_count > 0 {
            noise_sum / noise_count as f32
        } else {
            -100.0
        },
        is_primary_speaker: false,
        speaker_label: 0,
    }
}

/// Dictation scoring component for integration into assessment score.
#[derive(Debug, Clone)]
pub struct DictationScoreComponent {
    pub typed_score: f64,
    pub dictated_score: f64,
    pub dictation_ratio: f64,
    pub multi_speaker_detected: bool,
    pub composite_adjustment: f64,
}

/// Multi-speaker penalty applied to assessment score.
const MULTI_SPEAKER_PENALTY: f64 = 0.85;

/// Penalty when any dictation event has low plausibility.
const LOW_PLAUSIBILITY_PENALTY: f64 = 0.90;

/// Low plausibility threshold.
const LOW_PLAUSIBILITY_THRESHOLD: f64 = 0.3;

/// Apply dictation-aware penalties to an existing assessment score.
///
/// Returns a component breakdown for display in Pro-tier reports.
pub fn apply_dictation_adjustment(
    base_score: f64,
    events: &[DictationEvent],
    total_typed_words: u32,
    multi_speaker: bool,
) -> DictationScoreComponent {
    if events.is_empty() {
        return DictationScoreComponent {
            typed_score: base_score,
            dictated_score: 1.0,
            dictation_ratio: 0.0,
            multi_speaker_detected: multi_speaker,
            composite_adjustment: 0.0,
        };
    }

    let n = events.len() as f64;
    let mean_plausibility: f64 = events
        .iter()
        .map(score_dictation_plausibility)
        .sum::<f64>()
        / n;

    let total_dict_words: u32 = events.iter().map(|e| e.word_count).sum();
    let total_words = total_dict_words.saturating_add(total_typed_words);
    let ratio = if total_words > 0 {
        total_dict_words as f64 / total_words as f64
    } else {
        0.0
    };

    // Weighted composite: typed portion at base_score, dictated at mean_plausibility.
    let composite = ratio * mean_plausibility + (1.0 - ratio) * base_score;
    let mut adjusted = composite;

    if multi_speaker {
        adjusted *= MULTI_SPEAKER_PENALTY;
    }

    let has_low = events
        .iter()
        .any(|e| score_dictation_plausibility(e) < LOW_PLAUSIBILITY_THRESHOLD);
    if has_low {
        adjusted *= LOW_PLAUSIBILITY_PENALTY;
    }

    let adjustment = adjusted - base_score;

    DictationScoreComponent {
        typed_score: base_score,
        dictated_score: mean_plausibility,
        dictation_ratio: ratio,
        multi_speaker_detected: multi_speaker,
        composite_adjustment: adjustment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(word_count: u32, duration_sec: f64, mic_active: bool) -> DictationEvent {
        let wpm = if duration_sec > 0.0 {
            word_count as f64 / (duration_sec / 60.0)
        } else {
            0.0
        };
        DictationEvent {
            start_ns: 0,
            end_ns: (duration_sec * 1e9) as i64,
            word_count,
            char_count: word_count * 5,
            input_method: "com.apple.inputmethod.DictationIME".to_string(),
            mic_active,
            words_per_minute: wpm,
            plausibility_score: 0.0,
            es_speech_pid: 0,
            audio_transport_type: 0,
            device_uid_hash: [0u8; 8],
            fragment_count: 0,
            confidence_mean: 0.0,
            confidence_stddev: 0.0,
            correction_rate: 0.0,
            keystroke_void: true,
            keystrokes_during_dictation: 0,
            speaker_output_active: false,
            ambient_noise_db: -100.0,
            cross_window_similarity: 0.0,
            interim_revision_count: 5,
            disfluency_count: 2,
        }
    }

    #[test]
    fn zero_revisions_penalized() {
        let mut event = make_event(30, 30.0, true);
        event.fragment_count = 5;
        event.interim_revision_count = 0;
        let score = score_dictation_plausibility(&event);
        // Zero revisions on 5 fragments should trigger PENALTY_ZERO_REVISIONS
        assert!(score < 0.9, "zero revisions should penalize: {score}");

        event.interim_revision_count = 4;
        let score_with_revisions = score_dictation_plausibility(&event);
        assert!(score_with_revisions > score, "revisions present should score higher");
    }

    #[test]
    fn zero_disfluency_penalized() {
        let mut event = make_event(30, 30.0, true);
        event.disfluency_count = 0;
        let score = score_dictation_plausibility(&event);
        // Zero disfluencies on 30 words should trigger PENALTY_ZERO_DISFLUENCY
        assert!(score < 0.85, "zero disfluency should penalize: {score}");

        event.disfluency_count = 3;
        let score_with_disfluency = score_dictation_plausibility(&event);
        assert!(score_with_disfluency > score, "disfluencies present should score higher");
    }

    #[test]
    fn burst_timing_cv_computed() {
        let mut ev1 = make_event(20, 10.0, true);
        ev1.start_ns = 0;
        ev1.end_ns = 10_000_000_000;

        let mut ev2 = make_event(15, 8.0, true);
        ev2.start_ns = 15_000_000_000;
        ev2.end_ns = 23_000_000_000;

        let mut ev3 = make_event(25, 12.0, true);
        ev3.start_ns = 40_000_000_000; // larger gap
        ev3.end_ns = 52_000_000_000;

        let analytics = compute_dictation_analytics(&[ev1, ev2, ev3], 100);
        // Two gaps: 5s and 17s — high variance → high CV
        assert!(analytics.burst_timing_cv > 0.3, "CV should be high for varied gaps: {}", analytics.burst_timing_cv);
    }

    #[test]
    fn normal_dictation_scores_high() {
        // 120 WPM for 30 seconds with mic = perfectly normal
        let event = make_event(60, 30.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            score > 0.9,
            "normal dictation should score >0.9, got {score}"
        );
    }

    #[test]
    fn fast_dictation_penalized() {
        // 220 WPM — somewhat fast
        let event = make_event(110, 30.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            (0.4..=0.6).contains(&score),
            "fast dictation should be penalized, got {score}"
        );
    }

    #[test]
    fn suspicious_speed_heavily_penalized() {
        // 300 WPM — likely sped-up playback
        let event = make_event(150, 30.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            score < 0.2,
            "suspicious speed should score <0.2, got {score}"
        );
    }

    #[test]
    fn no_mic_penalized() {
        // Normal speed but mic off
        let event = make_event(60, 30.0, false);
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.5, "no-mic should be penalized, got {score}");
    }

    #[test]
    fn short_burst_many_words_penalized() {
        // 25 words in 1 second with mic
        let event = make_event(25, 1.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.3, "short burst should be penalized, got {score}");
    }

    #[test]
    fn long_session_mild_penalty() {
        // 2 hour dictation at normal speed
        let event = make_event(14400, 7200.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            (0.5..=0.8).contains(&score),
            "long session should get mild penalty, got {score}"
        );
    }

    #[test]
    fn slow_speech_penalized_when_sustained() {
        // 30 WPM for 60 seconds (30 words)
        let event = make_event(30, 60.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            (0.5..=0.7).contains(&score),
            "slow sustained speech should be penalized, got {score}"
        );
    }

    #[test]
    fn slow_speech_not_penalized_when_few_words() {
        // 30 WPM but only 5 words — short utterance, acceptable
        let event = make_event(5, 10.0, true);
        let score = score_dictation_plausibility(&event);
        assert!(
            score > 0.9,
            "short slow dictation should not be penalized, got {score}"
        );
    }

    #[test]
    fn combined_penalties_stack() {
        // Fast + no mic
        let event = make_event(110, 30.0, false);
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.2, "combined penalties should stack, got {score}");
    }

    #[test]
    fn score_clamped_to_unit_range() {
        let event = make_event(60, 30.0, true);
        let score = score_dictation_plausibility(&event);
        assert!((0.0..=1.0).contains(&score));

        // Worst case: all penalties
        let event = make_event(150, 0.5, false);
        let score = score_dictation_plausibility(&event);
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn virtual_device_heavily_penalized() {
        let mut event = make_event(60, 30.0, true);
        event.audio_transport_type = AUDIO_TRANSPORT_VIRTUAL;
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.15, "virtual device should be heavily penalized, got {score}");
    }

    #[test]
    fn builtin_device_not_penalized() {
        let mut event = make_event(60, 30.0, true);
        event.audio_transport_type = 1; // Built-in
        let score = score_dictation_plausibility(&event);
        assert!(score > 0.9, "built-in device should not be penalized, got {score}");
    }

    #[test]
    fn tts_confidence_penalized() {
        let mut event = make_event(60, 30.0, true);
        event.fragment_count = 5;
        event.confidence_stddev = 0.01; // Near-zero variance = TTS
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.95, "TTS-like confidence should be penalized, got {score}");
    }

    #[test]
    fn tts_confidence_not_penalized_with_few_fragments() {
        let mut event = make_event(60, 30.0, true);
        event.fragment_count = 2; // Below CONFIDENCE_MIN_FRAGMENTS
        event.confidence_stddev = 0.01;
        let score = score_dictation_plausibility(&event);
        assert!(score > 0.9, "few fragments should skip confidence check, got {score}");
    }

    #[test]
    fn speaker_output_penalized() {
        let mut event = make_event(60, 30.0, true);
        event.speaker_output_active = true;
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.85, "speaker output should be penalized, got {score}");
    }

    #[test]
    fn concurrent_keystrokes_penalized() {
        let mut event = make_event(60, 30.0, true);
        event.keystrokes_during_dictation = 50;
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.75, "concurrent keystrokes should be penalized, got {score}");
    }

    #[test]
    fn few_keystrokes_not_penalized() {
        let mut event = make_event(60, 30.0, true);
        event.keystrokes_during_dictation = 5; // Below threshold
        let score = score_dictation_plausibility(&event);
        assert!(score > 0.9, "few keystrokes should not be penalized, got {score}");
    }

    #[test]
    fn cross_window_copy_penalized() {
        let mut event = make_event(60, 30.0, true);
        event.cross_window_similarity = 0.85; // High similarity = copy
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.9, "cross-window copy should be penalized, got {score}");
    }

    #[test]
    fn anechoic_environment_penalized() {
        let mut event = make_event(60, 30.0, true);
        event.ambient_noise_db = -85.0; // Below threshold = silent environment
        let score = score_dictation_plausibility(&event);
        assert!(score < 0.8, "near-silent environment should be penalized, got {score}");
    }

    #[test]
    fn ambient_not_measured_no_penalty() {
        let mut event = make_event(60, 30.0, true);
        event.ambient_noise_db = -100.0; // Sentinel "not measured" value
        let score = score_dictation_plausibility(&event);
        assert!(score > 0.9, "unmeasured ambient should not be penalized, got {score}");
    }

    #[test]
    fn real_room_noise_floor_not_penalized() {
        let mut event = make_event(60, 30.0, true);
        event.ambient_noise_db = -45.0; // Normal room noise
        let score = score_dictation_plausibility(&event);
        assert!(score > 0.9, "real room noise should not be penalized, got {score}");
    }

    // ---- compute_dictation_analytics tests ----

    #[test]
    fn analytics_empty_events() {
        let a = compute_dictation_analytics(&[], 100);
        assert_eq!(a.total_dictation_events, 0);
        assert_eq!(a.total_dictated_words, 0);
        assert!((a.dictation_ratio_words - 0.0).abs() < f64::EPSILON);
        assert!(!a.multi_speaker_detected);
    }

    #[test]
    fn analytics_single_event() {
        let ev = make_event(60, 30.0, true);
        let a = compute_dictation_analytics(&[ev], 240);
        assert_eq!(a.total_dictation_events, 1);
        assert_eq!(a.total_dictated_words, 60);
        assert!((a.dictation_ratio_words - 0.2).abs() < 0.01); // 60 / 300
        assert!(!a.multi_speaker_detected);
        assert_eq!(a.plausibility_timeline.len(), 1);
    }

    #[test]
    fn analytics_nan_wpm_filtered() {
        let mut ev = make_event(60, 30.0, true);
        ev.words_per_minute = f64::NAN;
        let a = compute_dictation_analytics(&[ev], 0);
        assert!(a.mean_wpm.is_finite(), "NaN WPM should be filtered to 0");
    }

    #[test]
    fn analytics_nan_confidence_filtered() {
        let mut ev = make_event(60, 30.0, true);
        ev.confidence_mean = f32::NAN;
        let a = compute_dictation_analytics(&[ev], 0);
        assert!(a.mean_confidence.is_finite(), "NaN confidence should be filtered");
    }

    // ---- cluster_speaker_segments tests ----

    #[test]
    fn cluster_empty_events() {
        let segments = cluster_speaker_segments(&[]);
        assert!(segments.is_empty());
    }

    #[test]
    fn cluster_single_event() {
        let ev = make_event(60, 30.0, true);
        let segments = cluster_speaker_segments(&[ev]);
        assert_eq!(segments.len(), 1);
        assert!(segments[0].is_primary_speaker);
        assert_eq!(segments[0].speaker_label, 0);
    }

    #[test]
    fn cluster_same_device_no_breaks() {
        let ev1 = make_event(30, 15.0, true);
        let mut ev2 = make_event(30, 15.0, true);
        ev2.start_ns = 15_000_000_000;
        ev2.end_ns = 30_000_000_000;
        ev2.confidence_mean = 0.01; // small diff, within threshold
        let segments = cluster_speaker_segments(&[ev1, ev2]);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].word_count, 60);
    }

    #[test]
    fn cluster_different_devices_creates_segments() {
        let ev1 = make_event(30, 15.0, true);
        let mut ev2 = make_event(30, 15.0, true);
        ev2.device_uid_hash = [1u8; 8]; // different device
        ev2.start_ns = 15_000_000_000;
        ev2.end_ns = 30_000_000_000;
        let segments = cluster_speaker_segments(&[ev1, ev2]);
        assert_eq!(segments.len(), 2);
        assert_ne!(segments[0].speaker_label, segments[1].speaker_label);
    }

    #[test]
    fn cluster_confidence_break_creates_segment() {
        let mut ev1 = make_event(30, 15.0, true);
        ev1.confidence_mean = 0.9;
        let mut ev2 = make_event(30, 15.0, true);
        ev2.confidence_mean = 0.5; // >0.15 diff
        ev2.start_ns = 15_000_000_000;
        ev2.end_ns = 30_000_000_000;
        let segments = cluster_speaker_segments(&[ev1, ev2]);
        assert_eq!(segments.len(), 2);
    }

    #[test]
    fn cluster_nan_confidence_no_break() {
        let mut ev1 = make_event(30, 15.0, true);
        ev1.confidence_mean = f32::NAN;
        let mut ev2 = make_event(30, 15.0, true);
        ev2.confidence_mean = 0.5;
        ev2.start_ns = 15_000_000_000;
        ev2.end_ns = 30_000_000_000;
        let segments = cluster_speaker_segments(&[ev1, ev2]);
        // NaN diff is not finite, so no confidence break — single segment
        assert_eq!(segments.len(), 1);
    }

    #[test]
    fn cluster_primary_speaker_is_most_words() {
        let ev1 = make_event(100, 50.0, true);
        let mut ev2 = make_event(10, 5.0, true);
        ev2.device_uid_hash = [1u8; 8];
        ev2.start_ns = 50_000_000_000;
        ev2.end_ns = 55_000_000_000;
        let segments = cluster_speaker_segments(&[ev1, ev2]);
        assert!(segments[0].is_primary_speaker);
        assert!(!segments[1].is_primary_speaker);
    }

    // ---- apply_dictation_adjustment tests ----

    #[test]
    fn adjustment_empty_events_no_change() {
        let comp = apply_dictation_adjustment(0.8, &[], 100, false);
        assert!((comp.typed_score - 0.8).abs() < f64::EPSILON);
        assert!((comp.composite_adjustment - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn adjustment_good_dictation_minimal_change() {
        let ev = make_event(60, 30.0, true);
        let comp = apply_dictation_adjustment(0.8, &[ev], 240, false);
        // 20% dictation at ~1.0 plausibility + 80% typed at 0.8 ≈ 0.84
        assert!(comp.composite_adjustment > -0.05, "good dictation should barely change score");
        assert!(!comp.multi_speaker_detected);
    }

    #[test]
    fn adjustment_multi_speaker_penalty() {
        let ev = make_event(60, 30.0, true);
        let comp = apply_dictation_adjustment(0.8, &[ev], 240, true);
        assert!(comp.multi_speaker_detected);
        assert!(comp.composite_adjustment < 0.0, "multi-speaker should apply penalty");
    }

    #[test]
    fn adjustment_low_plausibility_penalty() {
        let mut ev = make_event(60, 30.0, false); // no mic = low plausibility
        ev.words_per_minute = 300.0; // suspicious WPM
        let comp = apply_dictation_adjustment(0.8, &[ev], 0, false);
        assert!(comp.composite_adjustment < -0.1, "low plausibility should penalize");
    }
}
