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

    crate::utils::Probability::clamp(score).get()
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
        }
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
}
