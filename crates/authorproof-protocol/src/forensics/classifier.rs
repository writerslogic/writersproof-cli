// SPDX-License-Identifier: Apache-2.0

//! Forensic signal-to-method classification.
//!
//! Converts ForensicMetrics from the engine into MethodDetectionResult
//! with conservative confidence thresholds and human-readable signal explanations.

use crate::method_detection::{AuthorshipMethod, MethodDetectionResult, SignalSet};

/// Input signals for authorship method classification.
///
/// All fields are optional; missing signals reduce confidence.
/// Use `Default` when only a subset of signals is available.
#[derive(Debug, Clone, Default)]
pub struct ForensicSignals {
    /// Coefficient of variation of keystroke speeds (0.0-1.0).
    pub keystroke_cv: Option<f64>,
    /// Number of paste events detected.
    pub paste_count: Option<u32>,
    /// Count of perfectly regular timing windows.
    pub zero_variance_windows: Option<u32>,
    /// Fraction of keystrokes that are deletions (0.0-1.0).
    pub correction_ratio: Option<f64>,
    /// Fraction of edits that append to end (0.0-1.0).
    pub monotonic_append_ratio: Option<f64>,
    /// CV of keystrokes after pauses (0.0-1.0).
    pub post_pause_cv: Option<f64>,
    /// Count of editing pass clusters.
    pub revision_clusters: Option<u32>,
    /// CV of typing speeds within bursts (0.0-1.0).
    pub burst_speed_cv: Option<f64>,
}

/// Classify authorship method from forensic metrics.
///
/// **Confidence thresholds:**
/// - >=0.85: High confidence (auto-detect)
/// - 0.70-0.85: Uncertain (user confirmation recommended)
/// - <0.70: Insufficient signal (author attestation fallback)
pub fn classify_authorship_method(input: &ForensicSignals) -> MethodDetectionResult {
    // Collect available signals
    let mut signals = SignalSet::empty();
    let mut signal_count = 0;
    let mut dominant_signals = Vec::new();

    if let Some(cv) = input.keystroke_cv {
        signals.keystroke_variance = Some(cv);
        signal_count += 1;
    }
    if let Some(count) = input.paste_count {
        signals.paste_events = Some(count);
        signal_count += 1;
    }
    if let Some(count) = input.zero_variance_windows {
        signals.zero_variance_windows = Some(count);
        signal_count += 1;
    }
    if let Some(ratio) = input.correction_ratio {
        signals.correction_ratio = Some(ratio);
        signal_count += 1;
    }
    if let Some(ratio) = input.monotonic_append_ratio {
        signals.monotonic_append_ratio = Some(ratio);
        signal_count += 1;
    }
    if let Some(cv) = input.post_pause_cv {
        signals.post_pause_cv = Some(cv);
        signal_count += 1;
    }
    if let Some(count) = input.revision_clusters {
        signals.revision_clusters = Some(count);
        signal_count += 1;
    }
    if let Some(cv) = input.burst_speed_cv {
        signals.burst_speed_cv = Some(cv);
        signal_count += 1;
    }

    // Insufficient signals: default to author attestation
    if signal_count < 2 {
        return MethodDetectionResult::author_attested(signals);
    }

    // Conservative classification with thresholds
    let mut method = AuthorshipMethod::Undetermined;
    let mut confidence = 0.0;

    // Prompt generation indicators:
    // - High paste count + mostly append-only editing
    if input.paste_count.is_some_and(|p| p > 5)
        && input.monotonic_append_ratio.is_some_and(|m| m > 0.85)
    {
        dominant_signals.push("paste_events".to_string());
        dominant_signals.push("monotonic_append_ratio".to_string());
        method = AuthorshipMethod::PromptGeneration;
        confidence = 0.87;
    }

    // Check for zero variance (perfectly regular timing = suspicious)
    if confidence < 0.70
        && input.zero_variance_windows.is_some_and(|z| z > 3)
        && input.paste_count.is_some_and(|p| p > 2)
    {
        dominant_signals.push("zero_variance_windows".to_string());
        dominant_signals.push("paste_events".to_string());
        method = AuthorshipMethod::PromptGeneration;
        confidence = 0.85;
    }

    // Human composition indicators:
    // - High keystroke variance (variable pace)
    // - High correction ratio (lots of backspacing)
    // - Low monotonic append ratio (mixed editing)
    // - High post-pause CV (thinking after pauses)
    if confidence < 0.70 {
        let mut human_signals = 0;

        if input.keystroke_cv.is_some_and(|cv| cv > 0.35) {
            human_signals += 1;
            dominant_signals.push("keystroke_variance".to_string());
        }

        if input.correction_ratio.is_some_and(|r| r > 0.10) {
            human_signals += 1;
            dominant_signals.push("correction_ratio".to_string());
        }

        if input.monotonic_append_ratio.is_some_and(|r| r < 0.70) {
            human_signals += 1;
            dominant_signals.push("monotonic_append_ratio".to_string());
        }

        if input.post_pause_cv.is_some_and(|cv| cv > 0.30) {
            human_signals += 1;
            dominant_signals.push("post_pause_cv".to_string());
        }

        if human_signals >= 3 {
            method = AuthorshipMethod::HumanComposition;
            confidence = 0.85 + (human_signals as f64 - 3.0) * 0.03;
            confidence = confidence.min(0.95); // Cap at 0.95
        }
    }

    // Human-in-the-loop indicators:
    // - High keystroke variance AND paste events
    // - Multiple revision clusters
    // - Mixed append ratio (0.50-0.80)
    if confidence < 0.70 {
        let mut mixed_signals = 0;

        if input.keystroke_cv.is_some_and(|cv| cv > 0.30) {
            mixed_signals += 1;
        }
        if input.paste_count.is_some_and(|p| p > 0) {
            mixed_signals += 1;
        }
        if input.revision_clusters.is_some_and(|c| c > 2) {
            mixed_signals += 1;
        }
        if input.burst_speed_cv.is_some_and(|cv| cv > 0.25) {
            mixed_signals += 1;
        }

        if mixed_signals >= 3 {
            method = AuthorshipMethod::HumanInTheLoop;
            confidence = 0.78 + (mixed_signals as f64 - 3.0) * 0.03;
            confidence = confidence.min(0.90);
            dominant_signals.push("keystroke_variance".to_string());
            dominant_signals.push("paste_events".to_string());
        }
    }

    // Insufficient confidence: fall back to author attestation
    if confidence < 0.70 {
        return MethodDetectionResult::author_attested(signals);
    }

    MethodDetectionResult::auto_detected(method, confidence, signals, dominant_signals)
}

/// Human-readable explanation of a forensic signal value.
pub fn explain_signal(signal_name: &str, value: f64) -> String {
    match signal_name {
        "keystroke_variance" => {
            if value < 0.15 {
                "Low (robotic)".to_string()
            } else if value < 0.30 {
                "Moderate".to_string()
            } else {
                "High (human variability)".to_string()
            }
        }
        "burst_speed_cv" => {
            if value < 0.15 {
                "Very low (transcription)".to_string()
            } else if value < 0.25 {
                "Low (regular pacing)".to_string()
            } else {
                "High (thinking/pausing)".to_string()
            }
        }
        "monotonic_append_ratio" => {
            if value > 0.95 {
                "Very high (mostly append-only generation)".to_string()
            } else if value > 0.70 {
                "High (mostly generation)".to_string()
            } else {
                "Mixed (human editing)".to_string()
            }
        }
        "correction_ratio" => {
            if value < 0.05 {
                "Very low (no revision)".to_string()
            } else if value < 0.15 {
                "Low (minimal edits)".to_string()
            } else {
                "High (active revision)".to_string()
            }
        }
        "post_pause_cv" => {
            if value > 0.30 {
                "High (variable after thinking)".to_string()
            } else if value > 0.10 {
                "Moderate".to_string()
            } else {
                "Low (consistent recovery)".to_string()
            }
        }
        _ => "Unknown signal".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method_detection::MethodOrigin;

    #[test]
    fn test_human_composition_high_variance() {
        let result = classify_authorship_method(&ForensicSignals {
            keystroke_cv: Some(0.45),
            paste_count: Some(0),
            zero_variance_windows: Some(0),
            correction_ratio: Some(0.15),
            monotonic_append_ratio: Some(0.60),
            post_pause_cv: Some(0.35),
            revision_clusters: Some(3),
            burst_speed_cv: Some(0.30),
        });

        assert_eq!(result.method, AuthorshipMethod::HumanComposition);
        assert!(result.confidence >= 0.85);
        assert!(result.should_auto_fill());
    }

    #[test]
    fn test_prompt_generation_high_paste() {
        let result = classify_authorship_method(&ForensicSignals {
            keystroke_cv: Some(0.10),
            paste_count: Some(8),
            zero_variance_windows: Some(4),
            correction_ratio: Some(0.02),
            monotonic_append_ratio: Some(0.92),
            post_pause_cv: Some(0.05),
            revision_clusters: Some(1),
            burst_speed_cv: Some(0.12),
        });

        assert_eq!(result.method, AuthorshipMethod::PromptGeneration);
        assert!(result.confidence >= 0.85);
    }

    #[test]
    fn test_human_in_the_loop_mixed_signals() {
        let result = classify_authorship_method(&ForensicSignals {
            keystroke_cv: Some(0.35), // at threshold (not > 0.35, so no human signal)
            paste_count: Some(3),     // > 0 triggers mixed signal
            correction_ratio: Some(0.08), // below 0.10, no human signal
            monotonic_append_ratio: Some(0.75), // not < 0.70, no human signal
            post_pause_cv: Some(0.25), // below 0.30, no human signal
            revision_clusters: Some(4), // > 2 triggers mixed signal
            burst_speed_cv: Some(0.28), // > 0.25 triggers mixed signal
            ..Default::default()
        });

        assert_eq!(result.method, AuthorshipMethod::HumanInTheLoop);
        assert!(result.confidence >= 0.70);
    }

    #[test]
    fn test_insufficient_signals_author_attestation() {
        let result = classify_authorship_method(&ForensicSignals {
            keystroke_cv: Some(0.30),
            ..Default::default()
        });

        assert_eq!(result.method, AuthorshipMethod::Undetermined);
        assert_eq!(result.origin, MethodOrigin::AuthorAttested);
    }

    #[test]
    fn test_explain_signal_keystroke_variance() {
        assert!(explain_signal("keystroke_variance", 0.10).contains("robotic"));
        assert!(explain_signal("keystroke_variance", 0.45).contains("High"));
    }

    #[test]
    fn test_explain_signal_burst_speed_cv() {
        assert!(explain_signal("burst_speed_cv", 0.12).contains("transcription"));
        assert!(explain_signal("burst_speed_cv", 0.30).contains("thinking"));
    }
}
