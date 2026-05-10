// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Tests for the forensics module.

use super::*;
use crate::jitter::SimpleJitterSample;
use crate::utils::Probability;
use std::collections::HashMap;

fn create_test_events(count: usize) -> Vec<EventData> {
    (0..count)
        .map(|i| EventData {
            id: i as i64,
            timestamp_ns: i as i64 * 1_000_000_000,
            file_size: 100 + i as i64 * 10,
            size_delta: 10,
            file_path: "/test/file.txt".to_string(),
        })
        .collect()
}

#[allow(dead_code)]
fn make_checkpoint_proof(ordinal: u64, timestamp_ns: i64) -> crate::evidence::CheckpointProof {
    crate::evidence::CheckpointProof {
        ordinal,
        content_hash: String::new(),
        content_size: 0,
        timestamp: chrono::DateTime::from_timestamp_nanos(timestamp_ns),
        message: None,
        vdf_input: None,
        vdf_output: None,
        vdf_iterations: None,
        elapsed_time: None,
        previous_hash: String::new(),
        hash: String::new(),
        signature: None,
    }
}

fn create_test_regions() -> HashMap<i64, Vec<RegionData>> {
    let mut regions = HashMap::new();
    for i in 0..10 {
        regions.insert(
            i,
            vec![RegionData {
                start_pct: i as f32 / 10.0,
                end_pct: (i + 1) as f32 / 10.0,
                delta_sign: if i % 3 == 0 { -1 } else { 1 },
                byte_count: 10,
            }],
        );
    }
    regions
}

#[test]
fn test_monotonic_append_ratio() {
    let regions = vec![
        RegionData {
            start_pct: 0.96,
            end_pct: 0.98,
            delta_sign: 1,
            byte_count: 10,
        },
        RegionData {
            start_pct: 0.50,
            end_pct: 0.55,
            delta_sign: 1,
            byte_count: 10,
        },
        RegionData {
            start_pct: 0.97,
            end_pct: 0.99,
            delta_sign: 1,
            byte_count: 10,
        },
    ];

    let ratio = monotonic_append_ratio(&regions, 0.95);
    assert!((ratio - 0.666).abs() < 0.01);
}

#[test]
fn test_edit_entropy() {
    let regions_concentrated = vec![
        RegionData {
            start_pct: 0.5,
            end_pct: 0.51,
            delta_sign: 1,
            byte_count: 10,
        },
        RegionData {
            start_pct: 0.51,
            end_pct: 0.52,
            delta_sign: 1,
            byte_count: 10,
        },
    ];
    let entropy_low = edit_entropy(&regions_concentrated, 20);
    assert!(entropy_low < 0.1);

    let regions_spread: Vec<_> = (0..20)
        .map(|i| RegionData {
            start_pct: i as f32 / 20.0,
            end_pct: (i + 1) as f32 / 20.0,
            delta_sign: 1,
            byte_count: 10,
        })
        .collect();
    let entropy_high = edit_entropy(&regions_spread, 20);
    assert!(entropy_high > 4.0); // Max is log2(20) ~ 4.32
}

#[test]
fn test_positive_negative_ratio() {
    let regions = vec![
        RegionData {
            start_pct: 0.1,
            end_pct: 0.2,
            delta_sign: 1,
            byte_count: 10,
        },
        RegionData {
            start_pct: 0.2,
            end_pct: 0.3,
            delta_sign: 1,
            byte_count: 10,
        },
        RegionData {
            start_pct: 0.3,
            end_pct: 0.4,
            delta_sign: -1,
            byte_count: 5,
        },
        RegionData {
            start_pct: 0.4,
            end_pct: 0.5,
            delta_sign: 0,
            byte_count: 10,
        },
    ];

    let ratio = positive_negative_ratio(&regions);
    assert!((ratio - 0.666).abs() < 0.01);
}

#[test]
fn test_deletion_clustering() {
    let regions_clustered = vec![
        RegionData {
            start_pct: 0.50,
            end_pct: 0.51,
            delta_sign: -1,
            byte_count: 5,
        },
        RegionData {
            start_pct: 0.51,
            end_pct: 0.52,
            delta_sign: -1,
            byte_count: 5,
        },
        RegionData {
            start_pct: 0.52,
            end_pct: 0.53,
            delta_sign: -1,
            byte_count: 5,
        },
    ];
    let coef_clustered = deletion_clustering_coef(&regions_clustered);
    assert!(coef_clustered < 0.5);

    let regions_scattered = vec![
        RegionData {
            start_pct: 0.1,
            end_pct: 0.11,
            delta_sign: -1,
            byte_count: 5,
        },
        RegionData {
            start_pct: 0.5,
            end_pct: 0.51,
            delta_sign: -1,
            byte_count: 5,
        },
        RegionData {
            start_pct: 0.9,
            end_pct: 0.91,
            delta_sign: -1,
            byte_count: 5,
        },
    ];
    let coef_scattered = deletion_clustering_coef(&regions_scattered);
    assert!(coef_scattered > coef_clustered);
}

#[test]
fn test_cadence_analysis() {
    use crate::jitter::SimpleJitterSample;

    let robotic_samples: Vec<_> = (0..50)
        .map(|i| SimpleJitterSample {
            timestamp_ns: i as i64 * 100_000_000,
            duration_since_last_ns: 100_000_000,
            zone: 0,
            ..Default::default()
        })
        .collect();

    let cadence = analyze_cadence(&robotic_samples);
    assert!(cadence.is_robotic);
    assert!(cadence.coefficient_of_variation < ROBOTIC_CV_THRESHOLD);

    let human_samples: Vec<_> = (0..50)
        .map(|i| {
            let variation = ((i * 17) % 100) as i64 * 5_000_000;
            SimpleJitterSample {
                timestamp_ns: i as i64 * 150_000_000 + variation,
                duration_since_last_ns: 150_000_000 + variation as u64,
                zone: 0,
                ..Default::default()
            }
        })
        .collect();

    let cadence_human = analyze_cadence(&human_samples);
    assert!(!cadence_human.is_robotic);
}

#[test]
fn test_compute_primary_metrics() {
    let events = create_test_events(10);
    let regions = create_test_regions();

    let metrics = compute_primary_metrics(SortedEvents::new(&events), &regions).unwrap();

    assert!(metrics.monotonic_append_ratio >= 0.0 && metrics.monotonic_append_ratio <= 1.0);
    assert!(metrics.edit_entropy >= 0.0);
    assert!(metrics.median_interval >= 0.0);
    assert!(metrics.positive_negative_ratio >= 0.0 && metrics.positive_negative_ratio <= 1.0);
}

#[test]
fn test_insufficient_data() {
    let events = create_test_events(2);
    let regions = HashMap::new();

    let result = compute_primary_metrics(SortedEvents::new(&events), &regions);
    assert!(matches!(result, Err(ForensicsError::InsufficientData)));
}

#[test]
fn test_session_detection() {
    let mut events = create_test_events(10);
    events[5].timestamp_ns = events[4].timestamp_ns + 3_600_000_000_000; // 1 hour gap

    events.sort_by_key(|e| e.timestamp_ns);
    let sessions = detect_sessions(SortedEvents::new(&events), 1800.0);
    assert_eq!(sessions.len(), 2);
}

#[test]
fn test_correlation() {
    let correlator = ContentKeystrokeCorrelator::new();

    let input_consistent = CorrelationInput {
        document_length: 1000,
        total_keystrokes: 1200,
        detected_paste_chars: 0,
        detected_paste_count: 0,
        autocomplete_chars: 0,
        suspicious_bursts: 0,
        actual_edit_ratio: None,
    };

    let result = correlator.analyze(&input_consistent);
    assert_eq!(result.status, CorrelationStatus::Consistent);

    let input_suspicious = CorrelationInput {
        document_length: 5000,
        total_keystrokes: 1000,
        detected_paste_chars: 0,
        detected_paste_count: 0,
        autocomplete_chars: 0,
        suspicious_bursts: 5,
        actual_edit_ratio: None,
    };

    let result = correlator.analyze(&input_suspicious);
    assert!(matches!(
        result.status,
        CorrelationStatus::Suspicious | CorrelationStatus::Inconsistent
    ));
}

#[test]
fn test_profile_comparison() {
    let profile_a = AuthorshipProfile {
        metrics: PrimaryMetrics {
            monotonic_append_ratio: Probability::clamp(0.5),
            edit_entropy: 2.5,
            median_interval: 3.0,
            positive_negative_ratio: Probability::clamp(0.7),
            deletion_clustering: 0.4,
        },
        ..Default::default()
    };

    let profile_b = AuthorshipProfile {
        metrics: PrimaryMetrics {
            monotonic_append_ratio: Probability::clamp(0.55),
            edit_entropy: 2.6,
            median_interval: 3.2,
            positive_negative_ratio: Probability::clamp(0.72),
            deletion_clustering: 0.45,
        },
        ..Default::default()
    };

    let comparison = compare_profiles(&profile_a, &profile_b);
    assert!(comparison.is_consistent);
    assert!(comparison.similarity_score > 0.6);
}

#[test]
fn test_assessment_score() {
    let good_primary = PrimaryMetrics {
        monotonic_append_ratio: Probability::clamp(0.4),
        edit_entropy: 3.0,
        median_interval: 5.0,
        positive_negative_ratio: Probability::clamp(0.7),
        deletion_clustering: 0.5,
    };

    let good_cadence = CadenceMetrics {
        coefficient_of_variation: 0.4,
        is_robotic: false,
        ..Default::default()
    };

    let score = compute_assessment_score(&good_primary, &good_cadence, 0, 100, 0.0);
    assert!(score > 0.7);

    let bad_primary = PrimaryMetrics {
        monotonic_append_ratio: Probability::clamp(0.95),
        edit_entropy: 0.5,
        median_interval: 5.0,
        positive_negative_ratio: Probability::clamp(0.98),
        deletion_clustering: 1.0,
    };

    let bad_cadence = CadenceMetrics {
        coefficient_of_variation: 0.1,
        is_robotic: true,
        ..Default::default()
    };

    let bad_score = compute_assessment_score(&bad_primary, &bad_cadence, 5, 100, 0.0);
    assert!(bad_score < 0.5);
}

#[test]
fn test_report_generation() {
    let events = create_test_events(20);
    let regions = create_test_regions();
    let profile = build_profile(&events, &regions);

    let report = generate_report(&profile);
    assert!(report.contains("FORENSIC AUTHORSHIP ANALYSIS"));
    assert!(report.contains("PRIMARY METRICS"));
    assert!(report.contains("Monotonic Append Ratio"));
    assert!(report.contains("ASSESSMENT"));
}

// ── Cross-modal tests ──────────────────────────────────────────────

fn make_events(count: usize, start_ns: i64, interval_ns: i64) -> Vec<EventData> {
    (0..count)
        .map(|i| EventData {
            id: i as i64,
            timestamp_ns: start_ns + i as i64 * interval_ns,
            file_size: (i as i64 + 1) * 100,
            size_delta: 10,
            file_path: "test.txt".into(),
        })
        .collect()
}

fn make_jitter(count: usize, start_ns: i64, interval_ns: i64) -> Vec<SimpleJitterSample> {
    (0..count)
        .map(|i| SimpleJitterSample {
            timestamp_ns: start_ns + i as i64 * interval_ns,
            duration_since_last_ns: 150_000_000,
            zone: 0,
            ..Default::default()
        })
        .collect()
}

#[test]
fn test_cross_modal_marginal_on_one_failure() {
    // Reasonable session except checkpoint_count = 0 => edit_checkpoint_ratio fails
    let events = make_events(30, 1_000_000_000, 1_000_000_000);
    let input = cross_modal::CrossModalInput {
        events: &events,
        jitter_samples: None,
        document_length: 300,
        total_keystrokes: 400,
        checkpoint_count: 0,
        session_duration_sec: 30.0,
    };
    let result = cross_modal::analyze_cross_modal(&input);
    assert_eq!(result.verdict, cross_modal::CrossModalVerdict::Marginal);
}

#[test]
fn test_cross_modal_negative_document_length() {
    let events = make_events(20, 1_000_000_000, 1_000_000_000);
    let input = cross_modal::CrossModalInput {
        events: &events,
        jitter_samples: None,
        document_length: -100,
        total_keystrokes: 50,
        checkpoint_count: 5,
        session_duration_sec: 20.0,
    };
    let result = cross_modal::analyze_cross_modal(&input);
    let growth = result
        .checks
        .iter()
        .find(|c| c.name == "content_growth_rate")
        .expect("content_growth_rate check should exist");
    assert!(!growth.passed);
    assert_eq!(growth.score, 0.0);
}

#[test]
fn test_cross_modal_temporal_drift_fails_on_misaligned_spans() {
    // Edit events and jitter samples in completely different time ranges
    let events = make_events(20, 1_000_000_000, 500_000_000);
    let jitter = make_jitter(30, 500_000_000_000, 100_000_000); // 500s later
    let input = cross_modal::CrossModalInput {
        events: &events,
        jitter_samples: Some(&jitter),
        document_length: 200,
        total_keystrokes: 300,
        checkpoint_count: 5,
        session_duration_sec: 10.0,
    };
    let result = cross_modal::analyze_cross_modal(&input);
    let alignment = result
        .checks
        .iter()
        .find(|c| c.name == "temporal_span_alignment")
        .expect("temporal_span_alignment check should exist");
    assert!(!alignment.passed);
}

#[test]
fn test_cross_modal_jitter_content_entanglement_insufficient() {
    // document_length = 0 => entanglement check returns insufficient score
    let events = make_events(20, 1_000_000_000, 500_000_000);
    let jitter = make_jitter(30, 1_000_000_000, 300_000_000);
    let input = cross_modal::CrossModalInput {
        events: &events,
        jitter_samples: Some(&jitter),
        document_length: 0,
        total_keystrokes: 0,
        checkpoint_count: 5,
        session_duration_sec: 20.0,
    };
    let result = cross_modal::analyze_cross_modal(&input);
    let entanglement = result
        .checks
        .iter()
        .find(|c| c.name == "jitter_content_entanglement")
        .expect("jitter_content_entanglement check should exist");
    assert!(entanglement.passed); // returns passed=true with insufficient score
    assert!((entanglement.score - 0.5).abs() < 0.01);
}

// ── Forgery cost tests ─────────────────────────────────────────────

#[test]
fn test_forgery_cost_all_features_moderate() {
    // Software-only but with VDF + jitter + behavioral + cross-modal
    let input = forgery_cost::ForgeryCostInput {
        vdf_iterations: 500_000,
        vdf_rate: 10_000,
        checkpoint_count: 20,
        chain_duration_sec: 7200,
        has_jitter_binding: true,
        jitter_sample_count: 3000,
        has_hardware_attestation: false,
        has_behavioral_fingerprint: true,
        cross_modal_consistent: true,
        cross_modal_passed: 5,
        cross_modal_total: 5,
        has_external_time_anchor: false,
        has_content_key_entanglement: true,
    };
    let result = forgery_cost::estimate_forgery_cost(&input);
    // With VDF + jitter + behavioral + cross-modal + entanglement, difficulty is significant
    assert!(
        result.overall_difficulty > 60.0,
        "overall_difficulty={:.1}",
        result.overall_difficulty
    );
    assert!(
        !matches!(result.tier, forgery_cost::ForgeryResistanceTier::Trivial),
        "expected non-Trivial tier, got {:?}",
        result.tier,
    );
    assert!(result.estimated_forge_time_sec > 0.0);
}

#[test]
fn test_forgery_cost_empty_evidence() {
    let input = forgery_cost::ForgeryCostInput {
        vdf_iterations: 0,
        vdf_rate: 0,
        checkpoint_count: 0,
        chain_duration_sec: 0,
        has_jitter_binding: false,
        jitter_sample_count: 0,
        has_hardware_attestation: false,
        has_behavioral_fingerprint: false,
        cross_modal_consistent: false,
        cross_modal_passed: 0,
        cross_modal_total: 0,
        has_external_time_anchor: false,
        has_content_key_entanglement: false,
    };
    let result = forgery_cost::estimate_forgery_cost(&input);
    assert_eq!(result.tier, forgery_cost::ForgeryResistanceTier::Trivial);
    assert_eq!(result.overall_difficulty, 0.0);
}

#[test]
fn test_forgery_cost_external_time_anchor_infinite() {
    let input = forgery_cost::ForgeryCostInput {
        vdf_iterations: 0,
        vdf_rate: 0,
        checkpoint_count: 10,
        chain_duration_sec: 600,
        has_jitter_binding: false,
        jitter_sample_count: 0,
        has_hardware_attestation: false,
        has_behavioral_fingerprint: false,
        cross_modal_consistent: false,
        cross_modal_passed: 0,
        cross_modal_total: 0,
        has_external_time_anchor: true,
        has_content_key_entanglement: false,
    };
    let result = forgery_cost::estimate_forgery_cost(&input);
    // External time anchor has infinite cost; combined with finite checkpoint cost
    // the overall_difficulty should be boosted (finite * 100)
    assert!(result.overall_difficulty > 600.0);
}

#[test]
fn test_forgery_cost_weakest_link_is_cheapest() {
    let input = forgery_cost::ForgeryCostInput {
        vdf_iterations: 1_000_000,
        vdf_rate: 10_000, // 100s VDF
        checkpoint_count: 10,
        chain_duration_sec: 3600, // 3600s chain
        has_jitter_binding: true,
        jitter_sample_count: 50, // 50 * 0.1 = 5s jitter (cheapest)
        has_hardware_attestation: false,
        has_behavioral_fingerprint: false,
        cross_modal_consistent: false,
        cross_modal_passed: 0,
        cross_modal_total: 0,
        has_external_time_anchor: false,
        has_content_key_entanglement: false,
    };
    let result = forgery_cost::estimate_forgery_cost(&input);
    // Jitter at 5s is cheapest among present components
    assert_eq!(result.weakest_link.as_deref(), Some("jitter_entropy"));
}

// ── Velocity tests ─────────────────────────────────────────────────

#[test]
fn test_velocity_empty_and_single_event() {
    let empty: Vec<EventData> = vec![];
    let m = analyze_velocity(SortedEvents::new(&empty));
    assert_eq!(m.mean_bps, 0.0);
    assert_eq!(m.high_velocity_bursts, 0);

    let single = make_events(1, 0, 1_000_000_000);
    let m = analyze_velocity(SortedEvents::new(&single));
    assert_eq!(m.mean_bps, 0.0);
}

#[test]
fn test_velocity_detects_high_bursts() {
    // Two events 10ms apart with size_delta=10 => 1000 bps (> 100 threshold)
    let events = vec![
        EventData {
            id: 0,
            timestamp_ns: 1_000_000_000,
            file_size: 100,
            size_delta: 10,
            file_path: "t.txt".into(),
        },
        EventData {
            id: 1,
            timestamp_ns: 1_010_000_000, // 10ms later
            file_size: 110,
            size_delta: 10,
            file_path: "t.txt".into(),
        },
    ];
    let m = analyze_velocity(SortedEvents::new(&events));
    assert!(m.max_bps > THRESHOLD_HIGH_VELOCITY_BPS);
    assert_eq!(m.high_velocity_bursts, 1);
    assert!(m.autocomplete_chars > 0);
}

#[test]
fn test_velocity_normal_typing() {
    // Events 1s apart with small deltas => ~10 bps, well under threshold
    let events = make_events(20, 1_000_000_000, 1_000_000_000);
    let m = analyze_velocity(SortedEvents::new(&events));
    assert!(m.mean_bps < THRESHOLD_HIGH_VELOCITY_BPS);
    assert_eq!(m.high_velocity_bursts, 0);
    assert_eq!(m.autocomplete_chars, 0);
}

#[test]
fn test_session_stats_multi_session() {
    let mut events = make_events(20, 1_000_000_000, 1_000_000_000);
    // Insert a 2-hour gap at event 10
    for event in &mut events[10..20] {
        event.timestamp_ns += 7_200_000_000_000;
    }
    let stats = compute_session_stats(SortedEvents::new(&events));
    assert_eq!(stats.session_count, 2);
    assert!(stats.total_editing_time_sec > 0.0);
    assert!(stats.time_span_sec > 7000.0);
}

// ── Cadence tests ──────────────────────────────────────────────────

#[test]
fn test_cadence_burst_detection() {
    // Build samples: 10 fast keystrokes (50ms apart), then a 3s pause, then 5 more fast
    let mut samples = Vec::new();
    let mut t: i64 = 1_000_000_000;
    for i in 0..10 {
        samples.push(SimpleJitterSample {
            timestamp_ns: t,
            duration_since_last_ns: if i == 0 { 0 } else { 50_000_000 },
            zone: 0,
            ..Default::default()
        });
        t += 50_000_000; // 50ms
    }
    t += 3_000_000_000; // 3s pause
    for _ in 0..5 {
        samples.push(SimpleJitterSample {
            timestamp_ns: t,
            duration_since_last_ns: 50_000_000,
            zone: 0,
            ..Default::default()
        });
        t += 50_000_000;
    }

    let cadence = analyze_cadence(&samples);
    assert!(
        cadence.burst_count >= 2,
        "expected at least 2 bursts, got {}",
        cadence.burst_count
    );
    assert!(
        cadence.pause_count >= 1,
        "expected at least 1 pause, got {}",
        cadence.pause_count
    );
    assert!(cadence.avg_pause_duration_ns > 2_000_000_000.0);
}

#[test]
fn test_cadence_single_sample() {
    let samples = vec![SimpleJitterSample {
        timestamp_ns: 1_000_000_000,
        duration_since_last_ns: 0,
        zone: 0,
        ..Default::default()
    }];
    let cadence = analyze_cadence(&samples);
    assert_eq!(cadence.mean_iki_ns, 0.0);
    assert_eq!(cadence.burst_count, 0);
}

#[test]
fn test_is_retyped_content_robotic() {
    // Perfectly uniform 100ms intervals => robotic => retyped
    let samples: Vec<_> = (0..30)
        .map(|i| SimpleJitterSample {
            timestamp_ns: i as i64 * 100_000_000,
            duration_since_last_ns: 100_000_000,
            zone: 0,
            ..Default::default()
        })
        .collect();
    assert!(is_retyped_content(&samples));
}

#[test]
fn test_is_retyped_content_human() {
    // Variable intervals => not robotic
    let samples: Vec<_> = (0..30)
        .map(|i| {
            let jitter = ((i * 37) % 200) as i64 * 1_000_000;
            SimpleJitterSample {
                timestamp_ns: i as i64 * 150_000_000 + jitter,
                duration_since_last_ns: 150_000_000,
                zone: 0,
                ..Default::default()
            }
        })
        .collect();
    assert!(!is_retyped_content(&samples));
}

#[test]
fn test_cadence_percentiles_ordered() {
    let samples: Vec<_> = (0..100)
        .map(|i| {
            let variation = ((i * 13) % 50) as i64 * 2_000_000;
            SimpleJitterSample {
                timestamp_ns: i as i64 * 120_000_000 + variation,
                duration_since_last_ns: 120_000_000,
                zone: 0,
                ..Default::default()
            }
        })
        .collect();
    let cadence = analyze_cadence(&samples);
    // p10 <= p25 <= p50 <= p75 <= p90
    for w in cadence.percentiles.windows(2) {
        assert!(
            w[0] <= w[1],
            "percentiles not monotonic: {:?}",
            cadence.percentiles
        );
    }
}

// ---------------------------------------------------------------------------
// per_checkpoint_flags / analyze_focus_patterns
// ---------------------------------------------------------------------------

// per_checkpoint_flags tests removed: function was refactored out of analysis module.

// ---------------------------------------------------------------------------
// analyze_focus_patterns
// ---------------------------------------------------------------------------

#[test]
fn test_analyze_focus_patterns_empty() {
    let result = analysis::analyze_focus_patterns(&[], 10_000);
    assert_eq!(result.switch_count, 0);
    assert_eq!(result.ai_app_switch_count, 0);
    assert!(!result.reading_pattern_detected);
}

#[test]
fn test_analyze_focus_patterns_zero_session() {
    use crate::sentinel::types::FocusSwitchRecord;
    let switches = vec![FocusSwitchRecord {
        lost_at: std::time::SystemTime::now(),
        regained_at: None,
        target_app: "TextEdit".to_string(),
        target_bundle_id: "com.apple.TextEdit".to_string(),
    }];
    let result = analysis::analyze_focus_patterns(&switches, 0);
    assert_eq!(result.switch_count, 0);
}

#[test]
fn test_analyze_focus_patterns_ai_app_detection() {
    use crate::sentinel::types::FocusSwitchRecord;
    let now = std::time::SystemTime::now();
    let switches = vec![
        FocusSwitchRecord {
            lost_at: now,
            regained_at: Some(now + std::time::Duration::from_secs(5)),
            target_app: "ChatGPT".to_string(),
            target_bundle_id: "com.openai.chatgpt".to_string(),
        },
        FocusSwitchRecord {
            lost_at: now + std::time::Duration::from_secs(10),
            regained_at: Some(now + std::time::Duration::from_secs(15)),
            target_app: "Claude".to_string(),
            target_bundle_id: "com.anthropic.claude".to_string(),
        },
    ];
    let result = analysis::analyze_focus_patterns(&switches, 60_000);
    assert_eq!(result.switch_count, 2);
    assert_eq!(result.ai_app_switch_count, 2);
}

#[test]
fn test_analyze_focus_patterns_reading_pattern() {
    use crate::sentinel::types::FocusSwitchRecord;
    let now = std::time::SystemTime::now();

    // 4 rapid short switches to the same browser (< 10s each)
    let switches: Vec<FocusSwitchRecord> = (0..4)
        .map(|i| FocusSwitchRecord {
            lost_at: now + std::time::Duration::from_secs(i * 15),
            regained_at: Some(now + std::time::Duration::from_secs(i * 15 + 5)),
            target_app: "Safari".to_string(),
            target_bundle_id: "com.apple.Safari".to_string(),
        })
        .collect();

    let result = analysis::analyze_focus_patterns(&switches, 120_000);
    assert!(result.reading_pattern_detected);
}

#[test]
fn test_analyze_focus_patterns_out_of_focus_ratio() {
    use crate::sentinel::types::FocusSwitchRecord;
    let now = std::time::SystemTime::now();
    let switches = vec![FocusSwitchRecord {
        lost_at: now,
        regained_at: Some(now + std::time::Duration::from_secs(30)),
        target_app: "Finder".to_string(),
        target_bundle_id: "com.apple.Finder".to_string(),
    }];
    // 30s away out of 60s session = 0.5 ratio
    let result = analysis::analyze_focus_patterns(&switches, 60_000);
    assert!(result.out_of_focus_ratio.get() > 0.4);
    assert!(result.out_of_focus_ratio.get() < 0.6);
}

// ---------------------------------------------------------------------------
// analyze_forensics (integration)
// ---------------------------------------------------------------------------

#[test]
fn test_analyze_forensics_minimal() {
    let events = create_test_events(20);
    let regions = create_test_regions();
    let metrics = analysis::analyze_forensics(&events, &regions, None, None, None);
    // Should produce a valid assessment score
    assert!(metrics.assessment_score.get() >= 0.0);
    assert!(metrics.assessment_score.get() <= 1.0);
}

#[test]
fn test_analyze_forensics_with_jitter() {
    let events = create_test_events(50);
    let regions = create_test_regions();

    let samples: Vec<SimpleJitterSample> = (0..50)
        .map(|i| {
            let variation = ((i * 7) % 30) as i64 * 5_000_000;
            SimpleJitterSample {
                timestamp_ns: i as i64 * 150_000_000 + variation,
                duration_since_last_ns: 150_000_000,
                zone: (i % 8) as u8,
                ..Default::default()
            }
        })
        .collect();

    let metrics = analysis::analyze_forensics(&events, &regions, Some(&samples), None, None);
    assert!(metrics.assessment_score.get() >= 0.0);
    // With jitter, cadence should be populated
    assert!(metrics.cadence.mean_iki_ns > 0.0);
}

#[test]
fn test_analyze_forensics_insufficient_events() {
    let events = create_test_events(2); // Below MIN_EVENTS_FOR_ANALYSIS
    let regions = HashMap::new();
    let metrics = analysis::analyze_forensics(&events, &regions, None, None, None);
    // Should still return valid metrics without panicking
    assert!(metrics.assessment_score.get() >= 0.0);
}

#[test]
fn test_analyze_forensics_ext_with_context() {
    let events = create_test_events(30);
    let regions = create_test_regions();
    let context = analysis::AnalysisContext {
        document_length: 5000,
        total_keystrokes: 300,
        checkpoint_count: 5,
        attestation_tier: None,
    };
    let metrics = analysis::analyze_forensics_ext(&events, &regions, None, None, None, &context);
    assert!(metrics.assessment_score.get() >= 0.0);
    assert_eq!(metrics.checkpoint_count, 5);
}

// ---------------------------------------------------------------------------
// assessment: compute_assessment_score
// ---------------------------------------------------------------------------

#[test]
fn test_assessment_score_insufficient_events() {
    let primary = PrimaryMetrics::default();
    let cadence = CadenceMetrics::default();
    let score = assessment::compute_assessment_score(&primary, &cadence, 0, 2, 0.0);
    assert_eq!(score, 0.0, "too few events should return 0.0");
}

#[test]
fn test_assessment_score_perfect_human() {
    let primary = PrimaryMetrics {
        monotonic_append_ratio: Probability::clamp(0.5),
        edit_entropy: 3.5,
        positive_negative_ratio: Probability::clamp(0.7),
        deletion_clustering: 0.5,
        ..Default::default()
    };
    let cadence = CadenceMetrics {
        coefficient_of_variation: 0.5,
        is_robotic: false,
        correction_ratio: Probability::clamp(0.1),
        post_pause_cv: 0.6,
        pause_depth_distribution: [0.3, 0.4, 0.3],
        ..Default::default()
    };
    let score = assessment::compute_assessment_score(&primary, &cadence, 0, 100, 0.8);
    assert!(
        score > 0.8,
        "human-like input should score high, got {score}"
    );
}

#[test]
fn test_assessment_score_robotic_penalized() {
    let primary = PrimaryMetrics {
        monotonic_append_ratio: Probability::clamp(0.95),
        edit_entropy: 0.5,
        positive_negative_ratio: Probability::clamp(0.98),
        deletion_clustering: 1.0,
        ..Default::default()
    };
    let cadence = CadenceMetrics {
        coefficient_of_variation: 0.05,
        is_robotic: true,
        zero_variance_windows: 5,
        ..Default::default()
    };
    let score = assessment::compute_assessment_score(&primary, &cadence, 3, 100, 0.0);
    assert!(score < 0.4, "robotic input should score low, got {score}");
}

#[test]
fn test_assessment_score_anomalies_reduce_score() {
    let primary = PrimaryMetrics {
        monotonic_append_ratio: Probability::clamp(0.5),
        edit_entropy: 3.0,
        positive_negative_ratio: Probability::clamp(0.6),
        ..Default::default()
    };
    let cadence = CadenceMetrics {
        coefficient_of_variation: 0.4,
        ..Default::default()
    };
    let score_no_anomalies = assessment::compute_assessment_score(&primary, &cadence, 0, 100, 0.0);
    let score_with_anomalies =
        assessment::compute_assessment_score(&primary, &cadence, 5, 100, 0.0);
    assert!(
        score_with_anomalies < score_no_anomalies,
        "anomalies should reduce score"
    );
}

// ---------------------------------------------------------------------------
// assessment: determine_risk_level
// ---------------------------------------------------------------------------

#[test]
fn test_risk_level_insufficient() {
    assert_eq!(
        assessment::determine_risk_level(0.9, 2),
        RiskLevel::Insufficient
    );
}

#[test]
fn test_risk_level_low() {
    assert_eq!(assessment::determine_risk_level(0.8, 100), RiskLevel::Low);
}

#[test]
fn test_risk_level_medium() {
    assert_eq!(
        assessment::determine_risk_level(0.5, 100),
        RiskLevel::Medium
    );
}

#[test]
fn test_risk_level_high() {
    assert_eq!(assessment::determine_risk_level(0.2, 100), RiskLevel::High);
}

// ---------------------------------------------------------------------------
// assessment: compute_cadence_score
// ---------------------------------------------------------------------------

#[test]
fn test_cadence_score_robotic() {
    let cadence = CadenceMetrics {
        is_robotic: true,
        coefficient_of_variation: 0.05,
        percentiles: [0.0, 0.0, 0.0, 0.0, 100.0],
        ..Default::default()
    };
    let score = assessment::compute_cadence_score(&cadence);
    assert!(score < 0.5, "robotic cadence should score low, got {score}");
}

#[test]
fn test_cadence_score_normal() {
    let cadence = CadenceMetrics {
        is_robotic: false,
        coefficient_of_variation: 0.5,
        percentiles: [50.0, 80.0, 120.0, 180.0, 300.0],
        ..Default::default()
    };
    let score = assessment::compute_cadence_score(&cadence);
    assert!(score > 0.8, "normal cadence should score high, got {score}");
}

#[test]
fn test_cadence_score_no_data() {
    let cadence = CadenceMetrics {
        percentiles: [0.0; 5],
        ..Default::default()
    };
    let score = assessment::compute_cadence_score(&cadence);
    assert_eq!(score, 0.0, "no data should return 0.0");
}

// ---------------------------------------------------------------------------
// assessment: apply_focus_penalties
// ---------------------------------------------------------------------------

#[test]
fn test_focus_penalties_reading_pattern() {
    let mut score = Probability::clamp(0.9);
    let focus = FocusMetrics {
        reading_pattern_detected: true,
        ..Default::default()
    };
    assessment::apply_focus_penalties(&mut score, &focus);
    assert!(score.get() < 0.9, "reading pattern should reduce score");
}

#[test]
fn test_focus_penalties_ai_switches() {
    let mut score = Probability::clamp(0.9);
    let focus = FocusMetrics {
        ai_app_switch_count: 10,
        ..Default::default()
    };
    assessment::apply_focus_penalties(&mut score, &focus);
    assert!(score.get() < 0.9, "AI switches should reduce score");
}

#[test]
fn test_focus_penalties_no_flags() {
    let mut score = Probability::clamp(0.9);
    let focus = FocusMetrics::default();
    assessment::apply_focus_penalties(&mut score, &focus);
    assert_eq!(score.get(), 0.9, "no flags should not change score");
}
