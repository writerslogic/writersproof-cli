// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::fingerprint::activity::WeightedDistribution;
use crate::jitter::SimpleJitterSample;

fn make_samples_with_dwell(n: usize) -> Vec<SimpleJitterSample> {
    // Zone pattern produces varied digraphs: zone = (i*3 + i*i/7) % 8
    // This generates 10+ unique zone pairs for n >= 20.
    (0..n)
        .map(|i| SimpleJitterSample {
            timestamp_ns: (i as i64) * 200_000_000,
            duration_since_last_ns: if i == 0 { 0 } else { 200_000_000 },
            zone: ((i * 3 + (i * i) / 7) % 8) as u8,
            dwell_time_ns: Some(80_000_000 + (i as u64 % 40) * 1_000_000),
            flight_time_ns: Some(100_000_000 + (i as u64 % 50) * 1_000_000),
            ..Default::default()
        })
        .collect()
}

#[test]
fn test_dwell_distribution_from_samples() {
    let samples = make_samples_with_dwell(50);
    let dist = DwellDistribution::from_samples(&samples);
    assert!(dist.mean > 0.0, "dwell mean should be positive");
    assert!(dist.std_dev > 0.0, "dwell std_dev should be positive");
    assert_eq!(dist.histogram.len(), 20);
    let total: f64 = dist.histogram.iter().sum();
    assert!((total - 1.0).abs() < 1e-9, "histogram should be normalized");
}

#[test]
fn test_dwell_distribution_empty() {
    let dist = DwellDistribution::from_samples(&[]);
    assert_eq!(dist.mean, 0.0);
}

#[test]
fn test_dwell_distribution_no_dwell_data() {
    let samples: Vec<SimpleJitterSample> = (0..10)
        .map(|i| SimpleJitterSample {
            timestamp_ns: (i as i64) * 200_000_000,
            zone: 0,
            dwell_time_ns: None,
            ..Default::default()
        })
        .collect();
    let dist = DwellDistribution::from_samples(&samples);
    assert_eq!(dist.mean, 0.0);
}

#[test]
fn test_dwell_similarity_self() {
    let samples = make_samples_with_dwell(50);
    let dist = DwellDistribution::from_samples(&samples);
    let sim = WeightedDistribution::similarity(&dist, &dist);
    assert!(sim > 0.95, "self-similarity should be near 1.0, got {}", sim);
}

#[test]
fn test_dwell_merge() {
    let samples = make_samples_with_dwell(50);
    let mut d1 = DwellDistribution::from_samples(&samples[..25]);
    let d2 = DwellDistribution::from_samples(&samples[25..]);
    d1.weighted_merge(&d2, 0.5, 0.5);
    assert!(d1.mean > 0.0);
}

#[test]
fn test_flight_distribution_from_samples() {
    let samples = make_samples_with_dwell(50);
    let dist = FlightTimeDistribution::from_samples(&samples);
    assert!(dist.mean > 0.0, "flight mean should be positive");
    assert_eq!(dist.histogram.len(), 20);
}

#[test]
fn test_flight_distribution_empty() {
    let dist = FlightTimeDistribution::from_samples(&[]);
    assert_eq!(dist.mean, 0.0);
}

#[test]
fn test_flight_similarity_self() {
    let samples = make_samples_with_dwell(50);
    let dist = FlightTimeDistribution::from_samples(&samples);
    let sim = WeightedDistribution::similarity(&dist, &dist);
    assert!(sim > 0.95, "self-similarity should be near 1.0, got {}", sim);
}

#[test]
fn test_flight_merge() {
    let samples = make_samples_with_dwell(50);
    let mut f1 = FlightTimeDistribution::from_samples(&samples[..25]);
    let f2 = FlightTimeDistribution::from_samples(&samples[25..]);
    f1.weighted_merge(&f2, 0.5, 0.5);
    assert!(f1.mean > 0.0);
}

#[test]
fn test_digraph_profile_from_samples() {
    let samples = make_samples_with_dwell(100);
    let profile = DigraphProfile::from_samples(&samples);
    assert!(
        !profile.digraph_timings.is_empty(),
        "digraph timings should not be empty"
    );
    for timing in profile.digraph_timings.values() {
        assert!(timing.count > 0);
        assert!(timing.mean_ms > 0.0);
    }
}

#[test]
fn test_digraph_profile_empty() {
    let profile = DigraphProfile::from_samples(&[]);
    assert!(profile.digraph_timings.is_empty());
}

#[test]
fn test_digraph_similarity_self() {
    let samples = make_samples_with_dwell(100);
    let profile = DigraphProfile::from_samples(&samples);
    let sim = WeightedDistribution::similarity(&profile, &profile);
    assert!(sim > 0.95, "self-similarity should be near 1.0, got {}", sim);
}

#[test]
fn test_digraph_similarity_few_shared() {
    let s1: Vec<SimpleJitterSample> = (0..5)
        .map(|i| SimpleJitterSample {
            timestamp_ns: (i as i64) * 200_000_000,
            zone: 0,
            ..Default::default()
        })
        .collect();
    let s2: Vec<SimpleJitterSample> = (0..5)
        .map(|i| SimpleJitterSample {
            timestamp_ns: (i as i64) * 200_000_000,
            zone: 7,
            ..Default::default()
        })
        .collect();
    let p1 = DigraphProfile::from_samples(&s1);
    let p2 = DigraphProfile::from_samples(&s2);
    let sim = WeightedDistribution::similarity(&p1, &p2);
    assert!(
        (sim - 0.5).abs() < 1e-9,
        "few shared digraphs should return 0.5, got {}",
        sim
    );
}

#[test]
fn test_digraph_merge() {
    let samples = make_samples_with_dwell(100);
    let mut p1 = DigraphProfile::from_samples(&samples[..50]);
    let p2 = DigraphProfile::from_samples(&samples[50..]);
    p1.weighted_merge(&p2, 0.5, 0.5);
    assert!(!p1.digraph_timings.is_empty());
}

#[test]
fn test_dimension_confidence_saturation() {
    let dc = DimensionConfidence::from_sample_count(1000, true, true, true, 5000);
    assert!((dc.iki - 1.0).abs() < 1e-9, "iki should saturate at 200");
    assert!(
        (dc.circadian - 1.0).abs() < 1e-9,
        "circadian should saturate at 5000"
    );
    assert!(dc.overall() > 0.0);
}

#[test]
fn test_dimension_confidence_partial() {
    let dc = DimensionConfidence::from_sample_count(100, false, false, false, 0);
    assert_eq!(dc.dwell, 0.0, "no dwell data should yield 0");
    assert_eq!(dc.flight, 0.0, "no flight data should yield 0");
    assert_eq!(dc.hurst, 0.0, "no hurst data should yield 0");
    assert!(dc.iki > 0.0);
}

#[test]
fn test_iki_autocorrelation() {
    // Strongly correlated series: each IKI = previous + small delta
    let intervals: Vec<f64> = (0..50).map(|i| 100.0 + (i as f64) * 2.0).collect();
    let dist = IkiDistribution::from_intervals(&intervals);
    assert!(
        dist.autocorrelation_lag1 > 0.5,
        "monotonic series should have high lag-1 autocorrelation, got {}",
        dist.autocorrelation_lag1
    );
    assert!(
        dist.autocorrelation_lag2 > 0.3,
        "monotonic series should have positive lag-2 autocorrelation, got {}",
        dist.autocorrelation_lag2
    );
}

#[test]
fn test_iki_autocorrelation_short_series() {
    let dist = IkiDistribution::from_intervals(&[100.0, 200.0]);
    assert_eq!(dist.autocorrelation_lag2, 0.0);
}

#[test]
fn test_iki_autocorrelation_in_similarity() {
    let intervals_a: Vec<f64> = (0..50).map(|i| 100.0 + (i as f64) * 2.0).collect();
    let intervals_b: Vec<f64> = (0..50).map(|i| 100.0 + (i as f64) * 2.0).collect();
    let dist_a = IkiDistribution::from_intervals(&intervals_a);
    let dist_b = IkiDistribution::from_intervals(&intervals_b);
    let sim = WeightedDistribution::similarity(&dist_a, &dist_b);
    assert!(sim > 0.95, "identical series should have high similarity, got {}", sim);
}

#[test]
fn test_zone_dwell_means() {
    let samples = make_samples_with_dwell(50);
    let profile = ZoneProfile::from_samples(&samples);
    let has_nonzero = profile.zone_dwell_means.iter().any(|&v| v > 0.0);
    assert!(has_nonzero, "should have non-zero per-zone dwell means");
}

#[test]
fn test_zone_dwell_means_no_dwell() {
    let samples: Vec<SimpleJitterSample> = (0..10)
        .map(|i| SimpleJitterSample {
            timestamp_ns: (i as i64) * 200_000_000,
            zone: (i % 8) as u8,
            dwell_time_ns: None,
            ..Default::default()
        })
        .collect();
    let profile = ZoneProfile::from_samples(&samples);
    assert!(
        profile.zone_dwell_means.iter().all(|&v| v == 0.0),
        "no dwell data should yield all-zero zone_dwell_means"
    );
}

#[test]
fn test_zone_dwell_in_similarity() {
    let samples = make_samples_with_dwell(50);
    let profile = ZoneProfile::from_samples(&samples);
    let sim = WeightedDistribution::similarity(&profile, &profile);
    assert!(sim > 0.90, "self-similarity should be high, got {}", sim);
}

#[test]
fn test_pause_histogram() {
    let intervals: Vec<f64> = (0..100)
        .map(|i| if i % 10 == 0 { 600.0 } else { 150.0 })
        .collect();
    let sig = PauseSignature::from_intervals(&intervals);
    assert_eq!(sig.pause_histogram.len(), 20);
    let total: f64 = sig.pause_histogram.iter().sum();
    assert!(
        (total - 1.0).abs() < 1e-9 || total == 0.0,
        "histogram should be normalized or empty"
    );
}

#[test]
fn test_pause_histogram_in_similarity() {
    let intervals: Vec<f64> = (0..100)
        .map(|i| if i % 10 == 0 { 600.0 } else { 150.0 })
        .collect();
    let sig = PauseSignature::from_intervals(&intervals);
    let sim = WeightedDistribution::similarity(&sig, &sig);
    assert!(sim > 0.90, "self-similarity should be high, got {}", sim);
}

#[test]
fn test_session_burst_metrics() {
    // Mix of bursts and pauses
    let intervals = vec![
        100.0, 80.0, 120.0, 90.0, // burst of 4
        600.0, // pause
        110.0, 95.0, // burst of 2
        800.0, // pause
        150.0, // burst of 1
    ];
    let mut sig = SessionSignature::default();
    sig.compute_burst_metrics(&intervals);
    assert!(
        sig.burst_pause_ratio > 0.0 && sig.burst_pause_ratio < 1.0,
        "burst_pause_ratio should be between 0 and 1, got {}",
        sig.burst_pause_ratio
    );
    assert!(
        sig.mean_burst_length > 0.0,
        "mean_burst_length should be positive, got {}",
        sig.mean_burst_length
    );
}

#[test]
fn test_session_burst_metrics_empty() {
    let mut sig = SessionSignature::default();
    sig.compute_burst_metrics(&[]);
    assert_eq!(sig.burst_pause_ratio, 0.0);
    assert_eq!(sig.mean_burst_length, 0.0);
}

#[test]
fn test_dimension_confidence_circadian_downweight() {
    let dc = DimensionConfidence::from_sample_count(1000, true, true, true, 5000);
    // Verify circadian gets 0.05 weight (half of others)
    let weights = [0.25, 0.15, 0.10, 0.10, 0.10, 0.15, 0.05, 0.05];
    let values = [
        dc.iki, dc.zone, dc.pause, dc.dwell, dc.flight, dc.digraph, dc.hurst, dc.circadian,
    ];
    let expected: f64 = values
        .iter()
        .zip(weights.iter())
        .map(|(v, w)| v * w)
        .sum::<f64>()
        / weights.iter().sum::<f64>();
    assert!(
        (dc.overall() - expected).abs() < 1e-9,
        "overall should match expected weighting"
    );
}

#[test]
fn test_pearson_autocorrelation_constant() {
    let series = vec![5.0; 20];
    let r = distribution_helpers::pearson_autocorrelation(&series, 1);
    assert_eq!(r, 0.0, "constant series should have zero autocorrelation");
}
