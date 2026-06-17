// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers;
use super::*;
use crate::jitter::{default_parameters, Session};
use chrono::Timelike;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_hardware_class_detection() {
    let hw = helpers::detect_hardware_class();
    assert!(!hw.arch.is_empty());
    assert!(!hw.core_bucket.is_empty());
}

#[test]
fn test_os_type_detection() {
    let os = helpers::detect_os_type();
    #[cfg(target_os = "macos")]
    assert_eq!(os, OsType::MacOS);
    #[cfg(target_os = "linux")]
    assert_eq!(os, OsType::Linux);
    #[cfg(target_os = "windows")]
    assert_eq!(os, OsType::Windows);
}

#[test]
fn test_timestamp_rounding() {
    use chrono::Utc;
    let ts = Utc::now();
    let rounded = helpers::round_timestamp_to_hour(ts);
    assert_eq!(rounded.minute(), 0);
    assert_eq!(rounded.second(), 0);
    assert_eq!(rounded.nanosecond(), 0);
}

#[test]
fn test_anonymized_session_creation() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "test content").unwrap();
    temp_file.flush().unwrap();

    let params = default_parameters();
    let mut session = Session::new(temp_file.path(), params).unwrap();

    for _ in 0..100 {
        let _ = session.record_keystroke();
    }

    let evidence = session.export();
    let anonymized = AnonymizedSession::from_evidence(&evidence);

    assert!(!anonymized.research_id.is_empty());
    assert_eq!(anonymized.collected_at.minute(), 0);
    assert!(!anonymized.hardware_class.arch.is_empty());
}

#[test]
fn test_research_collector_disabled() {
    use crate::config::ResearchConfig;
    use crate::jitter::{Evidence, Statistics};
    use chrono::Utc;

    let config = ResearchConfig {
        contribute_to_research: false,
        ..Default::default()
    };

    let mut collector = ResearchCollector::new(config);
    assert!(!collector.config.contribute_to_research);

    let evidence = Evidence {
        session_id: "test".to_string(),
        started_at: Utc::now(),
        ended_at: Utc::now(),
        document_path: "/test".to_string(),
        params: default_parameters(),
        samples: vec![],
        statistics: Statistics::default(),
    };

    collector.add_session(&evidence);
    assert_eq!(collector.sessions.len(), 0);
}

#[test]
fn test_memory_bucket() {
    assert_eq!(helpers::memory_gb_to_bucket(2), "<=4GB");
    assert_eq!(helpers::memory_gb_to_bucket(6), "4-8GB");
    assert_eq!(helpers::memory_gb_to_bucket(12), "8-16GB");
    assert_eq!(helpers::memory_gb_to_bucket(24), "16-32GB");
    assert_eq!(helpers::memory_gb_to_bucket(64), "32GB+");
}

#[test]
fn test_memory_bucket_boundaries() {
    assert_eq!(helpers::memory_gb_to_bucket(0), "<=4GB");
    assert_eq!(helpers::memory_gb_to_bucket(4), "<=4GB");
    assert_eq!(helpers::memory_gb_to_bucket(5), "4-8GB");
    assert_eq!(helpers::memory_gb_to_bucket(8), "4-8GB");
    assert_eq!(helpers::memory_gb_to_bucket(9), "8-16GB");
    assert_eq!(helpers::memory_gb_to_bucket(16), "8-16GB");
    assert_eq!(helpers::memory_gb_to_bucket(17), "16-32GB");
    assert_eq!(helpers::memory_gb_to_bucket(32), "16-32GB");
    assert_eq!(helpers::memory_gb_to_bucket(33), "32GB+");
}

#[test]
fn test_research_id_uniqueness() {
    let id1 = helpers::generate_research_id();
    let id2 = helpers::generate_research_id();
    assert_ne!(id1, id2);
    assert_eq!(id1.len(), 32); // 16 bytes hex-encoded
    assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_collector_enabled_with_sufficient_samples() {
    use crate::config::ResearchConfig;
    use crate::jitter::{Evidence, Sample, Statistics};
    use chrono::Utc;

    let config = ResearchConfig {
        contribute_to_research: true,
        min_samples_per_session: 3,
        ..Default::default()
    };

    let mut collector = ResearchCollector::new(config);
    assert!(collector.config.contribute_to_research);

    let now = Utc::now();
    let samples: Vec<Sample> = (0..5)
        .map(|i| Sample {
            timestamp: now,
            keystroke_count: i as u64,
            document_hash: [0u8; 32],
            jitter_micros: 100 + i * 10,
            hash: [0u8; 32],
            previous_hash: [0u8; 32],
        })
        .collect();

    let evidence = Evidence {
        session_id: "test-enabled".to_string(),
        started_at: now,
        ended_at: now,
        document_path: "/test".to_string(),
        params: default_parameters(),
        samples,
        statistics: Statistics {
            total_keystrokes: 5,
            total_samples: 5,
            duration: std::time::Duration::from_secs(60),
            keystrokes_per_min: 50.0,
            unique_doc_hashes: 1,
            chain_valid: true,
        },
    };

    collector.add_session(&evidence);
    assert_eq!(collector.sessions.len(), 1);
}

#[test]
fn test_collector_rejects_insufficient_samples() {
    use crate::config::ResearchConfig;
    use crate::jitter::{Evidence, Statistics};
    use chrono::Utc;

    let config = ResearchConfig {
        contribute_to_research: true,
        min_samples_per_session: 10,
        ..Default::default()
    };

    let mut collector = ResearchCollector::new(config);

    let evidence = Evidence {
        session_id: "too-few".to_string(),
        started_at: Utc::now(),
        ended_at: Utc::now(),
        document_path: "/test".to_string(),
        params: default_parameters(),
        samples: vec![], // 0 samples, below threshold of 10
        statistics: Statistics::default(),
    };

    collector.add_session(&evidence);
    assert_eq!(collector.sessions.len(), 0);
}

#[test]
fn test_collector_max_sessions_eviction() {
    use crate::config::ResearchConfig;
    use crate::jitter::{Evidence, Sample, Statistics};
    use chrono::Utc;

    let config = ResearchConfig {
        contribute_to_research: true,
        min_samples_per_session: 1,
        max_sessions: 3,
        ..Default::default()
    };

    let mut collector = ResearchCollector::new(config);

    let now = Utc::now();
    for i in 0..5 {
        let evidence = Evidence {
            session_id: format!("session-{}", i),
            started_at: now,
            ended_at: now,
            document_path: "/test".to_string(),
            params: default_parameters(),
            samples: vec![Sample {
                timestamp: now,
                keystroke_count: 1,
                document_hash: [0u8; 32],
                jitter_micros: 100,
                hash: [0u8; 32],
                previous_hash: [0u8; 32],
            }],
            statistics: Statistics::default(),
        };
        collector.add_session(&evidence);
    }

    assert_eq!(collector.sessions.len(), 3);
}

#[test]
fn test_export_format_fields() {
    use crate::config::ResearchConfig;

    let config = ResearchConfig {
        contribute_to_research: true,
        ..Default::default()
    };

    let collector = ResearchCollector::new(config);
    let export = collector.export();

    assert_eq!(export.version, 1);
    assert!(export.consent_confirmed);
    assert!(export.sessions.is_empty());
}

#[test]
fn test_export_json_valid() {
    use crate::config::ResearchConfig;
    use crate::jitter::{Evidence, Sample, Statistics};
    use chrono::Utc;

    let config = ResearchConfig {
        contribute_to_research: true,
        min_samples_per_session: 1,
        ..Default::default()
    };

    let mut collector = ResearchCollector::new(config);

    let now = Utc::now();
    let evidence = Evidence {
        session_id: "json-test".to_string(),
        started_at: now,
        ended_at: now,
        document_path: "/test".to_string(),
        params: default_parameters(),
        samples: vec![Sample {
            timestamp: now,
            keystroke_count: 1,
            document_hash: [0u8; 32],
            jitter_micros: 500,
            hash: [0u8; 32],
            previous_hash: [0u8; 32],
        }],
        statistics: Statistics {
            total_keystrokes: 1,
            total_samples: 1,
            duration: std::time::Duration::from_secs(120),
            keystrokes_per_min: 30.0,
            unique_doc_hashes: 1,
            chain_valid: true,
        },
    };

    collector.add_session(&evidence);
    let json = collector.export_json().expect("JSON export should succeed");

    let parsed: ResearchDataExport =
        serde_json::from_str(&json).expect("exported JSON should parse back");
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.sessions.len(), 1);
    assert_eq!(parsed.sessions[0].samples.len(), 1);
    // Laplace noise (scale = jitter * 0.03 = 15) is applied during anonymization,
    // so the value will be close to 500 but not exact.
    let jitter = parsed.sessions[0].samples[0].jitter_micros;
    assert!(
        (400..=600).contains(&jitter),
        "jitter_micros {jitter} should be near 500 (Laplace noise applied)"
    );
}

#[test]
fn test_should_upload_threshold() {
    use crate::config::ResearchConfig;
    use crate::jitter::{Evidence, Sample, Statistics};
    use chrono::Utc;

    let config = ResearchConfig {
        contribute_to_research: true,
        min_samples_per_session: 1,
        ..Default::default()
    };

    let mut collector = ResearchCollector::new(config);
    assert!(!collector.should_upload());

    let now = Utc::now();
    for i in 0..MIN_SESSIONS_FOR_UPLOAD {
        let evidence = Evidence {
            session_id: format!("upload-{}", i),
            started_at: now,
            ended_at: now,
            document_path: "/test".to_string(),
            params: default_parameters(),
            samples: vec![Sample {
                timestamp: now,
                keystroke_count: 1,
                document_hash: [0u8; 32],
                jitter_micros: 100,
                hash: [0u8; 32],
                previous_hash: [0u8; 32],
            }],
            statistics: Statistics::default(),
        };
        collector.add_session(&evidence);
    }

    assert!(collector.should_upload());
}

#[test]
fn test_anonymized_statistics_computation() {
    use crate::jitter::Statistics;

    let samples = vec![
        AnonymizedSample {
            relative_time_secs: 0.0,
            jitter_micros: 100,
            keystroke_ordinal: 0,
            document_changed: true,
        },
        AnonymizedSample {
            relative_time_secs: 1.0,
            jitter_micros: 200,
            keystroke_ordinal: 1,
            document_changed: false,
        },
        AnonymizedSample {
            relative_time_secs: 2.0,
            jitter_micros: 300,
            keystroke_ordinal: 2,
            document_changed: true,
        },
    ];

    let stats = Statistics {
        total_keystrokes: 3,
        total_samples: 3,
        duration: std::time::Duration::from_secs(600),
        keystrokes_per_min: 45.0,
        unique_doc_hashes: 2,
        chain_valid: true,
    };

    let anon = helpers::compute_anonymized_statistics(&stats, &samples, None);
    assert_eq!(anon.total_samples, 3);
    assert_eq!(anon.duration_bucket, "5-15min");
    assert_eq!(anon.typing_rate_bucket, "moderate");
    assert_eq!(anon.min_jitter_micros, 100);
    assert_eq!(anon.max_jitter_micros, 300);
    // Laplace noise (scale = mean * 0.05 = 10) is applied for differential privacy,
    // so the value will be close to 200 but not exact.
    assert!(
        (anon.mean_jitter_micros - 200.0).abs() < 50.0,
        "mean_jitter_micros {} should be near 200.0 (Laplace noise applied)",
        anon.mean_jitter_micros
    );
    assert!(anon.jitter_std_dev > 0.0);
    assert!(anon.phys_ratio.is_none());
    assert!(anon.entropy_source.is_none());
}

#[test]
fn test_anonymized_statistics_empty_samples() {
    use crate::jitter::Statistics;

    let stats = Statistics::default();
    let anon = helpers::compute_anonymized_statistics(&stats, &[], None);

    assert_eq!(anon.total_samples, 0);
    assert_eq!(anon.mean_jitter_micros, 0.0);
    assert_eq!(anon.jitter_std_dev, 0.0);
    assert_eq!(anon.min_jitter_micros, 0);
    assert_eq!(anon.max_jitter_micros, 0);
    assert_eq!(anon.duration_bucket, "0-5min");
}

#[test]
fn test_collector_save_and_load() {
    use crate::config::ResearchConfig;
    use crate::jitter::{Evidence, Sample, Statistics};
    use chrono::Utc;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let config = ResearchConfig {
        contribute_to_research: true,
        min_samples_per_session: 1,
        research_data_dir: tmp.path().join("research"),
        ..Default::default()
    };

    let mut collector = ResearchCollector::new(config.clone());

    let now = Utc::now();
    let evidence = Evidence {
        session_id: "save-load".to_string(),
        started_at: now,
        ended_at: now,
        document_path: "/test".to_string(),
        params: default_parameters(),
        samples: vec![Sample {
            timestamp: now,
            keystroke_count: 1,
            document_hash: [0u8; 32],
            jitter_micros: 42,
            hash: [0u8; 32],
            previous_hash: [0u8; 32],
        }],
        statistics: Statistics::default(),
    };

    collector.add_session(&evidence);
    assert_eq!(collector.sessions.len(), 1);
    collector.save().expect("save should succeed");

    let mut loader = ResearchCollector::new(config);
    loader.load().expect("load should succeed");
    assert_eq!(loader.sessions.len(), 1);
}
