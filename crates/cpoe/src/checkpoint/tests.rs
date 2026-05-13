// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::vdf::{self, Parameters};
use authorproof_protocol::rfc;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

fn temp_document() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("create temp dir");
    let canonical_dir = dir.path().canonicalize().expect("canonicalize temp dir");
    let path = canonical_dir.join("test_document.txt");
    fs::write(&path, b"initial content").expect("write initial content");
    (dir, path)
}

/// Create chain with Optional signature policy for tests.
fn test_chain(path: &Path) -> Chain {
    Chain::new(path, test_vdf_params())
        .expect("create chain")
        .with_signature_policy(SignaturePolicy::Optional)
}

fn test_chain_entangled(path: &Path) -> Chain {
    Chain::new_with_mode(path, test_vdf_params(), EntanglementMode::Entangled)
        .expect("create chain")
        .with_signature_policy(SignaturePolicy::Optional)
}

fn test_vdf_params() -> Parameters {
    Parameters {
        iterations_per_second: 1000,
        min_iterations: 10,
        max_iterations: 100_000,
    }
}

#[test]
fn test_chain_creation() {
    let (_dir, path) = temp_document();
    let chain = test_chain(&path);
    assert!(!chain.metadata.document_id.is_empty());
    assert!(chain.checkpoints.is_empty());
    assert_eq!(chain.metadata.document_path, path.to_string_lossy());
}

#[test]
fn test_chain_creation_invalid_path() {
    let err = Chain::new("/nonexistent/path/to/file.txt", test_vdf_params()).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("No such file") || msg.contains("cannot find the path"),
        "Unexpected error: {}",
        msg
    );
}

#[test]
fn test_single_commit() {
    let (_dir, path) = temp_document();
    let mut chain = test_chain(&path);
    let checkpoint = chain
        .commit(Some("first commit".to_string()))
        .expect("commit");

    assert_eq!(checkpoint.ordinal, 0);
    // Genesis prev-hash is now H(CBOR(document-ref)), not all-zeros
    assert_ne!(checkpoint.previous_hash, [0u8; 32]);
    assert_eq!(checkpoint.message, Some("first commit".to_string()));
    // Genesis checkpoint now always has a VDF proof (H-013 fix)
    assert!(checkpoint.vdf.is_some());
    assert_ne!(checkpoint.content_hash, [0u8; 32]);
    assert_ne!(checkpoint.hash, [0u8; 32]);
}

#[test]
fn test_multiple_commits_with_vdf() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    let cp0 = chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    assert_eq!(cp0.ordinal, 0);
    // Genesis checkpoint now always has a VDF proof (H-013 fix)
    assert!(cp0.vdf.is_some());

    fs::write(&path, b"updated content").expect("update content");

    let cp1 = chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");
    assert_eq!(cp1.ordinal, 1);
    assert!(cp1.vdf.is_some());
    assert_eq!(cp1.previous_hash, cp0.hash);

    fs::write(&path, b"final content").expect("update content again");

    let cp2 = chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 2");
    assert_eq!(cp2.ordinal, 2);
    assert!(cp2.vdf.is_some());
    assert_eq!(cp2.previous_hash, cp1.hash);

    chain.verify().expect("verify chain");

    drop(dir);
}

#[test]
fn test_chain_verification_valid() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    chain.verify().expect("verification should pass");
    drop(dir);
}

#[test]
fn test_chain_verification_hash_mismatch() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit");

    chain.checkpoints[0].hash = [0xFFu8; 32];

    let err = chain.verify().unwrap_err();
    assert!(err.to_string().contains("hash mismatch"));
    drop(dir);
}

#[test]
fn test_chain_verification_broken_chain_link() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    chain.checkpoints[1].previous_hash = [0xFFu8; 32];
    chain.checkpoints[1].hash = chain.checkpoints[1].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("broken chain link"),
        "Expected 'broken chain link', got: {}",
        err
    );
    drop(dir);
}

#[test]
fn test_chain_verification_nonzero_first_previous_hash() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit");

    chain.checkpoints[0].previous_hash = [0x01u8; 32];
    chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(err.to_string().contains("invalid genesis prev-hash"));
    drop(dir);
}

#[test]
fn test_save_and_load_chain() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(Some("test".to_string()), Duration::from_millis(10))
        .expect("commit");

    let chain_path = dir.path().join("chain.json");
    chain.save(&chain_path).expect("save chain");

    let loaded = Chain::load(&chain_path).expect("load chain");
    assert_eq!(loaded.metadata.document_id, chain.metadata.document_id);
    assert_eq!(loaded.metadata.document_path, chain.metadata.document_path);
    assert_eq!(loaded.checkpoints.len(), chain.checkpoints.len());
    assert_eq!(loaded.checkpoints[0].hash, chain.checkpoints[0].hash);
    loaded.verify().expect("loaded chain should verify");

    drop(dir);
}

#[test]
fn test_chain_summary() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    let summary = chain.summary();
    assert_eq!(summary.checkpoint_count, 2);
    assert!(summary.first_commit.is_some());
    assert!(summary.last_commit.is_some());
    assert!(summary.final_content_hash.is_some());
    assert!(summary.chain_valid.is_none());

    drop(dir);
}

#[test]
fn test_chain_latest_and_at() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    assert!(chain.latest().is_none());

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    assert!(chain.latest().is_some());
    assert_eq!(chain.latest().expect("latest after commit 0").ordinal, 0);

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");
    assert_eq!(chain.latest().expect("latest after commit 1").ordinal, 1);

    assert_eq!(chain.at(0).expect("at ordinal 0").ordinal, 0);
    assert_eq!(chain.at(1).expect("at ordinal 1").ordinal, 1);
    assert!(chain.at(2).is_err());

    drop(dir);
}

#[test]
fn test_total_elapsed_time() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    // Genesis checkpoint now has VDF, so elapsed time is > 0 (H-013 fix)
    let genesis_elapsed = chain.total_elapsed_time();
    assert!(genesis_elapsed > Duration::from_secs(0));

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(50))
        .expect("commit 1");

    let elapsed = chain.total_elapsed_time();
    assert!(elapsed > genesis_elapsed);

    drop(dir);
}

#[test]
fn test_get_or_create_chain() {
    let dir = TempDir::new().expect("create temp dir");
    let doc_path = dir.path().join("document.txt");
    let writersproof_dir = dir.path().join(".writersproof");

    fs::write(&doc_path, b"content").expect("write doc");

    let chain1 = Chain::get_or_create_chain(&doc_path, &writersproof_dir, test_vdf_params())
        .expect("get_or_create");
    assert!(chain1.checkpoints.is_empty());

    drop(dir);
}

#[test]
fn test_find_chain_not_found() {
    let dir = TempDir::new().expect("create temp dir");
    let doc_path = dir.path().join("document.txt");
    let writersproof_dir = dir.path().join(".writersproof");

    fs::write(&doc_path, b"content").expect("write doc");
    fs::create_dir_all(writersproof_dir.join("chains")).expect("create chains dir");

    let err = Chain::find_chain(&doc_path, &writersproof_dir).unwrap_err();
    assert!(err.to_string().contains("no chain found"));

    drop(dir);
}

#[test]
fn test_commit_detects_content_changes() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    let hash0 = chain.checkpoints[0].content_hash;

    fs::write(&path, b"different content").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");
    let hash1 = chain.checkpoints[1].content_hash;

    assert_ne!(hash0, hash1);

    drop(dir);
}

#[test]
fn test_vdf_verification_in_chain() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    if let Some(ref mut vdf) = chain.checkpoints[1].vdf {
        vdf.output = [0xFFu8; 32];
    }
    chain.checkpoints[1].hash = chain.checkpoints[1].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("VDF verification failed"),
        "Expected 'VDF verification failed', got: {}",
        err
    );

    drop(dir);
}

#[test]
fn test_vdf_input_mismatch_detection() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    if let Some(ref mut vdf) = chain.checkpoints[1].vdf {
        vdf.input = [0xAAu8; 32];
    }
    chain.checkpoints[1].hash = chain.checkpoints[1].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("VDF input mismatch"),
        "Expected 'VDF input mismatch', got: {}",
        err
    );

    drop(dir);
}

#[test]
fn test_entangled_chain_creation() {
    let (dir, path) = temp_document();
    let chain = test_chain_entangled(&path);
    assert_eq!(
        chain.metadata.entanglement_mode,
        EntanglementMode::Entangled
    );
    assert!(chain.checkpoints.is_empty());
    drop(dir);
}

#[test]
fn test_entangled_commit_requires_entangled_mode() {
    let (dir, path) = temp_document();
    let mut chain = Chain::new(&path, test_vdf_params()).expect("create legacy chain");

    let err = chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-1".to_string(),
            100,
            Duration::from_millis(10),
            None,
        )
        .unwrap_err();
    assert!(err.to_string().contains("EntanglementMode::Entangled"));
    drop(dir);
}

#[test]
fn test_entangled_single_commit() {
    let (dir, path) = temp_document();
    let mut chain = test_chain_entangled(&path);

    let jitter_hash = [0xABu8; 32];
    let checkpoint = chain
        .commit_entangled(
            Some("first entangled commit".to_string()),
            jitter_hash,
            "session-1".to_string(),
            50,
            Duration::from_millis(10),
            None,
        )
        .expect("commit entangled");

    assert_eq!(checkpoint.ordinal, 0);
    assert!(checkpoint.vdf.is_some());
    assert!(checkpoint.jitter_binding.is_some());
    let binding = checkpoint.jitter_binding.as_ref().expect("jitter binding");
    assert_eq!(binding.jitter_hash, jitter_hash);
    assert_eq!(binding.session_id, "session-1");
    assert_eq!(binding.keystroke_count, 50);

    chain.verify().expect("verify entangled chain");
    drop(dir);
}

#[test]
fn test_entangled_multiple_commits() {
    let (dir, path) = temp_document();
    let mut chain = test_chain_entangled(&path);

    let cp0 = chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-1".to_string(),
            10,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 0");

    fs::write(&path, b"updated content").expect("update");
    let cp1 = chain
        .commit_entangled(
            None,
            [2u8; 32],
            "session-1".to_string(),
            25,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 1");

    fs::write(&path, b"final content").expect("final update");
    let cp2 = chain
        .commit_entangled(
            None,
            [3u8; 32],
            "session-1".to_string(),
            50,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 2");

    assert_eq!(chain.checkpoints.len(), 3);
    assert_eq!(cp1.previous_hash, cp0.hash);
    assert_eq!(cp2.previous_hash, cp1.hash);

    let vdf0 = cp0.vdf.as_ref().expect("vdf proof 0");
    let vdf1 = cp1.vdf.as_ref().expect("vdf proof 1");
    let expected_input1 = vdf::chain_input_entangled(vdf0.output, [2u8; 32], cp1.content_hash, 1);
    assert_eq!(vdf1.input, expected_input1);

    chain.verify().expect("verify entangled chain");
    drop(dir);
}

#[test]
fn test_entangled_verify_detects_vdf_tampering() {
    let (dir, path) = temp_document();
    let mut chain = test_chain_entangled(&path);

    chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-1".to_string(),
            10,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_entangled(
            None,
            [2u8; 32],
            "session-1".to_string(),
            20,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 1");

    if let Some(ref mut vdf) = chain.checkpoints[0].vdf {
        vdf.output = [0xFFu8; 32];
    }
    chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("VDF verification failed"),
        "Expected VDF verification failure, got: {}",
        err
    );
    drop(dir);
}

#[test]
fn test_entangled_verify_detects_jitter_tampering() {
    let (dir, path) = temp_document();
    let mut chain = test_chain_entangled(&path);

    chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-1".to_string(),
            10,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 0");

    chain.checkpoints[0]
        .jitter_binding
        .as_mut()
        .expect("jitter binding")
        .jitter_hash = [0xFFu8; 32];
    chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("VDF input mismatch"),
        "Expected VDF input mismatch, got: {}",
        err
    );
    drop(dir);
}

#[test]
fn test_entangled_verify_requires_jitter_binding() {
    let (dir, path) = temp_document();
    let mut chain = test_chain_entangled(&path);

    chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-1".to_string(),
            10,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 0");

    chain.checkpoints[0].jitter_binding = None;
    chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

    let err = chain.verify().unwrap_err();
    assert!(
        err.to_string().contains("missing jitter binding"),
        "Expected missing jitter binding error, got: {}",
        err
    );
    drop(dir);
}

#[test]
fn test_entangled_chain_save_load() {
    let dir = TempDir::new().expect("create temp dir");
    let canonical_dir = dir.path().canonicalize().expect("canonicalize");
    let path = canonical_dir.join("test_doc.txt");
    fs::write(&path, b"test content").expect("write");

    let mut chain = test_chain_entangled(&path);

    chain
        .commit_entangled(
            Some("entangled test".to_string()),
            [0xABu8; 32],
            "session-test".to_string(),
            42,
            Duration::from_millis(10),
            None,
        )
        .expect("commit");

    let chain_path = canonical_dir.join("chain.json");
    chain.save(&chain_path).expect("save");

    let loaded = Chain::load(&chain_path).expect("load");
    assert_eq!(
        loaded.metadata.entanglement_mode,
        EntanglementMode::Entangled
    );
    assert_eq!(loaded.checkpoints.len(), 1);

    let binding = loaded.checkpoints[0]
        .jitter_binding
        .as_ref()
        .expect("loaded jitter binding");
    assert_eq!(binding.jitter_hash, [0xABu8; 32]);
    assert_eq!(binding.session_id, "session-test");
    assert_eq!(binding.keystroke_count, 42);

    loaded.verify().expect("verify loaded chain");
    drop(dir);
}

#[test]
fn test_legacy_mode_default() {
    let (dir, path) = temp_document();
    let chain = test_chain(&path);
    assert_eq!(chain.metadata.entanglement_mode, EntanglementMode::Legacy);
    drop(dir);
}

#[test]
fn test_commit_rfc_basic() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    let calibration = rfc::CalibrationAttestation::new(
        1_000_000, // 1M iterations per second
        "test-hardware".to_string(),
        vec![0u8; 64], // dummy signature
        1700000000,
    );

    let checkpoint = chain
        .commit_rfc(
            Some("RFC-compliant commit".to_string()),
            Duration::from_millis(10),
            None, // No jitter binding
            None, // No time evidence
            calibration,
            None,
        )
        .expect("commit_rfc");

    assert_eq!(checkpoint.ordinal, 0);
    assert!(checkpoint.vdf.is_none());
    assert!(checkpoint.rfc_vdf.is_none());
    assert!(checkpoint.rfc_jitter.is_none());
    assert!(checkpoint.time_evidence.is_none());

    chain.verify().expect("verify chain");
    drop(dir);
}

#[test]
fn test_commit_rfc_with_jitter_binding() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    let entropy_commitment = rfc::jitter_binding::EntropyCommitment {
        hash: [0xABu8; 32],
        timestamp_ms: 1700000000000,
        previous_hash: [0u8; 32],
    };

    let sources = vec![rfc::jitter_binding::SourceDescriptor {
        source_type: authorproof_protocol::rfc::SourceType::Other("keyboard".to_string()),
        weight: 1000,
        device_fingerprint: None,
        transport_calibration: None,
    }];

    let summary = rfc::jitter_binding::JitterSummary {
        sample_count: 100,
        mean_interval_us: 150000.0,
        std_dev: 50000.0,
        coefficient_of_variation: 0.33,
        percentiles: [50000.0, 80000.0, 140000.0, 200000.0, 300000.0],
        entropy_bits: 8.5,
        hurst_exponent: Some(0.72),
    };

    let binding_mac = rfc::jitter_binding::BindingMac {
        mac: [0xCDu8; 32],
        document_hash: [0u8; 32],
        keystroke_count: 100,
        timestamp_ms: 1700000000000,
    };

    let rfc_jitter = rfc::JitterBinding::new(entropy_commitment, sources, summary, binding_mac);

    let calibration = rfc::CalibrationAttestation::new(
        1_000_000,
        "test-hardware".to_string(),
        vec![0u8; 64],
        1700000000,
    );

    chain
        .commit_rfc(
            None,
            Duration::from_millis(10),
            None,
            None,
            calibration.clone(),
            None,
        )
        .expect("commit 0");

    fs::write(&path, b"updated content").expect("update");

    let checkpoint = chain
        .commit_rfc(
            Some("With jitter".to_string()),
            Duration::from_millis(10),
            Some(rfc_jitter),
            None,
            calibration,
            None,
        )
        .expect("commit 1");

    assert_eq!(checkpoint.ordinal, 1);
    assert!(checkpoint.vdf.is_some());
    assert!(checkpoint.rfc_vdf.is_some());
    assert!(checkpoint.rfc_jitter.is_some());
    assert!(checkpoint.jitter_binding.is_some());

    let rfc_vdf = checkpoint.rfc_vdf.as_ref().expect("rfc vdf proof");
    assert!(rfc_vdf.iterations > 0);
    assert_eq!(rfc_vdf.calibration.hardware_class, "test-hardware");

    let jitter = checkpoint.rfc_jitter.as_ref().expect("rfc jitter binding");
    assert_eq!(jitter.entropy_commitment.hash, [0xABu8; 32]);
    assert_eq!(jitter.summary.hurst_exponent, Some(0.72));

    chain.verify().expect("verify chain");
    drop(dir);
}

#[test]
fn test_commit_rfc_v3_domain_separator() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    let calibration =
        rfc::CalibrationAttestation::new(1_000_000, "test".to_string(), vec![], 1700000000);

    let cp0 = chain
        .commit_rfc(
            None,
            Duration::from_millis(10),
            None,
            None,
            calibration.clone(),
            None,
        )
        .expect("commit 0");

    let expected_hash = cp0.compute_hash();
    assert_eq!(cp0.hash, expected_hash);

    fs::write(&path, b"updated").expect("update");

    let entropy_commitment = rfc::jitter_binding::EntropyCommitment {
        hash: [1u8; 32],
        timestamp_ms: 1700000000000,
        previous_hash: [0u8; 32],
    };
    let summary = rfc::jitter_binding::JitterSummary {
        sample_count: 10,
        mean_interval_us: 100000.0,
        std_dev: 10000.0,
        coefficient_of_variation: 0.1,
        percentiles: [0.0; 5],
        entropy_bits: 5.0,
        hurst_exponent: None,
    };
    let binding_mac = rfc::jitter_binding::BindingMac {
        mac: [0u8; 32],
        document_hash: [0u8; 32],
        keystroke_count: 10,
        timestamp_ms: 1700000000000,
    };
    let rfc_jitter = rfc::JitterBinding::new(entropy_commitment, vec![], summary, binding_mac);

    let cp1 = chain
        .commit_rfc(
            None,
            Duration::from_millis(10),
            Some(rfc_jitter),
            None,
            calibration,
            None,
        )
        .expect("commit 1");

    assert!(cp1.rfc_jitter.is_some());
    let computed = cp1.compute_hash();
    assert_eq!(cp1.hash, computed);

    chain.verify().expect("verify chain");
    drop(dir);
}

#[test]
fn test_checkpoint_to_rfc_vdf_conversion() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(50))
        .expect("commit 1");

    let checkpoint = &chain.checkpoints[1];
    assert!(checkpoint.vdf.is_some());

    let calibration = rfc::CalibrationAttestation::new(
        test_vdf_params().iterations_per_second as u64,
        "test".to_string(),
        vec![],
        1700000000,
    );
    let rfc_vdf = checkpoint.to_rfc_vdf(calibration).expect("to_rfc_vdf");
    let internal_vdf = checkpoint.vdf.as_ref().expect("internal vdf proof");
    assert_eq!(rfc_vdf.challenge, internal_vdf.input);
    assert_eq!(&rfc_vdf.output[..32], &internal_vdf.output[..]);
    assert_eq!(rfc_vdf.iterations, internal_vdf.iterations);
    assert_eq!(
        rfc_vdf.duration_ms,
        crate::utils::duration_to_ms(internal_vdf.duration)
    );

    drop(dir);
}

#[test]
fn test_ordinal_gap_detected() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    chain.checkpoints[1].ordinal = 5;
    chain.checkpoints[1].hash = chain.checkpoints[1].compute_hash();

    let report = chain.verify_detailed();
    assert!(!report.valid);
    assert!(!report.ordinal_gaps.is_empty());
    assert_eq!(report.ordinal_gaps[0], (1, 5));
    assert!(report.errors.iter().any(|e| e.contains("ordinal gap")));
    drop(dir);
}

#[test]
fn test_unsigned_checkpoint_rejected_required_policy() {
    let (_dir, path) = temp_document();
    let mut chain = Chain::new(&path, test_vdf_params()).expect("create chain");
    assert_eq!(chain.metadata.signature_policy, SignaturePolicy::Required);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    let err = chain.verify().unwrap_err();
    assert!(err.to_string().contains("unsigned"));
}

#[test]
fn test_unsigned_checkpoint_accepted_optional_policy() {
    let (_dir, path) = temp_document();
    let mut chain = test_chain(&path); // Optional policy

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    let report = chain.verify_detailed();
    assert!(report.valid);
    assert!(!report.unsigned_checkpoints.is_empty());
    assert_eq!(report.unsigned_checkpoints[0], 0);
    assert!(!report.warnings.is_empty());
}

#[test]
fn test_signature_policy_serialization() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain.metadata.signature_policy = SignaturePolicy::Required;

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    let chain_path = dir.path().join("policy_chain.json");
    chain.save(&chain_path).expect("save");

    let loaded = Chain::load(&chain_path).expect("load");
    assert_eq!(loaded.metadata.signature_policy, SignaturePolicy::Required);
    drop(dir);
}

#[test]
fn test_legacy_chain_deserializes_optional_policy() {
    // Legacy chains without signature_policy field should deserialize as Optional
    let json = r#"{
        "metadata": {
            "document_id": "test",
            "document_path": "/tmp/test.txt",
            "created_at": "2024-01-01T00:00:00Z",
            "vdf_params": {"iterations_per_second": 1000, "min_iterations": 10, "max_iterations": 100000},
            "entanglement_mode": "Legacy"
        },
        "checkpoints": []
    }"#;

    let chain: Chain = serde_json::from_str(json).expect("deserialize");
    assert_eq!(chain.metadata.signature_policy, SignaturePolicy::Optional);
}

#[test]
fn test_verify_detailed_report() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    let report = chain.verify_detailed();
    assert!(report.valid);
    assert_eq!(report.unsigned_checkpoints.len(), 2);
    assert!(report.signature_failures.is_empty());
    assert!(report.ordinal_gaps.is_empty());
    assert!(report.metadata_valid);
    drop(dir);
}

// Integrity metadata (checkpoint_count, mmr_root) verification is now handled
// externally by CheckpointMmr, not by Chain::verify_detailed().

#[test]
fn test_entangled_commit_with_physics_context() {
    let (dir, path) = temp_document();
    let mut chain = Chain::new_with_mode(&path, test_vdf_params(), EntanglementMode::Entangled)
        .expect("create chain")
        .with_signature_policy(SignaturePolicy::Optional);

    let physics = crate::PhysicalContext {
        clock_skew: 42,
        thermal_proxy: 1000,
        silicon_puf: [0xBBu8; 32],
        io_latency_ns: 500,
        ambient_hash: [0u8; 32],
        is_virtualized: false,
        combined_hash: [0xCCu8; 32],
    };

    let cp0 = chain
        .commit_entangled(
            Some("physics-bound commit".to_string()),
            [1u8; 32],
            "session-phys".to_string(),
            10,
            Duration::from_millis(10),
            Some(&physics),
        )
        .expect("commit 0");

    assert!(cp0.vdf.is_some());
    let binding = cp0.jitter_binding.as_ref().expect("jitter binding");
    assert!(binding.physics_seed.is_some());

    let expected_seed =
        crate::physics::entanglement::Entanglement::create_seed(cp0.content_hash, &physics);
    assert_eq!(binding.physics_seed.expect("physics seed"), expected_seed);

    let plain_input = vdf::chain_input_entangled([0u8; 32], [1u8; 32], cp0.content_hash, 0);
    let vdf_proof = cp0.vdf.as_ref().expect("vdf proof");
    assert_ne!(
        vdf_proof.input, plain_input,
        "VDF input should differ from non-physics input"
    );

    chain.verify().expect("verify physics-bound chain");

    fs::write(&path, b"updated content").expect("update");
    let cp1 = chain
        .commit_entangled(
            None,
            [2u8; 32],
            "session-phys".to_string(),
            20,
            Duration::from_millis(10),
            Some(&physics),
        )
        .expect("commit 1");

    assert!(cp1
        .jitter_binding
        .as_ref()
        .expect("jitter binding cp1")
        .physics_seed
        .is_some());
    chain
        .verify()
        .expect("verify multi-checkpoint physics chain");

    drop(dir);
}

#[test]
fn test_entangled_commit_mixed_physics_and_none() {
    let (dir, path) = temp_document();
    let mut chain = Chain::new_with_mode(&path, test_vdf_params(), EntanglementMode::Entangled)
        .expect("create chain")
        .with_signature_policy(SignaturePolicy::Optional);

    let physics = crate::PhysicalContext {
        clock_skew: 100,
        thermal_proxy: 2000,
        silicon_puf: [0xAAu8; 32],
        io_latency_ns: 300,
        ambient_hash: [0u8; 32],
        is_virtualized: false,
        combined_hash: [0xDDu8; 32],
    };

    chain
        .commit_entangled(
            None,
            [1u8; 32],
            "session-mix".to_string(),
            10,
            Duration::from_millis(10),
            Some(&physics),
        )
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_entangled(
            None,
            [2u8; 32],
            "session-mix".to_string(),
            20,
            Duration::from_millis(10),
            None,
        )
        .expect("commit 1");

    fs::write(&path, b"final").expect("final update");
    chain
        .commit_entangled(
            None,
            [3u8; 32],
            "session-mix".to_string(),
            30,
            Duration::from_millis(10),
            Some(&physics),
        )
        .expect("commit 2");

    assert!(chain.checkpoints[0]
        .jitter_binding
        .as_ref()
        .expect("jitter binding 0")
        .physics_seed
        .is_some());
    assert!(chain.checkpoints[1]
        .jitter_binding
        .as_ref()
        .expect("jitter binding 1")
        .physics_seed
        .is_none());
    assert!(chain.checkpoints[2]
        .jitter_binding
        .as_ref()
        .expect("jitter binding 2")
        .physics_seed
        .is_some());

    chain.verify().expect("verify mixed physics chain");
    drop(dir);
}

#[test]
fn test_commit_entangled_with_lock() {
    let (dir, path) = temp_document();
    let mut chain = test_chain_entangled(&path);

    // The entangled commit acquires an advisory file lock internally.
    // Verify it succeeds (lock acquired and released) for a normal commit.
    let cp = chain
        .commit_entangled(
            Some("locked commit".to_string()),
            [0x11u8; 32],
            "session-lock".to_string(),
            20,
            Duration::from_millis(10),
            None,
        )
        .expect("entangled commit should acquire lock");

    assert_eq!(cp.ordinal, 0);
    assert!(cp.vdf.is_some());
    assert!(cp.jitter_binding.is_some());
    chain.verify().expect("verify after locked commit");
    drop(dir);
}

#[test]
fn test_commit_rfc_with_argon2() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    let calibration = rfc::CalibrationAttestation::new(
        1_000_000,
        "test-hardware".to_string(),
        vec![0u8; 64],
        1700000000,
    );

    // First commit (ordinal 0): should produce argon2_swf
    let cp0 = chain
        .commit_rfc(
            Some("RFC commit with Argon2".to_string()),
            Duration::from_millis(10),
            None,
            None,
            calibration.clone(),
            None,
        )
        .expect("commit_rfc 0");

    assert!(
        cp0.argon2_swf.is_some(),
        "genesis RFC commit should have Argon2id SWF proof"
    );
    let swf = cp0.argon2_swf.as_ref().expect("argon2 swf proof");
    assert_ne!(swf.merkle_root, [0u8; 32], "Merkle root should be non-zero");
    assert_ne!(swf.input, [0u8; 32], "SWF input should be non-zero");

    // Second commit with VDF
    fs::write(&path, b"updated for argon2 test").expect("update");
    let cp1 = chain
        .commit_rfc(
            None,
            Duration::from_millis(10),
            None,
            None,
            calibration,
            None,
        )
        .expect("commit_rfc 1");

    assert!(
        cp1.argon2_swf.is_some(),
        "second RFC commit should also have Argon2id SWF"
    );
    chain
        .verify()
        .expect("verify chain with Argon2id SWF proofs");
    drop(dir);
}

#[test]
fn test_verify_detailed_catches_tampered_hash() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    fs::write(&path, b"updated").expect("update");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    // Tamper with content_hash but do NOT recompute the checkpoint hash
    chain.checkpoints[1].content_hash = [0xDE; 32];

    let report = chain.verify_detailed();
    assert!(
        !report.valid,
        "tampered content_hash should fail verification"
    );
    assert!(
        report.errors.iter().any(|e| e.contains("hash mismatch")),
        "should report hash mismatch, got: {:?}",
        report.errors
    );
    drop(dir);
}

#[test]
fn test_verify_detailed_catches_bad_signature() {
    let (dir, path) = temp_document();
    let mut chain = Chain::new(&path, test_vdf_params())
        .expect("create chain")
        .with_signature_policy(SignaturePolicy::Required);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    // Attach a truncated signature (wrong length)
    chain.checkpoints[0].signature = Some(vec![0xAA; 32]);
    chain.checkpoints[0].hash = chain.checkpoints[0].compute_hash();

    let report = chain.verify_detailed();
    assert!(!report.valid);
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("invalid Ed25519 signature length")),
        "should reject wrong-length signature, got: {:?}",
        report.errors
    );
    drop(dir);
}

#[test]
fn test_save_load_roundtrip() {
    let dir = TempDir::new().expect("create temp dir");
    let canonical_dir = dir.path().canonicalize().expect("canonicalize");
    let path = canonical_dir.join("roundtrip_doc.txt");
    fs::write(&path, b"roundtrip content").expect("write");

    let mut chain = test_chain(&path);
    chain
        .commit_with_vdf_duration(Some("first".to_string()), Duration::from_millis(10))
        .expect("commit 0");

    fs::write(&path, b"updated roundtrip content").expect("update");
    chain
        .commit_with_vdf_duration(Some("second".to_string()), Duration::from_millis(10))
        .expect("commit 1");

    let chain_path = canonical_dir.join("roundtrip_chain.json");
    chain.save(&chain_path).expect("save");

    let loaded = Chain::load(&chain_path).expect("load");
    assert_eq!(loaded.metadata.document_id, chain.metadata.document_id);
    assert_eq!(loaded.metadata.document_path, chain.metadata.document_path);
    assert_eq!(loaded.checkpoints.len(), 2);
    assert_eq!(
        loaded.metadata.entanglement_mode,
        chain.metadata.entanglement_mode
    );
    assert_eq!(
        loaded.metadata.signature_policy,
        chain.metadata.signature_policy
    );

    for i in 0..2 {
        assert_eq!(loaded.checkpoints[i].ordinal, chain.checkpoints[i].ordinal);
        assert_eq!(loaded.checkpoints[i].hash, chain.checkpoints[i].hash);
        assert_eq!(
            loaded.checkpoints[i].content_hash,
            chain.checkpoints[i].content_hash
        );
        assert_eq!(
            loaded.checkpoints[i].previous_hash,
            chain.checkpoints[i].previous_hash
        );
        assert_eq!(loaded.checkpoints[i].message, chain.checkpoints[i].message);
    }

    loaded.verify().expect("loaded chain should verify");
    drop(dir);
}

#[test]
fn test_genesis_prev_hash_deterministic() {
    let (dir, path) = temp_document();
    let mut chain1 = test_chain(&path);
    let mut chain2 = test_chain(&path);

    let cp1 = chain1
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit chain1");
    let cp2 = chain2
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit chain2");

    // Same file content and path should produce the same genesis prev-hash
    assert_eq!(
        cp1.previous_hash, cp2.previous_hash,
        "genesis prev-hash should be deterministic for the same document"
    );
    assert_ne!(
        cp1.previous_hash, [0u8; 32],
        "genesis prev-hash should not be zeros"
    );
    drop(dir);
}

#[test]
fn test_chain_handles_empty_file() {
    let dir = TempDir::new().expect("create temp dir");
    let canonical_dir = dir.path().canonicalize().expect("canonicalize");
    let path = canonical_dir.join("empty.txt");
    fs::write(&path, b"").expect("write empty file");

    let mut chain = test_chain(&path);
    let cp = chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit on empty file");

    assert_eq!(cp.ordinal, 0);
    assert_eq!(cp.content_size, 0);
    assert_ne!(
        cp.content_hash, [0u8; 32],
        "hash of empty file should not be all-zeros"
    );
    assert_ne!(
        cp.previous_hash, [0u8; 32],
        "genesis prev-hash should not be zeros"
    );
    chain.verify().expect("verify chain with empty file");
    drop(dir);
}

#[test]
fn test_mmr_anchored_chain_verifies() {
    let (dir, path) = temp_document();
    let mmr = crate::checkpoint_mmr::CheckpointMmr::in_memory().expect("in-memory mmr");
    let mut chain = test_chain(&path).with_mmr(mmr);

    let cp0 = chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");
    assert!(
        cp0.mmr_root.is_some(),
        "genesis checkpoint should have mmr_root"
    );
    assert!(
        cp0.mmr_inclusion_proof.is_some(),
        "genesis checkpoint should have mmr_inclusion_proof"
    );

    fs::write(&path, b"second version").expect("update file");
    let cp1 = chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");
    assert!(cp1.mmr_root.is_some(), "checkpoint 1 should have mmr_root");
    assert!(
        cp1.mmr_inclusion_proof.is_some(),
        "checkpoint 1 should have mmr_inclusion_proof"
    );

    chain.verify().expect("MMR-anchored chain should verify");
    drop(dir);
}

#[test]
fn test_mmr_proof_cross_checkpoint_anchor() {
    use crate::mmr::InclusionProof;

    let (dir, path) = temp_document();
    let mmr = crate::checkpoint_mmr::CheckpointMmr::in_memory().expect("in-memory mmr");
    let mut chain = test_chain(&path).with_mmr(mmr);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    fs::write(&path, b"second version").expect("update file");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    let proof_bytes = chain.checkpoints[0]
        .mmr_inclusion_proof
        .as_ref()
        .expect("checkpoint 0 proof");
    let proof = InclusionProof::deserialize(proof_bytes).expect("deserialize proof");

    let next_mmr_root = chain.checkpoints[1]
        .mmr_root
        .expect("checkpoint 1 mmr_root");

    assert_eq!(
        proof.root, next_mmr_root,
        "proof[0].root must equal checkpoint[1].mmr_root (cross-checkpoint anchor)"
    );
    drop(dir);
}

#[test]
fn test_mmr_tampered_root_rejected() {
    let (dir, path) = temp_document();
    let mmr = crate::checkpoint_mmr::CheckpointMmr::in_memory().expect("in-memory mmr");
    let mut chain = test_chain(&path).with_mmr(mmr);

    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    fs::write(&path, b"second version").expect("update file");
    chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 1");

    // Tamper the mmr_root in checkpoint 1 so the cross-checkpoint anchor fails.
    chain.checkpoints[1].mmr_root = Some([0xABu8; 32]);

    let report = chain.verify_detailed();
    assert!(!report.valid, "tampered mmr_root should fail verification");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("rollback detected")),
        "expected rollback error, got: {:?}",
        report.errors
    );
    drop(dir);
}

#[test]
fn test_min_iterations_zero_rejected() {
    let (_dir, path) = temp_document();
    let mut chain = Chain::new(
        &path,
        Parameters {
            iterations_per_second: 1000,
            min_iterations: 0,
            max_iterations: 100_000,
        },
    )
    .expect("create chain")
    .with_signature_policy(SignaturePolicy::Optional);

    let err = chain
        .commit(None)
        .expect_err("should reject zero min_iterations");
    assert!(
        err.to_string().contains("min_iterations=0"),
        "expected min_iterations=0 error, got: {err}"
    );
}

#[test]
fn test_clock_tolerance_tracked_in_report() {
    let (_dir, path) = temp_document();
    let mut chain = test_chain(&path);

    let cp0 = chain
        .commit_with_vdf_duration(None, Duration::from_millis(10))
        .expect("commit 0");

    let mut cp1 = Checkpoint::new_base(1, cp0.hash, cp0.content_hash, 100, None);
    cp1.timestamp = cp0.timestamp - chrono::Duration::milliseconds(500);
    let vdf_input = vdf::chain_input(cp1.content_hash, cp1.previous_hash, cp1.ordinal);
    cp1.vdf = Some(vdf::compute_iterations(vdf_input, 10));
    cp1.hash = cp1.compute_hash();

    chain.checkpoints.push(cp1);

    let report = chain.verify_detailed();
    assert!(report.valid, "clock drift within 1s tolerance should pass");
    assert!(
        report.clock_tolerance_violations.len() > 0,
        "should track tolerance violations"
    );
}

#[test]
fn test_mac_sidecar_legacy_fallback() {
    let (dir, path) = temp_document();
    let mut chain = test_chain(&path);
    chain.commit(None).expect("commit");

    let tmp_path = dir.path().join("test_chain.json");
    chain.save(&tmp_path).expect("save without MAC");

    let mac_key = b"test_key_32_bytes_padding_heree";
    let loaded = Chain::load_with_mac(&tmp_path, mac_key).expect("fallback to unverified load");
    assert_eq!(
        loaded.checkpoints.len(),
        1,
        "should load legacy chain without MAC"
    );
}

#[test]
fn test_batch_verifier_no_silent_panics() {
    use crate::vdf::Parameters;

    let _params = Parameters {
        iterations_per_second: 1000,
        min_iterations: 10,
        max_iterations: 100_000,
    };

    let vdf1 = crate::vdf::compute_iterations([1u8; 32], 100);
    let vdf2 = crate::vdf::compute_iterations([2u8; 32], 100);

    let verifier = crate::vdf::params::BatchVerifier::new(2);
    let results = verifier.verify_all(&[Some(vdf1), Some(vdf2), None]);

    assert_eq!(results.len(), 3);
    assert!(results[0].valid);
    assert!(results[1].valid);
    assert!(!results[2].valid);
    assert!(
        results[2].error.is_some(),
        "nil proof should be marked with error"
    );
}
