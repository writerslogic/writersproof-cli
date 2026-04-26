// SPDX-License-Identifier: Apache-2.0

//! End-to-end and edge case tests for cpoe-jitter.

use cpoe_jitter::{
    derive_session_secret, Evidence, EvidenceChain, HumanModel, HybridEngine, Jitter, Session,
};

// ---------------------------------------------------------------------------
// 1. Full session lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_full_session_lifecycle() {
    // Test-only secret; not for production use.
    let secret = [42u8; 32];
    let mut session = Session::new(&secret);

    // Record 30 samples (above min_sequence_length of 20)
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    for i in 0..30 {
        let input = format!("keystroke event {}", i);
        inputs.push(input.as_bytes().to_vec());
        let jitter = session.sample(input.as_bytes()).unwrap();
        assert!(jitter >= 500, "jitter {} below minimum", jitter);
        assert!(jitter < 5000, "jitter {} above maximum", jitter);
    }

    // Evidence chain should have all records
    let chain = session.evidence();
    assert_eq!(chain.records().len(), 30);
    assert!(chain.validate_sequences());
    assert!(chain.validate_timestamps());

    // Verify chain integrity
    assert!(chain.verify_integrity(&secret));

    // Validate human model
    let validation = session.validate();
    assert!(validation.stats.count == 30);
    assert!(validation.stats.mean > 0.0);

    // Export and re-import JSON
    let json = session.export_json().unwrap();
    let reimported: EvidenceChain = serde_json::from_str(&json).unwrap();
    assert_eq!(reimported.records().len(), 30);
    assert!(reimported.verify_integrity(&secret));
}

// ---------------------------------------------------------------------------
// 2. Hybrid engine with hardware fallback
// ---------------------------------------------------------------------------

#[test]
fn test_session_with_hardware_fallback() {
    // Force fallback by requiring impossibly high entropy
    let engine = HybridEngine::default().with_min_entropy(255);
    let secret = [7u8; 32];
    let mut session = Session::with_engine(&secret, engine);

    for i in 0..25 {
        let input = format!("fallback keystroke {}", i);
        session.sample(input.as_bytes()).unwrap();
    }

    // All samples should be pure (fallback) since min_entropy=255 is impossible
    let chain = session.evidence();
    assert_eq!(chain.records().len(), 25);
    for record in chain.records().iter() {
        assert!(
            !record.is_phys(),
            "Record should be pure (fallback), not phys"
        );
    }
    assert_eq!(chain.phys_count(), 0);
    assert_eq!(chain.pure_count(), 25);
    assert_eq!(chain.phys_ratio(), 0.0);

    // Chain integrity still holds
    assert!(chain.verify_integrity(&secret));
}

// ---------------------------------------------------------------------------
// 3. Evidence chain tamper detection — moved to evidence.rs (inline #[cfg(test)])
//    so records_mut() can be gated to test-only builds.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 4. Human model: realistic typing classified as human
// ---------------------------------------------------------------------------

#[test]
fn test_human_model_realistic_typing() {
    let model = HumanModel::default();

    // Simulate realistic typing at ~60 WPM with natural variance
    // 60 WPM = 300 chars/min = 5 chars/sec = 200ms IKI
    // Jitter values should be varied, within 500-3000us range
    let human_jitters: Vec<Jitter> = (0..50)
        .map(|i| {
            let base = 1200u32;
            let variance = ((i * 37 + 13) % 1800) as u32;
            (base + variance).clamp(500, 3000)
        })
        .collect();

    let result = model.validate(&human_jitters);
    assert!(
        result.is_human,
        "Realistic typing should be classified as human; anomalies: {:?}",
        result.anomalies
    );
    assert!(result.confidence > 0.5);
    assert_eq!(result.stats.count, 50);
}

// ---------------------------------------------------------------------------
// 5. Human model: bot detection
// ---------------------------------------------------------------------------

#[test]
fn test_human_model_bot_detection() {
    let model = HumanModel::default();

    // Constant interval: clear bot signature
    let bot_jitters: Vec<Jitter> = vec![1000; 50];
    let result = model.validate(&bot_jitters);
    assert!(
        !result.is_human,
        "Constant-interval data should be detected as non-human"
    );
    assert!(result
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, cpoe_jitter::AnomalyKind::LowVariance)));

    // Repeating pattern: another bot signature
    let pattern_jitters: Vec<Jitter> = (0..50).map(|i| [800, 1200][i % 2]).collect();
    let result2 = model.validate(&pattern_jitters);
    assert!(
        !result2.is_human,
        "Repeating pattern should be detected as non-human"
    );
    assert!(result2
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, cpoe_jitter::AnomalyKind::RepeatingPattern)));
}

// ---------------------------------------------------------------------------
// 6. Session key derivation: deterministic
// ---------------------------------------------------------------------------

#[test]
fn test_session_key_derivation_deterministic() {
    let master = [0xAA; 32];
    let context = b"session-2026-03-25-doc-abc";

    let key1 = derive_session_secret(&master, context, None).unwrap();
    let key2 = derive_session_secret(&master, context, None).unwrap();

    assert_eq!(*key1, *key2, "Same inputs must produce same session key");
    assert_ne!(*key1, [0u8; 32], "Derived key should not be all zeros");
}

// ---------------------------------------------------------------------------
// 7. Different context produces different key
// ---------------------------------------------------------------------------

#[test]
fn test_session_different_context_different_key() {
    let master = [0xBB; 32];

    let key_a = derive_session_secret(&master, b"context-alpha", None).unwrap();
    let key_b = derive_session_secret(&master, b"context-beta", None).unwrap();
    let key_c = derive_session_secret(&master, b"context-alpha-extended", None).unwrap();

    assert_ne!(
        *key_a, *key_b,
        "Different contexts must produce different keys"
    );
    assert_ne!(*key_a, *key_c);
    assert_ne!(*key_b, *key_c);

    // Different master keys with same context also differ
    let other_master = [0xCC; 32];
    let key_d = derive_session_secret(&other_master, b"context-alpha", None).unwrap();
    assert_ne!(
        *key_a, *key_d,
        "Different masters must produce different keys"
    );
}

// ---------------------------------------------------------------------------
// 8. Chain serialization across versions (forward compatibility)
// ---------------------------------------------------------------------------

#[test]
fn test_chain_serialization_across_versions() {
    let secret = [0xDD; 32];
    let mut chain = EvidenceChain::with_secret(&secret);

    // Mix of phys and pure evidence
    chain
        .append(Evidence::phys_with_timestamp(
            [1u8; 32].into(),
            1000,
            100000,
        ))
        .unwrap();
    chain
        .append(Evidence::pure_with_timestamp(1500, 200000))
        .unwrap();
    chain
        .append(Evidence::phys_with_timestamp(
            [2u8; 32].into(),
            2000,
            300000,
        ))
        .unwrap();

    // Serialize
    let json = serde_json::to_string(&chain).unwrap();

    // Verify version field present
    assert!(json.contains("\"version\""));
    assert!(json.contains("\"records\""));
    assert!(json.contains("\"chain_mac\""));

    // Deserialize and verify all fields preserved
    let restored: EvidenceChain = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.records().len(), 3);
    assert!(restored.records()[0].is_phys());
    assert!(!restored.records()[1].is_phys());
    assert!(restored.records()[2].is_phys());
    assert_eq!(restored.records()[0].jitter(), 1000);
    assert_eq!(restored.records()[1].jitter(), 1500);
    assert_eq!(restored.records()[2].jitter(), 2000);
    assert_eq!(restored.records()[0].timestamp_us(), 100000);
    assert_eq!(restored.records()[1].timestamp_us(), 200000);
    assert_eq!(restored.records()[2].timestamp_us(), 300000);
    assert_eq!(restored.records()[0].sequence(), 0);
    assert_eq!(restored.records()[1].sequence(), 1);
    assert_eq!(restored.records()[2].sequence(), 2);

    // Integrity still verifiable after deserialization
    assert!(restored.verify_integrity(&secret));
    assert!(restored.validate_sequences());
    assert!(restored.validate_timestamps());

    // Secret is not leaked in serialization
    assert!(!json.contains("secret"));
}
