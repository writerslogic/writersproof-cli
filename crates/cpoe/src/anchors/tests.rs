// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use chrono::Utc;
use std::collections::HashMap;

fn test_hash() -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = 0xAB;
    h[31] = 0xCD;
    h
}

fn zero_hash() -> [u8; 32] {
    [0u8; 32]
}

fn make_proof(provider: ProviderType, status: ProofStatus) -> Proof {
    Proof {
        id: format!("{provider:?}-proof-1"),
        provider,
        status,
        anchored_hash: test_hash(),
        submitted_at: Utc::now(),
        confirmed_at: if status == ProofStatus::Confirmed {
            Some(Utc::now())
        } else {
            None
        },
        proof_data: vec![0xDE, 0xAD],
        location: None,
        attestation_path: None,
        extra: HashMap::new(),
    }
}

// --- Anchor::new ---

#[test]
fn anchor_new_sets_pending_status() {
    let anchor = Anchor::new(test_hash());
    assert_eq!(anchor.status, ProofStatus::Pending);
    assert_eq!(anchor.version, 1);
    assert!(anchor.proofs.is_empty());
    assert!(anchor.document_id.is_none());
    assert_eq!(anchor.hash, test_hash());
}

#[test]
fn anchor_new_with_zero_hash() {
    let anchor = Anchor::new(zero_hash());
    assert_eq!(anchor.hash, zero_hash());
    assert_eq!(anchor.status, ProofStatus::Pending);
}

// --- Anchor::add_proof ---

#[test]
fn add_pending_proof_keeps_anchor_pending() {
    let mut anchor = Anchor::new(test_hash());
    anchor.add_proof(make_proof(
        ProviderType::OpenTimestamps,
        ProofStatus::Pending,
    ));
    assert_eq!(anchor.status, ProofStatus::Pending);
    assert_eq!(anchor.proofs.len(), 1);
}

#[test]
fn add_confirmed_proof_promotes_anchor_status() {
    let mut anchor = Anchor::new(test_hash());
    anchor.add_proof(make_proof(ProviderType::Rfc3161, ProofStatus::Confirmed));
    assert_eq!(anchor.status, ProofStatus::Confirmed);
    assert_eq!(anchor.proofs.len(), 1);
}

#[test]
fn add_failed_proof_demotes_to_failed() {
    let mut anchor = Anchor::new(test_hash());
    anchor.add_proof(make_proof(ProviderType::Notary, ProofStatus::Failed));
    assert_eq!(anchor.status, ProofStatus::Failed);
}

#[test]
fn add_multiple_proofs_accumulates() {
    let mut anchor = Anchor::new(test_hash());
    anchor.add_proof(make_proof(
        ProviderType::OpenTimestamps,
        ProofStatus::Pending,
    ));
    anchor.add_proof(make_proof(ProviderType::Rfc3161, ProofStatus::Confirmed));
    assert_eq!(anchor.proofs.len(), 2);
    assert_eq!(anchor.status, ProofStatus::Confirmed);
}

// --- Anchor::is_confirmed ---

#[test]
fn is_confirmed_false_when_no_proofs() {
    let anchor = Anchor::new(test_hash());
    assert!(!anchor.is_confirmed());
}

#[test]
fn is_confirmed_false_when_all_pending() {
    let mut anchor = Anchor::new(test_hash());
    anchor.add_proof(make_proof(
        ProviderType::OpenTimestamps,
        ProofStatus::Pending,
    ));
    anchor.add_proof(make_proof(ProviderType::Rfc3161, ProofStatus::Pending));
    assert!(!anchor.is_confirmed());
}

#[test]
fn is_confirmed_true_when_one_confirmed() {
    let mut anchor = Anchor::new(test_hash());
    anchor.add_proof(make_proof(
        ProviderType::OpenTimestamps,
        ProofStatus::Pending,
    ));
    anchor.add_proof(make_proof(ProviderType::Rfc3161, ProofStatus::Confirmed));
    assert!(anchor.is_confirmed());
}

// --- Anchor::best_proof ---

#[test]
fn best_proof_none_when_empty() {
    let anchor = Anchor::new(test_hash());
    // Falls back to first(), which is None
    assert!(anchor.best_proof().is_none());
}

#[test]
fn best_proof_prefers_rfc3161_over_others() {
    let mut anchor = Anchor::new(test_hash());
    anchor.add_proof(make_proof(ProviderType::Notary, ProofStatus::Confirmed));
    anchor.add_proof(make_proof(ProviderType::Rfc3161, ProofStatus::Confirmed));
    anchor.add_proof(make_proof(
        ProviderType::OpenTimestamps,
        ProofStatus::Confirmed,
    ));
    let best = anchor.best_proof().expect("should have best proof");
    assert_eq!(best.provider, ProviderType::Rfc3161);
}

#[test]
fn best_proof_prefers_ots_when_no_rfc3161() {
    let mut anchor = Anchor::new(test_hash());
    anchor.add_proof(make_proof(ProviderType::Notary, ProofStatus::Confirmed));
    anchor.add_proof(make_proof(
        ProviderType::OpenTimestamps,
        ProofStatus::Confirmed,
    ));
    let best = anchor.best_proof().expect("should have best proof");
    assert_eq!(best.provider, ProviderType::OpenTimestamps);
}

#[test]
fn best_proof_returns_none_when_none_confirmed() {
    let mut anchor = Anchor::new(test_hash());
    anchor.add_proof(make_proof(ProviderType::Notary, ProofStatus::Pending));
    anchor.add_proof(make_proof(ProviderType::Rfc3161, ProofStatus::Failed));
    assert!(anchor.best_proof().is_none());
}

// --- verify_proof_format ---

#[test]
fn verify_proof_format_rejects_empty_data() {
    let mut proof = make_proof(ProviderType::Rfc3161, ProofStatus::Confirmed);
    proof.proof_data = vec![];
    let err = verify_proof_format(&proof).unwrap_err();
    assert!(matches!(err, AnchorError::InvalidFormat(_)));
}

#[test]
fn verify_proof_format_rejects_zero_hash() {
    let mut proof = make_proof(ProviderType::Rfc3161, ProofStatus::Confirmed);
    proof.anchored_hash = zero_hash();
    let err = verify_proof_format(&proof).unwrap_err();
    assert!(matches!(err, AnchorError::HashMismatch));
}

#[test]
fn verify_proof_format_accepts_valid_proof() {
    let proof = make_proof(ProviderType::OpenTimestamps, ProofStatus::Confirmed);
    assert!(verify_proof_format(&proof).unwrap());
}

// --- AnchorError display ---

#[test]
fn anchor_error_display_messages() {
    assert_eq!(
        AnchorError::Unavailable("down".into()).to_string(),
        "provider unavailable: down"
    );
    assert_eq!(AnchorError::NotReady.to_string(), "proof not ready");
    assert_eq!(AnchorError::Expired.to_string(), "proof expired");
    assert_eq!(AnchorError::HashMismatch.to_string(), "hash mismatch");
}

// --- AnchorManagerConfig ---

#[test]
fn anchor_manager_config_defaults() {
    let cfg = AnchorManagerConfig::default();
    assert!(cfg.multi_anchor);
    assert_eq!(cfg.timeout, std::time::Duration::from_secs(30));
    assert_eq!(cfg.retry_count, 3);
}

#[test]
fn anchor_manager_new_has_no_providers() {
    let mgr = AnchorManager::new(AnchorManagerConfig::default());
    assert!(mgr.providers.is_empty());
}

// --- ProviderType serde ---

#[test]
fn provider_type_serde_roundtrip() {
    let types = [
        (ProviderType::OpenTimestamps, r#""ots""#),
        (ProviderType::Rfc3161, r#""rfc3161""#),
        (ProviderType::Notary, r#""notary""#),
    ];
    for (variant, expected_json) in &types {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(&json, expected_json, "serialize {variant:?}");
        let back: ProviderType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&back, variant, "roundtrip {variant:?}");
    }
}

// --- ProofStatus serde ---

#[test]
fn proof_status_serde_roundtrip() {
    let statuses = [
        (ProofStatus::Pending, r#""pending""#),
        (ProofStatus::Confirmed, r#""confirmed""#),
        (ProofStatus::Failed, r#""failed""#),
        (ProofStatus::Expired, r#""expired""#),
    ];
    for (variant, expected_json) in &statuses {
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(&json, expected_json, "serialize {variant:?}");
        let back: ProofStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&back, variant, "roundtrip {variant:?}");
    }
}

// --- Proof serde roundtrip ---

#[test]
fn proof_serde_roundtrip() {
    let proof = make_proof(ProviderType::Rfc3161, ProofStatus::Confirmed);
    let json = serde_json::to_string(&proof).expect("serialize proof");
    let back: Proof = serde_json::from_str(&json).expect("deserialize proof");
    assert_eq!(back.id, proof.id);
    assert_eq!(back.provider, proof.provider);
    assert_eq!(back.status, proof.status);
    assert_eq!(back.anchored_hash, proof.anchored_hash);
    assert_eq!(back.proof_data, proof.proof_data);
}

// --- Anchor serde roundtrip ---

#[test]
fn anchor_serde_roundtrip() {
    let mut anchor = Anchor::new(test_hash());
    anchor.document_id = Some("doc-123".to_string());
    anchor.add_proof(make_proof(ProviderType::Rfc3161, ProofStatus::Confirmed));
    let json = serde_json::to_string(&anchor).expect("serialize anchor");
    let back: Anchor = serde_json::from_str(&json).expect("deserialize anchor");
    assert_eq!(back.hash, anchor.hash);
    assert_eq!(back.version, 1);
    assert_eq!(back.status, ProofStatus::Confirmed);
    assert_eq!(back.proofs.len(), 1);
    assert_eq!(back.document_id, Some("doc-123".to_string()));
}

// --- AttestationOp serde ---

#[test]
fn attestation_op_serde_roundtrip() {
    let ops = [
        AttestationOp::Sha256,
        AttestationOp::Ripemd160,
        AttestationOp::Append,
        AttestationOp::Prepend,
        AttestationOp::Verify,
    ];
    for op in &ops {
        let json = serde_json::to_string(op).expect("serialize");
        let back: AttestationOp = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&back, op);
    }
}

// --- ProviderConfig ---

#[test]
fn provider_config_serde_with_options() {
    let config = ProviderConfig {
        provider_type: ProviderType::Rfc3161,
        enabled: true,
        endpoint: Some("https://tsa.example.com".to_string()),
        api_key: None,
        timeout_seconds: 60,
        options: {
            let mut m = HashMap::new();
            m.insert("cert_path".to_string(), "/etc/tsa.pem".to_string());
            m
        },
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let back: ProviderConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.provider_type, ProviderType::Rfc3161);
    assert!(back.enabled);
    assert_eq!(back.timeout_seconds, 60);
    assert_eq!(back.options.get("cert_path").unwrap(), "/etc/tsa.pem");
}


// --- verify_dual_anchor ---

#[test]
fn dual_anchor_within_tolerance_passes() {
    assert!(verify_dual_anchor(1_700_000_000, 1_700_000_010, 30).is_ok());
}

#[test]
fn dual_anchor_exceeds_tolerance_fails() {
    let err = verify_dual_anchor(1_700_000_000, 1_700_000_100, 30).unwrap_err();
    assert!(err.to_string().contains("disagree"));
}

#[test]
fn dual_anchor_zero_timestamp_fails() {
    assert!(verify_dual_anchor(0, 1_700_000_000, 30).is_err());
    assert!(verify_dual_anchor(1_700_000_000, 0, 30).is_err());
}

#[test]
fn dual_anchor_exact_tolerance_passes() {
    assert!(verify_dual_anchor(1_700_000_000, 1_700_000_030, 30).is_ok());
}
