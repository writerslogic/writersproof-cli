// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use ed25519_dalek::SigningKey;

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

#[test]
fn test_no_ai_declaration_creation_and_signing() {
    let doc_hash = [1u8; 32];
    let chain_hash = [2u8; 32];
    let signing_key = test_signing_key();

    let decl = no_ai_declaration(
        doc_hash,
        chain_hash,
        "Test Document",
        "I wrote this myself.",
    )
    .sign(&signing_key)
    .expect("sign declaration");

    assert_eq!(decl.title, "Test Document");
    assert_eq!(decl.statement, "I wrote this myself.");
    assert_eq!(decl.document_hash, doc_hash);
    assert_eq!(decl.chain_hash, chain_hash);
    assert!(!decl.has_ai_usage());
    assert_eq!(decl.max_ai_extent(), AiExtent::None);
}

#[test]
fn test_declaration_verification() {
    let signing_key = test_signing_key();
    let decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .sign(&signing_key)
        .expect("sign");

    assert!(decl.verify().is_ok());
}

#[test]
fn test_declaration_verification_fails_with_tampered_signature() {
    let signing_key = test_signing_key();
    let mut decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .sign(&signing_key)
        .expect("sign");

    decl.signature[0] ^= 0xFF;

    assert!(decl.verify().is_err());
}

#[test]
fn test_declaration_verification_fails_with_tampered_title() {
    let signing_key = test_signing_key();
    let mut decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .sign(&signing_key)
        .expect("sign");

    decl.title = "Tampered Title".to_string();

    assert!(decl.verify().is_err());
}

#[test]
fn test_declaration_verification_fails_with_tampered_statement() {
    let signing_key = test_signing_key();
    let mut decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .sign(&signing_key)
        .expect("sign");

    decl.statement = "Tampered Statement".to_string();

    assert!(decl.verify().is_err());
}

#[test]
fn test_ai_assisted_declaration_with_tool() {
    let signing_key = test_signing_key();
    let decl = ai_assisted_declaration([1u8; 32], [2u8; 32], "AI Assisted Doc")
        .add_modality(ModalityType::Keyboard, 80.0, None)
        .add_modality(ModalityType::Paste, 20.0, Some("code snippets".to_string()))
        .add_ai_tool(
            "ChatGPT",
            Some("4.0".to_string()),
            AiPurpose::Feedback,
            Some("Asked for suggestions".to_string()),
            AiExtent::Moderate,
        )
        .with_statement("I used AI for feedback but wrote the content myself.")
        .sign(&signing_key)
        .expect("sign");

    assert!(decl.has_ai_usage());
    assert_eq!(decl.max_ai_extent(), AiExtent::Moderate);
    assert_eq!(decl.ai_tools.len(), 1);
    assert_eq!(decl.ai_tools[0].tool, "ChatGPT");
}

#[test]
fn test_declaration_requires_document_hash() {
    let signing_key = test_signing_key();
    let err = Builder::new([0u8; 32], [2u8; 32], "Test")
        .add_modality(ModalityType::Keyboard, 100.0, None)
        .with_statement("Statement")
        .sign(&signing_key)
        .unwrap_err();

    assert!(err.to_string().contains("document hash is required"));
}

#[test]
fn test_declaration_requires_chain_hash() {
    let signing_key = test_signing_key();
    let err = Builder::new([1u8; 32], [0u8; 32], "Test")
        .add_modality(ModalityType::Keyboard, 100.0, None)
        .with_statement("Statement")
        .sign(&signing_key)
        .unwrap_err();

    assert!(err.to_string().contains("chain hash is required"));
}

#[test]
fn test_declaration_requires_title() {
    let signing_key = test_signing_key();
    let err = Builder::new([1u8; 32], [2u8; 32], "")
        .add_modality(ModalityType::Keyboard, 100.0, None)
        .with_statement("Statement")
        .sign(&signing_key)
        .unwrap_err();

    assert!(err.to_string().contains("title is required"));
}

#[test]
fn test_declaration_requires_modality() {
    let signing_key = test_signing_key();
    let err = Builder::new([1u8; 32], [2u8; 32], "Test")
        .with_statement("Statement")
        .sign(&signing_key)
        .unwrap_err();

    assert!(err
        .to_string()
        .contains("at least one input modality is required"));
}

#[test]
fn test_declaration_requires_statement() {
    let signing_key = test_signing_key();
    let err = Builder::new([1u8; 32], [2u8; 32], "Test")
        .add_modality(ModalityType::Keyboard, 100.0, None)
        .sign(&signing_key)
        .unwrap_err();

    assert!(err.to_string().contains("statement is required"));
}

#[test]
fn test_modality_percentages_must_sum_to_100() {
    let signing_key = test_signing_key();

    let err = Builder::new([1u8; 32], [2u8; 32], "Test")
        .add_modality(ModalityType::Keyboard, 50.0, None)
        .with_statement("Statement")
        .sign(&signing_key)
        .unwrap_err();
    assert!(err.to_string().contains("percentages sum to"));

    let err = Builder::new([1u8; 32], [2u8; 32], "Test")
        .add_modality(ModalityType::Keyboard, 150.0, None)
        .with_statement("Statement")
        .sign(&signing_key)
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("modality percentage must be 0-100"));
}

#[test]
fn test_modality_percentage_validation() {
    let signing_key = test_signing_key();

    let err = Builder::new([1u8; 32], [2u8; 32], "Test")
        .add_modality(ModalityType::Keyboard, -10.0, None)
        .with_statement("Statement")
        .sign(&signing_key)
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("modality percentage must be 0-100"));
}

#[test]
fn test_multiple_modalities() {
    let signing_key = test_signing_key();
    let decl = Builder::new([1u8; 32], [2u8; 32], "Mixed Input")
        .add_modality(ModalityType::Keyboard, 60.0, None)
        .add_modality(
            ModalityType::Dictation,
            30.0,
            Some("voice notes".to_string()),
        )
        .add_modality(ModalityType::Paste, 10.0, None)
        .with_statement("I used multiple input methods.")
        .sign(&signing_key)
        .expect("sign");

    assert_eq!(decl.input_modalities.len(), 3);
    assert!(decl.verify().is_ok());
}

#[test]
fn test_multiple_ai_tools() {
    let signing_key = test_signing_key();
    let decl = Builder::new([1u8; 32], [2u8; 32], "Multi AI")
        .add_modality(ModalityType::Keyboard, 100.0, None)
        .add_ai_tool(
            "ChatGPT",
            None,
            AiPurpose::Ideation,
            None,
            AiExtent::Minimal,
        )
        .add_ai_tool(
            "Grammarly",
            None,
            AiPurpose::Editing,
            None,
            AiExtent::Substantial,
        )
        .with_statement("I used multiple AI tools.")
        .sign(&signing_key)
        .expect("sign");

    assert_eq!(decl.ai_tools.len(), 2);
    assert_eq!(decl.max_ai_extent(), AiExtent::Substantial);
}

#[test]
fn test_collaborator_addition() {
    let signing_key = test_signing_key();
    let decl = Builder::new([1u8; 32], [2u8; 32], "Collaborative")
        .add_modality(ModalityType::Keyboard, 100.0, None)
        .add_collaborator(
            "Alice",
            CollaboratorRole::CoAuthor,
            vec!["Chapter 1".to_string()],
        )
        .add_collaborator("Bob", CollaboratorRole::Editor, vec![])
        .with_statement("We wrote this together.")
        .sign(&signing_key)
        .expect("sign");

    assert_eq!(decl.collaborators.len(), 2);
    assert_eq!(decl.collaborators[0].name, "Alice");
}

#[test]
fn test_declaration_encode_decode_roundtrip() {
    let signing_key = test_signing_key();
    let original = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .sign(&signing_key)
        .expect("sign");

    let encoded = original.encode().expect("encode");
    let decoded = Declaration::decode(&encoded).expect("decode");

    assert_eq!(decoded.title, original.title);
    assert_eq!(decoded.statement, original.statement);
    assert_eq!(decoded.document_hash, original.document_hash);
    assert_eq!(decoded.chain_hash, original.chain_hash);
    assert_eq!(decoded.signature, original.signature);
    assert!(decoded.verify().is_ok());
}

#[test]
fn test_declaration_summary() {
    let signing_key = test_signing_key();
    let decl = ai_assisted_declaration([1u8; 32], [2u8; 32], "Summary Test")
        .add_modality(ModalityType::Keyboard, 100.0, None)
        .add_ai_tool(
            "Claude",
            None,
            AiPurpose::Research,
            None,
            AiExtent::Moderate,
        )
        .add_collaborator("Alice", CollaboratorRole::Reviewer, vec![])
        .with_statement("Test")
        .sign(&signing_key)
        .expect("sign");

    let summary = decl.summary();
    assert_eq!(summary.title, "Summary Test");
    assert!(summary.ai_usage);
    assert_eq!(summary.ai_tools, vec!["Claude"]);
    assert_eq!(summary.max_ai_extent, "moderate");
    assert_eq!(summary.collaborators, 1);
    assert!(summary.signature_valid);
}

#[test]
fn test_invalid_public_key_length() {
    let signing_key = test_signing_key();
    let mut decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .sign(&signing_key)
        .expect("sign");

    decl.author_public_key = vec![0u8; 16];

    assert!(decl.verify().is_err());
}

#[test]
fn test_invalid_signature_length() {
    let signing_key = test_signing_key();
    let mut decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .sign(&signing_key)
        .expect("sign");

    decl.signature = vec![0u8; 32];

    assert!(decl.verify().is_err());
}

#[test]
fn test_all_modality_types() {
    let signing_key = test_signing_key();

    for (modality, name) in [
        (ModalityType::Keyboard, "keyboard"),
        (ModalityType::Dictation, "dictation"),
        (ModalityType::Handwriting, "handwriting"),
        (ModalityType::Paste, "paste"),
        (ModalityType::Import, "import"),
        (ModalityType::Mixed, "mixed"),
        (ModalityType::Other, "other"),
    ] {
        let decl = Builder::new([1u8; 32], [2u8; 32], format!("Test {name}"))
            .add_modality(modality, 100.0, None)
            .with_statement("Test")
            .sign(&signing_key)
            .expect("sign");
        assert!(decl.verify().is_ok());
    }
}

#[test]
fn test_all_ai_purposes() {
    let signing_key = test_signing_key();

    for purpose in [
        AiPurpose::Ideation,
        AiPurpose::Outline,
        AiPurpose::Drafting,
        AiPurpose::Feedback,
        AiPurpose::Editing,
        AiPurpose::Research,
        AiPurpose::Formatting,
        AiPurpose::Other,
    ] {
        let decl = ai_assisted_declaration([1u8; 32], [2u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .add_ai_tool("Tool", None, purpose, None, AiExtent::Minimal)
            .with_statement("Test")
            .sign(&signing_key)
            .expect("sign");
        assert!(decl.verify().is_ok());
    }
}

#[test]
fn test_all_ai_extents() {
    let signing_key = test_signing_key();

    for (extent, expected_rank) in [
        (AiExtent::None, 0),
        (AiExtent::Minimal, 1),
        (AiExtent::Moderate, 2),
        (AiExtent::Substantial, 3),
    ] {
        let decl = ai_assisted_declaration([1u8; 32], [2u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .add_ai_tool("Tool", None, AiPurpose::Other, None, extent)
            .with_statement("Test")
            .sign(&signing_key)
            .expect("sign");
        assert_eq!(helpers::extent_rank(&decl.max_ai_extent()), expected_rank);
    }
}

#[test]
fn test_all_collaborator_roles() {
    let signing_key = test_signing_key();

    for role in [
        CollaboratorRole::CoAuthor,
        CollaboratorRole::Editor,
        CollaboratorRole::ResearchAssistant,
        CollaboratorRole::Reviewer,
        CollaboratorRole::Transcriber,
        CollaboratorRole::Other,
    ] {
        let decl = Builder::new([1u8; 32], [2u8; 32], "Test")
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .add_collaborator("Person", role, vec![])
            .with_statement("Test")
            .sign(&signing_key)
            .expect("sign");
        assert!(decl.verify().is_ok());
    }
}

#[test]
fn test_modalities_near_100_percent() {
    let signing_key = test_signing_key();

    let decl = Builder::new([1u8; 32], [2u8; 32], "Test")
        .add_modality(ModalityType::Keyboard, 95.0, None)
        .with_statement("Test")
        .sign(&signing_key)
        .expect("sign at 95%");
    assert!(decl.verify().is_ok());

    let decl = Builder::new([1u8; 32], [2u8; 32], "Test")
        .add_modality(ModalityType::Keyboard, 100.0, None)
        .with_statement("Test")
        .sign(&signing_key)
        .expect("sign at 100%");
    assert!(decl.verify().is_ok());

    let result = Builder::new([1u8; 32], [2u8; 32], "Test")
        .add_modality(ModalityType::Keyboard, 105.0, None)
        .with_statement("Test")
        .sign(&signing_key);
    assert!(result.is_err(), "Expected error for 105%, got success");
}

#[test]
fn test_declaration_jitter_from_samples() {
    let samples = vec![1000u32, 1500, 2000, 1200, 1800];
    let jitter = DeclarationJitter::from_samples(&samples, 500, false).expect("from_samples");

    assert_eq!(jitter.keystroke_count, 5);
    assert_eq!(jitter.duration_ms, 500);
    assert!(!jitter.hardware_sealed);
    assert!(jitter.entropy_bits > 0.0);
    assert!((jitter.avg_interval_ms - 125.0).abs() < 0.01);
}

#[test]
fn test_declaration_jitter_hash_deterministic() {
    let samples = vec![1000u32, 1500, 2000];
    let jitter1 = DeclarationJitter::from_samples(&samples, 300, false).expect("from_samples");
    let jitter2 = DeclarationJitter::from_samples(&samples, 300, false).expect("from_samples");

    assert_eq!(jitter1.jitter_hash, jitter2.jitter_hash);
}

#[test]
fn test_declaration_jitter_hash_changes_with_samples() {
    let samples1 = vec![1000u32, 1500, 2000];
    let samples2 = vec![1000u32, 1500, 2001];
    let jitter1 = DeclarationJitter::from_samples(&samples1, 300, false).expect("from_samples");
    let jitter2 = DeclarationJitter::from_samples(&samples2, 300, false).expect("from_samples");

    assert_ne!(jitter1.jitter_hash, jitter2.jitter_hash);
}

#[test]
fn test_declaration_with_jitter_seal() {
    let signing_key = test_signing_key();
    let jitter = DeclarationJitter::from_samples(&[1000u32; 10], 1000, true).expect("from_samples");

    let decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "I wrote this.")
        .with_jitter_seal(jitter.clone())
        .sign(&signing_key)
        .expect("sign");

    assert!(decl.has_jitter_seal());
    assert!(decl.verify().is_ok());

    let sealed = decl.jitter_sealed.as_ref().expect("jitter seal present");
    assert_eq!(sealed.keystroke_count, 10);
    assert!(sealed.hardware_sealed);
}

#[test]
fn test_declaration_jitter_seal_in_signature() {
    let signing_key = test_signing_key();
    let jitter1 =
        DeclarationJitter::from_samples(&[1000u32; 10], 1000, false).expect("from_samples");
    let jitter2 =
        DeclarationJitter::from_samples(&[2000u32; 10], 1000, false).expect("from_samples");

    let decl1 = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .with_jitter_seal(jitter1)
        .sign(&signing_key)
        .expect("sign 1");

    let decl2 = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .with_jitter_seal(jitter2)
        .sign(&signing_key)
        .expect("sign 2");

    assert_ne!(decl1.signature, decl2.signature);
}

#[test]
fn test_declaration_jitter_seal_tampering_detected() {
    let signing_key = test_signing_key();
    let jitter =
        DeclarationJitter::from_samples(&[1000u32; 10], 1000, false).expect("from_samples");

    let mut decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .with_jitter_seal(jitter)
        .sign(&signing_key)
        .expect("sign");

    decl.jitter_sealed
        .as_mut()
        .expect("jitter seal present for tampering")
        .jitter_hash = [0xFFu8; 32];

    assert!(decl.verify().is_err());
}

#[test]
fn test_declaration_without_jitter_seal() {
    let signing_key = test_signing_key();
    let decl = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .sign(&signing_key)
        .expect("sign");

    assert!(!decl.has_jitter_seal());
    assert!(decl.jitter_sealed.is_none());
    assert!(decl.verify().is_ok());
}

#[test]
fn test_declaration_jitter_encode_decode_roundtrip() {
    let signing_key = test_signing_key();
    let jitter = DeclarationJitter::new([0xABu8; 32], 50, 5000, 100.0, 32.5, true);

    let original = no_ai_declaration([1u8; 32], [2u8; 32], "Test", "Statement")
        .with_jitter_seal(jitter)
        .sign(&signing_key)
        .expect("sign");

    let encoded = original.encode().expect("encode");
    let decoded = Declaration::decode(&encoded).expect("decode");

    assert!(decoded.has_jitter_seal());
    assert!(decoded.verify().is_ok());

    let sealed = decoded.jitter_sealed.expect("decoded jitter seal present");
    assert_eq!(sealed.jitter_hash, [0xABu8; 32]);
    assert_eq!(sealed.keystroke_count, 50);
    assert_eq!(sealed.duration_ms, 5000);
    assert!((sealed.avg_interval_ms - 100.0).abs() < 0.01);
    assert!((sealed.entropy_bits - 32.5).abs() < 0.01);
    assert!(sealed.hardware_sealed);
}
