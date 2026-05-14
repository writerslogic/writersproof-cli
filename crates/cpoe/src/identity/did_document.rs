// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use serde::Serialize;

/// W3C DID Core 1.0 context URI.
const DID_CORE_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

/// Ed25519 verification suite context URI.
const ED25519_CONTEXT: &str = "https://w3id.org/security/suites/ed25519-2020/v1";

/// Ed25519 multicodec prefix (0xed, 0x01).
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// W3C DID Document per DID Core 1.0.
#[derive(Debug, Clone, Serialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(rename = "service", skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<ServiceEndpoint>,
}

/// Verification method entry within a DID Document.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// Service endpoint for DID Document (used by did:web).
#[derive(Debug, Clone, Serialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// Encode raw Ed25519 public key bytes as a multibase (base58btc) multicodec string.
fn encode_multibase_ed25519(public_key: &[u8]) -> String {
    let mut prefixed = Vec::with_capacity(2 + public_key.len());
    prefixed.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    prefixed.extend_from_slice(public_key);
    format!("z{}", bs58::encode(&prefixed).into_string())
}

/// Derive a `did:key` URI from raw Ed25519 public key bytes.
///
/// Returns `None` if `public_key` is not exactly 32 bytes.
pub fn did_key_from_public(public_key: &[u8]) -> Option<String> {
    log::debug!("did_key_from_public: key_len={}", public_key.len());
    if public_key.len() != 32 {
        return None;
    }
    Some(format!("did:key:{}", encode_multibase_ed25519(public_key)))
}

/// Generate a DID Document for a `did:key` or `did:web` identifier.
///
/// For `did:key`, the document is deterministic from the public key (Ed25519,
/// multicodec prefix `0xed01`). For `did:web`, a WritersProof API service
/// endpoint is included.
pub fn generate_did_document(did: &str, public_key: &[u8]) -> DidDocument {
    log::debug!("generate_did_document: did={}, key_len={}", did, public_key.len());
    let multibase = encode_multibase_ed25519(public_key);
    let key_id = format!("{}#keys-1", did);

    let verification_method = VerificationMethod {
        id: key_id.clone(),
        key_type: "Ed25519VerificationKey2020".to_string(),
        controller: did.to_string(),
        public_key_multibase: multibase,
    };

    let service = if did.starts_with("did:web:") {
        let domain = did
            .strip_prefix("did:web:")
            .unwrap_or_default()
            .replace(':', "/");
        vec![ServiceEndpoint {
            id: format!("{}#writersproof-api", did),
            service_type: "WritersProofAPI".to_string(),
            service_endpoint: format!("https://{}/api/v1", domain),
        }]
    } else {
        vec![]
    };

    DidDocument {
        context: vec![DID_CORE_CONTEXT.to_string(), ED25519_CONTEXT.to_string()],
        id: did.to_string(),
        verification_method: vec![verification_method],
        authentication: vec![key_id.clone()],
        assertion_method: vec![key_id],
        service,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBKEY: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    #[test]
    fn test_did_key_document_structure() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let doc = generate_did_document(did, &TEST_PUBKEY);

        assert_eq!(doc.id, did);
        assert_eq!(doc.context.len(), 2);
        assert_eq!(doc.context[0], DID_CORE_CONTEXT);
        assert_eq!(doc.context[1], ED25519_CONTEXT);
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.verification_method[0].controller, did);
        assert_eq!(
            doc.verification_method[0].key_type,
            "Ed25519VerificationKey2020"
        );
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        assert!(doc.service.is_empty());
    }

    #[test]
    fn test_did_key_references_match() {
        let did = "did:key:z6MkTest";
        let doc = generate_did_document(did, &TEST_PUBKEY);

        let key_id = &doc.verification_method[0].id;
        assert_eq!(key_id, &format!("{}#keys-1", did));
        assert_eq!(doc.authentication[0], *key_id);
        assert_eq!(doc.assertion_method[0], *key_id);
    }

    #[test]
    fn test_did_web_includes_service() {
        let did = "did:web:writersproof.com";
        let doc = generate_did_document(did, &TEST_PUBKEY);

        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].service_type, "WritersProofAPI");
        assert_eq!(
            doc.service[0].service_endpoint,
            "https://writersproof.com/api/v1"
        );
        assert_eq!(
            doc.service[0].id,
            "did:web:writersproof.com#writersproof-api"
        );
    }

    #[test]
    fn test_did_web_path_encoding() {
        let did = "did:web:example.com:users:alice";
        let doc = generate_did_document(did, &TEST_PUBKEY);

        assert_eq!(doc.service.len(), 1);
        assert_eq!(
            doc.service[0].service_endpoint,
            "https://example.com/users/alice/api/v1"
        );
    }

    #[test]
    fn test_multibase_encoding() {
        let mb = encode_multibase_ed25519(&TEST_PUBKEY);
        assert!(
            mb.starts_with('z'),
            "multibase must use base58btc prefix 'z'"
        );

        // Decode back to verify prefix bytes.
        let decoded = bs58::decode(&mb[1..]).into_vec().expect("base58 decode");
        assert_eq!(decoded[0], 0xed);
        assert_eq!(decoded[1], 0x01);
        assert_eq!(&decoded[2..], &TEST_PUBKEY);
    }

    #[test]
    fn test_json_ld_serialization() {
        let did = "did:key:z6MkTest";
        let doc = generate_did_document(did, &TEST_PUBKEY);
        let json = serde_json::to_value(&doc).expect("serialize");

        assert!(json["@context"].is_array());
        assert_eq!(json["@context"][0], DID_CORE_CONTEXT);
        assert_eq!(json["id"], did);
        assert!(json["verificationMethod"].is_array());
        assert!(json["authentication"].is_array());
        assert!(json["assertionMethod"].is_array());
        // service should be absent for did:key (skip_serializing_if empty)
        assert!(json.get("service").is_none());
    }

    #[test]
    fn test_did_web_json_includes_service() {
        let did = "did:web:writersproof.com";
        let doc = generate_did_document(did, &TEST_PUBKEY);
        let json = serde_json::to_value(&doc).expect("serialize");

        assert!(json["service"].is_array());
        assert_eq!(json["service"][0]["type"], "WritersProofAPI");
    }

    #[test]
    fn test_deterministic_output() {
        let did = "did:key:z6MkTest";
        let doc1 = generate_did_document(did, &TEST_PUBKEY);
        let doc2 = generate_did_document(did, &TEST_PUBKEY);

        let json1 = serde_json::to_string(&doc1).expect("serialize");
        let json2 = serde_json::to_string(&doc2).expect("serialize");
        assert_eq!(json1, json2);
    }

    #[test]
    fn test_did_document_deterministic_different_keys() {
        let did = "did:key:z6MkTest";
        let key_a = [0xAAu8; 32];
        let key_b = [0xBBu8; 32];

        let doc_a = generate_did_document(did, &key_a);
        let doc_b = generate_did_document(did, &key_b);

        // Same DID but different keys must produce different multibase values.
        assert_ne!(
            doc_a.verification_method[0].public_key_multibase,
            doc_b.verification_method[0].public_key_multibase
        );

        // Same key called twice must produce identical output.
        let doc_a2 = generate_did_document(did, &key_a);
        assert_eq!(
            doc_a.verification_method[0].public_key_multibase,
            doc_a2.verification_method[0].public_key_multibase
        );
    }

    #[test]
    fn test_did_document_multibase_format() {
        let did = "did:key:z6MkTest";
        let doc = generate_did_document(did, &TEST_PUBKEY);
        let mb = &doc.verification_method[0].public_key_multibase;

        // Must start with 'z' (base58btc multibase prefix).
        assert!(mb.starts_with('z'), "multibase must start with 'z'");

        // Decode and verify Ed25519 multicodec prefix 0xed01.
        let decoded = bs58::decode(&mb[1..]).into_vec().expect("base58 decode");
        assert!(
            decoded.len() >= 34,
            "decoded must be at least 2 prefix + 32 key bytes"
        );
        assert_eq!(decoded[0], 0xed, "first multicodec byte must be 0xed");
        assert_eq!(decoded[1], 0x01, "second multicodec byte must be 0x01");
        assert_eq!(&decoded[2..], &TEST_PUBKEY, "key bytes must match input");
    }
}
