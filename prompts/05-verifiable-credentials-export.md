# Session 5: W3C Verifiable Credentials — Export & Conformance

## Project
Rust workspace at `/Volumes/A/writerslogic`. VC implementation at `crates/cpoe/src/war/profiles/vc.rs`. Read CLAUDE.md and MEMORY.md for context.

## Prerequisites
Sessions 1-4 complete. C2PA-VC cross-reference integrity fixed (Session 4 Gap 3).

## Current State (already implemented)

**Working W3C VC 2.0 implementation** at `war/profiles/vc.rs`:
- Data model: `@context` with W3C credentials/v2 + custom WritersLogic context
- Types: `VerifiableCredential`, `ProcessAttestationCredential`
- Issuer: `did:web:writerslogic.com`
- Subject: author's `did:key` + `ProcessAttestation` claims (status, trustVector, documentRef, chainDuration, writingMode, compositionMode, forensicSignals)
- **Data Integrity Proof**: `eddsa-jcs-2022` cryptosuite — JCS canonicalize proof options + VC, sign SHA256(proof_options) || SHA256(vc), encode as multibase base16
- **COSE_Sign1 envelope**: `to_cose_secured_vc()` wrapping VC as CBOR payload
- **Evidence array**: ProofOfProcessEvidence with verifier identity and seal hash
- **Forensic signals**: 5 normalized scores (cognitiveLoad, revisionTopology, errorEcology, likelihoodPCognitive, compositionMode)
- **Report integration**: VC JSON embedded in HTML reports and PDF attachments
- **19 tests** covering COSE roundtrip, headers, proof structure, forensic enrichment

**Known issue fixed in Session 4:** Report VC is now signed (was unsigned). `build_vc_json()` calls `to_signed_verifiable_credential()` with TPM provider.

## What's Missing (5 gaps)

### Gap 1: Multi-Format VC Export

**Problem:** VCs are only available as JSON strings embedded in reports. Users need standalone export in multiple formats for interoperability with external verifiers.

**Current:** `WarReport.verifiable_credential_json: Option<String>` — JSON string. No file export.

**Fix — 3 new FFI functions:**

```rust
/// Export VC as JSON file (.vc.json)
/// W3C standard format — any JSON-LD processor can read this.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_vc_json(evidence_path: String, document_path: String, output_path: String) -> FfiResult {
    // 1. Load evidence, build EarToken, construct VC
    // 2. Sign with to_signed_verifiable_credential()
    // 3. Serialize to pretty JSON
    // 4. Atomic write to output_path (tempfile + rename)
}

/// Export VC as COSE_Sign1 binary (.vc.cbor)
/// Compact binary format per "Securing VCs using JOSE and COSE" W3C Recommendation.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_export_vc_cbor(evidence_path: String, document_path: String, output_path: String) -> FfiResult {
    // 1. Same as above through signing
    // 2. Call to_cose_secured_vc() for COSE_Sign1 wrapping
    // 3. Atomic write CBOR bytes to output_path
}

/// Verify a VC file (JSON or CBOR) and return verification result.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_verify_vc(vc_path: String) -> FfiVcVerifyResult {
    // 1. Detect format from extension (.vc.json vs .vc.cbor)
    // 2. For JSON: parse, extract proof, verify eddsa-jcs-2022 signature
    // 3. For CBOR: call verify_cose_secured_vc() with extracted public key
    // 4. Validate credential structure (required fields, dates, types)
    // 5. Return: valid, issuer_did, subject_did, verdict, expiry, forensic_signals
}
```

**FfiVcVerifyResult struct:**
```rust
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiVcVerifyResult {
    pub success: bool,
    pub signature_valid: bool,
    pub issuer_did: Option<String>,
    pub subject_did: Option<String>,
    pub verdict: Option<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub is_expired: bool,
    pub forensic_signals: Option<FfiForensicSignals>,
    pub error_message: Option<String>,
}
```

**Files:**
- New: `crates/cpoe/src/ffi/vc_export.rs`
- Modify: `crates/cpoe/src/ffi/mod.rs` (register module)
- Modify: `crates/cpoe/src/ffi/types.rs` (add FfiVcVerifyResult, FfiForensicSignals)

**macOS integration:** Add export options in `ExportFormView.swift`:
- "Verifiable Credential (JSON)" — calls `ffi_export_vc_json`
- "Verifiable Credential (CBOR)" — calls `ffi_export_vc_cbor`
- "Verify Credential" — file picker + calls `ffi_verify_vc`

### Gap 2: DID Document Publication

**Problem:** Issuer is `did:web:writerslogic.com` but no DID document is published at `https://writerslogic.com/.well-known/did.json`. External verifiers cannot resolve the issuer to validate the signature.

**Fix:**

1. **Generate DID document** from the WritersProof signing key:
   ```json
   {
     "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
     "id": "did:web:writerslogic.com",
     "verificationMethod": [{
       "id": "did:web:writerslogic.com#key-1",
       "type": "Ed25519VerificationKey2020",
       "controller": "did:web:writerslogic.com",
       "publicKeyMultibase": "z6Mk..."
     }],
     "assertionMethod": ["did:web:writerslogic.com#key-1"],
     "authentication": ["did:web:writerslogic.com#key-1"]
   }
   ```

2. **Serve at `/.well-known/did.json`** on writerslogic.com:
   - Add a static route in the website (`apps/web`) or as a Cloudflare Worker rule
   - The public key comes from the WritersProof CA root key (already exists as `ROOT_CA_CERTIFICATE` env var in the API)

3. **Per-author DID documents:** Each author has a `did:key` derived from their device signing key. These are self-resolving (no publication needed) — the public key IS the DID. Verification requires only the VC itself.

4. **Validate issuer resolution** in `ffi_verify_vc`:
   - For `did:web`: fetch `https://{domain}/.well-known/did.json`, extract public key, verify
   - For `did:key`: extract public key from DID string directly (already implemented in `identity/did_key.rs`)

**Files:**
- New: `~/workspace_local/Writerslogic/writersproof/apps/web/public/.well-known/did.json` (static file)
- Modify: `crates/cpoe/src/ffi/vc_export.rs` (DID resolution in verify)
- Modify: `crates/cpoe/src/identity/did_key.rs` (ensure did:key → public key extraction works)

### Gap 3: Credential Status (Revocation)

**Problem:** No mechanism to revoke an issued VC. Once a certificate is revoked in WritersProof, the corresponding VC remains valid.

**W3C VC spec:** `credentialStatus` field (§5.5) with `type` and `id` pointing to a status list.

**Fix — Bitstring Status List (W3C standard):**

1. **Add `credentialStatus` to VC** (`vc.rs`):
   ```rust
   #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
   pub credential_status: Option<CredentialStatus>,

   #[derive(Serialize, Deserialize)]
   pub struct CredentialStatus {
       pub id: String,           // https://writersproof.com/credentials/status/1#INDEX
       #[serde(rename = "type")]
       pub status_type: String,  // "BitstringStatusListEntry"
       #[serde(rename = "statusPurpose")]
       pub status_purpose: String, // "revocation"
       #[serde(rename = "statusListIndex")]
       pub status_list_index: String, // position in bitstring
       #[serde(rename = "statusListCredential")]
       pub status_list_credential: String, // URL to the status list VC
   }
   ```

2. **Status list endpoint** in WritersProof API:
   ```typescript
   // GET /v1/credentials/status/:listId
   // Returns a VerifiableCredential containing a BitstringStatusList
   // The bitstring is a gzip-compressed, base64-encoded bitarray
   // where bit N = 1 means credential at index N is revoked
   ```

3. **On revocation** (existing `revoke.ts` route): Set the corresponding bit in the status list.

4. **On VC creation:** Assign a status list index (monotonic counter per list, stored in Supabase).

5. **On VC verification** (`ffi_verify_vc`): If `credentialStatus` present, fetch the status list URL, decompress bitstring, check the index bit. Report `is_revoked: bool` in result.

**Files:**
- Modify: `crates/cpoe/src/war/profiles/vc.rs` (add CredentialStatus)
- New: `~/workspace_local/Writerslogic/writersproof/apps/api/src/routes/credentialStatus.ts`
- Modify: `~/workspace_local/Writerslogic/writersproof/apps/api/src/routes/revoke.ts` (set revocation bit)
- New: `~/workspace_local/Writerslogic/writersproof/supabase/migrations/YYYYMMDD_credential_status_lists.sql`
- Modify: `crates/cpoe/src/ffi/vc_export.rs` (revocation check in verify)

### Gap 4: JSON-LD Context Publication

**Problem:** Custom context `https://writerslogic.com/ns/pop/v1` is not published. External JSON-LD processors fail to expand the VC.

**Fix:**

1. **Create the context document** defining all custom terms:
   ```json
   {
     "@context": {
       "@version": 1.1,
       "pop": "https://writerslogic.com/ns/pop/v1#",
       "ProcessAttestationCredential": "pop:ProcessAttestationCredential",
       "processAttestation": "pop:processAttestation",
       "ProcessAttestation": "pop:ProcessAttestation",
       "status": "pop:status",
       "trustVector": "pop:trustVector",
       "documentRef": "pop:documentRef",
       "chainDuration": "pop:chainDuration",
       "attestationTier": "pop:attestationTier",
       "writingMode": "pop:writingMode",
       "compositionMode": "pop:compositionMode",
       "forensicSignals": "pop:forensicSignals",
       "cognitiveLoadScore": "pop:cognitiveLoadScore",
       "revisionTopologyScore": "pop:revisionTopologyScore",
       "errorEcologyScore": "pop:errorEcologyScore",
       "likelihoodPCognitive": "pop:likelihoodPCognitive",
       "compositionModeScore": "pop:compositionModeScore",
       "c2paManifestRef": "pop:c2paManifestRef"
     }
   }
   ```

2. **Serve at `https://writerslogic.com/ns/pop/v1`:**
   - Static file at `apps/web/public/ns/pop/v1.jsonld`
   - Content-Type: `application/ld+json`
   - Cache with long TTL (context is immutable per version)

3. **Versioning:** If the schema changes, publish as `/ns/pop/v2` and update the VC `@context` array. Never modify an existing version.

**Files:**
- New: `~/workspace_local/Writerslogic/writersproof/apps/web/public/ns/pop/v1.jsonld`
- Verify: `crates/cpoe/src/war/profiles/vc.rs:165` context URL matches the served path

### Gap 5: COSE Content Type Registration

**Problem:** COSE header `content_type` is `"application/vc"` (line 264 of vc.rs) — not registered with IANA.

**Fix:** Change to `"application/vc+cose"` per the W3C "Securing VCs using JOSE and COSE" specification (Section 3.3), or use the media type registered by the VC working group. Check the current W3C spec for the correct value.

```rust
// vc.rs line 264, in to_cose_secured_vc():
// Change:
.content_type("application/vc".to_string())
// To:
.content_type("application/vc+cose".to_string())
```

Also update the `from_cose_secured_vc()` and `verify_cose_secured_vc()` functions to accept both old and new content types for backward compatibility.

**Files:**
- Modify: `crates/cpoe/src/war/profiles/vc.rs:264` (content type)

## Tests

```rust
// Export tests:
test_export_vc_json_produces_valid_file
test_export_vc_cbor_produces_valid_cose
test_verify_vc_json_roundtrip
test_verify_vc_cbor_roundtrip
test_verify_vc_detects_tampered_signature
test_verify_vc_detects_expired_credential

// DID resolution tests:
test_did_key_resolution_extracts_public_key
test_did_web_url_construction

// Revocation tests:
test_credential_status_field_present_when_configured
test_revocation_bit_set_rejects_credential
test_unrevoked_credential_passes

// Context tests:
test_context_document_parseable_as_jsonld
test_all_custom_terms_defined_in_context

// Integration:
test_signed_vc_json_verifiable_by_external_tool
test_cose_vc_verifiable_by_coset_library
```

## Dependency Order
```
Gap 5 (content type) — trivial, do first
Gap 4 (context publication) — independent, do early
Gap 1 (multi-format export) — core feature
Gap 2 (DID document) — needed for verify to work externally
Gap 3 (revocation) — depends on API endpoint
```

## Constraints
- The VC implementation is in the `cpoe` engine crate (not `authorproof-protocol`) because it depends on TPM/signing infrastructure
- VCs must remain valid JSON-LD (parseable by standard processors)
- Don't break existing report VC embedding (HTML `<script type="application/ld+json">` and PDF attachment)
- `eddsa-jcs-2022` cryptosuite is correct per W3C Data Integrity EdDSA Cryptosuites v1.0
- Export functions follow the same `ffi_export_*` pattern as C2PA export
- Re-read files before editing; batch edits, minimize cargo runs
