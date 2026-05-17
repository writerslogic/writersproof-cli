# Session 4: C2PA Integration — Production Hardening

## Project
Rust workspace at `/Volumes/A/writerslogic`. Protocol crate at `crates/authorproof-protocol/`. Engine at `crates/cpoe/`. Read CLAUDE.md and MEMORY.md for context.

## Prerequisites
Sessions 1-3 complete. Engine: 1874+ tests, 0 clippy warnings. Protocol: 257+ tests.

## Current State (already implemented)
- **ManifestBuilder** (`authorproof-protocol/src/c2pa/builder.rs`): fluent builder producing `C2paManifest` with COSE_Sign1 Ed25519 signature, JUMBF container, x5chain header
- **Assertions**: c2pa.hash.data (hard binding), c2pa.actions.v2, c2pa.ai-disclosure, c2pa.external-reference, c2pa.metadata, org.cpoe.evidence (forensic signals), com.writerslogic.vc-reference.v1
- **CAWG**: identity assertion + training/data mining assertion
- **Ingredients**: C2paIngredient with validated relationship enum (parentOf/componentOf/inputTo)
- **Validation**: 11 checks including ingredient relationships, AI disclosure, timestamps, forensic signal bounds, hash verification, COSE_Sign1 verification
- **X.509**: self-signed Ed25519 cert with C2PA EKU OID (1.3.6.1.4.1.62558.2.1)
- **RFC 3161**: TSA token field in builder, best-effort fetch from 4 default TSA URLs in FFI export
- **FFI**: `ffi_export_c2pa_manifest()` produces JUMBF bytes from evidence + document
- **JUMBF**: ISO 19566-5 superbox encoding with proper UUIDs (c2pa/c2ma/c2cl/c2as/c2cs)

## What's Missing (6 gaps)

### Gap 1: Embedded Manifest Support (sidecar-only today)

**Problem:** C2PA manifests are only produced as standalone `.c2pa` sidecar files. C2PA 2.4 requires embedded manifests placed at the END of container formats (PNG, JPEG, TIFF, PDF) with exclusion ranges in the hard binding hash.

**Current:** `ffi_export_c2pa_manifest()` returns raw JUMBF bytes written to a sidecar file. `HashDataAssertion.exclusions` is always empty (`types.rs:132`).

**Fix:**

1. **Add embedding functions per format** in a new file `authorproof-protocol/src/c2pa/embed.rs`:
   - `embed_in_png(document_bytes: &[u8], jumbf: &[u8]) -> Vec<u8>` — insert as `caBX` chunk before IEND
   - `embed_in_jpeg(document_bytes: &[u8], jumbf: &[u8]) -> Vec<u8>` — insert as APP11 marker segment
   - `embed_in_pdf(document_bytes: &[u8], jumbf: &[u8]) -> Vec<u8>` — append as incremental update with `/C2PA` entry
   - Each returns the modified document bytes with the manifest embedded

2. **Compute exclusion ranges** for the hard binding hash:
   - Before embedding: note the byte range where the JUMBF will be inserted
   - Set `HashDataAssertion.exclusions` to `[{ start: offset, length: jumbf_len }]`
   - Recompute the hash EXCLUDING those bytes
   - This is a chicken-and-egg problem: the hash depends on the exclusion range which depends on the JUMBF size which depends on the hash. C2PA solves this by using a placeholder hash, computing JUMBF size, then replacing the hash.

3. **Two-pass hash computation** in the builder:
   ```rust
   // Pass 1: Build manifest with placeholder hash (all zeros)
   let placeholder_hash = [0u8; 32];
   let manifest_pass1 = builder.clone().document_hash(placeholder_hash).build_jumbf(&signer)?;
   let jumbf_size = manifest_pass1.len();

   // Pass 2: Compute real hash with exclusion range
   let exclusion = HashExclusion { start: embed_offset, length: jumbf_size };
   let real_hash = hash_with_exclusions(&document_bytes, &[exclusion]);
   let manifest_final = builder.document_hash(real_hash).exclusions(vec![exclusion]).build_jumbf(&signer)?;
   ```

4. **Add `hash_with_exclusions()` utility** to `authorproof-protocol/src/c2pa/types.rs`:
   ```rust
   pub fn hash_with_exclusions(data: &[u8], exclusions: &[HashExclusion]) -> [u8; 32] {
       let mut hasher = Sha256::new();
       let mut pos = 0;
       for exc in exclusions {
           hasher.update(&data[pos..exc.start]);
           pos = exc.start + exc.length;
       }
       hasher.update(&data[pos..]);
       hasher.finalize().into()
   }
   ```

5. **FFI**: Add `ffi_export_c2pa_embedded(evidence_path: String, document_path: String, output_path: String) -> FfiResult` that detects format from extension and calls the appropriate embed function. Falls back to sidecar for unsupported formats.

**Files:**
- New: `crates/authorproof-protocol/src/c2pa/embed.rs`
- Modify: `crates/authorproof-protocol/src/c2pa/types.rs` (add HashExclusion struct, hash_with_exclusions)
- Modify: `crates/authorproof-protocol/src/c2pa/builder.rs` (add exclusions() method)
- Modify: `crates/authorproof-protocol/src/c2pa/mod.rs` (export embed module)
- Modify: `crates/cpoe/src/ffi/evidence_derivative.rs` (add embedded export FFI)

**Tests:**
- PNG embed/extract roundtrip (use a 1x1 pixel PNG)
- Hash exclusion computation correctness
- Two-pass hash placeholder replacement
- Sidecar fallback for unsupported formats

### Gap 2: X.509 Certificate Chain Management

**Problem:** Only self-signed certs. C2PA Trust Model requires validating certificate chain against trust anchors. Production deployment needs CA-signed certs.

**Current:** `cert.rs` generates self-signed Ed25519 certs. `builder.rs` puts the single cert in x5chain.

**Fix:**

1. **Support loading external cert chain** in builder:
   ```rust
   // builder.rs — already has cert_der(), extend to accept chain:
   pub fn cert_chain(mut self, chain: Vec<Vec<u8>>) -> Self {
       self.cert_chain = chain;  // leaf first, then intermediates, then root
       self
   }
   ```

2. **Chain validation in `validation.rs`:**
   - Extract full x5chain from COSE header (array of certs, not just first)
   - Verify leaf cert signed by intermediate, intermediate by root
   - Check each cert's validity period (notBefore/notAfter)
   - Verify leaf has C2PA EKU OID
   - Check for revocation (optional — CRL or OCSP, defer to future)

3. **Trust anchor list** in `authorproof-protocol/src/c2pa/trust.rs`:
   ```rust
   pub const C2PA_TRUST_ANCHORS: &[&[u8]] = &[
       include_bytes!("trust/c2pa-root.der"),
       // Add more as C2PA org publishes
   ];
   ```
   For now, accept self-signed certs with a warning. Log trust level in validation result.

4. **FFI cert loading:** The engine already has cert loading infrastructure at `ffi/helpers.rs` (`load_or_generate_cert`). Extend to load a chain from keychain or PEM file:
   ```rust
   pub fn load_cert_chain() -> Result<Vec<Vec<u8>>> { ... }
   ```

**Files:**
- New: `crates/authorproof-protocol/src/c2pa/trust.rs`
- Modify: `crates/authorproof-protocol/src/c2pa/builder.rs` (cert_chain method)
- Modify: `crates/authorproof-protocol/src/c2pa/validation.rs` (chain validation)
- Modify: `crates/cpoe/src/ffi/helpers.rs` (chain loading)

### Gap 3: C2PA-VC Cross-Reference Integrity

**Problem:** C2PA manifest embeds a VC hash reference, but the VC in the report is unsigned. The hash reference points to an unsigned VC, which undermines the integrity chain.

**Current:**
- `package.rs:281` links VC hash into C2PA via `builder.vc_reference(vc_hash, None)`
- `report.rs:1295-1389` builds VC JSON but calls `to_verifiable_credential()` (unsigned, line 207 of vc.rs) not `to_signed_verifiable_credential()`
- The VC hash in C2PA manifest doesn't match any signed VC

**Fix:**

1. **Sign the report VC:** In `build_vc_json()` (`ffi/report.rs:1295`), change from `to_verifiable_credential()` to `to_signed_verifiable_credential()`. This requires a `&dyn tpm::Provider` — pass the TPM provider through the report building chain:
   ```rust
   // In build_war_report_for_path(), after computing guilloche_seed:
   let provider = crate::tpm::detect_provider();
   let vc_json = build_vc_json(&report, &events, signing_key.as_ref(), &*provider);
   ```

2. **Compute VC hash AFTER signing:** In `CredentialPackage::build()` (`package.rs`), the VC hash must be computed from the signed VC (including proof), not the unsigned version.

3. **Add reverse reference in VC:** Add a field to `ProcessAttestation` in `vc.rs`:
   ```rust
   #[serde(rename = "c2paManifestRef", skip_serializing_if = "Option::is_none")]
   pub c2pa_manifest_ref: Option<String>,  // SHA-256 hex of C2PA JUMBF
   ```
   This creates bidirectional linkage: C2PA → VC (via VcReferenceAssertion) and VC → C2PA (via c2paManifestRef).

4. **Validation:** Add a check in `validate_manifest()` that verifies the VC reference hash matches the actual VC content when both are available.

**Files:**
- Modify: `crates/cpoe/src/ffi/report.rs:1295-1389` (sign the VC)
- Modify: `crates/cpoe/src/war/profiles/vc.rs` (add c2paManifestRef)
- Modify: `crates/cpoe/src/war/profiles/package.rs` (hash after signing, bidirectional ref)
- Modify: `crates/authorproof-protocol/src/c2pa/validation.rs` (VC hash consistency check)

### Gap 4: Offline TSA Fallback

**Problem:** RFC 3161 TSA tokens require network access. Offline users get no timestamp in their C2PA manifest.

**Current:** `ffi_export_c2pa_manifest()` tries 4 TSA URLs, logs warning on failure, continues without token.

**Fix:** When all TSAs are unreachable, embed a local temporal proof instead:
1. Use the VDF proof from the checkpoint chain as the timestamp anchor
2. Add a custom assertion `com.writerslogic.local-timestamp.v1` containing the VDF proof hash + iteration count + wall clock time
3. This is weaker than RFC 3161 but provides SOME temporal evidence
4. Log the downgrade: `log::warn!("No TSA available; using local VDF timestamp")`

**Files:**
- Modify: `crates/cpoe/src/ffi/evidence_derivative.rs` (add fallback after TSA loop)
- Modify: `crates/authorproof-protocol/src/c2pa/types.rs` (add LocalTimestampAssertion type)
- Modify: `crates/authorproof-protocol/src/c2pa/builder.rs` (add local_timestamp method)

### Gap 5: Manifest Stripping Detection

**Problem:** No way to detect if a C2PA manifest was removed from a document (e.g., someone strips the sidecar file or removes the embedded JUMBF).

**Fix:** Use the engine's content fingerprint (SimHash) as a soft binding. When a C2PA manifest is created, store a mapping `document_simhash -> manifest_hash` in the local database. When verifying a document without a manifest, compute its SimHash and check if a manifest was previously issued for similar content.

1. Add `simhash: u64` field to C2PA manifest metadata
2. In FFI export, compute SimHash of document content and store in evidence database
3. Add `ffi_check_manifest_stripping(document_path: String) -> FfiStrippingResult` that:
   - Computes SimHash of document
   - Checks local DB for matching manifest
   - Returns: `NoManifestExpected`, `ManifestPresent`, `ManifestStripped { original_manifest_hash }`

**Files:**
- Modify: `crates/cpoe/src/ffi/evidence_derivative.rs` (store SimHash on export)
- New: `crates/cpoe/src/ffi/evidence_verify.rs` or extend existing verify functions
- Modify: `crates/cpoe/src/store/` (add manifest_registry table)

### Gap 6: Production Test Suite

**Missing tests that must exist before shipping:**

```rust
// In authorproof-protocol/src/c2pa/tests.rs:
test_manifest_roundtrip_jumbf_encode_decode
test_embedded_png_preserves_image_data
test_embedded_jpeg_preserves_image_data
test_hash_exclusion_range_correctness
test_two_pass_hash_placeholder_replacement
test_cert_chain_validation_with_intermediate
test_expired_cert_rejected
test_wrong_eku_cert_rejected
test_vc_hash_matches_signed_vc
test_bidirectional_c2pa_vc_reference
test_tsa_token_in_cose_unprotected_header
test_local_timestamp_fallback_when_offline
test_manifest_stripping_detection
test_sidecar_fallback_for_unknown_format

// Integration test (in cpoe crate):
test_full_pipeline_document_to_c2pa_to_vc_to_verify
```

## Dependency Order
```
Gap 1 (embed) + Gap 2 (cert chain) — can parallelize
Gap 3 (VC cross-ref) — depends on VC signing working
Gap 4 (offline fallback) — independent
Gap 5 (stripping detection) — depends on Gap 1 (needs to know if embedded)
Gap 6 (tests) — after all gaps
```

## Constraints
- `authorproof-protocol` crate is `wasm32`-compatible: no filesystem, no network, no platform APIs. Embedding functions take `&[u8]` input, return `Vec<u8>`. Network calls (TSA) happen in the engine crate only.
- Don't break existing sidecar export path — embedding is additive.
- Self-signed certs must remain supported (development/testing). Chain validation is optional with a warning.
- Re-read files before editing; run `cargo check -p authorproof-protocol --lib` and `cargo check -p cpoe --lib` after batching edits.
