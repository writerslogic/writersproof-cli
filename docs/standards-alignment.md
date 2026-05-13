# CPoE Standards Alignment Map

This document maps CPoE's implementation to external standards and specifications,
documenting current alignment status, integration points, and identified gaps.

Last updated: 2026-05-11

## Alignment Summary

| Standard | Status | Integration Point |
|----------|--------|-------------------|
| IETF RATS (EAT/EAR/AR4SI) | **Strong** | Core appraisal framework |
| W3C DID Core 1.0 | **Strong** | Author identity (did:key, did:web) |
| W3C VC Data Model 2.0 | **Strong** | war/profiles/vc.rs projection |
| W3C VC COSE Securing | **Implemented** | war/profiles/vc.rs COSE_Sign1 envelope |
| C2PA (ISO 19566-5) | **Good** | war/profiles/c2pa.rs assertion, sentinel/content_fingerprint.rs soft binding |
| CBOR/COSE (RFC 8949/9052) | **Strong** | Wire format + signatures |
| NIST AI RMF 1.0 | **Mapped** | war/profiles/standards.rs |
| NIST AI 100-4 | **Aligned** | Provenance metadata, watermarking |
| ISO/IEC 42001 | **Mapped** | war/profiles/standards.rs |
| IPTC Digital Source Type | **Implemented** | AiDisclosureLevel mapping |
| W3C AI Content Disclosure CG | **Implemented** | AiDisclosureLevel + HTML meta + element attributes |
| IETF AI Content Disclosure Header | **Planned** | draft-abaris-aicdh HTTP header |
| WGA MBA / SAG-AFTRA | **Mapped** | CreativeRightsCompliance |
| EU AI Act Article 50 | **Implemented** | AiDisclosureLevel + declaration fields |
| CAWG Identity Assertion v1.2 | **Partial** | DID-based identity, key hierarchy |
| CAWG Training/Data Mining v1.1 | **Partial** | Declaration AI tool disclosure |
| IETF SCITT | **Partial** | Transparency log anchoring |
| ToIP EGF | **Planned** | Trust policy / governance framework |
| TRQP | **Planned** | Trust registry query integration |
| OpenID4VC (OID4VCI) | **Implemented** | identity/openid4vc.rs issuer metadata |
| DIF Well Known DID Config | **Implemented** | identity/did_configuration.rs |
| ORCID | **Implemented** | identity/orcid.rs author binding |
| JPEG Trust (ISO 21617) | **Implemented** | war/profiles/jpeg_trust.rs |
| DIF Presentation Exchange | **Implemented** | identity/presentation_exchange.rs |
| CoRIM | **Partial** | EAR token carries CoRIM-compatible claims |
| WebAuthn/FIDO2 | Not applicable | User auth, not authorship proof |
| IEEE P3119 | Not applicable | Procurement standard, not metadata |
| NCCoE AI Agent Identity | **Partial** | DID-based author identity |

## 1. IETF RATS Working Group

### Specifications
- draft-ietf-rats-eat (Entity Attestation Token)
- draft-ietf-rats-ear (Entity Attestation Result)
- draft-ietf-rats-ar4si (Attestation Results for Secure Interactions)
- draft-condrey-rats-pop (Proof of Process -- our draft)

### Implementation
- **EAT Profile URI**: `urn:ietf:params:rats:eat:profile:pop:1.0`
- **EAR Token**: Full implementation in `war/ear.rs`
- **AR4SI Trust Vector**: 8-component mapping in `war/appraisal.rs`
  - Instance Identity -> hardware attestation tier
  - Configuration -> declaration signature validity
  - Executables -> binary attestation presence
  - File System -> hash chain integrity (H1/H2/H3)
  - Hardware -> TPM/Secure Enclave binding
  - Runtime Opaque -> VDF proof strength + time plausibility
  - Storage Opaque -> key hierarchy + session certificate
  - Sourced Data -> behavioral entropy + jitter quality
- **Private-use CWT keys**: 70001-70009 for CPoE-specific claims
- **CBOR wire format**: Tagged per RFC 8949 with tags 0x43504F50 and 0x43574152

### Gap: None identified

## 2. W3C DID Core 1.0

### DID Methods Used
- `did:key:z6Mk...` -- Self-sovereign Ed25519 identity (primary)
- `did:web:writerslogic.com` -- Organizational issuer identity
- `did:web:writerslogic.com:authors:{id}` -- API-anchored author identity

### Verification Relationships
- `assertionMethod` -- Used for signing evidence packets and VCs
- `authentication` -- Used for session binding (implicit via key hierarchy)

### Implementation
- DID generation in `cmd_identity.rs`
- Author DID in VC credential subject
- Verification method references in VC proof

### Gap: No formal DID Document generation/resolution

## 3. W3C Verifiable Credentials Data Model 2.0

### Implementation (`war/profiles/vc.rs`)
- `@context`: `["https://www.w3.org/ns/credentials/v2", "https://writerslogic.com/ns/pop/v1"]`
- Type: `["VerifiableCredential", "ProcessAttestationCredential"]`
- Issuer: `did:web:writerslogic.com`
- Data Integrity Proof: `eddsa-rdfc-2022` cryptosuite
- Evidence array with verifier identity
- Credential subject with author DID and process attestation

### Gap: Proof value is placeholder -- actual signing at higher layer

## 4. C2PA (Content Credentials)

### Implementation (`war/profiles/c2pa.rs`)
- Assertion label: `com.writerslogic.cpoe-attestation.v1` (entity-specific per C2PA spec)
- Action: `c2pa.created` with IPTC `humanCreation` digital source type
- Trust vector, seal hashes, evidence reference in assertion data
- C2PA action for `c2pa.actions.v2` integration

### C2PA spec alignment (v2.3)
- **Cryptographic**: Ed25519 is in C2PA allowed algorithm list
- **Hash**: SHA-256 is in C2PA allowed hash list
- **CBOR**: Both use RFC 8949 deterministic encoding
- **Signing**: Both use COSE_Sign1 format

### Soft binding
- Algorithm: `com.writersproof.content-fingerprint.v1`
- Type: fingerprint (SimHash, 64-bit, character 4-grams, FNV-1a)
- Matching: Hamming distance < 11 bits
- Spec: `https://writersproof.com/specs/content-fingerprint-v1.html`
- Code path: `sentinel/content_fingerprint.rs`
- Registration: pending submission to `c2pa-org/softbinding-algorithm-list`

### Gaps
- No JUMBF container generation (C2PA manifests use JUMBF)
- No X.509 certificate chain (C2PA requires X.509)
- No hard binding (`c2pa.hash.data`) to document bytes
- No RFC 3161 time-stamp in COSE unprotected headers

### Integration path
CPoE is positioned as an **evidence source for C2PA**, not a C2PA replacement.
The assertion projection allows CPoE attestations to be consumed by C2PA manifest
generators (e.g., c2patool) as custom assertions. The soft binding algorithm
enables provenance recovery when a document's C2PA manifest has been stripped
or when the same content has been exported across applications.

## 5. CBOR/COSE (RFC 8949 / RFC 9052)

### Implementation
- **ciborium** crate for CBOR encoding (deterministic, RFC 8949 Section 4.2.1)
- **coset** crate for COSE signatures
- Custom CBOR tags: 0x43504F50 (evidence), 0x43574152 (attestation)
- Media types: `application/vnd.writersproof.cpoe+cbor`, `application/vnd.writersproof.cwar+cbor`
- Ed25519 signatures via ed25519-dalek with zeroize

### Gap: None identified

## 6. NIST AI RMF 1.0 (AI 100-1) / AI 100-4

### Mapping (`war/profiles/standards.rs`)
| RMF Subcategory | CPoE Coverage |
|-----------------|---------------|
| GV-1.1 | Declaration with AI disclosure fields per EU AI Act Art. 50 |
| GV-1.2 | AR4SI trustworthiness vector (8 components) |
| MS-2.6 | Forensic assessment_score with 5 verdict levels |
| MS-2.11 | Biological plausibility ranges, not demographic profiling |
| MG-4.1 | Continuous sentinel monitoring with checkpoint chain |

### NIST AI 100-4 (Synthetic Content) alignment
- Provenance metadata: origin, timestamp, author, edit history (**implemented**)
- Watermarking: ZWC steganographic marks (**implemented**)
- Content authentication: cryptographic signatures (**implemented**)
- C2PA interoperability: assertion projection (**implemented**)

## 7. ISO/IEC 42001 (AI Management Systems)

### Mapping (`war/profiles/standards.rs`)
| Control | Topic | CPoE Coverage |
|---------|-------|---------------|
| A.6 | Data governance | HMAC chains, WAL, MMR append-only proofs |
| A.7 | System documentation | claim_generator_info with version, capabilities |
| A.8 | Transparency | Forensic verdict, confidence, limitations array |
| A.10 | Accountability | Key hierarchy ties actions to signing identity |

## 8. IPTC Digital Source Type

### Implementation (`war/profiles/standards.rs`)
| CPoE AiExtent | IPTC Source Type | W3C ai-disclosure | IETF AI-Disclosure mode |
|---------------|------------------|-------------------|------------------------|
| None | `humanCreation` | `none` | `none` |
| Minimal | `compositeWithTrainedAlgorithmicMedia` | `ai-assisted` | `ai-modified` |
| Moderate | `compositeWithTrainedAlgorithmicMedia` | `ai-assisted` | `ai-modified` |
| Substantial | `trainedAlgorithmicMedia` | `ai-generated` | `ai-originated` |

Used in C2PA action entries via `digitalSourceType` field.

## 9. W3C AI Content Disclosure Community Group

### Status: Implemented

The W3C AI Content Disclosure CG defines lightweight, in-document metadata
for disclosing AI involvement in content creation. Founded February 2026
with kickoff May 2026; driven by EU AI Act Article 50 compliance (August 2026).

- **W3C CG**: https://www.w3.org/community/ai-content-disclosure/
- **Explainer**: https://github.com/dweekly/ai-content-disclosure
- **WICG Proposal**: WICG/proposals#261
- **WHATWG HTML**: whatwg/html#9479
- **Chairs**: Dogu Abaris, David Weekly

### Specification overview

The CG defines three disclosure mechanisms:

#### A. HTML global attribute: `ai-disclosure`

Applied to any HTML element. Four values defined:

| Value | Meaning |
|-------|---------|
| `none` | No AI involvement; human-authored |
| `ai-assisted` | Human-authored, AI edited/refined |
| `ai-generated` | AI-generated with human prompting/review |
| `autonomous` | AI-generated without human oversight |

Absence of the attribute means "unknown", not "none" -- a deliberate design
choice. Children inherit the nearest ancestor's value unless they override it.

Optional companion attributes:
- `ai-model` -- model identifier (e.g., `"claude-3.5-sonnet"`)
- `ai-provider` -- provider/organization (e.g., `"Anthropic"`)
- `ai-prompt-url` -- URL to methodology documentation

#### B. Page-level meta tag

```html
<meta name="ai-disclosure" content="none|ai-assisted|ai-generated|autonomous|mixed">
```

The `mixed` value is unique to the meta tag; it signals that different sections
carry different disclosure levels via element-level attributes. Element-level
attributes override the page-level meta.

#### C. Schema.org integration (proposed)

Schema.org issue #3391 proposes an `aiDisclosure` property:

```json
{
  "@type": "Article",
  "aiDisclosure": {
    "level": "ai-assisted",
    "tool": "Claude 3.5 Sonnet",
    "provider": "Anthropic"
  }
}
```

### CPoE implementation (`war/profiles/standards.rs`)

- `AiDisclosureLevel` enum: `none`, `ai-assisted`, `ai-generated`, `autonomous`, `mixed`
- `to_html_meta_tag()` generates `<meta name="ai-disclosure" content="...">`
- `to_html_element_attr()` generates element-level `ai-disclosure="..."` attribute
- `from_ai_extent()` maps CPoE's `AiExtent` to W3C disclosure values
- `to_iptc_digital_source_type()` cross-maps to IPTC URIs
- `to_ietf_header_mode()` maps to draft-abaris-aicdh `mode` token
- `AiDisclosureAttributes` struct bundles level + companion attributes:
  - `to_html_meta_tags()` emits all `<meta>` tags (disclosure + model + provider + prompt-url + evidence-url)
  - `to_html_element_attrs()` emits element-level attribute string
  - `to_ietf_header()` emits IETF `AI-Disclosure` structured field header
  - `from_declaration()` populates from CPoE declaration + optional evidence URL

### Cross-standard mapping

| CPoE AiExtent | W3C ai-disclosure | IPTC Source Type | IETF header mode |
|---------------|-------------------|------------------|------------------|
| None | `none` | `humanCreation` | `none` |
| Minimal | `ai-assisted` | `compositeWithTrainedAlgorithmicMedia` | `ai-modified` |
| Moderate | `ai-assisted` | `compositeWithTrainedAlgorithmicMedia` | `ai-modified` |
| Substantial | `ai-generated` | `trainedAlgorithmicMedia` | `ai-originated` |
| (third-party) | `autonomous` | `trainedAlgorithmicMedia` | `machine-generated` |
| (mixed doc) | `mixed` | `compositeWithTrainedAlgorithmicMedia` | `ai-modified` |

### WritersProof extension: `ai-evidence-url`

CPoE extends the W3C vocabulary with `ai-evidence-url`, an attribute pointing
to the WritersProof verification endpoint (`https://writersproof.com/verify/{proof_id}`).
This makes AI disclosure machine-verifiable rather than self-declared. Emitted
in both `<meta>` tags and element-level attributes via `AiDisclosureAttributes`.

### Gaps (remaining)
- **No Schema.org output**: The `aiDisclosure` JSON-LD property is not generated.

### Relationship to C2PA
The CG spec explicitly complements C2PA rather than replacing it. C2PA provides
cryptographically signed provenance assertions; the `ai-disclosure` attribute
provides a lightweight, in-document signal. CPoE bridges both: the C2PA assertion
carries the full trust vector while the HTML meta tag provides the human-readable
and machine-parseable disclosure.

### Spec reference
W3C AI Content Disclosure CG (2026), Explainer (pre-report)

## 10. IETF AI Content Disclosure Header

### Status: Implemented

draft-abaris-aicdh-00 defines an HTTP response header for AI content disclosure,
using RFC 9651 Structured Fields.

### Header format

```
AI-Disclosure: mode=ai-originated; model="gpt-4"; provider="OpenAI"; reviewed-by="editorial-team"; date=@1745286896
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `mode` | Token | `none`, `ai-modified`, `ai-originated`, `machine-generated` |
| `model` | String | AI model identifier |
| `provider` | String | Organization operating the AI system |
| `reviewed-by` | String | Entity that reviewed the content |
| `date` | Date | RFC 9651 epoch timestamp |

### Mapping to W3C CG values

| IETF header `mode` | W3C `ai-disclosure` |
|--------------------|---------------------|
| `none` | `none` |
| `ai-modified` | `ai-assisted` |
| `ai-originated` | `ai-generated` |
| `machine-generated` | `autonomous` |

### CPoE alignment (`war/profiles/standards.rs`)

`AiDisclosureAttributes::to_ietf_header()` generates the structured field header.
`AiDisclosureLevel::to_ietf_header_mode()` maps each level to the `mode` token.
The WritersProof API verification endpoint can emit this header when serving
attestation results.

### Note
- The header is advisory only (no integrity protection), which is a weaker
  guarantee than CPoE's signed attestations, but useful for HTTP-layer
  interoperability.
- IETF draft expired November 2025; status of revision unclear.

### Spec reference
draft-abaris-aicdh-00 (IETF Individual, April 2025)

## 11. WGA MBA / SAG-AFTRA AI Provisions

### Implementation (`war/profiles/standards.rs`)
- `CreativeRightsCompliance` struct with:
  - `human_authored`: whether EAR appraisal affirms human authorship
  - `gai_source_disclosed`: whether AI tools are disclosed per WGA MBA Section 72
  - `wga_mba_compliant`: composite compliance check
  - `digital_source_type`: IPTC URI for cross-standard compatibility

### WGA MBA alignment
- "AI is not a writer": CPoE's behavioral attestation proves human authorship process
- Company disclosure obligation: CPoE's declaration records AI tool usage
- Writer consent: Declaration is author-signed, proving informed consent

### SAG-AFTRA alignment
- Content provenance chain distinguishes human-performed vs AI-generated
- Signing identity ties attestation to specific author

## 12. WebAuthn/FIDO2

### Status: Not applicable
WebAuthn proves **user presence** (button press, biometric) for authentication.
CPoE proves **authorship process** (keystrokes, timing, behavior) for content creation.
These are complementary but different concerns.

**Future opportunity**: WebAuthn assertions could supplement CPoE evidence as
additional human-presence proofs during authoring sessions.

## 13. IEEE P3119

### Status: Not applicable
IEEE P3119-2025 is a **procurement process standard** for acquiring AI systems.
It has no metadata fields or technical data structures to implement.
CPoE can reference P3119 compliance in procurement responses.

## 14. NCCoE AI Agent Identity

### Alignment
- CPoE uses DIDs for human author identity (NCCoE recommends distinguishing human/AI)
- CPoE's declaration includes `ai_tools` disclosure (distinguishes AI involvement)
- Key hierarchy with delegation supports the NCCoE's "delegation chain" model

### Gap: No explicit `author_type: human | ai_agent` field in evidence packet
(implicit via behavioral attestation -- EAR verdict distinguishes human from synthetic)

## 15. EU AI Act Article 50

### Status: Implemented
Article 50 of the EU AI Act (effective August 2026) requires providers of AI
systems that generate synthetic content to ensure outputs are marked in a
machine-readable format and are detectable as artificially generated.

### Implementation
- `AiDisclosureLevel` enum maps directly to Article 50 disclosure categories
- Declaration's `AiExtent` field records the degree of AI involvement
- HTML meta tag `<meta name="ai-disclosure">` satisfies machine-readable requirement
  (per W3C AI Content Disclosure CG, section 9)
- IPTC Digital Source Type URIs provide interoperable content labeling
- IETF `AI-Disclosure` header provides HTTP-layer compliance (section 10, planned)
- Code path: `war/profiles/standards.rs`

### Cross-standard compliance chain
Article 50 does not mandate a specific technical mechanism. CPoE satisfies it
through multiple complementary layers:
1. **In-document**: W3C `ai-disclosure` meta tag and element attributes
2. **In-transport**: IETF `AI-Disclosure` HTTP header (planned)
3. **In-provenance**: C2PA assertion with IPTC `digitalSourceType`
4. **In-credential**: VC credential subject with `ai_disclosure` claim
5. **In-evidence**: CPoE declaration's `AiExtent` + `ai_tools` array

### Spec reference
Regulation (EU) 2024/1689, Article 50 (Transparency obligations for certain AI systems)

## 16. CAWG Identity Assertion v1.2

### Status: Partial
The C2PA-Affiliated Working Group (CAWG) Identity Assertion specification
defines how to bind a verified identity to a C2PA manifest.

### Implementation
- Author DID (did:key, did:web) in evidence packets and VC credential subject
- Ed25519 key hierarchy provides cryptographic identity binding
- Session certificates link authoring sessions to master identity
- Code path: `identity/`, `keyhierarchy/`

### Gap
- No X.509 certificate with identity claims (CAWG requires X.509 or VC)
- No explicit CAWG `identity_assertion` JUMBF box generation

### Spec reference
CAWG Identity Assertion, version 1.2 (2025)

## 17. CAWG Training and Data Mining v1.1

### Status: Partial
Defines how content creators can express preferences about AI training and
data mining use of their content.

### Implementation
- Declaration includes `ai_tools` array disclosing AI involvement in creation
- `AiExtent` communicates the degree of AI contribution
- C2PA action entries carry `digitalSourceType` distinguishing human vs AI content
- Code path: `declaration/types.rs`, `war/profiles/c2pa.rs`

### Gap
- No explicit `c2pa.training-mining` assertion with `do_not_train` / `constraint_info`

### Spec reference
CAWG Training and Data Mining Assertion, version 1.1 (2025)

## 18. W3C VC COSE Securing

### Status: Implemented
The W3C "Securing Verifiable Credentials using JOSE and COSE" Recommendation
defines how to wrap a VC payload in a COSE_Sign1 structure.

### Implementation (`war/profiles/vc.rs`)
- `to_cose_secured_vc()` serializes the VC as CBOR and wraps in COSE_Sign1
- EdDSA (Ed25519) signing via ed25519-dalek
- Content type set to `application/vc` in COSE protected headers
- Data Integrity proof (`eddsa-rdfc-2022`) also supported as alternative

### Spec reference
W3C Recommendation, "Securing Verifiable Credentials using JOSE and COSE" (May 2025)

## 19. IETF SCITT

### Status: Partial
Supply Chain Integrity, Transparency, and Trust (SCITT) defines append-only
transparency logs for supply chain claims.

### Implementation
- WritersProof beacon anchoring submits evidence hashes to a transparency log
- Beacon attestation includes counter-signatures from the log operator
- Checkpoint chain provides an append-only evidence trail
- Code path: `writersproof/`, `anchors/`, `ffi/beacon.rs`

### Gap
- Not a full SCITT Reference Architecture (no Receipt / COSE_Sign1 countersign per draft-ietf-scitt-architecture)
- Transparency log is WritersProof-operated, not a generic SCITT ledger

### Spec reference
draft-ietf-scitt-architecture (IETF SCITT WG)

## 20. ToIP EGF (Trust over IP Ecosystem Governance Framework)

### Status: Planned
ToIP's Ecosystem Governance Framework defines governance metadata for trust
ecosystems including credential schemas, trust registries, and policies.

### Alignment
- CPoE's trust policy module (`trust_policy/`) evaluates evidence against
  configurable policy profiles, which could map to ToIP governance rules
- Key hierarchy and session certificates align with ToIP's credential lifecycle

### Spec reference
Trust over IP Foundation, Ecosystem Governance Framework Specification v1.0

## 21. TRQP (Trust Registry Query Protocol)

### Status: Planned
TRQP defines how verifiers query trust registries to determine whether an
issuer or holder is authorized within a governance framework.

### Alignment
- WritersProof API could expose a TRQP-compatible endpoint for querying
  authorized CPoE attestation issuers
- DID-based identity aligns with TRQP's identifier model

### Spec reference
Trust over IP Foundation, Trust Registry Query Protocol v2.0

## 22. OpenID4VC (OID4VCI)

### Status: Implemented
OpenID for Verifiable Credential Issuance defines how a credential issuer
advertises supported credential types and issues credentials to wallets.

### Implementation (`identity/openid4vc.rs`)
- `CredentialIssuerMetadata` describes WritersProof as an OID4VCI issuer
- Supports `vc+sd-jwt` and `vc+cose` credential formats
- Credential type: `ProcessAttestationCredential`
- Claims: author_did, process_verdict, attestation_tier, evidence_ref,
  chain_duration_secs, ai_disclosure

### Spec reference
OpenID for Verifiable Credential Issuance (OID4VCI), draft 13

## 23. DIF Well Known DID Configuration

### Status: Implemented
Links a web domain to DIDs it controls via a `.well-known/did-configuration.json`
resource containing domain linkage credentials.

### Implementation (`identity/did_configuration.rs`)
- Generates domain linkage credentials binding `writerslogic.com` to issuer DIDs
- Supports `did:web` and `did:key` methods

### Spec reference
DIF Well Known DID Configuration, v0.2.0

## 24. ORCID

### Status: Implemented
ORCID provides persistent digital identifiers for researchers and authors.

### Implementation (`identity/orcid.rs`)
- Binds an ORCID iD to a CPoE author identity
- ORCID can be included in evidence packets and VC credential subjects
- Validates ORCID format (0000-0000-0000-000X)

### Spec reference
ORCID API v3.0, ISO 27729 (ISNI)

## 25. JPEG Trust (ISO/IEC 21617)

### Status: Implemented
JPEG Trust defines Trust Profiles and Trust Reports for assessing media
trustworthiness. A Trust Report aggregates trust indicators from multiple sources.

### Implementation (`war/profiles/jpeg_trust.rs`)
- `JpegTrustProfile` maps CPoE attestation to a JPEG Trust profile
- Three trust indicators: process_evidence, identity_binding, temporal_proof
- Confidence levels derived from attestation strength
- Profile ID: `cpoe-attestation-v1`

### Spec reference
ISO/IEC 21617 (JPEG Trust), Parts 1-4

## 26. DIF Presentation Exchange

### Status: Implemented
Defines how verifiers describe proof requirements and how holders submit
matching verifiable presentations.

### Implementation (`identity/presentation_exchange.rs`)
- Presentation definition for `ProcessAttestationCredential`
- Input descriptors for required claims (author_did, process_verdict)
- Supports JSON Path constraint syntax

### Spec reference
DIF Presentation Exchange, v2.1.1

## 27. CoRIM (Concise Reference Integrity Manifest)

### Status: Partial
CoRIM defines a CBOR-based format for reference values used in RATS
attestation verification.

### Alignment
- EAR token carries claims compatible with CoRIM reference value structure
- AR4SI trust vector components map to CoRIM measurement categories
- CBOR wire format shared between CPoE evidence and CoRIM manifests

### Gap
- No explicit CoRIM manifest generation or parsing
- Reference values are embedded in trust policy, not in CoRIM format

### Spec reference
draft-ietf-rats-corim (IETF RATS WG)

---

## Code References

| Module | File | Purpose |
|--------|------|---------|
| EAR Token | `war/ear.rs` | IETF RATS EAR implementation |
| AR4SI Appraisal | `war/appraisal.rs` | Trust vector computation |
| C2PA Profile | `war/profiles/c2pa.rs` | C2PA assertion projection |
| VC Profile | `war/profiles/vc.rs` | W3C VC 2.0 + COSE securing |
| JPEG Trust | `war/profiles/jpeg_trust.rs` | ISO 21617 trust profile |
| EU AI Act | `war/profiles/eu_ai_act.rs` | Article 50 compliance |
| CAWG | `war/profiles/cawg.rs` | Identity/Training assertions |
| Content Fingerprint | `sentinel/content_fingerprint.rs` | C2PA soft binding (SimHash) |
| Standards Map | `war/profiles/standards.rs` | Multi-standard compliance |
| OpenID4VC | `identity/openid4vc.rs` | OID4VCI issuer metadata |
| DID Configuration | `identity/did_configuration.rs` | DIF Well Known DID |
| ORCID | `identity/orcid.rs` | ORCID author binding |
| Presentation Exchange | `identity/presentation_exchange.rs` | DIF PE definitions |
| DID Identity | `cmd_identity.rs` | DID generation |
| Declaration | `declaration/types.rs` | AI disclosure (AiExtent, AiToolUsage) |
| Steganography | `steganography/` | ZWC watermarking (NIST AI 100-4) |
| Anchoring | `anchors/` | RFC 3161, OTS, blockchain timestamps |
