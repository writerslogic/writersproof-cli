# WritersProof C2PA Conformance Submission

**Organization:** WritersLogic, Inc.
**Product:** WritersProof (macOS desktop app + browser extension)
**Contact:** David Condrey, david@writerslogic.com
**Date:** May 2026

## Product Description

WritersProof is a Proof-of-Process authorship witnessing system that generates C2PA-conformant manifests for text documents. It captures behavioral evidence (keystroke timing, revision patterns, editing topology) during the writing process and packages it into signed C2PA manifests.

## C2PA Implementation

- **Spec version:** C2PA 2.4
- **Role:** Claim Generator
- **Signature algorithm:** EdDSA (Ed25519) via COSE_Sign1
- **Certificate:** Self-signed X.509 v3 with Ed25519 public key in x5chain (label 33)
- **Hash algorithm:** SHA-256
- **Container format:** Reverse Sidecar (asset encapsulated inside .c2pa file, per writerslogic.com/protocol/reverse-sidecar-v1/)

## Why Reverse Sidecar?

C2PA's standard embedding targets image/video containers (JPEG, PNG, BMFF). Text documents (.txt, .md, .docx, .rtf, .fdx) have no standardized manifest embedding point. Our Reverse Sidecar Container wraps the original document inside the .c2pa file alongside the JUMBF manifest store, preserving the document hash binding while supporting arbitrary asset formats.

## Custom Assertions

| Label | Schema | Description |
|-------|--------|-------------|
| `com.writerslogic.process-proof` | [process-proof.schema.json](https://writerslogic.com/ns/v1/schemas/process-proof.schema.json) | Forensic verdict, assessment score, signal scores, composition mode |
| `com.writerslogic.keystroke-cadence` | [keystroke-cadence.schema.json](https://writerslogic.com/ns/v1/schemas/keystroke-cadence.schema.json) | IKI distribution, burst patterns, correction ratio, fatigue trajectory |
| `com.writerslogic.cognitive-markers` | [cognitive-markers.schema.json](https://writerslogic.com/ns/v1/schemas/cognitive-markers.schema.json) | Sentence initiation ratio, IKI modality, lexical retrieval delay |
| `com.writerslogic.evidence-chain` | [evidence-chain.schema.json](https://writerslogic.com/ns/v1/schemas/evidence-chain.schema.json) | Checkpoint chain summary with hash linkage |
| `com.writerslogic.verifiable-credential` | [verifiable-credential.schema.json](https://writerslogic.com/ns/v1/schemas/verifiable-credential.schema.json) | W3C VC 2.0 with EdDSA-JCS-2022 proof |

## Standard Assertions Used

- `c2pa.hash.data` — SHA-256 hash of the source document
- `c2pa.actions` — "c2pa.created" action with WritersProof as software agent
- `c2pa.metadata` — dc:format media type
- `c2pa.external-reference` — Link to full evidence packet on verify.writersproof.com

## Sample Files

| File | Description |
|------|-------------|
| `sample-essay.txt` | Source document (543 bytes) |
| `sample-essay.c2pa` | Reverse Sidecar Container (manifest + embedded document) |
| `sample-essay.jumbf` | Raw JUMBF manifest store (for inspection) |

## Verification

Evidence can be verified at: https://verify.writersproof.com

## Related Standards Work

- IETF Internet-Drafts: draft-condrey-rats-pop (Proof-of-Process)
- C2PA text extension: External Hashed Assertions for unstructured text
- IANA registrations: CBOR tags 0x43504F50, 0x43504F51, 0x43574152
- Patent pending: USPTO #19/460,364

## Trust Model

Currently using self-signed Ed25519 certificates. Planning migration to subordinate CA under an established trust anchor for C2PA trust list inclusion. The evidence chain's cryptographic integrity is independent of the trust model — the behavioral forensics are verifiable regardless of the signer's trust status.
