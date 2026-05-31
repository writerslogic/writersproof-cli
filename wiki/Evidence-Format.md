# Evidence Packet Format Specification

**Version:** 1.1.0  
**Format:** `.c2pa` (CBOR/JSON)

## Overview

A CPoE **Evidence Packet** (`.c2pa`) is a self-contained, portable proof of documented authorship. It bundles cryptographic proofs, process declarations, and sequential attestations into a single format compliant with the [[Glossary#RATS|IETF RATS (Remote ATtestation ProcedureS)]] framework and the **[[Glossary#PoP|Proof-of-Process (PoP)]]** protocol.

## Design Goals

### Binary & JSON Interoperability
While the primary wire format is CBOR (RFC 8949) for compactness and hardware compatibility, a standard JSON mapping is defined for ease of use in web and documentation contexts.

### Verification Tiers
The format supports tiered evidence:
- **Tier 1 (Core):** Checkpoint chain + SWF (Sequential Work Function) proofs.
- **Tier 2 (Enhanced):** Adds Jitter Binding (behavioral entropy) and Hardware Attestation.
- **Tier 3 (Maximum):** Adds full Behavioral analysis, Physical State markers, and Active Probes.

---

## Packet Structure

| Key | Type | Description |
|:----|:-----|:------------|
| `version` | uint | Protocol version (current: 1) |
| `packet_id` | uuid | Unique identifier for this evidence packet |
| `created_at` | timestamp | Packet generation time (UTC) |
| `document` | object | Metadata about the final document (name, size, hash) |
| `checkpoints` | array | Ordered chain of document states ([[Checkpoint]]) |
| `content_tier` | enum | Evidence depth (1, 2, or 3) |

---

## Checkpoint Structure

An atomic record of a document's state at a specific point in time.

| Field | Description |
|:------|:------------|
| `sequence` | Monotonic sequence number |
| `timestamp` | Local wall-clock time |
| `content_hash` | SHA-256 hash of document state |
| `edit_delta` | Count of chars added/deleted since last checkpoint |
| `prev_hash` | Hash of the previous checkpoint (chaining) |
| `process_proof` | **[[Glossary#VDF|SWFProof]]** (Verifiable Delay/Work Function proof) |
| `jitter_binding` | Timing entropy and [JitterSample](#jittersample) (Tier 2+) |
| `forensic_score` | Composite authorship score (0.0 - 1.0) |
| `is_paste` | Boolean flag for suspected paste detection |

## Cryptographic Primitives

### JitterSample

An atomic record of high-precision timing entropy.

| Field | Description |
|:------|:------------|
| `ordinal` | Sample sequence number |
| `timestamp` | Capture time (UTC) |
| `doc_hash` | Current document hash binding |
| `zone_transition` | Keycode region transition marker |
| `interval_bucket` | Timing interval classification |
| `jitter_micros` | Injected or measured jitter (μs) |
| `clock_skew` | CPU TSC vs Wall Clock drift (cycles) |
| `sample_hash` | HMAC binding for the sample |

---

## Verification Procedure

1. **Chain Integrity:** Verify that every `prev_hash` matches the hash of the preceding entry.
2. **SWF Verification:** Verify the Verifiable Delay Function proofs to confirm the claimed time duration.
3. **Identity Binding:** Verify signatures against the author's public key.
4. **Causality Check:** Ensure that the input of each proof is correctly entangled with previous states.

---

*For more technical details, see the **[[Ratchet Key Hierarchy]]**.*
