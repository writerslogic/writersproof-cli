# Evidence Packet Format Specification

**Version:** 1.2.0
**Status:** Draft
**Last Updated:** 2026-05-27
**Standard:** draft-condrey-rats-pop

## Overview

A CPoE **Evidence Packet** (`.c2pa`) is a self-contained, portable proof of documented authorship. It bundles cryptographic proofs, process declarations, and sequential attestations into a single format compliant with the IETF RATS (Remote ATtestation ProcedureS) framework and the **Proof-of-Process (PoP)** protocol.

This specification aligns with the CDDL schema defined in `draft-condrey-rats-pop`.

## Design Goals

### Binary & JSON Interoperability

While the primary wire format is CBOR (RFC 8949) for compactness and hardware compatibility, a standard JSON mapping is defined for ease of use in web and documentation contexts. This specification uses JSON keys that map directly to the integer keys defined in the CDDL.

### Verification Tiers

The format supports tiered evidence per the `content-tier` specification:
- **Core (1):** Checkpoint chain + SWF (Sequential Work Function) proofs.
- **Enhanced (2):** Adds Jitter Binding (behavioral entropy) and Hardware Attestation.
- **Maximum (3):** Adds full Behavioral analysis, Physical State markers, and Active Probes.

## Packet Structure (EvidencePacket)

| JSON Key | CDDL Key | Type | Description |
|:---------|:---------|:-----|:------------|
| `version` | 1 | uint | Protocol version (MUST be 1) |
| `profile_uri` | 2 | uri | PoP profile URI (`urn:ietf:params:rats:eat:profile:pop:1.0`) |
| `packet_id` | 3 | uuid | Unique identifier (16 bytes, min 4 nonzero) |
| `created_at` | 4 | timestamp | Packet generation time (epoch ms, UTC) |
| `document` | 5 | object | Reference to the witnessed document ([DocumentRef](#documentref)) |
| `checkpoints` | 6 | array | Ordered chain of document states (min 3, max 10000) |
| `attestation_tier` | 7 | enum | Device assurance level (T1-T4) |
| `limitations` | 8 | strings | Disclosures about the environment or collection process |
| `profile` | 9 | object | Profile-specific metadata and feature flags |
| `presence_challenges` | 10 | array | Presence verification challenge-responses |
| `channel_binding` | 11 | object | IPC channel binding proof |
| `signing_public_key` | 12 | bytes | Ed25519 public key (32 bytes) |
| `content_tier` | 13 | enum | Evidence depth (1=Core, 2=Enhanced, 3=Maximum) |
| `previous_packet_ref` | 14 | HashValue | Hash of previous packet in a multi-packet chain |
| `packet_sequence` | 15 | uint | 1-based sequence in multi-packet chains |
| `physical_liveness` | 18 | object | Thermal and entropy markers for liveness |
| `baseline_verification` | 19 | object | Baseline verification data |
| `author_did` | 20 | string | did:webvh Decentralized Identifier (optional) |
| `document_content` | 21 | bytes | Embedded document content (optional, max 100MB) |
| `document_filename` | 22 | string | Original filename for content extraction |
| `project_files` | 23 | array | Multi-file project references (max 1000) |
| `session_counter` | 24 | uint | Monotonic hardware counter |
| `forensic_summary` | 25 | object | Session-level forensic metrics summary |

### DocumentRef

Contains metadata about the final document state.

| Field | CDDL Key | Description |
|:------|:---------|:------------|
| `content_hash` | 1 | [HashValue](#hashvalue) of the final document |
| `filename` | 2 | Original name of the document |
| `byte_length` | 3 | Size of document in bytes |
| `char_count` | 4 | Character count (logical size) |

### Checkpoint

An atomic record of a document's state at a specific point in time.

| Field | CDDL Key | Description |
|:------|:---------|:------------|
| `sequence` | 1 | Monotonic sequence number |
| `checkpoint_id` | 2 | UUID for this checkpoint |
| `timestamp` | 3 | Local wall-clock time |
| `content_hash` | 4 | [HashValue](#hashvalue) of document state |
| `char_count` | 5 | Character count at this state |
| `edit_delta` | 6 | [EditDelta](#editdelta) since last checkpoint |
| `prev_hash` | 7 | [HashValue](#hashvalue) of previous checkpoint |
| `checkpoint_hash` | 8 | The binding hash for this entire checkpoint |
| `process_proof` | 9 | [SWFProof](#swfproof) (Sequential Work Function) |
| `jitter_binding` | 10 | Timing entropy and [JitterSample](#jittersample) |
| `forensic_score` | 12 | Composite authorship score (0.0 - 1.0) |
| `is_paste` | 14 | Boolean flag for suspected paste detection |
| `physical_state` | 11 | Thermal and kernel markers (Enhanced+) |

## Cryptographic Primitives

### HashValue

A tagged hash structure supporting algorithm agility.

| Field | CDDL Key | Value |
|:------|:---------|:------|
| `algorithm` | 1 | 1=SHA256, 2=SHA384, 3=SHA512 |
| `digest` | 2 | The raw binary or hex-encoded digest |

### JitterSample

An atomic record of high-precision timing entropy.

| Field | CDDL Key | Description |
|:------|:---------|:------------|
| `ordinal` | 1 | Sample sequence number |
| `timestamp` | 2 | Capture time (UTC) |
| `doc_hash` | 3 | Current document hash binding |
| `zone_transition` | 4 | Keycode region transition marker |
| `interval_bucket` | 5 | Timing interval classification |
| `jitter_micros` | 6 | Injected or measured jitter (μs) |
| `clock_skew` | 7 | CPU TSC vs Wall Clock drift (cycles) |
| `sample_hash` | 8 | HMAC binding for the sample |

### SWFProof (Sequential Work Function)

Proves that a minimum amount of non-parallelizable work occurred.

| Field | CDDL Key | Description |
|:------|:---------|:------------|
| `algorithm` | 1 | 20=Argon2id, 21=Argon2id-Entangled |
| `params` | 2 | Cost factors (t, m, p, iterations) |
| `input` | 3 | Seed for the work function |
| `merkle_root` | 4 | Root of the work step Merkle tree |
| `proofs` | 5 | Sampled proofs from the tree |
| `duration_ms` | 6 | Claimed duration in milliseconds |

### EditDelta

Forensic metrics describing the magnitude and location of changes.

| Field | CDDL Key | Description |
|:------|:---------|:------------|
| `chars_added` | 1 | Count of inserted characters |
| `chars_deleted` | 2 | Count of removed characters |
| `op_count` | 3 | Number of discrete edit operations |
| `positions` | 4 | Array of [offset, change] pairs |

## Verification Procedure

1. **Chain Integrity:** Verify that every `prev_hash` matches the `checkpoint_hash` of the preceding entry.
2. **SWF Verification:** Recompute or verify Merkle samples for every `process_proof` to confirm the claimed `duration_ms`.
3. **Identity Binding:** Verify the signature on the terminal checkpoint or declaration packet using the author's public key.
4. **Causality Check:** (WAR/1.1) Verify that the `input` of each VDF is correctly entangled with the content and jitter of previous states.

## Domain & Schemas

The official JSON schemas are hosted at:
- `https://protocol.writerslogic.com/schemas/evidence-v1.json`
- `https://protocol.writerslogic.com/schemas/declaration-v1.json`

## References

- RFC 8949: CBOR
- RFC 9052: COSE
- draft-condrey-rats-pop: IETF Internet-Draft
