# Technical Specifications

Formal specifications for the **Proof-of-Process (PoP)** protocol suite (`draft-condrey-rats-pop`).

## Documents

- **[Evidence Format](evidence-format.md)** — Packet structure, CBOR wire format, and verification tiers.
- **[Process Declaration](process-declaration.md)** — Signed author attestation with AI disclosure.
- **[Ratchet Key Hierarchy](ratchet-key-hierarchy.md)** — Three-tier key derivation and forward secrecy.
- **[Architectural Hardening](architectural-hardening.md)** — Tier 4 protections (mlock, anti-debug, Labyrinth).
- **[Behavioral Metrics](behavioral-metrics.md)** — Forensic analysis, transcription detection, cross-modal checks.
- **[Persistence & Fault Tolerance](persistence-fault-tolerance.md)** — WAL, MMR, and crash recovery.

## Status

All specifications are in **Draft** status, tracking `draft-condrey-rats-pop`.

## Wire Format

- CBOR Tag: `1129336656` (0x43504F50 = "CPOP")
- Media type: `application/c2pa`
- File extension: `.c2pa`
- Profile URI: `urn:ietf:params:rats:eat:profile:pop:1.0`
