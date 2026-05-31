# Technical Specifications Index

CPoE is built on several core cryptographic and architectural protocols. These documents detail the low-level implementation of the Proof-of-Process (PoP) system.

## Data Formats

- **[[Evidence Format]]**: The structure of the `.c2pa` evidence packets, including the CDDL schema and serialization rules.
- **[[Process Declaration]]**: Details on how creative intent is declared and signed before work begins.
- **[[WAR Block Format]]**: Write-Ahead Recovery blocks for ensuring data integrity during crashes.

## Protocol Mechanics

- **[[Ratchet Key Hierarchy]]**: Our forward-secure key management system using Ed25519 and HKDF.
- **[[Architectural Hardening]]**: Tier 4 protection mechanisms including memory locking, anti-debugging, and machine-state entanglement.
- **[[Behavioral Metrics]]**: Implementation of keystroke dynamics, nanosecond jitter capture, and behavioral attestation.
- **[[Persistence & Fault Tolerance]]**: How CPoE manages its local event database and recovery mechanisms.

## Schemas (JSON)

- [evidence-v1.json](https://github.com/writerslogic/cpoe/blob/main/docs/schemas/evidence-v1.json)
- [declaration-v1.json](https://github.com/writerslogic/cpoe/blob/main/docs/schemas/declaration-v1.json)
- [war-block-v1.json](https://github.com/writerslogic/cpoe/blob/main/docs/schemas/war-block-v1.json)

---

*For usage information, see the **[[Home]]** page.*
