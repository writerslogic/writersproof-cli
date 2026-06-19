# cpoe_protocol

**cpoe_protocol** is the core Rust implementation of the **[[Glossary#PoP|Proof-of-Process (PoP)]]** protocol wire format, currently being socialized in the **[[Glossary#RATS|IETF RATS]]** working group.

**License:** Apache-2.0
**Path:** [`crates/cpoe_protocol`](https://github.com/writerslogic/writersproof-cli/tree/main/crates/cpoe_protocol)

---

## Key Responsibilities

- **Wire Format**: [[Glossary#COSE|CBOR/COSE encoding]] of PoP packets following RFC 8949 and RFC 9052
- **Cryptographic Identity**: X.509 certificate-based identity with [[Glossary#Declaration|Proof-of-Possession]]
- **Forensic Models**: [[Behavioral Metrics|Process scoring]], behavioral analysis data structures
- **Signature Verification**: Ed25519 signature creation and verification
- **Cross-Platform**: Supports `no_std`, WASM, and native targets

## Architecture

```
cpoe_protocol/src/
├── crypto.rs        Cryptographic primitives and key management
├── forensics/       Forensic analysis models and scoring
│   └── mod.rs       ProcessScore, BehavioralScore, ForensicReport
├── identity.rs      X.509 identity, SealedIdentity, PoP verification
├── lib.rs           Public API and re-exports
└── tests/           Integration and unit tests
```

## Features

| Feature | Description |
|:--------|:------------|
| `default` (`std`) | Standard library support |
| `full` | `std` + JSON serialization |
| `apple-secure-enclave` | macOS Secure Enclave attestation |
| `wasm` | WebAssembly target support |

## IETF Alignment

The protocol implements types defined in [draft-condrey-rats-pop](https://github.com/writerslogic/draft-condrey-rats-pop):

- `EvidencePacketWire` - Top-level evidence container (CBOR tag 600)
- `AttestationResultWire` - Verification result (CBOR tag 601)
- `CheckpointWire` - Document state snapshot
- `ProcessProof` - VDF and jitter proof bundle
- `Verdict` - Pass/Fail/Inconclusive verification outcome

## Usage

```toml
[dependencies]
cpoe_protocol = { git = "https://github.com/writerslogic/writersproof-cli", branch = "main" }
```

## Dependencies

- **[[cpoe_jitter]]**: Hardware timing entropy for jitter seals

## Related Pages

- [[Evidence Format]] - Wire format specification
- [[Technical Specifications Index]] - All specifications
- [[Glossary]] - Key terms (PoP, RATS, COSE, etc.)
