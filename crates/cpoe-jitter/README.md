[//]: # (SPDX-License-Identifier: Apache-2.0)

<div align="center">

<img alt="cpoe-jitter" src="https://raw.githubusercontent.com/LF-Decentralized-Trust-labs/proof-of-effort/main/assets/branding/production/dark/png/cpoe-jitter.png" width="360">

### Timing entropy primitive for human process attestation

[![crates.io](https://img.shields.io/crates/v/cpoe-jitter.svg?style=for-the-badge)](https://crates.io/crates/cpoe-jitter)
[![downloads](https://img.shields.io/crates/d/cpoe-jitter?style=for-the-badge)](https://crates.io/crates/cpoe-jitter)
[![docs.rs](https://img.shields.io/docsrs/cpoe-jitter?style=for-the-badge)](https://docs.rs/cpoe-jitter)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](https://github.com/LF-Decentralized-Trust-labs/proof-of-effort/blob/main/LICENSE)

Part of the [Cryptographic Proof of Effort (CPoE)](https://github.com/LF-Decentralized-Trust-labs/proof-of-effort/blob/main/README.md) specification — an [LF Decentralized Trust](https://www.lfdecentralizedtrust.org/) Lab

</div>

---

## Overview

`cpoe-jitter` provides cryptographic proof-of-effort through timing jitter,
producing tamper-evident evidence that content was created through a human
typing process rather than generated or pasted. Two engines are available:

- **PureJitter** — HMAC-based, deterministic, `no_std` compatible. Uses
  externally-provided timestamps for environments without OS timing.
- **PhysJitter** — Hardware entropy collection via CPU timing (TSC).
  Requires `std` for OS timing primitives.
- **HybridEngine** — Automatic fallback from PhysJitter to PureJitter.

## Quick Start

```toml
[dependencies]
cpoe-jitter = "0.2"
```

```rust
use cpoe_jitter::{HybridEngine, JitterEngine, Session};

let engine = HybridEngine::new(b"my-secret-key");
let mut session = Session::new(engine);

session.record_keystroke(b'H', None);
session.record_keystroke(b'i', None);

let evidence = session.finalize();
assert!(evidence.verify().is_ok());
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | Yes | Standard library — enables Session, timing, serde_json |
| `hardware` | No | Hardware entropy collection (TSC) |
| `rand` | No | Random secret generation |

For `no_std` environments, use `PureJitter` with explicit timestamps:

```toml
[dependencies]
cpoe-jitter = { version = "0.2", default-features = false }
```

## Architecture

```
PureJitter (HMAC-SHA256, deterministic)
    ↓ fallback
PhysJitter (hardware TSC entropy)
    ↓ combined
HybridEngine → Session → Evidence
```

Each keystroke is bound to a timing jitter measurement. The evidence chain
is HMAC-linked, making insertion, deletion, or reordering of events
cryptographically detectable.

## Contributing

See [CONTRIBUTING.md](https://github.com/LF-Decentralized-Trust-labs/proof-of-effort/blob/main/CONTRIBUTING.md) for DCO sign-off requirements and contribution workflow.

## License

Apache License, Version 2.0. See [LICENSE](https://github.com/LF-Decentralized-Trust-labs/proof-of-effort/blob/main/LICENSE).

Part of the [proof-of-effort](https://github.com/LF-Decentralized-Trust-labs/proof-of-effort) repository.
