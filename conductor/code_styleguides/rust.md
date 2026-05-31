# Rust Style Guide

Project-specific Rust conventions for the CPoE workspace (`crates/cpoe`, `crates/cpoe-jitter`, `crates/authorproof-protocol`, `crates/posme`, `apps/cpoe_cli`).

## 1. Formatting

- **Edition:** 2021
- **Max line width:** 100 characters (enforced by `rustfmt.toml`)
- **Indentation:** 4 spaces (see `.editorconfig`)
- **Line endings:** LF (Unix-style)
- **Trailing whitespace:** Trimmed
- **Heuristics:** Small (rustfmt default)

Run `cargo fmt --all -- --check` before committing.

## 2. License Headers

Every `.rs` file must begin with an SPDX identifier on line 1:

- **cpoe (engine):** `// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial`
- **cpoe-jitter, authorproof-protocol:** `// SPDX-License-Identifier: Apache-2.0`
- **cpoe_cli:** `// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial`

## 3. Module Organization

Use **directory-based submodules** with `mod.rs` re-exports:

```rust
// mod.rs
pub mod types;
pub mod builder;
mod internal;

pub use types::{EvidencePacket, EvidenceField};
pub use builder::EvidenceBuilder;

#[cfg(test)]
mod tests;
```

- Platform-specific `#[cfg]` gates go in `mod.rs`, not in submodule files.
- Factory functions in `platform/mod.rs` select implementations per platform.
- `lib.rs` re-exports the public API (~60+ types).

## 4. Import Ordering

Group imports top-to-bottom, separated by blank lines:

```rust
// 1. Standard library
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

// 2. External crates (alphabetical within group)
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

// 3. Workspace crates
use authorproof_protocol::EvidencePacketWire;

// 4. Internal crate imports
use crate::error::{Error, Result};
use crate::DateTimeNanosExt;

// 5. Relative module imports
use super::crypto::SomeType;
```

## 5. Error Handling

Use `thiserror` for all error types. Define a `Result<T>` alias per module:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ForensicsError {
    #[error("insufficient samples: need {need}, got {got}")]
    InsufficientSamples { need: usize, got: usize },

    #[error("analysis failed")]
    Analysis(#[from] AnalysisError),
}

pub type Result<T> = std::result::Result<T, ForensicsError>;
```

The master `Error` enum in `crates/cpoe/src/error.rs` wraps subsystem errors via `#[from]`. Use constructor helpers: `Error::checkpoint("msg")`, `Error::crypto("msg")`.

No `.unwrap()` in production code. Use `?` propagation or explicit error handling.

## 6. Naming

| Item | Convention | Example |
|------|-----------|---------|
| Types, traits, enums | PascalCase | `EvidencePacket`, `KeystrokeCapture` |
| Functions, methods | snake_case | `compute_assessment_score` |
| Constants | UPPER_SNAKE_CASE | `MAX_MESSAGE_SIZE`, `SWF_DURATION_MIN` |
| Modules | snake_case | `keyhierarchy`, `cross_modal` |
| Feature flags | snake_case | `cpoe_jitter`, `did-webvh` |
| Type parameters | Single uppercase or PascalCase | `T`, `E` |

## 7. Dead Code & Clippy

- Use targeted `#[allow(dead_code)]` on specific items only. Never blanket `#![allow(dead_code)]` at file level.
- Acceptable allows: `clippy::too_many_arguments` (when unavoidable), `clippy::type_complexity` (for FFI types).
- No `#[allow(clippy::all)]` or crate-level suppression.
- Maintain zero clippy warnings: `cargo clippy --workspace -- -D warnings`.

## 8. Testing

Inline test modules in the same file or a sibling `tests.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_digest_has_zero_sessions() {
        let digest = SessionDigest::default();
        assert_eq!(digest.session_count, 0);
    }
}
```

- Test naming: `test_subject_behavior` or `subject_behavior` (the `#[test]` attribute makes intent clear).
- Use `#[cfg(test)]` modules, not a separate `tests/` directory (except integration tests).
- `test-utils` feature flag exposes internal helpers for integration tests.

## 9. Cryptography & Security

- **Zeroize all key material** after use (`zeroize` crate with `Drop` impl or `Zeroizing<T>` wrapper).
- Use constant-time operations for secret data (`subtle::ConstantTimeEq`).
- No secrets in logs, errors, or debug output.
- Use `OsRng` for cryptographic randomness, never `thread_rng`.
- Document `unsafe` blocks with `// SAFETY:` comments explaining invariants.

```rust
// SAFETY: ptrace(PT_DENY_ATTACH=31) is a well-defined macOS syscall.
// All arguments are constants; no memory is accessed.
unsafe {
    libc::ptrace(31, 0, std::ptr::null_mut(), 0);
}
```

## 10. Feature Flags

```toml
[features]
default = ["cpoe_jitter"]
cpoe_jitter = ["dep:cpoe-jitter"]    # Hardware entropy
x11 = ["x11rb"]                       # Linux X11 focus detection
wayland = ["dep:wayland-client"]       # Linux Wayland
ffi = ["dep:uniffi", "uniffi/cli"]     # Swift/Kotlin bindings
posme = ["dep:posme"]                  # Proof of Sequential Memory-bound Effort
did-webvh = ["dep:didwebvh-rs"]        # Decentralized identity
```

- Lowercase with underscores (or hyphens for spec names).
- Group by purpose: platform, FFI, experimental.
- Gate platform-specific code with `#[cfg(feature = "...")]` or `#[cfg(target_os = "...")]`.

## 11. Documentation

```rust
//! Module-level documentation explaining purpose.

/// Short one-liner for simple items.
pub fn simple() {}

/// Multi-line doc with sections.
///
/// # Panics
/// When the signing key is not initialized.
///
/// # Examples
/// ```rust
/// let packet = EvidenceBuilder::new().build()?;
/// ```
pub fn complex() {}
```

- All public items must have doc comments.
- Module-level `//!` docs explain the module's role.
- Use `# Panics`, `# Errors`, `# Examples` sections where applicable.

## 12. Concurrency

- Tokio async runtime for IPC and network operations.
- `std::sync::mpsc` channels for platform event capture to sentinel bridge.
- `Arc<RwLock<>>` for shared state; `DashMap` for concurrent collections.
- Document lock ordering to prevent deadlocks.
- No `std` blocking calls in async contexts (use `tokio::fs`, `tokio::time::sleep`).

## 13. Serialization

| Format | Crate | Use |
|--------|-------|-----|
| CBOR | ciborium | Wire format (evidence packets, attestations) |
| COSE | coset | Signatures (RFC 8152) |
| JSON | serde_json | API responses, config |
| TOML | toml | Configuration files |
| Bincode | bincode | Internal storage |
| SQLite | rusqlite (bundled) | Secure event storage |

## 14. Workspace Dependencies

Pin versions centrally in the workspace `Cargo.toml` via `[workspace.dependencies]`. Individual crates reference via `workspace = true`:

```toml
# In workspace Cargo.toml
[workspace.dependencies]
serde = { version = "1.0", features = ["derive"] }

# In crate Cargo.toml
[dependencies]
serde = { workspace = true }
```

## 15. Release Profile

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
strip = true
overflow-checks = true
```

Overflow checks are enabled even in release builds for security.

## 16. Domain Separation

- Internal DSTs use `witnessd-` prefix: `witnessd-checkpoint-v3`, `witnessd-event-v2`.
- Spec DSTs (wire format) use `PoP-` prefix: `PoP-SWF-Seed-v1`, `PoP-Checkpoint-v1`.
- Never rename existing DST strings; they are baked into signed evidence.

## 17. IPC Constants

Reference constants from their canonical module. Never hardcode magic values:

```rust
// Good
use super::messages::MAX_MESSAGE_SIZE;

// Bad
const MAX_SIZE: usize = 1024 * 1024;
```
