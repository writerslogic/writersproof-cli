# Architectural Hardening Specification (Tier 4)

**Version:** 1.0.0
**Status:** Implementation Complete
**Last Updated:** 2026-02-23

## Overview

This specification defines the high-integrity hardening measures implemented in `cpoe` to protect cryptographic material and evidence capture logic against a **white-box adversary** (a local user with root privileges and debugging tools).

## 1. Adversarial Memory Guarding

The engine utilizes tiered memory protection to ensure that sensitive cryptographic secrets (T0-T2 keys) are never exposed to persistent storage or unauthorized process memory access.

### 1.1 Physical RAM Locking (mlock)

To prevent the operating system from swapping sensitive keys to disk (where they could be recovered via forensic analysis of the swap file), `cpoe` utilizes the `mlock` system call.

- **Mechanism:** The `ProtectedKey<N>` wrapper (see `crates/cpoe/src/crypto/mem.rs`) calls `libc::mlock` on its internal buffer during initialization.
- **Scope:** Applied to all `RatchetState` keys, HMAC keys, and master seeds.
- **Cleanup:** Memory is unlocked using `libc::munlock` and immediately overwritten with zeros via the `Zeroize` trait upon `Drop`.

### 1.2 Automated Zeroization

All sensitive data structures implement the `Zeroize` and `ZeroizeOnDrop` traits. This ensures that even if a memory lock fails, the duration of the secret's residency in RAM is minimized to the absolute necessary window of operation.

## 2. Anti-Analysis & Anti-Debugging

To prevent real-time manipulation of the forensic capture loop or the VDF computation, `cpoe` implements platform-specific anti-analysis measures.

### 2.1 macOS: PT_DENY_ATTACH

On macOS, the daemon invokes `ptrace(PT_DENY_ATTACH, 0, 0, 0)` during the `Engine::start` sequence.

- **Effect:** If a debugger (like `lldb`) attempts to attach to the running process, the process will immediately terminate.
- **Adversarial Cost:** This forces an attacker to use significantly more complex kernel-level instrumentation to bypass the protection, raising the "cost of forgery" to exceed the value of the document.

### 2.2 Debugger Presence Detection

The `is_debugger_present()` utility provides a cross-platform way for the engine to detect if it is being monitored.

- **Action on Detection:** If a debugger is detected during sensitive operations (like signing terminal checkpoints), the engine will downgrade the `TrustTier` of the resulting evidence to `Local` and add a limitation marker to the packet.

## 3. Machine-State Entanglement (The Labyrinth)

The "Labyrinth" ensures that the integrity of evidence for one document is cryptographically bound to the integrity of all other documents witnessed on the same machine.

### 3.1 Global Hash Chain

The `integrity` table in the local SQLite database maintains a single, monotonic hash-chain (`chain_hash`).

- **Formula:** $H_{global}(n) = 	ext{SHA256}(H_{global}(n-1) \| 	ext{Event}_n)$
- **Binding:** Every `SecureEvent` includes the current global `chain_hash` as its `previous_hash`.
- **Anti-Deletion Property:** A user cannot "selectively delete" events from a single document's history without invalidating the global `chain_hash`, making the tampering globally detectable during a machine-wide audit.

## 4. Hardware-Bound Entropy (Jitter Hardening)

To prevent software simulation of human keystroke timing, the "Jitter Seal" is bound to hardware-level physics.

### 4.1 Clock Skew Attestation

Every `JitterSample` now includes a `clock_skew` measurement.

- **Method:** Measures the drift between the CPU's Time Stamp Counter (TSC) and the system wall clock over a 100μs window.
- **Integrity:** The `clock_skew` is hashed into the `sample_hash`.
- **Defense:** An attacker simulating keystrokes in software would need to also simulate nanosecond-scale CPU cycle drift that matches the physical characteristics of the local processor, which is extremely difficult to do without introducing statistical anomalies.

## References

- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- Apple Developer Documentation: `ptrace(2)`
- POSIX.1-2017: `mlock(2)`
- draft-condrey-rats-pop: IETF Proof-of-Process Protocol
