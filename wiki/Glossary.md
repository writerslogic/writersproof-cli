# Glossary

Key terms used throughout the CPoE documentation.

---

## A

### Anti-Analysis
Process-level security measures (e.g., `PT_DENY_ATTACH`) that detect or prevent the use of debuggers, decompilers, and instrumentation tools to inspect or modify a running program.

### Attestation
A cryptographic statement by a device or software component that a particular set of conditions holds. In CPoE, attestation binds process evidence to hardware trust anchors (e.g., TPM, Secure Enclave).

### Adversarial Collapse
The core security property of CPoE: any attempt to forge process evidence requires the adversary to expend effort comparable to actually performing the creative process. The cost of forgery *collapses* to near the cost of genuine authorship.

### Adversarial-Grade Process Hardening (Tier 4)
Advanced process-level security measures including physical RAM locking (`mlock`), anti-debugging (`PT_DENY_ATTACH`), and binary integrity self-checksums. Designed to thwart a root user with a debugger.

## B

### Behavioral Metrics
Statistical measurements of typing patterns (keystroke dynamics) used to distinguish human authorship from automated content generation. Includes inter-keystroke intervals (IKI), flight times, and entropy analysis.

## C

### Causality Lock
A cryptographic mechanism ensuring that evidence records are causally ordered -- each record depends on all previous records, making it impossible to insert, delete, or reorder entries without detection.

### Checkpoint
A snapshot of a document's state at a specific point in time, cryptographically bound to VDF proofs and the Merkle Mountain Range. Created via `writersproof-cli commit`.

### COSE (CBOR Object Signing and Encryption)
The encoding format used for CPoE evidence packets, as specified in RFC 9052. Provides compact, binary-safe serialization with built-in signature support.

## D

### Declaration
A cryptographic statement of creative intent that initiates a witnessing session. Includes the author's identity, the document being witnessed, and the declared process type.

### Dwell Time
The duration between a key press and its corresponding release. A secondary biometric marker in keystroke dynamics.

## E

### Ed25519
A modern, high-performance Edwards-curve digital signature algorithm (EdDSA) used by CPoE for all identity and checkpoint signatures. Specified in RFC 8032.

### Evidence Packet (`.c2pa`)
The serialized output of a CPoE session containing all process evidence: checkpoints, VDF proofs, behavioral metrics, and optional hardware attestations. Encoded as a C2PA manifest following the PoP wire format.

### Evidence Tier
The level of assurance provided by an evidence packet:
- **Core (1)**: Checkpoint chain + VDF proofs + jitter evidence
- **Enhanced (2)**: + TPM/hardware attestation
- **Maximum (3)**: + behavioral analysis + external anchors

## F

### Falsifiability
The property that CPoE evidence can be independently tested and potentially disproven. Unlike unfalsifiable claims, CPoE evidence provides concrete, testable assertions.

## H

### HMAC (Hash-based Message Authentication Code)
A keyed hash function used in CPoE for tamper detection on evidence chains and for the "economic security" model in jitter computation.

## I

### IKI (Inter-Keystroke Interval)
The time between consecutive key presses, measured in milliseconds. A primary behavioral metric for distinguishing human typing from automated input.

## J

### Jitter Seal
A cryptographic binding between a timing measurement and the content being created. Uses hardware entropy (when available) or HMAC-based computation to create evidence that content was produced through a real-time process.

## K

### Key Ratchet
A forward-secure key derivation mechanism where each new key is derived from the previous one, then the previous key is securely erased. Ensures that compromise of a current key does not reveal past evidence.

## L

### The Labyrinth
A machine-wide cryptographic entanglement mechanism where every witnessed event on a device is hashed into a single, monotonic Merkle Mountain Range (MMR). This prevents selective deletion of history by making the integrity of one document dependent on the integrity of all other documents on the same machine.

## M

### MMR (Merkle Mountain Range)
An append-only data structure used by CPoE to store event hashes. Provides efficient proof of inclusion and tamper detection. Unlike a standard Merkle tree, MMR supports efficient appending.

## P

### PoP (Proof-of-Process)
The protocol implemented by CPoE, currently being socialized in the IETF RATS working group. PoP provides verifiable evidence that a particular process (e.g., human typing) occurred as claimed.

### PUF (Physically Unclonable Function)
Hardware-derived entropy sources that produce outputs unique to a specific physical device. Used by cpoe_jitter in "physics" mode to bind evidence to hardware.

## R

### RATS (Remote ATtestation procedureS)
The IETF working group where the PoP protocol is being socialized. RATS defines architecture for remote attestation including Attesters, Verifiers, and Relying Parties.

### Roughtime
A protocol for rough time synchronization that provides cryptographic proof of time. Used by CPoE as an external time anchor.

## S

### Sentinel
The CPoE component responsible for real-time file monitoring, change detection, and session management. Watches configured directories and triggers checkpoints.

### Shadow Cache
An optional encrypted cache of file content snapshots, stored locally using AES-256-GCM. Allows reconstruction of document history but is disabled by default for privacy.

## T

### TPM (Trusted Platform Module)
A hardware security module that provides cryptographic operations in a tamper-resistant environment. CPoE uses TPM 2.0 for hardware-backed key storage and attestation on Linux.

### TSC (Time Stamp Counter)
A hardware register in modern CPUs that increments with each clock cycle. Used by cpoe_jitter for hardware entropy collection in "physics" mode.

## V

### VDF (Verifiable Delay Function)
A function that takes a specified amount of time to compute but whose result can be quickly verified. CPoE uses VDFs to create cryptographic proofs that a minimum amount of wall-clock time has elapsed between checkpoints.

## W

### WAL (Write-Ahead Log)
A journaling mechanism that logs changes before they are applied to the main database, ensuring crash recovery without data loss.

### WAR (Write-Ahead Recovery)
CPoE's fault-tolerance mechanism built on WAL. WAR blocks contain enough information to recover session state after crashes or unexpected termination.
