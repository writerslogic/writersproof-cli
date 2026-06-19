# Ratchet Key Hierarchy Specification

**Version:** 1.0.0
**Status:** Draft
**Last Updated:** 2026-01-27
**Patent:** USPTO Application No. 19/460,364

## Overview

This specification defines a three-tier key hierarchy for `cpoe` that provides:
- **Persistent identity** through a hardware-bound master key
- **Session isolation** through per-session derived keys
- **Forward secrecy** through checkpoint-level key ratcheting

> [!IMPORTANT]
> Code examples in this document are provided in **pseudocode (Go-like syntax)** for architectural clarity. The reference implementation is in **Rust**.

## Design Goals

### Security Properties

1. **Device Binding:** Master identity tied to hardware via PUF
2. **Session Isolation:** Compromise of session N does not affect sessions N±1
3. **Forward Secrecy:** Compromise of current key cannot forge past checkpoints
4. **Backward Secrecy:** Compromise of past key cannot forge future checkpoints
5. **Persistent Identity:** Author maintains recognizable identity across documents

### Usability Properties

1. Evidence can be verified years later
2. No per-session key management burden on user
3. Transparent operation during normal writing

## Key Hierarchy Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TIER 0: IDENTITY ROOT                               │
│                                                                             │
│  master_seed = PUF_Response(device_challenge)                               │
│  master_key = HKDF-SHA256(master_seed, "cpoe-identity-v1", 32)          │
│  master_pubkey = Ed25519_PublicKey(master_key)                              │
│                                                                             │
│  Properties:                                                                │
│  - Derived from device PUF (hardware-bound)                                 │
│  - Never used directly for signing checkpoints                              │
│  - Used only to derive session keys and sign session certificates           │
│  - Can be re-derived from PUF on demand (no persistent storage required)    │
│  - Public key is the persistent author identity                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HKDF derivation
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TIER 1: SESSION KEY                                 │
│                                                                             │
│  session_id = Random(32)                                                    │
│  session_seed = HKDF-SHA256(master_key, session_id || timestamp, 32)        │
│  session_key = Ed25519_PrivateKey(session_seed)                             │
│  session_pubkey = Ed25519_PublicKey(session_key)                            │
│                                                                             │
│  Session Certificate (signed by master_key):                                │
│  cert = {                                                                   │
│      session_id,                                                            │
│      session_pubkey,                                                        │
│      created_at,                                                            │
│      document_hash,     // binds session to specific document               │
│      master_pubkey,     // identifies the author                            │
│      signature          // master_key signs (session_id || session_pubkey   │
│  }                      //                   || created_at || document_hash)│
│                                                                             │
│  Properties:                                                                │
│  - Generated at session start                                               │
│  - Certified by master key (proves session belongs to identity)             │
│  - Used to initialize the ratchet                                           │
│  - Destroyed when session ends (only certificate retained)                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Ratchet derivation
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TIER 2: RATCHETING CHECKPOINT KEY                        │
│                                                                             │
│  ratchet_0 = HKDF-SHA256(session_key, "ratchet-init-v1", 32)                │
│                                                                             │
│  For each checkpoint n:                                                     │
│    signing_key_n = Ed25519_PrivateKey(ratchet_n)                            │
│    signature_n = Sign(signing_key_n, checkpoint_hash_n)                     │
│    ratchet_{n+1} = HKDF-SHA256(ratchet_n, checkpoint_hash_n, 32)            │
│    SecureWipe(ratchet_n)  // Critical: destroy after deriving next          │
│                                                                             │
│  Properties:                                                                │
│  - Each checkpoint signed with unique key                                   │
│  - Key derived from previous ratchet state + checkpoint content             │
│  - Previous ratchet states are wiped after use                              │
│  - Forward secrecy: can't derive past keys from current state               │
│  - Backward secrecy: can't derive future keys from past state               │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

| Primitive | Algorithm | Parameters |
|-----------|-----------|------------|
| Key Derivation | HKDF-SHA256 | RFC 5869 |
| Signing | Ed25519 | RFC 8032 |
| Hashing | SHA-256 | FIPS 180-4 |
| Random | crypto/rand | OS CSPRNG |
| Secure Wipe | explicit_bzero | Platform-specific |
| Memory Guard | mlock / VirtualLock | Tier 4 protection |
| Anti-Analysis | PT_DENY_ATTACH | Process hardening |

## Adversarial Hardening (Tier 4)

To protect the key material against a sophisticated local adversary, CPoE implements Tier 4 process-level hardening.

### 1. In-Memory Sealing (mlock)

Standard `Zeroize` is insufficient against forensic memory scraping. To eliminate the risk of keys leaking to persistent swap files, all `RatchetState` material is physically locked in RAM using the `mlock` system call. 

This ensures that the OS kernel cannot move the sensitive key bytes to the disk, maintaining a "RAM-only" residency for the duration of the session.

### 2. Anti-Debugging (Deny Attach)

On macOS, the engine utilizes `ptrace(PT_DENY_ATTACH)` to prevent unauthorized process inspection. If a debugger attempts to attach to the writersproof-cli daemon while keys are in memory, the daemon will immediately self-terminate, protecting the integrity of the key hierarchy.

## Data Structures

### Master Identity

```go
type MasterIdentity struct {
    // Public key is the persistent identity (can be shared)
    PublicKey  ed25519.PublicKey

    // Fingerprint for display/verification (SHA256 of public key, hex)
    Fingerprint string

    // Device ID from PUF (for re-derivation)
    DeviceID   string

    // Creation timestamp
    CreatedAt  time.Time
}
```

### Session Certificate

```go
type SessionCertificate struct {
    // Unique session identifier
    SessionID     [32]byte

    // Session public key (for verifying checkpoint signatures)
    SessionPubKey ed25519.PublicKey

    // When session was created
    CreatedAt     time.Time

    // Document this session is bound to (hash of initial state)
    DocumentHash  [32]byte

    // Master identity that certified this session
    MasterPubKey  ed25519.PublicKey

    // Master key signature over (SessionID || SessionPubKey || CreatedAt || DocumentHash)
    Signature     [64]byte

    // Version for forward compatibility
    Version       uint32
}
```

### Ratchet State

```go
type RatchetState struct {
    // Current ratchet value (secret, wiped after use)
    current     [32]byte

    // Current checkpoint ordinal
    ordinal     uint64

    // Session this ratchet belongs to
    sessionID   [32]byte

    // Whether state has been wiped (for safety checks)
    wiped       bool
}
```

### Checkpoint Signature Record

```go
type CheckpointSignature struct {
    // Checkpoint ordinal
    Ordinal       uint64

    // Public key used for this checkpoint (derived from ratchet)
    PublicKey     ed25519.PublicKey

    // Signature over checkpoint hash
    Signature     [64]byte

    // Hash of checkpoint that was signed
    CheckpointHash [32]byte
}
```

## Operations

### Initialize Identity (First Run)

```go
func InitializeIdentity(puf *hardware.PUF) (*MasterIdentity, error) {
    // 1. Get PUF response for device binding
    challenge := sha256.Sum256([]byte("cpoe-identity-challenge-v1"))
    pufResponse, err := puf.GetResponse(challenge[:])
    if err != nil {
        return nil, fmt.Errorf("PUF response failed: %w", err)
    }

    // 2. Derive master seed via HKDF
    masterSeed := hkdf.Extract(sha256.New, pufResponse, []byte("cpoe-identity-v1"))

    // 3. Generate Ed25519 key from seed
    // Note: Ed25519 seeds are 32 bytes
    var seed [32]byte
    io.ReadFull(hkdf.Expand(sha256.New, masterSeed, []byte("ed25519-seed")), seed[:])

    privateKey := ed25519.NewKeyFromSeed(seed[:])
    publicKey := privateKey.Public().(ed25519.PublicKey)

    // 4. Compute fingerprint
    fingerprint := sha256.Sum256(publicKey)

    // 5. Securely wipe intermediate values
    secureWipe(seed[:])
    secureWipe(masterSeed)
    // Note: privateKey is not stored - re-derived when needed

    return &MasterIdentity{
        PublicKey:   publicKey,
        Fingerprint: hex.EncodeToString(fingerprint[:8]), // First 8 bytes
        DeviceID:    puf.DeviceID(),
        CreatedAt:   time.Now(),
    }, nil
}
```

### Start Session

```go
func StartSession(puf *hardware.PUF, documentPath string) (*Session, error) {
    // 1. Re-derive master key from PUF
    masterKey := deriveMasterKey(puf)
    defer secureWipe(masterKey)

    // 2. Generate random session ID
    var sessionID [32]byte
    if _, err := rand.Read(sessionID[:]); err != nil {
        return nil, err
    }

    // 3. Derive session key
    sessionSeed := hkdf.Extract(sha256.New, masterKey,
        append(sessionID[:], []byte(time.Now().String())...))

    var seed [32]byte
    io.ReadFull(hkdf.Expand(sha256.New, sessionSeed, []byte("session-key")), seed[:])

    sessionKey := ed25519.NewKeyFromSeed(seed[:])
    sessionPubKey := sessionKey.Public().(ed25519.PublicKey)

    // 4. Hash initial document state
    docHash := hashDocument(documentPath)

    // 5. Create and sign session certificate
    certData := buildCertData(sessionID, sessionPubKey, time.Now(), docHash)
    masterPrivKey := ed25519.NewKeyFromSeed(masterKey[:32])
    signature := ed25519.Sign(masterPrivKey, certData)

    cert := &SessionCertificate{
        SessionID:     sessionID,
        SessionPubKey: sessionPubKey,
        CreatedAt:     time.Now(),
        DocumentHash:  docHash,
        MasterPubKey:  masterPrivKey.Public().(ed25519.PublicKey),
        Signature:     [64]byte(signature),
        Version:       1,
    }

    // 6. Initialize ratchet
    ratchetInit := hkdf.Extract(sha256.New, seed[:], []byte("ratchet-init-v1"))
    var ratchet [32]byte
    io.ReadFull(hkdf.Expand(sha256.New, ratchetInit, nil), ratchet[:])

    // 7. Wipe intermediate values
    secureWipe(seed[:])
    secureWipe(sessionSeed)
    secureWipe(masterKey)

    return &Session{
        Certificate: cert,
        ratchet: &RatchetState{
            current:   ratchet,
            ordinal:   0,
            sessionID: sessionID,
        },
    }, nil
}
```

### Sign Checkpoint (with Ratchet)

```go
func (s *Session) SignCheckpoint(checkpointHash [32]byte) (*CheckpointSignature, error) {
    if s.ratchet.wiped {
        return nil, errors.New("ratchet state has been wiped")
    }

    // 1. Derive signing key from current ratchet state
    var seed [32]byte
    r := hkdf.Expand(sha256.New, s.ratchet.current[:], []byte("signing-key"))
    io.ReadFull(r, seed[:])

    signingKey := ed25519.NewKeyFromSeed(seed[:])
    pubKey := signingKey.Public().(ed25519.PublicKey)

    // 2. Sign the checkpoint
    signature := ed25519.Sign(signingKey, checkpointHash[:])

    // 3. Ratchet forward: derive next state from current + checkpoint hash
    nextRatchet := hkdf.Extract(sha256.New, s.ratchet.current[:], checkpointHash[:])
    var next [32]byte
    io.ReadFull(hkdf.Expand(sha256.New, nextRatchet, []byte("ratchet-next")), next[:])

    // 4. CRITICAL: Securely wipe current ratchet state
    secureWipe(s.ratchet.current[:])
    secureWipe(seed[:])

    // 5. Update ratchet state
    s.ratchet.current = next
    currentOrdinal := s.ratchet.ordinal
    s.ratchet.ordinal++

    return &CheckpointSignature{
        Ordinal:        currentOrdinal,
        PublicKey:      pubKey,
        Signature:      [64]byte(signature),
        CheckpointHash: checkpointHash,
    }, nil
}
```

### End Session

```go
func (s *Session) End() error {
    // Securely wipe all key material
    if s.ratchet != nil && !s.ratchet.wiped {
        secureWipe(s.ratchet.current[:])
        s.ratchet.wiped = true
    }

    // Certificate is retained for verification
    // Session key material is destroyed

    return nil
}
```

## Verification

### Verify Session Certificate

```go
func VerifySessionCertificate(cert *SessionCertificate) error {
    // Reconstruct signed data
    certData := buildCertData(
        cert.SessionID,
        cert.SessionPubKey,
        cert.CreatedAt,
        cert.DocumentHash,
    )

    // Verify master key signature
    if !ed25519.Verify(cert.MasterPubKey, certData, cert.Signature[:]) {
        return errors.New("invalid session certificate signature")
    }

    return nil
}
```

### Verify Checkpoint Signature Chain

```go
func VerifyCheckpointChain(
    cert *SessionCertificate,
    signatures []CheckpointSignature,
    checkpoints []Checkpoint,
) error {
    if len(signatures) != len(checkpoints) {
        return errors.New("signature/checkpoint count mismatch")
    }

    // Verify each signature independently
    // Note: We cannot verify ratchet derivation (forward secrecy means
    // we don't have the ratchet states), but we can verify:
    // 1. Each signature is valid for its public key
    // 2. Signatures are sequential by ordinal

    for i, sig := range signatures {
        // Verify ordinal sequence
        if sig.Ordinal != uint64(i) {
            return fmt.Errorf("checkpoint %d: ordinal mismatch", i)
        }

        // Verify signature
        if !ed25519.Verify(sig.PublicKey, sig.CheckpointHash[:], sig.Signature[:]) {
            return fmt.Errorf("checkpoint %d: invalid signature", i)
        }

        // Verify checkpoint hash matches
        computed := checkpoints[i].ComputeHash()
        if computed != sig.CheckpointHash {
            return fmt.Errorf("checkpoint %d: hash mismatch", i)
        }
    }

    return nil
}
```

## Evidence Packet Integration

The evidence packet includes:

```json
{
  "key_hierarchy": {
    "version": 1,
    "master_identity": {
      "public_key": "base64...",
      "fingerprint": "a1b2c3d4",
      "device_id": "device-xyz"
    },
    "session_certificate": {
      "session_id": "base64...",
      "session_pubkey": "base64...",
      "created_at": "2026-01-27T10:00:00Z",
      "document_hash": "hex...",
      "master_pubkey": "base64...",
      "signature": "base64..."
    },
    "checkpoint_signatures": [
      {
        "ordinal": 0,
        "public_key": "base64...",
        "signature": "base64...",
        "checkpoint_hash": "hex..."
      }
    ]
  }
}
```

## Security Analysis

### Forward Secrecy

After signing checkpoint $n$, the ratchet state is:
$$\text{ratchet}_{n+1} = \text{HKDF}(\text{ratchet}_n, \text{checkpoint\_hash}_n)$$

To compute $\text{ratchet}_n$ from $\text{ratchet}_{n+1}$, an adversary would need to invert HKDF, which requires breaking the preimage resistance of SHA-256.

### Backward Secrecy

To compute $\text{ratchet}_{n+1}$ from $\text{ratchet}_n$, an adversary needs $\text{checkpoint\_hash}_n$, which includes the document content hash and VDF output. Without knowing the future document state, future keys cannot be derived.

### Session Isolation

Each session key is derived from:
$$\text{session\_key} = \text{HKDF}(\text{master\_key}, \text{session\_id} \| \text{timestamp})$$

Sessions are cryptographically independent due to the random session ID. Compromising session $N$ reveals nothing about session $N \pm 1$.

### Device Binding

The master key is derived from the PUF response:
$$\text{master\_key} = \text{HKDF}(\text{PUF}(\text{challenge}), \text{info})$$

Without access to the physical device, the master key cannot be derived. This binds all evidence to the specific hardware.

## Secure Wipe Implementation

```go
// secureWipe overwrites memory with zeros, preventing recovery.
// Uses platform-specific secure memory clearing when available.
func secureWipe(data []byte) {
    // Use explicit_bzero semantics to prevent compiler optimization
    for i := range data {
        data[i] = 0
    }

    // Memory barrier to ensure writes complete
    runtime.KeepAlive(data)
}
```

On platforms with `explicit_bzero` or `SecureZeroMemory`, those should be used via cgo for guaranteed clearing.

## Migration Path

For existing users with persistent Ed25519 keys:

1. **Import existing key as master key** (one-time migration)
2. **Generate session certificate** signed by imported key
3. **Begin using ratchet** for new sessions

Existing evidence packets remain valid; new packets include the full key hierarchy.

## Implementation Checklist

- [ ] HKDF wrapper with secure memory handling
- [ ] PUF integration for master key derivation
- [ ] Session certificate generation and signing
- [ ] Ratchet state management with secure wipe
- [ ] Checkpoint signing with ratchet advancement
- [ ] Evidence packet serialization with key hierarchy
- [ ] Verification functions for certificates and chains
- [ ] Migration tool for existing keys
- [ ] Unit tests for all cryptographic operations
- [ ] Integration tests for full session lifecycle

## References

- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- Signal Protocol: Double Ratchet Algorithm (inspiration for ratchet design)
- FIPS 180-4: Secure Hash Standard (SHA-256)
