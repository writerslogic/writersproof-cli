/**
 * CPoE Secure Channel — ECDH + AES-256-GCM encrypted communication
 *
 * Provides end-to-end encryption between the browser extension and the
 * native messaging host using P-256 ECDH key exchange and AES-256-GCM
 * authenticated encryption with sequence number replay protection.
 *
 * Key ratcheting: after each jitter batch, both sides re-derive the session
 * key using the jitter hash as entropy, providing forward secrecy bound to
 * actual keystroke behavior.
 */

// M-114: Cross-language domain-separation strings. Must match Rust native host exactly.
const DST_HKDF_SALT = "cpoe-nmh-v1";
const DST_SESSION_KEY_INFO = "aes-256-gcm-key";
const DST_CANARY_SEED_INFO = "canary-seed";
const DST_KEY_CONFIRM = "cpoe-key-confirm-ok";
const DST_KEY_RATCHET = "cpoe-key-ratchet";
const DST_JITTER_BINDING = "cpoe-jitter-binding";
const DST_BROWSER_COMMIT = "cpoe-browser-commit";

// M-081: Expected sizes for public key validation
const P256_UNCOMPRESSED_PUBKEY_LEN = 65; // 0x04 || X(32) || Y(32)

// Allowlist of message types the native host is permitted to send through the encrypted channel.
// Prevents a compromised NMH binary from injecting arbitrary privileged message types.
const ALLOWED_NATIVE_MSG_TYPES = new Set([
  "session_started", "session_stopped", "checkpoint_created",
  "status", "jitter_received", "error", "pong", "text_attestation",
]);

// eslint-disable-next-line no-unused-vars
class SecureChannel {
  constructor() {
    this.keyPair = null;
    this.sessionKey = null; // CryptoKey for AES-256-GCM
    this.rawKeyBytes = null; // Uint8Array(32) for ratcheting
    this.txSequence = 0; // Client sends even: 0, 2, 4, ...
    this.rxSequence = 1; // Server sends odd: 1, 3, 5, ...
    this.ratchetCount = 0;
    this.handshakeComplete = false;
    this.canarySeed = null; // Uint8Array(32)
  }

  /** Generate ephemeral P-256 ECDH keypair. */
  async generateKeyPair() {
    this.keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true, // extractable (need raw public key bytes)
      ["deriveKey", "deriveBits"]
    );
  }

  /** Export public key as uncompressed SEC1 bytes (65 bytes: 0x04 || X || Y). */
  async getPublicKeyBytes() {
    const raw = await crypto.subtle.exportKey("raw", this.keyPair.publicKey);
    return new Uint8Array(raw);
  }

  /** Export public key as base64 for JSON transport. */
  async getPublicKeyBase64() {
    const bytes = await this.getPublicKeyBytes();
    return uint8ToBase64(bytes);
  }

  /**
   * Perform the v2 handshake with the native messaging host.
   * @param {Function} sendRaw - function to send raw JSON to native port
   * @returns {Promise<boolean>} true if handshake succeeded
   */
  async performHandshake(sendRaw) {
    if (this._handshakeTimeout) {
      clearTimeout(this._handshakeTimeout);
    }
    // Reset channel state on re-handshake to prevent stale sequences/keys carrying over.
    this.txSequence = 0;
    this.rxSequence = 1;
    this.ratchetCount = 0;
    this.handshakeComplete = false;
    if (this.rawKeyBytes) {
      this.rawKeyBytes.fill(0);
      this.rawKeyBytes = null;
    }
    this.sessionKey = null;
    if (this.canarySeed) {
      this.canarySeed.fill(0);
      this.canarySeed = null;
    }
    await this.generateKeyPair();
    const clientPubKey = await this.getPublicKeyBase64();

    return new Promise((resolve, reject) => {
      this._handshakeTimeout = setTimeout(() => {
        this._handshakeTimeout = null;
        reject(new Error("Handshake timed out (3s)"));
      }, 3000);

      this._handshakeResolve = (serverMsg) => {
        clearTimeout(this._handshakeTimeout);
        this._handshakeTimeout = null;
        resolve(serverMsg);
      };
      this._handshakeReject = (err) => {
        clearTimeout(this._handshakeTimeout);
        this._handshakeTimeout = null;
        reject(err);
      };

      sendRaw({
        type: "hello",
        protocol_version: 2,
        client_pubkey: clientPubKey,
      });
    });
  }

  /**
   * Handle the server's hello_accept message during handshake.
   * Derives session key and verifies the server's confirmation token.
   * @param {Object} message - { server_pubkey, confirm } from NMH
   * @param {Function} sendRaw - function to send raw JSON to native port
   */
  async handleHelloAccept(message, sendRaw) {
    if (this.handshakeComplete) {
      return;
    }

    try {
      // M-081: Validate server public key format and length
      if (typeof message.server_pubkey !== "string" || message.server_pubkey.length === 0) {
        throw new Error("Missing or empty server_pubkey in hello_accept");
      }
      const serverPubKeyBytes = base64ToUint8(message.server_pubkey);
      if (serverPubKeyBytes.length !== P256_UNCOMPRESSED_PUBKEY_LEN) {
        throw new Error(
          `Invalid server pubkey size: expected ${P256_UNCOMPRESSED_PUBKEY_LEN}, got ${serverPubKeyBytes.length}`
        );
      }
      if (serverPubKeyBytes[0] !== 0x04) {
        throw new Error("Server pubkey is not uncompressed SEC1 format (missing 0x04 prefix)");
      }

      // Import server's public key
      const serverPubKey = await crypto.subtle.importKey(
        "raw",
        serverPubKeyBytes,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
      );

      // Compute ECDH shared secret
      const sharedBits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: serverPubKey },
        this.keyPair.privateKey,
        256
      );
      const sharedSecret = new Uint8Array(sharedBits);

      // Derive session key + canary seed via multi-output HKDF
      const clientPubKeyBytes = await this.getPublicKeyBytes();
      const { sessionKeyBytes, canarySeed } = await this.deriveKeys(
        sharedSecret,
        clientPubKeyBytes,
        serverPubKeyBytes
      );

      this.rawKeyBytes = sessionKeyBytes;
      this.canarySeed = canarySeed;

      // Import as AES-256-GCM CryptoKey
      this.sessionKey = await crypto.subtle.importKey(
        "raw",
        sessionKeyBytes,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );

      // Decrypt and verify server's confirmation
      if (typeof message.confirm !== "string" || message.confirm.length === 0) {
        throw new Error("hello_accept: missing or invalid 'confirm' field");
      }
      const confirmCiphertext = base64ToUint8(message.confirm);
      const confirmPlaintext = await this.decryptRaw(confirmCiphertext);
      const expectedConfirm = new TextEncoder().encode(DST_KEY_CONFIRM);
      if (!constantTimeEqual(confirmPlaintext, expectedConfirm)) {
        throw new Error("Key confirmation failed: server derived different key");
      }

      // Send client's confirmation
      const clientConfirm = await this.encryptRaw(expectedConfirm);
      sendRaw({
        type: "hello_confirm",
        confirm: uint8ToBase64(clientConfirm),
      });

      this.handshakeComplete = true;

      if (this._handshakeResolve) {
        this._handshakeResolve(true);
        this._handshakeResolve = null;
        this._handshakeReject = null;
      }
    } catch (err) {
      if (this._handshakeReject) {
        this._handshakeReject(err);
        this._handshakeResolve = null;
        this._handshakeReject = null;
      }
      throw err;
    }
  }

  /**
   * Multi-output HKDF: derive session key (32 bytes) and canary seed (32 bytes).
   * Info strings match the Rust side exactly for cross-language compatibility.
   */
  async deriveKeys(sharedSecret, clientPubKey, serverPubKey) {
    const salt = new TextEncoder().encode(DST_HKDF_SALT);

    // Import shared secret as HKDF key material
    const ikm = await crypto.subtle.importKey(
      "raw",
      sharedSecret,
      "HKDF",
      false,
      ["deriveBits"]
    );

    // Session key info: DST_SESSION_KEY_INFO || client_pubkey(65) || server_pubkey(65)
    const keyInfo = concatBytes(
      new TextEncoder().encode(DST_SESSION_KEY_INFO),
      clientPubKey,
      serverPubKey
    );

    const sessionKeyBits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: keyInfo },
      ikm,
      256
    );
    const sessionKeyBytes = new Uint8Array(sessionKeyBits);

    // Canary seed info: DST_CANARY_SEED_INFO || client_pubkey(65) || server_pubkey(65)
    const canaryInfo = concatBytes(
      new TextEncoder().encode(DST_CANARY_SEED_INFO),
      clientPubKey,
      serverPubKey
    );

    const canarySeedBits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: canaryInfo },
      ikm,
      256
    );
    const canarySeed = new Uint8Array(canarySeedBits);

    return { sessionKeyBytes, canarySeed };
  }

  /**
   * Encrypt plaintext bytes. Returns [8-byte seq][12-byte nonce][ciphertext+tag].
   * Matches the Rust SecureSession::encrypt format exactly.
   */
  async encryptRaw(plaintext) {
    const seq = this.txSequence;
    this.txSequence += 2;

    const nonceBytes = new Uint8Array(12);
    const seqBytes = uint64ToLE(seq);
    nonceBytes.set(seqBytes, 4); // nonce[4..12] = seq LE

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonceBytes, tagLength: 128 },
      this.sessionKey,
      plaintext
    );

    const result = new Uint8Array(8 + 12 + ciphertext.byteLength);
    result.set(seqBytes, 0);
    result.set(nonceBytes, 8);
    result.set(new Uint8Array(ciphertext), 20);
    return result;
  }

  /**
   * Decrypt wire bytes. Verifies sequence number for replay protection.
   * Input format: [8-byte seq][12-byte nonce][ciphertext+tag].
   */
  async decryptRaw(data) {
    if (data.length < 36) {
      throw new Error(`Encrypted message too short: ${data.length} bytes`);
    }

    const seq = leToUint64(data.subarray(0, 8));
    if (seq !== this.rxSequence) {
      throw new Error(
        `Sequence mismatch: expected ${this.rxSequence}, got ${seq} (replay?)`
      );
    }

    const nonce = data.subarray(8, 20);
    const ciphertext = data.subarray(20);

    this.rxSequence += 2;
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      this.sessionKey,
      ciphertext
    );

    return new Uint8Array(plaintext);
  }

  /**
   * Encrypt a JSON message for transport as an encrypted envelope.
   * Returns the envelope object ready to send via native messaging.
   */
  async encrypt(jsonObj) {
    const plaintext = new TextEncoder().encode(JSON.stringify(jsonObj));
    const encrypted = await this.encryptRaw(plaintext);
    return {
      type: "encrypted",
      seq: this.txSequence - 2, // already advanced
      rc: this.ratchetCount,
      payload: uint8ToBase64(encrypted),
    };
  }

  /**
   * Decrypt an encrypted envelope from the native host.
   * @param {Object} envelope - { type: "encrypted", seq, rc, payload }
   * @returns {Object} Decrypted JSON message with validated `type` field
   */
  async decrypt(envelope) {
    // M-079: Validate ratchet count from envelope is a non-negative integer
    if (envelope.rc !== undefined) {
      if (!Number.isInteger(envelope.rc) || envelope.rc < 0) {
        throw new Error(`Invalid remote ratchet count: ${envelope.rc}`);
      }
      // M-099: Ratchet count check is single-threaded in JS event loop,
      // so get-then-compare is effectively atomic.
      if (envelope.rc !== this.ratchetCount) {
        throw new Error(
          `Ratchet count desync: local=${this.ratchetCount}, remote=${envelope.rc}`
        );
      }
    }
    if (typeof envelope.seq === "number" && envelope.seq !== this.rxSequence) {
      throw new Error(
        `Envelope sequence mismatch: expected ${this.rxSequence}, got ${envelope.seq}`
      );
    }
    const data = base64ToUint8(envelope.payload);
    const plaintext = await this.decryptRaw(data);

    let parsed;
    try {
      parsed = JSON.parse(new TextDecoder().decode(plaintext));
    } catch (_) {
      throw new Error("Decrypted payload is not valid JSON");
    }

    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Decrypted payload is not a JSON object");
    }
    if (typeof parsed.type !== "string" || parsed.type.length === 0) {
      throw new Error("Decrypted message missing required 'type' field");
    }
    if (!ALLOWED_NATIVE_MSG_TYPES.has(parsed.type)) {
      throw new Error(`Decrypted message has disallowed type: ${parsed.type}`);
    }

    return parsed;
  }

  /**
   * Compute jitter hash for key ratcheting.
   * jitter_hash = SHA-256("cpoe-jitter-binding" || interval_1_le64 || interval_2_le64 || ...)
   */
  async computeJitterHash(intervals) {
    if (!Array.isArray(intervals) || intervals.length === 0) {
      throw new Error("computeJitterHash: intervals must be a non-empty array");
    }
    for (let i = 0; i < intervals.length; i++) {
      if (!Number.isFinite(intervals[i]) || intervals[i] < 0) {
        throw new Error(`computeJitterHash: intervals[${i}] is not a finite non-negative number`);
      }
    }
    const prefix = new TextEncoder().encode(DST_JITTER_BINDING);
    const data = new Uint8Array(prefix.length + intervals.length * 8);
    data.set(prefix, 0);
    for (let i = 0; i < intervals.length; i++) {
      data.set(uint64ToLE(intervals[i]), prefix.length + i * 8);
    }
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(hashBuffer);
  }

  /**
   * Ratchet the session key using jitter entropy.
   * new_key = HKDF(IKM=current_key, salt=jitter_hash, info="cpoe-key-ratchet" || ratchet_count_le64)
   * Must be called AFTER receiving jitter_received ACK from NMH.
   */
  async ratchetWithJitter(jitterHash, newRatchetCount) {
    if (newRatchetCount !== this.ratchetCount + 1) {
      throw new Error(
        `ratchetWithJitter: count must increment by exactly 1 (expected ${this.ratchetCount + 1}, got ${newRatchetCount})`
      );
    }

    const info = concatBytes(
      new TextEncoder().encode(DST_KEY_RATCHET),
      uint64ToLE(newRatchetCount)
    );

    // Import current key as HKDF IKM
    const ikm = await crypto.subtle.importKey(
      "raw",
      this.rawKeyBytes,
      "HKDF",
      false,
      ["deriveBits"]
    );

    const newKeyBits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: jitterHash, info },
      ikm,
      256
    );

    // M-082: Best-effort zeroization of old key material. In JavaScript, the GC
    // may retain copies of TypedArray backing buffers, and crypto.subtle CryptoKey
    // objects cannot be explicitly zeroized. This fill(0) is the best we can do.
    if (this.rawKeyBytes) {
      this.rawKeyBytes.fill(0);
    }

    this.rawKeyBytes = new Uint8Array(newKeyBits);
    this.sessionKey = await crypto.subtle.importKey(
      "raw",
      this.rawKeyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    this.ratchetCount = newRatchetCount;
  }

  /**
   * Compute a dual-channel commitment for a checkpoint.
   * commitment = SHA-256(DST || len(session_id) || session_id || ordinal_le64 || len(content_hash) || content_hash || timestamp_le64)
   * Variable-length fields are length-prefixed (4-byte LE) to prevent boundary confusion.
   */
  async computeCommitment(sessionId, ordinal, contentHash, timestamp) {
    if (typeof sessionId !== "string" || sessionId.length === 0 || sessionId.length > 256) {
      throw new Error("computeCommitment: sessionId must be a non-empty string up to 256 chars");
    }
    if (!Number.isInteger(ordinal) || ordinal < 0) {
      throw new Error(`computeCommitment: ordinal must be a non-negative integer, got ${ordinal}`);
    }
    if (typeof contentHash !== "string" || contentHash.length === 0 || contentHash.length > 256) {
      throw new Error("computeCommitment: contentHash must be a non-empty string up to 256 chars");
    }
    if (!Number.isFinite(timestamp) || timestamp < 0) {
      throw new Error(`computeCommitment: timestamp must be a non-negative finite number, got ${timestamp}`);
    }
    const sessionIdBytes = new TextEncoder().encode(sessionId);
    const contentHashBytes = new TextEncoder().encode(contentHash);
    const data = concatBytes(
      new TextEncoder().encode(DST_BROWSER_COMMIT),
      uint32ToLE(sessionIdBytes.length),
      sessionIdBytes,
      uint64ToLE(ordinal),
      uint32ToLE(contentHashBytes.length),
      contentHashBytes,
      uint64ToLE(timestamp)
    );
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return uint8ToHex(new Uint8Array(hashBuffer));
  }

  /**
   * Compute canary token for a checkpoint.
   * canary = HMAC-SHA256(canary_seed, ordinal_le64 || content_hash_bytes)[0..4] as u32 LE
   */
  async computeCanary(ordinal, contentHashHex) {
    if (!this.canarySeed) {
      throw new Error("Canary seed not initialized");
    }
    const key = await crypto.subtle.importKey(
      "raw",
      this.canarySeed,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const contentHashBytes = hexToUint8(contentHashHex);
    const data = concatBytes(uint64ToLE(ordinal), contentHashBytes);
    const sig = await crypto.subtle.sign("HMAC", key, data);
    const sigBytes = new Uint8Array(sig);
    // u32 LE from first 4 bytes (>>> 0 ensures unsigned)
    return (sigBytes[0] | (sigBytes[1] << 8) | (sigBytes[2] << 16) | (sigBytes[3] << 24)) >>> 0;
  }

  /** True if the encrypted channel is established. */
  get isSecure() {
    return this.handshakeComplete;
  }

  /**
   * M-082: Best-effort zeroization of all key material.
   * Call on disconnect/session end. CryptoKey objects cannot be explicitly
   * zeroized in JS — setting to null drops the reference for GC.
   */
  destroy() {
    if (this.rawKeyBytes) {
      this.rawKeyBytes.fill(0);
      this.rawKeyBytes = null;
    }
    if (this.canarySeed) {
      this.canarySeed.fill(0);
      this.canarySeed = null;
    }
    this.sessionKey = null;
    this.keyPair = null;
    this.handshakeComplete = false;
    this.txSequence = 0;
    this.rxSequence = 1;
    this.ratchetCount = 0;
    // Clear dangling handshake promise callbacks
    if (this._handshakeReject) {
      this._handshakeReject(new Error("channel destroyed"));
    }
    this._handshakeResolve = null;
    this._handshakeReject = null;
  }
}

// --- Utility functions ---

function uint8ToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8(b64) {
  if (typeof b64 !== "string" || b64.length === 0) {
    throw new Error("Invalid base64 input");
  }
  let binary;
  try {
    binary = atob(b64);
  } catch (_) {
    throw new Error("Invalid base64 encoding");
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function uint8ToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToUint8(hex) {
  if (typeof hex !== "string" || hex.length === 0) {
    throw new Error("hexToUint8: input must be a non-empty string");
  }
  if (hex.length % 2 !== 0) {
    throw new Error(`hexToUint8: odd-length string (${hex.length} chars)`);
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("hexToUint8: non-hex characters in input");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function uint32ToLE(n) {
  const bytes = new Uint8Array(4);
  bytes[0] = n & 0xff;
  bytes[1] = (n >> 8) & 0xff;
  bytes[2] = (n >> 16) & 0xff;
  bytes[3] = (n >>> 24) & 0xff;
  return bytes;
}

function uint64ToLE(n) {
  const bytes = new Uint8Array(8);
  // Safe for values up to 2^53 (Number.MAX_SAFE_INTEGER)
  bytes[0] = n & 0xff;
  bytes[1] = (n >> 8) & 0xff;
  bytes[2] = (n >> 16) & 0xff;
  bytes[3] = (n >>> 24) & 0xff;
  // For values > 2^32, use division
  const high = Math.floor(n / 0x100000000);
  bytes[4] = high & 0xff;
  bytes[5] = (high >> 8) & 0xff;
  bytes[6] = (high >> 16) & 0xff;
  bytes[7] = (high >>> 24) & 0xff;
  return bytes;
}

function leToUint64(bytes) {
  const low =
    bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | ((bytes[3] << 24) >>> 0);
  const high =
    (bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24)) >>> 0;
  return low + high * 0x100000000;
}

function concatBytes(...arrays) {
  let totalLen = 0;
  for (const a of arrays) totalLen += a.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

/** Constant-time comparison to prevent timing side-channels. */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
