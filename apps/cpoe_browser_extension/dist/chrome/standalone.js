/**
 * CPoE Browser Extension — Standalone Evidence Engine
 *
 * When the native messaging host (desktop app / CLI) is not installed,
 * this module provides a lightweight in-browser evidence chain using
 * Web Crypto API and IndexedDB. Evidence is weaker than the full engine
 * (no VDF proofs, no hardware attestation, no Secure Enclave) but still
 * provides a hash-chained, timestamped record of the writing process.
 *
 * Anti-forgery measures in standalone mode:
 *  - HMAC-SHA256 integrity tags on each checkpoint (keyed by session nonce)
 *  - Monotonic timestamp enforcement (rejects backward jumps)
 *  - Minimum checkpoint interval (rate-limits rapid-fire fakes)
 *  - Jitter-content binding (keystroke timing hashed into chain)
 *  - Delta plausibility checks (flag impossible char-count jumps)
 *  - Trust level metadata on export (standalone < native < hardware)
 *
 * When the desktop app IS installed, this module is not used — the
 * background script routes everything through native messaging instead.
 */

const DB_NAME = "writersproof-evidence";
const DB_VERSION = 2;
const STORE_SESSIONS = "sessions";
const STORE_CHECKPOINTS = "checkpoints";
const STORE_JITTER = "jitter";

const DST_GENESIS = "CPoE-StandaloneGenesis-v1";
const DST_CHAIN = "CPoE-StandaloneChain-v1";
const DST_HMAC = "CPoE-StandaloneHMAC-v1";
const DST_JITTER_BIND = "CPoE-StandaloneJitterBind-v1";

const MIN_CHECKPOINT_INTERVAL_MS = 5000;
const MAX_PLAUSIBLE_DELTA = 50000;

// Pre-allocated hex lookup table
const SA_HEX = [];
for (let i = 0; i < 256; i++) SA_HEX[i] = i.toString(16).padStart(2, "0");

const saEncoder = new TextEncoder();

let db = null;

async function openDB() {
  if (db) return db;
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const d = e.target.result;
      const oldVersion = e.oldVersion;

      // v0 -> v1: create sessions and checkpoints stores
      if (oldVersion < 1) {
        d.createObjectStore(STORE_SESSIONS, { keyPath: "id" });
        const cpStore = d.createObjectStore(STORE_CHECKPOINTS, {
          keyPath: "id",
          autoIncrement: true,
        });
        cpStore.createIndex("sessionId", "sessionId", { unique: false });
      }

      // v1 -> v2: add jitter store, new checkpoint fields (hmacTag, jitterBinding, flags)
      if (oldVersion < 2) {
        if (!d.objectStoreNames.contains(STORE_JITTER)) {
          const jStore = d.createObjectStore(STORE_JITTER, {
            keyPath: "id",
            autoIncrement: true,
          });
          jStore.createIndex("sessionId", "sessionId", { unique: false });
        }
      }
    };
    req.onsuccess = (e) => {
      db = e.target.result;
      resolve(db);
    };
    req.onerror = () => reject(req.error);
  });
}

function generateId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += SA_HEX[bytes[i]];
  return hex;
}

async function sha256Hex(data) {
  const encoded = typeof data === "string" ? saEncoder.encode(data) : data;
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  const arr = new Uint8Array(hash);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += SA_HEX[arr[i]];
  return hex;
}

// In-memory HMAC CryptoKey cache, keyed by session nonce.
// The key is non-extractable and never stored in IndexedDB.
const hmacKeyCache = new Map();

async function getHmacKey(nonce) {
  if (hmacKeyCache.has(nonce)) return hmacKeyCache.get(nonce);
  if (hmacKeyCache.size >= 50) {
    hmacKeyCache.delete(hmacKeyCache.keys().next().value);
  }
  const keyMaterial = await sha256Hex(`${DST_HMAC}:${nonce}`);
  const key = await crypto.subtle.importKey(
    "raw",
    hexToBytes(keyMaterial),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  hmacKeyCache.set(nonce, key);
  return key;
}

async function hmacSha256Hex(nonce, data) {
  const key = await getHmacKey(nonce);
  const encoded = typeof data === "string" ? saEncoder.encode(data) : data;
  const sig = await crypto.subtle.sign("HMAC", key, encoded);
  const arr = new Uint8Array(sig);
  let hex = "";
  for (let i = 0; i < arr.length; i++) hex += SA_HEX[arr[i]];
  return hex;
}

function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Invalid hex string");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// --- Public API (called from background.js) ---

async function standaloneStartSession(url, title) {
  const d = await openDB();
  const sessionId = generateId();
  const nonce = generateId();
  const now = Date.now();

  const genesisInput = `${DST_GENESIS}:${nonce}`;
  const genesisHash = await sha256Hex(genesisInput);

  const session = {
    id: sessionId,
    url,
    title,
    nonce,
    startedAt: now,
    lastCheckpointAt: now,
    lastJitterHash: null,
    checkpointCount: 0,
    prevHash: genesisHash,
    mode: "standalone",
  };

  const tx = d.transaction(STORE_SESSIONS, "readwrite");
  tx.objectStore(STORE_SESSIONS).put(session);
  await txComplete(tx);

  return {
    type: "session_started",
    session_id: sessionId,
    session_nonce: nonce,
    mode: "standalone",
  };
}

async function standaloneCheckpoint(sessionId, contentHash, charCount, delta, toolCategory, toolHost) {
  const d = await openDB();
  const tx = d.transaction([STORE_SESSIONS, STORE_CHECKPOINTS], "readwrite");
  const sessionStore = tx.objectStore(STORE_SESSIONS);
  const cpStore = tx.objectStore(STORE_CHECKPOINTS);

  const session = await storeGet(sessionStore, sessionId);
  if (!session) {
    return { type: "error", code: "NO_SESSION", message: "No active session" };
  }

  const ordinal = session.checkpointCount + 1;
  const now = Date.now();

  // Monotonic timestamp enforcement
  if (now < session.lastCheckpointAt) {
    return {
      type: "error",
      code: "TIMESTAMP_REGRESSION",
      message: "Clock moved backward; checkpoint rejected",
    };
  }

  // Rate limiting: reject checkpoints faster than minimum interval
  if (ordinal > 1 && (now - session.lastCheckpointAt) < MIN_CHECKPOINT_INTERVAL_MS) {
    return {
      type: "error",
      code: "RATE_LIMITED",
      message: "Checkpoint too soon; wait a few seconds",
    };
  }

  // Delta plausibility: flag impossible character-count jumps
  let flags = 0;
  if (Math.abs(delta) > MAX_PLAUSIBLE_DELTA) {
    flags |= 1; // FLAG_LARGE_DELTA
  }

  // Chain: SHA-256(DST || prevHash || contentHash || ordinal || timestamp || jitterBinding)
  const jitterBinding = session.lastJitterHash || "0".repeat(64);
  const chainInput = `${DST_CHAIN}:${session.prevHash}:${contentHash}:${ordinal}:${now}:${jitterBinding}`;
  const checkpointHash = await sha256Hex(chainInput);

  // HMAC integrity tag derived from session nonce (key never stored in IndexedDB)
  const hmacInput = `${checkpointHash}:${ordinal}:${now}:${contentHash}:${charCount}:${delta}`;
  const hmacTag = await hmacSha256Hex(session.nonce, hmacInput);

  const checkpoint = {
    sessionId,
    ordinal,
    timestamp: now,
    contentHash,
    charCount,
    delta,
    flags,
    prevHash: session.prevHash,
    checkpointHash,
    jitterBinding,
    hmacTag,
    toolCategory: toolCategory || "none",
    toolHost: toolHost || "",
  };

  cpStore.put(checkpoint);

  session.prevHash = checkpointHash;
  session.checkpointCount = ordinal;
  session.lastCheckpointAt = now;
  sessionStore.put(session);

  await txComplete(tx);

  return {
    type: "checkpoint_created",
    checkpoint_count: ordinal,
    hash: checkpointHash.slice(0, 24),
    mode: "standalone",
  };
}

async function standaloneStopSession(sessionId) {
  const d = await openDB();
  const tx = d.transaction(STORE_SESSIONS, "readwrite");
  const store = tx.objectStore(STORE_SESSIONS);
  const session = await storeGet(store, sessionId);

  if (session) {
    session.endedAt = Date.now();
    store.put(session);
    await txComplete(tx);
  }

  return {
    type: "session_stopped",
    message: "Standalone session ended",
    checkpoint_count: session?.checkpointCount || 0,
    mode: "standalone",
  };
}

async function standaloneRecordJitter(sessionId, intervals) {
  if (!sessionId || !intervals || intervals.length === 0) return;

  const d = await openDB();

  // Compute jitter hash to bind into next checkpoint
  const jitterInput = `${DST_JITTER_BIND}:${intervals.join(",")}`;
  const jitterHash = await sha256Hex(jitterInput);

  const tx = d.transaction([STORE_SESSIONS, STORE_JITTER], "readwrite");

  // Update session's jitter binding for next checkpoint
  const sessionStore = tx.objectStore(STORE_SESSIONS);
  const session = await storeGet(sessionStore, sessionId);
  if (session) {
    // Chain jitter hashes: SHA-256(prev_jitter_hash || new_jitter_hash)
    const prevJitter = session.lastJitterHash || "0".repeat(64);
    session.lastJitterHash = await sha256Hex(`${prevJitter}:${jitterHash}`);
    sessionStore.put(session);
  }

  tx.objectStore(STORE_JITTER).put({
    sessionId,
    timestamp: Date.now(),
    intervals,
    jitterHash,
  });
  await txComplete(tx);
}

async function standaloneRecordAiCopy(sessionId, source, charCount, timestamp) {
  if (!sessionId || !source) return;
  const d = await openDB();
  const tx = d.transaction(STORE_JITTER, "readwrite");
  tx.objectStore(STORE_JITTER).put({
    sessionId,
    timestamp: timestamp || Date.now(),
    type: "ai_copy",
    source,
    charCount: charCount || 0,
  });
  await txComplete(tx);
}

async function standaloneGetStatus(sessionId) {
  if (!sessionId) {
    return {
      type: "status",
      active: false,
      tracked_files: 0,
      total_checkpoints: 0,
      mode: "standalone",
    };
  }

  const d = await openDB();
  const session = await storeGet(
    d.transaction(STORE_SESSIONS).objectStore(STORE_SESSIONS),
    sessionId
  );

  return {
    type: "status",
    active: session && !session.endedAt,
    tracked_files: session ? 1 : 0,
    total_checkpoints: session?.checkpointCount || 0,
    mode: "standalone",
  };
}

async function standaloneExportEvidence(sessionId) {
  const d = await openDB();
  const tx = d.transaction([STORE_SESSIONS, STORE_CHECKPOINTS, STORE_JITTER]);
  const session = await storeGet(
    tx.objectStore(STORE_SESSIONS),
    sessionId
  );
  if (!session) return null;

  const checkpoints = await storeGetAllByIndex(
    tx.objectStore(STORE_CHECKPOINTS),
    "sessionId",
    sessionId
  );

  const jitterBatches = await storeGetAllByIndex(
    tx.objectStore(STORE_JITTER),
    "sessionId",
    sessionId
  );

  // Verify chain integrity before export
  checkpoints.sort((a, b) => a.ordinal - b.ordinal);
  let chainValid = true;
  let expectedPrev = await sha256Hex(`${DST_GENESIS}:${session.nonce}`);
  for (const cp of checkpoints) {
    if (cp.prevHash !== expectedPrev) {
      chainValid = false;
      break;
    }
    expectedPrev = cp.checkpointHash;
  }

  const evidence = {
    version: 2,
    mode: "standalone",
    trustLevel: "browser-attestation",
    trustDescription: "Browser-based authorship attestation using SHA-256 hash chain with HMAC integrity and keystroke timing entropy. For hardware-backed attestation with Ed25519 signatures and VDF time-proofs, install the WritersProof desktop app.",
    chainIntegrity: chainValid ? "verified" : "broken",
    session: {
      id: session.id,
      url: session.url,
      title: session.title,
      startedAt: session.startedAt,
      endedAt: session.endedAt,
      nonce: session.nonce,
    },
    checkpoints: checkpoints.map((cp) => ({
      ordinal: cp.ordinal,
      timestamp: cp.timestamp,
      contentHash: cp.contentHash,
      charCount: cp.charCount,
      delta: cp.delta,
      flags: cp.flags || 0,
      prevHash: cp.prevHash,
      checkpointHash: cp.checkpointHash,
      jitterBinding: cp.jitterBinding,
      hmacTag: cp.hmacTag,
    })),
    keystrokeJitter: jitterBatches.map((jb) => ({
      timestamp: jb.timestamp,
      intervals: jb.intervals,
      jitterHash: jb.jitterHash,
    })),
    exportSeal: null,
  };

  // HMAC seal over the payload so verifiers can detect post-export tampering.
  // A verifier re-derives the key from session.nonce using DST_HMAC.
  const sealInput = JSON.stringify({
    session: evidence.session,
    checkpoints: evidence.checkpoints,
    keystrokeJitter: evidence.keystrokeJitter,
    chainIntegrity: evidence.chainIntegrity,
  });
  evidence.exportSeal = await hmacSha256Hex(session.nonce, sealInput);

  return evidence;
}

// --- IndexedDB helpers ---

function txComplete(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

function storeGet(store, key) {
  return new Promise((resolve, reject) => {
    const req = store.get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function storeGetAllByIndex(store, indexName, key) {
  return new Promise((resolve, reject) => {
    const req = store.index(indexName).getAll(key);
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}
