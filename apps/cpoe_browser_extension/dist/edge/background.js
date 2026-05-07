/**
 * CPoE Browser Extension — Background Service Worker
 *
 * Operates in two modes:
 *   "native"     — desktop app installed; full evidence with VDF + hardware attestation
 *   "standalone" — no desktop app; lightweight in-browser hash chain via IndexedDB
 *
 * The mode is detected on startup by probing the native messaging host.
 * Users can install the desktop app later to upgrade their evidence quality.
 */

importScripts("standalone.js");
importScripts("secure-channel.js");

const NATIVE_HOST_NAME = "com.writerslogic.witnessd";
const PROTOCOL_VERSION = 1;
const MIN_NATIVE_PROTOCOL_VERSION = 1;
const DEFAULT_CHECKPOINT_INTERVAL_MS = 30_000;
const MIN_CHECKPOINT_INTERVAL_MS = 10_000;
const MAX_CHECKPOINT_INTERVAL_MS = 300_000;
const GENESIS_COMMITMENT_PREFIX = "CPoE-Genesis-v1";
const COMMITMENT_CHAIN_INITIAL_ORDINAL = 2;
const MAX_REHANDSHAKE_ATTEMPTS = 3;

const CONTENT_ACTIONS = new Set([
  "start_witnessing", "stop_witnessing", "content_changed", "keystroke_jitter"
]);
const VALID_ACTIONS = new Set([
  "start_witnessing", "stop_witnessing", "content_changed", "keystroke_jitter",
  "ai_content_copied", "get_status", "popup_connect", "export_evidence", "open_desktop_app"
]);

let nativePort = null;
let isConnected = false;
let isConnecting = false;
let activeTabId = null;
let checkpointTimer = null;

let operatingMode = "detecting";
let standaloneSessionId = null;
let nativeHostVersion = null;
let checkpointIntervalMs = DEFAULT_CHECKPOINT_INTERVAL_MS;
let rehandshakeAttempts = 0;

// Feature capabilities — populated from native host handshake or defaults
let capabilities = {
  hardwareAttestation: false,
  vdfProofs: false,
  secureEnclave: false,
  secureChannel: false,
  ed25519Signatures: false,
  hashChain: true,
  keystrokeJitter: true,
};

let sessionNonce = null;
let prevCommitment = null;
let genesisReady = null;
let checkpointOrdinal = COMMITMENT_CHAIN_INITIAL_ORDINAL;
let devicePublicKey = null;
let secureChannel = null;

function detectNativeHost() {
  operatingMode = "detecting";
  try {
    const probe = chrome.runtime.connectNative(NATIVE_HOST_NAME);
    const timeout = setTimeout(() => {
      probe.disconnect();
      setStandaloneMode();
    }, 2000);

    probe.onMessage.addListener((msg) => {
      clearTimeout(timeout);
      probe.disconnect();

      if (msg && typeof msg.protocol_version === "number") {
        if (msg.protocol_version < MIN_NATIVE_PROTOCOL_VERSION) {
          setStandaloneMode();
          broadcastToPopup({
            type: "error",
            message: "Desktop app is outdated. Please update for full attestation.",
          });
          return;
        }
        nativeHostVersion = msg.version || null;

        // Populate capabilities from host response
        if (msg.capabilities && typeof msg.capabilities === "object") {
          capabilities = { ...capabilities, ...msg.capabilities };
        } else {
          capabilities.hardwareAttestation = true;
          capabilities.vdfProofs = true;
          capabilities.secureEnclave = true;
          capabilities.secureChannel = true;
          capabilities.ed25519Signatures = true;
        }
      }

      operatingMode = "native";
      updateBadge("", "#2ecc71");
    });

    probe.onDisconnect.addListener(() => {
      clearTimeout(timeout);
      if (operatingMode === "detecting") {
        setStandaloneMode();
      }
    });

    probe.postMessage({ type: "ping", protocol_version: PROTOCOL_VERSION });
  } catch (_) {
    setStandaloneMode();
  }
}

function setStandaloneMode() {
  operatingMode = "standalone";
  capabilities = {
    hardwareAttestation: false,
    vdfProofs: false,
    secureEnclave: false,
    secureChannel: false,
    ed25519Signatures: false,
    hashChain: true,
    keystrokeJitter: true,
  };
  updateBadge("S", "#f39c12");
}

function connectToNativeHost() {
  if (nativePort || isConnecting) return;

  isConnecting = true;
  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);

    nativePort.onMessage.addListener((message) => {
      handleNativeMessage(message);
    });

    nativePort.onDisconnect.addListener(() => {
      nativePort = null;
      isConnected = false;
      isConnecting = false;
      secureChannel = null;
      rehandshakeAttempts = 0;

      if (activeTabId && operatingMode === "native") {
        console.warn("[CPoE] Native host disconnected mid-session; switching to standalone mode");
        operatingMode = "standalone";
        capabilities = {
          hardwareAttestation: false,
          vdfProofs: false,
          secureEnclave: false,
          secureChannel: false,
          ed25519Signatures: false,
          hashChain: true,
          keystrokeJitter: true,
        };
        stopCheckpointTimer();
        chrome.tabs.get(activeTabId, (tab) => {
          const url = tab?.url || "";
          const title = tab?.title || "";
          standaloneStartSession(url, title).then((result) => {
            standaloneSessionId = result.session_id;
            chrome.storage.local.set({
              _standaloneSessionId: standaloneSessionId,
              _standaloneTabId: activeTabId,
              _sessionStartTime: Date.now(),
            });
            startCheckpointTimer();
            updateBadge("S", "#f39c12");
            broadcastToPopup({ type: "session_update", ...result, active: true, mode: "standalone" });
          }).catch(() => {
            updateBadge("!", "#e74c3c");
          });
        });
      } else {
        updateBadge("!", "#e74c3c");
      }
    });

    isConnected = true;
    updateBadge("", "#2ecc71");

    sendNativeMessage({ type: "ping", protocol_version: PROTOCOL_VERSION });
  } catch (_) {
    isConnected = false;
    updateBadge("!", "#e74c3c");
  } finally {
    isConnecting = false;
  }
}

function disconnectFromNativeHost() {
  if (nativePort) {
    nativePort.disconnect();
    nativePort = null;
  }
  isConnected = false;
  secureChannel = null;
  updateBadge("", "#95a5a6");
}

function initiateSecureChannel() {
  if (secureChannel) return;
  secureChannel = new SecureChannel();
  secureChannel.performHandshake((msg) => nativePort.postMessage(msg)).catch(() => {
    secureChannel = null;
  });
}

function sendNativeMessage(message) {
  if (!nativePort) connectToNativeHost();
  if (!nativePort) return;

  if (secureChannel && secureChannel.handshakeComplete) {
    secureChannel.encrypt(message).then((envelope) => {
      nativePort.postMessage(envelope);
    }).catch((err) => {
      broadcastToPopup({ type: "error", message: "Secure channel encrypt failed" });
    });
    return;
  }

  nativePort.postMessage(message);
}

function handleNativeMessage(message) {
  if (!message || typeof message !== "object" || typeof message.type !== "string") {
    return;
  }

  switch (message.type) {
    case "pong":
      isConnected = true;
      if (typeof message.protocol_version === "number") {
        nativeHostVersion = message.version || null;
      }
      updateBadge("", "#2ecc71");
      initiateSecureChannel();
      break;

    case "hello_accept":
      if (secureChannel && !secureChannel.handshakeComplete && secureChannel._handshakeResolve) {
        secureChannel.handleHelloAccept(message, (msg) => nativePort.postMessage(msg))
          .then(() => { capabilities.secureChannel = true; })
          .catch(() => { secureChannel = null; });
      }
      break;

    case "key_confirmed":
      break;

    case "encrypted":
      if (secureChannel && secureChannel.handshakeComplete) {
        secureChannel.decrypt(message).then((inner) => {
          rehandshakeAttempts = 0;
          handleNativeMessage(inner);
        }).catch((err) => {
          const msg = err?.message || "";
          const isDesync = msg.includes("Ratchet count desync")
            || msg.includes("Sequence mismatch")
            || msg.includes("decrypt");
          if (isDesync && nativePort && rehandshakeAttempts < MAX_REHANDSHAKE_ATTEMPTS) {
            rehandshakeAttempts++;
            console.warn(
              `[CPoE] Secure channel decrypt failed (attempt ${rehandshakeAttempts}/${MAX_REHANDSHAKE_ATTEMPTS}), re-handshaking: ${msg}`
            );
            secureChannel.destroy();
            secureChannel = new SecureChannel();
            secureChannel.performHandshake((m) => nativePort.postMessage(m)).catch(() => {
              secureChannel = null;
            });
          } else if (rehandshakeAttempts >= MAX_REHANDSHAKE_ATTEMPTS) {
            console.error("[CPoE] Secure channel re-handshake limit reached; falling back to plaintext");
            secureChannel.destroy();
            secureChannel = null;
            rehandshakeAttempts = 0;
          }
        });
      }
      break;

    case "session_started":
      if (message.session_nonce) {
        sessionNonce = message.session_nonce;
        checkpointOrdinal = COMMITMENT_CHAIN_INITIAL_ORDINAL;
        devicePublicKey = message.device_public_key || null;
        genesisReady = computeGenesisCommitment(message.session_nonce)
          .then((genesis) => { prevCommitment = genesis; })
          .catch(() => { prevCommitment = null; });
      }
      updateBadge("\u2713", "#2ecc71");
      broadcastToPopup({ type: "session_update", session_id: message.session_id, session_nonce: message.session_nonce, device_public_key: message.device_public_key, checkpoint_count: message.checkpoint_count });
      break;

    case "checkpoint_created":
      if (message.commitment) {
        prevCommitment = message.commitment;
      }
      if (message.document_url && message.content_hash) {
        sendNativeMessage({
          type: "snapshot_save",
          document_url: message.document_url,
          content_hash: message.content_hash,
          char_count: message.char_count || 0,
        });
      }
      updateBadge(String(message.checkpoint_count), "#2ecc71");
      broadcastToPopup({ type: "checkpoint_update", hash: message.hash, checkpoint_count: message.checkpoint_count, commitment: message.commitment });
      break;

    case "session_stopped":
      sessionNonce = null;
      prevCommitment = null;
      genesisReady = null;
      checkpointOrdinal = COMMITMENT_CHAIN_INITIAL_ORDINAL;
      devicePublicKey = null;
      updateBadge("", "#95a5a6");
      stopCheckpointTimer();
      broadcastToPopup({ type: "session_update", active: false });
      break;

    case "status":
      broadcastToPopup({ type: "status_update", initialized: message.initialized, active_session: message.active_session, checkpoint_count: message.checkpoint_count, tracked_files: message.tracked_files });
      break;

    case "jitter_received":
      break;

    case "error":
      broadcastToPopup({
        type: "error",
        message: sanitizeErrorMessage(message.message),
        code: message.code,
      });
      break;

    default:
      break;
  }
}

const ALLOWED_ORIGINS = [
  /^https:\/\/docs\.google\.com\//,
  /^https:\/\/(www\.)?overleaf\.com\//,
  /^https:\/\/medium\.com\//,
  /^https:\/\/(www\.)?notion\.so\//,
  /^https:\/\/(www\.)?craft\.do\//,
  /^https:\/\/coda\.io\//,
  /^https:\/\/app\.clickup\.com\//,
  /^https:\/\/app\.nuclino\.com\//,
  /^https:\/\/stackedit\.io\//,
  /^https:\/\/hackmd\.io\//,
  /^https:\/\/hemingwayapp\.com\//,
  /^https:\/\/quillbot\.com\//,
  /^https:\/\/prosemirror\.net\//,
  /^https:\/\/[^/]*\.?etherpad\.org\//,
  /^https:\/\/pad\.riseup\.net\//,
  /^https:\/\/write\.as\//,
  /^https:\/\/[^/]*\.?wordpress\.com\//,
  /^https:\/\/[^/]*\.?ghost\.io\//,
  /^https:\/\/[^/]*\.?substack\.com\//,
];

let customDomainList = [];

function loadCustomDomains() {
  chrome.storage.local.get(["customDomains"], (result) => {
    customDomainList = (result.customDomains || [])
      .filter((d) => typeof d === "string" && d.length > 0);
  });
}

function matchesCustomDomain(url) {
  let hostname;
  try { hostname = new URL(url).hostname; } catch { return false; }
  for (const domain of customDomainList) {
    if (domain.startsWith("*.")) {
      const suffix = domain.slice(2);
      if (hostname === suffix || hostname.endsWith("." + suffix)) return true;
    } else {
      if (hostname === domain) return true;
    }
  }
  return false;
}

const CUSTOM_SCRIPT_ID = "cpoe-custom-domains";

function syncCustomContentScripts(domains) {
  if (!domains || domains.length === 0) {
    chrome.scripting.unregisterContentScripts({ ids: [CUSTOM_SCRIPT_ID] }).catch(() => {});
    return;
  }
  const patterns = domains.map((d) => `https://${d.replace(/\*/g, "*")}/*`);
  chrome.scripting.unregisterContentScripts({ ids: [CUSTOM_SCRIPT_ID] }).catch(() => {}).then(() => {
    chrome.scripting.registerContentScripts([{
      id: CUSTOM_SCRIPT_ID,
      matches: patterns,
      js: ["content.js"],
      runAt: "document_idle",
    }]).catch(() => {});
  });
}

chrome.storage.onChanged.addListener((changes) => {
  if (changes.customDomains) {
    loadCustomDomains();
    syncCustomContentScripts(changes.customDomains.newValue || []);
  }
  if (changes.checkpointInterval) {
    const raw = changes.checkpointInterval.newValue;
    const ms = typeof raw === "number"
      ? Math.max(MIN_CHECKPOINT_INTERVAL_MS, Math.min(MAX_CHECKPOINT_INTERVAL_MS, raw * 1000))
      : DEFAULT_CHECKPOINT_INTERVAL_MS;
    checkpointIntervalMs = ms;
    if (checkpointTimer) {
      startCheckpointTimer();
    }
  }
});

loadCustomDomains();
chrome.storage.local.get(["customDomains", "checkpointInterval"], (result) => {
  syncCustomContentScripts(result.customDomains || []);
  if (typeof result.checkpointInterval === "number") {
    checkpointIntervalMs = Math.max(
      MIN_CHECKPOINT_INTERVAL_MS,
      Math.min(MAX_CHECKPOINT_INTERVAL_MS, result.checkpointInterval * 1000)
    );
  }
});

function isAllowedOrigin(url) {
  return ALLOWED_ORIGINS.some((re) => re.test(url)) ||
    matchesCustomDomain(url);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object" || typeof message.action !== "string") {
    sendResponse({ ok: false, error: "Malformed message" });
    return true;
  }

  if (!VALID_ACTIONS.has(message.action)) {
    sendResponse({ ok: false, error: "Unknown action" });
    return true;
  }

  if (sender.id !== chrome.runtime.id) {
    sendResponse({ ok: false, error: "Unauthorized sender" });
    return true;
  }

  if (CONTENT_ACTIONS.has(message.action)) {
    const tabUrl = sender.tab?.url || sender.url || "";
    if (!sender.tab || !isAllowedOrigin(tabUrl)) {
      sendResponse({ ok: false, error: "Unauthorized origin" });
      return true;
    }
  }

  if (message.action === "ai_content_copied") {
    if (!sender.tab) {
      sendResponse({ ok: false, error: "Unauthorized sender" });
      return true;
    }
  }

  if (operatingMode === "standalone") {
    handleStandaloneAction(message, sender, sendResponse);
    return true;
  }

  switch (message.action) {
    case "start_witnessing":
      {
        const url = message.url;
        if (typeof url !== "string" || !isAllowedOrigin(url)) {
          sendResponse({ ok: false, error: "Invalid document URL" });
          break;
        }
        connectToNativeHost();
        sendNativeMessage({
          type: "start_session",
          document_url: url,
          document_title: typeof message.title === "string" ? message.title : "",
          timer_resolution_ms: typeof message.timerResolution === "number" ? message.timerResolution : 0,
        });
        activeTabId = sender.tab?.id;
        startCheckpointTimer();
        sendResponse({ ok: true, mode: "native" });
      }
      break;

    case "stop_witnessing":
      sendNativeMessage({ type: "stop_session" });
      activeTabId = null;
      stopCheckpointTimer();
      sendResponse({ ok: true, mode: "native" });
      break;

    case "content_changed":
      {
        const ordinal = checkpointOrdinal;
        const checkpointMsg = {
          type: "checkpoint",
          content_hash: message.contentHash,
          char_count: message.charCount,
          delta: message.delta,
          ordinal,
          tool_category: message.toolCategory || "none",
          tool_host: message.toolHost || "",
        };
        checkpointOrdinal++;
        const ready = genesisReady || Promise.resolve();
        ready.then(() => {
          if (prevCommitment && sessionNonce) {
            return computeCommitment(prevCommitment, message.contentHash, ordinal, sessionNonce)
              .then((commitment) => {
                checkpointMsg.commitment = commitment;
                sendNativeMessage(checkpointMsg);
                sendResponse({ ok: true, mode: "native" });
              });
          }
          console.warn("[CPoE] Checkpoint sent without commitment (genesis failed or session nonce missing)");
          sendNativeMessage(checkpointMsg);
          sendResponse({ ok: true, mode: "native", commitment_missing: true });
        }).catch((err) => {
          console.error("[CPoE] Commitment computation failed:", err?.message || err);
          sendResponse({ ok: false, error: "Commitment failed" });
        });
      }
      return true;

    case "keystroke_jitter":
      sendNativeMessage({
        type: "inject_jitter",
        intervals: message.intervals,
      });
      sendResponse({ ok: true });
      break;

    case "ai_content_copied":
      sendNativeMessage({
        type: "ai_content_copied",
        source: message.source,
        char_count: message.charCount,
        timestamp: message.timestamp,
      });
      sendResponse({ ok: true });
      break;

    case "get_status":
      sendNativeMessage({ type: "get_status" });
      sendResponse({ ok: true, connected: isConnected, mode: "native", capabilities });
      break;

    case "popup_connect":
      sendNativeMessage({ type: "get_status" });
      sendResponse({ ok: true, connected: isConnected, mode: "native", capabilities });
      break;

    case "export_evidence":
      sendResponse({ ok: false, error: "Export not available in native mode; use the desktop app" });
      break;

    case "open_desktop_app":
      sendNativeMessage({ type: "open_view", view: message.view || "main" });
      sendResponse({ ok: true });
      break;

    default:
      sendResponse({ ok: false, error: "Unknown action" });
  }

  return true;
});

function startCheckpointTimer() {
  stopCheckpointTimer();
  checkpointTimer = setInterval(() => {
    if (activeTabId) {
      chrome.tabs.sendMessage(activeTabId, { action: "capture_state" }).catch(() => {
        stopCheckpointTimer();
      });
    }
  }, checkpointIntervalMs);
}

function stopCheckpointTimer() {
  if (checkpointTimer) {
    clearInterval(checkpointTimer);
    checkpointTimer = null;
  }
}

function updateBadge(text, color) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

function broadcastToPopup(message) {
  chrome.runtime.sendMessage(message).catch(() => {});
}

function sanitizeErrorMessage(raw) {
  if (typeof raw !== "string") return "Unknown error";
  const cleaned = raw.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
  if (cleaned.length > 200) {
    return cleaned.slice(0, 200) + "\u2026";
  }
  return cleaned || "Unknown error";
}

// Pre-allocated lookup table for hex encoding
const HEX = [];
for (let i = 0; i < 256; i++) HEX[i] = i.toString(16).padStart(2, "0");

async function computeGenesisCommitment(sessionNonceHex) {
  const prefix = new TextEncoder().encode(GENESIS_COMMITMENT_PREFIX);
  const nonce = hexToBytes(sessionNonceHex);
  const combined = new Uint8Array(prefix.length + nonce.length);
  combined.set(prefix, 0);
  combined.set(nonce, prefix.length);
  const hashBuf = await crypto.subtle.digest("SHA-256", combined);
  return bytesToHex(new Uint8Array(hashBuf));
}

async function computeCommitment(prevCommitmentHex, contentHash, ordinal, sessionNonceHex) {
  const prev = hexToBytes(prevCommitmentHex);
  const nonce = hexToBytes(sessionNonceHex);
  const contentBytes = new TextEncoder().encode(contentHash);

  const ordinalBuf = new ArrayBuffer(8);
  const ordinalView = new DataView(ordinalBuf);
  ordinalView.setUint32(0, ordinal & 0xffffffff, true);
  ordinalView.setUint32(4, Math.floor(ordinal / 0x100000000), true);
  const ordinalBytes = new Uint8Array(ordinalBuf);

  // Must match Rust compute_commitment: H(prev || content_hash || ordinal_le || nonce)
  const combined = new Uint8Array(prev.length + contentBytes.length + 8 + nonce.length);
  let offset = 0;
  combined.set(prev, offset); offset += prev.length;
  combined.set(contentBytes, offset); offset += contentBytes.length;
  combined.set(ordinalBytes, offset); offset += 8;
  combined.set(nonce, offset);

  const hashBuf = await crypto.subtle.digest("SHA-256", combined);
  return bytesToHex(new Uint8Array(hashBuf));
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

function bytesToHex(bytes) {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += HEX[bytes[i]];
  return hex;
}

async function handleStandaloneAction(message, sender, sendResponse) {
  let responded = false;
  const respond = (data) => { if (!responded) { responded = true; sendResponse(data); } };
  try {
    return await handleStandaloneActionInner(message, sender, respond);
  } catch (err) {
    const msg = err?.name === "QuotaExceededError"
      ? "Storage full. Evidence cannot be saved. Free up browser storage or install the desktop app."
      : "Evidence storage error. Try restarting the browser.";
    broadcastToPopup({ type: "error", message: msg });
    respond({ ok: false, error: msg });
  }
}

async function handleStandaloneActionInner(message, sender, sendResponse) {
  switch (message.action) {
    case "start_witnessing":
      {
        const result = await standaloneStartSession(
          message.url || sender.tab?.url || "",
          message.title || ""
        );
        standaloneSessionId = result.session_id;
        activeTabId = sender.tab?.id;
        await chrome.storage.local.set({
          _standaloneSessionId: standaloneSessionId,
          _standaloneTabId: activeTabId,
          _sessionStartTime: Date.now(),
        });
        startCheckpointTimer();
        updateBadge("\u2713", "#f39c12");
        broadcastToPopup({ type: "session_update", ...result, active: true });
        sendResponse({ ok: true, mode: "standalone", session_id: result.session_id });
      }
      break;

    case "stop_witnessing":
      {
        const result = await standaloneStopSession(standaloneSessionId);
        activeTabId = null;
        standaloneSessionId = null;
        await chrome.storage.local.remove(["_standaloneSessionId", "_standaloneTabId", "_sessionStartTime"]);
        stopCheckpointTimer();
        updateBadge("S", "#f39c12");
        broadcastToPopup({ type: "session_update", active: false, ...result });
        sendResponse({ ok: true, mode: "standalone" });
      }
      break;

    case "content_changed":
      {
        if (!standaloneSessionId) {
          sendResponse({ ok: false, error: "No active standalone session" });
          break;
        }
        const result = await standaloneCheckpoint(
          standaloneSessionId,
          message.contentHash,
          message.charCount,
          message.delta,
          message.toolCategory,
          message.toolHost
        );
        if (result.type === "error") {
          sendResponse({ ok: false, error: result.message });
        } else {
          updateBadge(String(result.checkpoint_count), "#f39c12");
          broadcastToPopup({ type: "checkpoint_update", ...result });
          sendResponse({ ok: true, mode: "standalone" });
        }
      }
      break;

    case "keystroke_jitter":
      if (standaloneSessionId && message.intervals) {
        await standaloneRecordJitter(standaloneSessionId, message.intervals);
      }
      sendResponse({ ok: true, mode: "standalone" });
      break;

    case "ai_content_copied":
      if (standaloneSessionId) {
        await standaloneRecordAiCopy(standaloneSessionId, message.source, message.charCount, message.timestamp);
      }
      sendResponse({ ok: true, mode: "standalone" });
      break;

    case "get_status":
    case "popup_connect":
      {
        const status = await standaloneGetStatus(standaloneSessionId);
        broadcastToPopup({ type: "status_update", ...status });
        sendResponse({ ok: true, mode: "standalone", connected: false, capabilities, ...status });
      }
      break;

    case "export_evidence":
      {
        if (!message.sessionId && !standaloneSessionId) {
          sendResponse({ ok: false, error: "No session to export" });
          break;
        }
        const evidence = await standaloneExportEvidence(
          message.sessionId || standaloneSessionId
        );
        if (evidence) {
          sendResponse({ ok: true, mode: "standalone", evidence });
        } else {
          sendResponse({ ok: false, error: "Session not found" });
        }
      }
      break;

    default:
      sendResponse({ ok: false, error: "Unknown action" });
  }
}

chrome.runtime.onInstalled.addListener(() => {
  detectNativeHost();
});

detectNativeHost();

chrome.storage.local.get(["_standaloneSessionId", "_standaloneTabId"], (result) => {
  if (result._standaloneSessionId) {
    standaloneSessionId = result._standaloneSessionId;
    activeTabId = result._standaloneTabId || null;
    if (activeTabId) {
      startCheckpointTimer();
    }
  }
});

// Gracefully stop active sessions before extension update takes effect.
chrome.runtime.onUpdateAvailable.addListener(() => {
  if (standaloneSessionId) {
    standaloneStopSession(standaloneSessionId).then(() => {
      chrome.storage.local.remove(["_standaloneSessionId", "_standaloneTabId", "_sessionStartTime"]);
      chrome.runtime.reload();
    });
  } else if (operatingMode === "native" && activeTabId) {
    sendNativeMessage({ type: "stop_session" });
    chrome.runtime.reload();
  } else {
    chrome.runtime.reload();
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  if (tabId === activeTabId) {
    if (operatingMode === "native") {
      sendNativeMessage({ type: "stop_session" });
    } else if (standaloneSessionId) {
      await standaloneStopSession(standaloneSessionId);
    }
    activeTabId = null;
    standaloneSessionId = null;
    sessionNonce = null;
    prevCommitment = null;
    checkpointOrdinal = COMMITMENT_CHAIN_INITIAL_ORDINAL;
    stopCheckpointTimer();
    chrome.storage.local.remove(["_standaloneSessionId", "_standaloneTabId", "_sessionStartTime"]);
    updateBadge(operatingMode === "standalone" ? "S" : "", "#95a5a6");
  }
});

// ---------------------------------------------------------------------------
// Text Attestation — right-click context menu
// ---------------------------------------------------------------------------

const ATTEST_MENU_ID = "writersproof-attest-text";
const ATTEST_DB_NAME = "writersproof-attestations";
const ATTEST_STORE_NAME = "text_attestations";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: ATTEST_MENU_ID,
    title: "Attest Authorship with WritersProof",
    contexts: ["selection"],
  });
});

/**
 * NFC-normalize text for attestation: keep only Unicode letters + ASCII
 * digits, lowercase everything. Must match Rust normalize_for_attestation().
 */
function normalizeForAttestation(text) {
  const nfc = text.normalize("NFC");
  let result = "";
  for (const ch of nfc) {
    const code = ch.codePointAt(0);
    if (code >= 0x30 && code <= 0x39) {
      result += ch;
    } else if (/\p{Letter}/u.test(ch)) {
      result += ch.toLowerCase();
    }
  }
  return result;
}

async function attestHashText(text) {
  const data = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(buf));
}

async function persistAttestation(record) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(ATTEST_DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(ATTEST_STORE_NAME)) {
        db.createObjectStore(ATTEST_STORE_NAME, { keyPath: "content_hash" });
      }
    };
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction(ATTEST_STORE_NAME, "readwrite");
      tx.objectStore(ATTEST_STORE_NAME).put(record);
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    };
    req.onerror = () => reject(req.error);
  });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== ATTEST_MENU_ID) return;
  const selectedText = info.selectionText;
  if (!selectedText || !selectedText.trim()) return;

  const normalized = normalizeForAttestation(selectedText);
  if (!normalized) {
    notifyTab(tab.id, "No attestable content (letters/digits only).");
    return;
  }

  const hash = await attestHashText(normalized);
  const wpId = hash.slice(0, 8);
  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

  let tier = "declared";
  if (operatingMode === "native" && isConnected && activeTabId === tab.id) {
    tier = "verified";
  } else if (standaloneSessionId && activeTabId === tab.id) {
    tier = "corroborated";
  }

  const tierLabels = { verified: "Verified", corroborated: "Corroborated", declared: "Declared" };
  const tierDescs = {
    verified: "Cryptographic authorship attestation with keystroke evidence.",
    corroborated: "Authorship attestation, sentinel active during authoring.",
    declared: "Signed author declaration.",
  };

  const attestationBlock =
    `WritersProof ${tierLabels[tier]} | ID: ${wpId} | ${timestamp}\n` +
    `${tierDescs[tier]}\n` +
    `verify.writersproof.com`;

  // Copy attestation block to clipboard via content script.
  let clipboardOk = false;
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: async (block) => {
        try {
          await navigator.clipboard.writeText(block);
          return true;
        } catch {
          return false;
        }
      },
      args: [attestationBlock],
    });
    clipboardOk = results?.[0]?.result === true;
  } catch (e) {
    console.warn("Clipboard write failed:", e);
  }

  // Persist to IndexedDB so attestation survives browser restart.
  try {
    await persistAttestation({
      content_hash: hash,
      writersproof_id: wpId,
      tier,
      attested_at: timestamp,
      synced: false,
      source_url: tab.url || "",
      source_title: tab.title || "",
    });
  } catch (e) {
    console.warn("Failed to persist attestation:", e);
  }

  // Sync via native messaging if desktop app connected (it has signing key + auth).
  let synced = false;
  if (operatingMode === "native" && isConnected) {
    sendNativeMessage({
      type: "text_attestation",
      content_hash: hash,
      tier,
      writersproof_id: wpId,
      attested_at: timestamp,
      app_bundle_id: tab.url ? new URL(tab.url).hostname : "",
    });
    synced = true;
  }

  let msg = `Attestation copied (${tierLabels[tier]}).`;
  if (!synced) {
    msg += " Install the desktop app to enable online verification.";
  } else {
    msg += " Paste after your text.";
  }
  if (!clipboardOk) {
    msg = `Attestation created (${tierLabels[tier]}) but clipboard access was denied.`;
  }
  notifyTab(tab.id, msg);
});

function notifyTab(tabId, message) {
  if (!tabId) return;
  chrome.scripting.executeScript({
    target: { tabId },
    func: (msg) => {
      const existing = document.getElementById("writersproof-toast");
      if (existing) existing.remove();
      const d = document.createElement("div");
      d.id = "writersproof-toast";
      d.textContent = msg;
      Object.assign(d.style, {
        position: "fixed", bottom: "20px", right: "20px", zIndex: "2147483647",
        background: "#1a1a2e", color: "#2dd4bf", padding: "12px 20px",
        borderRadius: "8px", fontSize: "14px", fontFamily: "system-ui, sans-serif",
        boxShadow: "0 4px 12px rgba(0,0,0,0.3)", maxWidth: "400px",
        opacity: "0", transition: "opacity 0.3s",
      });
      document.body.appendChild(d);
      requestAnimationFrame(() => { d.style.opacity = "1"; });
      setTimeout(() => {
        d.style.opacity = "0";
        setTimeout(() => d.remove(), 300);
      }, 4000);
    },
    args: [message],
  }).catch(() => {});
}
