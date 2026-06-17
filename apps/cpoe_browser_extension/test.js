/**
 * CPoE Browser Extension — Unit Tests
 *
 * Tests crypto-critical utility functions that must produce identical output
 * to the Rust native host. Run with: node test.js
 *
 * Requires Node.js 20+ (Web Crypto API available as globalThis.crypto).
 */

const { subtle } = globalThis.crypto;
const { TextEncoder, TextDecoder } = globalThis;

let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, name) {
	if (condition) {
		passed++;
	} else {
		failed++;
		failures.push(name);
		console.error(`  FAIL: ${name}`);
	}
}

function assertEq(actual, expected, name) {
	if (actual === expected) {
		passed++;
	} else {
		failed++;
		failures.push(name);
		console.error(`  FAIL: ${name} — expected ${expected}, got ${actual}`);
	}
}

function assertArrayEq(actual, expected, name) {
	const a = Array.from(actual);
	const b = Array.from(expected);
	if (a.length === b.length && a.every((v, i) => v === b[i])) {
		passed++;
	} else {
		failed++;
		failures.push(name);
		console.error(`  FAIL: ${name} — arrays differ`);
		console.error(`    expected: [${b.join(",")}]`);
		console.error(`    actual:   [${a.join(",")}]`);
	}
}

function assertThrows(fn, name) {
	try {
		fn();
		failed++;
		failures.push(name);
		console.error(`  FAIL: ${name} — expected throw, got none`);
	} catch {
		passed++;
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Functions under test (copied to avoid import issues with browser globals)
// ═══════════════════════════════════════════════════════════════════════════

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
	bytes[0] = n & 0xff;
	bytes[1] = (n >> 8) & 0xff;
	bytes[2] = (n >> 16) & 0xff;
	bytes[3] = (n >>> 24) & 0xff;
	const high = Math.floor(n / 0x100000000);
	bytes[4] = high & 0xff;
	bytes[5] = (high >> 8) & 0xff;
	bytes[6] = (high >> 16) & 0xff;
	bytes[7] = (high >>> 24) & 0xff;
	return bytes;
}

function leToUint64(bytes) {
	const low =
		(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>>
		0;
	const high =
		(bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24)) >>>
		0;
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

function constantTimeEqual(a, b) {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff === 0;
}

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

const GENESIS_COMMITMENT_PREFIX = "CPoE-Genesis-v1";

function hexToBytes(hex) {
	if (
		typeof hex !== "string" ||
		hex.length % 2 !== 0 ||
		!/^[0-9a-fA-F]*$/.test(hex)
	) {
		throw new Error("Invalid hex string");
	}
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
	}
	return bytes;
}

function bytesToHex(bytes) {
	const HEX = [];
	for (let i = 0; i < 256; i++) HEX[i] = i.toString(16).padStart(2, "0");
	let hex = "";
	for (let i = 0; i < bytes.length; i++) hex += HEX[bytes[i]];
	return hex;
}

async function computeGenesisCommitment(sessionNonceHex) {
	const prefix = new TextEncoder().encode(GENESIS_COMMITMENT_PREFIX);
	const nonce = hexToBytes(sessionNonceHex);
	const combined = new Uint8Array(prefix.length + nonce.length);
	combined.set(prefix, 0);
	combined.set(nonce, prefix.length);
	const hashBuf = await subtle.digest("SHA-256", combined);
	return bytesToHex(new Uint8Array(hashBuf));
}

async function computeCommitment(
	prevCommitmentHex,
	contentHash,
	ordinal,
	sessionNonceHex,
) {
	const prev = hexToBytes(prevCommitmentHex);
	const nonce = hexToBytes(sessionNonceHex);
	const contentBytes = new TextEncoder().encode(contentHash);

	const ordinalBuf = new ArrayBuffer(8);
	const ordinalView = new DataView(ordinalBuf);
	ordinalView.setUint32(0, ordinal & 0xffffffff, true);
	ordinalView.setUint32(4, Math.floor(ordinal / 0x100000000), true);
	const ordinalBytes = new Uint8Array(ordinalBuf);

	const combined = new Uint8Array(
		prev.length + contentBytes.length + 8 + nonce.length,
	);
	let offset = 0;
	combined.set(prev, offset);
	offset += prev.length;
	combined.set(contentBytes, offset);
	offset += contentBytes.length;
	combined.set(ordinalBytes, offset);
	offset += 8;
	combined.set(nonce, offset);

	const hashBuf = await subtle.digest("SHA-256", combined);
	return bytesToHex(new Uint8Array(hashBuf));
}

async function sha256Hex(data) {
	const encoded =
		typeof data === "string" ? new TextEncoder().encode(data) : data;
	const hash = await subtle.digest("SHA-256", encoded);
	const arr = new Uint8Array(hash);
	const SA_HEX = [];
	for (let i = 0; i < 256; i++) SA_HEX[i] = i.toString(16).padStart(2, "0");
	let hex = "";
	for (let i = 0; i < arr.length; i++) hex += SA_HEX[arr[i]];
	return hex;
}

const VALID_SHA256_RE = /^[0-9a-f]{64}$/;
function isValidContentHash(hash) {
	return typeof hash === "string" && VALID_SHA256_RE.test(hash);
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

async function runTests() {
	console.log("=== CPoE Browser Extension Unit Tests ===\n");

	// --- Hex encoding/decoding ---
	console.log("--- hex encoding ---");

	assertEq(uint8ToHex(new Uint8Array([0])), "00", "hex: zero byte");
	assertEq(uint8ToHex(new Uint8Array([255])), "ff", "hex: 0xff");
	assertEq(
		uint8ToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef])),
		"deadbeef",
		"hex: deadbeef",
	);
	assertEq(uint8ToHex(new Uint8Array([])), "", "hex: empty");

	assertArrayEq(
		hexToUint8("deadbeef"),
		[0xde, 0xad, 0xbe, 0xef],
		"unhex: deadbeef",
	);
	assertArrayEq(hexToUint8("00ff"), [0, 255], "unhex: 00ff");
	assertArrayEq(hexToUint8("AABB"), [0xaa, 0xbb], "unhex: uppercase");
	assertThrows(() => hexToUint8(""), "unhex: empty throws");
	assertThrows(() => hexToUint8("0"), "unhex: odd length throws");
	assertThrows(() => hexToUint8("zz"), "unhex: non-hex throws");

	// Roundtrip
	const original = new Uint8Array([1, 127, 128, 255, 0]);
	assertArrayEq(hexToUint8(uint8ToHex(original)), original, "hex roundtrip");

	// --- Base64 encoding/decoding ---
	console.log("--- base64 encoding ---");

	const testBytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
	assertEq(uint8ToBase64(testBytes), "SGVsbG8=", "b64: Hello");
	assertArrayEq(base64ToUint8("SGVsbG8="), testBytes, "b64 decode: Hello");
	assertThrows(() => base64ToUint8(""), "b64: empty throws");
	assertThrows(() => base64ToUint8("!!!"), "b64: invalid throws");

	// Roundtrip with binary data
	const binaryData = new Uint8Array(256);
	for (let i = 0; i < 256; i++) binaryData[i] = i;
	assertArrayEq(
		base64ToUint8(uint8ToBase64(binaryData)),
		binaryData,
		"b64 roundtrip: all byte values",
	);

	// --- Integer encoding ---
	console.log("--- integer encoding ---");

	assertArrayEq(uint32ToLE(0), [0, 0, 0, 0], "u32le: 0");
	assertArrayEq(uint32ToLE(1), [1, 0, 0, 0], "u32le: 1");
	assertArrayEq(uint32ToLE(256), [0, 1, 0, 0], "u32le: 256");
	assertArrayEq(
		uint32ToLE(0xdeadbeef),
		[0xef, 0xbe, 0xad, 0xde],
		"u32le: deadbeef",
	);
	assertArrayEq(uint32ToLE(0xffffffff), [255, 255, 255, 255], "u32le: max");

	assertArrayEq(uint64ToLE(0), [0, 0, 0, 0, 0, 0, 0, 0], "u64le: 0");
	assertArrayEq(uint64ToLE(1), [1, 0, 0, 0, 0, 0, 0, 0], "u64le: 1");
	assertArrayEq(
		uint64ToLE(0xffffffff),
		[255, 255, 255, 255, 0, 0, 0, 0],
		"u64le: u32 max",
	);
	assertArrayEq(
		uint64ToLE(0x100000000),
		[0, 0, 0, 0, 1, 0, 0, 0],
		"u64le: 2^32",
	);
	// 0x0001020304050607 = 283686952306183 (within MAX_SAFE_INTEGER)
	assertArrayEq(
		uint64ToLE(0x0001020304050607),
		[7, 6, 5, 4, 3, 2, 1, 0],
		"u64le: multi-byte value",
	);

	// Roundtrip
	assertEq(leToUint64(uint64ToLE(0)), 0, "u64 roundtrip: 0");
	assertEq(leToUint64(uint64ToLE(1)), 1, "u64 roundtrip: 1");
	assertEq(
		leToUint64(uint64ToLE(0xffffffff)),
		0xffffffff,
		"u64 roundtrip: u32 max",
	);
	assertEq(
		leToUint64(uint64ToLE(0x100000000)),
		0x100000000,
		"u64 roundtrip: 2^32",
	);
	// Test with realistic timestamp
	const ts = 1719532800000; // 2024-06-28T00:00:00Z
	assertEq(leToUint64(uint64ToLE(ts)), ts, "u64 roundtrip: timestamp");

	// --- concatBytes ---
	console.log("--- concatBytes ---");

	assertArrayEq(
		concatBytes(new Uint8Array([1, 2]), new Uint8Array([3, 4])),
		[1, 2, 3, 4],
		"concat: two arrays",
	);
	assertArrayEq(
		concatBytes(
			new Uint8Array([1]),
			new Uint8Array([2]),
			new Uint8Array([3]),
		),
		[1, 2, 3],
		"concat: three arrays",
	);
	assertArrayEq(
		concatBytes(new Uint8Array([]), new Uint8Array([1])),
		[1],
		"concat: empty + non-empty",
	);
	assertArrayEq(concatBytes(), [], "concat: no args");

	// --- constantTimeEqual ---
	console.log("--- constantTimeEqual ---");

	assert(
		constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])),
		"cte: equal arrays",
	);
	assert(
		!constantTimeEqual(
			new Uint8Array([1, 2, 3]),
			new Uint8Array([1, 2, 4]),
		),
		"cte: differ at end",
	);
	assert(
		!constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2])),
		"cte: different lengths",
	);
	assert(
		constantTimeEqual(new Uint8Array([]), new Uint8Array([])),
		"cte: both empty",
	);
	assert(
		!constantTimeEqual(new Uint8Array([0]), new Uint8Array([1])),
		"cte: single byte differ",
	);
	// All zeros vs all zeros
	const z32 = new Uint8Array(32);
	assert(constantTimeEqual(z32, z32), "cte: 32-byte zeros");
	// Differ in one bit
	const z32copy = new Uint8Array(32);
	z32copy[15] = 1;
	assert(!constantTimeEqual(z32, z32copy), "cte: 32-byte one bit diff");

	// --- normalizeForAttestation ---
	console.log("--- normalizeForAttestation ---");

	assertEq(
		normalizeForAttestation("Hello World"),
		"helloworld",
		"norm: basic",
	);
	assertEq(
		normalizeForAttestation("Hello, World! 123"),
		"helloworld123",
		"norm: punctuation stripped",
	);
	assertEq(normalizeForAttestation(""), "", "norm: empty");
	assertEq(normalizeForAttestation("!!!@#$%"), "", "norm: all punctuation");
	assertEq(
		normalizeForAttestation("ABC123"),
		"abc123",
		"norm: uppercase + digits",
	);
	assertEq(normalizeForAttestation("café"), "café", "norm: accented");
	assertEq(
		normalizeForAttestation("日本語テスト"),
		"日本語テスト",
		"norm: CJK",
	);
	assertEq(
		normalizeForAttestation("Stra\u00DFe"),
		"straße",
		"norm: German eszett",
	);
	// NFC normalization: e + combining acute = é
	assertEq(
		normalizeForAttestation("e\u0301"),
		normalizeForAttestation("\u00e9"),
		"norm: NFC combining char",
	);

	// --- isValidContentHash ---
	console.log("--- isValidContentHash ---");

	assert(isValidContentHash("a".repeat(64)), "hash: valid 64 hex");
	assert(
		isValidContentHash("0123456789abcdef".repeat(4)),
		"hash: valid mixed hex",
	);
	assert(!isValidContentHash("A".repeat(64)), "hash: uppercase rejected");
	assert(!isValidContentHash("a".repeat(63)), "hash: too short");
	assert(!isValidContentHash("a".repeat(65)), "hash: too long");
	assert(!isValidContentHash(""), "hash: empty");
	assert(!isValidContentHash(null), "hash: null");
	assert(!isValidContentHash(123), "hash: number");
	assert(!isValidContentHash("g".repeat(64)), "hash: non-hex chars");

	// --- SHA-256 ---
	console.log("--- SHA-256 ---");

	const emptyHash = await sha256Hex("");
	assertEq(
		emptyHash,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"sha256: empty string",
	);

	const helloHash = await sha256Hex("hello");
	assertEq(
		helloHash,
		"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		"sha256: hello",
	);

	// --- Genesis commitment ---
	console.log("--- genesis commitment ---");

	const testNonce = "00".repeat(16);
	const genesis = await computeGenesisCommitment(testNonce);
	assertEq(genesis.length, 64, "genesis: correct length");
	assert(isValidContentHash(genesis), "genesis: valid hex");

	// Deterministic: same nonce → same genesis
	const genesis2 = await computeGenesisCommitment(testNonce);
	assertEq(genesis, genesis2, "genesis: deterministic");

	// Different nonce → different genesis
	const genesis3 = await computeGenesisCommitment("ff".repeat(16));
	assert(genesis3 !== genesis, "genesis: different nonce → different hash");

	// --- Commitment chain ---
	console.log("--- commitment chain ---");

	const nonce = "ab".repeat(16);
	const g = await computeGenesisCommitment(nonce);
	const contentHash1 = await sha256Hex("document v1");
	const contentHash2 = await sha256Hex("document v2");

	const c1 = await computeCommitment(g, contentHash1, 2, nonce);
	assertEq(c1.length, 64, "commitment: correct length");
	assert(c1 !== g, "commitment: differs from genesis");

	// Chain: c2 depends on c1
	const c2 = await computeCommitment(c1, contentHash2, 3, nonce);
	assert(c2 !== c1, "commitment: c2 differs from c1");

	// Deterministic
	const c1b = await computeCommitment(g, contentHash1, 2, nonce);
	assertEq(c1, c1b, "commitment: deterministic");

	// Different ordinal → different commitment
	const c1alt = await computeCommitment(g, contentHash1, 99, nonce);
	assert(c1alt !== c1, "commitment: different ordinal → different hash");

	// Different content → different commitment
	const c1diff = await computeCommitment(g, contentHash2, 2, nonce);
	assert(c1diff !== c1, "commitment: different content → different hash");

	// --- Standalone chain integrity ---
	console.log("--- standalone chain ---");

	const DST_GENESIS = "CPoE-StandaloneGenesis-v1";
	const DST_CHAIN = "CPoE-StandaloneChain-v1";
	const sessionNonce = "cc".repeat(16);

	const saGenesis = await sha256Hex(`${DST_GENESIS}:${sessionNonce}`);
	assertEq(saGenesis.length, 64, "sa genesis: length");

	// Simulate 3 checkpoints
	let prevHash = saGenesis;
	const hashes = [saGenesis];
	for (let i = 1; i <= 3; i++) {
		const content = await sha256Hex(`content ${i}`);
		const jitterBinding = "0".repeat(64);
		const ts = 1700000000000 + i * 30000;
		const input = `${DST_CHAIN}:${prevHash}:${content}:${i}:${ts}:${jitterBinding}`;
		const cpHash = await sha256Hex(input);
		hashes.push(cpHash);
		prevHash = cpHash;
	}

	// Verify chain: each hash depends on previous
	assert(hashes.length === 4, "sa chain: 4 hashes (genesis + 3)");
	const uniqueHashes = new Set(hashes);
	assert(uniqueHashes.size === 4, "sa chain: all unique");

	// --- Jitter chain ---
	console.log("--- jitter chain ---");

	const DST_JITTER_BIND = "CPoE-StandaloneJitterBind-v1";
	let jitterHash = "0".repeat(64);

	// Simulate 3 jitter batches
	const batches = [
		[100, 200, 150],
		[80, 90, 110],
		[200, 180, 160],
	];
	for (const intervals of batches) {
		const input = `${DST_JITTER_BIND}:${intervals.join(",")}`;
		const batchHash = await sha256Hex(input);
		jitterHash = await sha256Hex(`${jitterHash}:${batchHash}`);
	}

	assertEq(jitterHash.length, 64, "jitter chain: correct length");
	assert(
		jitterHash !== "0".repeat(64),
		"jitter chain: non-zero after batches",
	);

	// Deterministic
	let jitterHash2 = "0".repeat(64);
	for (const intervals of batches) {
		const input = `${DST_JITTER_BIND}:${intervals.join(",")}`;
		const batchHash = await sha256Hex(input);
		jitterHash2 = await sha256Hex(`${jitterHash2}:${batchHash}`);
	}
	assertEq(jitterHash, jitterHash2, "jitter chain: deterministic");

	// --- Evidence quality scoring ---
	console.log("--- evidence quality ---");

	function computeEvidenceQuality(
		session,
		checkpoints,
		jitterBatches,
		chainValid,
	) {
		const cpCount = checkpoints.length;
		const jitterCount = jitterBatches.length;
		const durationMs =
			(session.endedAt || Date.now()) - (session.startedAt || Date.now());
		const durationMin = durationMs / 60000;
		let score = 0;

		if (cpCount >= 20) score += 25;
		else if (cpCount >= 5) score += 15;
		else if (cpCount >= 1) score += 5;

		if (jitterCount >= 10) score += 25;
		else if (jitterCount >= 3) score += 15;
		else if (jitterCount >= 1) score += 5;

		if (durationMin >= 30) score += 15;
		else if (durationMin >= 5) score += 10;
		else if (durationMin >= 1) score += 5;

		if (chainValid) score += 20;

		if (cpCount >= 3) {
			const deltas = checkpoints.map((cp) => Math.abs(cp.delta));
			const avgDelta = deltas.reduce((a, b) => a + b, 0) / deltas.length;
			const smallDeltas = deltas.filter((d) => d < avgDelta * 3).length;
			if (smallDeltas / cpCount >= 0.6) score += 15;
		}

		let grade;
		if (score >= 80) grade = "strong";
		else if (score >= 50) grade = "moderate";
		else if (score >= 25) grade = "weak";
		else grade = "insufficient";

		return { score, grade };
	}

	// Strong evidence
	const now = Date.now();
	const strongSession = { startedAt: now - 3600000, endedAt: now };
	const strongCps = Array.from({ length: 25 }, (_, i) => ({ delta: 10 + i }));
	const strongJitter = Array.from({ length: 15 }, () => ({}));
	const strongResult = computeEvidenceQuality(
		strongSession,
		strongCps,
		strongJitter,
		true,
	);
	assertEq(strongResult.grade, "strong", "quality: rich session → strong");
	assert(strongResult.score >= 80, "quality: rich score >= 80");

	// Weak evidence: 1cp(5) + 0jitter(0) + 30s(0) + no chain(0) = 5
	const weakSession = { startedAt: now - 30000, endedAt: now };
	const weakCps = [{ delta: 5000 }];
	const weakResult = computeEvidenceQuality(weakSession, weakCps, [], false);
	assertEq(
		weakResult.grade,
		"insufficient",
		"quality: minimal session → insufficient",
	);

	// Insufficient evidence
	const emptyResult = computeEvidenceQuality(
		{ startedAt: now, endedAt: now },
		[],
		[],
		false,
	);
	assertEq(
		emptyResult.grade,
		"insufficient",
		"quality: empty → insufficient",
	);

	// Moderate evidence
	const modSession = { startedAt: now - 600000, endedAt: now };
	const modCps = Array.from({ length: 8 }, (_, i) => ({ delta: 20 + i * 2 }));
	const modJitter = Array.from({ length: 5 }, () => ({}));
	const modResult = computeEvidenceQuality(
		modSession,
		modCps,
		modJitter,
		true,
	);
	assertEq(
		modResult.grade,
		"moderate",
		"quality: moderate session → moderate",
	);

	// Delta consistency: one massive paste in otherwise normal session
	const pastedCps = [
		...Array.from({ length: 19 }, () => ({ delta: 15 })),
		{ delta: 50000 },
	];
	const pastedResult = computeEvidenceQuality(
		strongSession,
		pastedCps,
		strongJitter,
		true,
	);
	assert(
		pastedResult.score >= 80,
		"quality: one paste in 20 cps still strong",
	);

	// All huge deltas (suspicious)
	const bulkCps = Array.from({ length: 5 }, () => ({ delta: 10000 }));
	const bulkResult = computeEvidenceQuality(
		strongSession,
		bulkCps,
		strongJitter,
		true,
	);
	// All deltas equal → all within 3x avg → still passes delta check
	assert(
		bulkResult.score >= 50,
		"quality: uniform large deltas → passes consistency",
	);

	// ═══════════════════════════════════════════════════════════════════════
	// Report
	// ═══════════════════════════════════════════════════════════════════════

	console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
	if (failures.length > 0) {
		console.log("\nFailed tests:");
		for (const f of failures) console.log(`  - ${f}`);
	}
	process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((err) => {
	console.error("Test runner error:", err);
	process.exit(1);
});
