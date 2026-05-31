// SPDX-License-Identifier: AGPL-3.0-only
// WritersProof Canvas LMS — API client

import { createHash } from "crypto";

const API_BASE_URL = "https://api.writerslogic.com/v1";
const MAX_RETRIES = 3;
const REQUEST_TIMEOUT_MS = 30_000;
const CLIENT_PLATFORM = "canvas";
const CLIENT_VERSION = "1.0.0";

// --- Session ID validation ---

const SESSION_ID_PATTERN = /^[a-zA-Z0-9_-]{1,128}$/;

function validateSessionId(sessionId: string): void {
	if (!SESSION_ID_PATTERN.test(sessionId)) {
		throw new Error(
			`Invalid session ID format: must match ${SESSION_ID_PATTERN}`,
		);
	}
}

// --- Request / Response Types ---

export interface CreateSessionPayload {
	documentId: string;
	documentNameHash: string;
	platform: string;
	clientVersion: string;
	userId?: string;
	courseId?: string;
	assignmentId?: string;
}

export interface CreateSessionResponse {
	sessionId: string;
	createdAt: string;
}

export interface AuthoringEvent {
	type: string;
	timestamp: string;
	data: Record<string, unknown>;
}

export interface CheckpointData {
	wordCount: number;
	charCount: number;
	paragraphCount: number;
	bodyHash: string;
	timestamp: string;
	submissionType?: string;
}

export interface EvidenceResponse {
	sessionId: string;
	eventCount: number;
	downloadUrl: string;
	verdict: string;
	score: number;
}

export interface VerifyResponse {
	sessionId: string;
	verdict: string;
	score: number;
	confidence: number;
	tier: string;
	anchorTimestamp: string;
	details: Record<string, unknown>;
}

// --- HTTP plumbing ---

interface RetryableResponse {
	ok: boolean;
	status: number;
	headers: Headers;
	text(): Promise<string>;
}

async function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Parses a JSON response and asserts that all required top-level fields are present.
 * Throws a descriptive error if the response body is malformed or missing fields.
 */
function parseResponse<T>(
	body: string,
	requiredFields: string[],
	endpoint: string,
): T {
	let parsed: Record<string, unknown>;
	try {
		parsed = JSON.parse(body) as Record<string, unknown>;
	} catch {
		throw new Error(
			`Invalid JSON from ${endpoint}: ${body.substring(0, 200)}`,
		);
	}
	if (typeof parsed !== "object" || parsed === null) {
		throw new Error(
			`Expected object from ${endpoint}, got ${typeof parsed}`,
		);
	}
	for (const field of requiredFields) {
		if (!(field in parsed) || parsed[field] === undefined) {
			throw new Error(
				`Missing required field '${field}' in response from ${endpoint}`,
			);
		}
	}
	return parsed as unknown as T;
}

/**
 * HTTP client for the WritersProof API. Uses Node.js built-in fetch (Node 20+)
 * with 3 retries, 429/5xx back-off, and a 30-second AbortController timeout.
 */
export class WritersProofClient {
	private readonly apiKey: string;

	constructor(apiKey: string) {
		if (!apiKey || apiKey.trim().length === 0) {
			throw new Error("WritersProof API key is required.");
		}
		this.apiKey = apiKey.trim();
	}

	// --- Session lifecycle ---

	async createSession(
		payload: CreateSessionPayload,
	): Promise<CreateSessionResponse> {
		const body = await this.post("/sessions", payload);
		return parseResponse<CreateSessionResponse>(
			body,
			["sessionId", "createdAt"],
			"/sessions",
		);
	}

	async submitEvents(
		sessionId: string,
		events: AuthoringEvent[],
	): Promise<void> {
		if (events.length === 0) return;
		validateSessionId(sessionId);
		await this.post(`/sessions/${sessionId}/events`, { sessionId, events });
	}

	async createCheckpoint(
		sessionId: string,
		data: CheckpointData,
	): Promise<void> {
		validateSessionId(sessionId);
		await this.post(`/sessions/${sessionId}/checkpoints`, data);
	}

	async finalizeSession(sessionId: string): Promise<void> {
		validateSessionId(sessionId);
		await this.post(`/sessions/${sessionId}/finalize`, {});
	}

	async getEvidence(sessionId: string): Promise<EvidenceResponse> {
		validateSessionId(sessionId);
		const body = await this.get(`/sessions/${sessionId}/evidence`);
		return parseResponse<EvidenceResponse>(
			body,
			["sessionId", "eventCount", "verdict"],
			"/evidence",
		);
	}

	async verifyEvidence(sessionId: string): Promise<VerifyResponse> {
		validateSessionId(sessionId);
		const body = await this.post("/verify", { sessionId });
		return parseResponse<VerifyResponse>(
			body,
			["verdict", "score", "confidence"],
			"/verify",
		);
	}

	// --- HTTP primitives ---

	private headers(): Record<string, string> {
		return {
			Authorization: `Bearer ${this.apiKey}`,
			"X-Client-Platform": CLIENT_PLATFORM,
			"X-Client-Version": CLIENT_VERSION,
			"Content-Type": "application/json",
		};
	}

	private async get(path: string): Promise<string> {
		return this.request("GET", path, undefined);
	}

	private async post(path: string, payload: unknown): Promise<string> {
		return this.request("POST", path, JSON.stringify(payload));
	}

	private async request(
		method: string,
		path: string,
		body: string | undefined,
	): Promise<string> {
		const url = API_BASE_URL + path;
		let lastStatus = 0;
		let lastBody = "";
		let lastError: Error | null = null;

		for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
			const controller = new AbortController();
			const timer = setTimeout(
				() => controller.abort(),
				REQUEST_TIMEOUT_MS,
			);

			try {
				const response = await fetch(url, {
					method,
					headers: this.headers(),
					body,
					signal: controller.signal,
				});

				clearTimeout(timer);
				lastStatus = response.status;
				lastBody = await response.text();

				if (response.ok) {
					return lastBody;
				}

				// Rate limited: respect Retry-After header
				if (response.status === 429) {
					const retryAfter = response.headers.get("retry-after");
					const parsed = retryAfter ? parseInt(retryAfter, 10) : NaN;
					const waitMs = Number.isFinite(parsed)
						? parsed * 1000
						: 1000 * (attempt + 1);
					await sleep(Math.min(waitMs, 15_000));
					continue;
				}

				// Server error: exponential back-off
				if (response.status >= 500) {
					await sleep(1000 * (attempt + 1));
					continue;
				}

				// Client error (4xx except 429): non-retryable
				throw new Error(
					`WritersProof API error ${response.status} at ${path}: ${lastBody.substring(0, 500)}`,
				);
			} catch (err) {
				clearTimeout(timer);
				if (
					err instanceof Error &&
					err.message.startsWith("WritersProof API error")
				) {
					throw err;
				}
				lastError = err instanceof Error ? err : new Error(String(err));
				if (attempt < MAX_RETRIES - 1) {
					await sleep(1000 * (attempt + 1));
				}
			}
		}

		if (lastStatus > 0) {
			throw new Error(
				`WritersProof API error ${lastStatus} after ${MAX_RETRIES} retries at ${path}: ${lastBody.substring(0, 500)}`,
			);
		}
		throw (
			lastError ??
			new Error(`Request to ${path} failed after ${MAX_RETRIES} retries`)
		);
	}
}

/** SHA-256 hash of a string, returned as lowercase hex. */
export function sha256Hex(input: string): string {
	return createHash("sha256").update(input, "utf8").digest("hex");
}
