// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";

interface RetryConfig {
	maxRetries: number;
	baseDelayMs: number;
}

export interface SessionParams {
	documentId: string;
	documentTitle: string;
	contentHash: string;
	platform?: string;
}

export interface CheckpointParams {
	contentHash: string;
	wordCount: number;
	charCount: number;
}

export interface FinalizeParams {
	contentHash: string;
	wordCount: number;
	finalSnapshot?: string;
}

export interface Session {
	id: string;
	documentId: string;
	documentTitle: string;
	platform: string;
	contentHash: string;
	createdAt: string;
	[key: string]: unknown;
}

export interface Evidence {
	sessionId: string;
	packets: unknown[];
	[key: string]: unknown;
}

export function hashContent(content: string): string {
	return crypto.createHash("sha256").update(content, "utf8").digest("hex");
}

export class WritersProofClient {
	private readonly baseUrl: string;
	private readonly apiKey: string;
	private readonly platform: string;
	private readonly retryConfig: RetryConfig = {
		maxRetries: 3,
		baseDelayMs: 1000,
	};

	constructor(
		apiKey: string,
		platform: string,
		baseUrl = "https://api.writerslogic.com/v1",
	) {
		if (!apiKey) throw new Error("WritersProofClient: apiKey is required");
		if (!platform)
			throw new Error("WritersProofClient: platform is required");
		this.apiKey = apiKey;
		this.platform = platform;
		this.baseUrl = baseUrl;
	}

	private async request<T>(
		method: string,
		path: string,
		body?: unknown,
	): Promise<T> {
		let lastError: unknown;

		for (
			let attempt = 0;
			attempt <= this.retryConfig.maxRetries;
			attempt++
		) {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 30_000);

			try {
				const resp = await fetch(`${this.baseUrl}${path}`, {
					method,
					headers: {
						Authorization: `Bearer ${this.apiKey}`,
						"Content-Type": "application/json",
						"X-Client-Platform": this.platform,
						"X-Client-Version": "1.0.0",
					},
					body: body !== undefined ? JSON.stringify(body) : undefined,
					signal: controller.signal,
				});
				clearTimeout(timeoutId);

				if (resp.status === 429) {
					const retryAfterHeader = resp.headers.get("Retry-After");
					const retryAfterSec = retryAfterHeader
						? parseInt(retryAfterHeader, 10)
						: 5;
					const retryAfterMs = Number.isFinite(retryAfterSec)
						? retryAfterSec * 1000
						: 5000;
					await this.delay(retryAfterMs);
					continue;
				}

				if (
					resp.status >= 500 &&
					attempt < this.retryConfig.maxRetries
				) {
					await this.delay(
						this.retryConfig.baseDelayMs * Math.pow(2, attempt),
					);
					continue;
				}

				if (!resp.ok) {
					const text = await resp.text();
					throw new Error(`WritersProof API ${resp.status}: ${text}`);
				}

				return (await resp.json()) as T;
			} catch (err) {
				clearTimeout(timeoutId);
				lastError = err;

				if (err instanceof Error && err.name === "AbortError") {
					throw new Error(
						`WritersProof API request timed out after 30s: ${method} ${path}`,
					);
				}

				if (attempt === this.retryConfig.maxRetries) {
					throw lastError;
				}
				await this.delay(
					this.retryConfig.baseDelayMs * Math.pow(2, attempt),
				);
			}
		}

		throw lastError;
	}

	private delay(ms: number): Promise<void> {
		return new Promise((resolve) => setTimeout(resolve, ms));
	}

	async createSession(params: SessionParams): Promise<Session> {
		return this.request<Session>("POST", "/sessions", {
			documentId: params.documentId,
			documentTitle: params.documentTitle,
			platform: params.platform ?? this.platform,
			contentHash: params.contentHash,
		});
	}

	async submitEvents(sessionId: string, events: unknown[]): Promise<unknown> {
		return this.request(
			"POST",
			`/sessions/${encodeURIComponent(sessionId)}/events`,
			{ events },
		);
	}

	async createCheckpoint(
		sessionId: string,
		data: CheckpointParams,
	): Promise<unknown> {
		return this.request(
			"POST",
			`/sessions/${encodeURIComponent(sessionId)}/checkpoints`,
			{
				contentHash: data.contentHash,
				wordCount: data.wordCount,
				charCount: data.charCount,
			},
		);
	}

	async finalizeSession(
		sessionId: string,
		data: FinalizeParams,
	): Promise<unknown> {
		return this.request(
			"POST",
			`/sessions/${encodeURIComponent(sessionId)}/finalize`,
			{
				contentHash: data.contentHash,
				wordCount: data.wordCount,
				finalSnapshot: data.finalSnapshot,
			},
		);
	}

	async getEvidence(sessionId: string): Promise<Evidence> {
		return this.request<Evidence>(
			"GET",
			`/sessions/${encodeURIComponent(sessionId)}/evidence`,
		);
	}

	async verifyEvidence(data: unknown): Promise<unknown> {
		return this.request("POST", "/verify", data);
	}
}
