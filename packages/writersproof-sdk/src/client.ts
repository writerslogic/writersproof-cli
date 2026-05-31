// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";
import type {
	SessionParams,
	CheckpointParams,
	FinalizeParams,
	Session,
	Evidence,
} from "./types.js";
import {
	WritersProofError,
	RateLimitError,
	TimeoutError,
	AuthenticationError,
} from "./errors.js";
import type { Logger } from "./logger.js";

interface RetryConfig {
	maxRetries: number;
	baseDelayMs: number;
}

export interface WritersProofClientOptions {
	apiKey: string;
	platform: string;
	baseUrl?: string;
	logger?: Logger;
	retryConfig?: Partial<RetryConfig>;
}

export class WritersProofClient {
	private readonly baseUrl: string;
	private readonly apiKey: string;
	private readonly platform: string;
	private readonly logger?: Logger;
	private readonly retryConfig: RetryConfig;

	constructor(options: WritersProofClientOptions);
	constructor(
		apiKey: string,
		platform: string,
		baseUrl?: string,
		logger?: Logger,
	);
	constructor(
		optionsOrApiKey: WritersProofClientOptions | string,
		platform?: string,
		baseUrl?: string,
		logger?: Logger,
	) {
		if (typeof optionsOrApiKey === "string") {
			if (!optionsOrApiKey)
				throw new AuthenticationError(
					"WritersProofClient: apiKey is required",
				);
			if (!platform)
				throw new WritersProofError(
					"WritersProofClient: platform is required",
				);
			this.apiKey = optionsOrApiKey;
			this.platform = platform;
			this.baseUrl = baseUrl ?? "https://api.writerslogic.com/v1";
			this.logger = logger;
			this.retryConfig = { maxRetries: 3, baseDelayMs: 1000 };
		} else {
			if (!optionsOrApiKey.apiKey)
				throw new AuthenticationError(
					"WritersProofClient: apiKey is required",
				);
			if (!optionsOrApiKey.platform)
				throw new WritersProofError(
					"WritersProofClient: platform is required",
				);
			this.apiKey = optionsOrApiKey.apiKey;
			this.platform = optionsOrApiKey.platform;
			this.baseUrl =
				optionsOrApiKey.baseUrl ?? "https://api.writerslogic.com/v1";
			this.logger = optionsOrApiKey.logger;
			this.retryConfig = {
				maxRetries: optionsOrApiKey.retryConfig?.maxRetries ?? 3,
				baseDelayMs: optionsOrApiKey.retryConfig?.baseDelayMs ?? 1000,
			};
		}
	}

	static hashContent(content: string): string {
		return crypto
			.createHash("sha256")
			.update(content, "utf8")
			.digest("hex");
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

				if (resp.status === 401) {
					throw new AuthenticationError();
				}

				if (resp.status === 429) {
					const retryAfterHeader = resp.headers.get("Retry-After");
					const retryAfterSec = retryAfterHeader
						? parseInt(retryAfterHeader, 10)
						: 5;
					const retryAfterMs = Number.isFinite(retryAfterSec)
						? retryAfterSec * 1000
						: 5000;
					if (attempt === this.retryConfig.maxRetries) {
						throw new RateLimitError(retryAfterMs);
					}
					this.logger?.warn("Rate limited, retrying", {
						attempt,
						retryAfterMs,
					});
					await this.delay(retryAfterMs);
					continue;
				}

				if (
					resp.status >= 500 &&
					attempt < this.retryConfig.maxRetries
				) {
					this.logger?.warn("Server error, retrying", {
						status: resp.status,
						attempt,
					});
					await this.delay(
						this.retryConfig.baseDelayMs * Math.pow(2, attempt),
					);
					continue;
				}

				if (!resp.ok) {
					const text = await resp.text();
					throw new WritersProofError(
						`WritersProof API ${resp.status}: ${text}`,
						resp.status,
					);
				}

				return (await resp.json()) as T;
			} catch (err) {
				clearTimeout(timeoutId);
				lastError = err;

				if (
					err instanceof AuthenticationError ||
					err instanceof RateLimitError
				) {
					throw err;
				}

				if (err instanceof Error && err.name === "AbortError") {
					throw new TimeoutError(method, path);
				}

				if (attempt === this.retryConfig.maxRetries) {
					throw lastError;
				}
				this.logger?.warn("Request failed, retrying", {
					attempt,
					error: String(err),
				});
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
		this.logger?.debug("Creating session", {
			documentId: params.documentId,
		});
		return this.request<Session>("POST", "/sessions", {
			documentId: params.documentId,
			documentTitle: params.documentTitle,
			platform: params.platform ?? this.platform,
			contentHash: params.contentHash,
		});
	}

	async submitEvents(sessionId: string, events: unknown[]): Promise<unknown> {
		this.logger?.debug("Submitting events", {
			sessionId,
			count: events.length,
		});
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
		this.logger?.debug("Creating checkpoint", { sessionId });
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
		this.logger?.info("Finalizing session", { sessionId });
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

	async anchor(sessionId: string): Promise<unknown> {
		this.logger?.info("Anchoring session", { sessionId });
		return this.request(
			"POST",
			`/sessions/${encodeURIComponent(sessionId)}/anchor`,
			{},
		);
	}

	async beacon(sessionId: string): Promise<unknown> {
		this.logger?.info("Submitting beacon", { sessionId });
		return this.request(
			"POST",
			`/sessions/${encodeURIComponent(sessionId)}/beacon`,
			{},
		);
	}
}
