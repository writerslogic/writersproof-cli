// SPDX-License-Identifier: AGPL-3.0-only
// WritersProof Blackboard Learn — Blackboard REST API content monitor

import { createHash } from "crypto";

const REQUEST_TIMEOUT_MS = 30_000;
const TOKEN_EXPIRY_BUFFER_MS = 60_000;

export interface ContentSnapshot {
	contentId: string;
	courseId: string;
	title: string;
	bodyHash: string;
	wordCount: number;
	charCount: number;
	updatedAt: string;
	contentType: string;
}

export interface AttemptSnapshot {
	attemptId: string;
	courseId: string;
	columnId: string;
	userId: string;
	bodyHash: string;
	wordCount: number;
	charCount: number;
	submittedAt: string;
	status: string;
}

export interface DiscussionPostSnapshot {
	postId: string;
	courseId: string;
	threadId: string;
	userId: string;
	bodyHash: string;
	wordCount: number;
	charCount: number;
	postedAt: string;
}

export interface ContentDiff {
	previousHash: string | null;
	currentHash: string;
	wordCountDelta: number;
	charCountDelta: number;
	changed: boolean;
}

const snapshotCache = new Map<
	string,
	{ bodyHash: string; wordCount: number; charCount: number }
>();

function stripHtml(html: string): string {
	let text = html
		.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
		.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "");
	text = text.replace(
		/<\/?(p|div|br|li|h[1-6]|blockquote|pre|tr|td|th)[^>]*>/gi,
		" ",
	);
	text = text.replace(/<[^>]+>/g, "");
	text = text
		.replace(/&amp;/g, "&")
		.replace(/&lt;/g, "<")
		.replace(/&gt;/g, ">")
		.replace(/&quot;/g, '"')
		.replace(/&#39;/g, "'")
		.replace(/&nbsp;/g, " ");
	return text;
}

function countWords(text: string): number {
	const trimmed = text.trim();
	if (trimmed.length === 0) return 0;
	return trimmed.split(/\s+/).length;
}

function sha256Hex(input: string): string {
	return createHash("sha256").update(input, "utf8").digest("hex");
}

function computeDiff(
	cacheKey: string,
	currentHash: string,
	wordCount: number,
	charCount: number,
): ContentDiff {
	const prev = snapshotCache.get(cacheKey) ?? null;
	snapshotCache.set(cacheKey, {
		bodyHash: currentHash,
		wordCount,
		charCount,
	});
	return {
		previousHash: prev?.bodyHash ?? null,
		currentHash,
		wordCountDelta: wordCount - (prev?.wordCount ?? 0),
		charCountDelta: charCount - (prev?.charCount ?? 0),
		changed: prev === null || prev.bodyHash !== currentHash,
	};
}

interface OAuthTokenResponse {
	access_token: string;
	expires_in: number;
}

/**
 * Thin wrapper around the Blackboard REST API.
 * Manages client_credentials token acquisition and renewal automatically.
 */
export class ContentMonitor {
	private readonly bbUrl: string;
	private readonly clientId: string;
	private readonly clientSecret: string;
	private accessToken: string = "";
	private tokenExpiresAt: number = 0;

	constructor(bbUrl: string, clientId: string, clientSecret: string) {
		if (!bbUrl || !clientId || !clientSecret) {
			throw new Error("bbUrl, clientId, and clientSecret are required");
		}
		this.bbUrl = bbUrl.replace(/\/+$/, "");
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	private async ensureToken(): Promise<void> {
		if (
			this.accessToken &&
			Date.now() < this.tokenExpiresAt - TOKEN_EXPIRY_BUFFER_MS
		) {
			return;
		}

		const url = `${this.bbUrl}/learn/api/public/v1/oauth2/token`;
		const body = new URLSearchParams({
			grant_type: "client_credentials",
		});

		const credentials = Buffer.from(
			`${this.clientId}:${this.clientSecret}`,
		).toString("base64");
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

		try {
			const response = await fetch(url, {
				method: "POST",
				headers: {
					Authorization: `Basic ${credentials}`,
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: body.toString(),
				signal: controller.signal,
			});

			const text = await response.text();
			if (!response.ok) {
				throw new Error(
					`Blackboard OAuth2 error ${response.status}: ${text.substring(0, 400)}`,
				);
			}

			const data = JSON.parse(text) as OAuthTokenResponse;
			this.accessToken = data.access_token;
			this.tokenExpiresAt = Date.now() + data.expires_in * 1000;
		} finally {
			clearTimeout(timer);
		}
	}

	async fetchContent(
		courseId: string,
		contentId: string,
	): Promise<{ snapshot: ContentSnapshot; diff: ContentDiff }> {
		await this.ensureToken();
		const path = `/learn/api/public/v3/courses/${encodeURIComponent(courseId)}/contents/${encodeURIComponent(contentId)}`;
		const raw = await this.get(path);

		const body: string = (raw.body as string) ?? "";
		const plainText = stripHtml(body);
		const bodyHash = sha256Hex(plainText);
		const wordCount = countWords(plainText);
		const charCount = plainText.length;

		const snapshot: ContentSnapshot = {
			contentId: String(raw.id ?? contentId),
			courseId,
			title: String(raw.title ?? ""),
			bodyHash,
			wordCount,
			charCount,
			updatedAt: String(raw.modified ?? new Date().toISOString()),
			contentType: String(
				(raw.contentHandler as Record<string, unknown> | undefined)
					?.id ?? "unknown",
			),
		};

		const cacheKey = `content:${courseId}:${contentId}`;
		const diff = computeDiff(cacheKey, bodyHash, wordCount, charCount);

		return { snapshot, diff };
	}

	async fetchAttempt(
		courseId: string,
		columnId: string,
		attemptId: string,
	): Promise<{ snapshot: AttemptSnapshot; diff: ContentDiff }> {
		await this.ensureToken();
		const path = `/learn/api/public/v2/courses/${encodeURIComponent(courseId)}/gradebook/columns/${encodeURIComponent(columnId)}/attempts/${encodeURIComponent(attemptId)}`;
		const raw = await this.get(path);

		const body: string = (raw.text as string) ?? "";
		const plainText = stripHtml(body);
		const bodyHash = sha256Hex(plainText);
		const wordCount = countWords(plainText);
		const charCount = plainText.length;

		const userId = String((raw.userId as string) ?? "");
		const snapshot: AttemptSnapshot = {
			attemptId: String(raw.id ?? attemptId),
			courseId,
			columnId,
			userId,
			bodyHash,
			wordCount,
			charCount,
			submittedAt: String(raw.created ?? new Date().toISOString()),
			status: String(raw.status ?? "unknown"),
		};

		const cacheKey = `attempt:${courseId}:${columnId}:${attemptId}`;
		const diff = computeDiff(cacheKey, bodyHash, wordCount, charCount);

		return { snapshot, diff };
	}

	async fetchDiscussionPosts(
		courseId: string,
		threadId: string,
	): Promise<Array<{ snapshot: DiscussionPostSnapshot; diff: ContentDiff }>> {
		await this.ensureToken();
		const path = `/learn/api/public/v1/courses/${encodeURIComponent(courseId)}/discussions/threads/${encodeURIComponent(threadId)}/posts`;
		const raw = await this.get(path);
		const posts = Array.isArray(raw.results)
			? (raw.results as Array<Record<string, unknown>>)
			: [];

		return posts.map((post) => {
			const body: string = (post.body as string) ?? "";
			const plainText = stripHtml(body);
			const bodyHash = sha256Hex(plainText);
			const wordCount = countWords(plainText);
			const charCount = plainText.length;
			const postId = String(post.id ?? "");
			const userId = String(post.userId ?? "");

			const snapshot: DiscussionPostSnapshot = {
				postId,
				courseId,
				threadId,
				userId,
				bodyHash,
				wordCount,
				charCount,
				postedAt: String(post.created ?? new Date().toISOString()),
			};

			const cacheKey = `discussion:${courseId}:${threadId}:${postId}`;
			const diff = computeDiff(cacheKey, bodyHash, wordCount, charCount);

			return { snapshot, diff };
		});
	}

	private async get(path: string): Promise<Record<string, unknown>> {
		const url = `${this.bbUrl}${path}`;
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

		try {
			const response = await fetch(url, {
				headers: {
					Authorization: `Bearer ${this.accessToken}`,
					Accept: "application/json",
				},
				signal: controller.signal,
			});

			const text = await response.text();
			if (!response.ok) {
				throw new Error(
					`Blackboard API error ${response.status} at ${path}: ${text.substring(0, 400)}`,
				);
			}

			return JSON.parse(text) as Record<string, unknown>;
		} finally {
			clearTimeout(timer);
		}
	}
}
