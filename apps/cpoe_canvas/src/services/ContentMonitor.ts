// SPDX-License-Identifier: AGPL-3.0-only
// WritersProof Canvas LMS — Canvas REST API content monitor

import { createHash } from "crypto";

const REQUEST_TIMEOUT_MS = 30_000;

export interface SubmissionSnapshot {
	submissionId: string;
	userId: string;
	courseId: string;
	assignmentId: string;
	bodyHash: string;
	wordCount: number;
	charCount: number;
	submittedAt: string;
	workflowState: string;
}

export interface WikiPageSnapshot {
	pageId: string;
	courseId: string;
	url: string;
	bodyHash: string;
	wordCount: number;
	charCount: number;
	updatedAt: string;
}

export interface DiscussionEntrySnapshot {
	entryId: string;
	courseId: string;
	topicId: string;
	userId: string;
	bodyHash: string;
	wordCount: number;
	charCount: number;
	createdAt: string;
}

export interface ContentDiff {
	previousHash: string | null;
	currentHash: string;
	wordCountDelta: number;
	charCountDelta: number;
	changed: boolean;
}

// In-memory snapshot store for diff tracking. In production, back with the
// SQLite store or Redis to survive restarts.
const snapshotCache = new Map<
	string,
	{ bodyHash: string; wordCount: number; charCount: number }
>();

function stripHtml(html: string): string {
	// Remove script/style blocks first to avoid leaking their text content.
	let text = html
		.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
		.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "");
	// Replace block-level tags with spaces so words don't run together.
	text = text.replace(
		/<\/?(p|div|br|li|h[1-6]|blockquote|pre|tr|td|th)[^>]*>/gi,
		" ",
	);
	// Strip remaining tags.
	text = text.replace(/<[^>]+>/g, "");
	// Decode common HTML entities.
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

/**
 * Thin wrapper around the Canvas REST API. Requires an OAuth access token
 * obtained either via the LTI AGS service or a Canvas Developer Key.
 */
export class ContentMonitor {
	private readonly canvasUrl: string;
	private readonly accessToken: string;

	constructor(canvasUrl: string, accessToken: string) {
		if (!canvasUrl || !accessToken) {
			throw new Error("canvasUrl and accessToken are required");
		}
		// Normalise: strip trailing slash.
		this.canvasUrl = canvasUrl.replace(/\/+$/, "");
		this.accessToken = accessToken;
	}

	async fetchSubmission(
		courseId: string,
		assignmentId: string,
		userId: string,
	): Promise<{ snapshot: SubmissionSnapshot; diff: ContentDiff }> {
		const path = `/api/v1/courses/${encodeURIComponent(courseId)}/assignments/${encodeURIComponent(assignmentId)}/submissions/${encodeURIComponent(userId)}`;
		const raw = await this.get(path);

		const body = String(raw.body ?? "");
		const plainText = stripHtml(body);
		const bodyHash = sha256Hex(plainText);
		const wordCount = countWords(plainText);
		const charCount = plainText.length;

		const snapshot: SubmissionSnapshot = {
			submissionId: String(raw.id ?? ""),
			userId: String(raw.user_id ?? userId),
			courseId,
			assignmentId,
			bodyHash,
			wordCount,
			charCount,
			submittedAt: String(raw.submitted_at ?? new Date().toISOString()),
			workflowState: String(raw.workflow_state ?? "unknown"),
		};

		const cacheKey = `submission:${courseId}:${assignmentId}:${userId}`;
		const diff = computeDiff(cacheKey, bodyHash, wordCount, charCount);

		return { snapshot, diff };
	}

	async fetchWikiPage(
		courseId: string,
		pageUrl: string,
	): Promise<{ snapshot: WikiPageSnapshot; diff: ContentDiff }> {
		const path = `/api/v1/courses/${encodeURIComponent(courseId)}/pages/${encodeURIComponent(pageUrl)}`;
		const raw = await this.get(path);

		const body = String(raw.body ?? "");
		const plainText = stripHtml(body);
		const bodyHash = sha256Hex(plainText);
		const wordCount = countWords(plainText);
		const charCount = plainText.length;

		const snapshot: WikiPageSnapshot = {
			pageId: String(raw.page_id ?? raw.url ?? pageUrl),
			courseId,
			url: String(raw.url ?? pageUrl),
			bodyHash,
			wordCount,
			charCount,
			updatedAt: String(raw.updated_at ?? new Date().toISOString()),
		};

		const cacheKey = `wiki:${courseId}:${pageUrl}`;
		const diff = computeDiff(cacheKey, bodyHash, wordCount, charCount);

		return { snapshot, diff };
	}

	async fetchDiscussionEntries(
		courseId: string,
		topicId: string,
	): Promise<
		Array<{ snapshot: DiscussionEntrySnapshot; diff: ContentDiff }>
	> {
		const path = `/api/v1/courses/${encodeURIComponent(courseId)}/discussion_topics/${encodeURIComponent(topicId)}/entries`;
		const entries = await this.getList(path);

		return entries.map((entry: Record<string, unknown>) => {
			const body: string = (entry.message as string) ?? "";
			const plainText = stripHtml(body);
			const bodyHash = sha256Hex(plainText);
			const wordCount = countWords(plainText);
			const charCount = plainText.length;
			const entryId = String(entry.id ?? "");
			const userId = String(entry.user_id ?? "");

			const snapshot: DiscussionEntrySnapshot = {
				entryId,
				courseId,
				topicId,
				userId,
				bodyHash,
				wordCount,
				charCount,
				createdAt: String(entry.created_at ?? new Date().toISOString()),
			};

			const cacheKey = `discussion:${courseId}:${topicId}:${entryId}`;
			const diff = computeDiff(cacheKey, bodyHash, wordCount, charCount);

			return { snapshot, diff };
		});
	}

	private async get(path: string): Promise<Record<string, unknown>> {
		const url = `${this.canvasUrl}${path}`;
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
					`Canvas API error ${response.status} at ${path}: ${text.substring(0, 400)}`,
				);
			}

			return JSON.parse(text) as Record<string, unknown>;
		} finally {
			clearTimeout(timer);
		}
	}

	private async getList(
		path: string,
	): Promise<Array<Record<string, unknown>>> {
		const result = await this.get(path);
		if (Array.isArray(result)) {
			return result as Array<Record<string, unknown>>;
		}
		return [];
	}
}
