// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";
import jwt from "jsonwebtoken";
import fs from "fs";

export interface ContentSnapshot {
	documentId: string;
	documentTitle: string;
	plainText: string;
	contentHash: string;
	wordCount: number;
	charCount: number;
	fetchedAt: number;
}

export interface ContentDiff {
	previous: ContentSnapshot | null;
	current: ContentSnapshot;
	changed: boolean;
	wordDelta: number;
	charDelta: number;
}

interface GitHubIssue {
	number: number;
	title: string;
	body: string | null;
	state: string;
}

interface GitHubComment {
	id: number;
	body: string | null;
}

interface GitHubPR {
	number: number;
	title: string;
	body: string | null;
	state: string;
}

interface GitHubPRReview {
	id: number;
	body: string | null;
	state: string;
}

interface GitHubInstallationTokenResponse {
	token: string;
	expires_at: string;
}

interface GitHubDiscussionResponse {
	data?: {
		repository?: {
			discussion?: {
				title: string;
				body: string;
			};
		};
	};
}

interface GitHubWikiPage {
	title: string;
	content_url: string;
}

function stripMarkdown(text: string): string {
	return (
		text
			// Fenced code blocks
			.replace(/```[\s\S]*?```/g, " ")
			// Inline code
			.replace(/`[^`]*`/g, " ")
			// ATX headings
			.replace(/^#{1,6}\s+/gm, "")
			// Bold/italic
			.replace(/\*{1,3}([^*]+)\*{1,3}/g, "$1")
			.replace(/_{1,3}([^_]+)_{1,3}/g, "$1")
			// Links and images
			.replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
			// Blockquotes
			.replace(/^>\s+/gm, "")
			// Horizontal rules
			.replace(/^[-*_]{3,}\s*$/gm, "")
			// HTML tags
			.replace(/<[^>]+>/g, " ")
			// Collapse whitespace
			.replace(/\s+/g, " ")
			.trim()
	);
}

function countWords(text: string): number {
	if (!text) return 0;
	return text.split(/\s+/).filter((w) => w.length > 0).length;
}

function hashText(text: string): string {
	return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * Builds a GitHub App JWT valid for 10 minutes, used to obtain installation
 * access tokens. The private key is loaded from disk once per instance.
 *
 * Reference: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
 */
function buildAppJwt(appId: string, privateKey: string): string {
	const now = Math.floor(Date.now() / 1000);
	return jwt.sign({ iat: now - 60, exp: now + 600, iss: appId }, privateKey, {
		algorithm: "RS256",
	});
}

export class ContentMonitor {
	private readonly appId: string;
	private readonly privateKey: string;
	/** Cache of installation tokens: installationId -> { token, expiresAt } */
	private readonly tokenCache = new Map<
		string,
		{ token: string; expiresAt: number }
	>();
	/** In-memory snapshot store keyed by "{type}:{owner}/{repo}#{id}" */
	private readonly snapshots = new Map<string, ContentSnapshot>();

	constructor(appId: string, privateKeyPath: string) {
		if (!appId) throw new Error("ContentMonitor: appId is required");
		if (!privateKeyPath)
			throw new Error("ContentMonitor: privateKeyPath is required");
		this.appId = appId;
		this.privateKey = fs.readFileSync(privateKeyPath, "utf8");
	}

	async getInstallationToken(installationId: string): Promise<string> {
		const cached = this.tokenCache.get(installationId);
		// Tokens expire in 1h; refresh 5 minutes early
		if (cached && cached.expiresAt > Date.now() + 5 * 60 * 1000) {
			return cached.token;
		}

		const appJwt = buildAppJwt(this.appId, this.privateKey);
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);

		try {
			const resp = await fetch(
				`https://api.github.com/app/installations/${encodeURIComponent(installationId)}/access_tokens`,
				{
					method: "POST",
					headers: {
						Authorization: `Bearer ${appJwt}`,
						Accept: "application/vnd.github+json",
						"X-GitHub-Api-Version": "2022-11-28",
					},
					signal: controller.signal,
				},
			);
			clearTimeout(timeoutId);

			if (!resp.ok) {
				const text = await resp.text().catch(() => resp.statusText);
				throw new Error(
					`GitHub App token request failed ${resp.status}: ${text}`,
				);
			}

			const data = (await resp.json()) as GitHubInstallationTokenResponse;
			const expiresAt = new Date(data.expires_at).getTime();
			this.tokenCache.set(installationId, {
				token: data.token,
				expiresAt,
			});
			return data.token;
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	private async githubGet<T>(path: string, token: string): Promise<T> {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);

		try {
			const resp = await fetch(`https://api.github.com${path}`, {
				headers: {
					Authorization: `Bearer ${token}`,
					Accept: "application/vnd.github+json",
					"X-GitHub-Api-Version": "2022-11-28",
				},
				signal: controller.signal,
			});
			clearTimeout(timeoutId);

			if (!resp.ok) {
				const text = await resp.text().catch(() => resp.statusText);
				throw new Error(
					`GitHub REST API ${resp.status} for ${path}: ${text}`,
				);
			}

			return (await resp.json()) as T;
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	private async githubGraphQL<T>(
		query: string,
		variables: Record<string, unknown>,
		token: string,
	): Promise<T> {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);

		try {
			const resp = await fetch("https://api.github.com/graphql", {
				method: "POST",
				headers: {
					Authorization: `Bearer ${token}`,
					"Content-Type": "application/json",
					"X-GitHub-Api-Version": "2022-11-28",
				},
				body: JSON.stringify({ query, variables }),
				signal: controller.signal,
			});
			clearTimeout(timeoutId);

			if (!resp.ok) {
				const text = await resp.text().catch(() => resp.statusText);
				throw new Error(`GitHub GraphQL ${resp.status}: ${text}`);
			}

			return (await resp.json()) as T;
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	async fetchIssueBody(
		owner: string,
		repo: string,
		issueNumber: number,
		token: string,
	): Promise<GitHubIssue> {
		return this.githubGet<GitHubIssue>(
			`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${issueNumber}`,
			token,
		);
	}

	async fetchPRBody(
		owner: string,
		repo: string,
		prNumber: number,
		token: string,
	): Promise<GitHubPR> {
		return this.githubGet<GitHubPR>(
			`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls/${prNumber}`,
			token,
		);
	}

	async fetchComment(
		owner: string,
		repo: string,
		commentId: number,
		token: string,
	): Promise<GitHubComment> {
		return this.githubGet<GitHubComment>(
			`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/comments/${commentId}`,
			token,
		);
	}

	async fetchPRReviewComment(
		owner: string,
		repo: string,
		commentId: number,
		token: string,
	): Promise<GitHubComment> {
		return this.githubGet<GitHubComment>(
			`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls/comments/${commentId}`,
			token,
		);
	}

	async fetchPRReview(
		owner: string,
		repo: string,
		prNumber: number,
		reviewId: number,
		token: string,
	): Promise<GitHubPRReview> {
		return this.githubGet<GitHubPRReview>(
			`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls/${prNumber}/reviews/${reviewId}`,
			token,
		);
	}

	async fetchDiscussion(
		owner: string,
		repo: string,
		discussionNumber: number,
		token: string,
	): Promise<{ title: string; body: string } | null> {
		const query = `
			query DiscussionContent($owner: String!, $repo: String!, $number: Int!) {
				repository(owner: $owner, name: $repo) {
					discussion(number: $number) {
						title
						body
					}
				}
			}
		`;
		const data = await this.githubGraphQL<GitHubDiscussionResponse>(
			query,
			{ owner, repo, number: discussionNumber },
			token,
		);
		return data.data?.repository?.discussion ?? null;
	}

	async fetchWikiPage(
		owner: string,
		repo: string,
		pageTitle: string,
		token: string,
	): Promise<string | null> {
		// GitHub's REST API lists wiki pages but doesn't return content directly.
		// We fetch the page list to find the content_url, then fetch raw markdown.
		const pages = await this.githubGet<GitHubWikiPage[]>(
			`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/wiki/pages`,
			token,
		).catch(() => null);

		if (!pages) return null;

		const match = pages.find(
			(p) => p.title.toLowerCase() === pageTitle.toLowerCase(),
		);
		if (!match) return null;

		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);
		try {
			const resp = await fetch(match.content_url, {
				headers: {
					Authorization: `Bearer ${token}`,
					Accept: "application/vnd.github.raw+json",
					"X-GitHub-Api-Version": "2022-11-28",
				},
				signal: controller.signal,
			});
			clearTimeout(timeoutId);
			if (!resp.ok) return null;
			return resp.text();
		} catch {
			clearTimeout(timeoutId);
			return null;
		}
	}

	captureSnapshot(
		documentId: string,
		documentTitle: string,
		rawContent: string,
	): ContentSnapshot {
		const plainText = stripMarkdown(rawContent);
		return {
			documentId,
			documentTitle,
			plainText,
			contentHash: hashText(plainText),
			wordCount: countWords(plainText),
			charCount: plainText.length,
			fetchedAt: Date.now(),
		};
	}

	computeDiff(storeKey: string, current: ContentSnapshot): ContentDiff {
		const previous = this.snapshots.get(storeKey) ?? null;
		this.snapshots.set(storeKey, current);
		return {
			previous,
			current,
			changed:
				previous === null ||
				previous.contentHash !== current.contentHash,
			wordDelta: current.wordCount - (previous?.wordCount ?? 0),
			charDelta: current.charCount - (previous?.charCount ?? 0),
		};
	}

	getSnapshot(storeKey: string): ContentSnapshot | null {
		return this.snapshots.get(storeKey) ?? null;
	}

	clearSnapshot(storeKey: string): void {
		this.snapshots.delete(storeKey);
	}
}
