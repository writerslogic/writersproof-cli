// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";

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

interface LinearIssueResponse {
	data?: {
		issue?: {
			id: string;
			title: string;
			description: string | null;
			state: { name: string };
			updatedAt: string;
			comments: {
				nodes: Array<{
					id: string;
					body: string;
					updatedAt: string;
					user: { name: string };
				}>;
			};
		};
	};
}

interface LinearCommentResponse {
	data?: {
		comment?: {
			id: string;
			body: string;
			updatedAt: string;
		};
	};
}

interface LinearProjectResponse {
	data?: {
		project?: {
			id: string;
			name: string;
			description: string | null;
			updatedAt: string;
		};
	};
}

interface LinearTokenResponse {
	access_token: string;
	token_type: string;
	expires_in?: number;
	scope?: string;
}

function stripMarkdown(text: string): string {
	return text
		.replace(/```[\s\S]*?```/g, " ")
		.replace(/`[^`]*`/g, " ")
		.replace(/^#{1,6}\s+/gm, "")
		.replace(/\*{1,3}([^*]+)\*{1,3}/g, "$1")
		.replace(/_{1,3}([^_]+)_{1,3}/g, "$1")
		.replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
		.replace(/^>\s+/gm, "")
		.replace(/^[-*_]{3,}\s*$/gm, "")
		.replace(/<[^>]+>/g, " ")
		.replace(/\s+/g, " ")
		.trim();
}

function countWords(text: string): number {
	if (!text) return 0;
	return text.split(/\s+/).filter((w) => w.length > 0).length;
}

function hashText(text: string): string {
	return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

const LINEAR_GRAPHQL = "https://api.linear.app/graphql";

export class ContentMonitor {
	/** In-memory snapshot store keyed by "{type}:{id}" */
	private readonly snapshots = new Map<string, ContentSnapshot>();

	private async graphql<T>(
		query: string,
		variables: Record<string, unknown>,
		accessToken: string,
	): Promise<T> {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);

		try {
			const resp = await fetch(LINEAR_GRAPHQL, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${accessToken}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ query, variables }),
				signal: controller.signal,
			});
			clearTimeout(timeoutId);

			if (!resp.ok) {
				const text = await resp.text().catch(() => resp.statusText);
				throw new Error(`Linear GraphQL ${resp.status}: ${text}`);
			}

			return (await resp.json()) as T;
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	async fetchIssue(
		issueId: string,
		accessToken: string,
	): Promise<{ id: string; title: string; description: string } | null> {
		const query = `
			query IssueContent($id: String!) {
				issue(id: $id) {
					id
					title
					description
					state { name }
					updatedAt
					comments { nodes { id body updatedAt user { name } } }
				}
			}
		`;
		const data = await this.graphql<LinearIssueResponse>(
			query,
			{ id: issueId },
			accessToken,
		);
		const issue = data.data?.issue;
		if (!issue) return null;
		return {
			id: issue.id,
			title: issue.title,
			description: issue.description ?? "",
		};
	}

	async fetchComment(
		commentId: string,
		accessToken: string,
	): Promise<{ id: string; body: string } | null> {
		const query = `
			query CommentContent($id: String!) {
				comment(id: $id) {
					id
					body
					updatedAt
				}
			}
		`;
		const data = await this.graphql<LinearCommentResponse>(
			query,
			{ id: commentId },
			accessToken,
		);
		const comment = data.data?.comment;
		if (!comment) return null;
		return { id: comment.id, body: comment.body };
	}

	async fetchProject(
		projectId: string,
		accessToken: string,
	): Promise<{ id: string; name: string; description: string } | null> {
		const query = `
			query ProjectContent($id: String!) {
				project(id: $id) {
					id
					name
					description
					updatedAt
				}
			}
		`;
		const data = await this.graphql<LinearProjectResponse>(
			query,
			{ id: projectId },
			accessToken,
		);
		const project = data.data?.project;
		if (!project) return null;
		return {
			id: project.id,
			name: project.name,
			description: project.description ?? "",
		};
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

	static async exchangeCodeForToken(
		clientId: string,
		clientSecret: string,
		code: string,
		redirectUri: string,
	): Promise<LinearTokenResponse> {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);

		try {
			const resp = await fetch("https://api.linear.app/oauth/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: new URLSearchParams({
					client_id: clientId,
					client_secret: clientSecret,
					code,
					redirect_uri: redirectUri,
					grant_type: "authorization_code",
				}).toString(),
				signal: controller.signal,
			});
			clearTimeout(timeoutId);

			if (!resp.ok) {
				const text = await resp.text().catch(() => resp.statusText);
				throw new Error(
					`Linear token exchange failed ${resp.status}: ${text}`,
				);
			}

			return (await resp.json()) as LinearTokenResponse;
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}
}
