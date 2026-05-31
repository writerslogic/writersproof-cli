// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";

export interface ContentSnapshot {
	resourceId: string;
	resourceTitle: string;
	plainText: string;
	contentHash: string;
	wordCount: number;
	charCount: number;
	fetchedAt: number;
}

export interface ContentDiff {
	charDelta: number;
	wordDelta: number;
}

export type ClioResourceType = "document" | "note" | "communication";

interface ClioDocumentVersion {
	id: number;
	document_id: number;
}

interface ClioDocument {
	id: number;
	name: string;
	content_type: string;
	latest_document_version?: ClioDocumentVersion;
}

interface ClioNote {
	id: number;
	subject: string;
	detail: string;
	date: string;
}

interface ClioNoteResponse {
	data: ClioNote;
}

interface ClioDocumentResponse {
	data: ClioDocument;
}

interface ClioCommunication {
	id: number;
	subject: string;
	body: string;
	date: string;
}

interface ClioCommunicationResponse {
	data: ClioCommunication;
}

interface TokenStore {
	accessToken: string;
	refreshToken: string;
}

function countWords(text: string): number {
	if (!text) return 0;
	return text.split(/\s+/).filter((w) => w.length > 0).length;
}

function hashText(text: string): string {
	return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function hashBinary(buf: Buffer): string {
	return crypto.createHash("sha256").update(buf).digest("hex");
}

export class ContentMonitor {
	private readonly clientId: string;
	private readonly clientSecret: string;
	private tokens: TokenStore;
	private readonly snapshots = new Map<string, ContentSnapshot>();
	private static readonly API_BASE = "https://app.clio.com/api/v4";

	constructor(
		clientId: string,
		clientSecret: string,
		accessToken: string,
		refreshToken: string,
	) {
		if (!clientId) throw new Error("ContentMonitor: clientId is required");
		if (!clientSecret)
			throw new Error("ContentMonitor: clientSecret is required");
		if (!accessToken)
			throw new Error("ContentMonitor: accessToken is required");
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.tokens = { accessToken, refreshToken };
	}

	updateTokens(accessToken: string, refreshToken: string): void {
		this.tokens = { accessToken, refreshToken };
	}

	getTokens(): Readonly<TokenStore> {
		return this.tokens;
	}

	private async fetchWithAuth(
		url: string,
		options: RequestInit = {},
	): Promise<Response> {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);

		try {
			const resp = await fetch(url, {
				...options,
				headers: {
					Authorization: `Bearer ${this.tokens.accessToken}`,
					"Content-Type": "application/json",
					...(options.headers as Record<string, string> | undefined),
				},
				signal: controller.signal,
			});
			clearTimeout(timeoutId);

			if (resp.status === 401 && this.tokens.refreshToken) {
				const refreshed = await this.refreshAccessToken(
					this.tokens.refreshToken,
				);
				this.tokens = refreshed;
				// Retry once with new token
				const controller2 = new AbortController();
				const timeoutId2 = setTimeout(
					() => controller2.abort(),
					30_000,
				);
				try {
					const resp2 = await fetch(url, {
						...options,
						headers: {
							Authorization: `Bearer ${this.tokens.accessToken}`,
							"Content-Type": "application/json",
							...(options.headers as
								| Record<string, string>
								| undefined),
						},
						signal: controller2.signal,
					});
					clearTimeout(timeoutId2);
					return resp2;
				} catch (err) {
					clearTimeout(timeoutId2);
					throw err;
				}
			}

			return resp;
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	private async refreshAccessToken(
		refreshToken: string,
	): Promise<TokenStore> {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);
		try {
			const resp = await fetch("https://app.clio.com/oauth/token", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					grant_type: "refresh_token",
					refresh_token: refreshToken,
					client_id: this.clientId,
					client_secret: this.clientSecret,
				}),
				signal: controller.signal,
			});
			clearTimeout(timeoutId);
			if (!resp.ok) {
				const text = await resp.text();
				throw new Error(
					`Clio token refresh failed ${resp.status}: ${text}`,
				);
			}
			const data = (await resp.json()) as {
				access_token: string;
				refresh_token: string;
			};
			return {
				accessToken: data.access_token,
				refreshToken: data.refresh_token,
			};
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	private snapshotKey(type: ClioResourceType, id: number): string {
		return `${type}:${id}`;
	}

	async captureDocumentSnapshot(
		documentId: number,
	): Promise<ContentSnapshot> {
		const url = `${ContentMonitor.API_BASE}/documents/${documentId}.json?fields=id,name,content_type,latest_document_version`;
		const resp = await this.fetchWithAuth(url);
		if (!resp.ok) {
			const text = await resp.text();
			throw new Error(
				`Clio document ${documentId} fetch failed: ${text}`,
			);
		}
		const data = (await resp.json()) as ClioDocumentResponse;
		const doc = data.data;

		let contentHash: string;
		let plainText = "";
		let wordCount = 0;
		let charCount = 0;

		if (doc.latest_document_version) {
			const dlUrl = `${ContentMonitor.API_BASE}/document_versions/${doc.latest_document_version.id}/download`;
			const dlResp = await this.fetchWithAuth(dlUrl, {
				headers: { "Content-Type": "application/octet-stream" },
			});
			if (dlResp.ok) {
				const buf = Buffer.from(await dlResp.arrayBuffer());
				// For text-based content types, extract plain text for word counting
				if (
					doc.content_type.startsWith("text/") ||
					doc.content_type === "application/json"
				) {
					plainText = buf.toString("utf8");
					wordCount = countWords(plainText);
					charCount = plainText.length;
					contentHash = hashText(plainText);
				} else {
					contentHash = hashBinary(buf);
				}
			} else {
				contentHash = hashText(`${doc.id}:${doc.name}`);
			}
		} else {
			contentHash = hashText(`${doc.id}:${doc.name}`);
		}

		const snapshot: ContentSnapshot = {
			resourceId: String(doc.id),
			resourceTitle: doc.name,
			plainText,
			contentHash,
			wordCount,
			charCount,
			fetchedAt: Date.now(),
		};

		this.snapshots.set(this.snapshotKey("document", documentId), snapshot);
		return snapshot;
	}

	async captureNoteSnapshot(noteId: number): Promise<ContentSnapshot> {
		const url = `${ContentMonitor.API_BASE}/notes/${noteId}.json?fields=id,subject,detail,date`;
		const resp = await this.fetchWithAuth(url);
		if (!resp.ok) {
			const text = await resp.text();
			throw new Error(`Clio note ${noteId} fetch failed: ${text}`);
		}
		const data = (await resp.json()) as ClioNoteResponse;
		const note = data.data;
		const plainText = [note.subject, note.detail]
			.filter(Boolean)
			.join("\n");

		const snapshot: ContentSnapshot = {
			resourceId: String(note.id),
			resourceTitle: note.subject ?? `Note ${note.id}`,
			plainText,
			contentHash: hashText(plainText),
			wordCount: countWords(plainText),
			charCount: plainText.length,
			fetchedAt: Date.now(),
		};

		this.snapshots.set(this.snapshotKey("note", noteId), snapshot);
		return snapshot;
	}

	async captureCommunicationSnapshot(
		commId: number,
	): Promise<ContentSnapshot> {
		const url = `${ContentMonitor.API_BASE}/communications/${commId}.json?fields=id,subject,body,date`;
		const resp = await this.fetchWithAuth(url);
		if (!resp.ok) {
			const text = await resp.text();
			throw new Error(
				`Clio communication ${commId} fetch failed: ${text}`,
			);
		}
		const data = (await resp.json()) as ClioCommunicationResponse;
		const comm = data.data;
		const plainText = [comm.subject, comm.body].filter(Boolean).join("\n");

		const snapshot: ContentSnapshot = {
			resourceId: String(comm.id),
			resourceTitle: comm.subject ?? `Communication ${comm.id}`,
			plainText,
			contentHash: hashText(plainText),
			wordCount: countWords(plainText),
			charCount: plainText.length,
			fetchedAt: Date.now(),
		};

		this.snapshots.set(this.snapshotKey("communication", commId), snapshot);
		return snapshot;
	}

	getPreviousSnapshot(
		type: ClioResourceType,
		id: number,
	): ContentSnapshot | null {
		return this.snapshots.get(this.snapshotKey(type, id)) ?? null;
	}

	clearSnapshot(type: ClioResourceType, id: number): void {
		this.snapshots.delete(this.snapshotKey(type, id));
	}

	computeDiff(
		previous: ContentSnapshot,
		current: ContentSnapshot,
	): ContentDiff {
		return {
			charDelta: current.charCount - previous.charCount,
			wordDelta: current.wordCount - previous.wordCount,
		};
	}
}
