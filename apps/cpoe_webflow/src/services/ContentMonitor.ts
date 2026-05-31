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

interface WebflowCollectionItem {
	id: string;
	fieldData: Record<string, unknown>;
	[key: string]: unknown;
}

interface WebflowCollectionItemResponse {
	item?: WebflowCollectionItem;
	[key: string]: unknown;
}

interface WebflowPageResponse {
	id: string;
	title?: string;
	slug?: string;
	[key: string]: unknown;
}

function hashText(text: string): string {
	return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function countWords(text: string): number {
	if (!text) return 0;
	return text.split(/\s+/).filter((w) => w.length > 0).length;
}

/**
 * Extracts all string-valued fields from a Webflow CMS item's fieldData,
 * concatenates them in key order for a stable, deterministic snapshot.
 */
function extractTextFromFieldData(fieldData: Record<string, unknown>): string {
	return Object.keys(fieldData)
		.sort()
		.map((k) => {
			const v = fieldData[k];
			if (typeof v === "string") return v;
			if (typeof v === "number" || typeof v === "boolean")
				return String(v);
			return "";
		})
		.filter((s) => s.length > 0)
		.join(" ");
}

/**
 * Derives a human-readable title from Webflow CMS item field data.
 * Checks common field names in priority order.
 */
function extractTitle(
	fieldData: Record<string, unknown>,
	fallbackId: string,
): string {
	const candidates = ["name", "title", "slug", "Name", "Title", "Slug"];
	for (const key of candidates) {
		const v = fieldData[key];
		if (typeof v === "string" && v.length > 0) return v;
	}
	return fallbackId;
}

export class ContentMonitor {
	private readonly accessToken: string;
	private readonly apiBase = "https://api.webflow.com/v2";
	private readonly snapshots = new Map<string, ContentSnapshot>();

	constructor(accessToken: string) {
		if (!accessToken)
			throw new Error("ContentMonitor: accessToken is required");
		this.accessToken = accessToken;
	}

	private authHeader(): Record<string, string> {
		return {
			Authorization: `Bearer ${this.accessToken}`,
			"Accept-Version": "2.0.0",
		};
	}

	private async fetchWithTimeout(url: string): Promise<Response> {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);
		try {
			const resp = await fetch(url, {
				headers: this.authHeader(),
				signal: controller.signal,
			});
			clearTimeout(timeoutId);
			return resp;
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	async snapshotCollectionItem(
		collectionId: string,
		itemId: string,
	): Promise<ContentDiff> {
		const url = `${this.apiBase}/collections/${encodeURIComponent(collectionId)}/items/${encodeURIComponent(itemId)}`;
		const resp = await this.fetchWithTimeout(url);

		if (!resp.ok) {
			const text = await resp.text();
			throw new Error(
				`Webflow API ${resp.status} for collections/${collectionId}/items/${itemId}: ${text}`,
			);
		}

		const data = (await resp.json()) as WebflowCollectionItemResponse;
		const item = data.item ?? (data as unknown as WebflowCollectionItem);
		const fieldData: Record<string, unknown> =
			typeof item.fieldData === "object" && item.fieldData !== null
				? item.fieldData
				: {};

		const plainText = extractTextFromFieldData(fieldData);
		const title = extractTitle(fieldData, itemId);
		return this.recordSnapshot(itemId, title, plainText);
	}

	async snapshotPage(pageId: string): Promise<ContentDiff> {
		const url = `${this.apiBase}/pages/${encodeURIComponent(pageId)}`;
		const resp = await this.fetchWithTimeout(url);

		if (resp.status === 404) {
			return this.recordSnapshot(pageId, pageId, "");
		}

		if (!resp.ok) {
			const text = await resp.text();
			throw new Error(
				`Webflow API ${resp.status} for pages/${pageId}: ${text}`,
			);
		}

		const data = (await resp.json()) as WebflowPageResponse;
		const title = data.title ?? data.slug ?? pageId;
		return this.recordSnapshot(pageId, title, title);
	}

	private recordSnapshot(
		id: string,
		title: string,
		plainText: string,
	): ContentDiff {
		const snapshot: ContentSnapshot = {
			documentId: id,
			documentTitle: title,
			plainText,
			contentHash: hashText(plainText),
			wordCount: countWords(plainText),
			charCount: plainText.length,
			fetchedAt: Date.now(),
		};

		const previous = this.snapshots.get(id) ?? null;
		this.snapshots.set(id, snapshot);

		return {
			previous,
			current: snapshot,
			changed:
				previous === null ||
				previous.contentHash !== snapshot.contentHash,
			wordDelta: snapshot.wordCount - (previous?.wordCount ?? 0),
			charDelta: snapshot.charCount - (previous?.charCount ?? 0),
		};
	}

	getSnapshot(id: string): ContentSnapshot | null {
		return this.snapshots.get(id) ?? null;
	}

	clearSnapshot(id: string): void {
		this.snapshots.delete(id);
	}

	/** Clears all stored snapshots, e.g. on site_publish finalization. */
	clearAll(): void {
		this.snapshots.clear();
	}
}
