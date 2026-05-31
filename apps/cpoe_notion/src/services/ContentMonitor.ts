// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";

export interface ContentSnapshot {
	pageId: string;
	pageTitle: string;
	plainText: string;
	contentHash: string;
	wordCount: number;
	charCount: number;
	blockCount: number;
	fetchedAt: number;
}

export interface ContentDiff {
	charDelta: number;
	wordDelta: number;
	blockDelta: number;
}

// Notion API block types
interface NotionRichText {
	plain_text: string;
}

interface NotionBlock {
	id: string;
	type: string;
	has_children?: boolean;
	paragraph?: { rich_text: NotionRichText[] };
	heading_1?: { rich_text: NotionRichText[] };
	heading_2?: { rich_text: NotionRichText[] };
	heading_3?: { rich_text: NotionRichText[] };
	bulleted_list_item?: { rich_text: NotionRichText[] };
	numbered_list_item?: { rich_text: NotionRichText[] };
	to_do?: { rich_text: NotionRichText[]; checked: boolean };
	toggle?: { rich_text: NotionRichText[] };
	code?: { rich_text: NotionRichText[] };
	callout?: { rich_text: NotionRichText[] };
	quote?: { rich_text: NotionRichText[] };
	table_row?: { cells: NotionRichText[][] };
}

interface NotionBlocksResponse {
	results: NotionBlock[];
	has_more: boolean;
	next_cursor: string | null;
}

interface NotionPageTitle {
	title?: Array<{ plain_text: string }>;
	Name?: Array<{ plain_text: string }>;
}

interface NotionPageProperties {
	[key: string]: NotionPageTitle | unknown;
}

interface NotionPage {
	id: string;
	last_edited_time: string;
	last_edited_by?: { id: string };
	properties?: NotionPageProperties;
}

interface NotionSearchResponse {
	results: NotionPage[];
	has_more: boolean;
	next_cursor: string | null;
}

/**
 * Notion API rate limit is 3 req/s. Queue enforces 340ms spacing between
 * requests and serializes all API calls so parallel polls don't collide.
 */
class RateLimitedQueue {
	private readonly minDelayMs = 340;
	private lastRequestTime = 0;
	private queue: Array<() => void> = [];
	private running = false;

	enqueue<T>(fn: () => Promise<T>): Promise<T> {
		return new Promise<T>((resolve, reject) => {
			this.queue.push(async () => {
				const now = Date.now();
				const elapsed = now - this.lastRequestTime;
				if (elapsed < this.minDelayMs) {
					await new Promise((r) =>
						setTimeout(r, this.minDelayMs - elapsed),
					);
				}
				this.lastRequestTime = Date.now();
				try {
					resolve(await fn());
				} catch (err) {
					reject(err);
				}
			});
			if (!this.running) this.drain();
		});
	}

	private async drain(): Promise<void> {
		this.running = true;
		while (this.queue.length > 0) {
			const next = this.queue.shift();
			if (next) await next();
		}
		this.running = false;
	}
}

function extractRichText(items: NotionRichText[]): string {
	return items.map((r) => r.plain_text).join("");
}

function extractTextFromBlocks(blocks: NotionBlock[]): string {
	const parts: string[] = [];
	for (const block of blocks) {
		switch (block.type) {
			case "paragraph":
				if (block.paragraph?.rich_text.length) {
					parts.push(extractRichText(block.paragraph.rich_text));
				}
				break;
			case "heading_1":
				if (block.heading_1?.rich_text.length) {
					parts.push(extractRichText(block.heading_1.rich_text));
				}
				break;
			case "heading_2":
				if (block.heading_2?.rich_text.length) {
					parts.push(extractRichText(block.heading_2.rich_text));
				}
				break;
			case "heading_3":
				if (block.heading_3?.rich_text.length) {
					parts.push(extractRichText(block.heading_3.rich_text));
				}
				break;
			case "bulleted_list_item":
				if (block.bulleted_list_item?.rich_text.length) {
					parts.push(
						extractRichText(block.bulleted_list_item.rich_text),
					);
				}
				break;
			case "numbered_list_item":
				if (block.numbered_list_item?.rich_text.length) {
					parts.push(
						extractRichText(block.numbered_list_item.rich_text),
					);
				}
				break;
			case "to_do":
				if (block.to_do?.rich_text.length) {
					parts.push(extractRichText(block.to_do.rich_text));
				}
				break;
			case "toggle":
				if (block.toggle?.rich_text.length) {
					parts.push(extractRichText(block.toggle.rich_text));
				}
				break;
			case "code":
				if (block.code?.rich_text.length) {
					parts.push(extractRichText(block.code.rich_text));
				}
				break;
			case "callout":
				if (block.callout?.rich_text.length) {
					parts.push(extractRichText(block.callout.rich_text));
				}
				break;
			case "quote":
				if (block.quote?.rich_text.length) {
					parts.push(extractRichText(block.quote.rich_text));
				}
				break;
			case "table_row":
				if (block.table_row?.cells.length) {
					const cellText = block.table_row.cells
						.map((cell) => extractRichText(cell))
						.join(" ");
					parts.push(cellText);
				}
				break;
			// image, video, file, embed, bookmark, divider — no text content
			default:
				break;
		}
	}
	return parts.filter((p) => p.length > 0).join("\n");
}

function countWords(text: string): number {
	if (!text) return 0;
	return text.split(/\s+/).filter((w) => w.length > 0).length;
}

function hashText(text: string): string {
	return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function extractPageTitle(page: NotionPage): string {
	if (!page.properties) return page.id;
	for (const prop of Object.values(page.properties)) {
		const p = prop as NotionPageTitle;
		if (Array.isArray(p?.title) && p.title.length > 0) {
			return p.title.map((t) => t.plain_text).join("");
		}
		if (Array.isArray(p?.Name) && p.Name.length > 0) {
			return p.Name.map((t) => t.plain_text).join("");
		}
	}
	return page.id;
}

export class ContentMonitor {
	private readonly notionApiKey: string;
	private readonly queue = new RateLimitedQueue();
	/** In-memory snapshot store keyed by page ID */
	private readonly snapshots = new Map<string, ContentSnapshot>();

	constructor(notionApiKey: string) {
		if (!notionApiKey)
			throw new Error("ContentMonitor: notionApiKey is required");
		this.notionApiKey = notionApiKey;
	}

	private notionHeaders(): Record<string, string> {
		return {
			Authorization: `Bearer ${this.notionApiKey}`,
			"Notion-Version": "2022-06-28",
			"Content-Type": "application/json",
		};
	}

	private async fetchJson<T>(
		method: string,
		url: string,
		body?: unknown,
	): Promise<T> {
		return this.queue.enqueue(async () => {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 30_000);
			try {
				const resp = await fetch(url, {
					method,
					headers: this.notionHeaders(),
					body: body !== undefined ? JSON.stringify(body) : undefined,
					signal: controller.signal,
				});
				clearTimeout(timeoutId);
				if (!resp.ok) {
					const text = await resp.text();
					throw new Error(
						`Notion API ${resp.status} ${method} ${url}: ${text}`,
					);
				}
				return (await resp.json()) as T;
			} catch (err) {
				clearTimeout(timeoutId);
				throw err;
			}
		});
	}

	/**
	 * Fetches all blocks for a page, following has_more pagination.
	 * Recursively fetches children for blocks that have them.
	 */
	private async fetchAllBlocks(blockId: string): Promise<NotionBlock[]> {
		const allBlocks: NotionBlock[] = [];
		let cursor: string | null = null;

		do {
			const url = new URL(
				`https://api.notion.com/v1/blocks/${encodeURIComponent(blockId)}/children`,
			);
			url.searchParams.set("page_size", "100");
			if (cursor) url.searchParams.set("start_cursor", cursor);

			const resp = await this.fetchJson<NotionBlocksResponse>(
				"GET",
				url.toString(),
			);
			allBlocks.push(...resp.results);
			cursor = resp.has_more ? resp.next_cursor : null;
		} while (cursor !== null);

		// Recursively fetch children for blocks that have nested content
		const withChildren = allBlocks.filter(
			(b) =>
				b.has_children &&
				["toggle", "bulleted_list_item", "numbered_list_item"].includes(
					b.type,
				),
		);
		for (const block of withChildren) {
			const children = await this.fetchAllBlocks(block.id);
			allBlocks.push(...children);
		}

		return allBlocks;
	}

	async captureSnapshot(page: NotionPage): Promise<ContentSnapshot> {
		const blocks = await this.fetchAllBlocks(page.id);
		const plainText = extractTextFromBlocks(blocks);
		const title = extractPageTitle(page);

		const snapshot: ContentSnapshot = {
			pageId: page.id,
			pageTitle: title,
			plainText,
			contentHash: hashText(plainText),
			wordCount: countWords(plainText),
			charCount: plainText.length,
			blockCount: blocks.length,
			fetchedAt: Date.now(),
		};

		this.snapshots.set(page.id, snapshot);
		return snapshot;
	}

	getPreviousSnapshot(pageId: string): ContentSnapshot | null {
		return this.snapshots.get(pageId) ?? null;
	}

	clearSnapshot(pageId: string): void {
		this.snapshots.delete(pageId);
	}

	computeDiff(
		previous: ContentSnapshot,
		current: ContentSnapshot,
	): ContentDiff {
		return {
			charDelta: current.charCount - previous.charCount,
			wordDelta: current.wordCount - previous.wordCount,
			blockDelta: current.blockCount - previous.blockCount,
		};
	}

	/**
	 * Returns pages modified since the given time, newest first.
	 * page_size capped at 20 to avoid deep pagination on every poll cycle.
	 */
	async searchRecentPages(since?: Date): Promise<NotionPage[]> {
		const resp = await this.fetchJson<NotionSearchResponse>(
			"POST",
			"https://api.notion.com/v1/search",
			{
				filter: { property: "object", value: "page" },
				sort: {
					timestamp: "last_edited_time",
					direction: "descending",
				},
				page_size: 20,
			},
		);

		if (!since) return resp.results;
		return resp.results.filter((p) => new Date(p.last_edited_time) > since);
	}
}
