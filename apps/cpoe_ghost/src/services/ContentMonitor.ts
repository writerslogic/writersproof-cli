// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";
import jwt from "jsonwebtoken";

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

interface GhostPostData {
	id: string;
	title: string;
	html: string | null;
	status: string;
	updated_at: string;
}

interface GhostPostResponse {
	posts?: GhostPostData[];
	pages?: GhostPostData[];
}

/**
 * Strips HTML tags and normalizes whitespace, returning plain text suitable
 * for hashing and word counting.
 */
function stripHtml(html: string): string {
	return html
		.replace(/<[^>]+>/g, " ")
		.replace(/&nbsp;/g, " ")
		.replace(/&#x([0-9a-fA-F]+);/g, (_m, hex) =>
			String.fromCodePoint(parseInt(hex, 16)),
		)
		.replace(/&#(\d+);/g, (_m, dec) =>
			String.fromCodePoint(parseInt(dec, 10)),
		)
		.replace(/&amp;/g, "&")
		.replace(/&lt;/g, "<")
		.replace(/&gt;/g, ">")
		.replace(/&quot;/g, '"')
		.replace(/&#39;/g, "'")
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

/**
 * Generates a Ghost Admin API JWT.
 * Ghost Admin API key format: "{id}:{secret}" where secret is hex-encoded.
 * Token is valid for 5 minutes.
 */
function buildGhostAdminToken(adminApiKey: string): string {
	const colonIdx = adminApiKey.indexOf(":");
	if (colonIdx === -1) {
		throw new Error(
			'GHOST_ADMIN_API_KEY must be in the format "id:secret"',
		);
	}
	const keyId = adminApiKey.slice(0, colonIdx);
	const secret = adminApiKey.slice(colonIdx + 1);

	const iat = Math.floor(Date.now() / 1000);
	return jwt.sign(
		{ iat, exp: iat + 300, aud: "/admin/" },
		Buffer.from(secret, "hex"),
		{
			algorithm: "HS256",
			header: { alg: "HS256", typ: "JWT", kid: keyId },
		},
	);
}

export class ContentMonitor {
	private readonly ghostUrl: string;
	private readonly adminApiKey: string;
	/** In-memory snapshot store keyed by "{type}:{id}" */
	private readonly snapshots = new Map<string, ContentSnapshot>();

	private readonly adminKeyValid: boolean;

	constructor(ghostUrl: string, adminApiKey: string) {
		if (!ghostUrl) throw new Error("ContentMonitor: ghostUrl is required");
		if (!adminApiKey)
			throw new Error("ContentMonitor: adminApiKey is required");
		this.ghostUrl = ghostUrl.replace(/\/$/, "");
		this.adminApiKey = adminApiKey;

		try {
			buildGhostAdminToken(this.adminApiKey);
			this.adminKeyValid = true;
		} catch {
			this.adminKeyValid = false;
		}
	}

	private authHeader(): string {
		if (!this.adminKeyValid) {
			throw new Error(
				'GHOST_ADMIN_API_KEY must be in the format "id:secret"',
			);
		}
		return `Ghost ${buildGhostAdminToken(this.adminApiKey)}`;
	}

	private async fetchResource(
		type: "posts" | "pages",
		id: string,
	): Promise<GhostPostData | null> {
		const url = `${this.ghostUrl}/ghost/api/admin/${type}/${encodeURIComponent(id)}/`;
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);

		try {
			const resp = await fetch(url, {
				headers: {
					Authorization: this.authHeader(),
					"Accept-Version": "v5.0",
				},
				signal: controller.signal,
			});
			clearTimeout(timeoutId);

			if (resp.status === 404) return null;
			if (!resp.ok) {
				const text = await resp.text();
				throw new Error(
					`Ghost Admin API ${resp.status} for ${type}/${id}: ${text}`,
				);
			}

			const data = (await resp.json()) as GhostPostResponse;
			const items = type === "posts" ? data.posts : data.pages;
			return items && items.length > 0 ? items[0] : null;
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	async snapshotPost(id: string): Promise<ContentDiff> {
		return this.snapshotResource("posts", id);
	}

	async snapshotPage(id: string): Promise<ContentDiff> {
		return this.snapshotResource("pages", id);
	}

	private async snapshotResource(
		type: "posts" | "pages",
		id: string,
	): Promise<ContentDiff> {
		const storeKey = `${type}:${id}`;
		const resource = await this.fetchResource(type, id);

		const plainText = resource?.html ? stripHtml(resource.html) : "";
		const title = resource?.title ?? id;
		const snapshot: ContentSnapshot = {
			documentId: id,
			documentTitle: title,
			plainText,
			contentHash: hashText(plainText),
			wordCount: countWords(plainText),
			charCount: plainText.length,
			fetchedAt: Date.now(),
		};

		const previous = this.snapshots.get(storeKey) ?? null;
		this.snapshots.set(storeKey, snapshot);

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

	/**
	 * Returns the stored snapshot for a resource without fetching from Ghost.
	 * Returns null if no snapshot has been recorded yet.
	 */
	getSnapshot(type: "posts" | "pages", id: string): ContentSnapshot | null {
		return this.snapshots.get(`${type}:${id}`) ?? null;
	}

	/**
	 * Removes the stored snapshot, e.g. after a session is finalized.
	 */
	clearSnapshot(type: "posts" | "pages", id: string): void {
		this.snapshots.delete(`${type}:${id}`);
	}
}
