// SPDX-License-Identifier: AGPL-3.0-only
import { Request, Response } from "express";
import { WritersProofClient } from "@writersproof/sdk";
import { ContentMonitor } from "../services/ContentMonitor.js";

interface GhostResourceCurrent {
	id: string;
	title?: string;
	html?: string;
	status?: string;
	updated_at?: string;
}

interface GhostWebhookPayload {
	post?: { current?: GhostResourceCurrent; previous?: GhostResourceCurrent };
	page?: { current?: GhostResourceCurrent; previous?: GhostResourceCurrent };
}

interface GhostWebhookBody {
	event?: string;
	data?: GhostWebhookPayload;
	// Ghost also sends the event type at the top level in some versions
	[key: string]: unknown;
}

const MAX_SESSIONS = 100;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

interface SessionEntry {
	sessionId: string;
	createdAt: number;
}

/** Active WritersProof session IDs keyed by "{type}:{resourceId}" */
const activeSessions = new Map<string, SessionEntry>();

function pruneSessions(): void {
	const now = Date.now();
	for (const [key, entry] of activeSessions) {
		if (now - entry.createdAt > SESSION_TTL_MS) activeSessions.delete(key);
	}
	if (activeSessions.size > MAX_SESSIONS) {
		const sorted = [...activeSessions.entries()].sort(
			(a, b) => a[1].createdAt - b[1].createdAt,
		);
		const excess = sorted.slice(0, activeSessions.size - MAX_SESSIONS);
		for (const [key] of excess) activeSessions.delete(key);
	}
}

function sessionKey(type: "post" | "page", id: string): string {
	return `${type}:${id}`;
}

export function createGhostEventHandler(
	client: WritersProofClient,
	monitor: ContentMonitor,
) {
	return async function handleGhostEvent(
		req: Request,
		res: Response,
	): Promise<void> {
		const body = req.body as GhostWebhookBody;

		// Ghost sends the event type as a top-level key alongside "data",
		// or as body.event depending on integration version.
		const eventType =
			typeof body.event === "string"
				? body.event
				: (Object.keys(body).find(
						(k) => k !== "data" && k !== "event",
					) ?? "");

		const data = (body.data ?? body[eventType]) as
			| GhostWebhookPayload
			| undefined;

		const resourceType: "post" | "page" = eventType.startsWith("page")
			? "page"
			: "post";
		const resourceData = resourceType === "page" ? data?.page : data?.post;
		const current = resourceData?.current;

		if (!current?.id) {
			res.status(200).json({ ok: true, skipped: "no resource id" });
			return;
		}

		const resourceId = current.id;
		const key = sessionKey(resourceType, resourceId);

		try {
			switch (eventType) {
				case "post.added":
				case "page.added": {
					const diff =
						await monitor[
							resourceType === "post"
								? "snapshotPost"
								: "snapshotPage"
						](resourceId);
					const session = await client.createSession({
						documentId: resourceId,
						documentTitle: diff.current.documentTitle,
						contentHash: diff.current.contentHash,
					});
					pruneSessions();
					activeSessions.set(key, {
						sessionId: session.id,
						createdAt: Date.now(),
					});
					break;
				}

				case "post.edited":
				case "page.edited": {
					const diff =
						await monitor[
							resourceType === "post"
								? "snapshotPost"
								: "snapshotPage"
						](resourceId);

					let sessionId = activeSessions.get(key)?.sessionId;
					if (!sessionId) {
						const session = await client.createSession({
							documentId: resourceId,
							documentTitle: diff.current.documentTitle,
							contentHash:
								diff.previous?.contentHash ??
								diff.current.contentHash,
						});
						sessionId = session.id;
						pruneSessions();
						activeSessions.set(key, {
							sessionId,
							createdAt: Date.now(),
						});
					}

					if (diff.changed) {
						await client.submitEvents(sessionId, [
							{
								type: "content_change",
								timestamp: Date.now(),
								wordDelta: diff.wordDelta,
								charDelta: diff.charDelta,
								contentHash: diff.current.contentHash,
							},
						]);

						await client.createCheckpoint(sessionId, {
							contentHash: diff.current.contentHash,
							wordCount: diff.current.wordCount,
							charCount: diff.current.charCount,
						});
					}
					break;
				}

				case "post.published":
				case "page.published": {
					const diff =
						await monitor[
							resourceType === "post"
								? "snapshotPost"
								: "snapshotPage"
						](resourceId);
					const published = activeSessions.get(key);
					if (published) {
						await client.finalizeSession(published.sessionId, {
							contentHash: diff.current.contentHash,
							wordCount: diff.current.wordCount,
							finalSnapshot: diff.current.plainText,
						});
						activeSessions.delete(key);
						monitor.clearSnapshot(
							resourceType === "post" ? "posts" : "pages",
							resourceId,
						);
					}
					break;
				}

				case "post.deleted":
				case "page.deleted": {
					const deleted = activeSessions.get(key);
					if (deleted) {
						const snapshot = monitor.getSnapshot(
							resourceType === "post" ? "posts" : "pages",
							resourceId,
						);
						await client.finalizeSession(deleted.sessionId, {
							contentHash: snapshot?.contentHash ?? "",
							wordCount: snapshot?.wordCount ?? 0,
							finalSnapshot: "deleted",
						});
						activeSessions.delete(key);
						monitor.clearSnapshot(
							resourceType === "post" ? "posts" : "pages",
							resourceId,
						);
					}
					break;
				}

				default:
					res.status(200).json({
						ok: true,
						skipped: `unhandled event: ${eventType}`,
					});
					return;
			}

			res.status(200).json({ ok: true, event: eventType, resourceId });
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			res.status(500).json({ ok: false, error: message });
		}
	};
}
