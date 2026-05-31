// SPDX-License-Identifier: AGPL-3.0-only
import { Request, Response } from "express";
import { WritersProofClient } from "../services/WritersProofClient.js";
import { ContentMonitor } from "../services/ContentMonitor.js";

interface WebflowItemPayload {
	_id?: string;
	id?: string;
	slug?: string;
	name?: string;
	_cid?: string;
	siteId?: string;
	"field-values"?: Record<string, unknown>;
	[key: string]: unknown;
}

interface WebflowWebhookBody {
	triggerType?: string;
	payload?: WebflowItemPayload;
	[key: string]: unknown;
}

const activeSessions = new Map<string, string>();

function resolveItemId(payload: WebflowItemPayload): string {
	return payload._id ?? payload.id ?? "";
}

function resolveCollectionId(payload: WebflowItemPayload): string {
	return payload._cid ?? "";
}

function resolveTitle(payload: WebflowItemPayload): string {
	return payload.name ?? payload.slug ?? resolveItemId(payload);
}

export function createWebflowEventHandler(
	client: WritersProofClient,
	monitor: ContentMonitor,
) {
	return async function handleWebflowEvent(
		req: Request,
		res: Response,
	): Promise<void> {
		const body = req.body as WebflowWebhookBody;
		const triggerType = body.triggerType ?? "";
		const payload = body.payload ?? {};

		try {
			switch (triggerType) {
				case "collection_item_created": {
					const itemId = resolveItemId(payload);
					const collectionId = resolveCollectionId(payload);
					if (!itemId) {
						res.status(200).json({
							ok: true,
							skipped: "no item id",
						});
						return;
					}

					const diff = collectionId
						? await monitor.snapshotCollectionItem(
								collectionId,
								itemId,
							)
						: {
								current: {
									documentId: itemId,
									documentTitle: resolveTitle(payload),
									plainText: "",
									contentHash: "",
									wordCount: 0,
									charCount: 0,
									fetchedAt: Date.now(),
								},
								previous: null,
								changed: true,
								wordDelta: 0,
								charDelta: 0,
							};

					const title =
						diff.current.documentTitle !== itemId
							? diff.current.documentTitle
							: resolveTitle(payload);

					const session = await client.createSession({
						documentId: itemId,
						documentTitle: title,
						contentHash: diff.current.contentHash,
					});
					activeSessions.set(itemId, session.id);
					res.status(200).json({
						ok: true,
						event: triggerType,
						itemId,
						sessionId: session.id,
					});
					break;
				}

				case "collection_item_changed": {
					const itemId = resolveItemId(payload);
					const collectionId = resolveCollectionId(payload);
					if (!itemId) {
						res.status(200).json({
							ok: true,
							skipped: "no item id",
						});
						return;
					}

					const diff = collectionId
						? await monitor.snapshotCollectionItem(
								collectionId,
								itemId,
							)
						: {
								current: {
									documentId: itemId,
									documentTitle: resolveTitle(payload),
									plainText: "",
									contentHash: "",
									wordCount: 0,
									charCount: 0,
									fetchedAt: Date.now(),
								},
								previous: null,
								changed: true,
								wordDelta: 0,
								charDelta: 0,
							};

					let sessionId = activeSessions.get(itemId);
					if (!sessionId) {
						const session = await client.createSession({
							documentId: itemId,
							documentTitle: diff.current.documentTitle,
							contentHash:
								diff.previous?.contentHash ??
								diff.current.contentHash,
						});
						sessionId = session.id;
						activeSessions.set(itemId, sessionId);
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

					res.status(200).json({
						ok: true,
						event: triggerType,
						itemId,
						changed: diff.changed,
					});
					break;
				}

				case "collection_item_deleted": {
					const itemId = resolveItemId(payload);
					if (!itemId) {
						res.status(200).json({
							ok: true,
							skipped: "no item id",
						});
						return;
					}

					const sessionId = activeSessions.get(itemId);
					if (sessionId) {
						const snapshot = monitor.getSnapshot(itemId);
						await client.finalizeSession(sessionId, {
							contentHash: snapshot?.contentHash ?? "",
							wordCount: snapshot?.wordCount ?? 0,
							finalSnapshot: "deleted",
						});
						activeSessions.delete(itemId);
						monitor.clearSnapshot(itemId);
					}

					res.status(200).json({
						ok: true,
						event: triggerType,
						itemId,
					});
					break;
				}

				case "site_publish": {
					const siteId = payload.siteId ?? "";
					const toFinalize = Array.from(activeSessions.entries());
					await Promise.allSettled(
						toFinalize.map(async ([itemId, sessionId]) => {
							const snapshot = monitor.getSnapshot(itemId);
							await client.finalizeSession(sessionId, {
								contentHash: snapshot?.contentHash ?? "",
								wordCount: snapshot?.wordCount ?? 0,
								finalSnapshot: snapshot?.plainText,
							});
							activeSessions.delete(itemId);
							monitor.clearSnapshot(itemId);
						}),
					);

					res.status(200).json({
						ok: true,
						event: triggerType,
						siteId,
						finalized: toFinalize.length,
					});
					break;
				}

				case "page_created":
				case "page_metadata_updated": {
					const pageId = resolveItemId(payload);
					if (!pageId) {
						res.status(200).json({
							ok: true,
							skipped: "no page id",
						});
						return;
					}

					const diff = await monitor.snapshotPage(pageId);
					let sessionId = activeSessions.get(pageId);

					if (!sessionId) {
						const session = await client.createSession({
							documentId: pageId,
							documentTitle: diff.current.documentTitle,
							contentHash: diff.current.contentHash,
						});
						sessionId = session.id;
						activeSessions.set(pageId, sessionId);
					} else if (diff.changed) {
						await client.submitEvents(sessionId, [
							{
								type: "metadata_change",
								timestamp: Date.now(),
								contentHash: diff.current.contentHash,
							},
						]);
						await client.createCheckpoint(sessionId, {
							contentHash: diff.current.contentHash,
							wordCount: diff.current.wordCount,
							charCount: diff.current.charCount,
						});
					}

					res.status(200).json({
						ok: true,
						event: triggerType,
						pageId,
					});
					break;
				}

				default:
					res.status(200).json({
						ok: true,
						skipped: `unhandled event: ${triggerType}`,
					});
			}
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			res.status(500).json({ ok: false, error: message });
		}
	};
}
