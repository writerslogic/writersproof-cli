// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";
import { Request, Response } from "express";
import { WritersProofClient } from "../services/WritersProofClient.js";
import {
	ContentMonitor,
	ClioResourceType,
} from "../services/ContentMonitor.js";

export interface ClioWebhookPayload {
	data: {
		id: number;
		type: string;
		[key: string]: unknown;
	};
	event: "created" | "updated" | "deleted";
}

/** Active WritersProof session IDs keyed by "{type}:{id}" */
const activeSessions = new Map<string, string>();

function sessionKey(type: ClioResourceType, id: number): string {
	return `${type}:${id}`;
}

export function getActiveSessionId(
	type: ClioResourceType,
	id: number,
): string | undefined {
	return activeSessions.get(sessionKey(type, id));
}

export function verifyClioSignature(
	rawBody: Buffer,
	signatureHeader: string,
	webhookSecret: string,
): boolean {
	const expected = crypto
		.createHmac("sha256", webhookSecret)
		.update(rawBody)
		.digest("hex");
	const provided = signatureHeader.toLowerCase().startsWith("sha256=")
		? signatureHeader.slice(7)
		: signatureHeader;
	try {
		return crypto.timingSafeEqual(
			Buffer.from(expected, "hex"),
			Buffer.from(provided, "hex"),
		);
	} catch {
		return false;
	}
}

async function handleDocument(
	event: "created" | "updated" | "deleted",
	id: number,
	client: WritersProofClient,
	monitor: ContentMonitor,
): Promise<void> {
	const key = sessionKey("document", id);

	if (event === "created") {
		const snapshot = await monitor.captureDocumentSnapshot(id);
		const session = await client.createSession({
			documentId: String(id),
			documentTitle: snapshot.resourceTitle,
			contentHash: snapshot.contentHash,
		});
		activeSessions.set(key, session.id);
		return;
	}

	if (event === "updated") {
		const previous = monitor.getPreviousSnapshot("document", id);
		const snapshot = await monitor.captureDocumentSnapshot(id);

		let sessionId = activeSessions.get(key);
		if (!sessionId) {
			const session = await client.createSession({
				documentId: String(id),
				documentTitle: snapshot.resourceTitle,
				contentHash: previous?.contentHash ?? snapshot.contentHash,
			});
			sessionId = session.id;
			activeSessions.set(key, sessionId);
		}

		if (!previous || previous.contentHash !== snapshot.contentHash) {
			const diff = previous
				? monitor.computeDiff(previous, snapshot)
				: {
						charDelta: snapshot.charCount,
						wordDelta: snapshot.wordCount,
					};

			await client.submitEvents(sessionId, [
				{
					type: "content_change",
					timestamp: Date.now(),
					charDelta: diff.charDelta,
					wordDelta: diff.wordDelta,
					contentHash: snapshot.contentHash,
				},
			]);
			await client.createCheckpoint(sessionId, {
				contentHash: snapshot.contentHash,
				wordCount: snapshot.wordCount,
				charCount: snapshot.charCount,
			});
		}
		return;
	}

	if (event === "deleted") {
		const sessionId = activeSessions.get(key);
		if (sessionId) {
			const snapshot = monitor.getPreviousSnapshot("document", id);
			await client.finalizeSession(sessionId, {
				contentHash: snapshot?.contentHash ?? "",
				wordCount: snapshot?.wordCount ?? 0,
				finalSnapshot: "deleted",
			});
			activeSessions.delete(key);
			monitor.clearSnapshot("document", id);
		}
	}
}

async function handleNote(
	event: "created" | "updated" | "deleted",
	id: number,
	client: WritersProofClient,
	monitor: ContentMonitor,
): Promise<void> {
	const key = sessionKey("note", id);

	if (event === "created") {
		const snapshot = await monitor.captureNoteSnapshot(id);
		const session = await client.createSession({
			documentId: String(id),
			documentTitle: snapshot.resourceTitle,
			contentHash: snapshot.contentHash,
		});
		activeSessions.set(key, session.id);
		return;
	}

	if (event === "updated") {
		const previous = monitor.getPreviousSnapshot("note", id);
		const snapshot = await monitor.captureNoteSnapshot(id);

		let sessionId = activeSessions.get(key);
		if (!sessionId) {
			const session = await client.createSession({
				documentId: String(id),
				documentTitle: snapshot.resourceTitle,
				contentHash: previous?.contentHash ?? snapshot.contentHash,
			});
			sessionId = session.id;
			activeSessions.set(key, sessionId);
		}

		if (!previous || previous.contentHash !== snapshot.contentHash) {
			const diff = previous
				? monitor.computeDiff(previous, snapshot)
				: {
						charDelta: snapshot.charCount,
						wordDelta: snapshot.wordCount,
					};

			await client.submitEvents(sessionId, [
				{
					type: "content_change",
					timestamp: Date.now(),
					charDelta: diff.charDelta,
					wordDelta: diff.wordDelta,
					contentHash: snapshot.contentHash,
				},
			]);
			await client.createCheckpoint(sessionId, {
				contentHash: snapshot.contentHash,
				wordCount: snapshot.wordCount,
				charCount: snapshot.charCount,
			});
		}
		return;
	}

	if (event === "deleted") {
		const sessionId = activeSessions.get(key);
		if (sessionId) {
			const snapshot = monitor.getPreviousSnapshot("note", id);
			await client.finalizeSession(sessionId, {
				contentHash: snapshot?.contentHash ?? "",
				wordCount: snapshot?.wordCount ?? 0,
				finalSnapshot: "deleted",
			});
			activeSessions.delete(key);
			monitor.clearSnapshot("note", id);
		}
	}
}

async function handleCommunication(
	event: "created" | "updated" | "deleted",
	id: number,
	client: WritersProofClient,
	monitor: ContentMonitor,
): Promise<void> {
	const key = sessionKey("communication", id);

	if (event === "created") {
		const snapshot = await monitor.captureCommunicationSnapshot(id);
		const session = await client.createSession({
			documentId: String(id),
			documentTitle: snapshot.resourceTitle,
			contentHash: snapshot.contentHash,
		});
		activeSessions.set(key, session.id);
		return;
	}

	if (event === "updated") {
		const previous = monitor.getPreviousSnapshot("communication", id);
		const snapshot = await monitor.captureCommunicationSnapshot(id);

		let sessionId = activeSessions.get(key);
		if (!sessionId) {
			const session = await client.createSession({
				documentId: String(id),
				documentTitle: snapshot.resourceTitle,
				contentHash: previous?.contentHash ?? snapshot.contentHash,
			});
			sessionId = session.id;
			activeSessions.set(key, sessionId);
		}

		if (!previous || previous.contentHash !== snapshot.contentHash) {
			const diff = previous
				? monitor.computeDiff(previous, snapshot)
				: {
						charDelta: snapshot.charCount,
						wordDelta: snapshot.wordCount,
					};

			await client.submitEvents(sessionId, [
				{
					type: "content_change",
					timestamp: Date.now(),
					charDelta: diff.charDelta,
					wordDelta: diff.wordDelta,
					contentHash: snapshot.contentHash,
				},
			]);
			await client.createCheckpoint(sessionId, {
				contentHash: snapshot.contentHash,
				wordCount: snapshot.wordCount,
				charCount: snapshot.charCount,
			});
		}
		return;
	}

	if (event === "deleted") {
		const sessionId = activeSessions.get(key);
		if (sessionId) {
			const snapshot = monitor.getPreviousSnapshot("communication", id);
			await client.finalizeSession(sessionId, {
				contentHash: snapshot?.contentHash ?? "",
				wordCount: snapshot?.wordCount ?? 0,
				finalSnapshot: "deleted",
			});
			activeSessions.delete(key);
			monitor.clearSnapshot("communication", id);
		}
	}
}

async function handleMatterUpdated(
	matterId: number,
	client: WritersProofClient,
	monitor: ContentMonitor,
): Promise<void> {
	const types: ClioResourceType[] = ["document", "note", "communication"];
	for (const type of types) {
		const key = sessionKey(type, matterId);
		const sessionId = activeSessions.get(key);
		if (!sessionId) continue;
		const snapshot = monitor.getPreviousSnapshot(type, matterId);
		if (!snapshot) continue;
		await client.createCheckpoint(sessionId, {
			contentHash: snapshot.contentHash,
			wordCount: snapshot.wordCount,
			charCount: snapshot.charCount,
		});
	}
}

export function createClioWebhookHandler(
	client: WritersProofClient,
	monitor: ContentMonitor,
	webhookSecret: string,
) {
	return async function handleClioWebhook(
		req: Request,
		res: Response,
	): Promise<void> {
		const rawBody = (req as Request & { rawBody?: Buffer }).rawBody;
		const signatureHeader = req.headers["x-clio-signature"];

		if (
			!rawBody ||
			typeof signatureHeader !== "string" ||
			!verifyClioSignature(rawBody, signatureHeader, webhookSecret)
		) {
			res.status(403).json({ error: "Forbidden" });
			return;
		}

		const body = req.body as ClioWebhookPayload;
		const { data, event } = body;

		if (!data?.id || !data?.type || !event) {
			res.status(200).json({ ok: true, skipped: "missing fields" });
			return;
		}

		const resourceId = data.id;
		const resourceType = data.type;

		try {
			switch (resourceType) {
				case "Document":
					await handleDocument(event, resourceId, client, monitor);
					break;
				case "Note":
					await handleNote(event, resourceId, client, monitor);
					break;
				case "Communication":
					await handleCommunication(
						event,
						resourceId,
						client,
						monitor,
					);
					break;
				case "Matter":
					if (event === "updated") {
						await handleMatterUpdated(resourceId, client, monitor);
					}
					break;
				default:
					res.status(200).json({
						ok: true,
						skipped: `unhandled type: ${resourceType}`,
					});
					return;
			}

			res.status(200).json({ ok: true, event, resourceType, resourceId });
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			res.status(500).json({ ok: false, error: message });
		}
	};
}
