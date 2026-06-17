// SPDX-License-Identifier: AGPL-3.0-only
import { WritersProofClient } from "../services/WritersProofClient.js";
import { ContentMonitor } from "../services/ContentMonitor.js";

const MAX_SESSIONS = 100;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

interface SessionEntry {
	sessionId: string;
	createdAt: number;
}

/** Active WritersProof session IDs keyed by Notion page ID */
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

export async function handlePageChanged(
	page: { id: string; last_edited_time: string },
	client: WritersProofClient,
	monitor: ContentMonitor,
): Promise<void> {
	const previous = monitor.getPreviousSnapshot(page.id);
	const snapshot = await monitor.captureSnapshot(page);

	if (!previous) {
		const session = await client.createSession({
			documentId: page.id,
			documentTitle: snapshot.pageTitle,
			contentHash: snapshot.contentHash,
		});
		pruneSessions();
		activeSessions.set(page.id, {
			sessionId: session.id,
			createdAt: Date.now(),
		});
		return;
	}

	const diff = monitor.computeDiff(previous, snapshot);
	if (diff.charDelta === 0 && diff.wordDelta === 0) return;

	let sessionId = activeSessions.get(page.id)?.sessionId;
	if (!sessionId) {
		const session = await client.createSession({
			documentId: page.id,
			documentTitle: snapshot.pageTitle,
			contentHash: previous.contentHash,
		});
		sessionId = session.id;
		pruneSessions();
		activeSessions.set(page.id, { sessionId, createdAt: Date.now() });
	}

	await client.submitEvents(sessionId, [
		{
			type: "content_change",
			timestamp: Date.now(),
			charDelta: diff.charDelta,
			wordDelta: diff.wordDelta,
			blockDelta: diff.blockDelta,
			contentHash: snapshot.contentHash,
		},
	]);

	await client.createCheckpoint(sessionId, {
		contentHash: snapshot.contentHash,
		wordCount: snapshot.wordCount,
		charCount: snapshot.charCount,
	});
}

export async function finalizePageSession(
	pageId: string,
	client: WritersProofClient,
	monitor: ContentMonitor,
): Promise<void> {
	const entry = activeSessions.get(pageId);
	if (!entry) return;

	const snapshot = monitor.getPreviousSnapshot(pageId);
	await client.finalizeSession(entry.sessionId, {
		contentHash: snapshot?.contentHash ?? "",
		wordCount: snapshot?.wordCount ?? 0,
		finalSnapshot: snapshot?.plainText,
	});

	activeSessions.delete(pageId);
	monitor.clearSnapshot(pageId);
}

export function getActiveSessionId(pageId: string): string | undefined {
	return activeSessions.get(pageId)?.sessionId;
}
