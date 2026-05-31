// SPDX-License-Identifier: AGPL-3.0-only
import { WritersProofClient } from "../services/WritersProofClient.js";
import { ContentMonitor } from "../services/ContentMonitor.js";

/** Active WritersProof session IDs keyed by Notion page ID */
const activeSessions = new Map<string, string>();

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
		activeSessions.set(page.id, session.id);
		return;
	}

	const diff = monitor.computeDiff(previous, snapshot);
	if (diff.charDelta === 0 && diff.wordDelta === 0) return;

	let sessionId = activeSessions.get(page.id);
	if (!sessionId) {
		const session = await client.createSession({
			documentId: page.id,
			documentTitle: snapshot.pageTitle,
			contentHash: previous.contentHash,
		});
		sessionId = session.id;
		activeSessions.set(page.id, sessionId);
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
	const sessionId = activeSessions.get(pageId);
	if (!sessionId) return;

	const snapshot = monitor.getPreviousSnapshot(pageId);
	await client.finalizeSession(sessionId, {
		contentHash: snapshot?.contentHash ?? "",
		wordCount: snapshot?.wordCount ?? 0,
		finalSnapshot: snapshot?.plainText,
	});

	activeSessions.delete(pageId);
	monitor.clearSnapshot(pageId);
}

export function getActiveSessionId(pageId: string): string | undefined {
	return activeSessions.get(pageId);
}
