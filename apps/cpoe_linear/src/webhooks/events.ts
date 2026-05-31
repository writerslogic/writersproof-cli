// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";
import { Request, Response } from "express";
import { ContentMonitor } from "../services/ContentMonitor";
import { WritersProofClient, Session } from "../services/WritersProofClient";

interface ActiveSession {
	sessionId: string;
	contentHash: string;
	wordCount: number;
	charCount: number;
}

// In-memory session store keyed by "{type}:{id}"
const activeSessions = new Map<string, ActiveSession>();

// In-memory OAuth token store keyed by organizationId.
// In production this should be persisted to a database.
const orgTokens = new Map<string, string>();

export function storeOrgToken(
	organizationId: string,
	accessToken: string,
): void {
	orgTokens.set(organizationId, accessToken);
}

function getOrgToken(organizationId: string): string | undefined {
	return orgTokens.get(organizationId);
}

function verifySignature(
	rawBody: Buffer,
	secret: string,
	signature: string,
): boolean {
	if (!signature) return false;
	const computed = crypto
		.createHmac("sha256", secret)
		.update(rawBody)
		.digest("hex");
	try {
		return crypto.timingSafeEqual(
			Buffer.from(signature),
			Buffer.from(computed),
		);
	} catch {
		return false;
	}
}

// ---------------------------------------------------------------------------
// Individual event handlers
// ---------------------------------------------------------------------------

async function handleIssueCreate(
	data: Record<string, unknown>,
	organizationId: string,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const issueId = data.id as string;
	const storeKey = `Issue:${issueId}`;
	const accessToken = getOrgToken(organizationId);
	if (!accessToken) return;

	const issue = await monitor.fetchIssue(issueId, accessToken);
	if (!issue) return;

	const snap = monitor.captureSnapshot(
		storeKey,
		issue.title,
		issue.description,
	);
	const diff = monitor.computeDiff(storeKey, snap);

	const session = await client.createSession({
		documentId: storeKey,
		documentTitle: issue.title,
		contentHash: snap.contentHash,
	});
	activeSessions.set(storeKey, {
		sessionId: (session as Session).id,
		contentHash: snap.contentHash,
		wordCount: snap.wordCount,
		charCount: snap.charCount,
	});
	await client.submitEvents((session as Session).id, [
		{
			type: "content_change",
			timestamp: Date.now(),
			wordDelta: diff.wordDelta,
			charDelta: diff.charDelta,
			contentHash: snap.contentHash,
		},
	]);
}

async function handleIssueUpdate(
	data: Record<string, unknown>,
	organizationId: string,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const issueId = data.id as string;
	const storeKey = `Issue:${issueId}`;
	const accessToken = getOrgToken(organizationId);
	if (!accessToken) return;

	const issue = await monitor.fetchIssue(issueId, accessToken);
	if (!issue) return;

	const snap = monitor.captureSnapshot(
		storeKey,
		issue.title,
		issue.description,
	);
	const diff = monitor.computeDiff(storeKey, snap);

	if (!diff.changed) return;

	let active = activeSessions.get(storeKey);
	if (!active) {
		const session = await client.createSession({
			documentId: storeKey,
			documentTitle: issue.title,
			contentHash: snap.contentHash,
		});
		active = {
			sessionId: (session as Session).id,
			contentHash: snap.contentHash,
			wordCount: snap.wordCount,
			charCount: snap.charCount,
		};
		activeSessions.set(storeKey, active);
	}

	await client.submitEvents(active.sessionId, [
		{
			type: "content_change",
			timestamp: Date.now(),
			wordDelta: diff.wordDelta,
			charDelta: diff.charDelta,
			contentHash: snap.contentHash,
		},
	]);
	await client.createCheckpoint(active.sessionId, {
		contentHash: snap.contentHash,
		wordCount: snap.wordCount,
		charCount: snap.charCount,
	});
	active.contentHash = snap.contentHash;
	active.wordCount = snap.wordCount;
	active.charCount = snap.charCount;
}

async function handleIssueRemove(
	data: Record<string, unknown>,
	client: WritersProofClient,
	monitor: ContentMonitor,
): Promise<void> {
	const issueId = data.id as string;
	const storeKey = `Issue:${issueId}`;
	const active = activeSessions.get(storeKey);
	if (!active) return;

	await client.finalizeSession(active.sessionId, {
		contentHash: active.contentHash,
		wordCount: active.wordCount,
	});
	activeSessions.delete(storeKey);
	monitor.clearSnapshot(storeKey);
}

async function handleCommentCreate(
	data: Record<string, unknown>,
	organizationId: string,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const commentId = data.id as string;
	const storeKey = `Comment:${commentId}`;
	const accessToken = getOrgToken(organizationId);
	if (!accessToken) return;

	const comment = await monitor.fetchComment(commentId, accessToken);
	if (!comment) return;

	const snap = monitor.captureSnapshot(
		storeKey,
		`Comment ${commentId}`,
		comment.body,
	);
	const diff = monitor.computeDiff(storeKey, snap);

	const session = await client.createSession({
		documentId: storeKey,
		documentTitle: `Comment ${commentId}`,
		contentHash: snap.contentHash,
	});
	activeSessions.set(storeKey, {
		sessionId: (session as Session).id,
		contentHash: snap.contentHash,
		wordCount: snap.wordCount,
		charCount: snap.charCount,
	});
	await client.submitEvents((session as Session).id, [
		{
			type: "content_change",
			timestamp: Date.now(),
			wordDelta: diff.wordDelta,
			charDelta: diff.charDelta,
			contentHash: snap.contentHash,
		},
	]);
}

async function handleCommentUpdate(
	data: Record<string, unknown>,
	organizationId: string,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const commentId = data.id as string;
	const storeKey = `Comment:${commentId}`;
	const accessToken = getOrgToken(organizationId);
	if (!accessToken) return;

	const comment = await monitor.fetchComment(commentId, accessToken);
	if (!comment) return;

	const snap = monitor.captureSnapshot(
		storeKey,
		`Comment ${commentId}`,
		comment.body,
	);
	const diff = monitor.computeDiff(storeKey, snap);

	if (!diff.changed) return;

	let active = activeSessions.get(storeKey);
	if (!active) {
		const session = await client.createSession({
			documentId: storeKey,
			documentTitle: `Comment ${commentId}`,
			contentHash: snap.contentHash,
		});
		active = {
			sessionId: (session as Session).id,
			contentHash: snap.contentHash,
			wordCount: snap.wordCount,
			charCount: snap.charCount,
		};
		activeSessions.set(storeKey, active);
	}

	await client.submitEvents(active.sessionId, [
		{
			type: "content_change",
			timestamp: Date.now(),
			wordDelta: diff.wordDelta,
			charDelta: diff.charDelta,
			contentHash: snap.contentHash,
		},
	]);
	await client.createCheckpoint(active.sessionId, {
		contentHash: snap.contentHash,
		wordCount: snap.wordCount,
		charCount: snap.charCount,
	});
	active.contentHash = snap.contentHash;
	active.wordCount = snap.wordCount;
	active.charCount = snap.charCount;
}

async function handleCommentRemove(
	data: Record<string, unknown>,
	client: WritersProofClient,
	monitor: ContentMonitor,
): Promise<void> {
	const commentId = data.id as string;
	const storeKey = `Comment:${commentId}`;
	const active = activeSessions.get(storeKey);
	if (!active) return;

	await client.finalizeSession(active.sessionId, {
		contentHash: active.contentHash,
		wordCount: active.wordCount,
	});
	activeSessions.delete(storeKey);
	monitor.clearSnapshot(storeKey);
}

async function handleProjectUpdate(
	data: Record<string, unknown>,
	organizationId: string,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const projectId = data.id as string;
	const storeKey = `Project:${projectId}`;
	const accessToken = getOrgToken(organizationId);
	if (!accessToken) return;

	const project = await monitor.fetchProject(projectId, accessToken);
	if (!project) return;

	const snap = monitor.captureSnapshot(
		storeKey,
		project.name,
		project.description,
	);
	const diff = monitor.computeDiff(storeKey, snap);

	if (!diff.changed) return;

	let active = activeSessions.get(storeKey);
	if (!active) {
		const session = await client.createSession({
			documentId: storeKey,
			documentTitle: project.name,
			contentHash: snap.contentHash,
		});
		active = {
			sessionId: (session as Session).id,
			contentHash: snap.contentHash,
			wordCount: snap.wordCount,
			charCount: snap.charCount,
		};
		activeSessions.set(storeKey, active);
	}

	await client.submitEvents(active.sessionId, [
		{
			type: "content_change",
			timestamp: Date.now(),
			wordDelta: diff.wordDelta,
			charDelta: diff.charDelta,
			contentHash: snap.contentHash,
		},
	]);
	await client.createCheckpoint(active.sessionId, {
		contentHash: snap.contentHash,
		wordCount: snap.wordCount,
		charCount: snap.charCount,
	});
	active.contentHash = snap.contentHash;
	active.wordCount = snap.wordCount;
	active.charCount = snap.charCount;
}

// ---------------------------------------------------------------------------
// Main webhook dispatcher
// ---------------------------------------------------------------------------

export function createWebhookHandler(
	monitor: ContentMonitor,
	client: WritersProofClient,
	webhookSecret: string,
) {
	return async (req: Request, res: Response): Promise<void> => {
		const signature = req.headers["linear-signature"] as string | undefined;
		const rawBody: Buffer =
			(req as Request & { rawBody?: Buffer }).rawBody ?? Buffer.alloc(0);

		if (!verifySignature(rawBody, webhookSecret, signature ?? "")) {
			res.status(401).json({ error: "Invalid signature" });
			return;
		}

		const payload = req.body as {
			action: string;
			type: string;
			data: Record<string, unknown>;
			organizationId?: string;
			createdAt?: string;
		};

		const { action, type, data, organizationId = "" } = payload;

		try {
			switch (type) {
				case "Issue":
					if (action === "create") {
						await handleIssueCreate(
							data,
							organizationId,
							monitor,
							client,
						);
					} else if (action === "update") {
						await handleIssueUpdate(
							data,
							organizationId,
							monitor,
							client,
						);
					} else if (action === "remove") {
						await handleIssueRemove(data, client, monitor);
					}
					break;
				case "Comment":
					if (action === "create") {
						await handleCommentCreate(
							data,
							organizationId,
							monitor,
							client,
						);
					} else if (action === "update") {
						await handleCommentUpdate(
							data,
							organizationId,
							monitor,
							client,
						);
					} else if (action === "remove") {
						await handleCommentRemove(data, client, monitor);
					}
					break;
				case "Project":
					if (action === "update") {
						await handleProjectUpdate(
							data,
							organizationId,
							monitor,
							client,
						);
					}
					break;
				case "IssueLabel":
				case "Cycle":
					break;
				default:
					break;
			}
			res.status(200).json({ ok: true });
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			res.status(500).json({ error: message });
		}
	};
}
