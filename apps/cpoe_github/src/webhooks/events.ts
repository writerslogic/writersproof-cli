// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";
import { Request, Response } from "express";
import { ContentMonitor } from "../services/ContentMonitor";
import { WritersProofClient, Session } from "../services/WritersProofClient";

const MAX_SESSIONS = 100;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

interface ActiveSession {
	sessionId: string;
	contentHash: string;
	wordCount: number;
	charCount: number;
	createdAt: number;
}

// In-memory session store keyed by "{type}:{owner}/{repo}#{id}"
const activeSessions = new Map<string, ActiveSession>();

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

function verifySignature(
	rawBody: Buffer,
	secret: string,
	signature: string,
): boolean {
	if (!signature || !signature.startsWith("sha256=")) return false;
	const expected =
		"sha256=" +
		crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
	try {
		return crypto.timingSafeEqual(
			Buffer.from(signature),
			Buffer.from(expected),
		);
	} catch {
		return false;
	}
}

// ---------------------------------------------------------------------------
// Individual event handlers
// ---------------------------------------------------------------------------

async function handleIssue(
	payload: Record<string, unknown>,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const action = payload.action as string;
	const issue = payload.issue as Record<string, unknown> | undefined;
	const repo = payload.repository as Record<string, unknown> | undefined;
	const installation = payload.installation as
		| Record<string, unknown>
		| undefined;

	if (!issue || !repo) return;
	const ownerObj = repo.owner as Record<string, unknown> | undefined;
	if (!ownerObj?.login || !repo.name) return;

	const owner = ownerObj.login as string;
	const repoName = repo.name as string;
	const issueNumber = issue.number as number;
	const storeKey = `issue:${owner}/${repoName}#${issueNumber}`;
	const installationId = String(installation?.id ?? "");

	if (!installationId) return;

	const token = await monitor.getInstallationToken(installationId);

	if (action === "opened") {
		const data = await monitor.fetchIssueBody(
			owner,
			repoName,
			issueNumber,
			token,
		);
		const snap = monitor.captureSnapshot(
			storeKey,
			data.title,
			data.body ?? "",
		);
		const diff = monitor.computeDiff(storeKey, snap);

		const session = await client.createSession({
			documentId: storeKey,
			documentTitle: data.title,
			contentHash: snap.contentHash,
		});
		pruneSessions();
		activeSessions.set(storeKey, {
			sessionId: (session as Session).id,
			contentHash: snap.contentHash,
			wordCount: snap.wordCount,
			charCount: snap.charCount,
			createdAt: Date.now(),
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
	} else if (action === "edited") {
		const data = await monitor.fetchIssueBody(
			owner,
			repoName,
			issueNumber,
			token,
		);
		const snap = monitor.captureSnapshot(
			storeKey,
			data.title,
			data.body ?? "",
		);
		const diff = monitor.computeDiff(storeKey, snap);

		let active = activeSessions.get(storeKey);
		if (!active) {
			const session = await client.createSession({
				documentId: storeKey,
				documentTitle: data.title,
				contentHash: snap.contentHash,
			});
			active = {
				sessionId: (session as Session).id,
				contentHash: snap.contentHash,
				wordCount: snap.wordCount,
				charCount: snap.charCount,
				createdAt: Date.now(),
			};
			pruneSessions();
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
			createdAt: Date.now(),
		});
		active.contentHash = snap.contentHash;
		active.wordCount = snap.wordCount;
		active.charCount = snap.charCount;
	} else if (action === "closed") {
		const active = activeSessions.get(storeKey);
		if (active) {
			await client.finalizeSession(active.sessionId, {
				contentHash: active.contentHash,
				wordCount: active.wordCount,
			});
			activeSessions.delete(storeKey);
			monitor.clearSnapshot(storeKey);
		}
	}
}

async function handleIssueComment(
	payload: Record<string, unknown>,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const action = payload.action as string;
	const comment = payload.comment as Record<string, unknown> | undefined;
	const repo = payload.repository as Record<string, unknown> | undefined;
	const installation = payload.installation as
		| Record<string, unknown>
		| undefined;

	if (!comment || !repo) return;
	const ownerObj = repo.owner as Record<string, unknown> | undefined;
	if (!ownerObj?.login || !repo.name) return;

	const owner = ownerObj.login as string;
	const repoName = repo.name as string;
	const commentId = comment.id as number;
	const storeKey = `issue_comment:${owner}/${repoName}#${commentId}`;
	const installationId = String(installation?.id ?? "");

	if (!installationId) return;

	const token = await monitor.getInstallationToken(installationId);

	if (action === "created") {
		const data = await monitor.fetchComment(
			owner,
			repoName,
			commentId,
			token,
		);
		const snap = monitor.captureSnapshot(
			storeKey,
			`Comment #${commentId}`,
			data.body ?? "",
		);
		const diff = monitor.computeDiff(storeKey, snap);

		const session = await client.createSession({
			documentId: storeKey,
			documentTitle: `Comment #${commentId}`,
			contentHash: snap.contentHash,
		});
		pruneSessions();
		activeSessions.set(storeKey, {
			sessionId: (session as Session).id,
			contentHash: snap.contentHash,
			wordCount: snap.wordCount,
			charCount: snap.charCount,
			createdAt: Date.now(),
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
	} else if (action === "edited") {
		const data = await monitor.fetchComment(
			owner,
			repoName,
			commentId,
			token,
		);
		const snap = monitor.captureSnapshot(
			storeKey,
			`Comment #${commentId}`,
			data.body ?? "",
		);
		const diff = monitor.computeDiff(storeKey, snap);

		let active = activeSessions.get(storeKey);
		if (!active) {
			const session = await client.createSession({
				documentId: storeKey,
				documentTitle: `Comment #${commentId}`,
				contentHash: snap.contentHash,
			});
			active = {
				sessionId: (session as Session).id,
				contentHash: snap.contentHash,
				wordCount: snap.wordCount,
				charCount: snap.charCount,
				createdAt: Date.now(),
			};
			pruneSessions();
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
			createdAt: Date.now(),
		});
		active.contentHash = snap.contentHash;
		active.wordCount = snap.wordCount;
		active.charCount = snap.charCount;
	}
}

async function handlePullRequest(
	payload: Record<string, unknown>,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const action = payload.action as string;
	const pr = payload.pull_request as Record<string, unknown> | undefined;
	const repo = payload.repository as Record<string, unknown> | undefined;
	const installation = payload.installation as
		| Record<string, unknown>
		| undefined;

	if (!pr || !repo) return;
	const ownerObj = repo.owner as Record<string, unknown> | undefined;
	if (!ownerObj?.login || !repo.name) return;

	const owner = ownerObj.login as string;
	const repoName = repo.name as string;
	const prNumber = pr.number as number;
	const storeKey = `pr:${owner}/${repoName}#${prNumber}`;
	const installationId = String(installation?.id ?? "");

	if (!installationId) return;

	const token = await monitor.getInstallationToken(installationId);

	if (action === "opened" || action === "edited") {
		const data = await monitor.fetchPRBody(
			owner,
			repoName,
			prNumber,
			token,
		);
		const snap = monitor.captureSnapshot(
			storeKey,
			data.title,
			data.body ?? "",
		);
		const diff = monitor.computeDiff(storeKey, snap);

		let active = activeSessions.get(storeKey);
		if (!active || action === "opened") {
			const session = await client.createSession({
				documentId: storeKey,
				documentTitle: data.title,
				contentHash: snap.contentHash,
			});
			active = {
				sessionId: (session as Session).id,
				contentHash: snap.contentHash,
				wordCount: snap.wordCount,
				charCount: snap.charCount,
				createdAt: Date.now(),
			};
			pruneSessions();
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

		if (action === "edited") {
			await client.createCheckpoint(active.sessionId, {
				contentHash: snap.contentHash,
				wordCount: snap.wordCount,
				charCount: snap.charCount,
			});
			active.contentHash = snap.contentHash;
			active.wordCount = snap.wordCount;
			active.charCount = snap.charCount;
		}
	} else if (action === "closed") {
		const active = activeSessions.get(storeKey);
		if (active) {
			await client.finalizeSession(active.sessionId, {
				contentHash: active.contentHash,
				wordCount: active.wordCount,
			});
			activeSessions.delete(storeKey);
			monitor.clearSnapshot(storeKey);
		}
	}
}

async function handlePRReview(
	payload: Record<string, unknown>,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const action = payload.action as string;
	if (action !== "submitted") return;

	const review = payload.review as Record<string, unknown> | undefined;
	const pr = payload.pull_request as Record<string, unknown> | undefined;
	const repo = payload.repository as Record<string, unknown> | undefined;
	const installation = payload.installation as
		| Record<string, unknown>
		| undefined;

	if (!review || !pr || !repo) return;
	const ownerObj = repo.owner as Record<string, unknown> | undefined;
	if (!ownerObj?.login || !repo.name) return;

	const owner = ownerObj.login as string;
	const repoName = repo.name as string;
	const prNumber = pr.number as number;
	const reviewId = review.id as number;
	const storeKey = `pr_review:${owner}/${repoName}#${prNumber}:${reviewId}`;
	const installationId = String(installation?.id ?? "");

	if (!installationId) return;

	const token = await monitor.getInstallationToken(installationId);
	const data = await monitor.fetchPRReview(
		owner,
		repoName,
		prNumber,
		reviewId,
		token,
	);
	const snap = monitor.captureSnapshot(
		storeKey,
		`PR #${prNumber} Review #${reviewId}`,
		data.body ?? "",
	);
	monitor.computeDiff(storeKey, snap);

	const session = await client.createSession({
		documentId: storeKey,
		documentTitle: `PR #${prNumber} Review #${reviewId}`,
		contentHash: snap.contentHash,
	});
	await client.finalizeSession((session as Session).id, {
		contentHash: snap.contentHash,
		wordCount: snap.wordCount,
	});
}

async function handlePRReviewComment(
	payload: Record<string, unknown>,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const action = payload.action as string;
	const comment = payload.comment as Record<string, unknown> | undefined;
	const repo = payload.repository as Record<string, unknown> | undefined;
	const installation = payload.installation as
		| Record<string, unknown>
		| undefined;

	if (!comment || !repo) return;
	const ownerObj = repo.owner as Record<string, unknown> | undefined;
	if (!ownerObj?.login || !repo.name) return;

	const owner = ownerObj.login as string;
	const repoName = repo.name as string;
	const commentId = comment.id as number;
	const storeKey = `pr_review_comment:${owner}/${repoName}#${commentId}`;
	const installationId = String(installation?.id ?? "");

	if (!installationId) return;

	const token = await monitor.getInstallationToken(installationId);

	if (action === "created") {
		const data = await monitor.fetchPRReviewComment(
			owner,
			repoName,
			commentId,
			token,
		);
		const snap = monitor.captureSnapshot(
			storeKey,
			`Review Comment #${commentId}`,
			data.body ?? "",
		);
		const diff = monitor.computeDiff(storeKey, snap);

		const session = await client.createSession({
			documentId: storeKey,
			documentTitle: `Review Comment #${commentId}`,
			contentHash: snap.contentHash,
		});
		pruneSessions();
		activeSessions.set(storeKey, {
			sessionId: (session as Session).id,
			contentHash: snap.contentHash,
			wordCount: snap.wordCount,
			charCount: snap.charCount,
			createdAt: Date.now(),
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
	} else if (action === "edited") {
		const data = await monitor.fetchPRReviewComment(
			owner,
			repoName,
			commentId,
			token,
		);
		const snap = monitor.captureSnapshot(
			storeKey,
			`Review Comment #${commentId}`,
			data.body ?? "",
		);
		const diff = monitor.computeDiff(storeKey, snap);

		let active = activeSessions.get(storeKey);
		if (!active) {
			const session = await client.createSession({
				documentId: storeKey,
				documentTitle: `Review Comment #${commentId}`,
				contentHash: snap.contentHash,
			});
			active = {
				sessionId: (session as Session).id,
				contentHash: snap.contentHash,
				wordCount: snap.wordCount,
				charCount: snap.charCount,
				createdAt: Date.now(),
			};
			pruneSessions();
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
			createdAt: Date.now(),
		});
		active.contentHash = snap.contentHash;
		active.wordCount = snap.wordCount;
		active.charCount = snap.charCount;
	}
}

async function handleDiscussion(
	payload: Record<string, unknown>,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const action = payload.action as string;
	const discussion = payload.discussion as
		| Record<string, unknown>
		| undefined;
	const repo = payload.repository as Record<string, unknown> | undefined;
	const installation = payload.installation as
		| Record<string, unknown>
		| undefined;

	if (!discussion || !repo) return;
	const ownerObj = repo.owner as Record<string, unknown> | undefined;
	if (!ownerObj?.login || !repo.name) return;

	const owner = ownerObj.login as string;
	const repoName = repo.name as string;
	const discussionNumber = discussion.number as number;
	const storeKey = `discussion:${owner}/${repoName}#${discussionNumber}`;
	const installationId = String(installation?.id ?? "");

	if (!installationId) return;

	const token = await monitor.getInstallationToken(installationId);

	if (action === "created") {
		const data = await monitor.fetchDiscussion(
			owner,
			repoName,
			discussionNumber,
			token,
		);
		if (!data) return;

		const snap = monitor.captureSnapshot(storeKey, data.title, data.body);
		const diff = monitor.computeDiff(storeKey, snap);

		const session = await client.createSession({
			documentId: storeKey,
			documentTitle: data.title,
			contentHash: snap.contentHash,
		});
		pruneSessions();
		activeSessions.set(storeKey, {
			sessionId: (session as Session).id,
			contentHash: snap.contentHash,
			wordCount: snap.wordCount,
			charCount: snap.charCount,
			createdAt: Date.now(),
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
	} else if (action === "edited") {
		const data = await monitor.fetchDiscussion(
			owner,
			repoName,
			discussionNumber,
			token,
		);
		if (!data) return;

		const snap = monitor.captureSnapshot(storeKey, data.title, data.body);
		const diff = monitor.computeDiff(storeKey, snap);

		let active = activeSessions.get(storeKey);
		if (!active) {
			const session = await client.createSession({
				documentId: storeKey,
				documentTitle: data.title,
				contentHash: snap.contentHash,
			});
			active = {
				sessionId: (session as Session).id,
				contentHash: snap.contentHash,
				wordCount: snap.wordCount,
				charCount: snap.charCount,
				createdAt: Date.now(),
			};
			pruneSessions();
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
			createdAt: Date.now(),
		});
		active.contentHash = snap.contentHash;
		active.wordCount = snap.wordCount;
		active.charCount = snap.charCount;
	}
}

async function handleDiscussionComment(
	payload: Record<string, unknown>,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const action = payload.action as string;
	const comment = payload.comment as Record<string, unknown> | undefined;
	const repo = payload.repository as Record<string, unknown> | undefined;
	const installation = payload.installation as
		| Record<string, unknown>
		| undefined;

	if (!comment || !repo) return;
	const ownerObj = repo.owner as Record<string, unknown> | undefined;
	if (!ownerObj?.login || !repo.name) return;

	const owner = ownerObj.login as string;
	const repoName = repo.name as string;
	const commentId = comment.id as number;
	const storeKey = `discussion_comment:${owner}/${repoName}#${commentId}`;
	const installationId = String(installation?.id ?? "");

	if (!installationId) return;

	if (action === "created") {
		const body = (comment.body as string | null) ?? "";
		const snap = monitor.captureSnapshot(
			storeKey,
			`Discussion Comment #${commentId}`,
			body,
		);
		const diff = monitor.computeDiff(storeKey, snap);

		const token = await monitor.getInstallationToken(installationId);
		void token;

		const session = await client.createSession({
			documentId: storeKey,
			documentTitle: `Discussion Comment #${commentId}`,
			contentHash: snap.contentHash,
		});
		pruneSessions();
		activeSessions.set(storeKey, {
			sessionId: (session as Session).id,
			contentHash: snap.contentHash,
			wordCount: snap.wordCount,
			charCount: snap.charCount,
			createdAt: Date.now(),
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
	} else if (action === "edited") {
		const body = (comment.body as string | null) ?? "";
		const snap = monitor.captureSnapshot(
			storeKey,
			`Discussion Comment #${commentId}`,
			body,
		);
		const diff = monitor.computeDiff(storeKey, snap);

		let active = activeSessions.get(storeKey);
		if (!active) {
			const session = await client.createSession({
				documentId: storeKey,
				documentTitle: `Discussion Comment #${commentId}`,
				contentHash: snap.contentHash,
			});
			active = {
				sessionId: (session as Session).id,
				contentHash: snap.contentHash,
				wordCount: snap.wordCount,
				charCount: snap.charCount,
				createdAt: Date.now(),
			};
			pruneSessions();
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
			createdAt: Date.now(),
		});
		active.contentHash = snap.contentHash;
		active.wordCount = snap.wordCount;
		active.charCount = snap.charCount;
	}
}

async function handleGollum(
	payload: Record<string, unknown>,
	monitor: ContentMonitor,
	client: WritersProofClient,
): Promise<void> {
	const pages = payload.pages as Array<Record<string, unknown>> | undefined;
	const repo = payload.repository as Record<string, unknown> | undefined;
	const installation = payload.installation as
		| Record<string, unknown>
		| undefined;

	if (!repo) return;
	const ownerObj = repo.owner as Record<string, unknown> | undefined;
	if (!ownerObj?.login || !repo.name) return;

	const owner = ownerObj.login as string;
	const repoName = repo.name as string;
	const installationId = String(installation?.id ?? "");

	if (!installationId || !pages || pages.length === 0) return;

	const token = await monitor.getInstallationToken(installationId);

	for (const page of pages) {
		const pageTitle = page.title as string;
		const action = page.action as string;
		const storeKey = `wiki:${owner}/${repoName}:${pageTitle}`;

		const rawContent = await monitor.fetchWikiPage(
			owner,
			repoName,
			pageTitle,
			token,
		);
		const snap = monitor.captureSnapshot(
			storeKey,
			pageTitle,
			rawContent ?? "",
		);
		const diff = monitor.computeDiff(storeKey, snap);

		if (action === "created") {
			const session = await client.createSession({
				documentId: storeKey,
				documentTitle: pageTitle,
				contentHash: snap.contentHash,
			});
			pruneSessions();
			activeSessions.set(storeKey, {
				sessionId: (session as Session).id,
				contentHash: snap.contentHash,
				wordCount: snap.wordCount,
				charCount: snap.charCount,
				createdAt: Date.now(),
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
		} else if (action === "edited") {
			let active = activeSessions.get(storeKey);
			if (!active) {
				const session = await client.createSession({
					documentId: storeKey,
					documentTitle: pageTitle,
					contentHash: snap.contentHash,
				});
				active = {
					sessionId: (session as Session).id,
					contentHash: snap.contentHash,
					wordCount: snap.wordCount,
					charCount: snap.charCount,
					createdAt: Date.now(),
				};
				pruneSessions();
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
	}
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
		const signature = req.headers["x-hub-signature-256"] as
			| string
			| undefined;
		const rawBody: Buffer =
			(req as Request & { rawBody?: Buffer }).rawBody ?? Buffer.alloc(0);

		if (!verifySignature(rawBody, webhookSecret, signature ?? "")) {
			res.status(401).json({ error: "Invalid signature" });
			return;
		}

		const event = req.headers["x-github-event"] as string | undefined;
		const payload = req.body as Record<string, unknown>;

		try {
			switch (event) {
				case "issues":
					await handleIssue(payload, monitor, client);
					break;
				case "issue_comment":
					await handleIssueComment(payload, monitor, client);
					break;
				case "pull_request":
					await handlePullRequest(payload, monitor, client);
					break;
				case "pull_request_review":
					await handlePRReview(payload, monitor, client);
					break;
				case "pull_request_review_comment":
					await handlePRReviewComment(payload, monitor, client);
					break;
				case "discussion":
					await handleDiscussion(payload, monitor, client);
					break;
				case "discussion_comment":
					await handleDiscussionComment(payload, monitor, client);
					break;
				case "gollum":
					await handleGollum(payload, monitor, client);
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
