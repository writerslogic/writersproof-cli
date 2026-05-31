// SPDX-License-Identifier: AGPL-3.0-only
// WritersProof Blackboard Learn — Blackboard REST webhook handler

import { Router, Request, Response } from "express";
import { createHmac, timingSafeEqual } from "crypto";
import {
	WritersProofClient,
	sha256Hex,
	AuthoringEvent,
} from "../services/WritersProofClient";
import { ContentMonitor } from "../services/ContentMonitor";

const activeSessions = new Map<string, string>();

function contentKey(type: string, courseId: string, itemId: string): string {
	return `${type}:${courseId}:${itemId}`;
}

function verifyBlackboardSignature(
	body: Buffer,
	signature: string | undefined,
	secret: string,
): boolean {
	if (!signature) return false;
	const expected = createHmac("sha256", secret).update(body).digest("hex");
	const expectedBuf = Buffer.from(expected, "hex");
	try {
		const sigBuf = Buffer.from(signature.replace(/^sha256=/, ""), "hex");
		if (sigBuf.length !== expectedBuf.length) return false;
		return timingSafeEqual(sigBuf, expectedBuf);
	} catch {
		return false;
	}
}

async function ensureSession(
	client: WritersProofClient,
	key: string,
	documentId: string,
	documentName: string,
	meta: { courseId?: string; contentId?: string; userId?: string },
): Promise<string> {
	const existing = activeSessions.get(key);
	if (existing) return existing;

	const resp = await client.createSession({
		documentId,
		documentNameHash: sha256Hex(documentName),
		platform: "blackboard",
		clientVersion: "1.0.0",
		courseId: meta.courseId,
		contentId: meta.contentId,
		userId: meta.userId,
	});

	activeSessions.set(key, resp.sessionId);
	return resp.sessionId;
}

async function handleContentEvent(
	client: WritersProofClient,
	monitor: ContentMonitor,
	payload: Record<string, unknown>,
	eventType: string,
): Promise<void> {
	const body = (payload.body ?? payload) as Record<string, unknown>;
	const courseId = String(body.courseId ?? body.course_id ?? "");
	const contentId = String(
		body.contentId ?? body.content_id ?? body.id ?? "",
	);

	if (!courseId || !contentId) return;

	const key = contentKey("content", courseId, contentId);
	const sessionId = await ensureSession(
		client,
		key,
		`${courseId}/${contentId}`,
		`Blackboard Content ${contentId}`,
		{ courseId, contentId },
	);

	const { snapshot, diff } = await monitor.fetchContent(courseId, contentId);

	const event: AuthoringEvent = {
		type:
			eventType === "content.created"
				? "document_created"
				: "document_modified",
		timestamp: new Date().toISOString(),
		data: {
			bodyHash: snapshot.bodyHash,
			wordCount: snapshot.wordCount,
			charCount: snapshot.charCount,
			wordCountDelta: diff.wordCountDelta,
			changed: diff.changed,
			contentType: snapshot.contentType,
		},
	};

	await client.submitEvents(sessionId, [event]);

	if (diff.changed) {
		await client.createCheckpoint(sessionId, {
			wordCount: snapshot.wordCount,
			charCount: snapshot.charCount,
			paragraphCount: 0,
			bodyHash: snapshot.bodyHash,
			timestamp: new Date().toISOString(),
			submissionType: "blackboard_content",
		});
	}
}

async function handleAttemptEvent(
	client: WritersProofClient,
	monitor: ContentMonitor,
	payload: Record<string, unknown>,
	eventType: string,
): Promise<void> {
	const body = (payload.body ?? payload) as Record<string, unknown>;
	const courseId = String(body.courseId ?? body.course_id ?? "");
	const columnId = String(body.columnId ?? body.column_id ?? "");
	const attemptId = String(
		body.attemptId ?? body.attempt_id ?? body.id ?? "",
	);
	const userId = String(body.userId ?? body.user_id ?? "");

	if (!courseId || !columnId || !attemptId) return;

	const key = contentKey("attempt", courseId, `${columnId}:${attemptId}`);
	const sessionId = await ensureSession(
		client,
		key,
		`${courseId}/${columnId}/${attemptId}`,
		`Blackboard Attempt ${attemptId}`,
		{ courseId, contentId: columnId, userId },
	);

	const { snapshot, diff } = await monitor.fetchAttempt(
		courseId,
		columnId,
		attemptId,
	);

	const event: AuthoringEvent = {
		type:
			eventType === "gradebook.attempt.created"
				? "document_created"
				: "document_modified",
		timestamp: new Date().toISOString(),
		data: {
			bodyHash: snapshot.bodyHash,
			wordCount: snapshot.wordCount,
			charCount: snapshot.charCount,
			wordCountDelta: diff.wordCountDelta,
			changed: diff.changed,
			status: snapshot.status,
		},
	};

	await client.submitEvents(sessionId, [event]);

	if (diff.changed) {
		await client.createCheckpoint(sessionId, {
			wordCount: snapshot.wordCount,
			charCount: snapshot.charCount,
			paragraphCount: 0,
			bodyHash: snapshot.bodyHash,
			timestamp: new Date().toISOString(),
			submissionType: "blackboard_attempt",
		});
	}

	if (snapshot.status === "NeedsGrading" || snapshot.status === "Completed") {
		await client.finalizeSession(sessionId);
		activeSessions.delete(key);
	}
}

async function handleDiscussionPostEvent(
	client: WritersProofClient,
	monitor: ContentMonitor,
	payload: Record<string, unknown>,
): Promise<void> {
	const body = (payload.body ?? payload) as Record<string, unknown>;
	const courseId = String(body.courseId ?? body.course_id ?? "");
	const threadId = String(body.threadId ?? body.thread_id ?? "");
	const postId = String(body.postId ?? body.post_id ?? body.id ?? "");
	const userId = String(body.userId ?? body.user_id ?? "");

	if (!courseId || !threadId) return;

	const key = contentKey("discussion", courseId, `${threadId}:${postId}`);
	const sessionId = await ensureSession(
		client,
		key,
		`${courseId}/discussions/${threadId}/${postId}`,
		`Blackboard Discussion Post ${postId}`,
		{ courseId, userId },
	);

	const posts = await monitor.fetchDiscussionPosts(courseId, threadId);
	const post = posts.find((p) => p.snapshot.postId === postId) ?? posts[0];
	if (!post) return;

	const { snapshot, diff } = post;
	const event: AuthoringEvent = {
		type: "document_created",
		timestamp: new Date().toISOString(),
		data: {
			bodyHash: snapshot.bodyHash,
			wordCount: snapshot.wordCount,
			charCount: snapshot.charCount,
			changed: diff.changed,
		},
	};

	await client.submitEvents(sessionId, [event]);

	if (diff.changed) {
		await client.createCheckpoint(sessionId, {
			wordCount: snapshot.wordCount,
			charCount: snapshot.charCount,
			paragraphCount: 0,
			bodyHash: snapshot.bodyHash,
			timestamp: new Date().toISOString(),
			submissionType: "blackboard_discussion_post",
		});
	}
}

export function createWebhookRouter(
	client: WritersProofClient,
	monitor: ContentMonitor,
	webhookSecret: string,
): Router {
	const router = Router();

	router.post("/blackboard", async (req: Request, res: Response) => {
		const rawBody: Buffer = req.body as Buffer;
		const signature = req.headers["x-blackboard-signature"] as
			| string
			| undefined;

		if (
			webhookSecret &&
			!verifyBlackboardSignature(rawBody, signature, webhookSecret)
		) {
			res.status(401).json({ error: "Invalid webhook signature" });
			return;
		}

		let payload: Record<string, unknown>;
		try {
			payload = JSON.parse(rawBody.toString("utf8")) as Record<
				string,
				unknown
			>;
		} catch {
			res.status(400).json({ error: "Invalid JSON payload" });
			return;
		}

		const eventType = String(payload.event ?? payload.type ?? "");

		res.status(200).json({ received: true });

		try {
			if (
				eventType === "content.created" ||
				eventType === "content.modified"
			) {
				await handleContentEvent(client, monitor, payload, eventType);
			} else if (
				eventType === "gradebook.attempt.created" ||
				eventType === "gradebook.attempt.updated"
			) {
				await handleAttemptEvent(client, monitor, payload, eventType);
			} else if (eventType === "discussion.post.created") {
				await handleDiscussionPostEvent(client, monitor, payload);
			}
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			process.stderr.write(
				`[bb-webhook] Error processing ${eventType}: ${msg}\n`,
			);
		}
	});

	return router;
}
