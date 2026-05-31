// SPDX-License-Identifier: AGPL-3.0-only
// WritersProof Canvas LMS — Canvas Live Events / webhook handler

import { Router, Request, Response } from "express";
import { createHmac, timingSafeEqual } from "crypto";
import {
	WritersProofClient,
	sha256Hex,
	AuthoringEvent,
} from "../services/WritersProofClient";
import { ContentMonitor } from "../services/ContentMonitor";

// Active session map: maps a content key → WritersProof sessionId.
// In production, back with the SQLite store directory.
const activeSessions = new Map<string, string>();

function contentKey(type: string, courseId: string, contentId: string): string {
	return `${type}:${courseId}:${contentId}`;
}

function verifyCanvasSignature(
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
	meta: { courseId?: string; assignmentId?: string; userId?: string },
): Promise<string> {
	const existing = activeSessions.get(key);
	if (existing) return existing;

	const resp = await client.createSession({
		documentId,
		documentNameHash: sha256Hex(documentName),
		platform: "canvas",
		clientVersion: "1.0.0",
		courseId: meta.courseId,
		assignmentId: meta.assignmentId,
		userId: meta.userId,
	});

	activeSessions.set(key, resp.sessionId);
	return resp.sessionId;
}

async function handleSubmissionEvent(
	client: WritersProofClient,
	monitor: ContentMonitor,
	payload: Record<string, unknown>,
	eventType: string,
): Promise<void> {
	const data = (payload.data ?? payload) as Record<string, unknown>;
	const courseId = String(data.course_id ?? data.context_id ?? "");
	const assignmentId = String(data.assignment_id ?? "");
	const userId = String(data.user_id ?? data.student_id ?? "");

	if (!courseId || !assignmentId || !userId) return;

	const key = contentKey("submission", courseId, `${assignmentId}:${userId}`);
	const sessionId = await ensureSession(
		client,
		key,
		`${courseId}/${assignmentId}`,
		`Canvas Submission ${assignmentId}`,
		{ courseId, assignmentId, userId },
	);

	const { snapshot, diff } = await monitor.fetchSubmission(
		courseId,
		assignmentId,
		userId,
	);

	const event: AuthoringEvent = {
		type:
			eventType === "submission_created"
				? "document_created"
				: "document_modified",
		timestamp: new Date().toISOString(),
		data: {
			bodyHash: snapshot.bodyHash,
			wordCount: snapshot.wordCount,
			charCount: snapshot.charCount,
			wordCountDelta: diff.wordCountDelta,
			changed: diff.changed,
			workflowState: snapshot.workflowState,
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
			submissionType: "canvas_submission",
		});
	}

	if (
		snapshot.workflowState === "submitted" ||
		snapshot.workflowState === "graded"
	) {
		await client.finalizeSession(sessionId);
		activeSessions.delete(key);
	}
}

async function handleWikiPageEvent(
	client: WritersProofClient,
	monitor: ContentMonitor,
	payload: Record<string, unknown>,
	eventType: string,
): Promise<void> {
	const data = (payload.data ?? payload) as Record<string, unknown>;
	const courseId = String(data.course_id ?? data.context_id ?? "");
	const pageUrl = String(data.url ?? data.page_url ?? "");

	if (!courseId || !pageUrl) return;

	const key = contentKey("wiki", courseId, pageUrl);
	const sessionId = await ensureSession(
		client,
		key,
		`${courseId}/pages/${pageUrl}`,
		`Canvas Wiki ${pageUrl}`,
		{ courseId },
	);

	const { snapshot, diff } = await monitor.fetchWikiPage(courseId, pageUrl);

	const event: AuthoringEvent = {
		type:
			eventType === "wiki_page_created"
				? "document_created"
				: "document_modified",
		timestamp: new Date().toISOString(),
		data: {
			bodyHash: snapshot.bodyHash,
			wordCount: snapshot.wordCount,
			charCount: snapshot.charCount,
			wordCountDelta: diff.wordCountDelta,
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
			submissionType: "canvas_wiki_page",
		});
	}
}

async function handleDiscussionEvent(
	client: WritersProofClient,
	monitor: ContentMonitor,
	payload: Record<string, unknown>,
): Promise<void> {
	const data = (payload.data ?? payload) as Record<string, unknown>;
	const courseId = String(data.course_id ?? data.context_id ?? "");
	const topicId = String(data.discussion_topic_id ?? data.topic_id ?? "");
	const entryId = String(data.id ?? "");
	const userId = String(data.user_id ?? "");

	if (!courseId || !topicId) return;

	const key = contentKey("discussion", courseId, `${topicId}:${entryId}`);
	const sessionId = await ensureSession(
		client,
		key,
		`${courseId}/discussions/${topicId}/${entryId}`,
		`Canvas Discussion ${topicId}`,
		{ courseId, userId },
	);

	const entries = await monitor.fetchDiscussionEntries(courseId, topicId);
	const entry =
		entries.find((e) => e.snapshot.entryId === entryId) ?? entries[0];
	if (!entry) return;

	const { snapshot, diff } = entry;
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
			submissionType: "canvas_discussion_entry",
		});
	}
}

export function createWebhookRouter(
	client: WritersProofClient,
	monitor: ContentMonitor,
	webhookSecret: string,
): Router {
	const router = Router();

	router.post("/canvas", async (req: Request, res: Response) => {
		// Canvas Live Events sends the raw body; express must be configured with
		// express.raw() on this route so we can verify the HMAC before parsing.
		const rawBody: Buffer = req.body as Buffer;
		const signature = req.headers["x-canvas-signature"] as
			| string
			| undefined;

		if (
			webhookSecret &&
			!verifyCanvasSignature(rawBody, signature, webhookSecret)
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

		const eventType = String(payload.event_type ?? payload.type ?? "");

		// Acknowledge immediately; process asynchronously so Canvas does not time out.
		res.status(200).json({ received: true });

		const canvasUrl = process.env["CANVAS_PLATFORM_URL"] ?? "";
		const accessToken = process.env["CANVAS_ACCESS_TOKEN"] ?? "";

		try {
			if (
				eventType === "submission_created" ||
				eventType === "submission_updated"
			) {
				await handleSubmissionEvent(
					client,
					monitor,
					payload,
					eventType,
				);
			} else if (
				eventType === "wiki_page_created" ||
				eventType === "wiki_page_updated"
			) {
				await handleWikiPageEvent(client, monitor, payload, eventType);
			} else if (eventType === "discussion_entry_created") {
				await handleDiscussionEvent(client, monitor, payload);
			}
			// Unknown event types are silently ignored; Canvas sends many event types
			// and we only care about content-creation events.
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			process.stderr.write(
				`[canvas-webhook] Error processing ${eventType}: ${msg}\n`,
			);
		}
	});

	return router;
}
