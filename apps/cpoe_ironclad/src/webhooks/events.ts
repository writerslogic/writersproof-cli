// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";
import { WritersProofClient } from "../services/WritersProofClient.js";
import { ContentMonitor } from "../services/ContentMonitor.js";

const activeSessions = new Map<string, string>();

export interface IroncladWebhookPayload {
	event: string;
	data: {
		id: string;
		type?: string;
		status?: string;
		attributes?: Record<string, unknown>;
		recordId?: string;
		commentId?: string;
		[key: string]: unknown;
	};
	timestamp: string;
}

export function verifyWebhookSignature(
	rawBody: Buffer,
	signature: string,
	secret: string,
): boolean {
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

export function parseWebhookPayload(
	body: unknown,
): IroncladWebhookPayload | null {
	if (typeof body !== "object" || body === null) return null;
	const b = body as Record<string, unknown>;
	if (typeof b["event"] !== "string") return null;
	if (typeof b["data"] !== "object" || b["data"] === null) return null;
	const data = b["data"] as Record<string, unknown>;
	if (typeof data["id"] !== "string") return null;
	return {
		event: b["event"] as string,
		data: data as IroncladWebhookPayload["data"],
		timestamp:
			typeof b["timestamp"] === "string"
				? b["timestamp"]
				: new Date().toISOString(),
	};
}

export async function handleWorkflowEvent(
	payload: IroncladWebhookPayload,
	client: WritersProofClient,
	monitor: ContentMonitor,
): Promise<void> {
	const { event, data } = payload;
	const workflowId = data.id;

	switch (event) {
		case "workflow_launched": {
			if (activeSessions.has(workflowId)) return;

			let initialHash = "unknown";
			let title = workflowId;
			try {
				const snapshot = await monitor.captureSnapshot(workflowId);
				initialHash = snapshot.workflowHash;
				title = snapshot.title;
			} catch {
				// Documents may not be attached yet at launch
			}

			const session = await client.createSession({
				documentId: workflowId,
				documentTitle: title,
				contentHash: initialHash,
				platform: "ironclad",
			});
			activeSessions.set(workflowId, session.id);

			await client.submitEvents(session.id, [
				{
					type: "workflow_lifecycle",
					action: "workflow_launched",
					workflowId,
					workflowType: data.type,
					timestamp: payload.timestamp,
				},
			]);
			break;
		}

		case "workflow_updated": {
			const sessionId = activeSessions.get(workflowId);
			if (!sessionId) return;

			const snapshot = await monitor.captureSnapshot(workflowId);
			await client.submitEvents(sessionId, [
				{
					type: "content_change",
					action: "workflow_updated",
					workflowId,
					workflowHash: snapshot.workflowHash,
					attributeHash: snapshot.attributeHash,
					documentCount: snapshot.documents.length,
					timestamp: payload.timestamp,
				},
			]);
			break;
		}

		case "workflow_document_uploaded": {
			const sessionId = activeSessions.get(workflowId);
			if (!sessionId) return;

			const snapshot = await monitor.captureSnapshot(workflowId);
			await client.createCheckpoint(sessionId, {
				contentHash: snapshot.workflowHash,
				wordCount: snapshot.documents.length,
				charCount: snapshot.commentCount,
			});
			break;
		}

		case "workflow_signed": {
			const sessionId = activeSessions.get(workflowId);
			if (!sessionId) return;

			const snapshot = await monitor.captureSnapshot(workflowId);
			await client.createCheckpoint(sessionId, {
				contentHash: snapshot.workflowHash,
				wordCount: snapshot.documents.length,
				charCount: snapshot.commentCount,
			});

			await client.submitEvents(sessionId, [
				{
					type: "signature_event",
					action: "workflow_signed",
					workflowId,
					timestamp: payload.timestamp,
				},
			]);
			break;
		}

		case "workflow_completed": {
			const sessionId = activeSessions.get(workflowId);
			if (!sessionId) return;

			const snapshot = await monitor.captureSnapshot(workflowId);

			let recordHash: string | null = null;
			if (typeof data.recordId === "string") {
				try {
					const record = await monitor.getRecord(data.recordId);
					recordHash = record.hash;
				} catch {
					// Record may not yet be available
				}
			}

			await client.finalizeSession(sessionId, {
				contentHash: snapshot.workflowHash,
				wordCount: snapshot.documents.length,
				finalSnapshot: JSON.stringify({
					documents: snapshot.documents,
					attributeHash: snapshot.attributeHash,
					commentCount: snapshot.commentCount,
					recordHash,
					completedAt: snapshot.capturedAt,
				}),
				status: "completed",
			});
			activeSessions.delete(workflowId);
			break;
		}

		case "workflow_cancelled": {
			const sessionId = activeSessions.get(workflowId);
			if (!sessionId) {
				activeSessions.delete(workflowId);
				return;
			}

			let finalHash = "unknown";
			try {
				const snapshot = await monitor.captureSnapshot(workflowId);
				finalHash = snapshot.workflowHash;
			} catch {
				// Cancelled workflows may have restricted access
			}

			await client.finalizeSession(sessionId, {
				contentHash: finalHash,
				wordCount: 0,
				status: "cancelled",
			});
			activeSessions.delete(workflowId);
			break;
		}

		case "workflow_comment_added": {
			const sessionId = activeSessions.get(workflowId);
			if (!sessionId) return;

			await client.submitEvents(sessionId, [
				{
					type: "content_event",
					action: "comment_added",
					workflowId,
					commentId: data.commentId,
					timestamp: payload.timestamp,
				},
			]);
			break;
		}

		case "approval_requested": {
			const sessionId = activeSessions.get(workflowId);
			if (!sessionId) return;

			const approvalStatus = await monitor
				.getApprovalStatus(workflowId)
				.catch(() => "unknown");
			await client.submitEvents(sessionId, [
				{
					type: "approval_event",
					action: "approval_requested",
					workflowId,
					approvalStatus,
					timestamp: payload.timestamp,
				},
			]);
			break;
		}

		case "approval_completed": {
			const sessionId = activeSessions.get(workflowId);
			if (!sessionId) return;

			const snapshot = await monitor.captureSnapshot(workflowId);
			await client.createCheckpoint(sessionId, {
				contentHash: snapshot.workflowHash,
				wordCount: snapshot.documents.length,
				charCount: snapshot.commentCount,
			});

			await client.submitEvents(sessionId, [
				{
					type: "approval_event",
					action: "approval_completed",
					workflowId,
					timestamp: payload.timestamp,
				},
			]);
			break;
		}
	}
}
