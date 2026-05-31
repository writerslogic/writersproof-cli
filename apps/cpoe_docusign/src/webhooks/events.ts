// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";
import { WritersProofClient } from "../services/WritersProofClient.js";
import { ContentMonitor } from "../services/ContentMonitor.js";

// Map from envelopeId to WritersProof sessionId
const activeSessions = new Map<string, string>();

export interface EnvelopeEventPayload {
	envelopeId: string;
	event: string;
	accountId: string;
	emailSubject?: string;
	status?: string;
	templateId?: string;
	[key: string]: unknown;
}

/**
 * Verifies a DocuSign Connect HMAC-SHA256 signature.
 * DocuSign encodes the HMAC digest in Base64 (not hex).
 * Supports rotating through multiple HMAC keys (up to 5).
 */
export function verifyConnectSignature(
	rawBody: Buffer,
	signature: string,
	hmacKeys: string[],
): boolean {
	for (const key of hmacKeys) {
		if (!key) continue;
		const computed = crypto
			.createHmac("sha256", key)
			.update(rawBody)
			.digest("base64");
		try {
			if (
				crypto.timingSafeEqual(
					Buffer.from(signature, "base64"),
					Buffer.from(computed, "base64"),
				)
			) {
				return true;
			}
		} catch {
			// Buffer lengths differ — this key does not match; try next
		}
	}
	return false;
}

/**
 * Parses a DocuSign Connect JSON payload into a normalized envelope event.
 * DocuSign can send either JSON or XML; this handler expects JSON (configured
 * in the Connect subscription).
 */
export function parseConnectPayload(
	body: unknown,
): EnvelopeEventPayload | null {
	if (typeof body !== "object" || body === null) return null;
	const b = body as Record<string, unknown>;

	// JSON Connect format wraps events under different keys depending on version
	const info =
		(b["DocuSignEnvelopeInformation"] as
			| Record<string, unknown>
			| undefined) ?? b;

	const envelopeStatus =
		(info["EnvelopeStatus"] as Record<string, unknown> | undefined) ?? info;

	const envelopeId =
		(envelopeStatus["EnvelopeID"] as string | undefined) ??
		(envelopeStatus["envelopeId"] as string | undefined) ??
		(info["envelopeId"] as string | undefined);

	const event =
		(info["event"] as string | undefined) ??
		(envelopeStatus["Status"] as string | undefined) ??
		"";

	const accountId =
		(info["accountId"] as string | undefined) ??
		(envelopeStatus["AccountID"] as string | undefined) ??
		"";

	if (!envelopeId) return null;

	return {
		envelopeId,
		event: event.toLowerCase(),
		accountId,
		emailSubject:
			(envelopeStatus["Subject"] as string | undefined) ??
			(info["emailSubject"] as string | undefined),
		status: (envelopeStatus["Status"] as string | undefined)?.toLowerCase(),
		templateId: info["templateId"] as string | undefined,
	};
}

export async function handleEnvelopeEvent(
	payload: EnvelopeEventPayload,
	client: WritersProofClient,
	monitor: ContentMonitor,
): Promise<void> {
	const { envelopeId, event, emailSubject } = payload;

	switch (event) {
		case "envelope-sent":
		case "envelope-created": {
			if (activeSessions.has(envelopeId)) return;

			let initialHash = "unknown";
			try {
				const snapshot = await monitor.captureSnapshot(envelopeId);
				initialHash = snapshot.envelopeHash;
			} catch {
				// Envelope documents may not be available immediately after creation
			}

			const session = await client.createSession({
				documentId: envelopeId,
				documentTitle: emailSubject ?? envelopeId,
				contentHash: initialHash,
				platform: "docusign",
			});
			activeSessions.set(envelopeId, session.id);

			await client.submitEvents(session.id, [
				{
					type: "envelope_lifecycle",
					action: event,
					envelopeId,
					timestamp: new Date().toISOString(),
				},
			]);
			break;
		}

		case "envelope-delivered":
		case "recipient-completed":
		case "recipient-delivered": {
			const sessionId = activeSessions.get(envelopeId);
			if (!sessionId) return;

			const snapshot = await monitor.captureSnapshot(envelopeId);
			await client.createCheckpoint(sessionId, {
				contentHash: snapshot.envelopeHash,
				wordCount: snapshot.documents.length,
				charCount: snapshot.auditEventCount,
			});

			await client.submitEvents(sessionId, [
				{
					type: "envelope_lifecycle",
					action: event,
					envelopeId,
					documentCount: snapshot.documents.length,
					timestamp: snapshot.capturedAt,
				},
			]);
			break;
		}

		case "envelope-completed": {
			const sessionId = activeSessions.get(envelopeId);
			if (!sessionId) return;

			const snapshot = await monitor.captureSnapshot(envelopeId);
			await client.finalizeSession(sessionId, {
				contentHash: snapshot.envelopeHash,
				wordCount: snapshot.documents.length,
				finalSnapshot: JSON.stringify({
					documents: snapshot.documents,
					tabTextHash: snapshot.tabTextHash,
					auditEventCount: snapshot.auditEventCount,
					completedAt: snapshot.capturedAt,
				}),
				status: "completed",
			});
			activeSessions.delete(envelopeId);
			break;
		}

		case "envelope-declined":
		case "envelope-voided": {
			const sessionId = activeSessions.get(envelopeId);
			if (!sessionId) {
				activeSessions.delete(envelopeId);
				return;
			}

			let finalHash = "unknown";
			try {
				const snapshot = await monitor.captureSnapshot(envelopeId);
				finalHash = snapshot.envelopeHash;
			} catch {
				// Voided envelopes may have restricted document access
			}

			await client.finalizeSession(sessionId, {
				contentHash: finalHash,
				wordCount: 0,
				status: event === "envelope-declined" ? "declined" : "voided",
			});
			activeSessions.delete(envelopeId);
			break;
		}

		case "document-completed": {
			const sessionId = activeSessions.get(envelopeId);
			if (!sessionId) return;

			await client.submitEvents(sessionId, [
				{
					type: "document_lifecycle",
					action: "document_completed",
					envelopeId,
					timestamp: new Date().toISOString(),
				},
			]);
			break;
		}
	}
}
