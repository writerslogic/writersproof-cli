// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";

export interface DocumentHash {
	documentId: string;
	name: string;
	hash: string;
	sizeBytes: number;
}

export interface EnvelopeSnapshot {
	envelopeId: string;
	subject: string;
	status: string;
	envelopeHash: string;
	documents: DocumentHash[];
	tabTextHash: string | null;
	auditEventCount: number;
	capturedAt: string;
}

interface DocuSignDocument {
	documentId: string;
	name: string;
	type?: string;
	uri?: string;
}

interface DocuSignTab {
	value?: string;
	tabLabel?: string;
	[key: string]: unknown;
}

interface DocuSignRecipients {
	signers?: Array<{
		tabs?: { textTabs?: DocuSignTab[]; [key: string]: unknown };
		[key: string]: unknown;
	}>;
	[key: string]: unknown;
}

interface DocuSignEnvelope {
	envelopeId: string;
	emailSubject?: string;
	status: string;
	recipients?: DocuSignRecipients;
	[key: string]: unknown;
}

interface DocuSignAuditEvent {
	eventFields?: Array<{ name: string; value: string }>;
	[key: string]: unknown;
}

/**
 * Fetches content from the DocuSign eSignature REST API v2.1 and produces
 * deterministic SHA-256 hashes suitable for WritersProof evidence packets.
 */
export class ContentMonitor {
	private readonly baseUrl: string;
	private readonly accountId: string;
	private getToken: () => Promise<string>;

	constructor(
		getToken: () => Promise<string>,
		accountId: string,
		baseUrl: string,
	) {
		this.getToken = getToken;
		this.accountId = accountId;
		this.baseUrl = baseUrl.replace(/\/$/, "");
	}

	private async apiGet<T>(path: string): Promise<T> {
		const token = await this.getToken();
		const url = `${this.baseUrl}/restapi/v2.1/accounts/${encodeURIComponent(this.accountId)}${path}`;
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);

		try {
			const resp = await fetch(url, {
				headers: {
					Authorization: `Bearer ${token}`,
					Accept: "application/json",
				},
				signal: controller.signal,
			});
			clearTimeout(timeoutId);
			if (!resp.ok) {
				const text = await resp.text().catch(() => resp.statusText);
				throw new Error(
					`DocuSign API ${resp.status} for ${path}: ${text}`,
				);
			}
			return (await resp.json()) as T;
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	private async downloadDocument(
		envelopeId: string,
		documentId: string,
	): Promise<Buffer> {
		const token = await this.getToken();
		const path = `/envelopes/${encodeURIComponent(envelopeId)}/documents/${encodeURIComponent(documentId)}`;
		const url = `${this.baseUrl}/restapi/v2.1/accounts/${encodeURIComponent(this.accountId)}${path}`;
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 60_000);

		try {
			const resp = await fetch(url, {
				headers: {
					Authorization: `Bearer ${await this.getToken()}`,
					Accept: "application/pdf",
				},
				signal: controller.signal,
			});
			clearTimeout(timeoutId);
			if (!resp.ok) {
				const text = await resp.text().catch(() => resp.statusText);
				throw new Error(
					`DocuSign document download ${resp.status} for ${documentId}: ${text}`,
				);
			}
			return Buffer.from(await resp.arrayBuffer());
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	/**
	 * Fetches all documents for an envelope, SHA-256 hashes each binary,
	 * and combines them into a single deterministic envelope hash.
	 * Also extracts tab text values and hashes them separately.
	 */
	async captureSnapshot(envelopeId: string): Promise<EnvelopeSnapshot> {
		const [envelope, docsResp, auditResp] = await Promise.all([
			this.apiGet<DocuSignEnvelope>(
				`/envelopes/${encodeURIComponent(envelopeId)}`,
			),
			this.apiGet<{ envelopeDocuments?: DocuSignDocument[] }>(
				`/envelopes/${encodeURIComponent(envelopeId)}/documents`,
			),
			this.apiGet<{ auditEvents?: DocuSignAuditEvent[] }>(
				`/envelopes/${encodeURIComponent(envelopeId)}/audit_events`,
			).catch(() => ({ auditEvents: [] as DocuSignAuditEvent[] })),
		]);

		const rawDocs: DocuSignDocument[] = docsResp.envelopeDocuments ?? [];

		// Download and hash each document in parallel (cap concurrency to 5)
		const documentHashes: DocumentHash[] = [];
		const chunks: DocuSignDocument[][] = [];
		for (let i = 0; i < rawDocs.length; i += 5) {
			chunks.push(rawDocs.slice(i, i + 5));
		}

		for (const chunk of chunks) {
			const results = await Promise.all(
				chunk.map(async (doc) => {
					const bytes = await this.downloadDocument(
						envelopeId,
						doc.documentId,
					);
					const hash = crypto
						.createHash("sha256")
						.update(bytes)
						.digest("hex");
					return {
						documentId: doc.documentId,
						name: doc.name ?? doc.documentId,
						hash,
						sizeBytes: bytes.length,
					};
				}),
			);
			documentHashes.push(...results);
		}

		// Deterministic envelope hash: sort by documentId
		const sorted = [...documentHashes].sort((a, b) =>
			a.documentId.localeCompare(b.documentId),
		);
		const combined = sorted
			.map((d) => `${d.documentId}:${d.hash}`)
			.join("|");
		const envelopeHash = crypto
			.createHash("sha256")
			.update(combined, "utf8")
			.digest("hex");

		// Hash tab text fields (free-text fields in the envelope)
		const tabTextHash = this.hashTabValues(envelope);

		return {
			envelopeId,
			subject: envelope.emailSubject ?? envelopeId,
			status: envelope.status,
			envelopeHash,
			documents: documentHashes,
			tabTextHash,
			auditEventCount: auditResp.auditEvents?.length ?? 0,
			capturedAt: new Date().toISOString(),
		};
	}

	/**
	 * Fetches template details for change detection on template-based envelopes.
	 */
	async getTemplateHash(templateId: string): Promise<string> {
		const template = await this.apiGet<{
			templateId: string;
			name?: string;
			lastModified?: string;
		}>(`/templates/${encodeURIComponent(templateId)}`);
		const sig = `${template.templateId}|${template.name ?? ""}|${template.lastModified ?? ""}`;
		return crypto.createHash("sha256").update(sig, "utf8").digest("hex");
	}

	private hashTabValues(envelope: DocuSignEnvelope): string | null {
		const texts: string[] = [];
		const recipients = envelope.recipients;
		if (!recipients) return null;

		for (const signer of recipients.signers ?? []) {
			const tabs = signer.tabs;
			if (!tabs) continue;
			for (const textTab of tabs.textTabs ?? []) {
				if (
					typeof textTab.value === "string" &&
					textTab.value.length > 0
				) {
					texts.push(`${textTab.tabLabel ?? ""}:${textTab.value}`);
				}
			}
		}

		if (texts.length === 0) return null;
		texts.sort();
		return crypto
			.createHash("sha256")
			.update(texts.join("\n"), "utf8")
			.digest("hex");
	}
}
