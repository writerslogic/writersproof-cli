// SPDX-License-Identifier: AGPL-3.0-only
import crypto from "crypto";

export interface DocumentHash {
	docId: string;
	name: string;
	hash: string;
	sizeBytes: number;
}

export interface WorkflowSnapshot {
	workflowId: string;
	title: string;
	status: string;
	workflowHash: string;
	documents: DocumentHash[];
	attributeHash: string | null;
	commentCount: number;
	capturedAt: string;
}

interface IroncladDocument {
	id: string;
	name?: string;
	[key: string]: unknown;
}

interface IroncladWorkflow {
	id: string;
	title?: string;
	status?: string;
	attributes?: Record<string, unknown>;
	[key: string]: unknown;
}

interface IroncladComment {
	id: string;
	[key: string]: unknown;
}

export class ContentMonitor {
	private readonly apiBase = "https://ironcladapp.com/public/api/v1";
	private getToken: () => Promise<string>;

	constructor(getToken: () => Promise<string>) {
		this.getToken = getToken;
	}

	private async apiGet<T>(path: string): Promise<T> {
		const token = await this.getToken();
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);

		try {
			const resp = await fetch(`${this.apiBase}${path}`, {
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
					`Ironclad API ${resp.status} for ${path}: ${text}`,
				);
			}
			return (await resp.json()) as T;
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	private async downloadDocument(
		workflowId: string,
		docId: string,
	): Promise<Buffer> {
		const token = await this.getToken();
		const path = `/workflows/${encodeURIComponent(workflowId)}/documents/${encodeURIComponent(docId)}/download`;
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 60_000);

		try {
			const resp = await fetch(`${this.apiBase}${path}`, {
				headers: { Authorization: `Bearer ${token}` },
				signal: controller.signal,
			});
			clearTimeout(timeoutId);
			if (!resp.ok) {
				const text = await resp.text().catch(() => resp.statusText);
				throw new Error(
					`Ironclad document download ${resp.status} for ${docId}: ${text}`,
				);
			}
			return Buffer.from(await resp.arrayBuffer());
		} catch (err) {
			clearTimeout(timeoutId);
			throw err;
		}
	}

	async captureSnapshot(workflowId: string): Promise<WorkflowSnapshot> {
		const [workflow, docsResp, commentsResp] = await Promise.all([
			this.apiGet<IroncladWorkflow>(
				`/workflows/${encodeURIComponent(workflowId)}`,
			),
			this.apiGet<{ records?: IroncladDocument[] }>(
				`/workflows/${encodeURIComponent(workflowId)}/documents`,
			).catch(() => ({ records: [] as IroncladDocument[] })),
			this.apiGet<{ records?: IroncladComment[] }>(
				`/workflows/${encodeURIComponent(workflowId)}/comments`,
			).catch(() => ({ records: [] as IroncladComment[] })),
		]);

		const rawDocs: IroncladDocument[] = docsResp.records ?? [];

		const documentHashes: DocumentHash[] = [];
		const chunks: IroncladDocument[][] = [];
		for (let i = 0; i < rawDocs.length; i += 5) {
			chunks.push(rawDocs.slice(i, i + 5));
		}

		for (const chunk of chunks) {
			const results = await Promise.all(
				chunk.map(async (doc) => {
					const bytes = await this.downloadDocument(
						workflowId,
						doc.id,
					);
					const hash = crypto
						.createHash("sha256")
						.update(bytes)
						.digest("hex");
					return {
						docId: doc.id,
						name: (doc.name as string | undefined) ?? doc.id,
						hash,
						sizeBytes: bytes.length,
					};
				}),
			);
			documentHashes.push(...results);
		}

		const sorted = [...documentHashes].sort((a, b) =>
			a.docId.localeCompare(b.docId),
		);
		const combined = sorted.map((d) => `${d.docId}:${d.hash}`).join("|");
		const workflowHash = crypto
			.createHash("sha256")
			.update(combined || workflowId, "utf8")
			.digest("hex");

		const attributeHash = this.hashAttributes(workflow.attributes);

		return {
			workflowId,
			title: workflow.title ?? workflowId,
			status: workflow.status ?? "unknown",
			workflowHash,
			documents: documentHashes,
			attributeHash,
			commentCount: commentsResp.records?.length ?? 0,
			capturedAt: new Date().toISOString(),
		};
	}

	async getApprovalStatus(workflowId: string): Promise<string> {
		const resp = await this.apiGet<{ status?: string }>(
			`/workflows/${encodeURIComponent(workflowId)}/approval`,
		).catch(() => ({ status: "unknown" }));
		return resp.status ?? "unknown";
	}

	async getRecord(recordId: string): Promise<{ id: string; hash: string }> {
		const record = await this.apiGet<{
			id: string;
			[key: string]: unknown;
		}>(`/records/${encodeURIComponent(recordId)}`);
		const sig = JSON.stringify(record);
		const hash = crypto
			.createHash("sha256")
			.update(sig, "utf8")
			.digest("hex");
		return { id: record.id, hash };
	}

	private hashAttributes(
		attributes: Record<string, unknown> | undefined,
	): string | null {
		if (!attributes || Object.keys(attributes).length === 0) return null;
		const entries = Object.entries(attributes)
			.filter(([, v]) => v !== null && v !== undefined && v !== "")
			.map(([k, v]) => `${k}:${JSON.stringify(v)}`)
			.sort();
		if (entries.length === 0) return null;
		return crypto
			.createHash("sha256")
			.update(entries.join("\n"), "utf8")
			.digest("hex");
	}
}
