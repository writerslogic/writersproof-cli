// SPDX-License-Identifier: AGPL-3.0-only
export interface SessionParams {
	documentId: string;
	documentTitle: string;
	contentHash: string;
	platform?: string;
}

export interface CheckpointParams {
	contentHash: string;
	wordCount: number;
	charCount: number;
}

export interface FinalizeParams {
	contentHash: string;
	wordCount: number;
	finalSnapshot?: string;
}

export interface Session {
	id: string;
	documentId: string;
	documentTitle: string;
	platform: string;
	contentHash: string;
	createdAt: string;
}

export interface Evidence {
	sessionId: string;
	packets: unknown[];
}

export interface ContentEvent {
	type: "content_change" | "structure_change" | "field_modified";
	timestamp: string;
	contentHash: string;
	wordDelta?: number;
	charDelta?: number;
	metadata?: Record<string, unknown>;
}
