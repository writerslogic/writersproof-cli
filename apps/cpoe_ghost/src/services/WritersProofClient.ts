// SPDX-License-Identifier: AGPL-3.0-only
// Re-export from shared SDK for backward compatibility
export {
	WritersProofClient,
	type SessionParams,
	type CheckpointParams,
	type FinalizeParams,
	type Session,
	type Evidence,
} from "@writersproof/sdk";
import { WritersProofClient } from "@writersproof/sdk";

export function hashContent(content: string): string {
	return WritersProofClient.hashContent(content);
}
