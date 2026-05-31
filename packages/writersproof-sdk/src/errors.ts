// SPDX-License-Identifier: AGPL-3.0-only
export class WritersProofError extends Error {
	constructor(
		message: string,
		public readonly statusCode?: number,
		public readonly retryable = false,
	) {
		super(message);
		this.name = "WritersProofError";
	}
}

export class RateLimitError extends WritersProofError {
	constructor(public readonly retryAfterMs: number) {
		super(`Rate limited, retry after ${retryAfterMs}ms`, 429, true);
		this.name = "RateLimitError";
	}
}

export class TimeoutError extends WritersProofError {
	constructor(method: string, path: string) {
		super(
			`Request timed out after 30s: ${method} ${path}`,
			undefined,
			true,
		);
		this.name = "TimeoutError";
	}
}

export class AuthenticationError extends WritersProofError {
	constructor(message = "Authentication failed") {
		super(message, 401, false);
		this.name = "AuthenticationError";
	}
}
