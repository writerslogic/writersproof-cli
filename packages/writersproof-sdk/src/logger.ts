// SPDX-License-Identifier: AGPL-3.0-only
export interface Logger {
	info(msg: string, context?: Record<string, unknown>): void;
	warn(msg: string, context?: Record<string, unknown>): void;
	error(msg: string, context?: Record<string, unknown>): void;
	debug(msg: string, context?: Record<string, unknown>): void;
}

function emit(
	stream: NodeJS.WriteStream,
	level: string,
	platform: string,
	msg: string,
	ctx?: Record<string, unknown>,
): void {
	stream.write(
		JSON.stringify({
			level,
			platform,
			msg,
			...ctx,
			ts: new Date().toISOString(),
		}) + "\n",
	);
}

export function createLogger(platform: string): Logger {
	return {
		info: (msg, ctx) => emit(process.stdout, "info", platform, msg, ctx),
		warn: (msg, ctx) => emit(process.stderr, "warn", platform, msg, ctx),
		error: (msg, ctx) => emit(process.stderr, "error", platform, msg, ctx),
		debug: (msg, ctx) => {
			if (process.env.LOG_LEVEL === "debug")
				emit(process.stdout, "debug", platform, msg, ctx);
		},
	};
}
