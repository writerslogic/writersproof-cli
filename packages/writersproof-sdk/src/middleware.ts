// SPDX-License-Identifier: AGPL-3.0-only
import type { Request, Response, NextFunction } from "express";
import type { Logger } from "./logger.js";

export function requestLogger(logger: Logger) {
	return (req: Request, res: Response, next: NextFunction) => {
		const start = Date.now();
		res.on("finish", () => {
			logger.info("request", {
				method: req.method,
				path: req.path,
				status: res.statusCode,
				duration: Date.now() - start,
			});
		});
		next();
	};
}

export function gracefulShutdown(cleanup?: () => Promise<void>) {
	const shutdown = async (signal: string) => {
		process.stdout.write(
			JSON.stringify({
				level: "info",
				msg: `${signal} received, shutting down gracefully`,
			}) + "\n",
		);
		if (cleanup) await cleanup();
		process.exit(0);
	};
	process.on("SIGTERM", () => void shutdown("SIGTERM"));
	process.on("SIGINT", () => void shutdown("SIGINT"));
}
