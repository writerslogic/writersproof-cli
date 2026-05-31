// SPDX-License-Identifier: AGPL-3.0-only
import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import {
	WritersProofClient,
	createLogger,
	requestLogger,
	gracefulShutdown,
	requireEnv,
} from "@writersproof/sdk";
import { ContentMonitor } from "./services/ContentMonitor.js";
import { createGhostEventHandler } from "./webhooks/events.js";

const GHOST_URL = requireEnv("GHOST_URL");
const GHOST_ADMIN_API_KEY = requireEnv("GHOST_ADMIN_API_KEY");
const WRITERSPROOF_API_KEY = requireEnv("WRITERSPROOF_API_KEY");
const WEBHOOK_SECRET = requireEnv("WEBHOOK_SECRET");
const PORT = parseInt(process.env.PORT ?? "3000", 10);

const logger = createLogger("ghost");

const app = express();

app.use(requestLogger(logger));

app.use(
	express.json({
		verify(req: Request, _res: Response, buf: Buffer) {
			(req as Request & { rawBody: Buffer }).rawBody = buf;
		},
	}),
);

function verifyWebhookSecret(
	req: Request,
	res: Response,
	next: NextFunction,
): void {
	const provided = req.headers["x-ghost-webhook-secret"];
	if (
		!provided ||
		!crypto.timingSafeEqual(
			Buffer.from(String(provided)),
			Buffer.from(WEBHOOK_SECRET),
		)
	) {
		res.status(403).json({ error: "Forbidden" });
		return;
	}
	next();
}

const rateLimiter = new Map<string, number[]>();
function rateLimit(windowMs: number, maxRequests: number) {
	return (req: Request, res: Response, next: NextFunction) => {
		const key = req.ip ?? "unknown";
		const now = Date.now();
		const window = rateLimiter.get(key) ?? [];
		const recent = window.filter((t) => now - t < windowMs);
		if (recent.length >= maxRequests) {
			res.status(429).json({ error: "Too many requests" });
			return;
		}
		recent.push(now);
		rateLimiter.set(key, recent);
		next();
	};
}

const client = new WritersProofClient(WRITERSPROOF_API_KEY, "ghost");
const monitor = new ContentMonitor(GHOST_URL, GHOST_ADMIN_API_KEY);
const handleGhostEvent = createGhostEventHandler(client, monitor);

app.post(
	"/webhooks/ghost",
	rateLimit(60_000, 100),
	verifyWebhookSecret,
	handleGhostEvent,
);

app.get("/health", (_req: Request, res: Response) => {
	res.json({
		status: "ok",
		platform: "ghost",
		timestamp: new Date().toISOString(),
	});
});

gracefulShutdown(async () => {
	logger.info("Cleaning up active sessions");
});

app.listen(PORT, () => {
	logger.info("Server started", { port: PORT });
});

export default app;
