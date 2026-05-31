// SPDX-License-Identifier: AGPL-3.0-only
import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import { WritersProofClient } from "./services/WritersProofClient.js";
import { ContentMonitor } from "./services/ContentMonitor.js";
import {
	createClioWebhookHandler,
	getActiveSessionId,
} from "./webhooks/events.js";

const CLIO_CLIENT_ID = process.env.CLIO_CLIENT_ID ?? "";
const CLIO_CLIENT_SECRET = process.env.CLIO_CLIENT_SECRET ?? "";
const CLIO_WEBHOOK_SECRET = process.env.CLIO_WEBHOOK_SECRET ?? "";
const WRITERSPROOF_API_KEY = process.env.WRITERSPROOF_API_KEY ?? "";
const PORT = parseInt(process.env.PORT ?? "3007", 10);
const OAUTH_REDIRECT_URI =
	process.env.OAUTH_REDIRECT_URI ?? `http://localhost:${PORT}/oauth/callback`;

if (!CLIO_CLIENT_ID)
	throw new Error("CLIO_CLIENT_ID environment variable is required");
if (!CLIO_CLIENT_SECRET)
	throw new Error("CLIO_CLIENT_SECRET environment variable is required");
if (!CLIO_WEBHOOK_SECRET)
	throw new Error("CLIO_WEBHOOK_SECRET environment variable is required");
if (!WRITERSPROOF_API_KEY)
	throw new Error("WRITERSPROOF_API_KEY environment variable is required");

// Token store — in production, persist to a database
let currentAccessToken = "";
let currentRefreshToken = "";

const app = express();

// Capture raw body for webhook signature verification before JSON parsing
app.use(
	express.json({
		verify(req: Request, _res: Response, buf: Buffer) {
			(req as Request & { rawBody: Buffer }).rawBody = buf;
		},
	}),
);

const wpClient = new WritersProofClient(WRITERSPROOF_API_KEY, "clio");

function buildMonitor(): ContentMonitor {
	return new ContentMonitor(
		CLIO_CLIENT_ID,
		CLIO_CLIENT_SECRET,
		currentAccessToken,
		currentRefreshToken,
	);
}

// Lazily initialized after OAuth completes
let monitor: ContentMonitor | null = null;

function requireMonitor(
	_req: Request,
	res: Response,
	next: NextFunction,
): void {
	if (!monitor) {
		res.status(503).json({ error: "OAuth not completed; no access token" });
		return;
	}
	next();
}

app.get("/oauth/authorize", (_req: Request, res: Response) => {
	const params = new URLSearchParams({
		response_type: "code",
		client_id: CLIO_CLIENT_ID,
		redirect_uri: OAUTH_REDIRECT_URI,
	});
	res.redirect(`https://app.clio.com/oauth/authorize?${params.toString()}`);
});

app.get("/oauth/callback", async (req: Request, res: Response) => {
	const code = req.query["code"];
	if (typeof code !== "string" || !code) {
		res.status(400).json({ error: "Missing code parameter" });
		return;
	}

	try {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);
		const resp = await fetch("https://app.clio.com/oauth/token", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				grant_type: "authorization_code",
				code,
				client_id: CLIO_CLIENT_ID,
				client_secret: CLIO_CLIENT_SECRET,
				redirect_uri: OAUTH_REDIRECT_URI,
			}),
			signal: controller.signal,
		});
		clearTimeout(timeoutId);

		if (!resp.ok) {
			const text = await resp.text();
			res.status(502).json({ error: `Clio OAuth error: ${text}` });
			return;
		}

		const data = (await resp.json()) as {
			access_token: string;
			refresh_token: string;
		};
		currentAccessToken = data.access_token;
		currentRefreshToken = data.refresh_token;
		monitor = buildMonitor();
		res.json({ ok: true });
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		res.status(500).json({ error: message });
	}
});

app.post("/webhooks/clio", requireMonitor, (req: Request, res: Response) => {
	createClioWebhookHandler(wpClient, monitor!, CLIO_WEBHOOK_SECRET)(req, res);
});

app.get("/health", (_req: Request, res: Response) => {
	res.json({
		status: "ok",
		platform: "clio",
		authenticated: monitor !== null,
		timestamp: new Date().toISOString(),
	});
});

app.get("/api/status", (_req: Request, res: Response) => {
	res.json({
		authenticated: monitor !== null,
	});
});

app.get(
	"/api/evidence/:matterId",
	requireMonitor,
	async (req: Request, res: Response) => {
		const matterId = parseInt(req.params["matterId"] ?? "", 10);
		if (isNaN(matterId)) {
			res.status(400).json({ error: "matterId must be a number" });
			return;
		}

		const types = ["document", "note", "communication"] as const;
		const results: Record<string, string | undefined> = {};
		for (const type of types) {
			const sessionId = getActiveSessionId(type, matterId);
			if (sessionId) results[type] = sessionId;
		}

		if (Object.keys(results).length === 0) {
			res.status(404).json({
				error: "No active sessions for this matter",
			});
			return;
		}

		try {
			const evidence = await Promise.all(
				Object.entries(results).map(async ([type, sessionId]) => ({
					type,
					evidence: await wpClient.getEvidence(sessionId!),
				})),
			);
			res.json({ matterId, evidence });
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			res.status(502).json({ error: message });
		}
	},
);

app.listen(PORT, () => {
	process.stdout.write(`cpoe-clio listening on port ${PORT}\n`);
});

export default app;
