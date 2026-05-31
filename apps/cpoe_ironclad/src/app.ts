// SPDX-License-Identifier: AGPL-3.0-only
import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import { WritersProofClient } from "./services/WritersProofClient.js";
import { ContentMonitor } from "./services/ContentMonitor.js";
import {
	verifyWebhookSignature,
	parseWebhookPayload,
	handleWorkflowEvent,
} from "./webhooks/events.js";

const PORT = parseInt(process.env.PORT ?? "3009", 10);
const CLIENT_ID = process.env.IRONCLAD_CLIENT_ID ?? "";
const CLIENT_SECRET = process.env.IRONCLAD_CLIENT_SECRET ?? "";
const API_KEY = process.env.IRONCLAD_API_KEY ?? "";
const WEBHOOK_SECRET = process.env.IRONCLAD_WEBHOOK_SECRET ?? "";
const WP_API_KEY = process.env.WRITERSPROOF_API_KEY ?? "";

const IRONCLAD_AUTHORIZE_URL = "https://ironcladapp.com/oauth/authorize";
const IRONCLAD_TOKEN_URL = "https://ironcladapp.com/oauth/token";

interface TokenPair {
	accessToken: string;
	refreshToken: string;
	expiresAt: number;
}

let tokenPair: TokenPair | null = null;

async function getAccessToken(): Promise<string> {
	if (API_KEY) return API_KEY;

	if (tokenPair && Date.now() < tokenPair.expiresAt - 60_000) {
		return tokenPair.accessToken;
	}

	if (tokenPair?.refreshToken) {
		try {
			tokenPair = await refreshAccessToken(tokenPair.refreshToken);
			return tokenPair.accessToken;
		} catch {
			tokenPair = null;
		}
	}

	throw new Error(
		"No valid Ironclad credentials. Set IRONCLAD_API_KEY or complete OAuth flow at /oauth/authorize",
	);
}

async function refreshAccessToken(refreshToken: string): Promise<TokenPair> {
	const resp = await fetch(IRONCLAD_TOKEN_URL, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			grant_type: "refresh_token",
			refresh_token: refreshToken,
			client_id: CLIENT_ID,
			client_secret: CLIENT_SECRET,
		}),
	});

	if (!resp.ok) {
		const text = await resp.text().catch(() => resp.statusText);
		throw new Error(
			`Ironclad token refresh failed ${resp.status}: ${text}`,
		);
	}

	const data = (await resp.json()) as {
		access_token: string;
		refresh_token: string;
		expires_in?: number;
	};

	return {
		accessToken: data.access_token,
		refreshToken: data.refresh_token,
		expiresAt: Date.now() + (data.expires_in ?? 3600) * 1000,
	};
}

const wpClient = new WritersProofClient(WP_API_KEY, "ironclad");
const monitor = new ContentMonitor(getAccessToken);

const evidenceIndex = new Map<string, string>();

const app = express();

app.use(
	"/webhooks/ironclad",
	express.raw({ type: "*/*", limit: "10mb" }),
	(req: Request, _res: Response, next: NextFunction) => {
		(req as Request & { rawBody: Buffer }).rawBody = req.body as Buffer;
		try {
			req.body = JSON.parse((req.body as Buffer).toString("utf8"));
		} catch {
			req.body = {};
		}
		next();
	},
);

app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req: Request, res: Response) => {
	res.json({
		status: "ok",
		service: "cpoe-ironclad",
		timestamp: new Date().toISOString(),
	});
});

app.get("/api/status", (_req: Request, res: Response) => {
	res.json({
		service: "cpoe-ironclad",
		activeSessions: evidenceIndex.size,
		authMode: API_KEY ? "api_key" : "oauth",
		timestamp: new Date().toISOString(),
	});
});

app.get("/api/evidence/:workflowId", async (req: Request, res: Response) => {
	const { workflowId } = req.params;
	const sessionId = evidenceIndex.get(workflowId);
	if (!sessionId) {
		res.status(404).json({
			error: "No evidence session found for this workflow",
		});
		return;
	}
	try {
		const evidence = await wpClient.getEvidence(sessionId);
		res.json(evidence);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		res.status(502).json({ error: msg });
	}
});

app.get("/oauth/authorize", (req: Request, res: Response) => {
	if (!CLIENT_ID) {
		res.status(500).json({ error: "IRONCLAD_CLIENT_ID not configured" });
		return;
	}
	const redirectUri = `${process.env.APP_BASE_URL ?? `http://localhost:${PORT}`}/oauth/callback`;
	const state =
		(req.query["state"] as string | undefined) ?? crypto.randomUUID();
	const url =
		`${IRONCLAD_AUTHORIZE_URL}` +
		`?client_id=${encodeURIComponent(CLIENT_ID)}` +
		`&response_type=code` +
		`&redirect_uri=${encodeURIComponent(redirectUri)}` +
		`&state=${encodeURIComponent(state)}`;
	res.redirect(url);
});

app.get("/oauth/callback", async (req: Request, res: Response) => {
	const code = req.query["code"] as string | undefined;
	if (!code) {
		res.status(400).json({ error: "Missing authorization code" });
		return;
	}

	try {
		const redirectUri = `${process.env.APP_BASE_URL ?? `http://localhost:${PORT}`}/oauth/callback`;
		const resp = await fetch(IRONCLAD_TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				grant_type: "authorization_code",
				code,
				redirect_uri: redirectUri,
				client_id: CLIENT_ID,
				client_secret: CLIENT_SECRET,
			}),
		});

		if (!resp.ok) {
			const text = await resp.text().catch(() => resp.statusText);
			res.status(502).json({ error: `Token exchange failed: ${text}` });
			return;
		}

		const data = (await resp.json()) as {
			access_token: string;
			refresh_token: string;
			expires_in?: number;
		};

		tokenPair = {
			accessToken: data.access_token,
			refreshToken: data.refresh_token,
			expiresAt: Date.now() + (data.expires_in ?? 3600) * 1000,
		};

		res.json({ message: "Authorization successful" });
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		res.status(500).json({ error: msg });
	}
});

app.post("/webhooks/ironclad", async (req: Request, res: Response) => {
	const rawReq = req as Request & { rawBody?: Buffer };
	const rawBody = rawReq.rawBody;

	if (!rawBody) {
		res.status(400).json({ error: "Empty body" });
		return;
	}

	const signature = req.headers["x-ironclad-signature"] as string | undefined;
	if (WEBHOOK_SECRET && signature) {
		const valid = verifyWebhookSignature(
			rawBody,
			signature,
			WEBHOOK_SECRET,
		);
		if (!valid) {
			res.status(401).json({ error: "Invalid webhook signature" });
			return;
		}
	}

	const payload = parseWebhookPayload(req.body);
	if (!payload) {
		res.status(400).json({ error: "Unrecognized payload structure" });
		return;
	}

	res.status(202).json({ accepted: true });

	setImmediate(async () => {
		try {
			await handleWorkflowEvent(payload, wpClient, monitor);
		} catch {
			// Non-fatal; Ironclad will retry unacknowledged webhooks
		}
	});
});

app.listen(PORT, () => {
	process.stdout.write(`cpoe-ironclad listening on port ${PORT}\n`);
});

export default app;
