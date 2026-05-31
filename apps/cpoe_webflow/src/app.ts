// SPDX-License-Identifier: AGPL-3.0-only
import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { WritersProofClient } from "./services/WritersProofClient.js";
import { ContentMonitor } from "./services/ContentMonitor.js";
import { createWebflowEventHandler } from "./webhooks/events.js";

const WEBFLOW_CLIENT_ID = process.env.WEBFLOW_CLIENT_ID ?? "";
const WEBFLOW_CLIENT_SECRET = process.env.WEBFLOW_CLIENT_SECRET ?? "";
const WRITERSPROOF_API_KEY = process.env.WRITERSPROOF_API_KEY ?? "";
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET ?? "";
const PORT = parseInt(process.env.PORT ?? "3001", 10);

if (!WEBFLOW_CLIENT_ID)
	throw new Error("WEBFLOW_CLIENT_ID environment variable is required");
if (!WEBFLOW_CLIENT_SECRET)
	throw new Error("WEBFLOW_CLIENT_SECRET environment variable is required");
if (!WRITERSPROOF_API_KEY)
	throw new Error("WRITERSPROOF_API_KEY environment variable is required");
if (!WEBHOOK_SECRET)
	throw new Error("WEBHOOK_SECRET environment variable is required");

/** In-memory OAuth token store. Replace with persistent storage for production multi-tenant use. */
let webflowAccessToken = process.env.WEBFLOW_ACCESS_TOKEN ?? "";

const app = express();

app.use(
	express.json({
		verify(_req: Request, _res: Response, buf: Buffer) {
			(_req as Request & { rawBody: Buffer }).rawBody = buf;
		},
	}),
);

function verifyWebflowSignature(
	req: Request,
	res: Response,
	next: NextFunction,
): void {
	if (!WEBHOOK_SECRET) {
		next();
		return;
	}
	const signature = req.headers["x-webflow-signature"];
	if (!signature || typeof signature !== "string") {
		res.status(403).json({ error: "Missing X-Webflow-Signature" });
		return;
	}
	const rawBody = (req as Request & { rawBody?: Buffer }).rawBody;
	if (!rawBody) {
		res.status(400).json({ error: "Missing request body" });
		return;
	}
	const computed = crypto
		.createHmac("sha256", WEBHOOK_SECRET)
		.update(rawBody)
		.digest("hex");
	try {
		if (
			!crypto.timingSafeEqual(
				Buffer.from(signature, "hex"),
				Buffer.from(computed, "hex"),
			)
		) {
			res.status(403).json({ error: "Invalid signature" });
			return;
		}
	} catch {
		res.status(403).json({ error: "Invalid signature" });
		return;
	}
	next();
}

app.get("/oauth/authorize", (_req: Request, res: Response) => {
	const params = new URLSearchParams({
		response_type: "code",
		client_id: WEBFLOW_CLIENT_ID,
		scope: "cms:read cms:write sites:read webhooks:write",
	});
	res.redirect(`https://webflow.com/oauth/authorize?${params.toString()}`);
});

app.get("/oauth/callback", async (req: Request, res: Response) => {
	const code = typeof req.query.code === "string" ? req.query.code : "";
	if (!code) {
		res.status(400).json({ error: "Missing authorization code" });
		return;
	}

	try {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);
		const resp = await fetch("https://api.webflow.com/oauth/access_token", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				client_id: WEBFLOW_CLIENT_ID,
				client_secret: WEBFLOW_CLIENT_SECRET,
				code,
				grant_type: "authorization_code",
			}),
			signal: controller.signal,
		});
		clearTimeout(timeoutId);

		if (!resp.ok) {
			const text = await resp.text();
			res.status(502).json({
				error: `Webflow token exchange failed: ${text}`,
			});
			return;
		}

		const data = (await resp.json()) as { access_token?: string };
		if (!data.access_token) {
			res.status(502).json({
				error: "No access_token in Webflow response",
			});
			return;
		}

		webflowAccessToken = data.access_token;
		monitor = new ContentMonitor(webflowAccessToken);
		handleWebflowEvent = createWebflowEventHandler(client, monitor);

		res.json({ ok: true, message: "Webflow OAuth complete" });
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		res.status(500).json({ error: message });
	}
});

const client = new WritersProofClient(WRITERSPROOF_API_KEY, "webflow");
let monitor = new ContentMonitor(webflowAccessToken);
let handleWebflowEvent = createWebflowEventHandler(client, monitor);

app.post(
	"/webhooks/webflow",
	verifyWebflowSignature,
	(req: Request, res: Response) => {
		return handleWebflowEvent(req, res);
	},
);

app.get("/health", (_req: Request, res: Response) => {
	res.json({
		status: "ok",
		platform: "webflow",
		authenticated: webflowAccessToken.length > 0,
		timestamp: new Date().toISOString(),
	});
});

app.listen(PORT, () => {
	process.stdout.write(`cpoe-webflow listening on port ${PORT}\n`);
});

export default app;
