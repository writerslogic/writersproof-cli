// SPDX-License-Identifier: AGPL-3.0-only
import "dotenv/config";
import express, { Request, Response } from "express";
import { ContentMonitor } from "./services/ContentMonitor";
import { WritersProofClient } from "./services/WritersProofClient";
import { createWebhookHandler, storeOrgToken } from "./webhooks/events";

const PORT = parseInt(process.env.PORT ?? "3003", 10);
const LINEAR_CLIENT_ID = process.env.LINEAR_CLIENT_ID ?? "";
const LINEAR_CLIENT_SECRET = process.env.LINEAR_CLIENT_SECRET ?? "";
const LINEAR_WEBHOOK_SECRET = process.env.LINEAR_WEBHOOK_SECRET ?? "";
const WRITERSPROOF_API_KEY = process.env.WRITERSPROOF_API_KEY ?? "";

if (!LINEAR_CLIENT_ID) throw new Error("LINEAR_CLIENT_ID is required");
if (!LINEAR_CLIENT_SECRET) throw new Error("LINEAR_CLIENT_SECRET is required");
if (!LINEAR_WEBHOOK_SECRET)
	throw new Error("LINEAR_WEBHOOK_SECRET is required");
if (!WRITERSPROOF_API_KEY) throw new Error("WRITERSPROOF_API_KEY is required");

const monitor = new ContentMonitor();
const client = new WritersProofClient(WRITERSPROOF_API_KEY, "linear");
const webhookHandler = createWebhookHandler(
	monitor,
	client,
	LINEAR_WEBHOOK_SECRET,
);

const app = express();

// Capture raw body buffer before JSON parsing so webhook signature verification
// operates on the exact bytes Linear sent.
app.use(
	express.json({
		verify: (req: Request & { rawBody?: Buffer }, _res, buf) => {
			req.rawBody = buf;
		},
	}),
);

app.get("/health", (_req: Request, res: Response) => {
	res.json({ ok: true, platform: "linear", version: "1.0.0" });
});

app.get("/oauth/authorize", (_req: Request, res: Response) => {
	const redirectUri = `${process.env.APP_BASE_URL ?? ""}/oauth/callback`;
	const params = new URLSearchParams({
		client_id: LINEAR_CLIENT_ID,
		redirect_uri: redirectUri,
		response_type: "code",
		scope: "read write",
	});
	res.redirect(`https://linear.app/oauth/authorize?${params.toString()}`);
});

app.get("/oauth/callback", async (req: Request, res: Response) => {
	const { code, error } = req.query as { code?: string; error?: string };

	if (error || !code) {
		res.status(400).json({ error: error ?? "missing code" });
		return;
	}

	const redirectUri = `${process.env.APP_BASE_URL ?? ""}/oauth/callback`;

	try {
		const tokenData = await ContentMonitor.exchangeCodeForToken(
			LINEAR_CLIENT_ID,
			LINEAR_CLIENT_SECRET,
			code,
			redirectUri,
		);

		// Fetch the organization ID from Linear to key the token store.
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);
		let organizationId = "default";

		try {
			const resp = await fetch("https://api.linear.app/graphql", {
				method: "POST",
				headers: {
					Authorization: `Bearer ${tokenData.access_token}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					query: "{ organization { id } }",
				}),
				signal: controller.signal,
			});
			clearTimeout(timeoutId);

			if (resp.ok) {
				const body = (await resp.json()) as {
					data?: { organization?: { id: string } };
				};
				organizationId = body.data?.organization?.id ?? "default";
			}
		} catch {
			clearTimeout(timeoutId);
		}

		storeOrgToken(organizationId, tokenData.access_token);
		res.json({ ok: true, organizationId });
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		res.status(500).json({ error: message });
	}
});

app.post("/webhooks/linear", webhookHandler);

app.listen(PORT, () => {
	process.stdout.write(`cpoe-linear listening on port ${PORT}\n`);
});
