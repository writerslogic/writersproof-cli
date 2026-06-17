// SPDX-License-Identifier: AGPL-3.0-only
import "dotenv/config";
import express, { Request, Response } from "express";
import { ContentMonitor } from "./services/ContentMonitor";
import { WritersProofClient } from "./services/WritersProofClient";
import { createWebhookHandler } from "./webhooks/events";

const PORT = parseInt(process.env.PORT ?? "3002", 10);
const GITHUB_APP_ID = process.env.GITHUB_APP_ID ?? "";
const GITHUB_PRIVATE_KEY_PATH = process.env.GITHUB_PRIVATE_KEY_PATH ?? "";
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET ?? "";
const WRITERSPROOF_API_KEY = process.env.WRITERSPROOF_API_KEY ?? "";

if (!GITHUB_APP_ID) throw new Error("GITHUB_APP_ID is required");
if (!GITHUB_PRIVATE_KEY_PATH)
	throw new Error("GITHUB_PRIVATE_KEY_PATH is required");
if (!GITHUB_WEBHOOK_SECRET)
	throw new Error("GITHUB_WEBHOOK_SECRET is required");
if (!WRITERSPROOF_API_KEY) throw new Error("WRITERSPROOF_API_KEY is required");

const monitor = new ContentMonitor(GITHUB_APP_ID, GITHUB_PRIVATE_KEY_PATH);
const client = new WritersProofClient(WRITERSPROOF_API_KEY, "github");
const webhookHandler = createWebhookHandler(
	monitor,
	client,
	GITHUB_WEBHOOK_SECRET,
);

const app = express();

// Capture raw body buffer before JSON parsing so webhook signature verification
// operates on the exact bytes GitHub sent.
app.use(
	express.json({
		verify: (req: Request & { rawBody?: Buffer }, _res, buf) => {
			req.rawBody = buf;
		},
	}),
);

app.get("/health", (_req: Request, res: Response) => {
	res.json({ ok: true, platform: "github", version: "1.0.0" });
});

app.post("/webhooks/github", webhookHandler);

// Register a webhook URL on a given installation. Callers supply the
// installation token (or use the app JWT) and the target repo.
app.post("/api/setup", async (req: Request, res: Response) => {
	const { installationId, owner, repo, webhookUrl } = req.body as {
		installationId?: string;
		owner?: string;
		repo?: string;
		webhookUrl?: string;
	};

	if (!installationId || !owner || !repo || !webhookUrl) {
		res.status(400).json({
			error: "installationId, owner, repo, and webhookUrl are required",
		});
		return;
	}

	try {
		const parsed = new URL(webhookUrl);
		if (parsed.protocol !== "https:") {
			res.status(400).json({ error: "webhookUrl must use https://" });
			return;
		}
	} catch {
		res.status(400).json({ error: "webhookUrl is not a valid URL" });
		return;
	}

	try {
		const token = await monitor.getInstallationToken(installationId);
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);

		const resp = await fetch(
			`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/hooks`,
			{
				method: "POST",
				headers: {
					Authorization: `Bearer ${token}`,
					Accept: "application/vnd.github+json",
					"Content-Type": "application/json",
					"X-GitHub-Api-Version": "2022-11-28",
				},
				body: JSON.stringify({
					name: "web",
					active: true,
					events: [
						"issues",
						"issue_comment",
						"pull_request",
						"pull_request_review",
						"pull_request_review_comment",
						"discussion",
						"discussion_comment",
						"gollum",
					],
					config: {
						url: webhookUrl,
						content_type: "json",
						secret: GITHUB_WEBHOOK_SECRET,
						insecure_ssl: "0",
					},
				}),
				signal: controller.signal,
			},
		);
		clearTimeout(timeoutId);

		if (!resp.ok) {
			const text = await resp.text().catch(() => resp.statusText);
			res.status(resp.status).json({ error: text });
			return;
		}

		const hook = await resp.json();
		res.json({ ok: true, hookId: (hook as Record<string, unknown>).id });
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		res.status(500).json({ error: message });
	}
});

app.listen(PORT, () => {
	process.stdout.write(`cpoe-github listening on port ${PORT}\n`);
});
