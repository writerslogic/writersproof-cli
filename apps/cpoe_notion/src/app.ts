// SPDX-License-Identifier: AGPL-3.0-only
import "dotenv/config";
import express, { Request, Response } from "express";
import { WritersProofClient } from "./services/WritersProofClient.js";
import { ContentMonitor } from "./services/ContentMonitor.js";
import {
	handlePageChanged,
	finalizePageSession,
	getActiveSessionId,
} from "./webhooks/events.js";

const NOTION_API_KEY = process.env.NOTION_API_KEY ?? "";
const NOTION_CLIENT_ID = process.env.NOTION_CLIENT_ID ?? "";
const NOTION_CLIENT_SECRET = process.env.NOTION_CLIENT_SECRET ?? "";
const WRITERSPROOF_API_KEY = process.env.WRITERSPROOF_API_KEY ?? "";
const PORT = parseInt(process.env.PORT ?? "3006", 10);
const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS ?? "60000", 10);
const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI ?? "";

if (!WRITERSPROOF_API_KEY)
	throw new Error("WRITERSPROOF_API_KEY environment variable is required");
if (!NOTION_API_KEY && !NOTION_CLIENT_ID)
	throw new Error(
		"Either NOTION_API_KEY (internal) or NOTION_CLIENT_ID + NOTION_CLIENT_SECRET (OAuth) is required",
	);

// OAuth token storage — in production, persist to a database
let oauthAccessToken = NOTION_API_KEY;
const oauthTokens = new Map<string, { accessToken: string }>();

const app = express();
app.use(express.json());

const wpClient = new WritersProofClient(WRITERSPROOF_API_KEY, "notion");

function buildMonitor(): ContentMonitor {
	const key = oauthAccessToken;
	if (!key) throw new Error("No Notion API key available");
	return new ContentMonitor(key);
}

// Active polling state
let pollingInterval: ReturnType<typeof setInterval> | null = null;
let lastPollTime = new Date(0);
let monitor: ContentMonitor | null = null;
const monitoringActive = { value: false };

async function pollForChanges(): Promise<void> {
	if (!monitor) return;
	try {
		const pages = await monitor.searchRecentPages(lastPollTime);
		const pollStart = new Date();

		for (const page of pages) {
			const lastEdited = new Date(page.last_edited_time);
			if (lastEdited <= lastPollTime) continue;
			try {
				await handlePageChanged(page, wpClient, monitor);
			} catch (err) {
				process.stderr.write(
					`Poll error for page ${page.id}: ${err instanceof Error ? err.message : String(err)}\n`,
				);
			}
		}

		lastPollTime = pollStart;
	} catch (err) {
		process.stderr.write(
			`Poll cycle error: ${err instanceof Error ? err.message : String(err)}\n`,
		);
	}
}

// OAuth2 routes (public integration mode)
app.get("/oauth/authorize", (_req: Request, res: Response) => {
	if (!NOTION_CLIENT_ID) {
		res.status(400).json({ error: "OAuth not configured" });
		return;
	}
	const params = new URLSearchParams({
		client_id: NOTION_CLIENT_ID,
		response_type: "code",
		owner: "user",
		redirect_uri: OAUTH_REDIRECT_URI,
	});
	res.redirect(
		`https://api.notion.com/v1/oauth/authorize?${params.toString()}`,
	);
});

app.get("/oauth/callback", async (req: Request, res: Response) => {
	const code = req.query["code"];
	if (typeof code !== "string" || !code) {
		res.status(400).json({ error: "Missing code parameter" });
		return;
	}
	if (!NOTION_CLIENT_ID || !NOTION_CLIENT_SECRET) {
		res.status(400).json({ error: "OAuth not configured" });
		return;
	}

	try {
		const credentials = Buffer.from(
			`${NOTION_CLIENT_ID}:${NOTION_CLIENT_SECRET}`,
		).toString("base64");
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30_000);
		const resp = await fetch("https://api.notion.com/v1/oauth/token", {
			method: "POST",
			headers: {
				Authorization: `Basic ${credentials}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				grant_type: "authorization_code",
				code,
				redirect_uri: OAUTH_REDIRECT_URI,
			}),
			signal: controller.signal,
		});
		clearTimeout(timeoutId);

		if (!resp.ok) {
			const text = await resp.text();
			res.status(502).json({ error: `Notion OAuth error: ${text}` });
			return;
		}

		const data = (await resp.json()) as {
			access_token: string;
			workspace_id: string;
		};
		oauthAccessToken = data.access_token;
		oauthTokens.set(data.workspace_id, { accessToken: data.access_token });
		res.json({ ok: true, workspaceId: data.workspace_id });
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		res.status(500).json({ error: message });
	}
});

app.get("/health", (_req: Request, res: Response) => {
	res.json({
		status: "ok",
		platform: "notion",
		polling: monitoringActive.value,
		lastPollTime: lastPollTime.toISOString(),
		timestamp: new Date().toISOString(),
	});
});

app.post("/api/start-polling", (_req: Request, res: Response) => {
	if (monitoringActive.value) {
		res.json({ ok: true, message: "Polling already active" });
		return;
	}
	try {
		monitor = buildMonitor();
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		res.status(400).json({ error: message });
		return;
	}

	lastPollTime = new Date(0);
	monitoringActive.value = true;

	// Run first poll immediately, then on interval
	void pollForChanges();
	pollingInterval = setInterval(
		() => void pollForChanges(),
		POLL_INTERVAL_MS,
	);

	res.json({ ok: true, pollIntervalMs: POLL_INTERVAL_MS });
});

app.post("/api/stop-polling", (_req: Request, res: Response) => {
	if (pollingInterval !== null) {
		clearInterval(pollingInterval);
		pollingInterval = null;
	}
	monitoringActive.value = false;
	res.json({ ok: true, message: "Polling stopped" });
});

app.get("/api/status", (_req: Request, res: Response) => {
	res.json({
		polling: monitoringActive.value,
		pollIntervalMs: POLL_INTERVAL_MS,
		lastPollTime: lastPollTime.toISOString(),
	});
});

app.get("/api/evidence/:pageId", async (req: Request, res: Response) => {
	const { pageId } = req.params;
	if (!pageId) {
		res.status(400).json({ error: "pageId is required" });
		return;
	}

	const sessionId = getActiveSessionId(pageId);
	if (!sessionId) {
		res.status(404).json({ error: "No active session for this page" });
		return;
	}

	try {
		const evidence = await wpClient.getEvidence(sessionId);
		res.json(evidence);
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		res.status(502).json({ error: message });
	}
});

app.post("/api/finalize/:pageId", async (req: Request, res: Response) => {
	const { pageId } = req.params;
	if (!pageId || !monitor) {
		res.status(400).json({
			error: "pageId required and polling must be active",
		});
		return;
	}

	try {
		await finalizePageSession(pageId, wpClient, monitor);
		res.json({ ok: true });
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		res.status(502).json({ error: message });
	}
});

app.listen(PORT, () => {
	process.stdout.write(`cpoe-notion listening on port ${PORT}\n`);
});

export default app;
