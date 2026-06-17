// SPDX-License-Identifier: AGPL-3.0-only
import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import * as jose from "jose";
import { WritersProofClient } from "./services/WritersProofClient.js";
import { ContentMonitor } from "./services/ContentMonitor.js";
import {
	verifyConnectSignature,
	parseConnectPayload,
	handleEnvelopeEvent,
} from "./webhooks/events.js";

const PORT = parseInt(process.env.PORT ?? "3008", 10);
const INTEGRATION_KEY = process.env.DOCUSIGN_INTEGRATION_KEY ?? "";
const USER_ID = process.env.DOCUSIGN_USER_ID ?? "";
const ACCOUNT_ID = process.env.DOCUSIGN_ACCOUNT_ID ?? "";
const RSA_PRIVATE_KEY = process.env.DOCUSIGN_RSA_PRIVATE_KEY ?? "";
const DS_BASE_URL =
	process.env.DOCUSIGN_BASE_URL ?? "https://demo.docusign.net/restapi";
const WP_API_KEY = process.env.WRITERSPROOF_API_KEY ?? "";
const CONNECT_HMAC_KEY = process.env.CONNECT_HMAC_KEY ?? "";

// Derive auth server hostname from DS_BASE_URL
const dsAuthBase = DS_BASE_URL.includes("demo.docusign")
	? "https://account-d.docusign.com"
	: "https://account.docusign.com";

// Token cache
let cachedToken: string | null = null;
let tokenExpiresAt = 0;

async function getAccessToken(): Promise<string> {
	const now = Date.now();
	if (cachedToken && now < tokenExpiresAt - 60_000) {
		return cachedToken;
	}

	if (!INTEGRATION_KEY || !USER_ID || !RSA_PRIVATE_KEY) {
		throw new Error(
			"DocuSign JWT auth requires DOCUSIGN_INTEGRATION_KEY, DOCUSIGN_USER_ID, and DOCUSIGN_RSA_PRIVATE_KEY",
		);
	}

	const privateKey = await jose.importPKCS8(RSA_PRIVATE_KEY, "RS256");
	const jwt = await new jose.SignJWT({ scope: "signature impersonation" })
		.setProtectedHeader({ alg: "RS256" })
		.setIssuer(INTEGRATION_KEY)
		.setSubject(USER_ID)
		.setAudience(dsAuthBase.replace("https://", ""))
		.setIssuedAt()
		.setExpirationTime("1h")
		.sign(privateKey);

	const resp = await fetch(`${dsAuthBase}/oauth/token`, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
	});

	if (!resp.ok) {
		const text = await resp.text().catch(() => resp.statusText);
		throw new Error(
			`DocuSign token exchange failed ${resp.status}: ${text}`,
		);
	}

	const data = (await resp.json()) as {
		access_token: string;
		expires_in?: number;
	};
	cachedToken = data.access_token;
	tokenExpiresAt = now + (data.expires_in ?? 3600) * 1000;
	return cachedToken;
}

const wpClient = new WritersProofClient(WP_API_KEY, "docusign");
const monitor = new ContentMonitor(getAccessToken, ACCOUNT_ID, DS_BASE_URL);

// Map envelopeId -> evidence sessionId for the status endpoint
const evidenceIndex = new Map<string, string>();

const app = express();

// Collect raw body for Connect HMAC verification before JSON parsing
app.use(
	"/webhooks/docusign",
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
		service: "cpoe-docusign",
		timestamp: new Date().toISOString(),
	});
});

app.get("/api/status", (_req: Request, res: Response) => {
	res.json({
		service: "cpoe-docusign",
		activeSessions: evidenceIndex.size,
		dsBaseUrl: DS_BASE_URL,
		timestamp: new Date().toISOString(),
	});
});

app.get("/api/evidence/:envelopeId", async (req: Request, res: Response) => {
	const { envelopeId } = req.params;
	const sessionId = evidenceIndex.get(envelopeId);
	if (!sessionId) {
		res.status(404).json({
			error: "No evidence session found for this envelope",
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

app.get("/oauth/authorize", (_req: Request, res: Response) => {
	if (!INTEGRATION_KEY) {
		res.status(500).json({
			error: "DOCUSIGN_INTEGRATION_KEY not configured",
		});
		return;
	}
	const redirectUri = encodeURIComponent(
		`${process.env.APP_BASE_URL ?? `http://localhost:${PORT}`}/oauth/callback`,
	);
	const url =
		`${dsAuthBase}/oauth/auth` +
		`?response_type=code` +
		`&scope=signature+impersonation` +
		`&client_id=${encodeURIComponent(INTEGRATION_KEY)}` +
		`&redirect_uri=${redirectUri}`;
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
		const credentials = Buffer.from(
			`${INTEGRATION_KEY}:${process.env.DOCUSIGN_CLIENT_SECRET ?? ""}`,
		).toString("base64");
		const resp = await fetch(`${dsAuthBase}/oauth/token`, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Authorization: `Basic ${credentials}`,
			},
			body: `grant_type=authorization_code&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(redirectUri)}`,
		});
		if (!resp.ok) {
			const text = await resp.text().catch(() => resp.statusText);
			res.status(502).json({ error: `Token exchange failed: ${text}` });
			return;
		}
		const tokens = (await resp.json()) as Record<string, unknown>;
		// Strip sensitive fields before returning to the client.
		delete tokens["access_token"];
		delete tokens["refresh_token"];
		res.json({ message: "Authorization successful", tokens });
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		res.status(500).json({ error: msg });
	}
});

app.post("/webhooks/docusign", async (req: Request, res: Response) => {
	const rawReq = req as Request & { rawBody?: Buffer };
	const rawBody = rawReq.rawBody;

	if (!rawBody) {
		res.status(400).json({ error: "Empty body" });
		return;
	}

	const signature = req.headers["x-docusign-signature-1"] as
		| string
		| undefined;
	if (CONNECT_HMAC_KEY && signature) {
		const keys = [
			CONNECT_HMAC_KEY,
			...(process.env.CONNECT_HMAC_KEY_2
				? [process.env.CONNECT_HMAC_KEY_2]
				: []),
		];
		const valid = verifyConnectSignature(rawBody, signature, keys);
		if (!valid) {
			res.status(401).json({ error: "Invalid Connect signature" });
			return;
		}
	}

	const payload = parseConnectPayload(req.body);
	if (!payload) {
		res.status(400).json({ error: "Unrecognized payload structure" });
		return;
	}

	res.status(202).json({ accepted: true });

	setImmediate(() => {
		handleEnvelopeEvent(payload, wpClient, monitor).catch((err) => {
			const detail = err instanceof Error ? err.message : String(err);
			process.stderr.write(
				`[cpoe-docusign] webhook processing failed for ${payload.envelopeId}: ${detail}\n`,
			);
		});
	});
});

app.listen(PORT, () => {
	process.stdout.write(`cpoe-docusign listening on port ${PORT}\n`);
});

export default app;
