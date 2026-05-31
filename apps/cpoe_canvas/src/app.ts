// SPDX-License-Identifier: AGPL-3.0-only
// WritersProof Canvas LMS — Express server entry point

import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import session from "express-session";

declare module "express-session" {
	interface SessionData {
		[key: string]: unknown;
	}
}
import { createLtiRouter, initializeKeyPair } from "./lti/provider";
import { createWebhookRouter } from "./webhooks/events";
import { WritersProofClient } from "./services/WritersProofClient";
import { ContentMonitor } from "./services/ContentMonitor";

function requireEnv(name: string): string {
	const value = process.env[name];
	if (!value)
		throw new Error(`Missing required environment variable: ${name}`);
	return value;
}

async function main(): Promise<void> {
	const port = parseInt(process.env["PORT"] ?? "3004", 10);
	const sessionSecret = requireEnv("SESSION_SECRET");
	const wpApiKey = requireEnv("WRITERSPROOF_API_KEY");
	const canvasPlatformUrl = requireEnv("CANVAS_PLATFORM_URL");
	const canvasClientId = requireEnv("CANVAS_CLIENT_ID");
	const toolHostUrl = (
		process.env["TOOL_HOST_URL"] ?? `http://localhost:${port}`
	).replace(/\/+$/, "");
	const webhookSecret = process.env["CANVAS_WEBHOOK_SECRET"] ?? "";
	const canvasAccessToken = process.env["CANVAS_ACCESS_TOKEN"] ?? "";

	await initializeKeyPair();

	const wpClient = new WritersProofClient(wpApiKey);
	const monitor = new ContentMonitor(canvasPlatformUrl, canvasAccessToken);

	const app = express();

	app.set("trust proxy", 1);

	app.use(
		session({
			secret: sessionSecret,
			resave: false,
			saveUninitialized: false,
			cookie: {
				httpOnly: true,
				sameSite: "none",
				secure: process.env["NODE_ENV"] === "production",
				maxAge: 60 * 60 * 1000,
			},
		}),
	);

	// Webhook route must receive the raw body for HMAC verification.
	app.use(
		"/webhooks",
		express.raw({ type: "application/json", limit: "1mb" }),
		createWebhookRouter(wpClient, monitor, webhookSecret),
	);

	// All other routes use JSON body parsing.
	app.use(express.json({ limit: "1mb" }));
	app.use(express.urlencoded({ extended: false }));

	// LTI 1.3 routes: /lti/login, /lti/launch, /lti/deep-linking
	const ltiRouter = createLtiRouter(
		canvasPlatformUrl,
		canvasClientId,
		toolHostUrl,
	);
	app.use("/lti", ltiRouter);

	// JWKS endpoint for deep-linking JWT verification by Canvas.
	app.get("/.well-known/jwks.json", (req: Request, res: Response) => {
		ltiRouter(
			Object.assign(req, { url: "/jwks", path: "/jwks" }),
			res,
			() => res.status(404).json({ error: "Not found" }),
		);
	});

	// GET /api/session/status — check if a WritersProof session is active
	app.get("/api/session/status", (req: Request, res: Response) => {
		const ltiCtx = (req.session as Record<string, unknown>)["lti_context"];
		if (!ltiCtx) {
			res.status(401).json({ error: "No active LTI session" });
			return;
		}
		res.json({ active: true, context: ltiCtx });
	});

	// GET /api/evidence/:sessionId — retrieve evidence for a finalized session
	app.get("/api/evidence/:sessionId", async (req: Request, res: Response) => {
		const { sessionId } = req.params;
		if (!sessionId) {
			res.status(400).json({ error: "sessionId is required" });
			return;
		}

		const ltiCtx = (req.session as Record<string, unknown>)["lti_context"];
		if (!ltiCtx) {
			res.status(401).json({ error: "No active LTI session" });
			return;
		}

		try {
			const evidence = await wpClient.getEvidence(sessionId);
			res.json(evidence);
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			res.status(502).json({
				error: `Failed to retrieve evidence: ${msg}`,
			});
		}
	});

	// POST /api/verify — verify a session's evidence
	app.post("/api/verify", async (req: Request, res: Response) => {
		const { sessionId } = req.body as { sessionId?: string };
		if (!sessionId) {
			res.status(400).json({ error: "sessionId is required" });
			return;
		}

		const ltiCtx = (req.session as Record<string, unknown>)["lti_context"];
		if (!ltiCtx) {
			res.status(401).json({ error: "No active LTI session" });
			return;
		}

		try {
			const result = await wpClient.verifyEvidence(sessionId);
			res.json(result);
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			res.status(502).json({ error: `Verification failed: ${msg}` });
		}
	});

	// Health check
	app.get("/health", (_req: Request, res: Response) => {
		res.json({ status: "ok", platform: "canvas", version: "1.0.0" });
	});

	// LTI configuration descriptor (for Canvas tool registration)
	app.get("/lti/config", (_req: Request, res: Response) => {
		res.json({
			title: "WritersProof",
			description:
				"Cryptographic authorship attestation for student submissions",
			oidc_initiation_url: `${toolHostUrl}/lti/login`,
			target_link_uri: `${toolHostUrl}/lti/launch`,
			public_jwk_url: `${toolHostUrl}/.well-known/jwks.json`,
			extensions: [
				{
					platform: "canvas.instructure.com",
					settings: {
						placements: [
							{
								placement: "assignment_edit",
								message_type: "LtiDeepLinkingRequest",
							},
							{
								placement: "assignment_view",
								message_type: "LtiResourceLinkRequest",
							},
							{
								placement: "course_navigation",
								message_type: "LtiResourceLinkRequest",
							},
						],
					},
				},
			],
			scopes: [
				"https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
				"https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
				"https://canvas.instructure.com/lti/public_jwk/scope/update",
			],
		});
	});

	// Unhandled error handler (must have 4 parameters for Express to treat as error middleware)
	// eslint-disable-next-line @typescript-eslint/no-unused-vars
	app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
		process.stderr.write(`[canvas] Unhandled error: ${err.message}\n`);
		res.status(500).json({ error: "Internal server error" });
	});

	app.listen(port, () => {
		process.stdout.write(
			`[canvas] WritersProof Canvas integration listening on port ${port}\n`,
		);
	});
}

main().catch((err: unknown) => {
	const msg = err instanceof Error ? err.message : String(err);
	process.stderr.write(`[canvas] Fatal startup error: ${msg}\n`);
	process.exit(1);
});
