// SPDX-License-Identifier: AGPL-3.0-only
// WritersProof Blackboard Learn — Express server entry point

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
	const port = parseInt(process.env["PORT"] ?? "3005", 10);
	const sessionSecret = requireEnv("SESSION_SECRET");
	const wpApiKey = requireEnv("WRITERSPROOF_API_KEY");
	const bbPlatformUrl = requireEnv("BLACKBOARD_PLATFORM_URL");
	const bbClientId = requireEnv("BLACKBOARD_CLIENT_ID");
	const bbClientSecret = requireEnv("BLACKBOARD_CLIENT_SECRET");
	const toolHostUrl = (
		process.env["TOOL_HOST_URL"] ?? `http://localhost:${port}`
	).replace(/\/+$/, "");
	const webhookSecret = process.env["BLACKBOARD_WEBHOOK_SECRET"] ?? "";

	await initializeKeyPair();

	const wpClient = new WritersProofClient(wpApiKey);
	const monitor = new ContentMonitor(
		bbPlatformUrl,
		bbClientId,
		bbClientSecret,
	);

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

	app.use(
		"/webhooks",
		express.raw({ type: "application/json", limit: "1mb" }),
		createWebhookRouter(wpClient, monitor, webhookSecret),
	);

	app.use(express.json({ limit: "1mb" }));
	app.use(express.urlencoded({ extended: false }));

	const ltiRouter = createLtiRouter(bbPlatformUrl, bbClientId, toolHostUrl);
	app.use("/lti", ltiRouter);

	app.get("/.well-known/jwks.json", (req: Request, res: Response) => {
		ltiRouter(
			Object.assign(req, { url: "/jwks", path: "/jwks" }),
			res,
			() => res.status(404).json({ error: "Not found" }),
		);
	});

	app.get("/api/session/status", (req: Request, res: Response) => {
		const ltiCtx = (req.session as Record<string, unknown>)["lti_context"];
		if (!ltiCtx) {
			res.status(401).json({ error: "No active LTI session" });
			return;
		}
		res.json({ active: true, context: ltiCtx });
	});

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

	app.get("/health", (_req: Request, res: Response) => {
		res.json({ status: "ok", platform: "blackboard", version: "1.0.0" });
	});

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
					platform: bbPlatformUrl,
					settings: {
						placements: [
							{
								placement: "assignment",
								message_type: "LtiDeepLinkingRequest",
							},
							{
								placement: "course_tool",
								message_type: "LtiResourceLinkRequest",
							},
						],
					},
				},
			],
			scopes: [
				"https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
				"https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
			],
		});
	});

	// eslint-disable-next-line @typescript-eslint/no-unused-vars
	app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
		process.stderr.write(`[blackboard] Unhandled error: ${err.message}\n`);
		res.status(500).json({ error: "Internal server error" });
	});

	app.listen(port, () => {
		process.stdout.write(
			`[blackboard] WritersProof Blackboard integration listening on port ${port}\n`,
		);
	});
}

main().catch((err: unknown) => {
	const msg = err instanceof Error ? err.message : String(err);
	process.stderr.write(`[blackboard] Fatal startup error: ${msg}\n`);
	process.exit(1);
});
