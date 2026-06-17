// SPDX-License-Identifier: AGPL-3.0-only
// WritersProof Canvas LMS — LTI 1.3 OIDC launch handler

import { Router, Request, Response } from "express";
import {
	createRemoteJWKSet,
	jwtVerify,
	SignJWT,
	generateKeyPair,
	exportJWK,
} from "jose";
import { randomBytes, createHash } from "crypto";

// Configurable for self-hosted Canvas instances via environment variable.
const CANVAS_ISSUER =
	process.env.CANVAS_ISSUER || "https://canvas.instructure.com";

// LTI 1.3 claim URIs
const CLAIM_ROLES = "https://purl.imsglobal.org/spec/lti/claim/roles";
const CLAIM_RESOURCE_LINK =
	"https://purl.imsglobal.org/spec/lti/claim/resource_link";
const CLAIM_CONTEXT = "https://purl.imsglobal.org/spec/lti/claim/context";
const CLAIM_CUSTOM = "https://purl.imsglobal.org/spec/lti/claim/custom";
const CLAIM_DEEP_LINKING =
	"https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings";
const CLAIM_MESSAGE_TYPE =
	"https://purl.imsglobal.org/spec/lti/claim/message_type";
const CLAIM_DEPLOYMENT_ID =
	"https://purl.imsglobal.org/spec/lti/claim/deployment_id";

const ROLE_STUDENT =
	"http://purl.imsglobal.org/vocab/lis/v2/membership#Learner";
const ROLE_INSTRUCTOR =
	"http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor";

// Nonce store: maps nonce → expiry timestamp. Entries expire after 10 minutes.
// In production, back with Redis or a shared database.
const nonceStore = new Map<string, number>();
const NONCE_TTL_MS = 10 * 60 * 1000;
const NONCE_MAX_SIZE = 10000;
let nonceStoreCounter = 0;
const NONCE_CLEANUP_INTERVAL = 100;

function generateNonce(): string {
	return randomBytes(32).toString("base64url");
}

function storeNonce(nonce: string): void {
	nonceStoreCounter++;
	if (
		nonceStoreCounter % NONCE_CLEANUP_INTERVAL === 0 ||
		nonceStore.size >= NONCE_MAX_SIZE
	) {
		const now = Date.now();
		for (const [key, expiry] of nonceStore) {
			if (expiry < now) nonceStore.delete(key);
		}
	}
	if (nonceStore.size >= NONCE_MAX_SIZE) return;
	nonceStore.set(nonce, Date.now() + NONCE_TTL_MS);
}

function consumeNonce(nonce: string): boolean {
	const expiry = nonceStore.get(nonce);
	if (expiry === undefined || expiry < Date.now()) {
		nonceStore.delete(nonce);
		return false;
	}
	nonceStore.delete(nonce);
	return true;
}

function sha256Hex(input: string): string {
	return createHash("sha256").update(input, "utf8").digest("hex");
}

export interface LtiLaunchContext {
	userId: string;
	roles: string[];
	isStudent: boolean;
	isInstructor: boolean;
	courseId: string;
	courseName: string;
	resourceLinkId: string;
	assignmentTitle: string;
	custom: Record<string, string>;
	deploymentId: string;
	messageType: string;
	deepLinkingSettings: Record<string, unknown> | null;
}

// Key pair generated at startup; persisted in memory only. In production,
// load from environment / secrets manager so JWKS is stable across restarts.
let toolPublicKey: unknown = null;
let toolPrivateKey: unknown = null;
let toolKeyId = "";

export async function initializeKeyPair(): Promise<void> {
	const { publicKey, privateKey } = await generateKeyPair("RS256");
	toolPublicKey = publicKey;
	toolPrivateKey = privateKey;
	toolKeyId = randomBytes(8).toString("hex");
}

export function createLtiRouter(
	canvasPlatformUrl: string,
	canvasClientId: string,
	toolHostUrl: string,
): Router {
	const router = Router();

	// Canvas JWKS URI for validating id_token signatures.
	const canvasJwksUrl = new URL("/api/lti/security/jwks", canvasPlatformUrl);
	const JWKS = createRemoteJWKSet(canvasJwksUrl);

	// GET /lti/login — OIDC initiation endpoint (step 1 of LTI 1.3 launch)
	router.get("/login", (req: Request, res: Response) => {
		const {
			iss,
			login_hint,
			target_link_uri,
			lti_message_hint,
			client_id,
		} = req.query as Record<string, string>;

		if (!iss || !login_hint || !target_link_uri) {
			res.status(400).json({
				error: "Missing required OIDC parameters: iss, login_hint, target_link_uri",
			});
			return;
		}

		if (iss !== CANVAS_ISSUER && iss !== canvasPlatformUrl) {
			res.status(400).json({ error: "Unexpected issuer" });
			return;
		}

		if (client_id && client_id !== canvasClientId) {
			res.status(400).json({ error: "client_id mismatch" });
			return;
		}

		const nonce = generateNonce();
		const state = generateNonce();
		storeNonce(nonce);

		// Store state in session for CSRF validation at /launch.
		const session = req.session as Record<string, unknown>;
		session["lti_state"] = state;
		session["lti_nonce"] = nonce;

		const authUrl = new URL(
			"/api/lti/authorize/redirect",
			canvasPlatformUrl,
		);
		authUrl.searchParams.set("response_type", "id_token");
		authUrl.searchParams.set("response_mode", "form_post");
		authUrl.searchParams.set("scope", "openid");
		authUrl.searchParams.set("client_id", canvasClientId);
		authUrl.searchParams.set("redirect_uri", `${toolHostUrl}/lti/launch`);
		authUrl.searchParams.set("login_hint", login_hint);
		authUrl.searchParams.set("nonce", nonce);
		authUrl.searchParams.set("state", state);
		authUrl.searchParams.set("prompt", "none");
		if (lti_message_hint) {
			authUrl.searchParams.set("lti_message_hint", lti_message_hint);
		}

		res.redirect(authUrl.toString());
	});

	// POST /lti/launch — id_token validation and session creation (step 2)
	router.post("/launch", async (req: Request, res: Response) => {
		try {
			const { id_token, state } = req.body as Record<string, string>;

			if (!id_token || !state) {
				res.status(400).json({ error: "Missing id_token or state" });
				return;
			}

			const session = req.session as Record<string, unknown>;

			// CSRF: validate state matches what was set in /login.
			if (state !== session["lti_state"]) {
				res.status(403).json({
					error: "State mismatch — possible CSRF",
				});
				return;
			}

			// Validate the JWT signature using Canvas's public JWKS.
			const { payload } = await jwtVerify(id_token, JWKS, {
				issuer: CANVAS_ISSUER,
				audience: canvasClientId,
			});

			// Validate and consume the nonce (replay protection).
			const claimedNonce = payload["nonce"] as string | undefined;
			if (!claimedNonce || !consumeNonce(claimedNonce)) {
				res.status(403).json({ error: "Invalid or replayed nonce" });
				return;
			}

			const claims = payload as Record<string, unknown>;
			const roles = (claims[CLAIM_ROLES] as string[] | undefined) ?? [];
			const resourceLink =
				(claims[CLAIM_RESOURCE_LINK] as
					| Record<string, string>
					| undefined) ?? {};
			const context =
				(claims[CLAIM_CONTEXT] as Record<string, string> | undefined) ??
				{};
			const custom =
				(claims[CLAIM_CUSTOM] as Record<string, string> | undefined) ??
				{};
			const deepLinkingSettings =
				(claims[CLAIM_DEEP_LINKING] as Record<
					string,
					unknown
				> | null) ?? null;

			const ltiContext: LtiLaunchContext = {
				userId: String(claims["sub"] ?? ""),
				roles,
				isStudent: roles.some(
					(r) => r === ROLE_STUDENT || r.includes("Learner"),
				),
				isInstructor: roles.some(
					(r) => r === ROLE_INSTRUCTOR || r.includes("Instructor"),
				),
				courseId: context["id"] ?? "",
				courseName: context["title"] ?? "",
				resourceLinkId: resourceLink["id"] ?? "",
				assignmentTitle: resourceLink["title"] ?? "",
				custom,
				deploymentId: String(claims[CLAIM_DEPLOYMENT_ID] ?? ""),
				messageType: String(
					claims[CLAIM_MESSAGE_TYPE] ?? "LtiResourceLinkRequest",
				),
				deepLinkingSettings,
			};

			// Persist launch context in session for downstream routes.
			session["lti_context"] = ltiContext;
			delete session["lti_state"];
			delete session["lti_nonce"];

			// Render embedded tool UI.
			res.send(renderToolHtml(ltiContext, toolHostUrl));
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			res.status(403).json({
				error: `LTI launch validation failed: ${msg}`,
			});
		}
	});

	// POST /lti/deep-linking — return a content item to Canvas
	router.post("/deep-linking", async (req: Request, res: Response) => {
		try {
			const session = req.session as Record<string, unknown>;
			const ctx = session["lti_context"] as LtiLaunchContext | undefined;
			if (!ctx || !ctx.deepLinkingSettings) {
				res.status(403).json({
					error: "No active deep-linking session",
				});
				return;
			}

			const settings = ctx.deepLinkingSettings;
			const returnUrl = String(settings["deep_link_return_url"] ?? "");
			if (!returnUrl) {
				res.status(400).json({
					error: "deep_link_return_url missing from LTI claims",
				});
				return;
			}

			if (!toolPrivateKey) {
				res.status(500).json({
					error: "Tool key pair not initialized",
				});
				return;
			}

			const contentItems = [
				{
					type: "ltiResourceLink",
					title: "WritersProof Authorship Attestation",
					url: `${toolHostUrl}/lti/launch`,
					custom: {
						context_id: ctx.courseId,
						resource_link_id: ctx.resourceLinkId,
					},
				},
			];

			const now = Math.floor(Date.now() / 1000);
			const jwt = await new SignJWT({
				"https://purl.imsglobal.org/spec/lti/claim/message_type":
					"LtiDeepLinkingResponse",
				"https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
				"https://purl.imsglobal.org/spec/lti/claim/deployment_id":
					ctx.deploymentId,
				"https://purl.imsglobal.org/spec/lti-dl/claim/content_items":
					contentItems,
				"https://purl.imsglobal.org/spec/lti-dl/claim/data":
					settings["data"] ?? "",
			})
				.setProtectedHeader({ alg: "RS256", kid: toolKeyId })
				.setIssuer(canvasClientId)
				.setAudience(CANVAS_ISSUER)
				.setIssuedAt(now)
				.setExpirationTime(now + 300)
				.sign(toolPrivateKey as Parameters<SignJWT["sign"]>[0]);

			// Auto-submit form back to Canvas.
			res.send(`<!DOCTYPE html>
<html>
<body>
<form id="dl" method="POST" action="${escapeHtml(returnUrl)}">
  <input type="hidden" name="JWT" value="${escapeHtml(jwt)}">
</form>
<script>document.getElementById('dl').submit();</script>
</body>
</html>`);
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			res.status(500).json({ error: `Deep linking failed: ${msg}` });
		}
	});

	// GET /.well-known/jwks.json — expose tool's public key for Canvas to verify deep-linking JWTs
	router.get("/jwks", async (_req: Request, res: Response) => {
		if (!toolPublicKey) {
			res.status(503).json({ error: "Key pair not initialized" });
			return;
		}
		try {
			const jwk = await exportJWK(
				toolPublicKey as Parameters<typeof exportJWK>[0],
			);
			jwk.kid = toolKeyId;
			jwk.alg = "RS256";
			jwk.use = "sig";
			res.json({ keys: [jwk] });
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			res.status(500).json({ error: `JWKS export failed: ${msg}` });
		}
	});

	return router;
}

function escapeHtml(str: string): string {
	return str
		.replace(/&/g, "&amp;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;");
}

function renderToolHtml(ctx: LtiLaunchContext, hostUrl: string): string {
	const role = ctx.isInstructor
		? "Instructor"
		: ctx.isStudent
			? "Student"
			: "Observer";
	const courseIdSafe = escapeHtml(ctx.courseId);
	const resourceLinkIdSafe = escapeHtml(ctx.resourceLinkId);
	const userIdHash = sha256Hex(ctx.userId).substring(0, 16);

	return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WritersProof — Authorship Attestation</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 0; padding: 16px; background: #f9f9f9; }
    .card { background: #fff; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,.1); }
    h1 { font-size: 1.1rem; margin: 0 0 8px; color: #1a1a2e; }
    p { margin: 4px 0; font-size: .875rem; color: #555; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: .75rem;
             background: #e8f4fd; color: #1565c0; font-weight: 600; }
    .status { margin-top: 12px; padding: 10px; background: #f0fdf4; border-radius: 6px;
              font-size: .8rem; color: #166534; }
  </style>
</head>
<body>
  <div class="card">
    <h1>WritersProof Authorship Attestation</h1>
    <p>Role: <span class="badge">${escapeHtml(role)}</span></p>
    <p>Course ID: <code>${courseIdSafe}</code></p>
    <p>Resource: <code>${resourceLinkIdSafe}</code></p>
    <p>User: <code>${escapeHtml(userIdHash)}…</code></p>
    <div class="status">
      Behavioral evidence collection active. Authorship is being cryptographically witnessed.
    </div>
  </div>
  <script>
    // Report session status back to the embedding page.
    window.parent.postMessage({ type: 'writersproof:ready', courseId: '${courseIdSafe}' }, '${escapeHtml(hostUrl)}');
  </script>
</body>
</html>`;
}
