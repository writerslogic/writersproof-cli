/**
 * CPoE Browser Extension — Popup Script
 */

const WRITERSPROOF_URL = "https://writersproof.com";
const SUPABASE_URL = "https://auth.writerslogic.com";
const SUPABASE_ANON_KEY = "sb_publishable_wwoWB3FOs0qIJEDiLhTjOg_MhwFNTYT";

const elements = {
	modeBadge: document.getElementById("mode-badge"),
	connectionBadge: document.getElementById("connection-badge"),
	btnAccount: document.getElementById("btn-account"),
	accountAvatar: document.getElementById("account-avatar"),
	accountSection: document.getElementById("account-section"),
	accountSignedIn: document.getElementById("account-signed-in"),
	accountSignedOut: document.getElementById("account-signed-out"),
	accountName: document.getElementById("account-name"),
	accountEmail: document.getElementById("account-email"),
	btnSignin: document.getElementById("btn-signin"),
	btnSignout: document.getElementById("btn-signout"),
	welcome: document.getElementById("welcome"),
	welcomeDismiss: document.getElementById("welcome-dismiss"),
	standaloneNotice: document.getElementById("standalone-notice"),
	desktopNotice: document.getElementById("desktop-notice"),
	exportGroup: document.getElementById("export-group"),
	btnExport: document.getElementById("btn-export"),
	btnExportHtml: document.getElementById("btn-export-html"),
	noSession: document.getElementById("no-session"),
	activeSession: document.getElementById("active-session"),
	sessionSummary: document.getElementById("session-summary"),
	summaryCheckpoints: document.getElementById("summary-checkpoints"),
	summaryDuration: document.getElementById("summary-duration"),
	summaryEvidenceNote: document.getElementById("summary-evidence-note"),
	sessionTitle: document.getElementById("session-title"),
	checkpointCount: document.getElementById("checkpoint-count"),
	charCount: document.getElementById("char-count"),
	btnStart: document.getElementById("btn-start"),
	btnStop: document.getElementById("btn-stop"),
	totalFiles: document.getElementById("total-files"),
	totalCheckpoints: document.getElementById("total-checkpoints"),
	errorBanner: document.getElementById("error-banner"),
	errorMessage: document.getElementById("error-message"),
	errorDismiss: document.getElementById("error-dismiss"),
	openOptions: document.getElementById("open-options"),
	viewHistory: document.getElementById("view-history"),
};

let currentMode = "detecting";
let sessionStartTime = null;
let lastCheckpointCount = 0;
let durationTimer = null;
let jitterBatchCount = 0;

function startDurationTimer() {
	stopDurationTimer();
	const durationEl = document.getElementById("session-duration");
	if (!durationEl) return;
	durationTimer = setInterval(() => {
		if (!sessionStartTime) return;
		const elapsed = Math.floor((Date.now() - sessionStartTime) / 1000);
		const h = Math.floor(elapsed / 3600);
		const m = Math.floor((elapsed % 3600) / 60);
		const s = elapsed % 60;
		durationEl.textContent =
			h > 0
				? `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`
				: `${m}:${String(s).padStart(2, "0")}`;
	}, 1000);
}

function stopDurationTimer() {
	if (durationTimer) {
		clearInterval(durationTimer);
		durationTimer = null;
	}
}

function computeLiveScore(checkpoints, jitterBatches, durationMs) {
	let score = 0;

	// Match standalone.js computeEvidenceQuality weights exactly
	if (checkpoints >= 20) score += 25;
	else if (checkpoints >= 5) score += 15;
	else if (checkpoints >= 1) score += 5;

	if (jitterBatches >= 10) score += 25;
	else if (jitterBatches >= 3) score += 15;
	else if (jitterBatches >= 1) score += 5;

	const durationMin = (durationMs || 0) / 60000;
	if (durationMin >= 30) score += 15;
	else if (durationMin >= 5) score += 10;
	else if (durationMin >= 1) score += 5;

	// Chain integrity assumed verified during live session
	if (checkpoints >= 1) score += 20;

	// Delta consistency placeholder — can't compute live without full checkpoint list
	if (checkpoints >= 3) score += 15;

	return Math.min(score, 100);
}

function updateEvidenceMeter(checkpoints, jitterBatches, durationMs) {
	const fill = document.getElementById("evidence-fill");
	const label = document.getElementById("evidence-label");
	if (!fill || !label) return;

	const score = computeLiveScore(checkpoints, jitterBatches, durationMs);

	fill.style.width = score + "%";
	fill.className = "meter-fill";
	if (score >= 80) {
		fill.classList.add("strong");
		label.textContent = "Strong";
	} else if (score >= 50) {
		fill.classList.add("moderate");
		label.textContent = "Moderate";
	} else if (score >= 25) {
		fill.classList.add("weak");
		label.textContent = "Building...";
	} else {
		label.textContent = "Gathering...";
	}
}

function updateUI(state) {
	const isStandalone = state.mode === "standalone";
	currentMode = state.mode || currentMode;

	// Mode and connection badges
	if (isStandalone) {
		elements.modeBadge.textContent = "Standalone";
		elements.modeBadge.className = "badge standalone";
		elements.connectionBadge.textContent = "Browser-only";
		elements.connectionBadge.className = "badge standalone";
	} else if (state.connected) {
		elements.modeBadge.textContent = "Desktop";
		elements.modeBadge.className = "badge connected";
		if (state.secureChannelFailed) {
			elements.connectionBadge.textContent = "Plaintext";
			elements.connectionBadge.className = "badge degraded";
		} else {
			elements.connectionBadge.textContent = "Connected";
			elements.connectionBadge.className = "badge connected";
		}
	} else if (currentMode === "detecting") {
		elements.modeBadge.textContent = "";
		elements.connectionBadge.textContent = "Detecting...";
		elements.connectionBadge.className = "badge";
	} else {
		elements.modeBadge.textContent = "";
		elements.connectionBadge.textContent = "Disconnected";
		elements.connectionBadge.className = "badge disconnected";
	}

	// Mode-specific notices
	elements.standaloneNotice.hidden = !isStandalone;
	elements.desktopNotice.hidden = !(
		state.connected &&
		!isStandalone &&
		currentMode !== "detecting"
	);

	// Export buttons: standalone mode with an active or recent session
	elements.exportGroup.hidden =
		!isStandalone || (!state.activeSession && !state.hasExportableSession);

	if (state.activeSession) {
		elements.noSession.hidden = true;
		elements.activeSession.hidden = false;
		elements.sessionSummary.hidden = true;
		elements.welcome.hidden = true;
		elements.btnStart.hidden = true;
		elements.btnStop.hidden = false;
		elements.sessionTitle.textContent =
			state.documentTitle || "Untitled document";
		elements.checkpointCount.textContent = state.checkpointCount || "0";
		elements.charCount.textContent = formatNumber(state.charCount || 0);
		lastCheckpointCount = state.checkpointCount || 0;
		if (!sessionStartTime) {
			chrome.storage.local.get("_sessionStartTime", (r) => {
				sessionStartTime = r._sessionStartTime || Date.now();
				startDurationTimer();
				updateEvidenceMeter(
					lastCheckpointCount,
					jitterBatchCount,
					Date.now() - sessionStartTime,
				);
			});
		} else {
			startDurationTimer();
		}
		// Mark first session seen
		chrome.storage.local.set({ _hasUsedExtension: true });
	} else {
		stopDurationTimer();
		jitterBatchCount = 0;
		elements.activeSession.hidden = true;
		elements.btnStart.hidden = false;
		elements.btnStop.hidden = true;

		// Show summary if we just stopped a session
		if (state.showSummary && lastCheckpointCount > 0) {
			elements.noSession.hidden = true;
			elements.sessionSummary.hidden = false;
			elements.summaryCheckpoints.textContent =
				lastCheckpointCount +
				(lastCheckpointCount === 1 ? " checkpoint" : " checkpoints");
			const durationMin = sessionStartTime
				? Math.max(
						1,
						Math.round((Date.now() - sessionStartTime) / 60000),
					)
				: 0;
			elements.summaryDuration.textContent = durationMin + " min";
			elements.summaryEvidenceNote.textContent = isStandalone
				? "Browser-based attestation stored locally. Export JSON or install the desktop app for hardware-backed attestation."
				: "Evidence anchored with hardware attestation and VDF time-proofs.";
			sessionStartTime = null;
			lastCheckpointCount = 0;
		} else if (!state.showSummary) {
			elements.noSession.hidden = false;
			elements.sessionSummary.hidden = true;
		}
	}

	if (state.trackedFiles !== undefined) {
		elements.totalFiles.textContent = state.trackedFiles;
	}
	if (state.totalCheckpoints !== undefined) {
		elements.totalCheckpoints.textContent = formatNumber(
			state.totalCheckpoints,
		);
	}
}

function showError(message) {
	let safe = typeof message === "string" ? message : "Unknown error";
	safe = safe.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
	if (safe.length > 200) {
		safe = safe.slice(0, 200) + "\u2026";
	}
	elements.errorMessage.textContent = safe || "Unknown error";
	elements.errorBanner.hidden = false;
}

function hideError() {
	elements.errorBanner.hidden = true;
}

function formatNumber(n) {
	if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
	if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
	return String(n);
}

function escHtml(str) {
	if (typeof str !== "string") return "";
	return str
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
}

function generateHTMLReport(evidence) {
	const session = evidence.session;
	const checkpoints = evidence.checkpoints || [];
	const startDate = session.startedAt
		? new Date(session.startedAt).toLocaleString()
		: "Unknown";
	const endDate = session.endedAt
		? new Date(session.endedAt).toLocaleString()
		: "Ongoing";
	const durationMs =
		(session.endedAt || Date.now()) - (session.startedAt || Date.now());
	const durationMin = Math.max(1, Math.round(durationMs / 60000));
	const lastCharCount =
		checkpoints.length > 0
			? checkpoints[checkpoints.length - 1].charCount
			: 0;
	const chainStatus =
		evidence.chainIntegrity === "verified"
			? '<span style="color:#66bb6a;font-weight:600">Verified</span>'
			: '<span style="color:#ef5350;font-weight:600">Broken</span>';

	const qualityGrade = evidence.evidenceQuality?.grade || "unknown";
	const qualityScore = evidence.evidenceQuality?.score || 0;
	const qualityColors = {
		strong: "#66bb6a",
		moderate: "#ffa726",
		weak: "#ef5350",
		insufficient: "#ef5350",
		unknown: "#8892a8",
	};
	const qualityColor = qualityColors[qualityGrade] || qualityColors.unknown;
	const qualityLabel = `<span style="color:${qualityColor};font-weight:600">${escHtml(qualityGrade.charAt(0).toUpperCase() + qualityGrade.slice(1))} (${qualityScore}/100)</span>`;

	let checkpointRows = "";
	for (const cp of checkpoints) {
		const ts = new Date(cp.timestamp).toLocaleString();
		const hash = cp.checkpointHash
			? cp.checkpointHash.slice(0, 16) + "\u2026"
			: "";
		const deltaStr = cp.delta >= 0 ? "+" + cp.delta : String(cp.delta);
		checkpointRows += `<tr>
      <td>${cp.ordinal}</td>
      <td>${escHtml(ts)}</td>
      <td>${cp.charCount}</td>
      <td>${deltaStr}</td>
      <td><code>${escHtml(hash)}</code></td>
    </tr>`;
	}

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WritersProof Evidence Report</title>
<style>
:root{--bg:#1a1a2e;--surface:#16213e;--border:#2a3a5e;--text:#e0e0e0;--muted:#8892a8;--accent:#4fc3f7;--success:#66bb6a;--danger:#ef5350}
@media(prefers-color-scheme:light){:root{--bg:#f5f5f5;--surface:#fff;--border:#ddd;--text:#222;--muted:#666;--accent:#0277bd;--success:#2e7d32;--danger:#c62828}}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:24px;max-width:900px;margin:0 auto}
h1{font-size:22px;margin-bottom:4px}
h2{font-size:16px;margin:24px 0 12px;color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:6px}
.meta{color:var(--muted);font-size:13px;margin-bottom:24px}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}
.summary-item{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center}
.summary-value{font-size:24px;font-weight:700;color:var(--accent)}
.summary-label{font-size:12px;color:var(--muted);margin-top:2px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:24px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border)}
th{background:var(--surface);color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px}
td code{font-size:12px;color:var(--muted);word-break:break-all}
.trust{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:24px;font-size:13px;color:var(--muted);line-height:1.6}
.trust strong{color:var(--text)}
footer{text-align:center;color:var(--muted);font-size:12px;margin-top:32px;padding-top:16px;border-top:1px solid var(--border)}
footer a{color:var(--accent);text-decoration:none}
footer a:hover{text-decoration:underline}
</style>
</head>
<body>
<h1>WritersProof Evidence Report</h1>
<p class="meta">Exported ${escHtml(new Date().toLocaleString())}</p>

<h2>Document</h2>
<div class="summary">
  <div class="summary-item"><div class="summary-value">${checkpoints.length}</div><div class="summary-label">Checkpoints</div></div>
  <div class="summary-item"><div class="summary-value">${durationMin} min</div><div class="summary-label">Duration</div></div>
  <div class="summary-item"><div class="summary-value">${lastCharCount.toLocaleString()}</div><div class="summary-label">Final Characters</div></div>
  <div class="summary-item"><div class="summary-value">${chainStatus}</div><div class="summary-label">Chain Integrity</div></div>
  <div class="summary-item"><div class="summary-value">${qualityLabel}</div><div class="summary-label">Evidence Strength</div></div>
</div>
<table>
  <tr><td style="color:var(--muted)">Title</td><td>${escHtml(session.title || "Untitled")}</td></tr>
  <tr><td style="color:var(--muted)">URL</td><td>${escHtml(session.url || "")}</td></tr>
  <tr><td style="color:var(--muted)">Started</td><td>${escHtml(startDate)}</td></tr>
  <tr><td style="color:var(--muted)">Ended</td><td>${escHtml(endDate)}</td></tr>
  <tr><td style="color:var(--muted)">Session ID</td><td><code>${escHtml(session.id)}</code></td></tr>
</table>

<h2>Checkpoints</h2>
<table>
  <thead><tr><th>#</th><th>Timestamp</th><th>Characters</th><th>Delta</th><th>Hash</th></tr></thead>
  <tbody>${checkpointRows}</tbody>
</table>

<div class="trust">
  <strong>Trust Level: Browser-based attestation</strong><br>
  SHA-256 hash chain with HMAC integrity and keystroke timing entropy. Each checkpoint is chained to the previous via SHA-256, with jitter binding from keystroke intervals. Session integrity is sealed with HMAC-SHA256 derived from a per-session nonce.<br><br>
  For hardware-backed attestation with Ed25519 signatures, VDF time-proofs, and Secure Enclave binding, install the <a href="https://writerslogic.com/download">WritersProof desktop app</a>.
</div>

<footer>Generated by <a href="https://writerslogic.com">WritersProof</a> &mdash; writerslogic.com</footer>
</body>
</html>`;
}

elements.btnStart.addEventListener("click", async () => {
	try {
		const [tab] = await chrome.tabs.query({
			active: true,
			currentWindow: true,
		});
		if (!tab?.id) return;

		const response = await chrome.tabs.sendMessage(tab.id, {
			action: "start",
		});
		if (response?.ok) {
			sessionStartTime = Date.now();
			updateUI({
				connected: true,
				activeSession: true,
				documentTitle: tab.title,
				mode: currentMode,
			});
		} else {
			showError(response?.error || "Failed to start witnessing");
		}
	} catch (err) {
		showError("Could not start witnessing. Is this a supported page?");
	}
});

elements.btnStop.addEventListener("click", async () => {
	try {
		const [tab] = await chrome.tabs.query({
			active: true,
			currentWindow: true,
		});
		if (tab?.id) {
			const response = await chrome.tabs.sendMessage(tab.id, {
				action: "stop_witnessing",
			});
			if (response && !response.ok) {
				// Non-fatal; content script may have been unloaded
			}
		}
	} catch (err) {
		// Content script not reachable; proceed with background stop
	}
	chrome.runtime.sendMessage({ action: "stop_witnessing" });
	updateUI({
		connected: true,
		activeSession: false,
		mode: currentMode,
		showSummary: true,
		hasExportableSession: currentMode === "standalone",
	});
});

elements.btnExport.addEventListener("click", async () => {
	const resp = await chrome.runtime.sendMessage({
		action: "export_evidence",
	});
	if (resp?.ok && resp.evidence) {
		const blob = new Blob([JSON.stringify(resp.evidence, null, 2)], {
			type: "application/json",
		});
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = `writersproof-evidence-${Date.now()}.json`;
		a.click();
		URL.revokeObjectURL(url);
	} else {
		showError(resp?.error || "Export failed");
	}
});

elements.btnExportHtml.addEventListener("click", async () => {
	const resp = await chrome.runtime.sendMessage({
		action: "export_evidence",
	});
	if (resp?.ok && resp.evidence) {
		const html = generateHTMLReport(resp.evidence);
		const blob = new Blob([html], { type: "text/html" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = `writersproof-report-${Date.now()}.html`;
		a.click();
		URL.revokeObjectURL(url);
	} else {
		showError(resp?.error || "Export failed");
	}
});

elements.errorDismiss.addEventListener("click", hideError);

elements.welcomeDismiss.addEventListener("click", () => {
	elements.welcome.hidden = true;
	chrome.storage.local.set({ _hasUsedExtension: true });
});

elements.openOptions.addEventListener("click", (e) => {
	e.preventDefault();
	chrome.runtime.openOptionsPage();
});

elements.viewHistory.addEventListener("click", (e) => {
	e.preventDefault();
	chrome.runtime.sendMessage({
		action: "open_desktop_app",
		view: "versionHistory",
	});
});

chrome.runtime.onMessage.addListener((message) => {
	switch (message.type) {
		case "status_update":
			updateUI({
				connected: true,
				activeSession: message.active_session,
				documentTitle: message.document_title,
				documentUrl: message.document_url,
				checkpointCount: message.checkpoint_count,
				trackedFiles: message.tracked_files,
				totalCheckpoints: message.total_checkpoints,
				mode: message.mode,
			});
			break;

		case "session_update":
			if (message.active === false) {
				updateUI({
					connected: true,
					activeSession: false,
					mode: message.mode,
				});
				if (
					message.evidence_quality &&
					!elements.sessionSummary.hidden
				) {
					const qualityLabel =
						message.evidence_quality === "human_plausible"
							? "Human typing patterns confirmed."
							: message.evidence_quality === "low_variance"
								? "Low typing variance detected."
								: "Atypical typing patterns detected — evidence may be flagged.";
					elements.summaryEvidenceNote.textContent =
						elements.summaryEvidenceNote.textContent +
						" " +
						qualityLabel;
				}
			} else {
				updateUI({
					connected: true,
					activeSession: true,
					documentTitle: message.document_title,
					checkpointCount: message.checkpoint_count,
					mode: message.mode,
				});
			}
			break;

		case "checkpoint_update":
			elements.checkpointCount.textContent =
				message.checkpoint_count || "0";
			lastCheckpointCount = message.checkpoint_count || 0;
			if (message.charCount !== undefined) {
				elements.charCount.textContent = formatNumber(
					message.charCount,
				);
			}
			if (message.keystrokeCount) {
				jitterBatchCount++;
			}
			updateEvidenceMeter(
				lastCheckpointCount,
				jitterBatchCount,
				sessionStartTime ? Date.now() - sessionStartTime : 0,
			);
			break;

		case "connection_status":
			if (message.reconnecting) {
				elements.connectionBadge.textContent = `Reconnecting (${message.attempt || ""}/${message.maxAttempts || ""})`;
				elements.connectionBadge.className = "badge disconnected";
			} else if (message.connected) {
				elements.connectionBadge.textContent = "Connected";
				elements.connectionBadge.className = "badge connected";
			}
			if (message.message) {
				showError(message.message);
			}
			break;

		case "secure_channel_degraded":
			elements.connectionBadge.textContent = "Plaintext";
			elements.connectionBadge.className = "badge degraded";
			if (message.message) {
				showError(message.message);
			}
			break;

		case "error":
			showError(message.message);
			break;
	}
});

async function init() {
	let response = await chrome.runtime.sendMessage({
		action: "popup_connect",
	});

	// Retry once if background is still initializing
	if (!response || response.mode === "detecting") {
		await new Promise((r) => setTimeout(r, 300));
		response = await chrome.runtime.sendMessage({
			action: "popup_connect",
		});
	}

	currentMode = response?.mode || "detecting";

	updateUI({
		connected: response?.connected || false,
		activeSession: false,
		mode: currentMode,
		secureChannelFailed: response?.secureChannelFailed || false,
	});

	// Show welcome card on first use
	const { _hasUsedExtension } =
		await chrome.storage.local.get("_hasUsedExtension");
	if (!_hasUsedExtension) {
		elements.welcome.hidden = false;
	}

	try {
		const [tab] = await chrome.tabs.query({
			active: true,
			currentWindow: true,
		});
		if (tab?.id) {
			const pageInfo = await chrome.tabs.sendMessage(tab.id, {
				action: "get_page_info",
			});
			if (pageInfo?.ok && pageInfo.isWitnessing) {
				elements.welcome.hidden = true;
				updateUI({
					connected: response?.connected || false,
					activeSession: true,
					documentTitle: pageInfo.title,
					charCount: pageInfo.charCount,
					mode: currentMode,
				});
			}

			if (!pageInfo?.ok || !pageInfo.site) {
				elements.btnStart.disabled = true;
				elements.btnStart.title =
					"Navigate to a supported document editor";
			}
		}
	} catch {
		elements.btnStart.disabled = true;
		elements.btnStart.title = "Navigate to a supported document editor";
	}
}

const versionEl = document.getElementById("ext-version");
if (versionEl) {
	versionEl.textContent = `v${chrome.runtime.getManifest().version}`;
}

// --- Account ---

let accountVisible = false;

function updateAccountUI(session) {
	if (session?.user) {
		const name =
			session.user.user_metadata?.full_name ||
			session.user.email?.split("@")[0] ||
			"User";
		const email = session.user.email || "";
		const initials = name.charAt(0).toUpperCase();
		elements.accountAvatar.textContent = initials;
		elements.accountAvatar.classList.remove("signed-out");
		elements.accountName.textContent = name;
		elements.accountEmail.textContent = email;
		elements.accountSignedIn.hidden = false;
		elements.accountSignedOut.hidden = true;
	} else {
		elements.accountAvatar.textContent = "?";
		elements.accountAvatar.classList.add("signed-out");
		elements.accountSignedIn.hidden = true;
		elements.accountSignedOut.hidden = false;
	}
}

async function loadSession() {
	const { _wpSession } = await chrome.storage.local.get("_wpSession");
	if (!_wpSession?.access_token) {
		updateAccountUI(null);
		return null;
	}
	try {
		const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
			headers: {
				Authorization: `Bearer ${_wpSession.access_token}`,
				apikey: SUPABASE_ANON_KEY,
			},
		});
		if (res.ok) {
			const user = await res.json();
			updateAccountUI({ user });
			return { user, access_token: _wpSession.access_token };
		}
		if (res.status === 401 && _wpSession.refresh_token) {
			const refreshed = await refreshSession(_wpSession.refresh_token);
			if (refreshed) return refreshed;
		}
	} catch {
		/* network error — show signed out */
	}
	await chrome.storage.local.remove("_wpSession");
	updateAccountUI(null);
	return null;
}

async function refreshSession(refreshToken) {
	try {
		const res = await fetch(
			`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`,
			{
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					apikey: SUPABASE_ANON_KEY,
				},
				body: JSON.stringify({ refresh_token: refreshToken }),
			},
		);
		if (!res.ok) return null;
		const data = await res.json();
		const session = {
			access_token: data.access_token,
			refresh_token: data.refresh_token,
			expires_at: Date.now() + (data.expires_in || 3600) * 1000,
		};
		await chrome.storage.local.set({ _wpSession: session });
		const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
			headers: {
				Authorization: `Bearer ${session.access_token}`,
				apikey: SUPABASE_ANON_KEY,
			},
		});
		if (userRes.ok) {
			const user = await userRes.json();
			updateAccountUI({ user });
			return { user, access_token: session.access_token };
		}
	} catch {
		/* ignore */
	}
	return null;
}

elements.btnAccount.addEventListener("click", () => {
	accountVisible = !accountVisible;
	elements.accountSection.hidden = !accountVisible;
});

elements.btnSignin.addEventListener("click", async () => {
	elements.btnSignin.disabled = true;
	elements.btnSignin.textContent = "Signing in\u2026";
	try {
		const redirectUrl = chrome.identity.getRedirectURL("callback");
		const authUrl =
			`${SUPABASE_URL}/auth/v1/authorize?provider=google` +
			`&redirect_to=${encodeURIComponent(redirectUrl)}`;
		const responseUrl = await chrome.identity.launchWebAuthFlow({
			url: authUrl,
			interactive: true,
		});
		if (responseUrl) {
			const hash = new URL(responseUrl).hash.substring(1);
			const params = new URLSearchParams(hash);
			const accessToken = params.get("access_token");
			const refreshToken = params.get("refresh_token");
			const expiresIn = parseInt(params.get("expires_in") || "3600", 10);
			if (accessToken) {
				const session = {
					access_token: accessToken,
					refresh_token: refreshToken || null,
					expires_at: Date.now() + expiresIn * 1000,
				};
				await chrome.storage.local.set({ _wpSession: session });
				await loadSession();
			}
		}
	} catch (err) {
		if (!err?.message?.includes("canceled")) {
			showError("Sign-in failed. Please try again.");
		}
	} finally {
		elements.btnSignin.disabled = false;
		elements.btnSignin.textContent = "Sign in to WritersProof";
	}
});

elements.btnSignout.addEventListener("click", async () => {
	await chrome.storage.local.remove("_wpSession");
	updateAccountUI(null);
});

loadSession();
init();
