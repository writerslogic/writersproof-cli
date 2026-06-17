/**
 * CPoE Browser Extension — Content Script
 *
 * Monitors document editing in supported web applications.
 * Captures content changes via MutationObserver and keystroke
 * timing (inter-key intervals for SWF jitter binding).
 */

(() => {
	"use strict";

	const SITE_GOOGLE_DOCS = "google-docs";
	const SITE_OVERLEAF = "overleaf";
	const SITE_MEDIUM = "medium";
	const SITE_NOTION = "notion";
	const SITE_GENERIC = "generic";

	// AI tool hostnames for copy-paste attribution tracking.
	// Detecting copies from these sites lets the writer declare AI tool usage
	// as part of their creative control attestation (not punitive).
	const AI_TOOL_HOSTS = {
		"chat.openai.com": "chatgpt",
		"chatgpt.com": "chatgpt",
		"claude.ai": "claude",
		"gemini.google.com": "gemini",
		"copilot.microsoft.com": "copilot",
	};

	// O(1) action lookup instead of Array.includes
	const VALID_CONTENT_ACTIONS = new Set([
		"capture_state",
		"start",
		"stop",
		"stop_witnessing",
		"get_page_info",
	]);

	let isWitnessing = false;
	let lastCharCount = 0;
	let lastContentHash = "";
	let observerRetries = 0;
	let contentTier = "enhanced"; // "core" | "enhanced" | "maximum"
	let pendingPaste = null;
	let keystrokesSinceLastCheckpoint = 0;

	const JITTER_BATCH_SIZE = 50;
	const MIN_CHANGE_THRESHOLD = 5;
	const MAX_OBSERVER_RETRIES = 20;
	const MAX_DOCUMENT_SIZE = 10 * 1024 * 1024;

	// Reuse encoder across all calls to avoid GC pressure
	const textEncoder = new TextEncoder();

	function sendToBackground(msg, attempt) {
		const n = attempt || 0;
		try {
			chrome.runtime.sendMessage(msg).catch((err) => {
				const retriable =
					err?.message?.includes("Could not establish connection") ||
					err?.message?.includes("Receiving end does not exist");
				if (retriable && n < 3) {
					const delay = 500 * Math.pow(2, n);
					setTimeout(() => sendToBackground(msg, n + 1), delay);
				}
			});
		} catch {
			// Extension context invalidated — page needs reload
		}
	}

	// Pre-allocated ring buffer for keystroke timestamps.
	// Avoids dynamic array growth on every keydown event.
	const jitterBuffer = new Float64Array(JITTER_BATCH_SIZE + 1);
	let jitterIndex = 0;

	let timerResolution = 0;
	let cachedEditorElements = null;
	let cachedSiteId = undefined; // undefined = not yet detected
	let detectedWritingTools = { category: "none", host: "" };
	let writingToolsInterval = null;
	let titleObserver = null;
	let editorHealthInterval = null;
	const EDITOR_HEALTH_INTERVAL_MS = 5000;

	function storageKey() {
		return `witnessing_${window.location.origin}${window.location.pathname}`;
	}

	const KNOWN_SITES = {
		"docs.google.com": { id: SITE_GOOGLE_DOCS, pathPrefix: "/document/" },
		"www.overleaf.com": { id: SITE_OVERLEAF, pathPrefix: "/project/" },
		"medium.com": { id: SITE_MEDIUM },
		"notion.so": { id: SITE_NOTION },
		"www.notion.so": { id: SITE_NOTION },
	};

	const GENERIC_DOMAINS = [
		"www.craft.do",
		"coda.io",
		"app.clickup.com",
		"app.nuclino.com",
		"stackedit.io",
		"hackmd.io",
		"hemingwayapp.com",
		"quillbot.com",
		"prosemirror.net",
		"pad.riseup.net",
		"write.as",
		"wordpress.com",
		"ghost.io",
		"substack.com",
		"www.wattpad.com",
		"archiveofourown.org",
		"www.languagetool.org",
		"app.gitbook.com",
		"www.fictionpress.com",
		"www.scribblehub.com",
		"www.royalroad.com",
		"app.grammarly.com",
		"www.prowritingaid.com",
		"www.novelai.net",
		"www.dabblewriter.com",
		"www.atticus.io",
		"www.reedsy.com",
		"www.leanpub.com",
		"www.penana.com",
		"www.quotev.com",
		"docs.zoho.com",
		"www.deepl.com",
		"roamresearch.com",
		"www.remnote.com",
		"www.typeshare.co",
		"www.bearblog.dev",
	];

	let customDomainsList = [];
	let autoDetectEditors = false;

	chrome.storage.local.get(
		["customDomains", "contentTier", "autoDetectEditors"],
		(result) => {
			customDomainsList = result.customDomains || [];
			autoDetectEditors = !!result.autoDetectEditors;
			if (
				result.contentTier === "core" ||
				result.contentTier === "maximum"
			) {
				contentTier = result.contentTier;
			}
		},
	);
	chrome.storage.onChanged.addListener((changes) => {
		if (changes.customDomains) {
			customDomainsList = changes.customDomains.newValue || [];
			cachedSiteId = undefined;
		}
		if (changes.autoDetectEditors) {
			autoDetectEditors = !!changes.autoDetectEditors.newValue;
			cachedSiteId = undefined;
		}
		if (changes.contentTier) {
			const val = changes.contentTier.newValue;
			contentTier =
				val === "core" || val === "maximum" ? val : "enhanced";
		}
	});

	function detectSite() {
		// Cache: hostname never changes within a page lifecycle
		if (cachedSiteId !== undefined) return cachedSiteId;

		const hostname = window.location.hostname;
		const pathname = window.location.pathname;

		const known = KNOWN_SITES[hostname];
		if (known) {
			if (!known.pathPrefix || pathname.startsWith(known.pathPrefix)) {
				cachedSiteId = known.id;
				return cachedSiteId;
			}
		}

		for (const domain of GENERIC_DOMAINS) {
			if (hostname === domain || hostname.endsWith("." + domain)) {
				cachedSiteId = SITE_GENERIC;
				return cachedSiteId;
			}
		}

		for (const domain of customDomainsList) {
			if (domain.startsWith("*.")) {
				const suffix = domain.slice(2);
				if (suffix.split(".").length < 2) continue;
				if (hostname === suffix || hostname.endsWith("." + suffix)) {
					cachedSiteId = SITE_GENERIC;
					return cachedSiteId;
				}
			} else {
				if (hostname === domain) {
					cachedSiteId = SITE_GENERIC;
					return cachedSiteId;
				}
			}
		}

		if (autoDetectEditors && window.location.protocol === "https:") {
			cachedSiteId = SITE_GENERIC;
			return cachedSiteId;
		}

		cachedSiteId = null;
		return cachedSiteId;
	}

	function invalidateEditorCache() {
		cachedEditorElements = null;
	}

	let timerCalibrated = false;

	function calibrateTimer() {
		if (timerCalibrated) return;
		timerCalibrated = true;
		const samples = new Float64Array(10);
		let last = performance.now();
		for (let i = 0; i < 10; i++) {
			let current = performance.now();
			while (current === last) {
				current = performance.now();
			}
			samples[i] = current - last;
			last = current;
		}
		timerResolution = Math.min(...samples);
	}

	function findEditorByHeuristic() {
		const candidates = document.querySelectorAll(
			'[contenteditable="true"], [role="textbox"], [role="document"], textarea',
		);
		let best = null;
		let bestScore = 0;

		for (const el of candidates) {
			if (!el.isConnected || el.offsetHeight < 40) continue;
			if (isSensitiveTarget(el)) continue;

			// Skip elements inside navigation, headers, footers, sidebars
			const container = el.closest(
				"nav, header, footer, aside, [role='banner'], [role='navigation'], " +
					"[role='complementary'], [role='search'], .comments, .sidebar",
			);
			if (container) continue;

			let score = 0;
			const rect = el.getBoundingClientRect();
			const area = rect.width * rect.height;

			// Large visible area suggests primary editor
			if (area > 40000) score += 3;
			else if (area > 10000) score += 2;
			else if (area > 2000) score += 1;

			// Contains text content (not empty placeholder)
			const textLen = (el.textContent || "").trim().length;
			if (textLen > 50) score += 2;
			else if (textLen > 0) score += 1;

			// Editable attributes
			if (el.contentEditable === "true") score += 2;
			if (el.getAttribute("role") === "textbox") score += 1;
			if (el.getAttribute("role") === "document") score += 2;
			if (el.getAttribute("aria-multiline") === "true") score += 1;
			if (el.spellcheck !== false) score += 1;

			// Textarea with significant rows
			if (el.tagName === "TEXTAREA") {
				const rows = parseInt(el.getAttribute("rows"), 10) || 0;
				if (rows >= 5) score += 2;
			}

			if (score > bestScore) {
				bestScore = score;
				best = el;
			}
		}

		return bestScore >= 4 ? best : null;
	}

	function isSensitiveTarget(el) {
		if (el.tagName === "INPUT") return true;
		const type = (el.getAttribute("type") || "").toLowerCase();
		if (type === "password" || type === "email") return true;
		const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
		if (ac.includes("password") || ac.includes("cc-")) return true;
		const ariaLabel = (el.getAttribute("aria-label") || "").toLowerCase();
		if (ariaLabel.includes("password") || ariaLabel.includes("search"))
			return true;
		return false;
	}

	function getEditorElement() {
		if (cachedEditorElements && cachedEditorElements.length > 0) {
			if (cachedEditorElements[0].isConnected) {
				return cachedEditorElements;
			}
			cachedEditorElements = null;
		}

		const site = detectSite();
		let elements;

		switch (site) {
			case SITE_GOOGLE_DOCS: {
				const pages = document.querySelectorAll(".kix-page");
				elements =
					pages.length > 0
						? pages
						: document.querySelectorAll(
								'.kix-appview-editor [contenteditable="true"]',
							);
				break;
			}
			case SITE_OVERLEAF:
				elements = document.querySelectorAll(".cm-content");
				break;
			case SITE_MEDIUM:
				elements = document.querySelectorAll(
					'article [contenteditable="true"], .postArticle [contenteditable="true"], [role="textbox"]',
				);
				break;
			case SITE_NOTION:
				elements = document.querySelectorAll(
					'.notion-page-content [contenteditable="true"]',
				);
				break;
			case SITE_GENERIC:
			default:
				elements = document.querySelectorAll(
					'[contenteditable="true"], .cm-content, .monaco-editor textarea, ' +
						".ProseMirror, .ql-editor, .trix-content, textarea.editor, " +
						'textarea[name="content"], textarea[name="body"]',
				);
		}

		if (elements && elements.length > 0) {
			cachedEditorElements = elements;
			return elements;
		}

		// Fallback: if site-specific selectors failed, try generic framework selectors
		if (site && site !== SITE_GENERIC) {
			elements = document.querySelectorAll(
				'[contenteditable="true"], .cm-content, .monaco-editor textarea, ' +
					".ProseMirror, .ql-editor, .trix-content, textarea.editor, " +
					'textarea[name="content"], textarea[name="body"]',
			);
			if (elements && elements.length > 0) {
				cachedEditorElements = elements;
				return elements;
			}
		}

		// Last resort: heuristic detection for unknown/changed editors
		const candidate = findEditorByHeuristic();
		if (candidate) {
			cachedEditorElements = [candidate];
			return cachedEditorElements;
		}

		return elements;
	}

	function collectText(root, chunks, state) {
		if (state.length >= MAX_DOCUMENT_SIZE) return;

		const walker = document.createTreeWalker(
			root,
			NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT,
		);
		let node;
		while ((node = walker.nextNode())) {
			if (state.length >= MAX_DOCUMENT_SIZE) break;

			if (node.nodeType === Node.ELEMENT_NODE && node.shadowRoot) {
				collectText(node.shadowRoot, chunks, state);
				continue;
			}

			if (node.nodeType !== Node.TEXT_NODE) continue;
			const value = node.nodeValue;
			if (!value) continue;

			const remaining = MAX_DOCUMENT_SIZE - state.length;
			if (remaining <= 0) break;

			if (value.length <= remaining) {
				chunks.push(value);
				state.length += value.length;
			} else {
				chunks.push(value.slice(0, remaining));
				state.length += remaining;
				break;
			}
		}
	}

	function getDocumentText() {
		const elements = getEditorElement();
		if (!elements || elements.length === 0) return "";

		const chunks = [];
		const state = { length: 0 };

		for (const el of elements) {
			if (state.length >= MAX_DOCUMENT_SIZE) break;
			collectText(el, chunks, state);
		}

		return chunks.join("");
	}

	function countText(root, state) {
		if (state.length >= MAX_DOCUMENT_SIZE) return;
		const walker = document.createTreeWalker(
			root,
			NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT,
		);
		let node;
		while ((node = walker.nextNode())) {
			if (state.length >= MAX_DOCUMENT_SIZE) return;
			if (node.nodeType === Node.ELEMENT_NODE && node.shadowRoot) {
				countText(node.shadowRoot, state);
				continue;
			}
			if (node.nodeType !== Node.TEXT_NODE) continue;
			const value = node.nodeValue;
			if (!value) continue;
			state.length += value.length;
		}
	}

	function getDocumentCharCount() {
		const elements = getEditorElement();
		if (!elements || elements.length === 0) return 0;

		const state = { length: 0 };
		for (const el of elements) {
			if (state.length >= MAX_DOCUMENT_SIZE) break;
			countText(el, state);
		}
		return Math.min(state.length, MAX_DOCUMENT_SIZE);
	}

	function getDocumentTitle() {
		const site = detectSite();
		switch (site) {
			case SITE_GOOGLE_DOCS: {
				const titleEl = document.querySelector(
					".docs-title-input input",
				);
				return (
					titleEl?.value ||
					document.title.replace(" - Google Docs", "")
				);
			}
			case SITE_OVERLEAF:
				return document.title.replace(
					" - Overleaf, Online LaTeX Editor",
					"",
				);
			case SITE_MEDIUM:
				return (
					document.querySelector("h3.graf--title")?.textContent ||
					document.title
				);
			case SITE_NOTION:
				return (
					document.querySelector(".notion-page-block .notranslate")
						?.textContent || document.title
				);
			default:
				return document.title;
		}
	}

	// Pre-allocated lookup table for hex encoding (avoids toString(16) per byte)
	const HEX_CHARS = [];
	for (let i = 0; i < 256; i++) {
		HEX_CHARS[i] = i.toString(16).padStart(2, "0");
	}

	async function sha256(text) {
		const data = textEncoder.encode(text);
		const hashBuffer = await crypto.subtle.digest("SHA-256", data);
		const hashArray = new Uint8Array(hashBuffer);
		let hex = "";
		for (let i = 0; i < hashArray.length; i++) {
			hex += HEX_CHARS[hashArray[i]];
		}
		return hex;
	}

	let changeDebounceTimer = null;
	let pendingMutationCount = 0;

	// Maximum tier: mutation rate tracking
	let mutationRateWindow = [];
	const MUTATION_RATE_WINDOW_MS = 10_000;

	function handleContentChange() {
		if (!isWitnessing) return;

		pendingMutationCount++;
		clearTimeout(changeDebounceTimer);

		// Adaptive debounce: longer delay for rapid-fire mutations (e.g. paste),
		// shorter for normal typing to stay responsive
		const delay = pendingMutationCount > 10 ? 3000 : 2000;

		changeDebounceTimer = setTimeout(async () => {
			pendingMutationCount = 0;
			try {
				const text = getDocumentText();
				const charCount = text.length;
				const delta = charCount - lastCharCount;

				if (Math.abs(delta) < MIN_CHANGE_THRESHOLD) return;

				const contentHash = await sha256(text);
				if (contentHash === lastContentHash) return;

				lastContentHash = contentHash;
				const previousCount = lastCharCount;
				lastCharCount = charCount;

				const actualDelta = charCount - previousCount;
				const msg = {
					action: "content_changed",
					contentHash,
					charCount,
					delta: actualDelta,
					toolCategory: detectedWritingTools.category,
					toolHost: detectedWritingTools.host,
					keystrokeCount: keystrokesSinceLastCheckpoint,
				};

				if (
					pendingPaste &&
					Date.now() - pendingPaste.timestamp < 5000
				) {
					msg.pasteDetected = true;
					msg.pasteCharCount = pendingPaste.charCount;
					msg.pasteHasRichContent = pendingPaste.hasRichContent;
				}
				pendingPaste = null;

				keystrokesSinceLastCheckpoint = 0;

				if (contentTier === "enhanced" || contentTier === "maximum") {
					msg.documentTitle = getDocumentTitle();
				}
				if (contentTier === "maximum") {
					const now = Date.now();
					mutationRateWindow.push(now);
					const cutoff = now - MUTATION_RATE_WINDOW_MS;
					mutationRateWindow = mutationRateWindow.filter(
						(t) => t > cutoff,
					);
					msg.mutationRate = mutationRateWindow.length;
				}

				sendToBackground(msg);
			} catch (_) {
				// Will retry on next mutation
			}
		}, delay);
	}

	let observer = null;

	function startObserving() {
		if (observer) return;

		const elements = getEditorElement();
		if (!elements || elements.length === 0) {
			if (++observerRetries < MAX_OBSERVER_RETRIES) {
				setTimeout(startObserving, 1000);
			}
			return;
		}
		observerRetries = 0;

		// Batch multiple synchronous mutations into a single callback via microtask
		let mutationScheduled = false;
		observer = new MutationObserver(() => {
			if (!mutationScheduled) {
				mutationScheduled = true;
				queueMicrotask(() => {
					mutationScheduled = false;
					handleContentChange();
				});
			}
		});

		elements.forEach((el) => {
			observer.observe(el, {
				characterData: true,
				childList: true,
				subtree: true,
			});
		});

		const text = getDocumentText();
		lastCharCount = text.length;
		sha256(text)
			.then((hash) => {
				lastContentHash = hash;
			})
			.catch(() => {});
	}

	function stopObserving() {
		if (observer) {
			observer.disconnect();
			observer = null;
		}
	}

	function checkEditorHealth() {
		if (!isWitnessing) return;

		let stale = !cachedEditorElements || cachedEditorElements.length === 0;
		if (!stale) {
			for (const el of cachedEditorElements) {
				if (!el.isConnected) {
					stale = true;
					break;
				}
			}
		}

		if (stale) {
			stopObserving();
			invalidateEditorCache();
			observerRetries = 0;
			startObserving();
		}
	}

	// Batched per-keystroke events for dual-source validation with native engine.
	let keystrokeBatch = [];
	let keystrokeBatchTimer = null;
	const KEYSTROKE_BATCH_INTERVAL = 500; // ms

	function flushKeystrokeBatch() {
		if (keystrokeBatch.length === 0) return;
		const batch = keystrokeBatch;
		keystrokeBatch = [];
		sendToBackground({
			action: "browser_keystroke_batch",
			keystrokes: batch,
		});
	}

	function handlePaste(e) {
		if (!isWitnessing) return;
		const clipData = e.clipboardData;
		let charCount = 0;
		let hasRichContent = false;
		if (clipData) {
			const text = clipData.getData("text/plain");
			charCount = text ? text.length : 0;
			hasRichContent =
				clipData.types.includes("text/html") ||
				clipData.types.includes("text/rtf") ||
				clipData.types.some((t) => t.startsWith("image/"));
		}
		pendingPaste = {
			timestamp: Date.now(),
			charCount,
			hasRichContent,
		};
	}

	function handleKeyDown(e) {
		if (!isWitnessing || contentTier === "core") return;
		if (e.target && isSensitiveTarget(e.target)) return;
		keystrokesSinceLastCheckpoint++;

		// Collect per-keystroke data for dual-source validation.
		keystrokeBatch.push({
			t: performance.now(),
			k: e.key,
			c: e.code,
		});
		if (!keystrokeBatchTimer) {
			keystrokeBatchTimer = setTimeout(() => {
				keystrokeBatchTimer = null;
				flushKeystrokeBatch();
			}, KEYSTROKE_BATCH_INTERVAL);
		}

		jitterBuffer[jitterIndex++] = performance.now();

		if (jitterIndex > JITTER_BATCH_SIZE) {
			// Build intervals from ring buffer (avoid allocating intermediate array)
			const intervals = new Array(JITTER_BATCH_SIZE - 1);
			for (let i = 1; i < jitterIndex; i++) {
				intervals[i - 1] = Math.round(
					(jitterBuffer[i] - jitterBuffer[i - 1]) * 1000,
				);
			}
			// Keep last timestamp as start of next batch
			jitterBuffer[0] = jitterBuffer[jitterIndex - 1];
			jitterIndex = 1;

			sendToBackground({
				action: "keystroke_jitter",
				intervals,
			});
		}
	}

	function detectWritingTools() {
		if (
			document.querySelector("grammarly-extension") ||
			document.querySelector("#grammarly-btn")
		) {
			detectedWritingTools = {
				category: "grammar",
				host: "app.grammarly.com",
			};
			return;
		}
		if (
			document.querySelector(".lt-marker") ||
			document.querySelector("[data-lt-active]")
		) {
			detectedWritingTools = {
				category: "grammar",
				host: "languagetool.org",
			};
			return;
		}
		if (
			document.querySelector("iframe[src*='prowritingaid']") ||
			document.querySelector("[data-pwa-hint]")
		) {
			detectedWritingTools = {
				category: "grammar",
				host: "prowritingaid.com",
			};
			return;
		}
		if (window.location.hostname === "hemingwayapp.com") {
			detectedWritingTools = {
				category: "writing",
				host: "hemingwayapp.com",
			};
			return;
		}
		detectedWritingTools = { category: "none", host: "" };
	}

	function installTitleObserver() {
		if (titleObserver) return;
		const titleEl = document.querySelector("title");
		if (!titleEl) return;
		let lastTitle = document.title;
		titleObserver = new MutationObserver(() => {
			const newTitle = document.title;
			if (!isWitnessing || newTitle === lastTitle) return;
			lastTitle = newTitle;
			if (detectSite() && newTitle.length > 0) {
				stopWitnessing();
				setTimeout(startWitnessing, 600);
			}
		});
		titleObserver.observe(titleEl, {
			childList: true,
			characterData: true,
			subtree: true,
		});
	}

	function startWitnessing() {
		if (isWitnessing) return;

		calibrateTimer();
		isWitnessing = true;
		invalidateEditorCache();
		detectWritingTools();
		writingToolsInterval = setInterval(detectWritingTools, 10_000);

		chrome.storage.local.set({ [storageKey()]: true });

		startObserving();
		document.addEventListener("keydown", handleKeyDown, { passive: true });
		document.addEventListener("paste", handlePaste, { passive: true });
		editorHealthInterval = setInterval(
			checkEditorHealth,
			EDITOR_HEALTH_INTERVAL_MS,
		);

		sendToBackground({
			action: "start_witnessing",
			url: window.location.href,
			title: getDocumentTitle(),
			timerResolution,
			editorType: detectSite(),
		});

		installTitleObserver();
	}

	function stopWitnessing() {
		if (!isWitnessing) return;
		isWitnessing = false;
		invalidateEditorCache();

		chrome.storage.local.remove([storageKey()]);

		stopObserving();
		document.removeEventListener("keydown", handleKeyDown);
		document.removeEventListener("paste", handlePaste);
		pendingPaste = null;
		keystrokesSinceLastCheckpoint = 0;
		jitterIndex = 0;
		pendingMutationCount = 0;

		if (keystrokeBatchTimer) {
			clearTimeout(keystrokeBatchTimer);
			keystrokeBatchTimer = null;
		}
		if (changeDebounceTimer) {
			clearTimeout(changeDebounceTimer);
			changeDebounceTimer = null;
		}

		if (editorHealthInterval) {
			clearInterval(editorHealthInterval);
			editorHealthInterval = null;
		}
		if (writingToolsInterval) {
			clearInterval(writingToolsInterval);
			writingToolsInterval = null;
		}
		if (titleObserver) {
			titleObserver.disconnect();
			titleObserver = null;
		}

		sendToBackground({ action: "stop_witnessing" });
	}

	chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
		if (sender.id !== chrome.runtime.id) return;
		if (
			!message ||
			typeof message !== "object" ||
			typeof message.action !== "string"
		)
			return;
		if (!VALID_CONTENT_ACTIONS.has(message.action)) {
			sendResponse({ ok: false, error: "Unknown action" });
			return true;
		}

		switch (message.action) {
			case "capture_state":
				handleContentChange();
				sendResponse({ ok: true });
				break;
			case "start":
				startWitnessing();
				sendResponse({ ok: true });
				break;
			case "stop":
			case "stop_witnessing":
				stopWitnessing();
				sendResponse({ ok: true });
				break;
			case "get_page_info":
				sendResponse({
					ok: true,
					site: detectSite(),
					title: getDocumentTitle(),
					charCount: getDocumentCharCount(),
					isWitnessing,
				});
				break;
			default:
				sendResponse({ ok: false, error: "Unknown action" });
		}
		return true;
	});

	window.addEventListener("beforeunload", () => {
		clearTimeout(changeDebounceTimer);
		stopObserving();
	});

	// SPA navigation: detect URL changes without full page reload (Notion, Coda, etc.)
	let lastWitnessedURL = window.location.href;
	let spaRetryTimer = null;
	const spaNavHandler = () => {
		if (!isWitnessing) return;
		const newURL = window.location.href;
		if (newURL !== lastWitnessedURL) {
			stopWitnessing();
			lastWitnessedURL = newURL;
			cachedSiteId = undefined;
			invalidateEditorCache();
			if (spaRetryTimer) clearTimeout(spaRetryTimer);
			let retries = 0;
			const tryRestart = () => {
				spaRetryTimer = null;
				cachedSiteId = undefined;
				if (detectSite()) {
					startWitnessing();
				} else if (++retries < 5) {
					spaRetryTimer = setTimeout(tryRestart, 2000);
				}
			};
			spaRetryTimer = setTimeout(tryRestart, 1000);
		}
	};
	window.addEventListener("popstate", spaNavHandler);
	const origPushState = history.pushState;
	history.pushState = function (...args) {
		origPushState.apply(this, args);
		spaNavHandler();
	};
	const origReplaceState = history.replaceState;
	history.replaceState = function (...args) {
		origReplaceState.apply(this, args);
		spaNavHandler();
	};

	// AI tool copy attribution: record when the user copies text from an AI site.
	// This is declarative, not punitive — it documents tool usage for the attestation.
	const aiSiteId = AI_TOOL_HOSTS[window.location.hostname];
	if (aiSiteId) {
		document.addEventListener(
			"copy",
			() => {
				const sel = window.getSelection();
				const charCount = sel ? sel.toString().length : 0;
				if (charCount === 0) return;
				sendToBackground({
					action: "ai_content_copied",
					source: aiSiteId,
					charCount,
					timestamp: Date.now(),
				});
			},
			{ passive: true },
		);
	}

	chrome.storage.local.get([storageKey(), "autoWitness"], (result) => {
		if (result[storageKey()] || (result.autoWitness && detectSite())) {
			setTimeout(startWitnessing, 3000);
		}
	});
})();
