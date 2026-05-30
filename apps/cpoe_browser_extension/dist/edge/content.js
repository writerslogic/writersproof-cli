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

	const JITTER_BATCH_SIZE = 50;
	const MIN_CHANGE_THRESHOLD = 5;
	const MAX_OBSERVER_RETRIES = 20;
	const MAX_DOCUMENT_SIZE = 10 * 1024 * 1024;

	// Reuse encoder across all calls to avoid GC pressure
	const textEncoder = new TextEncoder();

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
	];

	let customDomainsList = [];

	chrome.storage.local.get(["customDomains", "contentTier"], (result) => {
		customDomainsList = result.customDomains || [];
		if (result.contentTier === "core" || result.contentTier === "maximum") {
			contentTier = result.contentTier;
		}
	});
	chrome.storage.onChanged.addListener((changes) => {
		if (changes.customDomains) {
			customDomainsList = changes.customDomains.newValue || [];
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
		}
		return elements;
	}

	function getDocumentText() {
		const elements = getEditorElement();
		if (!elements || elements.length === 0) return "";

		const chunks = [];
		let totalLength = 0;

		for (const el of elements) {
			if (totalLength >= MAX_DOCUMENT_SIZE) break;

			const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
			let node;
			while ((node = walker.nextNode())) {
				const value = node.nodeValue;
				if (!value) continue;

				const remaining = MAX_DOCUMENT_SIZE - totalLength;
				if (remaining <= 0) break;

				if (value.length <= remaining) {
					chunks.push(value);
					totalLength += value.length;
				} else {
					chunks.push(value.slice(0, remaining));
					totalLength += remaining;
					break;
				}
			}
		}

		return chunks.join("");
	}

	function getDocumentCharCount() {
		const elements = getEditorElement();
		if (!elements || elements.length === 0) return 0;

		let total = 0;
		for (const el of elements) {
			if (total >= MAX_DOCUMENT_SIZE) break;
			const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
			let node;
			while ((node = walker.nextNode())) {
				const value = node.nodeValue;
				if (!value) continue;
				total += value.length;
				if (total >= MAX_DOCUMENT_SIZE) return MAX_DOCUMENT_SIZE;
			}
		}
		return total;
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

				const msg = {
					action: "content_changed",
					contentHash,
					charCount,
					delta: charCount - previousCount,
					toolCategory: detectedWritingTools.category,
					toolHost: detectedWritingTools.host,
				};

				if (contentTier === "maximum") {
					msg.documentTitle = getDocumentTitle();
					const now = Date.now();
					mutationRateWindow.push(now);
					const cutoff = now - MUTATION_RATE_WINDOW_MS;
					mutationRateWindow = mutationRateWindow.filter(
						(t) => t > cutoff,
					);
					msg.mutationRate = mutationRateWindow.length;
				}

				chrome.runtime.sendMessage(msg);
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

	// Batched per-keystroke events for dual-source validation with native engine.
	let keystrokeBatch = [];
	let keystrokeBatchTimer = null;
	const KEYSTROKE_BATCH_INTERVAL = 500; // ms

	function flushKeystrokeBatch() {
		if (keystrokeBatch.length === 0) return;
		const batch = keystrokeBatch;
		keystrokeBatch = [];
		chrome.runtime.sendMessage({
			action: "browser_keystroke_batch",
			keystrokes: batch,
		});
	}

	function handleKeyDown(e) {
		if (!isWitnessing || contentTier === "core") return;

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

			chrome.runtime.sendMessage({
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

		chrome.runtime.sendMessage({
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
		jitterIndex = 0;
		pendingMutationCount = 0;

		if (writingToolsInterval) {
			clearInterval(writingToolsInterval);
			writingToolsInterval = null;
		}
		if (titleObserver) {
			titleObserver.disconnect();
			titleObserver = null;
		}

		chrome.runtime.sendMessage({ action: "stop_witnessing" });
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
	const spaNavHandler = () => {
		if (!isWitnessing) return;
		const newURL = window.location.href;
		if (newURL !== lastWitnessedURL) {
			stopWitnessing();
			lastWitnessedURL = newURL;
			cachedSiteId = undefined;
			invalidateEditorCache();
			if (detectSite()) {
				setTimeout(startWitnessing, 1000);
			}
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
				chrome.runtime
					.sendMessage({
						action: "ai_content_copied",
						source: aiSiteId,
						charCount,
						timestamp: Date.now(),
					})
					.catch(() => {});
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
