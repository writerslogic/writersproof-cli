// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * WritersProof editor hooks AMD module.
 *
 * Monitors the Moodle editor (Atto and TinyMCE) for timing metadata,
 * sends events to the PHP external API, and displays a status indicator.
 *
 * Privacy guarantees:
 *   - No characters, words, or content are captured or transmitted.
 *   - Only event timestamps, durations, and aggregate deltas are sent.
 *   - Content hashing is performed via SubtleCrypto entirely in-browser;
 *     only the hex digest is forwarded.
 *
 * @module     local_writersproof/editor_hooks
 * @copyright  2026 WritersLogic, Inc.
 * @license    https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

define(["core/ajax", "core/notification", "core/str"], function (
	Ajax,
	Notification,
	Str,
) {
	"use strict";

	// -------------------------------------------------------------------------
	// Constants
	// -------------------------------------------------------------------------

	/** Maximum events buffered before a forced flush. */
	const MAX_BUFFER = 200;

	/** Flush events after this many milliseconds of inactivity. */
	const FLUSH_DEBOUNCE_MS = 2000;

	/** Minimum milliseconds between checkpoint API calls. */
	const MIN_CHECKPOINT_GAP_MS = 5000;

	/** Idle threshold: no keydown events for this long = idle. */
	const IDLE_THRESHOLD_MS = 30000;

	// Status indicator CSS class names.
	const STATUS_CLASS_ACTIVE = "writersproof-active";
	const STATUS_CLASS_PAUSED = "writersproof-paused";
	const STATUS_CLASS_FAILED = "writersproof-failed";

	// -------------------------------------------------------------------------
	// Module state (one instance per page)
	// -------------------------------------------------------------------------

	let config = {}; // Runtime config from PHP (cmid, modname, etc.)
	let sessionId = null; // Remote WritersProof session ID
	let sessionStatus = "none";
	let isIdle = false;
	let lastKeydownMs = 0;
	let lastCheckpointMs = 0;
	let lastFlushMs = 0;
	let lastContentHash = null;

	let eventBuffer = []; // Pending events awaiting flush
	let flushTimer = null; // Debounce timer handle
	let idleTimer = null; // Idle detection timer handle
	let checkpointTimer = null; // Periodic checkpoint timer

	let indicatorEl = null; // Status indicator DOM element
	let observedEditors = new Set(); // Track attached editor elements

	// -------------------------------------------------------------------------
	// Entry point
	// -------------------------------------------------------------------------

	/**
	 * Initialise the module. Called by lib.php via $PAGE->requires->js_call_amd.
	 *
	 * @param {Object} cfg Runtime configuration.
	 * @param {number} cfg.cmid               Course module ID.
	 * @param {string} cfg.modname            Moodle module name (assign/forum/wiki).
	 * @param {number} cfg.checkpointInterval Seconds between checkpoints.
	 * @param {string} cfg.sesskey            Moodle session key.
	 */
	function init(cfg) {
		config = cfg;

		// Insert the status indicator into the page.
		renderIndicator();
		setStatus("initialising");

		// Start a session immediately.
		detectItemId()
			.then(function (itemInfo) {
				if (!itemInfo) {
					setStatus("failed");
					return;
				}
				return callStartSession(itemInfo);
			})
			.then(function (resp) {
				if (
					!resp ||
					resp.status === "failed" ||
					resp.status === "disabled"
				) {
					setStatus("failed");
					return;
				}
				sessionId = resp.sessionid;
				sessionStatus = resp.status;
				setStatus("active");

				// Attach editor listeners.
				attachEditorListeners();

				// Start periodic checkpoint timer.
				const intervalMs = Math.max(
					10000,
					(config.checkpointInterval || 60) * 1000,
				);
				checkpointTimer = setInterval(periodicCheckpoint, intervalMs);
			})
			.catch(function (err) {
				// Non-fatal: plugin fails silently so as not to disrupt the editor.
				setStatus("failed");
				window.console &&
					window.console.warn("[WritersProof] init error:", err);
			});
	}

	// -------------------------------------------------------------------------
	// Item ID detection
	// -------------------------------------------------------------------------

	/**
	 * Infer the content item type and ID from the current page URL and DOM.
	 *
	 * @return {Promise<{itemtype: string, itemid: number}|null>}
	 */
	function detectItemId() {
		const url = new URL(window.location.href);

		// Assignment submission page: /mod/assign/view.php?id=<cmid>&action=editsubmission
		if (config.modname === "assign") {
			// The submission ID is in a hidden field or inferred from the URL.
			const submissionInput = document.querySelector('input[name="id"]');
			// Assignments post the submission ID via a data attribute or hidden field.
			const submissionId = getDataAttrOrInput(
				"data-submission-id",
				"submissionid",
			);
			if (submissionId) {
				return Promise.resolve({
					itemtype: "assignment_submission",
					itemid: Number(submissionId),
				});
			}
			// Fall back: use cmid as item reference; server will resolve.
			return Promise.resolve({
				itemtype: "assignment_submission",
				itemid: config.cmid,
			});
		}

		// Forum: /mod/forum/post.php?edit=<postid> or reply/new thread.
		if (config.modname === "forum") {
			const postid =
				url.searchParams.get("edit") ||
				url.searchParams.get("reply") ||
				getDataAttrOrInput("data-post-id", "postid") ||
				"0";
			return Promise.resolve({
				itemtype: "forum_post",
				itemid: Number(postid),
			});
		}

		// Wiki: /mod/wiki/edit.php?pageid=<pageid>
		if (config.modname === "wiki") {
			const pageid =
				url.searchParams.get("pageid") ||
				getDataAttrOrInput("data-page-id", "pageid") ||
				"0";
			return Promise.resolve({
				itemtype: "wiki_page",
				itemid: Number(pageid),
			});
		}

		return Promise.resolve(null);
	}

	/**
	 * Try to find a value from a DOM data attribute or a hidden input.
	 *
	 * @param {string} attr   data-* attribute name.
	 * @param {string} inputName  Hidden input name attribute.
	 * @return {string|null}
	 */
	function getDataAttrOrInput(attr, inputName) {
		const el = document.querySelector("[" + attr + "]");
		if (el) {
			return el.getAttribute(attr);
		}
		const input = document.querySelector('input[name="' + inputName + '"]');
		if (input) {
			return input.value;
		}
		return null;
	}

	// -------------------------------------------------------------------------
	// Editor attachment
	// -------------------------------------------------------------------------

	/**
	 * Attach event listeners to the active editor element(s).
	 * Supports Atto (contenteditable div) and TinyMCE (iframe document).
	 */
	function attachEditorListeners() {
		// Atto: textarea converted to contenteditable div with class .editor_atto_content
		const attoEditors = document.querySelectorAll(".editor_atto_content");
		attoEditors.forEach(function (el) {
			if (!observedEditors.has(el)) {
				attachListenersToElement(el);
				observedEditors.add(el);
			}
		});

		// TinyMCE 4/6: editors register in tinymce.editors; listen after init.
		if (window.tinymce) {
			window.tinymce.on("AddEditor", function (e) {
				e.editor.on("init", function () {
					const doc = e.editor.getDoc();
					if (doc && !observedEditors.has(doc)) {
						attachListenersToDocument(doc);
						observedEditors.add(doc);
					}
				});
			});
			// Also hook any already-initialised TinyMCE instances.
			(window.tinymce.editors || []).forEach(function (editor) {
				const doc = editor.getDoc && editor.getDoc();
				if (doc && !observedEditors.has(doc)) {
					attachListenersToDocument(doc);
					observedEditors.add(doc);
				}
			});
		}

		// Plain textarea fallback (some Moodle themes disable rich editors).
		const textareas = document.querySelectorAll(
			'textarea.form-textarea, textarea[name="message"]',
		);
		textareas.forEach(function (el) {
			if (!observedEditors.has(el)) {
				attachListenersToElement(el);
				observedEditors.add(el);
			}
		});

		// Re-check after a short delay to catch editors that initialise late.
		setTimeout(attachEditorListeners, 3000);
	}

	/**
	 * Attach keyboard/paste/focus listeners to a DOM element.
	 *
	 * @param {Element} el
	 */
	function attachListenersToElement(el) {
		el.addEventListener("keydown", onKeydown, { passive: true });
		el.addEventListener("paste", onPaste, { passive: true });
		el.addEventListener("focus", onFocus, { passive: true });
		el.addEventListener("blur", onBlur, { passive: true });
	}

	/**
	 * Attach keyboard/paste/focus listeners to a Document (TinyMCE iframe).
	 *
	 * @param {Document} doc
	 */
	function attachListenersToDocument(doc) {
		doc.addEventListener("keydown", onKeydown, { passive: true });
		doc.addEventListener("paste", onPaste, { passive: true });
		doc.addEventListener("focus", onFocus, {
			passive: true,
			capture: true,
		});
		doc.addEventListener("blur", onBlur, { passive: true, capture: true });
	}

	// -------------------------------------------------------------------------
	// Event handlers — capture timing metadata only, never content
	// -------------------------------------------------------------------------

	/**
	 * Keydown event: record timestamp. No key value is captured.
	 *
	 * @param {KeyboardEvent} e
	 */
	function onKeydown(e) {
		const now = Date.now();
		const gap = now - lastKeydownMs;
		lastKeydownMs = now;

		bufferEvent({
			type: "keydown",
			timestamp_ms: now,
			// Inter-keystroke interval only — no key identity.
			duration_ms: Math.min(gap, 60000), // Cap at 60 s to avoid noise.
		});

		// Reset idle detection.
		if (isIdle) {
			isIdle = false;
			bufferEvent({ type: "idle_end", timestamp_ms: now });
		}
		resetIdleTimer();
		scheduleFlushe();
	}

	/**
	 * Paste event: record timestamp and paste length (byte count only).
	 *
	 * @param {ClipboardEvent} e
	 */
	function onPaste(e) {
		const now = Date.now();
		let pasteLength = 0;
		try {
			const text =
				e.clipboardData && e.clipboardData.getData("text/plain");
			if (text) {
				// Record only character count, not the text itself.
				pasteLength = text.length;
			}
		} catch (_) {
			// ClipboardData may be restricted; silently ignore.
		}

		bufferEvent({
			type: "paste",
			timestamp_ms: now,
			length: pasteLength,
		});

		resetIdleTimer();
		scheduleFlushe();
	}

	/**
	 * Focus event: editor received focus.
	 */
	function onFocus() {
		bufferEvent({ type: "focus", timestamp_ms: Date.now() });
	}

	/**
	 * Blur event: editor lost focus.
	 */
	function onBlur() {
		bufferEvent({ type: "blur", timestamp_ms: Date.now() });
		// Flush immediately on blur so no events are lost.
		flushEvents();
	}

	// -------------------------------------------------------------------------
	// Event buffer and flush
	// -------------------------------------------------------------------------

	/**
	 * Add an event to the buffer.
	 *
	 * @param {Object} event
	 */
	function bufferEvent(event) {
		eventBuffer.push(event);
		if (eventBuffer.length >= MAX_BUFFER) {
			flushEvents();
		}
	}

	/**
	 * Schedule a debounced flush.
	 */
	function scheduleFlushe() {
		if (flushTimer) {
			clearTimeout(flushTimer);
		}
		flushTimer = setTimeout(flushEvents, FLUSH_DEBOUNCE_MS);
	}

	/**
	 * Flush buffered events to the server.
	 */
	function flushEvents() {
		if (flushTimer) {
			clearTimeout(flushTimer);
			flushTimer = null;
		}
		if (!sessionId || eventBuffer.length === 0) {
			return;
		}
		const batch = eventBuffer.splice(0, eventBuffer.length);
		lastFlushMs = Date.now();

		Ajax.call([
			{
				methodname: "local_writersproof_submit_events",
				args: {
					sessionid: sessionId,
					events_json: JSON.stringify(batch),
				},
			},
		])[0].catch(function (err) {
			// Put events back if submission failed — retry on next flush.
			// Limit re-queue to avoid unbounded growth on persistent failure.
			if (eventBuffer.length < MAX_BUFFER) {
				eventBuffer.unshift(
					...batch.slice(0, MAX_BUFFER - eventBuffer.length),
				);
			}
			window.console &&
				window.console.warn("[WritersProof] flush error:", err);
		});
	}

	// -------------------------------------------------------------------------
	// Periodic checkpoint
	// -------------------------------------------------------------------------

	/**
	 * Compute content hash and create a checkpoint if content changed.
	 */
	function periodicCheckpoint() {
		if (
			!sessionId ||
			sessionStatus === "finalized" ||
			sessionStatus === "failed"
		) {
			return;
		}
		const now = Date.now();
		if (now - lastCheckpointMs < MIN_CHECKPOINT_GAP_MS) {
			return;
		}

		getEditorContent()
			.then(function (content) {
				if (!content) {
					return;
				}
				return hashContent(content);
			})
			.then(function (hash) {
				if (!hash || hash === lastContentHash) {
					return; // Content unchanged — skip checkpoint.
				}
				lastContentHash = hash;
				lastCheckpointMs = Date.now();

				return Ajax.call([
					{
						methodname: "local_writersproof_create_checkpoint",
						args: {
							sessionid: sessionId,
							contenthash: hash,
							wordcount: estimateWordCount(),
						},
					},
				])[0];
			})
			.then(function (resp) {
				if (resp && resp.success) {
					flashIndicator();
				}
			})
			.catch(function (err) {
				window.console &&
					window.console.warn(
						"[WritersProof] checkpoint error:",
						err,
					);
			});
	}

	// -------------------------------------------------------------------------
	// Content helpers
	// -------------------------------------------------------------------------

	/**
	 * Extract plain-text content from the active editor element.
	 *
	 * @return {Promise<string>}
	 */
	function getEditorContent() {
		// Atto.
		const atto = document.querySelector(".editor_atto_content");
		if (atto) {
			return Promise.resolve(atto.innerText || atto.textContent || "");
		}
		// TinyMCE.
		if (window.tinymce && window.tinymce.activeEditor) {
			try {
				return Promise.resolve(
					window.tinymce.activeEditor.getContent({
						format: "text",
					}) || "",
				);
			} catch (_) {
				/* fall through */
			}
		}
		// Plain textarea.
		const textarea = document.querySelector(
			'textarea[name="message"], textarea.form-textarea',
		);
		if (textarea) {
			return Promise.resolve(textarea.value || "");
		}
		return Promise.resolve("");
	}

	/**
	 * Compute a SHA-256 hash of a plain-text string via SubtleCrypto.
	 *
	 * Falls back to a simple djb2 hash string if SubtleCrypto is unavailable
	 * (e.g., non-HTTPS dev environment). The fallback is not cryptographically
	 * secure but keeps the module functional for development.
	 *
	 * @param  {string}          content
	 * @return {Promise<string>} 64-char lowercase hex string.
	 */
	function hashContent(content) {
		const encoder = new TextEncoder();
		const data = encoder.encode(content);

		if (window.crypto && window.crypto.subtle) {
			return window.crypto.subtle
				.digest("SHA-256", data)
				.then(function (buf) {
					return Array.from(new Uint8Array(buf))
						.map((b) => b.toString(16).padStart(2, "0"))
						.join("");
				});
		}

		// Non-secure fallback: djb2 hash, zero-padded to 64 hex chars.
		let h = 5381;
		for (let i = 0; i < content.length; i++) {
			h = ((h << 5) + h) ^ content.charCodeAt(i);
			h = h >>> 0; // Unsigned 32-bit.
		}
		const hex = h.toString(16).padStart(8, "0");
		return Promise.resolve(hex.padStart(64, "0"));
	}

	/**
	 * Estimate current word count from the active editor.
	 *
	 * @return {number}
	 */
	function estimateWordCount() {
		const atto = document.querySelector(".editor_atto_content");
		const text = atto ? atto.innerText || "" : "";
		if (!text.trim()) {
			return 0;
		}
		return text.trim().split(/\s+/).length;
	}

	// -------------------------------------------------------------------------
	// Idle detection
	// -------------------------------------------------------------------------

	/**
	 * Reset the idle detection timer.
	 */
	function resetIdleTimer() {
		if (idleTimer) {
			clearTimeout(idleTimer);
		}
		idleTimer = setTimeout(function () {
			if (!isIdle) {
				isIdle = true;
				bufferEvent({ type: "idle_start", timestamp_ms: Date.now() });
			}
		}, IDLE_THRESHOLD_MS);
	}

	// -------------------------------------------------------------------------
	// API calls
	// -------------------------------------------------------------------------

	/**
	 * Call the start_session external function.
	 *
	 * @param  {{itemtype: string, itemid: number}} itemInfo
	 * @return {Promise<{sessionid: string, status: string}>}
	 */
	function callStartSession(itemInfo) {
		return Ajax.call([
			{
				methodname: "local_writersproof_start_session",
				args: {
					cmid: config.cmid,
					itemtype: itemInfo.itemtype,
					itemid: itemInfo.itemid,
				},
			},
		])[0];
	}

	// -------------------------------------------------------------------------
	// Status indicator
	// -------------------------------------------------------------------------

	/**
	 * Inject the WritersProof status indicator pill next to the editor toolbar.
	 */
	function renderIndicator() {
		indicatorEl = document.createElement("div");
		indicatorEl.id = "writersproof-indicator";
		indicatorEl.setAttribute("role", "status");
		indicatorEl.setAttribute("aria-live", "polite");
		indicatorEl.style.cssText = [
			"display:inline-flex",
			"align-items:center",
			"gap:5px",
			"padding:3px 8px",
			"border-radius:4px",
			"font-size:0.75rem",
			"font-family:inherit",
			"cursor:default",
			"user-select:none",
			"transition:background 0.3s",
			"position:fixed",
			"bottom:16px",
			"right:16px",
			"z-index:9999",
			"box-shadow:0 1px 4px rgba(0,0,0,0.15)",
		].join(";");

		const dot = document.createElement("span");
		dot.id = "writersproof-dot";
		dot.style.cssText =
			"display:inline-block;width:8px;height:8px;border-radius:50%;background:#999";

		const label = document.createElement("span");
		label.id = "writersproof-label";
		label.textContent = "WritersProof";

		indicatorEl.appendChild(dot);
		indicatorEl.appendChild(label);
		document.body.appendChild(indicatorEl);
	}

	/**
	 * Update the indicator to reflect the current status.
	 *
	 * @param {string} status  'initialising'|'active'|'paused'|'failed'
	 */
	function setStatus(status) {
		if (!indicatorEl) {
			return;
		}
		const dot = document.getElementById("writersproof-dot");
		const label = document.getElementById("writersproof-label");
		if (!dot || !label) {
			return;
		}

		const styles = {
			initialising: {
				bg: "#f5f5f5",
				color: "#555",
				dot: "#aaa",
				text: "WritersProof…",
			},
			active: {
				bg: "#e8f5e9",
				color: "#2e7d32",
				dot: "#43a047",
				text: "WritersProof ON",
			},
			paused: {
				bg: "#fff8e1",
				color: "#f57f17",
				dot: "#fbc02d",
				text: "WP Paused",
			},
			failed: {
				bg: "#fce4ec",
				color: "#b71c1c",
				dot: "#e53935",
				text: "WP Off",
			},
		};
		const s = styles[status] || styles.initialising;

		indicatorEl.style.background = s.bg;
		indicatorEl.style.color = s.color;
		dot.style.background = s.dot;
		label.textContent = s.text;
	}

	/**
	 * Briefly flash the indicator green to acknowledge a checkpoint.
	 */
	function flashIndicator() {
		if (!indicatorEl) {
			return;
		}
		indicatorEl.style.background = "#c8e6c9";
		setTimeout(function () {
			setStatus("active");
		}, 500);
	}

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	return {
		init: init,
	};
});
