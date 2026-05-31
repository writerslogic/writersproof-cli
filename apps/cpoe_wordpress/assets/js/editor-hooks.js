/**
 * WritersProof editor integration.
 *
 * Gutenberg: registers a plugin sidebar panel and subscribes to wp.data
 * store changes to capture timing metadata and content hashes.
 *
 * Classic editor (TinyMCE): hooks into keydown/paste/change events when
 * the Gutenberg API is not available.
 *
 * Privacy guarantee: NO actual text content, keystrokes, or characters are
 * captured or transmitted. Only timing metadata (timestamps, intervals),
 * word/character counts, SHA-256 hashes of content, and event types.
 *
 * @package WritersProof
 */

/* global wp, writersProofData, tinymce */

(function () {
	"use strict";

	// -------------------------------------------------------------------------
	// Config from wp_localize_script()
	// -------------------------------------------------------------------------

	var cfg = window.writersProofData || {};
	var REST_URL = (cfg.restUrl || "").replace(/\/$/, "");
	var NONCE = cfg.nonce || "";
	var POST_ID = parseInt(cfg.postId, 10) || 0;
	var AUTO_START = !!cfg.autoStart;
	var INTERVAL = Math.max(10, parseInt(cfg.checkpointInterval, 10) || 60);
	var HAS_KEY = !!cfg.hasApiKey;

	// -------------------------------------------------------------------------
	// State
	// -------------------------------------------------------------------------

	var state = {
		sessionId: null, // string | null
		status: "none", // 'none' | 'active' | 'stopped' | 'finalized'
		lastHash: null, // string | null  — hex SHA-256 of last observed content
		lastWordCount: 0,
		lastBlockCount: 0,
		eventBuffer: [], // accumulated timing events not yet flushed
		flushTimer: null, // setInterval handle
		checkpointTimer: null, // setInterval handle
		sessionStartMs: 0, // performance.now() at session start
		indicator: null, // DOM element — visual badge
	};

	// -------------------------------------------------------------------------
	// Utility: SHA-256 via SubtleCrypto (no external library)
	// -------------------------------------------------------------------------

	/**
	 * Compute a hex SHA-256 digest of a string using the browser's native
	 * SubtleCrypto API.
	 *
	 * @param {string} text Input text.
	 * @returns {Promise<string>} Lowercase hex digest.
	 */
	function sha256(text) {
		var encoder = new TextEncoder();
		var data = encoder.encode(text);
		return crypto.subtle.digest("SHA-256", data).then(function (buf) {
			return Array.from(new Uint8Array(buf))
				.map(function (b) {
					return b.toString(16).padStart(2, "0");
				})
				.join("");
		});
	}

	// -------------------------------------------------------------------------
	// Utility: normalise block editor content for hashing
	// -------------------------------------------------------------------------

	/**
	 * Strip block comments and HTML tags from Gutenberg serialised content,
	 * then collapse whitespace. This mirrors the server-side normalisation in
	 * WritersProof_Monitor::normalise_content() so that hashes match.
	 *
	 * @param {string} raw Serialised block content.
	 * @returns {string} Normalised plain text.
	 */
	function normaliseContent(raw) {
		if (!raw) return "";
		// Remove Gutenberg block comment markers.
		var plain = raw.replace(/<!--[\s\S]*?-->/g, "");
		// Strip HTML tags.
		plain = plain.replace(/<[^>]+>/g, " ");
		// Decode common HTML entities.
		plain = plain
			.replace(/&amp;/g, "&")
			.replace(/&lt;/g, "<")
			.replace(/&gt;/g, ">")
			.replace(/&quot;/g, '"')
			.replace(/&#039;/g, "'")
			.replace(/&nbsp;/g, " ");
		// Collapse whitespace.
		plain = plain.replace(/\s+/g, " ").trim();
		return plain;
	}

	/**
	 * Count words in a plain-text string.
	 *
	 * @param {string} plain Normalised plain text.
	 * @returns {number} Word count.
	 */
	function countWords(plain) {
		if (!plain) return 0;
		var parts = plain.split(/\s+/).filter(function (w) {
			return w.length > 0;
		});
		return parts.length;
	}

	// -------------------------------------------------------------------------
	// Utility: REST API calls
	// -------------------------------------------------------------------------

	/**
	 * Make an authenticated REST API call.
	 *
	 * @param {string} method  HTTP method.
	 * @param {string} path    Path under the writersproof/v1 namespace.
	 * @param {Object} [body]  Request body (for POST).
	 * @returns {Promise<Object>} Parsed JSON response.
	 */
	function apiCall(method, path, body) {
		var url = REST_URL + path;
		var opts = {
			method: method,
			headers: {
				"Content-Type": "application/json",
				"X-WP-Nonce": NONCE,
			},
			credentials: "same-origin",
		};

		if (body && method !== "GET") {
			opts.body = JSON.stringify(body);
		}

		return fetch(url, opts).then(function (res) {
			return res.json().then(function (data) {
				if (!res.ok) {
					var msg =
						data && data.message
							? data.message
							: "HTTP " + res.status;
					return Promise.reject(new Error(msg));
				}
				return data;
			});
		});
	}

	// -------------------------------------------------------------------------
	// Indicator badge
	// -------------------------------------------------------------------------

	/**
	 * Inject (or update) a small status badge into the Gutenberg toolbar.
	 * Falls back to a fixed-position badge for classic editor.
	 */
	function ensureIndicator() {
		if (state.indicator) return;

		var badge = document.createElement("div");
		badge.id = "writersproof-indicator";
		badge.setAttribute("aria-live", "polite");
		badge.setAttribute("aria-label", "WritersProof witnessing status");

		// Try to attach to the editor header toolbar, else fall back to body.
		var toolbar = document.querySelector(
			".edit-post-header-toolbar, .editor-header__toolbar, #wp-toolbar",
		);
		if (toolbar) {
			toolbar.appendChild(badge);
		} else {
			badge.style.cssText =
				"position:fixed;bottom:20px;right:20px;z-index:99999;";
			document.body.appendChild(badge);
		}

		state.indicator = badge;
		updateIndicator();
	}

	/**
	 * Update indicator badge text and class to reflect current state.
	 */
	function updateIndicator() {
		var el = state.indicator;
		if (!el) return;

		el.className = "writersproof-badge writersproof-badge--" + state.status;

		var label =
			{
				none: "&#9997; WritersProof",
				active: "&#9997; Witnessing",
				stopped: "&#9997; Stopped",
				finalized: "&#9997; Finalized",
			}[state.status] || "&#9997; WritersProof";

		el.innerHTML = label;
	}

	// -------------------------------------------------------------------------
	// Core session management
	// -------------------------------------------------------------------------

	/**
	 * Start a WritersProof witnessing session for the current post.
	 *
	 * @returns {Promise<void>}
	 */
	function startSession() {
		if ("active" === state.status) return Promise.resolve();
		if (!HAS_KEY) {
			console.warn(
				"[WritersProof] API key not configured — witnessing disabled.",
			);
			return Promise.resolve();
		}

		return apiCall("POST", "/session/start", { post_id: POST_ID })
			.then(function (data) {
				state.sessionId = data.session_id || null;
				state.status = "active";
				state.sessionStartMs = performance.now();
				state.eventBuffer = [];
				updateIndicator();
				startTimers();
			})
			.catch(function (err) {
				console.error(
					"[WritersProof] Failed to start session:",
					err.message,
				);
			});
	}

	/**
	 * Stop the current witnessing session.
	 *
	 * @returns {Promise<void>}
	 */
	function stopSession() {
		if ("active" !== state.status) return Promise.resolve();

		// Flush any buffered events first.
		return flushEvents()
			.then(function () {
				return apiCall("POST", "/session/stop", { post_id: POST_ID });
			})
			.then(function () {
				state.status = "stopped";
				updateIndicator();
				stopTimers();
			})
			.catch(function (err) {
				console.error(
					"[WritersProof] Failed to stop session:",
					err.message,
				);
			});
	}

	// -------------------------------------------------------------------------
	// Timers
	// -------------------------------------------------------------------------

	/**
	 * Start the periodic event-flush and checkpoint timers.
	 */
	function startTimers() {
		stopTimers(); // Clear any stale timers.

		// Flush buffered events every 5 seconds.
		state.flushTimer = setInterval(flushEvents, 5000);

		// Create a checkpoint every INTERVAL seconds.
		state.checkpointTimer = setInterval(createCheckpoint, INTERVAL * 1000);
	}

	/**
	 * Stop periodic timers.
	 */
	function stopTimers() {
		if (state.flushTimer) {
			clearInterval(state.flushTimer);
			state.flushTimer = null;
		}
		if (state.checkpointTimer) {
			clearInterval(state.checkpointTimer);
			state.checkpointTimer = null;
		}
	}

	// -------------------------------------------------------------------------
	// Event buffering
	// -------------------------------------------------------------------------

	/**
	 * Record a timing event in the local buffer without transmitting it yet.
	 * No text content, keystrokes, or characters are captured.
	 *
	 * @param {string} type         Event type identifier.
	 * @param {Object} [extraFields] Additional numeric metadata fields.
	 */
	function recordEvent(type, extraFields) {
		if ("active" !== state.status) return;

		var event = Object.assign(
			{
				type: type,
				timestamp: Date.now(),
			},
			extraFields || {},
		);

		state.eventBuffer.push(event);
	}

	/**
	 * Flush the event buffer to the REST API.
	 *
	 * @returns {Promise<void>}
	 */
	function flushEvents() {
		if (state.eventBuffer.length === 0 || "active" !== state.status) {
			return Promise.resolve();
		}

		var batch = state.eventBuffer.slice();
		state.eventBuffer = [];

		return apiCall("POST", "/session/events", {
			post_id: POST_ID,
			events: batch,
		}).catch(function (err) {
			// On failure, re-queue the events (up to 200 max to prevent memory growth).
			console.warn(
				"[WritersProof] Event flush failed, re-queuing:",
				err.message,
			);
			state.eventBuffer = batch.concat(state.eventBuffer).slice(0, 200);
		});
	}

	// -------------------------------------------------------------------------
	// Checkpoint
	// -------------------------------------------------------------------------

	/**
	 * Create a checkpoint using the current content hash and counts.
	 *
	 * @returns {Promise<void>}
	 */
	function createCheckpoint() {
		if ("active" !== state.status || !state.lastHash)
			return Promise.resolve();

		return apiCall("POST", "/session/checkpoint", {
			post_id: POST_ID,
			contentHash: state.lastHash,
			wordCount: state.lastWordCount,
			charCount: 0, // updated below from full snapshot when possible.
			metadata: {
				trigger: "interval",
				blockCount: state.lastBlockCount,
			},
		}).catch(function (err) {
			console.warn("[WritersProof] Checkpoint failed:", err.message);
		});
	}

	// -------------------------------------------------------------------------
	// Content observation
	// -------------------------------------------------------------------------

	/**
	 * Called whenever the editor content changes. Hashes the new content and
	 * records a 'content_change' timing event if the hash differs from the
	 * last observed hash.
	 *
	 * @param {string} rawContent    Serialised block content or plain text.
	 * @param {number} [blockCount] Block count (Gutenberg only).
	 * @returns {Promise<void>}
	 */
	function onContentChange(rawContent, blockCount) {
		var plain = normaliseContent(rawContent);
		var words = countWords(plain);

		return sha256(plain).then(function (hash) {
			if (hash === state.lastHash) return;

			var prevHash = state.lastHash;
			state.lastHash = hash;
			state.lastWordCount = words;
			state.lastBlockCount = blockCount || 0;

			if (prevHash !== null) {
				recordEvent("content_change", {
					wordCount: words,
					blockCount: blockCount || 0,
				});
			}
		});
	}

	// -------------------------------------------------------------------------
	// Gutenberg (block editor) integration
	// -------------------------------------------------------------------------

	/**
	 * Bootstrap Gutenberg integration.
	 *
	 * Uses the wp.data subscribe API to observe editor store changes.
	 * Registers a sidebar plugin panel with start/stop controls.
	 */
	function initGutenberg() {
		var wpData = wp.data;
		var wpPlugins = wp.plugins;
		var wpEditPost = wp.editPost;
		var wpElement = wp.element;
		var wpComponents = wp.components;
		var wpI18n = wp.i18n;
		var __ = wpI18n.__;

		// -- Plugin sidebar --

		var el = wpElement.createElement;

		/**
		 * WritersProof sidebar panel component.
		 *
		 * @returns {wp.element.Element}
		 */
		function WritersProofPanel() {
			var useSelect = wpData.useSelect;
			var useState = wpElement.useState;
			var useEffect = wpElement.useEffect;

			// React-like state for this component.
			var statusState = useState(state.status);
			var uiStatus = statusState[0];
			var setUiStatus = statusState[1];

			var busyState = useState(false);
			var busy = busyState[0];
			var setBusy = busyState[1];

			var msgState = useState("");
			var msg = msgState[0];
			var setMsg = msgState[1];

			// Sync component state with module state every 2s.
			useEffect(function () {
				var t = setInterval(function () {
					setUiStatus(state.status);
				}, 2000);
				return function () {
					clearInterval(t);
				};
			}, []);

			function handleStart() {
				setBusy(true);
				setMsg("");
				startSession()
					.then(function () {
						setUiStatus(state.status);
					})
					.catch(function () {
						setMsg(__("Failed to start session.", "writersproof"));
					})
					.finally(function () {
						setBusy(false);
					});
			}

			function handleStop() {
				setBusy(true);
				setMsg("");
				stopSession()
					.then(function () {
						setUiStatus(state.status);
					})
					.catch(function () {
						setMsg(__("Failed to stop session.", "writersproof"));
					})
					.finally(function () {
						setBusy(false);
					});
			}

			var statusLabel =
				{
					none: __("Not started", "writersproof"),
					active: __("Witnessing active", "writersproof"),
					stopped: __("Stopped", "writersproof"),
					finalized: __("Finalized", "writersproof"),
				}[uiStatus] || __("Unknown", "writersproof");

			var statusClass =
				"writersproof-status-" +
				("active" === uiStatus ? "green" : "gray");

			return el(
				wpComponents.PanelBody,
				{
					title: __("WritersProof Attestation", "writersproof"),
					initialOpen: true,
					className: "writersproof-sidebar-panel",
				},
				!HAS_KEY
					? el(
							wpComponents.Notice,
							{ status: "warning", isDismissible: false },
							__(
								"API key not configured. Visit Settings > WritersProof.",
								"writersproof",
							),
						)
					: el(
							wpElement.Fragment,
							null,
							el(
								"div",
								{ className: "writersproof-panel-status" },
								el(
									"span",
									{
										className:
											"writersproof-status-badge " +
											statusClass,
									},
									statusLabel,
								),
							),
							"active" !== uiStatus
								? el(
										wpComponents.Button,
										{
											variant: "primary",
											isBusy: busy,
											disabled:
												busy ||
												!HAS_KEY ||
												"finalized" === uiStatus,
											onClick: handleStart,
											className: "writersproof-panel-btn",
										},
										__("Start Witnessing", "writersproof"),
									)
								: el(
										wpComponents.Button,
										{
											variant: "secondary",
											isBusy: busy,
											disabled: busy,
											onClick: handleStop,
											className: "writersproof-panel-btn",
										},
										__("Stop Witnessing", "writersproof"),
									),
							msg
								? el(
										"p",
										{ className: "writersproof-panel-msg" },
										msg,
									)
								: null,
						),
			);
		}

		// Register the plugin sidebar with the block editor.
		wpPlugins.registerPlugin("writersproof", {
			render: function () {
				return el(
					wpEditPost.PluginSidebar,
					{
						name: "writersproof-sidebar",
						title: __("WritersProof", "writersproof"),
						icon: "edit",
					},
					el(WritersProofPanel, null),
				);
			},
		});

		// -- Store subscription --

		var prevContent = null;
		var prevBlockCount = 0;
		var prevIsSaving = false;

		var unsubscribe = wpData.subscribe(function () {
			var editorStore = wpData.select("core/editor");
			if (!editorStore) return;

			// Observe content changes.
			var blocks = editorStore.getBlocks ? editorStore.getBlocks() : [];
			var content = editorStore.getEditedPostContent
				? editorStore.getEditedPostContent()
				: "";
			var blockCount = Array.isArray(blocks) ? blocks.length : 0;

			if (content !== prevContent || blockCount !== prevBlockCount) {
				prevContent = content;
				prevBlockCount = blockCount;
				onContentChange(content, blockCount);
			}

			// Observe autosave trigger to create a checkpoint.
			var isSaving = editorStore.isSavingPost
				? editorStore.isSavingPost()
				: false;
			if (isSaving && !prevIsSaving && "active" === state.status) {
				createCheckpoint();
				flushEvents();
			}
			prevIsSaving = isSaving;
		});

		// -- Paste events --

		// Attach paste listener to the editor's contenteditable (the iframe or
		// the main document contenteditable, depending on WP version).
		function attachPasteListener(root) {
			root.addEventListener(
				"paste",
				function (e) {
					if ("active" !== state.status) return;

					// Capture only timing metadata — not the pasted text.
					var dataTypes = e.clipboardData
						? Array.from(e.clipboardData.types)
						: [];

					recordEvent("paste", {
						hasText: dataTypes.indexOf("text/plain") !== -1 ? 1 : 0,
						hasHtml: dataTypes.indexOf("text/html") !== -1 ? 1 : 0,
						hasFiles: dataTypes.indexOf("Files") !== -1 ? 1 : 0,
					});
				},
				true,
			);
		}

		attachPasteListener(document);

		// Attempt to attach to an iframe (older WP Gutenberg builds).
		var ifr = document.querySelector('iframe[name="editor-canvas"]');
		if (ifr) {
			ifr.addEventListener("load", function () {
				try {
					attachPasteListener(
						ifr.contentDocument || ifr.contentWindow.document,
					);
				} catch (_e) {
					// Cross-origin — cannot attach; ignore.
				}
			});
		}

		// -- Auto-start --

		ensureIndicator();

		if (AUTO_START && HAS_KEY) {
			// Defer start until after the editor is ready.
			var readyCheck = setInterval(function () {
				var ed = wp.data.select("core/editor");
				if (ed && ed.isCleanNewPost) {
					clearInterval(readyCheck);
					startSession();
				}
			}, 300);
		}
	}

	// -------------------------------------------------------------------------
	// Classic editor (TinyMCE) integration
	// -------------------------------------------------------------------------

	/**
	 * Bootstrap Classic editor integration.
	 *
	 * Hooks into the TinyMCE instance to capture timing events from
	 * keydown and paste without reading actual content.
	 */
	function initClassicEditor() {
		if (typeof tinymce === "undefined") return;

		function attachToEditor(editor) {
			var lastEventMs = 0;

			editor.on("keydown", function () {
				if ("active" !== state.status) return;
				var now = Date.now();
				var interval = lastEventMs > 0 ? now - lastEventMs : 0;
				lastEventMs = now;
				recordEvent("keydown", { intervalMs: interval });
			});

			editor.on("paste", function () {
				if ("active" !== state.status) return;
				recordEvent("paste", {});
			});

			editor.on("change", function () {
				if ("active" !== state.status) return;
				var content = editor.getContent({ format: "text" }) || "";
				// Re-hash on text change; do not transmit the text itself.
				onContentChange(content, 0);
			});

			editor.on("init", function () {
				ensureIndicator();
				if (AUTO_START && HAS_KEY) {
					startSession();
				}
			});
		}

		// Attach to already-initialised editors.
		tinymce.editors.forEach(function (ed) {
			attachToEditor(ed);
		});

		// Attach to future editors (e.g. content + excerpt).
		if (tinymce.on) {
			tinymce.on("AddEditor", function (e) {
				attachToEditor(e.editor);
			});
		}
	}

	// -------------------------------------------------------------------------
	// Keyboard timing on the document (Gutenberg plain-text blocks etc.)
	// -------------------------------------------------------------------------

	/**
	 * Attach a document-level keydown listener to capture inter-keystroke
	 * interval timing for blocks that are contenteditable rather than
	 * delegating to TinyMCE (e.g. Gutenberg paragraph blocks).
	 *
	 * Privacy: only the timestamp / interval is recorded, never which key.
	 */
	function attachDocumentKeyListener() {
		var lastKeyMs = 0;

		document.addEventListener(
			"keydown",
			function (e) {
				if ("active" !== state.status) return;

				// Skip modifier-only, navigation, and function keys — these carry
				// no writing-timing signal.
				var key = e.key || "";
				if (
					key.startsWith("Arrow") ||
					key.startsWith("F") ||
					key === "Control" ||
					key === "Alt" ||
					key === "Meta" ||
					key === "Shift" ||
					key === "Tab" ||
					key === "CapsLock"
				) {
					return;
				}

				var now = Date.now();
				var interval = lastKeyMs > 0 ? now - lastKeyMs : 0;
				lastKeyMs = now;

				recordEvent("keydown", { intervalMs: interval });
			},
			true,
		);
	}

	// -------------------------------------------------------------------------
	// Entry point
	// -------------------------------------------------------------------------

	/**
	 * Determine which editor environment is active and initialise accordingly.
	 */
	function boot() {
		if (!POST_ID) return; // Safety: don't run outside a post edit screen.

		attachDocumentKeyListener();

		if (typeof wp !== "undefined" && wp.data && wp.plugins && wp.editPost) {
			initGutenberg();
		} else {
			// Classic editor.
			if (document.readyState === "loading") {
				document.addEventListener(
					"DOMContentLoaded",
					initClassicEditor,
				);
			} else {
				initClassicEditor();
			}
		}
	}

	// Run as soon as the script is evaluated (dependencies are already loaded).
	boot();
})();
