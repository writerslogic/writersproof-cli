=== WritersProof ===
Contributors: writerslogic
Tags: authorship, attestation, content verification, proof of writing, cryptography
Requires at least: 6.0
Tested up to: 6.7
Stable tag: 1.0.0
Requires PHP: 8.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Cryptographic authorship attestation for WordPress content. Prove that a human wrote your posts with verifiable behavioral evidence.

== Description ==

WritersProof integrates your WordPress site with the WritersProof API to produce cryptographically signed evidence that a human authored your content. It captures *timing metadata* (not actual keystrokes or text) during editing sessions and packages that evidence into signed attestation packets anchored to your content.

**How it works**

1. Open any post or page for editing. WritersProof automatically starts a witnessing session (configurable).
2. As you write, the plugin records inter-keystroke interval timing and content hashes — never the actual characters you type.
3. Periodic checkpoints create a cryptographic chain linking your writing process to your content.
4. When you publish, the session is finalized and an evidence score is attached to the post.
5. Readers and platforms can verify your authorship via the WritersProof verification portal.

**Privacy**

WritersProof is designed with privacy as a core constraint:

* No actual text content, keystrokes, or clipboard data is ever transmitted.
* Only timing intervals, word/character counts, and SHA-256 hashes of content are sent to the API.
* All evidence is scoped to your API key and post ID.
* You control which post types are monitored.

**Supported editors**

* Gutenberg block editor (primary, full sidebar panel)
* Classic editor / TinyMCE (fallback support)

**Requirements**

* A WritersProof API key from [writerslogic.com](https://writerslogic.com)
* WordPress 6.0 or later
* PHP 8.0 or later
* HTTPS (required for SubtleCrypto browser API used for client-side hashing)

== Installation ==

1. Upload the `writersproof` folder to the `/wp-content/plugins/` directory, or install directly via the WordPress plugin installer.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Go to **Settings > WritersProof** and enter your API key from [writerslogic.com/dashboard](https://writerslogic.com/dashboard).
4. Configure which post types to monitor and set your preferred checkpoint interval.
5. Open any post for editing — WritersProof will begin witnessing automatically if **Auto-start** is enabled.

== Frequently Asked Questions ==

= Do I need an account to use this plugin? =

Yes. You need a free or paid WritersProof account at [writerslogic.com](https://writerslogic.com) to obtain an API key.

= Does WritersProof store my content? =

No. The plugin only sends SHA-256 hashes of your content (not the content itself), plus word/character counts and timing intervals. Your actual writing never leaves your server.

= Will this slow down my editor? =

No. All API calls are asynchronous and batched. Events are buffered locally and sent every 5 seconds. The plugin uses the browser's native SubtleCrypto API for hashing — no heavy JavaScript libraries are loaded.

= Which post types can I monitor? =

Any public post type registered in your WordPress installation, including posts, pages, and custom post types.

= What happens if the API is unreachable? =

The plugin retries up to 3 times with exponential backoff. If the API remains unreachable, the editor continues to function normally — witnessing is best-effort and will not block saving or publishing.

= Can I start or stop witnessing manually? =

Yes. The Gutenberg sidebar panel has Start/Stop buttons. The meta box on the post edit screen also provides manual controls.

= How is my API key stored? =

Your API key is stored in the WordPress options table using the standard `get_option`/`update_option` API. It is never exposed in JavaScript or page source — only the last 4 characters are shown in the settings UI for confirmation.

= Does this work with the Classic editor plugin? =

Yes. When the Gutenberg block editor is not detected, WritersProof falls back to TinyMCE event hooks.

= Is HTTPS required? =

Yes. The browser's `SubtleCrypto` API (used for client-side SHA-256 hashing) is only available on secure origins (HTTPS or localhost). All WordPress sites should be running HTTPS in production.

== Screenshots ==

1. Settings page — configure your API key, checkpoint interval, and monitored post types.
2. Gutenberg sidebar panel — real-time witnessing status with start/stop controls.
3. Post meta box — session ID, evidence score, and quick actions on the post edit screen.

== Changelog ==

= 1.0.0 =
* Initial release.
* Gutenberg block editor integration with sidebar panel.
* Classic editor / TinyMCE fallback.
* REST API endpoints for session management and evidence retrieval.
* SHA-256 content hashing via browser SubtleCrypto (no external dependencies).
* 3-retry HTTP client with exponential backoff and Retry-After support.
* Settings page with connection test.
* Post meta box with status display and manual controls.
* Privacy-first design: no text content transmitted.

== Upgrade Notice ==

= 1.0.0 =
Initial release — no upgrade steps required.
