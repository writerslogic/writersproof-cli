<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Moodle event observer for WritersProof authorship attestation.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

namespace local_writersproof;

defined('MOODLE_INTERNAL') || die();

/**
 * Handles Moodle events for content creation and update across supported modules.
 *
 * Each handler follows the same lifecycle:
 *   1. Check plugin is enabled and API key is configured.
 *   2. Capture a content snapshot.
 *   3. Open or reuse an existing local session record.
 *   4. Start a remote WritersProof session if none exists.
 *   5. Submit a checkpoint with the current content hash.
 *   6. Finalize the session on final submission events.
 */
class observer {

    // -------------------------------------------------------------------------
    // Assignment events
    // -------------------------------------------------------------------------

    /**
     * Handle assignment final submission (assessable_submitted).
     *
     * @param \mod_assign\event\assessable_submitted $event
     */
    public static function submission_created(\mod_assign\event\assessable_submitted $event): void {
        if (!self::is_enabled(monitor::TYPE_ASSIGNMENT_SUBMISSION)) {
            return;
        }
        try {
            $submissionid = (int) $event->other['submissionid'];
            self::handle_content_event(
                $event->userid,
                $event->contextid,
                $event->get_context()->instanceid ?? null,
                monitor::TYPE_ASSIGNMENT_SUBMISSION,
                $submissionid,
                finalize: true
            );
        } catch (\Throwable $e) {
            self::log_error('submission_created', $event->userid, $e);
        }
    }

    /**
     * Handle assignment submission draft update.
     *
     * @param \mod_assign\event\submission_updated $event
     */
    public static function submission_updated(\mod_assign\event\submission_updated $event): void {
        if (!self::is_enabled(monitor::TYPE_ASSIGNMENT_SUBMISSION)) {
            return;
        }
        try {
            $submissionid = (int) ($event->other['submissionid'] ?? $event->objectid);
            self::handle_content_event(
                $event->userid,
                $event->contextid,
                $event->get_context()->instanceid ?? null,
                monitor::TYPE_ASSIGNMENT_SUBMISSION,
                $submissionid,
                finalize: false
            );
        } catch (\Throwable $e) {
            self::log_error('submission_updated', $event->userid, $e);
        }
    }

    // -------------------------------------------------------------------------
    // Forum events
    // -------------------------------------------------------------------------

    /**
     * Handle forum post creation.
     *
     * @param \mod_forum\event\post_created $event
     */
    public static function forum_post_created(\mod_forum\event\post_created $event): void {
        if (!self::is_enabled(monitor::TYPE_FORUM_POST)) {
            return;
        }
        try {
            self::handle_content_event(
                $event->userid,
                $event->contextid,
                $event->get_context()->instanceid ?? null,
                monitor::TYPE_FORUM_POST,
                (int) $event->objectid,
                finalize: true
            );
        } catch (\Throwable $e) {
            self::log_error('forum_post_created', $event->userid, $e);
        }
    }

    /**
     * Handle forum post edit.
     *
     * @param \mod_forum\event\post_updated $event
     */
    public static function forum_post_updated(\mod_forum\event\post_updated $event): void {
        if (!self::is_enabled(monitor::TYPE_FORUM_POST)) {
            return;
        }
        try {
            self::handle_content_event(
                $event->userid,
                $event->contextid,
                $event->get_context()->instanceid ?? null,
                monitor::TYPE_FORUM_POST,
                (int) $event->objectid,
                finalize: false
            );
        } catch (\Throwable $e) {
            self::log_error('forum_post_updated', $event->userid, $e);
        }
    }

    // -------------------------------------------------------------------------
    // Wiki events
    // -------------------------------------------------------------------------

    /**
     * Handle wiki page creation.
     *
     * @param \mod_wiki\event\page_created $event
     */
    public static function wiki_page_created(\mod_wiki\event\page_created $event): void {
        if (!self::is_enabled(monitor::TYPE_WIKI_PAGE)) {
            return;
        }
        try {
            self::handle_content_event(
                $event->userid,
                $event->contextid,
                $event->get_context()->instanceid ?? null,
                monitor::TYPE_WIKI_PAGE,
                (int) $event->objectid,
                finalize: false
            );
        } catch (\Throwable $e) {
            self::log_error('wiki_page_created', $event->userid, $e);
        }
    }

    /**
     * Handle wiki page update (saved revision).
     *
     * @param \mod_wiki\event\page_updated $event
     */
    public static function wiki_page_updated(\mod_wiki\event\page_updated $event): void {
        if (!self::is_enabled(monitor::TYPE_WIKI_PAGE)) {
            return;
        }
        try {
            self::handle_content_event(
                $event->userid,
                $event->contextid,
                $event->get_context()->instanceid ?? null,
                monitor::TYPE_WIKI_PAGE,
                (int) $event->objectid,
                finalize: false
            );
        } catch (\Throwable $e) {
            self::log_error('wiki_page_updated', $event->userid, $e);
        }
    }

    // -------------------------------------------------------------------------
    // Core event handler
    // -------------------------------------------------------------------------

    /**
     * Central handler shared by all event callbacks.
     *
     * @param  int      $userid     Moodle user ID.
     * @param  int      $contextid  Moodle context ID.
     * @param  int|null $cmid       Course module ID (may be null for some contexts).
     * @param  string   $itemtype   Content type constant.
     * @param  int      $itemid     Content primary key.
     * @param  bool     $finalize   Whether to finalize the session after this event.
     */
    private static function handle_content_event(
        int $userid,
        int $contextid,
        ?int $cmid,
        string $itemtype,
        int $itemid,
        bool $finalize
    ): void {
        $monitor = new monitor();
        $client  = new client();

        // Capture current content snapshot.
        $snapshot = $monitor->capture_snapshot($itemtype, $itemid);

        // If content is empty there is nothing to attest.
        if ($snapshot['wordcount'] === 0) {
            return;
        }

        // Find or create the local session record.
        $record = $monitor->find_session_record($userid, $itemtype, $itemid);
        if ($record === false) {
            $record = $monitor->create_session_record(
                $userid, $contextid, $cmid, $itemid, $itemtype, $snapshot
            );
        }

        // Skip if already finalized successfully — do not reopen.
        if ($record->status === 'verified') {
            return;
        }

        // Start a remote session if we do not have one yet.
        if (empty($record->sessionid)) {
            $user = \core_user::get_user($userid, '*', MUST_EXIST);
            $response = $client->create_session([
                'user_id'  => 'moodle:' . $userid,
                'context'  => [
                    'platform'    => 'moodle',
                    'item_type'   => $itemtype,
                    'item_id'     => $itemid,
                    'context_id'  => $contextid,
                ],
                'metadata' => [
                    'moodle_version' => $GLOBALS['CFG']->version ?? 'unknown',
                    'plugin_version' => '1.0.0',
                ],
            ]);
            $remoteid = (string) ($response['session_id'] ?? '');
            if ($remoteid === '') {
                throw new api_exception('API did not return a session_id.');
            }
            $monitor->set_remote_session_id($record->id, $remoteid);
            $record->sessionid = $remoteid;
        }

        // Create a content checkpoint.
        $client->create_checkpoint(
            $record->sessionid,
            $snapshot['contenthash'],
            $snapshot['wordcount'],
            $snapshot['charcount']
        );
        $monitor->increment_checkpoint_count($record->id);

        // Update local snapshot.
        $monitor->update_session_record(
            $record->id,
            $snapshot,
            $finalize ? 'finalized' : 'active'
        );

        // Finalize on terminal submission events.
        if ($finalize && $record->status !== 'finalized') {
            $response = $client->finalize_session(
                $record->sessionid,
                $snapshot['contenthash'],
                $snapshot['wordcount']
            );
            $score = isset($response['score']) ? (float) $response['score'] : 0.0;
            $monitor->set_evidence_score($record->id, $score);
        }
    }

    // -------------------------------------------------------------------------
    // Guard helpers
    // -------------------------------------------------------------------------

    /**
     * Check whether the plugin is enabled and the given content type is watched.
     *
     * @param  string $itemtype
     * @return bool
     */
    private static function is_enabled(string $itemtype): bool {
        if (!get_config('local_writersproof', 'enabled')) {
            return false;
        }
        $setting = match ($itemtype) {
            monitor::TYPE_ASSIGNMENT_SUBMISSION => 'witness_assignments',
            monitor::TYPE_FORUM_POST            => 'witness_forums',
            monitor::TYPE_WIKI_PAGE             => 'witness_wikis',
            default                             => null,
        };
        return $setting !== null && (bool) get_config('local_writersproof', $setting);
    }

    /**
     * Write a debugging/warning log entry; never throws.
     *
     * @param  string     $handler  Observer method name.
     * @param  int        $userid   Affected user.
     * @param  \Throwable $e        Exception to log.
     */
    private static function log_error(string $handler, int $userid, \Throwable $e): void {
        debugging(
            sprintf(
                '[local_writersproof] %s (userid=%d): %s',
                $handler,
                $userid,
                $e->getMessage()
            ),
            DEBUG_DEVELOPER
        );
        // Log at warning level so site admins can monitor failures without
        // surfacing stack traces to end users.
        if (function_exists('mtrace') && CLI_SCRIPT) {
            mtrace('[local_writersproof] ' . $handler . ': ' . $e->getMessage());
        }
    }
}
