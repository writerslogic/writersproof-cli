<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * WritersProof GDPR privacy provider.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

namespace local_writersproof\privacy;

defined('MOODLE_INTERNAL') || die();

use core_privacy\local\metadata\collection;
use core_privacy\local\request\approved_contextlist;
use core_privacy\local\request\approved_userlist;
use core_privacy\local\request\contextlist;
use core_privacy\local\request\userlist;
use core_privacy\local\request\writer;

/**
 * Implements Moodle's privacy API for GDPR compliance.
 *
 * Data stored locally:
 *   - local_writersproof_sessions: session metadata per user/item, including
 *     the remote session ID, content hash, word count, and evidence score.
 *
 * Data sent to the external WritersProof API:
 *   - An opaque user identifier ('moodle:{userid}')
 *   - SHA-256 hashes of content (not the content itself)
 *   - Typing timing metadata (timestamps, durations, no characters)
 *   - Platform/version metadata
 */
class provider implements
    \core_privacy\local\metadata\provider,
    \core_privacy\local\request\plugin\provider,
    \core_privacy\local\request\core_userlist_provider {

    /**
     * Describe all user data stored and shared by this plugin.
     *
     * @param  collection $collection
     * @return collection
     */
    public static function get_metadata(collection $collection): collection {
        // Local database table.
        $collection->add_database_table(
            'local_writersproof_sessions',
            [
                'userid'          => 'privacy:metadata:local_writersproof_sessions:userid',
                'contextid'       => 'privacy:metadata:local_writersproof_sessions:contextid',
                'cmid'            => 'privacy:metadata:local_writersproof_sessions:cmid',
                'itemid'          => 'privacy:metadata:local_writersproof_sessions:itemid',
                'itemtype'        => 'privacy:metadata:local_writersproof_sessions:itemtype',
                'sessionid'       => 'privacy:metadata:local_writersproof_sessions:sessionid',
                'status'          => 'privacy:metadata:local_writersproof_sessions:status',
                'contenthash'     => 'privacy:metadata:local_writersproof_sessions:contenthash',
                'wordcount'       => 'privacy:metadata:local_writersproof_sessions:wordcount',
                'evidencescore'   => 'privacy:metadata:local_writersproof_sessions:evidencescore',
                'checkpointcount' => 'privacy:metadata:local_writersproof_sessions:checkpointcount',
                'timecreated'     => 'privacy:metadata:local_writersproof_sessions:timecreated',
                'timemodified'    => 'privacy:metadata:local_writersproof_sessions:timemodified',
            ],
            'privacy:metadata:local_writersproof_sessions'
        );

        // External WritersProof API.
        $collection->add_external_location_link(
            'writerslogic_api',
            [
                'userid'        => 'privacy:metadata:external:userid',
                'content_hash'  => 'privacy:metadata:external:content_hash',
                'timing_events' => 'privacy:metadata:external:timing_events',
                'platform'      => 'privacy:metadata:external:platform',
            ],
            'privacy:metadata:external'
        );

        return $collection;
    }

    // =========================================================================
    // Context discovery
    // =========================================================================

    /**
     * Get all contexts that contain user data for the given user ID.
     *
     * @param  int         $userid
     * @return contextlist
     */
    public static function get_contexts_for_userid(int $userid): contextlist {
        $contextlist = new contextlist();
        $contextlist->add_from_sql(
            'SELECT DISTINCT contextid
               FROM {local_writersproof_sessions}
              WHERE userid = :userid',
            ['userid' => $userid]
        );
        return $contextlist;
    }

    /**
     * Get all users who have data in a given context.
     *
     * @param  userlist $userlist
     */
    public static function get_users_in_context(userlist $userlist): void {
        $context = $userlist->get_context();
        $userlist->add_from_sql(
            'userid',
            'SELECT userid FROM {local_writersproof_sessions} WHERE contextid = :contextid',
            ['contextid' => $context->id]
        );
    }

    // =========================================================================
    // Data export
    // =========================================================================

    /**
     * Export all user data for the given approved context list.
     *
     * @param  approved_contextlist $contextlist
     */
    public static function export_user_data(approved_contextlist $contextlist): void {
        global $DB;
        $userid = (int) $contextlist->get_user()->id;

        foreach ($contextlist->get_contexts() as $context) {
            $sessions = $DB->get_records('local_writersproof_sessions', [
                'userid'    => $userid,
                'contextid' => $context->id,
            ]);

            if (empty($sessions)) {
                continue;
            }

            $export = array_map(function ($session) {
                return [
                    'item_type'        => $session->itemtype,
                    'item_id'          => $session->itemid,
                    'remote_session'   => $session->sessionid ?? get_string('none'),
                    'status'           => $session->status,
                    'content_hash'     => $session->contenthash ?? get_string('none'),
                    'word_count'       => (int) $session->wordcount,
                    'evidence_score'   => $session->evidencescore,
                    'checkpoint_count' => (int) $session->checkpointcount,
                    'time_created'     => \core_privacy\local\request\transform::datetime($session->timecreated),
                    'time_modified'    => \core_privacy\local\request\transform::datetime($session->timemodified),
                ];
            }, $sessions);

            writer::with_context($context)->export_data(
                [get_string('pluginname', 'local_writersproof')],
                (object) ['sessions' => array_values($export)]
            );
        }
    }

    // =========================================================================
    // Data deletion
    // =========================================================================

    /**
     * Delete all user data for all users in a given context.
     *
     * @param  \context $context
     */
    public static function delete_data_for_all_users_in_context(\context $context): void {
        global $DB;
        $DB->delete_records('local_writersproof_sessions', ['contextid' => $context->id]);
    }

    /**
     * Delete all user data for a specific user in the approved contexts.
     *
     * @param  approved_contextlist $contextlist
     */
    public static function delete_data_for_user(approved_contextlist $contextlist): void {
        global $DB;
        $userid = (int) $contextlist->get_user()->id;
        foreach ($contextlist->get_contexts() as $context) {
            $DB->delete_records('local_writersproof_sessions', [
                'userid'    => $userid,
                'contextid' => $context->id,
            ]);
        }
    }

    /**
     * Delete data for multiple users within a single context.
     *
     * @param  approved_userlist $userlist
     */
    public static function delete_data_for_users(approved_userlist $userlist): void {
        global $DB;
        $context = $userlist->get_context();
        $userids = $userlist->get_userids();
        if (empty($userids)) {
            return;
        }
        [$insql, $inparams] = $DB->get_in_or_equal($userids, SQL_PARAMS_NAMED);
        $DB->delete_records_select(
            'local_writersproof_sessions',
            "contextid = :contextid AND userid $insql",
            array_merge(['contextid' => $context->id], $inparams)
        );
    }
}
