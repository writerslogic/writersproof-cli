<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * WritersProof external (AJAX) API functions.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

namespace local_writersproof\external;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir . '/externallib.php');

use external_api;
use external_function_parameters;
use external_single_structure;
use external_multiple_structure;
use external_value;
use local_writersproof\api_exception;
use local_writersproof\client;
use local_writersproof\monitor;

/**
 * External functions for the editor-side AMD module to call via AJAX.
 *
 * Each method validates parameters, checks capabilities, then calls the
 * {@see \local_writersproof\client} to communicate with the WritersProof API.
 */
class session_api extends external_api {

    // =========================================================================
    // start_session
    // =========================================================================

    /**
     * Parameter definition for start_session.
     *
     * @return external_function_parameters
     */
    public static function start_session_parameters(): external_function_parameters {
        return new external_function_parameters([
            'cmid'     => new external_value(PARAM_INT,  'Course module ID'),
            'itemtype' => new external_value(PARAM_ALPHANUMEXT, 'Item type (assignment_submission|forum_post|wiki_page)'),
            'itemid'   => new external_value(PARAM_INT,  'Content item ID'),
        ]);
    }

    /**
     * Return definition for start_session.
     *
     * @return external_single_structure
     */
    public static function start_session_returns(): external_single_structure {
        return new external_single_structure([
            'sessionid' => new external_value(PARAM_ALPHANUMEXT, 'WritersProof session ID', VALUE_OPTIONAL),
            'status'    => new external_value(PARAM_ALPHA, 'Session status'),
        ]);
    }

    /**
     * Start or retrieve an existing WritersProof session for a content item.
     *
     * @param  int    $cmid
     * @param  string $itemtype
     * @param  int    $itemid
     * @return array  {sessionid, status}
     */
    public static function start_session(int $cmid, string $itemtype, int $itemid): array {
        global $USER;

        $params = self::validate_parameters(self::start_session_parameters(), [
            'cmid'     => $cmid,
            'itemtype' => $itemtype,
            'itemid'   => $itemid,
        ]);
        $cmid     = (int) $params['cmid'];
        $itemtype = self::validate_item_type($params['itemtype']);
        $itemid   = (int) $params['itemid'];

        $context = \context_module::instance($cmid);
        self::validate_context($context);
        require_capability('local/writersproof:view', $context);

        if (!get_config('local_writersproof', 'enabled')) {
            return ['sessionid' => null, 'status' => 'disabled'];
        }

        $monitor = new monitor();
        $record  = $monitor->find_session_record((int) $USER->id, $itemtype, $itemid);

        if ($record !== false && !empty($record->sessionid)) {
            return [
                'sessionid' => $record->sessionid,
                'status'    => $record->status,
            ];
        }

        try {
            $snapshot = $monitor->capture_snapshot($itemtype, $itemid);
            if ($record === false) {
                $record = $monitor->create_session_record(
                    (int) $USER->id, $context->id, $cmid, $itemid, $itemtype, $snapshot
                );
            }

            $client = new client();
            $response = $client->create_session([
                'user_id'  => 'moodle:' . $USER->id,
                'context'  => [
                    'platform'   => 'moodle',
                    'item_type'  => $itemtype,
                    'item_id'    => $itemid,
                    'context_id' => $context->id,
                ],
                'metadata' => ['plugin_version' => '1.0.0'],
            ]);

            $remoteid = (string) ($response['session_id'] ?? '');
            if ($remoteid === '') {
                throw new api_exception('API returned empty session_id.');
            }

            $monitor->set_remote_session_id($record->id, $remoteid);
            return ['sessionid' => $remoteid, 'status' => 'active'];

        } catch (api_exception $e) {
            debugging('[local_writersproof] start_session failed: ' . $e->getMessage(), DEBUG_DEVELOPER);
            return ['sessionid' => null, 'status' => 'failed'];
        }
    }

    // =========================================================================
    // submit_events
    // =========================================================================

    /**
     * Parameter definition for submit_events.
     *
     * @return external_function_parameters
     */
    public static function submit_events_parameters(): external_function_parameters {
        return new external_function_parameters([
            'sessionid'   => new external_value(PARAM_ALPHANUMEXT, 'WritersProof session ID'),
            'events_json' => new external_value(PARAM_RAW, 'JSON-encoded array of editor event objects'),
        ]);
    }

    /**
     * Return definition for submit_events.
     *
     * @return external_single_structure
     */
    public static function submit_events_returns(): external_single_structure {
        return new external_single_structure([
            'success'  => new external_value(PARAM_BOOL, 'Whether events were accepted'),
            'accepted' => new external_value(PARAM_INT,  'Number of events accepted', VALUE_OPTIONAL),
        ]);
    }

    /**
     * Submit editor events to an active WritersProof session.
     *
     * @param  string $sessionid    Remote session ID.
     * @param  string $events_json  JSON-encoded event array.
     * @return array  {success, accepted}
     */
    public static function submit_events(string $sessionid, string $events_json): array {
        global $USER;

        $params = self::validate_parameters(self::submit_events_parameters(), [
            'sessionid'   => $sessionid,
            'events_json' => $events_json,
        ]);

        // Validate the session belongs to the current user.
        $record = self::require_user_session($params['sessionid'], (int) $USER->id);
        $context = \context::instance_by_id($record->contextid);
        self::validate_context($context);
        require_capability('local/writersproof:view', $context);

        // Decode and validate the events array.
        try {
            $events = json_decode($params['events_json'], true, 10, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \invalid_parameter_exception('events_json is not valid JSON.');
        }
        if (!is_array($events) || count($events) === 0) {
            throw new \invalid_parameter_exception('events_json must be a non-empty array.');
        }
        if (count($events) > 1000) {
            throw new \invalid_parameter_exception('events_json exceeds maximum batch size of 1000.');
        }

        // Strip any character-level content from events — only timing metadata.
        $sanitised = array_map([self::class, 'sanitise_event'], $events);

        try {
            $client   = new client();
            $response = $client->submit_events($params['sessionid'], $sanitised);
            return [
                'success'  => true,
                'accepted' => (int) ($response['accepted'] ?? count($sanitised)),
            ];
        } catch (api_exception $e) {
            debugging('[local_writersproof] submit_events failed: ' . $e->getMessage(), DEBUG_DEVELOPER);
            return ['success' => false, 'accepted' => 0];
        }
    }

    // =========================================================================
    // create_checkpoint
    // =========================================================================

    /**
     * Parameter definition for create_checkpoint.
     *
     * @return external_function_parameters
     */
    public static function create_checkpoint_parameters(): external_function_parameters {
        return new external_function_parameters([
            'sessionid'   => new external_value(PARAM_ALPHANUMEXT, 'WritersProof session ID'),
            'contenthash' => new external_value(PARAM_ALPHANUMEXT, 'SHA-256 hex hash of current content'),
            'wordcount'   => new external_value(PARAM_INT, 'Current word count'),
        ]);
    }

    /**
     * Return definition for create_checkpoint.
     *
     * @return external_single_structure
     */
    public static function create_checkpoint_returns(): external_single_structure {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether the checkpoint was created'),
        ]);
    }

    /**
     * Create a checkpoint for an active session.
     *
     * @param  string $sessionid    Remote session ID.
     * @param  string $contenthash  SHA-256 hex of current editor content.
     * @param  int    $wordcount    Current word count.
     * @return array  {success}
     */
    public static function create_checkpoint(
        string $sessionid,
        string $contenthash,
        int $wordcount
    ): array {
        global $USER;

        $params = self::validate_parameters(self::create_checkpoint_parameters(), [
            'sessionid'   => $sessionid,
            'contenthash' => $contenthash,
            'wordcount'   => $wordcount,
        ]);

        // Validate hex format (64 lowercase hex chars).
        if (!preg_match('/\A[0-9a-f]{64}\z/', $params['contenthash'])) {
            throw new \invalid_parameter_exception('contenthash must be a 64-character SHA-256 hex string.');
        }

        $record  = self::require_user_session($params['sessionid'], (int) $USER->id);
        $context = \context::instance_by_id($record->contextid);
        self::validate_context($context);
        require_capability('local/writersproof:view', $context);

        try {
            $client = new client();
            $client->create_checkpoint(
                $params['sessionid'],
                $params['contenthash'],
                (int) $params['wordcount'],
                0  // char count not available from client side in this call
            );
            $monitor = new monitor();
            $monitor->increment_checkpoint_count($record->id);
            return ['success' => true];
        } catch (api_exception $e) {
            debugging('[local_writersproof] create_checkpoint failed: ' . $e->getMessage(), DEBUG_DEVELOPER);
            return ['success' => false];
        }
    }

    // =========================================================================
    // get_status
    // =========================================================================

    /**
     * Parameter definition for get_status.
     *
     * @return external_function_parameters
     */
    public static function get_status_parameters(): external_function_parameters {
        return new external_function_parameters([
            'cmid'     => new external_value(PARAM_INT,  'Course module ID'),
            'itemtype' => new external_value(PARAM_ALPHANUMEXT, 'Item type'),
            'itemid'   => new external_value(PARAM_INT,  'Content item ID'),
        ]);
    }

    /**
     * Return definition for get_status.
     *
     * @return external_single_structure
     */
    public static function get_status_returns(): external_single_structure {
        return new external_single_structure([
            'sessionid'       => new external_value(PARAM_ALPHANUMEXT, 'WritersProof session ID', VALUE_OPTIONAL),
            'status'          => new external_value(PARAM_ALPHA, 'Session status'),
            'score'           => new external_value(PARAM_FLOAT, 'Evidence confidence score', VALUE_OPTIONAL),
            'checkpointcount' => new external_value(PARAM_INT,   'Number of checkpoints recorded'),
            'wordcount'       => new external_value(PARAM_INT,   'Last known word count'),
        ]);
    }

    /**
     * Return the current status and score for a content item.
     *
     * @param  int    $cmid
     * @param  string $itemtype
     * @param  int    $itemid
     * @return array
     */
    public static function get_status(int $cmid, string $itemtype, int $itemid): array {
        global $USER;

        $params = self::validate_parameters(self::get_status_parameters(), [
            'cmid'     => $cmid,
            'itemtype' => $itemtype,
            'itemid'   => $itemid,
        ]);
        $itemtype = self::validate_item_type($params['itemtype']);

        $context = \context_module::instance((int) $params['cmid']);
        self::validate_context($context);
        require_capability('local/writersproof:view', $context);

        $monitor = new monitor();
        $record  = $monitor->find_session_record((int) $USER->id, $itemtype, (int) $params['itemid']);

        if ($record === false) {
            return [
                'sessionid'       => null,
                'status'          => 'none',
                'score'           => null,
                'checkpointcount' => 0,
                'wordcount'       => 0,
            ];
        }

        return [
            'sessionid'       => $record->sessionid ?? null,
            'status'          => $record->status,
            'score'           => $record->evidencescore !== null ? (float) $record->evidencescore : null,
            'checkpointcount' => (int) $record->checkpointcount,
            'wordcount'       => (int) $record->wordcount,
        ];
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Look up a local session record by remote session ID and verify ownership.
     *
     * @param  string $sessionid  Remote session ID.
     * @param  int    $userid     Calling user ID.
     * @return \stdClass          DB record.
     * @throws \required_capability_exception  When the session belongs to another user.
     * @throws \invalid_parameter_exception    When no matching session is found.
     */
    private static function require_user_session(string $sessionid, int $userid): \stdClass {
        global $DB;
        $record = $DB->get_record('local_writersproof_sessions', ['sessionid' => $sessionid]);
        if ($record === false) {
            throw new \invalid_parameter_exception('Session not found: ' . $sessionid);
        }
        if ((int) $record->userid !== $userid) {
            throw new \required_capability_exception(
                \context_system::instance(),
                'local/writersproof:viewall',
                'nopermissions',
                ''
            );
        }
        return $record;
    }

    /**
     * Validate an item type string against the known constants.
     *
     * @param  string $itemtype
     * @return string  The validated item type.
     * @throws \invalid_parameter_exception
     */
    private static function validate_item_type(string $itemtype): string {
        $allowed = [
            monitor::TYPE_ASSIGNMENT_SUBMISSION,
            monitor::TYPE_FORUM_POST,
            monitor::TYPE_WIKI_PAGE,
        ];
        if (!in_array($itemtype, $allowed, strict: true)) {
            throw new \invalid_parameter_exception(
                'Invalid itemtype. Expected one of: ' . implode(', ', $allowed)
            );
        }
        return $itemtype;
    }

    /**
     * Strip character-level content from an editor event, keeping only metadata.
     *
     * This is the privacy boundary: we transmit timing information, not content.
     *
     * @param  mixed $event  Raw event from the AMD module.
     * @return array         Sanitised event safe to forward to the API.
     */
    private static function sanitise_event(mixed $event): array {
        if (!is_array($event)) {
            return [];
        }
        $allowed_types = [
            'keydown', 'paste', 'focus', 'blur', 'scroll',
            'selection_change', 'idle_start', 'idle_end',
        ];
        $type = isset($event['type']) && in_array($event['type'], $allowed_types, strict: true)
            ? (string) $event['type']
            : 'unknown';

        $sanitised = [
            'type'         => $type,
            'timestamp_ms' => isset($event['timestamp_ms']) ? (int) $event['timestamp_ms'] : 0,
        ];

        // Preserve safe numeric metadata fields only.
        $numeric_meta = ['duration_ms', 'length', 'delta_chars', 'delta_words'];
        foreach ($numeric_meta as $key) {
            if (isset($event[$key]) && is_numeric($event[$key])) {
                $sanitised[$key] = (int) $event[$key];
            }
        }

        return $sanitised;
    }
}
