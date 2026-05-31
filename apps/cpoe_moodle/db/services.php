<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * WritersProof external web service function declarations.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$functions = [

    'local_writersproof_start_session' => [
        'classname'     => '\local_writersproof\external\session_api',
        'methodname'    => 'start_session',
        'description'   => 'Start a WritersProof authorship attestation session for a content item.',
        'type'          => 'write',
        'ajax'          => true,
        'loginrequired' => true,
        'capabilities'  => 'local/writersproof:view',
    ],

    'local_writersproof_submit_events' => [
        'classname'     => '\local_writersproof\external\session_api',
        'methodname'    => 'submit_events',
        'description'   => 'Submit captured editor events to a WritersProof session.',
        'type'          => 'write',
        'ajax'          => true,
        'loginrequired' => true,
        'capabilities'  => 'local/writersproof:view',
    ],

    'local_writersproof_create_checkpoint' => [
        'classname'     => '\local_writersproof\external\session_api',
        'methodname'    => 'create_checkpoint',
        'description'   => 'Create a cryptographic checkpoint for a WritersProof session.',
        'type'          => 'write',
        'ajax'          => true,
        'loginrequired' => true,
        'capabilities'  => 'local/writersproof:view',
    ],

    'local_writersproof_get_status' => [
        'classname'     => '\local_writersproof\external\session_api',
        'methodname'    => 'get_status',
        'description'   => 'Get current WritersProof session status and score for a content item.',
        'type'          => 'read',
        'ajax'          => true,
        'loginrequired' => true,
        'capabilities'  => 'local/writersproof:view',
    ],
];
