<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * WritersProof capability definitions.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$capabilities = [

    // Configure plugin settings (API key, enable/disable, etc.).
    'local/writersproof:manage' => [
        'captype'      => 'write',
        'contextlevel' => CONTEXT_SYSTEM,
        'archetypes'   => [
            'manager' => CAP_ALLOW,
        ],
    ],

    // View own authorship evidence (status, score, checkpoints).
    'local/writersproof:view' => [
        'captype'      => 'read',
        'contextlevel' => CONTEXT_MODULE,
        'archetypes'   => [
            'student'          => CAP_ALLOW,
            'teacher'          => CAP_ALLOW,
            'editingteacher'   => CAP_ALLOW,
            'manager'          => CAP_ALLOW,
        ],
    ],

    // View authorship evidence for all users in a course context.
    'local/writersproof:viewall' => [
        'captype'      => 'read',
        'contextlevel' => CONTEXT_MODULE,
        'archetypes'   => [
            'teacher'        => CAP_ALLOW,
            'editingteacher' => CAP_ALLOW,
            'manager'        => CAP_ALLOW,
        ],
    ],
];
