<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * WritersProof local plugin library functions.
 *
 * This file contains Moodle callback functions that must live at the plugin root.
 * All business logic is in the classes/ directory.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

/**
 * Extend the course navigation to add an "Authorship Evidence" link inside
 * supported activity modules (assign, forum, wiki) when the current user has
 * the view capability.
 *
 * @param  \navigation_node  $navigation  The navigation tree root.
 * @param  \stdClass         $course      Current course record.
 * @param  \context          $context     Current context.
 */
function local_writersproof_extend_navigation(
    \navigation_node $navigation,
    \stdClass $course,
    \context $context
): void {
    // Only attach the link inside module contexts (assign/forum/wiki).
    if (!($context instanceof \context_module)) {
        return;
    }
    if (!get_config('local_writersproof', 'enabled')) {
        return;
    }
    if (!has_capability('local/writersproof:view', $context)) {
        return;
    }

    $cm = get_coursemodule_from_id('', $context->instanceid, 0, false, MUST_EXIST);
    $supported = ['assign', 'forum', 'wiki'];
    if (!in_array($cm->modname, $supported, strict: true)) {
        return;
    }

    $url = new \moodle_url('/local/writersproof/evidence.php', [
        'cmid' => $cm->id,
    ]);

    $navigation->add(
        get_string('evidence_nav_link', 'local_writersproof'),
        $url,
        \navigation_node::TYPE_SETTING,
        null,
        'writersproof_evidence',
        new \pix_icon('i/grade_correct', get_string('evidence_nav_link', 'local_writersproof'))
    );
}

/**
 * Extend the navigation inside the course settings block (flat navigation).
 *
 * Moodle 4.x flat navigation hook — adds the evidence link to the secondary
 * navigation bar when inside a supported activity.
 *
 * @param  \settings_navigation $navigation
 * @param  \context             $context
 */
function local_writersproof_extend_settings_navigation(
    \settings_navigation $navigation,
    \context $context
): void {
    // Intentionally empty — the main navigation link is added via
    // local_writersproof_extend_navigation(). Settings navigation
    // is reserved for admin/teacher configuration links.
}

/**
 * Output the WritersProof AMD editor-hooks module on all supported editing
 * pages (assign submission, forum post, wiki page editor).
 *
 * Called by Moodle's page_init hook (if registered). In practice the AMD
 * module self-initialises; this hook ensures the module loads early.
 */
function local_writersproof_before_footer(): void {
    global $PAGE;

    if (!get_config('local_writersproof', 'enabled')) {
        return;
    }

    // Only inject on module pages.
    $context = $PAGE->context;
    if (!($context instanceof \context_module)) {
        return;
    }
    if (!has_capability('local/writersproof:view', $context)) {
        return;
    }

    $cm = $PAGE->cm;
    if (!$cm || !in_array($cm->modname, ['assign', 'forum', 'wiki'], strict: true)) {
        return;
    }

    // Pass runtime config to the AMD module via a JSON inline script.
    $checkpointinterval = max(10, min(3600, (int) get_config('local_writersproof', 'checkpoint_interval') ?: 60));

    $PAGE->requires->js_call_amd('local_writersproof/editor_hooks', 'init', [[
        'cmid'               => $cm->id,
        'modname'            => $cm->modname,
        'checkpointInterval' => $checkpointinterval,
        'sesskey'            => sesskey(),
    ]]);
}
