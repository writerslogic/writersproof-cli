<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * WritersProof event observer registrations.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$observers = [

    // Assignment submission created.
    [
        'eventname'   => '\mod_assign\event\assessable_submitted',
        'callback'    => '\local_writersproof\observer::submission_created',
        'priority'    => 200,
        'internal'    => false,
    ],

    // Assignment submission updated/draft saved.
    [
        'eventname'   => '\mod_assign\event\submission_updated',
        'callback'    => '\local_writersproof\observer::submission_updated',
        'priority'    => 200,
        'internal'    => false,
    ],

    // Forum post created.
    [
        'eventname'   => '\mod_forum\event\post_created',
        'callback'    => '\local_writersproof\observer::forum_post_created',
        'priority'    => 200,
        'internal'    => false,
    ],

    // Forum post edited.
    [
        'eventname'   => '\mod_forum\event\post_updated',
        'callback'    => '\local_writersproof\observer::forum_post_updated',
        'priority'    => 200,
        'internal'    => false,
    ],

    // Wiki page created.
    [
        'eventname'   => '\mod_wiki\event\page_created',
        'callback'    => '\local_writersproof\observer::wiki_page_created',
        'priority'    => 200,
        'internal'    => false,
    ],

    // Wiki page updated.
    [
        'eventname'   => '\mod_wiki\event\page_updated',
        'callback'    => '\local_writersproof\observer::wiki_page_updated',
        'priority'    => 200,
        'internal'    => false,
    ],
];
