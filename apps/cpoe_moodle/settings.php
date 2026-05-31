<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * WritersProof plugin admin settings page.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

if ($hassiteconfig) {
    $settings = new admin_settingpage(
        'local_writersproof',
        get_string('pluginname', 'local_writersproof')
    );

    // -------------------------------------------------------------------------
    // Enable / disable plugin
    // -------------------------------------------------------------------------
    $settings->add(new admin_setting_configcheckbox(
        'local_writersproof/enabled',
        get_string('settings_enabled',     'local_writersproof'),
        get_string('settings_enabled_desc','local_writersproof'),
        0
    ));

    // -------------------------------------------------------------------------
    // API key
    // -------------------------------------------------------------------------
    $settings->add(new admin_setting_configpasswordunmask(
        'local_writersproof/apikey',
        get_string('settings_apikey',      'local_writersproof'),
        get_string('settings_apikey_desc', 'local_writersproof'),
        ''
    ));

    // -------------------------------------------------------------------------
    // Content type toggles
    // -------------------------------------------------------------------------
    $settings->add(new admin_setting_heading(
        'local_writersproof/heading_witness',
        get_string('settings_heading_witness', 'local_writersproof'),
        ''
    ));

    $settings->add(new admin_setting_configcheckbox(
        'local_writersproof/witness_assignments',
        get_string('settings_witness_assignments',      'local_writersproof'),
        get_string('settings_witness_assignments_desc', 'local_writersproof'),
        1
    ));

    $settings->add(new admin_setting_configcheckbox(
        'local_writersproof/witness_forums',
        get_string('settings_witness_forums',      'local_writersproof'),
        get_string('settings_witness_forums_desc', 'local_writersproof'),
        1
    ));

    $settings->add(new admin_setting_configcheckbox(
        'local_writersproof/witness_wikis',
        get_string('settings_witness_wikis',      'local_writersproof'),
        get_string('settings_witness_wikis_desc', 'local_writersproof'),
        1
    ));

    // -------------------------------------------------------------------------
    // Checkpoint interval
    // -------------------------------------------------------------------------
    $settings->add(new admin_setting_heading(
        'local_writersproof/heading_advanced',
        get_string('settings_heading_advanced', 'local_writersproof'),
        ''
    ));

    $settings->add(new admin_setting_configtext(
        'local_writersproof/checkpoint_interval',
        get_string('settings_checkpoint_interval',      'local_writersproof'),
        get_string('settings_checkpoint_interval_desc', 'local_writersproof'),
        60,      // default: 60 seconds
        PARAM_INT
    ));

    $ADMIN->add('localplugins', $settings);
}
