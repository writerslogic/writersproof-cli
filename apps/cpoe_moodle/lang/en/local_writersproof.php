<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * English language strings for the WritersProof local plugin.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

// ---- Core plugin strings ---------------------------------------------------

$string['pluginname']         = 'WritersProof Authorship Attestation';
$string['pluginname_desc']    = 'Monitors content creation in assignments, forums, and wikis and sends cryptographic authorship evidence to the WritersProof API.';

// ---- Capabilities ----------------------------------------------------------

$string['writersproof:manage']  = 'Configure WritersProof plugin settings';
$string['writersproof:view']    = 'View own WritersProof authorship evidence';
$string['writersproof:viewall'] = 'View WritersProof evidence for all users';

// ---- Settings page ---------------------------------------------------------

$string['settings_enabled']      = 'Enable WritersProof';
$string['settings_enabled_desc'] = 'When enabled, authorship evidence is collected for supported content types.';

$string['settings_apikey']       = 'API key';
$string['settings_apikey_desc']  = 'Your WritersProof API key from api.writerslogic.com. Required for evidence submission.';

$string['settings_heading_witness']      = 'Content types to witness';
$string['settings_witness_assignments']      = 'Witness assignment submissions';
$string['settings_witness_assignments_desc'] = 'Collect authorship evidence for assignment online-text submissions.';
$string['settings_witness_forums']           = 'Witness forum posts';
$string['settings_witness_forums_desc']      = 'Collect authorship evidence for forum discussion posts.';
$string['settings_witness_wikis']            = 'Witness wiki pages';
$string['settings_witness_wikis_desc']       = 'Collect authorship evidence for wiki page creation and edits.';

$string['settings_heading_advanced']             = 'Advanced settings';
$string['settings_checkpoint_interval']          = 'Checkpoint interval (seconds)';
$string['settings_checkpoint_interval_desc']     = 'How frequently the browser-side editor monitor creates cryptographic checkpoints. Minimum 10, maximum 3600.';

// ---- Evidence panel / navigation -------------------------------------------

$string['evidence_panel_title']       = 'WritersProof Evidence';
$string['evidence_nav_link']          = 'Authorship Evidence';
$string['status_label']               = 'Status';
$string['score_label']                = 'Evidence score';
$string['checkpoints_label']          = 'Checkpoints';
$string['wordcount_label']            = 'Word count';
$string['session_id_label']           = 'Session ID';
$string['no_session']                 = 'No attestation session found for this item.';
$string['score_not_available']        = 'Not yet available';

// ---- Status values (used in template) --------------------------------------

$string['status_active']    = 'Active';
$string['status_finalized'] = 'Finalized';
$string['status_verified']  = 'Verified';
$string['status_failed']    = 'Failed';
$string['status_none']      = 'None';
$string['status_disabled']  = 'Disabled';

// ---- Editor hooks AMD module ------------------------------------------------

$string['witnessing_active']   = 'WritersProof is witnessing this session.';
$string['witnessing_paused']   = 'WritersProof witnessing paused.';
$string['witnessing_failed']   = 'WritersProof could not connect. Evidence will not be collected.';
$string['checkpoint_created']  = 'Checkpoint recorded.';

// ---- Error strings ---------------------------------------------------------

$string['error_apikey_missing']    = 'WritersProof API key is not configured. Contact your site administrator.';
$string['error_session_not_found'] = 'WritersProof session not found.';
$string['error_api_unavailable']   = 'WritersProof API is temporarily unavailable. Please try again later.';
$string['unsupporteditemtype']     = 'Unsupported content type: {$a}';

// ---- Privacy / GDPR --------------------------------------------------------

$string['privacy:metadata:local_writersproof_sessions']                    = 'Stores metadata about WritersProof authorship attestation sessions linked to Moodle content items.';
$string['privacy:metadata:local_writersproof_sessions:userid']             = 'The Moodle user ID of the author.';
$string['privacy:metadata:local_writersproof_sessions:contextid']          = 'The Moodle context in which the content was created.';
$string['privacy:metadata:local_writersproof_sessions:cmid']               = 'The course module ID of the activity containing the content.';
$string['privacy:metadata:local_writersproof_sessions:itemid']             = 'The primary key of the content record (submission, post, or page ID).';
$string['privacy:metadata:local_writersproof_sessions:itemtype']           = 'The content type identifier (e.g. assignment_submission, forum_post, wiki_page).';
$string['privacy:metadata:local_writersproof_sessions:sessionid']          = 'The session identifier returned by the WritersProof API.';
$string['privacy:metadata:local_writersproof_sessions:status']             = 'Current session status (active, finalized, verified, failed).';
$string['privacy:metadata:local_writersproof_sessions:contenthash']        = 'SHA-256 hash of the most recent content snapshot. The content itself is not stored.';
$string['privacy:metadata:local_writersproof_sessions:wordcount']          = 'Word count of the most recent content snapshot.';
$string['privacy:metadata:local_writersproof_sessions:evidencescore']      = 'Confidence score (0–1) returned by the WritersProof API after finalization.';
$string['privacy:metadata:local_writersproof_sessions:checkpointcount']    = 'Number of cryptographic checkpoints recorded for this session.';
$string['privacy:metadata:local_writersproof_sessions:timecreated']        = 'Unix timestamp when the session record was first created.';
$string['privacy:metadata:local_writersproof_sessions:timemodified']       = 'Unix timestamp of the most recent update to this record.';

$string['privacy:metadata:external']              = 'WritersProof sends authorship attestation data to the external WritersProof API (api.writerslogic.com).';
$string['privacy:metadata:external:userid']       = 'An opaque platform-prefixed user identifier (e.g. "moodle:42"). Your real name or email is never sent.';
$string['privacy:metadata:external:content_hash'] = 'A SHA-256 cryptographic hash of your content. The content itself is never transmitted to the API.';
$string['privacy:metadata:external:timing_events'] = 'Keyboard timing metadata (timestamps and durations only — no characters or words are captured or transmitted).';
$string['privacy:metadata:external:platform']      = 'Platform and plugin version identifiers used for compatibility tracking.';
