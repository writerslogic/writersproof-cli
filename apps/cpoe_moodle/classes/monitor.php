<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Content monitoring and snapshot management.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

namespace local_writersproof;

defined('MOODLE_INTERNAL') || die();

/**
 * Fetches, hashes, and diffs content for the supported item types.
 *
 * All content is normalised (tags stripped, whitespace collapsed) before
 * hashing so that cosmetic HTML changes do not generate spurious events.
 */
class monitor {

    /** Supported item type identifiers. */
    public const TYPE_ASSIGNMENT_SUBMISSION = 'assignment_submission';
    public const TYPE_FORUM_POST            = 'forum_post';
    public const TYPE_WIKI_PAGE             = 'wiki_page';

    // -------------------------------------------------------------------------
    // Snapshot capture
    // -------------------------------------------------------------------------

    /**
     * Fetch current content for the given item type and ID, returning a
     * normalised snapshot array.
     *
     * @param  string $itemtype  One of the TYPE_* constants.
     * @param  int    $itemid    Primary key of the content record.
     * @return array {
     *   string contenthash  SHA-256 hex of normalised content.
     *   string rawcontent   Normalised plain-text content.
     *   int    wordcount    Word count of normalised content.
     *   int    charcount    Character count of normalised content.
     * }
     * @throws \moodle_exception When the item cannot be found or type is unknown.
     */
    public function capture_snapshot(string $itemtype, int $itemid): array {
        $content = $this->fetch_content($itemtype, $itemid);
        return $this->build_snapshot($content);
    }

    // -------------------------------------------------------------------------
    // Diff computation
    // -------------------------------------------------------------------------

    /**
     * Compute a diff between two snapshots.
     *
     * The diff is intentionally shallow — it records aggregate metrics rather
     * than a full textual diff, to avoid transmitting content to the API.
     *
     * @param  array $old  Previous snapshot from {@see capture_snapshot()}.
     * @param  array $new  Current snapshot.
     * @return array {
     *   int    char_delta     Characters added (positive) or removed (negative).
     *   int    word_delta     Words added or removed.
     *   bool   hash_changed   Whether the content hash changed.
     * }
     */
    public function compute_diff(array $old, array $new): array {
        return [
            'char_delta'   => $new['charcount'] - $old['charcount'],
            'word_delta'   => $new['wordcount']  - $old['wordcount'],
            'hash_changed' => $new['contenthash'] !== $old['contenthash'],
        ];
    }

    // -------------------------------------------------------------------------
    // Database record helpers
    // -------------------------------------------------------------------------

    /**
     * Find an existing local session record for the given user and item.
     *
     * @param  int    $userid
     * @param  string $itemtype
     * @param  int    $itemid
     * @return \stdClass|false  DB record or false if not found.
     */
    public function find_session_record(int $userid, string $itemtype, int $itemid) {
        global $DB;
        return $DB->get_record('local_writersproof_sessions', [
            'userid'   => $userid,
            'itemtype' => $itemtype,
            'itemid'   => $itemid,
        ]);
    }

    /**
     * Create a new local session record.
     *
     * @param  int    $userid
     * @param  int    $contextid
     * @param  int|null $cmid
     * @param  int    $itemid
     * @param  string $itemtype
     * @param  array  $snapshot  Result of {@see capture_snapshot()}.
     * @return \stdClass  The newly inserted record (with id set).
     */
    public function create_session_record(
        int $userid,
        int $contextid,
        ?int $cmid,
        int $itemid,
        string $itemtype,
        array $snapshot
    ): \stdClass {
        global $DB;
        $now = time();
        $record = (object) [
            'userid'          => $userid,
            'contextid'       => $contextid,
            'cmid'            => $cmid,
            'itemid'          => $itemid,
            'itemtype'        => $itemtype,
            'sessionid'       => null,
            'status'          => 'active',
            'contenthash'     => $snapshot['contenthash'],
            'wordcount'       => $snapshot['wordcount'],
            'evidencescore'   => null,
            'checkpointcount' => 0,
            'timecreated'     => $now,
            'timemodified'    => $now,
        ];
        $record->id = $DB->insert_record('local_writersproof_sessions', $record);
        return $record;
    }

    /**
     * Update snapshot fields and modification time on an existing record.
     *
     * @param  int    $recordid   Local session record ID.
     * @param  array  $snapshot   New snapshot from {@see capture_snapshot()}.
     * @param  string $status     Session status string.
     */
    public function update_session_record(int $recordid, array $snapshot, string $status): void {
        global $DB;
        $DB->update_record('local_writersproof_sessions', (object) [
            'id'           => $recordid,
            'contenthash'  => $snapshot['contenthash'],
            'wordcount'    => $snapshot['wordcount'],
            'status'       => $status,
            'timemodified' => time(),
        ]);
    }

    /**
     * Persist the remote session ID returned by the WritersProof API.
     *
     * @param  int    $recordid   Local session record ID.
     * @param  string $sessionid  Remote session ID.
     */
    public function set_remote_session_id(int $recordid, string $sessionid): void {
        global $DB;
        $DB->update_record('local_writersproof_sessions', (object) [
            'id'           => $recordid,
            'sessionid'    => $sessionid,
            'timemodified' => time(),
        ]);
    }

    /**
     * Increment the checkpoint counter for a local session.
     *
     * @param  int $recordid  Local session record ID.
     */
    public function increment_checkpoint_count(int $recordid): void {
        global $DB;
        $DB->execute(
            'UPDATE {local_writersproof_sessions}
                SET checkpointcount = checkpointcount + 1, timemodified = ?
              WHERE id = ?',
            [time(), $recordid]
        );
    }

    /**
     * Store the evidence score returned by the API after finalization.
     *
     * @param  int   $recordid  Local session record ID.
     * @param  float $score     Evidence confidence score (0.0 – 1.0).
     */
    public function set_evidence_score(int $recordid, float $score): void {
        global $DB;
        $DB->update_record('local_writersproof_sessions', (object) [
            'id'           => $recordid,
            'evidencescore' => round(max(0.0, min(1.0, $score)), 2),
            'timemodified' => time(),
        ]);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Fetch raw content from Moodle for the given item type/id.
     *
     * @param  string $itemtype
     * @param  int    $itemid
     * @return string Raw HTML or plain-text content.
     * @throws \moodle_exception
     */
    private function fetch_content(string $itemtype, int $itemid): string {
        global $DB;
        switch ($itemtype) {
            case self::TYPE_ASSIGNMENT_SUBMISSION:
                return $this->fetch_assignment_submission($itemid);
            case self::TYPE_FORUM_POST:
                return $this->fetch_forum_post($itemid);
            case self::TYPE_WIKI_PAGE:
                return $this->fetch_wiki_page($itemid);
            default:
                throw new \moodle_exception(
                    'unsupporteditemtype',
                    'local_writersproof',
                    '',
                    $itemtype
                );
        }
    }

    /**
     * Fetch online-text content from an assignment submission.
     *
     * Looks first in assignsubmission_onlinetext (most common), falls back to
     * the submission record's groupid/userid for file-only submissions.
     *
     * @param  int $submissionid  assign_submission.id
     * @return string
     * @throws \moodle_exception
     */
    private function fetch_assignment_submission(int $submissionid): string {
        global $DB;
        $onlinetext = $DB->get_record('assignsubmission_onlinetext', [
            'submission' => $submissionid,
        ]);
        if ($onlinetext && isset($onlinetext->onlinetext)) {
            return (string) $onlinetext->onlinetext;
        }
        // No online text — nothing to attest.
        return '';
    }

    /**
     * Fetch the message body of a forum post.
     *
     * @param  int $postid  forum_posts.id
     * @return string
     * @throws \moodle_exception
     */
    private function fetch_forum_post(int $postid): string {
        global $DB;
        $post = $DB->get_record('forum_posts', ['id' => $postid], 'id, message', MUST_EXIST);
        return (string) $post->message;
    }

    /**
     * Fetch the current revision content of a wiki page.
     *
     * @param  int $pageid  wiki_pages.id
     * @return string
     * @throws \moodle_exception
     */
    private function fetch_wiki_page(int $pageid): string {
        global $DB;
        // wiki_pages stores the current content directly.
        $page = $DB->get_record('wiki_pages', ['id' => $pageid], 'id, cachedcontent', MUST_EXIST);
        return (string) ($page->cachedcontent ?? '');
    }

    /**
     * Normalise raw content and build a snapshot array.
     *
     * @param  string $content  Raw HTML or plain-text content.
     * @return array  Snapshot with contenthash, rawcontent, wordcount, charcount.
     */
    private function build_snapshot(string $content): array {
        // Strip HTML tags and collapse whitespace for a stable plain-text base.
        $plain = strip_tags($content);
        $plain = html_entity_decode($plain, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $plain = preg_replace('/\s+/', ' ', $plain);
        $plain = trim($plain);

        $wordcount = $plain !== '' ? str_word_count($plain) : 0;
        $charcount = mb_strlen($plain, 'UTF-8');
        $hash      = hash('sha256', $plain);

        return [
            'contenthash' => $hash,
            'rawcontent'  => $plain,
            'wordcount'   => $wordcount,
            'charcount'   => $charcount,
        ];
    }
}
