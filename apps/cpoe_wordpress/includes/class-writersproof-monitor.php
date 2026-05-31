<?php
/**
 * WritersProof content monitor.
 *
 * Responsible for hashing post content, capturing consistent snapshots, and
 * computing incremental diffs between snapshots. No actual text content is
 * transmitted — only hashes, counts, and deltas.
 *
 * @package WritersProof
 * @since   1.0.0
 */

declare( strict_types = 1 );

defined( 'ABSPATH' ) || exit;

/**
 * Content monitoring and hashing utilities.
 */
class WritersProof_Monitor {

	/**
	 * Post meta key for the serialised snapshot.
	 */
	private const META_SNAPSHOT = '_writersproof_last_snapshot';

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	/**
	 * Compute a SHA-256 hex digest of the post's plain-text content.
	 *
	 * HTML tags are stripped before hashing so that minor mark-up changes
	 * (e.g. block wrapper attributes) do not alter the hash. Whitespace is
	 * normalised for consistency across editors.
	 *
	 * @param string $raw_content Raw post content (may contain HTML/blocks).
	 * @return string Lowercase hex SHA-256 digest.
	 */
	public function hash_content( string $raw_content ): string {
		$plain = $this->normalise_content( $raw_content );
		return hash( 'sha256', $plain );
	}

	/**
	 * Capture a content snapshot for the given post.
	 *
	 * @param int $post_id WordPress post ID.
	 * @return array{
	 *   content_hash:    string,
	 *   word_count:      int,
	 *   char_count:      int,
	 *   paragraph_count: int,
	 *   captured_at:     string,
	 * }
	 */
	public function capture_snapshot( int $post_id ): array {
		$post = get_post( $post_id );

		if ( ! $post instanceof WP_Post ) {
			return $this->empty_snapshot();
		}

		$plain = $this->normalise_content( $post->post_content );

		return array(
			'content_hash'    => hash( 'sha256', $plain ),
			'word_count'      => $this->count_words( $plain ),
			'char_count'      => mb_strlen( $plain, 'UTF-8' ),
			'paragraph_count' => $this->count_paragraphs( $post->post_content ),
			'captured_at'     => gmdate( 'Y-m-d\TH:i:s\Z' ),
		);
	}

	/**
	 * Compute the diff between a previous snapshot and a new one.
	 *
	 * @param array<string, mixed> $previous Previous snapshot (may be empty).
	 * @param array<string, mixed> $current  Current snapshot.
	 * @return array{
	 *   charDelta:      int,
	 *   wordDelta:      int,
	 *   paragraphDelta: int,
	 *   hashChanged:    bool,
	 * }
	 */
	public function compute_diff( array $previous, array $current ): array {
		return array(
			'charDelta'      => (int) ( $current['char_count'] ?? 0 ) - (int) ( $previous['char_count'] ?? 0 ),
			'wordDelta'      => (int) ( $current['word_count'] ?? 0 ) - (int) ( $previous['word_count'] ?? 0 ),
			'paragraphDelta' => (int) ( $current['paragraph_count'] ?? 0 ) - (int) ( $previous['paragraph_count'] ?? 0 ),
			'hashChanged'    => ( $current['content_hash'] ?? '' ) !== ( $previous['content_hash'] ?? '' ),
		);
	}

	/**
	 * Load the last saved snapshot for a post from post meta.
	 *
	 * @param int $post_id WordPress post ID.
	 * @return array<string, mixed> Previous snapshot, or an empty snapshot array.
	 */
	public function load_snapshot( int $post_id ): array {
		$raw = get_post_meta( $post_id, self::META_SNAPSHOT, true );

		if ( ! is_string( $raw ) || '' === $raw ) {
			return $this->empty_snapshot();
		}

		$decoded = json_decode( $raw, true );

		return ( JSON_ERROR_NONE === json_last_error() && is_array( $decoded ) )
			? $decoded
			: $this->empty_snapshot();
	}

	/**
	 * Persist a snapshot to post meta.
	 *
	 * @param int                  $post_id  WordPress post ID.
	 * @param array<string, mixed> $snapshot Snapshot to save.
	 */
	public function save_snapshot( int $post_id, array $snapshot ): void {
		$encoded = wp_json_encode( $snapshot );

		if ( false !== $encoded ) {
			update_post_meta( $post_id, self::META_SNAPSHOT, $encoded );
		}
	}

	// -------------------------------------------------------------------------
	// Internal helpers
	// -------------------------------------------------------------------------

	/**
	 * Strip HTML, decode entities, and normalise whitespace.
	 *
	 * @param string $content Raw content.
	 * @return string Plain text ready for hashing or counting.
	 */
	private function normalise_content( string $content ): string {
		// Remove Gutenberg block comments first.
		$plain = preg_replace( '/<!--.*?-->/s', '', $content ) ?? $content;

		// Strip HTML tags.
		$plain = wp_strip_all_tags( $plain );

		// Decode HTML entities.
		$plain = html_entity_decode( $plain, ENT_QUOTES | ENT_HTML5, 'UTF-8' );

		// Collapse runs of whitespace to a single space and trim.
		$plain = preg_replace( '/\s+/u', ' ', $plain ) ?? $plain;

		return trim( $plain );
	}

	/**
	 * Count words in plain text using a locale-aware approach.
	 *
	 * WordPress's str_word_count() equivalent is used so that multibyte
	 * characters are handled correctly.
	 *
	 * @param string $plain Normalised plain text.
	 * @return int Word count (minimum 0).
	 */
	private function count_words( string $plain ): int {
		if ( '' === $plain ) {
			return 0;
		}

		// Split on Unicode whitespace boundaries.
		$words = preg_split( '/\s+/u', $plain, -1, PREG_SPLIT_NO_EMPTY );

		return is_array( $words ) ? count( $words ) : 0;
	}

	/**
	 * Count paragraph-level blocks or HTML <p> tags in raw content.
	 *
	 * Gutenberg content uses HTML comments to delimit blocks; we count
	 * <!-- wp:paragraph --> openings. For classic content we count <p> tags.
	 *
	 * @param string $raw_content Original post content.
	 * @return int Paragraph/block count (minimum 0).
	 */
	private function count_paragraphs( string $raw_content ): int {
		// Gutenberg block format.
		if ( str_contains( $raw_content, '<!-- wp:' ) ) {
			$count = substr_count( $raw_content, '<!-- wp:paragraph' );
			// If blocks are present but none are paragraphs, fall back to any block.
			if ( 0 === $count ) {
				$count = substr_count( $raw_content, '<!-- wp:' );
			}
			return max( 0, $count );
		}

		// Classic editor: count opening <p> tags.
		$count = substr_count( strtolower( $raw_content ), '<p' );
		if ( $count > 0 ) {
			return $count;
		}

		// Plain text fallback: count double line-breaks.
		$paragraphs = preg_split( '/\n\s*\n/', $raw_content, -1, PREG_SPLIT_NO_EMPTY );
		return is_array( $paragraphs ) ? max( 0, count( $paragraphs ) ) : 0;
	}

	/**
	 * Return an empty snapshot placeholder.
	 *
	 * @return array{
	 *   content_hash:    string,
	 *   word_count:      int,
	 *   char_count:      int,
	 *   paragraph_count: int,
	 *   captured_at:     string,
	 * }
	 */
	private function empty_snapshot(): array {
		return array(
			'content_hash'    => '',
			'word_count'      => 0,
			'char_count'      => 0,
			'paragraph_count' => 0,
			'captured_at'     => '',
		);
	}
}
