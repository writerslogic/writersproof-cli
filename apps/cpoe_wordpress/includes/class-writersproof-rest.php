<?php
/**
 * WritersProof REST API endpoints.
 *
 * Registers /wp-json/writersproof/v1/* routes consumed by the Gutenberg
 * editor-hooks script and the admin meta box.
 *
 * @package WritersProof
 * @since   1.0.0
 */

declare( strict_types = 1 );

defined( 'ABSPATH' ) || exit;

/**
 * Registers and handles all plugin REST routes.
 */
class WritersProof_Rest {

	/**
	 * REST API namespace.
	 */
	private const NAMESPACE = 'writersproof/v1';

	/**
	 * Register all routes with the REST API dispatcher.
	 */
	public function register_routes(): void {
		// Session management.
		register_rest_route(
			self::NAMESPACE,
			'/session/start',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'start_session' ),
				'permission_callback' => array( $this, 'permission_edit_post' ),
				'args'                => array(
					'post_id' => array(
						'required'          => true,
						'validate_callback' => array( $this, 'validate_post_id' ),
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/session/checkpoint',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'create_checkpoint' ),
				'permission_callback' => array( $this, 'permission_edit_post' ),
				'args'                => array(
					'post_id'     => array(
						'required'          => true,
						'validate_callback' => array( $this, 'validate_post_id' ),
						'sanitize_callback' => 'absint',
					),
					'contentHash' => array(
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
						'validate_callback' => array( $this, 'validate_hex_hash' ),
					),
					'wordCount'   => array(
						'required'          => false,
						'type'              => 'integer',
						'sanitize_callback' => 'absint',
					),
					'charCount'   => array(
						'required'          => false,
						'type'              => 'integer',
						'sanitize_callback' => 'absint',
					),
					'metadata'    => array(
						'required' => false,
						'type'     => 'object',
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/session/stop',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'stop_session' ),
				'permission_callback' => array( $this, 'permission_edit_post' ),
				'args'                => array(
					'post_id' => array(
						'required'          => true,
						'validate_callback' => array( $this, 'validate_post_id' ),
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/session/status',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_session_status' ),
				'permission_callback' => array( $this, 'permission_edit_post' ),
				'args'                => array(
					'post_id' => array(
						'required'          => true,
						'validate_callback' => array( $this, 'validate_post_id' ),
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		// Event submission.
		register_rest_route(
			self::NAMESPACE,
			'/session/events',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'submit_events' ),
				'permission_callback' => array( $this, 'permission_edit_post' ),
				'args'                => array(
					'post_id' => array(
						'required'          => true,
						'validate_callback' => array( $this, 'validate_post_id' ),
						'sanitize_callback' => 'absint',
					),
					'events'  => array(
						'required' => true,
						'type'     => 'array',
					),
				),
			)
		);

		// Evidence retrieval.
		register_rest_route(
			self::NAMESPACE,
			'/evidence/(?P<post_id>\d+)',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_evidence' ),
				'permission_callback' => array( $this, 'permission_edit_post_by_id' ),
				'args'                => array(
					'post_id' => array(
						'required'          => true,
						'validate_callback' => array( $this, 'validate_post_id' ),
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		// API health test (settings page).
		register_rest_route(
			self::NAMESPACE,
			'/test',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'test_connection' ),
				'permission_callback' => function () {
					return current_user_can( 'manage_options' );
				},
			)
		);
	}

	// -------------------------------------------------------------------------
	// Route handlers
	// -------------------------------------------------------------------------

	/**
	 * POST /session/start — start a witnessing session for a post.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function start_session( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$post_id = (int) $request->get_param( 'post_id' );
		$post    = get_post( $post_id );

		if ( ! $post instanceof WP_Post ) {
			return new WP_Error( 'not_found', __( 'Post not found.', 'writersproof' ), array( 'status' => 404 ) );
		}

		// Reject if a session is already active.
		$existing = get_post_meta( $post_id, '_writersproof_session_id', true );
		$status   = get_post_meta( $post_id, '_writersproof_status', true );
		if ( ! empty( $existing ) && 'active' === $status ) {
			return rest_ensure_response(
				array(
					'success'    => true,
					'session_id' => $existing,
					'message'    => __( 'Session already active.', 'writersproof' ),
				)
			);
		}

		$monitor  = new WritersProof_Monitor();
		$snapshot = $monitor->capture_snapshot( $post_id );
		$client   = new WritersProof_Client();

		$result = $client->create_session(
			array(
				'documentId'    => $post_id,
				'documentTitle' => get_the_title( $post ),
				'platform'      => 'wordpress',
				'contentHash'   => $snapshot['content_hash'],
			)
		);

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$session_id = $result['id'] ?? $result['sessionId'] ?? '';
		if ( '' === $session_id ) {
			return new WP_Error(
				'writersproof_no_session_id',
				__( 'API did not return a session ID.', 'writersproof' ),
				array( 'status' => 502 )
			);
		}

		update_post_meta( $post_id, '_writersproof_session_id', sanitize_text_field( $session_id ) );
		update_post_meta( $post_id, '_writersproof_status', 'active' );
		$monitor->save_snapshot( $post_id, $snapshot );

		return rest_ensure_response(
			array(
				'success'    => true,
				'session_id' => $session_id,
				'message'    => __( 'Witnessing session started.', 'writersproof' ),
			)
		);
	}

	/**
	 * POST /session/checkpoint — create a checkpoint.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function create_checkpoint( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$post_id    = (int) $request->get_param( 'post_id' );
		$session_id = (string) get_post_meta( $post_id, '_writersproof_session_id', true );

		if ( '' === $session_id ) {
			return new WP_Error(
				'no_session',
				__( 'No active session for this post.', 'writersproof' ),
				array( 'status' => 409 )
			);
		}

		$client = new WritersProof_Client();
		$result = $client->create_checkpoint(
			$session_id,
			array(
				'contentHash' => (string) $request->get_param( 'contentHash' ),
				'wordCount'   => (int) $request->get_param( 'wordCount' ),
				'charCount'   => (int) $request->get_param( 'charCount' ),
				'metadata'    => $this->sanitize_metadata( (array) $request->get_param( 'metadata' ) ),
			)
		);

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( array( 'success' => true ) );
	}

	/**
	 * POST /session/stop — finalize (stop) a witnessing session.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function stop_session( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$post_id    = (int) $request->get_param( 'post_id' );
		$session_id = (string) get_post_meta( $post_id, '_writersproof_session_id', true );

		if ( '' === $session_id ) {
			return new WP_Error(
				'no_session',
				__( 'No active session for this post.', 'writersproof' ),
				array( 'status' => 409 )
			);
		}

		$monitor  = new WritersProof_Monitor();
		$snapshot = $monitor->capture_snapshot( $post_id );
		$client   = new WritersProof_Client();

		$result = $client->finalize_session(
			$session_id,
			array(
				'contentHash'   => $snapshot['content_hash'],
				'wordCount'     => $snapshot['word_count'],
				'finalSnapshot' => array(
					'charCount'      => $snapshot['char_count'],
					'paragraphCount' => $snapshot['paragraph_count'],
				),
			)
		);

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		update_post_meta( $post_id, '_writersproof_status', 'stopped' );

		return rest_ensure_response(
			array(
				'success' => true,
				'message' => __( 'Session stopped.', 'writersproof' ),
			)
		);
	}

	/**
	 * GET /session/status?post_id={id} — return current session state.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function get_session_status( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$post_id    = (int) $request->get_param( 'post_id' );
		$session_id = (string) get_post_meta( $post_id, '_writersproof_session_id', true );
		$status     = (string) get_post_meta( $post_id, '_writersproof_status', true );
		$score      = get_post_meta( $post_id, '_writersproof_evidence_score', true );

		return rest_ensure_response(
			array(
				'session_id' => $session_id,
				'status'     => '' !== $status ? $status : 'none',
				'score'      => null !== $score && '' !== $score ? (int) $score : null,
			)
		);
	}

	/**
	 * POST /session/events — forward timing events to the WritersProof API.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function submit_events( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$post_id    = (int) $request->get_param( 'post_id' );
		$session_id = (string) get_post_meta( $post_id, '_writersproof_session_id', true );

		if ( '' === $session_id ) {
			return new WP_Error(
				'no_session',
				__( 'No active session for this post.', 'writersproof' ),
				array( 'status' => 409 )
			);
		}

		$raw_events = $request->get_param( 'events' );
		if ( ! is_array( $raw_events ) || empty( $raw_events ) ) {
			return new WP_Error(
				'invalid_events',
				__( 'Events must be a non-empty array.', 'writersproof' ),
				array( 'status' => 400 )
			);
		}

		$events = $this->sanitize_events( $raw_events );
		$client = new WritersProof_Client();
		$result = $client->submit_events( $session_id, $events );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( array( 'success' => true, 'count' => count( $events ) ) );
	}

	/**
	 * GET /evidence/{post_id} — retrieve evidence for a post.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function get_evidence( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$post_id    = (int) $request->get_param( 'post_id' );
		$session_id = (string) get_post_meta( $post_id, '_writersproof_session_id', true );

		if ( '' === $session_id ) {
			return new WP_Error(
				'no_session',
				__( 'No WritersProof session found for this post.', 'writersproof' ),
				array( 'status' => 404 )
			);
		}

		$client = new WritersProof_Client();
		$result = $client->get_evidence( $session_id );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( $result );
	}

	/**
	 * GET /test — verify the API key is valid and the API is reachable.
	 *
	 * Attempts to list sessions with a zero limit to confirm auth without
	 * creating any data. Returns { ok: true } on success.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function test_connection( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$api_key = get_option( 'writersproof_api_key', '' );

		if ( empty( $api_key ) ) {
			return rest_ensure_response(
				array(
					'ok'      => false,
					'message' => __( 'No API key configured.', 'writersproof' ),
				)
			);
		}

		// Hit the verify endpoint with a dummy payload; a 4xx body response
		// (even 422 Unprocessable) confirms the API is reachable and key is valid.
		$client = new WritersProof_Client();
		$result = $client->verify_evidence( array( 'test' => true ) );

		// A 422 or 400 from the API still means auth passed and API is up.
		if ( is_wp_error( $result ) ) {
			$code = (int) ( $result->get_error_data( $result->get_error_code() )['status'] ?? 0 );
			if ( in_array( $code, array( 400, 422 ), true ) ) {
				return rest_ensure_response( array( 'ok' => true ) );
			}
			if ( 401 === $code || 403 === $code ) {
				return rest_ensure_response(
					array(
						'ok'      => false,
						'message' => __( 'API key is invalid or unauthorised.', 'writersproof' ),
					)
				);
			}
			return rest_ensure_response(
				array(
					'ok'      => false,
					'message' => $result->get_error_message(),
				)
			);
		}

		return rest_ensure_response( array( 'ok' => true ) );
	}

	// -------------------------------------------------------------------------
	// Permission callbacks
	// -------------------------------------------------------------------------

	/**
	 * Permission callback: user must be able to edit posts generically.
	 *
	 * @return bool
	 */
	public function permission_edit_post(): bool {
		return current_user_can( 'edit_posts' );
	}

	/**
	 * Permission callback for routes with a post_id URL segment.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return bool|WP_Error
	 */
	public function permission_edit_post_by_id( WP_REST_Request $request ): bool|WP_Error {
		$post_id = (int) $request->get_param( 'post_id' );

		if ( ! current_user_can( 'edit_post', $post_id ) ) {
			return new WP_Error(
				'forbidden',
				__( 'You do not have permission to view evidence for this post.', 'writersproof' ),
				array( 'status' => 403 )
			);
		}

		return true;
	}

	// -------------------------------------------------------------------------
	// Validation callbacks
	// -------------------------------------------------------------------------

	/**
	 * Validate that a post_id parameter refers to an existing post.
	 *
	 * @param mixed $value The parameter value.
	 * @return bool|WP_Error
	 */
	public function validate_post_id( mixed $value ): bool|WP_Error {
		$id = absint( $value );

		if ( $id < 1 ) {
			return new WP_Error( 'invalid_post_id', __( 'post_id must be a positive integer.', 'writersproof' ) );
		}

		if ( ! get_post( $id ) instanceof WP_Post ) {
			return new WP_Error( 'invalid_post_id', __( 'Post not found.', 'writersproof' ) );
		}

		return true;
	}

	/**
	 * Validate that a parameter is a valid lowercase hex SHA-256 hash.
	 *
	 * @param mixed $value The parameter value.
	 * @return bool|WP_Error
	 */
	public function validate_hex_hash( mixed $value ): bool|WP_Error {
		if ( ! is_string( $value ) || ! preg_match( '/^[0-9a-f]{64}$/i', $value ) ) {
			return new WP_Error(
				'invalid_hash',
				__( 'contentHash must be a 64-character hex SHA-256 digest.', 'writersproof' )
			);
		}
		return true;
	}

	// -------------------------------------------------------------------------
	// Sanitization helpers
	// -------------------------------------------------------------------------

	/**
	 * Sanitize an array of timing events submitted from the browser.
	 *
	 * Only allows known scalar fields; strips anything that could contain
	 * actual text content.
	 *
	 * @param array<int, mixed> $raw Raw events array.
	 * @return array<int, array<string, mixed>> Sanitized events.
	 */
	private function sanitize_events( array $raw ): array {
		$allowed_string_keys  = array( 'type', 'contentHash' );
		$allowed_integer_keys = array( 'timestamp', 'wordCount', 'charCount', 'blockCount', 'duration' );
		$allowed_float_keys   = array( 'intervalMs' );
		$sanitized            = array();

		foreach ( $raw as $event ) {
			if ( ! is_array( $event ) ) {
				continue;
			}

			$clean = array();

			foreach ( $allowed_string_keys as $key ) {
				if ( isset( $event[ $key ] ) ) {
					$clean[ $key ] = sanitize_text_field( (string) $event[ $key ] );
				}
			}
			foreach ( $allowed_integer_keys as $key ) {
				if ( isset( $event[ $key ] ) ) {
					$clean[ $key ] = (int) $event[ $key ];
				}
			}
			foreach ( $allowed_float_keys as $key ) {
				if ( isset( $event[ $key ] ) ) {
					$clean[ $key ] = (float) $event[ $key ];
				}
			}

			if ( ! empty( $clean ) ) {
				$sanitized[] = $clean;
			}
		}

		return $sanitized;
	}

	/**
	 * Sanitize a metadata array, keeping only known safe scalar values.
	 *
	 * @param array<string, mixed> $raw Raw metadata.
	 * @return array<string, scalar> Sanitized metadata.
	 */
	private function sanitize_metadata( array $raw ): array {
		$out = array();
		foreach ( $raw as $key => $value ) {
			$key = sanitize_key( (string) $key );
			if ( '' === $key ) {
				continue;
			}
			if ( is_int( $value ) || is_float( $value ) || is_bool( $value ) ) {
				$out[ $key ] = $value;
			} elseif ( is_string( $value ) ) {
				$out[ $key ] = sanitize_text_field( $value );
			}
			// Nested arrays are intentionally dropped.
		}
		return $out;
	}
}
