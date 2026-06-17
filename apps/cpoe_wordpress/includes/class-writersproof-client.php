<?php
/**
 * WritersProof HTTP client.
 *
 * Handles all communication with the WritersProof API, including retry logic,
 * exponential backoff on 5xx errors, and Retry-After header handling on 429.
 *
 * @package WritersProof
 * @since   1.0.0
 */

declare( strict_types = 1 );

defined( 'ABSPATH' ) || exit;

/**
 * Thin wrapper around the WritersProof REST API.
 *
 * All public methods return the decoded JSON body as an associative array on
 * success, or a WP_Error on failure.
 */
class WritersProof_Client {

	/**
	 * API base URL.
	 */
	private const API_BASE = WRITERSPROOF_API_BASE;

	/**
	 * Maximum number of retry attempts per request.
	 */
	private const MAX_RETRIES = 3;

	/**
	 * HTTP request timeout in seconds.
	 */
	private const TIMEOUT = 30;

	/**
	 * Base delay between retries in seconds (doubled on each attempt).
	 */
	private const BASE_BACKOFF = 1;

	/**
	 * API key used for authentication.
	 */
	private string $api_key;

	/**
	 * Constructor — resolves the API key from WordPress options.
	 */
	public function __construct() {
		$this->api_key = (string) get_option( 'writersproof_api_key', '' );
	}

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	/**
	 * Start a new witnessing session.
	 *
	 * @param array{
	 *   documentId:    int|string,
	 *   documentTitle: string,
	 *   platform:      string,
	 *   contentHash:   string,
	 * } $body Request body.
	 * @return array<string, mixed>|WP_Error Decoded response or error.
	 */
	public function create_session( array $body ): array|WP_Error {
		return $this->request( 'POST', '/sessions', $body );
	}

	/**
	 * Submit a batch of timing events for an active session.
	 *
	 * @param string                     $session_id API session ID.
	 * @param array<int, array<string, mixed>> $events    Array of event objects.
	 * @return array<string, mixed>|WP_Error Decoded response or error.
	 */
	public function submit_events( string $session_id, array $events ): array|WP_Error {
		return $this->request(
			'POST',
			"/sessions/{$session_id}/events",
			array( 'events' => $events )
		);
	}

	/**
	 * Create a checkpoint for an active session.
	 *
	 * @param string $session_id API session ID.
	 * @param array{
	 *   contentHash: string,
	 *   wordCount:   int,
	 *   charCount:   int,
	 *   metadata:    array<string, mixed>,
	 * } $body Checkpoint payload.
	 * @return array<string, mixed>|WP_Error Decoded response or error.
	 */
	public function create_checkpoint( string $session_id, array $body ): array|WP_Error {
		return $this->request( 'POST', "/sessions/{$session_id}/checkpoints", $body );
	}

	/**
	 * Finalize a witnessing session.
	 *
	 * @param string $session_id API session ID.
	 * @param array{
	 *   contentHash:   string,
	 *   wordCount:     int,
	 *   finalSnapshot: array<string, mixed>,
	 * } $body Finalization payload.
	 * @return array<string, mixed>|WP_Error Decoded response or error.
	 */
	public function finalize_session( string $session_id, array $body ): array|WP_Error {
		return $this->request( 'POST', "/sessions/{$session_id}/finalize", $body );
	}

	/**
	 * Retrieve the evidence record for a session.
	 *
	 * @param string $session_id API session ID.
	 * @return array<string, mixed>|WP_Error Decoded response or error.
	 */
	public function get_evidence( string $session_id ): array|WP_Error {
		return $this->request( 'GET', "/sessions/{$session_id}/evidence" );
	}

	/**
	 * Verify an evidence packet.
	 *
	 * @param array<string, mixed> $payload Payload to verify (session ID, hash, etc.).
	 * @return array<string, mixed>|WP_Error Decoded response or error.
	 */
	public function verify_evidence( array $payload ): array|WP_Error {
		return $this->request( 'POST', '/verify', $payload );
	}

	// -------------------------------------------------------------------------
	// Internal helpers
	// -------------------------------------------------------------------------

	/**
	 * Perform an HTTP request to the API with retry / backoff logic.
	 *
	 * @param string               $method HTTP method ('GET' or 'POST').
	 * @param string               $path   API path (starts with '/').
	 * @param array<string, mixed> $body   Optional request body (ignored for GET).
	 * @return array<string, mixed>|WP_Error
	 */
	private function request( string $method, string $path, array $body = array() ): array|WP_Error {
		if ( empty( $this->api_key ) ) {
			return new WP_Error(
				'writersproof_no_api_key',
				__( 'WritersProof API key is not configured.', 'writersproof' )
			);
		}

		$url     = self::API_BASE . $path;
		$headers = $this->build_headers();
		$attempt = 0;
		$last_error = null;

		while ( $attempt < self::MAX_RETRIES ) {
			$args = array(
				'method'  => $method,
				'headers' => $headers,
				'timeout' => self::TIMEOUT,
			);

			if ( 'POST' === $method && ! empty( $body ) ) {
				$encoded = wp_json_encode( $body );
				if ( false === $encoded ) {
					return new WP_Error(
						'writersproof_encode_error',
						__( 'Failed to encode request body as JSON.', 'writersproof' )
					);
				}
				$args['body'] = $encoded;
			}

			$response = wp_remote_request( $url, $args );

			if ( is_wp_error( $response ) ) {
				$last_error = $response;
				++$attempt;
				$this->sleep_backoff( $attempt );
				continue;
			}

			$code = (int) wp_remote_retrieve_response_code( $response );

			// 2xx: success.
			if ( $code >= 200 && $code < 300 ) {
				return $this->decode_body( $response );
			}

			// 429 Too Many Requests: respect Retry-After if present.
			if ( 429 === $code ) {
				$retry_after = max( 1, min( 60, intval( wp_remote_retrieve_header( $response, 'retry-after' ) ) ) );
				if ( function_exists( 'sleep' ) ) {
					sleep( $retry_after );
				}
				++$attempt;
				continue;
			}

			// 5xx: exponential backoff.
			if ( $code >= 500 ) {
				$last_error = $this->error_from_response( $code, $response );
				++$attempt;
				$this->sleep_backoff( $attempt );
				continue;
			}

			// 4xx (not 429): non-retryable client error.
			return $this->error_from_response( $code, $response );
		}

		return $last_error ?? new WP_Error(
			'writersproof_max_retries',
			sprintf(
				/* translators: %d: number of retry attempts */
				__( 'WritersProof API request failed after %d attempts.', 'writersproof' ),
				self::MAX_RETRIES
			)
		);
	}

	/**
	 * Build the HTTP request headers.
	 *
	 * @return array<string, string>
	 */
	private function build_headers(): array {
		return array(
			'Authorization'    => 'Bearer ' . $this->api_key,
			'Content-Type'     => 'application/json',
			'Accept'           => 'application/json',
			'X-Client-Platform' => 'wordpress',
			'X-Client-Version'  => WRITERSPROOF_VERSION,
		);
	}

	/**
	 * Decode the JSON body of an HTTP response.
	 *
	 * @param array<string, mixed>|WP_Error $response wp_remote_* response.
	 * @return array<string, mixed>|WP_Error
	 */
	private function decode_body( $response ): array|WP_Error {
		$raw = wp_remote_retrieve_body( $response );

		if ( '' === $raw ) {
			return array();
		}

		$data = json_decode( $raw, true );

		if ( JSON_ERROR_NONE !== json_last_error() ) {
			return new WP_Error(
				'writersproof_decode_error',
				sprintf(
					/* translators: %s: JSON parse error message */
					__( 'Failed to parse API response: %s', 'writersproof' ),
					json_last_error_msg()
				)
			);
		}

		return is_array( $data ) ? $data : array();
	}

	/**
	 * Build a WP_Error from a non-2xx HTTP response.
	 *
	 * @param int                          $code     HTTP status code.
	 * @param array<string, mixed>|WP_Error $response wp_remote_* response.
	 * @return WP_Error
	 */
	private function error_from_response( int $code, $response ): WP_Error {
		$body    = $this->decode_body( $response );
		$message = '';

		if ( is_array( $body ) && isset( $body['message'] ) ) {
			$message = (string) $body['message'];
		} elseif ( is_array( $body ) && isset( $body['error'] ) ) {
			$message = (string) $body['error'];
		}

		if ( '' === $message ) {
			$message = sprintf(
				/* translators: %d: HTTP status code */
				__( 'WritersProof API returned HTTP %d.', 'writersproof' ),
				$code
			);
		}

		return new WP_Error( 'writersproof_api_error_' . $code, $message, array( 'status' => $code ) );
	}

	/**
	 * Sleep for an exponentially increasing duration based on attempt number.
	 *
	 * @param int $attempt Current attempt number (1-based).
	 */
	private function sleep_backoff( int $attempt ): void {
		$seconds = self::BASE_BACKOFF * ( 2 ** ( $attempt - 1 ) );
		// Cap at 16s to avoid excessive delays in the request cycle.
		sleep( min( $seconds, 16 ) );
	}
}
