<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * WritersProof API HTTP client.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

namespace local_writersproof;

defined('MOODLE_INTERNAL') || die();

/**
 * HTTP client for the WritersProof API.
 *
 * All methods return a decoded PHP array on success or throw a
 * {@see \local_writersproof\api_exception} on unrecoverable failure.
 * Transient 429/5xx responses are retried up to MAX_RETRIES times with
 * exponential back-off before the exception is raised.
 */
class client {

    /** Base URL for the WritersProof API. */
    private const BASE_URL = 'https://api.writerslogic.com/v1';

    /** Platform identifier sent in every request. */
    private const CLIENT_PLATFORM = 'moodle';

    /** Plugin version string. */
    private const CLIENT_VERSION = '1.0.0';

    /** User-Agent header value. */
    private const USER_AGENT = 'WritersProof-Moodle/1.0.0';

    /** Maximum number of attempts per request (1 original + 2 retries). */
    private const MAX_RETRIES = 3;

    /** cURL timeout in seconds. */
    private const TIMEOUT_SECONDS = 30;

    /** Initial retry delay in milliseconds. */
    private const RETRY_DELAY_MS = 500;

    /** @var string WritersProof API key. */
    private string $apikey;

    /**
     * Constructor.
     *
     * @throws \local_writersproof\api_exception When API key is not configured.
     */
    public function __construct() {
        $apikey = get_config('local_writersproof', 'apikey');
        if (empty($apikey)) {
            throw new api_exception('WritersProof API key is not configured.');
        }
        $this->apikey = $apikey;
    }

    // -------------------------------------------------------------------------
    // Public API methods
    // -------------------------------------------------------------------------

    /**
     * Create a new remote attestation session.
     *
     * @param  array  $payload  Associative array with keys: user_id, context, metadata.
     * @return array            Decoded response containing 'session_id' and 'status'.
     * @throws \local_writersproof\api_exception
     */
    public function create_session(array $payload): array {
        return $this->request('POST', '/sessions', $payload);
    }

    /**
     * Submit a batch of captured editor events to an existing session.
     *
     * @param  string $sessionid  Remote session ID.
     * @param  array  $events     Array of event objects (type, timestamp_ms, metadata).
     * @return array              Decoded response containing 'accepted' count.
     * @throws \local_writersproof\api_exception
     */
    public function submit_events(string $sessionid, array $events): array {
        $this->validate_session_id($sessionid);
        return $this->request('POST', '/sessions/' . rawurlencode($sessionid) . '/events', [
            'events' => $events,
        ]);
    }

    /**
     * Create a cryptographic checkpoint for an active session.
     *
     * @param  string $sessionid   Remote session ID.
     * @param  string $contenthash SHA-256 hex of current content.
     * @param  int    $wordcount   Current word count.
     * @param  int    $charcount   Current character count.
     * @return array               Decoded response containing 'checkpoint_id'.
     * @throws \local_writersproof\api_exception
     */
    public function create_checkpoint(
        string $sessionid,
        string $contenthash,
        int $wordcount,
        int $charcount
    ): array {
        $this->validate_session_id($sessionid);
        $this->validate_sha256_hex($contenthash);
        return $this->request('POST', '/sessions/' . rawurlencode($sessionid) . '/checkpoints', [
            'content_hash' => $contenthash,
            'word_count'   => $wordcount,
            'char_count'   => $charcount,
        ]);
    }

    /**
     * Finalize a session after content submission is complete.
     *
     * @param  string $sessionid   Remote session ID.
     * @param  string $contenthash Final SHA-256 hex of content.
     * @param  int    $wordcount   Final word count.
     * @return array               Decoded response containing 'evidence_id' and 'score'.
     * @throws \local_writersproof\api_exception
     */
    public function finalize_session(
        string $sessionid,
        string $contenthash,
        int $wordcount
    ): array {
        $this->validate_session_id($sessionid);
        $this->validate_sha256_hex($contenthash);
        return $this->request('POST', '/sessions/' . rawurlencode($sessionid) . '/finalize', [
            'final_content_hash' => $contenthash,
            'final_word_count'   => $wordcount,
        ]);
    }

    /**
     * Retrieve evidence packet for a finalized session.
     *
     * @param  string $sessionid  Remote session ID.
     * @return array              Decoded evidence object.
     * @throws \local_writersproof\api_exception
     */
    public function get_evidence(string $sessionid): array {
        $this->validate_session_id($sessionid);
        return $this->request('GET', '/sessions/' . rawurlencode($sessionid) . '/evidence');
    }

    /**
     * Verify a content hash against stored evidence.
     *
     * @param  string $contenthash  SHA-256 hex of content to verify.
     * @param  string $sessionid    Remote session ID the content belongs to.
     * @return array                Decoded verification result with 'verified' and 'score'.
     * @throws \local_writersproof\api_exception
     */
    public function verify(string $contenthash, string $sessionid): array {
        $this->validate_sha256_hex($contenthash);
        $this->validate_session_id($sessionid);
        return $this->request('POST', '/verify', [
            'content_hash' => $contenthash,
            'session_id'   => $sessionid,
        ]);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Execute an HTTP request against the API, retrying on transient errors.
     *
     * @param  string     $method  HTTP verb (GET, POST).
     * @param  string     $path    API path starting with '/'.
     * @param  array|null $body    JSON-encodable request body (omitted for GET).
     * @return array               Decoded JSON response body.
     * @throws \local_writersproof\api_exception
     */
    private function request(string $method, string $path, ?array $body = null): array {
        $url     = self::BASE_URL . $path;
        $attempt = 0;
        $lasterror = null;

        while ($attempt < self::MAX_RETRIES) {
            $attempt++;
            try {
                return $this->execute_request($method, $url, $body);
            } catch (api_exception $e) {
                $lasterror = $e;
                // Only retry on transient errors (429 Too Many Requests, 5xx).
                if (!$e->is_retryable()) {
                    throw $e;
                }
                if ($attempt < self::MAX_RETRIES) {
                    // Exponential back-off: 500ms, 1000ms, 2000ms.
                    $delay_ms = self::RETRY_DELAY_MS * (2 ** ($attempt - 1));
                    usleep($delay_ms * 1000);
                }
            }
        }

        throw $lasterror;
    }

    /**
     * Perform a single cURL request.
     *
     * @param  string     $method  HTTP verb.
     * @param  string     $url     Full URL.
     * @param  array|null $body    Request body or null.
     * @return array               Decoded JSON response.
     * @throws \local_writersproof\api_exception
     */
    private function execute_request(string $method, string $url, ?array $body): array {
        $ch = curl_init();
        if ($ch === false) {
            throw new api_exception('Failed to initialise cURL handle.');
        }

        try {
            $headers = [
                'Authorization: Bearer ' . $this->apikey,
                'X-Client-Platform: ' . self::CLIENT_PLATFORM,
                'X-Client-Version: ' . self::CLIENT_VERSION,
                'Accept: application/json',
            ];

            $options = [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => self::TIMEOUT_SECONDS,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_USERAGENT      => self::USER_AGENT,
                CURLOPT_FOLLOWLOCATION => false,
                // Verify SSL — Moodle's CA bundle path.
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ];

            if ($method === 'POST') {
                $options[CURLOPT_POST] = true;
                if ($body !== null) {
                    $encoded = json_encode($body, JSON_THROW_ON_ERROR);
                    $options[CURLOPT_POSTFIELDS] = $encoded;
                    $headers[] = 'Content-Type: application/json';
                    $headers[] = 'Content-Length: ' . strlen($encoded);
                }
            } elseif ($method === 'GET') {
                $options[CURLOPT_HTTPGET] = true;
            } else {
                throw new api_exception('Unsupported HTTP method: ' . $method);
            }

            $options[CURLOPT_HTTPHEADER] = $headers;
            curl_setopt_array($ch, $options);

            $response = curl_exec($ch);
            $curlerr  = curl_error($ch);
            $httpcode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

        } finally {
            curl_close($ch);
        }

        if ($response === false) {
            throw new api_exception(
                'cURL request failed: ' . $curlerr,
                0,
                retryable: true
            );
        }

        if ($httpcode === 429 || ($httpcode >= 500 && $httpcode < 600)) {
            throw new api_exception(
                'WritersProof API transient error (HTTP ' . $httpcode . ').',
                $httpcode,
                retryable: true
            );
        }

        if ($httpcode < 200 || $httpcode >= 300) {
            // Attempt to surface API error message from body.
            $decoded = json_decode($response, true);
            $apimsg  = is_array($decoded) && isset($decoded['error'])
                ? (string) $decoded['error']
                : 'HTTP ' . $httpcode;
            throw new api_exception(
                'WritersProof API error: ' . $apimsg,
                $httpcode,
                retryable: false
            );
        }

        try {
            $decoded = json_decode($response, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new api_exception(
                'Invalid JSON response from WritersProof API: ' . $e->getMessage(),
                retryable: false
            );
        }

        if (!is_array($decoded)) {
            throw new api_exception(
                'Unexpected response shape from WritersProof API.',
                retryable: false
            );
        }

        return $decoded;
    }

    /**
     * Validate a session ID is safe to embed in a URL path.
     *
     * @param  string $sessionid
     * @throws \local_writersproof\api_exception
     */
    private function validate_session_id(string $sessionid): void {
        if (strlen($sessionid) < 1 || strlen($sessionid) > 64) {
            throw new api_exception('Invalid session ID length.');
        }
        if (!preg_match('/\A[A-Za-z0-9\-_]+\z/', $sessionid)) {
            throw new api_exception('Session ID contains disallowed characters.');
        }
    }

    /**
     * Validate a value is a 64-character lowercase hex string (SHA-256).
     *
     * @param  string $hex
     * @throws \local_writersproof\api_exception
     */
    private function validate_sha256_hex(string $hex): void {
        if (!preg_match('/\A[0-9a-f]{64}\z/', $hex)) {
            throw new api_exception('Invalid SHA-256 hex string.');
        }
    }
}
