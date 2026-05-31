<?php
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Exception class for WritersProof API errors.
 *
 * @package   local_writersproof
 * @copyright 2026 WritersLogic, Inc.
 * @license   https://www.gnu.org/licenses/gpl-3.0.html GNU GPL v3 or later
 */

namespace local_writersproof;

defined('MOODLE_INTERNAL') || die();

/**
 * Thrown when a WritersProof API call fails in a non-recoverable way.
 *
 * The {@see is_retryable()} method distinguishes transient errors (rate limiting,
 * server errors) from permanent failures (bad request, unauthorized, not found).
 */
class api_exception extends \RuntimeException {

    /** @var bool Whether the failed request should be retried. */
    private bool $retryable;

    /**
     * @param string         $message   Human-readable error description.
     * @param int            $code      HTTP status code or 0 for transport errors.
     * @param bool           $retryable True when the caller should retry.
     * @param \Throwable|null $previous  Chained exception, if any.
     */
    public function __construct(
        string $message,
        int $code = 0,
        bool $retryable = false,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->retryable = $retryable;
    }

    /**
     * Whether this error is likely transient and the request may be retried.
     */
    public function is_retryable(): bool {
        return $this->retryable;
    }
}
