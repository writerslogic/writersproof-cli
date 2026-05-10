// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared constants for forensic analysis modules.

/// Zone ID for correction/backspace keystrokes in jitter samples.
pub const CORRECTION_ZONE: u8 = 0xFF;

/// Pause threshold: IKI >= this is considered a pause (2 seconds).
pub const PAUSE_THRESHOLD_NS: u64 = 2_000_000_000;

/// Burst threshold: IKI < this is considered within a typing burst (200ms).
pub const BURST_THRESHOLD_NS: u64 = 200_000_000;
