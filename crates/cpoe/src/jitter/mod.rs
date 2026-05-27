// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Jitter chain: timing jitter analysis, typing profiles, zone-based detection.
//!
//! ## Submodules
//!
//! - [`simple`] — Simple jitter session (legacy capture used by platform hooks)
//! - [`session`] — Core jitter chain types (Parameters, Sample, Session, Evidence)
//! - [`verification`] — Chain verification and encoding for seeded jitter chains
//! - [`codec`] — Binary codec, chain comparison/continuity, format validation
//! - [`engine`] — Zone-committed jitter engine for real-time keystroke monitoring
//! - [`profile`] — Typing profile analysis and plausibility checking
//! - [`content`] — Content-based verification and zone analysis
//! - [`zones`] — QWERTY keyboard zone mapping and zone transition types

mod codec;
mod content;
mod engine;
mod profile;
mod session;
mod simple;
mod verification;
mod zones;

#[cfg(test)]
mod tests;

use crate::DateTimeNanosExt;
use chrono::{DateTime, Utc};

/// Clamps negative (pre-epoch) timestamps to 0.
pub(crate) fn timestamp_nanos_u64(ts: DateTime<Utc>) -> u64 {
    let nanos = ts.timestamp_nanos_safe();
    if nanos < 0 {
        0
    } else {
        nanos as u64
    }
}

/// HMAC-derived zone jitter shared by [`engine`] and [`content`] verification.
pub(super) fn compute_zone_jitter(
    secret: &[u8; 32],
    ordinal: u64,
    doc_hash: &[u8; 32],
    zone_transition: u8,
    interval_bucket: u8,
    timestamp: DateTime<Utc>,
    prev_jitter: u32,
) -> u32 {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(&ordinal.to_be_bytes());
    mac.update(doc_hash);
    mac.update(&timestamp_nanos_u64(timestamp).to_be_bytes());
    mac.update(&[zone_transition]);
    mac.update(&[interval_bucket]);
    mac.update(&prev_jitter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let raw = u32::from_be_bytes(hash[0..4].try_into().expect("4-byte slice"));
    session::MIN_JITTER + (raw % session::JITTER_RANGE)
}

pub use self::simple::{SimpleJitterSample, SimpleJitterSession};

pub use self::session::{
    default_parameters, Evidence, Parameters, Sample, Session, SessionData, Statistics,
};
pub(crate) use self::session::{INTERVAL_BUCKET_SIZE_MS, NUM_INTERVAL_BUCKETS};
#[cfg(test)]
pub(crate) use self::session::{MAX_JITTER, MIN_JITTER};

pub use self::verification::{
    verify_chain, verify_chain_detailed, verify_chain_with_seed, verify_sample, VerificationResult,
};

pub use self::verification::{decode_chain, encode_chain, ChainData};

pub use self::codec::{
    compare_chains, compare_samples, decode_chain_binary, decode_sample_binary,
    encode_chain_binary, encode_sample_binary, extract_chain_hashes, find_chain_divergence,
    hash_chain_root, marshal_sample_for_signing, validate_sample_format, verify_chain_continuity,
};

pub use self::engine::{JitterEngine, JitterSample, TypingProfile};

pub use self::profile::{
    compare_profiles, interval_to_bucket, is_human_plausible, profile_distance,
    quick_verify_profile,
};

pub use self::content::{
    analyze_document_zones, expected_transition_histogram, extract_recorded_zones,
    extract_transition_histogram, transition_histogram_divergence, verify_jitter_chain,
    verify_with_content, verify_with_secret, zone_kl_divergence, ContentVerificationResult,
    ZoneTransitionHistogram,
};

pub use self::zones::{
    char_to_zone, decode_zone_transition, encode_zone_transition, is_valid_zone_transition,
    keycode_to_zone, text_to_zone_sequence, ZoneTransition,
};
