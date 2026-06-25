//! Deterministic generative fingerprint badge artwork for WritersProof.
//!
//! Given a short-id (e.g. `WP-7F3C-A9B1`), this crate derives a tamper-evident
//! badge: an algorithmically-generated fingerprint plus several encoded channels
//! (seal-ring tooth-code, dot-row checksum, optional stars) that all recompute
//! from the same id. Output is an SVG string and is byte-identical for a given
//! id on every platform: all geometry is computed in integer / Q16.16
//! fixed-point math (see [`fixed`]). The crate is `wasm`-clean — the core has no
//! OS or IO dependencies.
//!
//! # Entry points
//! - [`derive_features`] — inspect the raw feature vector `f(id)`.
//! - [`render_badge_svg`] — the full badge (frame + channels).
//! - [`render_fingerprint_svg`] — just the fingerprint, for isolated testing.
//!
//! # Versioning
//! The hash preimage is `"fp-v1:" + short_id` ([`features::VERSION`]); bumping
//! the tag cleanly re-keys every badge.

pub mod badge;
pub mod features;
pub mod fingerprint;
pub mod fixed;
pub mod short_id;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use badge::{render_badge_svg, render_fingerprint_svg, Mode, Tier};
pub use features::{derive_features, FeatureVector, PatternClass};
pub use short_id::{payload_from_identifier, short_id_from_identifier, validate};
