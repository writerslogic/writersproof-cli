//! WASM bindings for the badge-fingerprint core.
//!
//! Build with: `wasm-pack build --target web --features wasm`
//!
//! The same deterministic core renders badges natively (CLI / desktop apps) and
//! in the browser, so the verify portal re-derives the canonical badge from a
//! signed short-id and confirms it matches the presented artwork (render ==
//! verify) — no second (TS) reimplementation, so nothing can drift from the
//! Rust. Every function is pure: identical input yields byte-identical output on
//! every platform.

use wasm_bindgen::prelude::*;

use crate::badge::{fp_seed, render_badge_svg, render_fingerprint_svg, Mode, Tier};
use crate::features::derive_features;
use crate::short_id::{payload_from_identifier, short_id_from_identifier, validate};

/// Render the canonical badge SVG for a short-id, authorship mode, and assurance
/// tier.
///
/// `mode` accepts the engine's `AuthorshipMode` slugs (`human-authored`,
/// `ai-assisted-disclosed`, `human-revised`); `tier` accepts
/// `verified` / `corroborated` / `declared` (and the engine's internal tier
/// strings). Unknown values degrade safely — mode to Human-Authored, tier to
/// the lowest assurance (Declared) — so a forged field can never inflate the
/// badge.
#[wasm_bindgen]
pub fn render_badge(short_id: &str, mode: &str, tier: &str) -> String {
    render_badge_svg(short_id, Mode::from_slug(mode), Tier::from_slug(tier))
}

/// Render just the deterministic fingerprint SVG for a short-id (no frame),
/// useful for isolated channel inspection.
#[wasm_bindgen]
pub fn render_fingerprint(short_id: &str) -> String {
    render_fingerprint_svg(short_id)
}

/// Derive the human display short-id `WP-XXX-XXX-XXX-C` from an existing
/// identifier (an author DID, or a verify.writersproof.com id). Lets the portal
/// recompute the short-id and confirm it matches the signed credential.
#[wasm_bindgen]
pub fn short_id_from_id(identifier: &str) -> String {
    short_id_from_identifier(identifier)
}

/// Derive the canonical 9-symbol payload (the lookup key / fingerprint seed)
/// from an identifier. This is what the credential `id` URL carries.
#[wasm_bindgen]
pub fn payload_from_id(identifier: &str) -> String {
    payload_from_identifier(identifier)
}

/// Validate a scanned or typed short-id: normalize case and `I`/`L`/`O`, verify
/// the mod-37 check symbol, and return the canonical 9-symbol payload — or `null`
/// if malformed or the check fails. The portal calls this before resolving the
/// record, so a transcription error is caught client-side.
#[wasm_bindgen]
pub fn validate_short_id(short_id: &str) -> Option<String> {
    validate(short_id)
}

/// Derive the raw feature vector `f(payload)` as a JSON string, for channel-level
/// verification (pattern, singularities, harmonics, minutiae). Seeded from the
/// same payload as `render_badge`, so the channels match the rendered badge. A
/// forger must match every channel; this lets the portal recompute them.
#[wasm_bindgen]
pub fn features_json(short_id: &str) -> Result<String, JsError> {
    serde_json::to_string(&derive_features(&fp_seed(short_id)))
        .map_err(|e| JsError::new(&format!("feature serialization failed: {e}")))
}
