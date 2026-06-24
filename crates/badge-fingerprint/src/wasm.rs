//! WASM bindings for the badge-fingerprint core.
//!
//! Build with: `wasm-pack build --target web --features wasm`
//!
//! The same deterministic core renders badges natively (CLI / desktop apps) and
//! in the browser, so the verify portal can re-derive the canonical badge from a
//! signed short-id and confirm it matches the presented artwork (render ==
//! verify). Every function is pure: identical input yields byte-identical output
//! on every platform.

use wasm_bindgen::prelude::*;

use crate::badge::{render_badge_svg, render_fingerprint_svg, Mode, Tier};
use crate::features::derive_features;
use crate::short_id::short_id_from_identifier;

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

/// Derive the canonical `WP-XXXX-XXXX` short-id from an existing identifier (an
/// author DID, or a verify.writersproof.com id). Lets the portal recompute the
/// short-id and confirm it matches the value carried in the signed credential.
#[wasm_bindgen]
pub fn short_id_from_id(identifier: &str) -> String {
    short_id_from_identifier(identifier)
}

/// Derive the raw feature vector `f(id)` as a JSON string, for channel-level
/// verification (tooth-code, dot positions, stars, minutiae). A forger must
/// match every channel; this lets the portal recompute them from the signed id.
#[wasm_bindgen]
pub fn features_json(short_id: &str) -> Result<String, JsError> {
    serde_json::to_string(&derive_features(short_id))
        .map_err(|e| JsError::new(&format!("feature serialization failed: {e}")))
}
