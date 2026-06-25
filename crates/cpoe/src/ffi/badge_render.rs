// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI entrypoints for rendering the canonical WritersProof badge artwork.
//!
//! The badge is rendered by the shared `badge_fingerprint` core — the SAME
//! deterministic, integer/fixed-point renderer used by the wasm verify portal.
//! Exposing it here lets the native apps (macOS / Windows) display the exact
//! badge a verifier re-derives from the signed credential: render == verify.
//!
//! All functions are pure (no IO) and degrade safely: an unknown `mode` falls
//! back to Human-Authored and an unknown `tier` to the lowest assurance
//! (Declared), so a forged or malformed field can never inflate the rendered
//! badge.

use crate::ffi::types::catch_ffi_panic;
use badge_fingerprint::{render_badge_svg, short_id_from_identifier, Mode, Tier};

/// Render the canonical badge SVG for a `WP-XXX-XXX-XXX-C` short-id.
///
/// `mode` accepts the engine's `AuthorshipMode` slugs (`human-authored`,
/// `ai-assisted-disclosed`, `human-revised`); `tier` accepts
/// `verified` / `corroborated` / `declared` (and the engine's internal tier
/// strings `hardware_bound` / `attested_software`). Unknown values degrade
/// safely. Output is byte-identical to the wasm portal's render for the same
/// inputs.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_render_badge_svg(short_id: String, mode: String, tier: String) -> String {
    catch_ffi_panic!(String::new(), {
        render_badge_svg(&short_id, Mode::from_slug(&mode), Tier::from_slug(&tier))
    })
}

/// Derive the `WP-XXX-XXX-XXX-C` short-id from an identifier (an author DID, or a
/// `verify.writersproof.com` credential id) and render the canonical badge SVG.
///
/// Convenience for the apps: the credential carries the author DID, so the badge
/// can be drawn directly from it without the caller computing the short-id.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_render_badge_for_identifier(identifier: String, mode: String, tier: String) -> String {
    catch_ffi_panic!(String::new(), {
        let short_id = short_id_from_identifier(&identifier);
        render_badge_svg(&short_id, Mode::from_slug(&mode), Tier::from_slug(&tier))
    })
}

/// Derive the canonical `WP-XXX-XXX-XXX-C` short-id from an identifier (author DID or
/// verify-portal id). Lets the app display and link the same short-id carried in
/// the signed credential.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_badge_short_id_from_identifier(identifier: String) -> String {
    catch_ffi_panic!(String::new(), { short_id_from_identifier(&identifier) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_is_deterministic_and_nonempty() {
        let did = "did:key:z6MkBadgeFfiRender";
        let a = ffi_render_badge_for_identifier(
            did.to_string(),
            "human-authored".into(),
            "verified".into(),
        );
        let b = ffi_render_badge_for_identifier(
            did.to_string(),
            "human-authored".into(),
            "verified".into(),
        );
        assert!(a.starts_with("<svg"));
        assert_eq!(a, b, "render must be deterministic for the same inputs");
    }

    #[test]
    fn render_matches_short_id_path() {
        // ffi_render_badge_for_identifier must equal: derive short-id, then render.
        let did = "did:key:z6MkBadgeFfiEquiv";
        let short_id = ffi_badge_short_id_from_identifier(did.to_string());
        assert!(short_id.starts_with("WP-"));
        let via_did = ffi_render_badge_for_identifier(
            did.to_string(),
            "ai-assisted-disclosed".into(),
            "corroborated".into(),
        );
        let via_short = ffi_render_badge_svg(
            short_id,
            "ai-assisted-disclosed".into(),
            "corroborated".into(),
        );
        assert_eq!(via_did, via_short);
    }

    #[test]
    fn unknown_fields_degrade_safely() {
        // Unknown mode/tier must not panic and must produce a valid badge.
        let svg = ffi_render_badge_svg(
            "WP-2345-6789-ABCD-EFGH".into(),
            "totally-bogus-mode".into(),
            "ultra-platinum".into(),
        );
        assert!(svg.starts_with("<svg"));
        // Degraded tier is Declared (the lowest), matching Tier::from_slug.
        let declared = ffi_render_badge_svg(
            "WP-2345-6789-ABCD-EFGH".into(),
            "human-authored".into(),
            "declared".into(),
        );
        assert_eq!(svg, declared);
    }
}
