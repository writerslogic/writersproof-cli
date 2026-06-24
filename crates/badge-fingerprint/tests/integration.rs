//! Cross-cutting determinism / containment / distinctness tests.

use badge_fingerprint::features::{Minutia, MINUTIAE};
use badge_fingerprint::fingerprint::{build_ridges, clamp_slot, feat_to_slot, SLOT};
use badge_fingerprint::fixed::{self};
use badge_fingerprint::{derive_features, render_badge_svg, render_fingerprint_svg, Mode, Tier};

/// Slot inset must match `fingerprint::INSET` (8). Geometry is clamped to this.
const SOFT_LO: i64 = 8;
const SOFT_HI: i64 = SLOT - 8;

#[test]
fn determinism_full_badge_byte_identical() {
    for id in [
        "WP-7F3C-A9B1",
        "WP-0000-0000",
        "WP-FFFF-FFFF",
        "WP-1A2B-3C4D",
    ] {
        let a = render_badge_svg(id, Mode::AiAssisted, Tier::Corroborated);
        let b = render_badge_svg(id, Mode::AiAssisted, Tier::Corroborated);
        assert_eq!(a, b, "badge SVG not deterministic for {id}");

        let fa = render_fingerprint_svg(id);
        let fb = render_fingerprint_svg(id);
        assert_eq!(fa, fb, "fingerprint SVG not deterministic for {id}");
    }
}

#[test]
fn different_ids_differ() {
    let a = derive_features("WP-0000-0001");
    let b = derive_features("WP-0000-0002");
    assert_ne!(a, b);
}

#[test]
fn containment_ridges_within_slot() {
    // All ridge geometry must stay within the soft inset (and thus inside the
    // clip rect). Allow a tiny epsilon for the final integration step.
    let eps = fixed::from_ratio(11, 10); // ~1.1 unit (one integration step)
    for i in 0..120u32 {
        let id = format!("WP-{:04X}-{:04X}", i, i.wrapping_mul(40503));
        let f = derive_features(&id);
        for r in build_ridges(&f) {
            for p in &r.pts {
                assert!(
                    p.x >= fixed::from_int(SOFT_LO) - eps && p.x <= fixed::from_int(SOFT_HI) + eps,
                    "ridge x {} outside slot for {id}",
                    fixed::fmt(p.x, 3)
                );
                assert!(
                    p.y >= fixed::from_int(SOFT_LO) - eps && p.y <= fixed::from_int(SOFT_HI) + eps,
                    "ridge y {} outside slot for {id}",
                    fixed::fmt(p.y, 3)
                );
            }
        }
    }
}

#[test]
fn containment_minutiae_within_slot() {
    for i in 0..120u32 {
        let id = format!("WP-{:04X}-{:04X}", i, i.wrapping_mul(2246822519));
        let f = derive_features(&id);
        assert_eq!(f.minutiae.len(), MINUTIAE);
        for m in &f.minutiae {
            let p = clamp_slot(feat_to_slot(m.x, m.y));
            assert!(p.x >= fixed::from_int(SOFT_LO) && p.x <= fixed::from_int(SOFT_HI));
            assert!(p.y >= fixed::from_int(SOFT_LO) && p.y <= fixed::from_int(SOFT_HI));
            let _: &Minutia = m;
        }
    }
}

#[test]
fn distinctness_100_ids_unique_and_spread() {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    let mut prints: HashSet<String> = HashSet::new();
    let (mut loops, mut whorls, mut arches) = (0, 0, 0);
    for i in 0..100u32 {
        let id = format!("WP-{:04X}-{:04X}", i, i.wrapping_mul(2654435761));
        let f = derive_features(&id);
        // serialize the feature vector and require uniqueness.
        let json = serde_json::to_string(&f).unwrap();
        assert!(seen.insert(json), "duplicate FeatureVector at id {id}");
        // distinct rendered fingerprints too.
        let svg = render_fingerprint_svg(&id);
        assert!(prints.insert(svg), "duplicate fingerprint SVG at id {id}");
        match f.pattern {
            badge_fingerprint::PatternClass::Loop => loops += 1,
            badge_fingerprint::PatternClass::Whorl => whorls += 1,
            badge_fingerprint::PatternClass::Arch => arches += 1,
        }
    }
    // well-spread pattern classes (each at least ~15% of 100).
    for c in [loops, whorls, arches] {
        assert!(
            c >= 15,
            "pattern skew: loops={loops} whorls={whorls} arches={arches}"
        );
    }
}

#[test]
fn svg_well_formed_enough() {
    let svg = render_badge_svg("WP-7F3C-A9B1", Mode::HumanAuthored, Tier::Verified);
    assert!(svg.starts_with("<svg"));
    assert!(svg.ends_with("</svg>"));
    assert!(svg.contains("WP-7F3C-A9B1"));
    assert!(svg.contains("VERIFIED"));
    // balanced-ish: equal count of <svg and </svg
    assert_eq!(svg.matches("<svg").count(), 1);
}
