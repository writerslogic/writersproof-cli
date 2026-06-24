//! Fixed badge template + channel rendering -> SVG string.
//!
//! The badge frame (seal ring, banner, checkmark, dot row, ribbon, short-id
//! text) is IDENTICAL for every id. Only the contents of the fixed fingerprint
//! slot, the per-tooth ring heights, the dot angular positions, and (AI mode)
//! the stars change with the id. Outer dimensions are pixel-identical.

use crate::features::{
    derive_features, FeatureVector, MinutiaKind, PatternClass, StarSpec, DOT_SLOTS, TOOTH_CODE_LEN,
};
use crate::fingerprint::{
    build_ridges, clamp_slot, feat_to_slot, local_dir, Pt, Ridge, INSET as FP_INSET, SLOT,
};
use crate::fixed::{self, Fx};
use std::fmt::Write as _;

/// Assurance tier. Dot count is fixed per tier and must survive degradation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Verified,
    Corroborated,
    Declared,
}

impl Tier {
    /// Fixed dot count — never varies with id.
    pub fn dots(self) -> usize {
        match self {
            Tier::Verified => 3,
            Tier::Corroborated => 2,
            Tier::Declared => 1,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Tier::Verified => "VERIFIED",
            Tier::Corroborated => "CORROBORATED",
            Tier::Declared => "DECLARED",
        }
    }

    /// Parse a tier from a credential string (case-insensitive). Unknown values
    /// fall back to the lowest tier, `Declared`, so a forged or malformed value
    /// can never inflate the displayed assurance.
    pub fn from_slug(s: &str) -> Tier {
        match s.trim().to_ascii_lowercase().as_str() {
            "verified" | "hardware_bound" => Tier::Verified,
            "corroborated" | "attested_software" => Tier::Corroborated,
            _ => Tier::Declared,
        }
    }
}

/// Authorship mode. Only `AiAssisted` renders stars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    HumanAuthored,
    AiAssisted,
    HumanRevised,
}

impl Mode {
    /// Parse a mode from an OB3 authorship-mode slug or label (case-insensitive,
    /// `_`/spaces normalized to `-`). Recognizes the engine's
    /// `AuthorshipMode` slugs (`human-authored`, `ai-assisted-disclosed`,
    /// `human-revised`). Unknown values fall back to `HumanAuthored`.
    pub fn from_slug(s: &str) -> Mode {
        let norm = s.trim().to_ascii_lowercase().replace([' ', '_'], "-");
        match norm.as_str() {
            "ai-assisted" | "ai-assisted-disclosed" | "ai-assisted-(disclosed)" => Mode::AiAssisted,
            "human-revised" => Mode::HumanRevised,
            _ => Mode::HumanAuthored,
        }
    }
}

// ---- Canvas geometry (fixed for all badges) -----------------------------------

const W: i64 = 300;
const H: i64 = 360;
const CX: i64 = 150;
const CY: i64 = 150; // badge disc center
const RING_OUTER: i64 = 120;
const RING_INNER: i64 = 100;
const SLOT_R: i64 = 70; // radius of fingerprint slot region
const TEETH: usize = TOOTH_CODE_LEN; // scallops on the ring

const INK: &str = "#16243f"; // deep navy, matches brand mark
const PAPER: &str = "#ffffff";

/// Render the full badge for an id. Frame is identical across ids; channels vary.
pub fn render_badge_svg(short_id: &str, mode: Mode, tier: Tier) -> String {
    let f = derive_features(short_id);
    let mut s = String::with_capacity(16_000);

    write!(
        s,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" width=\"{W}\" height=\"{H}\" viewBox=\"0 0 {W} {H}\" fill=\"none\">"
    )
    .unwrap();

    // White backing so fax/1-bit threshold has a defined background.
    write!(s, "<rect width=\"{W}\" height=\"{H}\" fill=\"{PAPER}\"/>").unwrap();

    // clipPath that confines the fingerprint to the slot disc.
    write!(
        s,
        "<defs><clipPath id=\"slot\"><circle cx=\"{CX}\" cy=\"{CY}\" r=\"{SLOT_R}\"/></clipPath></defs>"
    )
    .unwrap();

    scalloped_ring(&mut s, &f);
    top_banner(&mut s);
    fingerprint_in_slot(&mut s, &f);
    checkmark(&mut s);
    dot_row(&mut s, &f, tier);
    if mode == Mode::AiAssisted {
        stars(&mut s, &f);
    }
    mode_glyph(&mut s, mode);
    ribbon(&mut s, tier);
    short_id_text(&mut s, short_id);

    s.push_str("</svg>");
    s
}

/// Render only the fingerprint (slot-sized square) for isolated testing.
pub fn render_fingerprint_svg(short_id: &str) -> String {
    let f = derive_features(short_id);
    let mut s = String::with_capacity(12_000);
    write!(
        s,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{SLOT}\" height=\"{SLOT}\" viewBox=\"0 0 {SLOT} {SLOT}\" fill=\"none\">"
    )
    .unwrap();
    write!(
        s,
        "<rect width=\"{SLOT}\" height=\"{SLOT}\" fill=\"{PAPER}\"/>"
    )
    .unwrap();
    write!(
        s,
        "<defs><clipPath id=\"fp\"><rect x=\"0\" y=\"0\" width=\"{SLOT}\" height=\"{SLOT}\"/></clipPath></defs>"
    )
    .unwrap();
    s.push_str("<g clip-path=\"url(#fp)\">");
    emit_fingerprint(&mut s, &f, 0, 0);
    s.push_str("</g></svg>");
    s
}

// ---- Frame elements -----------------------------------------------------------

/// The scalloped notary-seal ring. Footprint is FIXED; only per-tooth height
/// (tall vs short) varies with the id (the ring tooth-code).
fn scalloped_ring(s: &mut String, f: &FeatureVector) {
    // Two concentric stroked circles. Stroke weights are kept heavy so the ring
    // survives a 1/3 downscale to the 0.5" fax floor.
    write!(
        s,
        "<circle cx=\"{CX}\" cy=\"{CY}\" r=\"{RING_OUTER}\" fill=\"none\" stroke=\"{INK}\" stroke-width=\"4.5\"/>"
    )
    .unwrap();
    write!(
        s,
        "<circle cx=\"{CX}\" cy=\"{CY}\" r=\"{RING_INNER}\" fill=\"none\" stroke=\"{INK}\" stroke-width=\"3\"/>"
    )
    .unwrap();

    // Scallop teeth around the outer ring. Each tooth is a filled bump; raised
    // teeth (tooth_code true) are taller. Geometry/positions are constant.
    let step = fixed::TURN / TEETH as i32;
    for i in 0..TEETH {
        let ang = i as i32 * step;
        let raised = *f.tooth_code.get(i).unwrap_or(&false);
        let r_base = fixed::from_int(RING_OUTER);
        let bump = if raised {
            fixed::from_int(12)
        } else {
            fixed::from_int(5)
        };
        let r_tip = r_base + bump;
        let half = step / 3;
        let p_base_a = polar(ang - half, r_base);
        let p_base_b = polar(ang + half, r_base);
        let p_tip = polar(ang, r_tip);
        write!(
            s,
            "<path d=\"M{} {}L{} {}L{} {}Z\" fill=\"{INK}\"/>",
            fixed::fmt(p_base_a.x, 2),
            fixed::fmt(p_base_a.y, 2),
            fixed::fmt(p_tip.x, 2),
            fixed::fmt(p_tip.y, 2),
            fixed::fmt(p_base_b.x, 2),
            fixed::fmt(p_base_b.y, 2),
        )
        .unwrap();
    }
}

/// Curved "WritersProof" top banner along the inner ring.
///
/// `<textPath>` is unreliable across librsvg builds (this one drops it), so each
/// glyph is placed and rotated individually with a plain `<text>` element —
/// proven to render in rsvg-convert. The word is centered over north and the
/// layout is a fixed string, so the banner is identical for every badge.
fn top_banner(s: &mut String) {
    const TEXT: &str = "WritersProof";
    let n = TEXT.chars().count() as i32;
    let r = fixed::from_int(RING_INNER - 13);
    // Spread glyphs over a top arc spanning +/- 60 deg around north (QUARTER),
    // sweeping left-to-right so the word reads naturally.
    let half_span = fixed::TURN * 60 / 360;
    let start = fixed::QUARTER + half_span; // left end (upper-left)
    let glyph_step = if n > 1 { (2 * half_span) / (n - 1) } else { 0 };

    for (i, ch) in TEXT.chars().enumerate() {
        let ang = start - i as i32 * glyph_step; // sweep L->R (decreasing angle)
        let p = polar(ang, r);
        // Upright tangent: a glyph at math-angle `ang` (north = QUARTER, CCW) on
        // a y-down canvas reads upright when rotated by (90 - ang_deg) degrees.
        let ang_deg = (ang as i64 * 360) / fixed::TURN as i64;
        let rot = 90 - ang_deg;
        write!(
            s,
            "<text x=\"{px}\" y=\"{py}\" transform=\"rotate({rot} {px} {py})\" font-family=\"Helvetica,Arial,sans-serif\" font-size=\"15\" font-weight=\"700\" fill=\"{INK}\" text-anchor=\"middle\">{}</text>",
            xml_escape(&ch.to_string()),
            px = fixed::fmt(p.x, 2),
            py = fixed::fmt(p.y, 2),
        )
        .unwrap();
    }
}

/// Render the fingerprint clipped to the slot disc.
///
/// The print is generated in a 0..SLOT box whose active (inset) circle has
/// radius `SLOT/2 - INSET`. We scale that circle up to fill the slot disc
/// (`SLOT_R`) and recenter it on the disc, so the ridges run edge-to-edge
/// across the seal instead of floating small in the middle. The transform is a
/// fixed string, so determinism is preserved.
fn fingerprint_in_slot(s: &mut String, f: &FeatureVector) {
    s.push_str("<g clip-path=\"url(#slot)\">");
    // Map slot center (SLOT/2) to disc center (CX,CY) and blow the print's
    // active radius (SLOT/2 - FP_INSET) up to SLOT_R.
    let scale_num = SLOT_R * 100;
    let scale_den = (SLOT / 2 - FP_INSET) * 100;
    write!(
        s,
        "<g transform=\"translate({CX} {CY}) scale({}) translate({} {})\">",
        fixed::fmt(fixed::from_ratio(scale_num, scale_den), 4),
        -SLOT / 2,
        -SLOT / 2,
    )
    .unwrap();
    emit_fingerprint(s, f, 0, 0);
    s.push_str("</g>");
    s.push_str("</g>");
}

/// Emit ridges + minutiae + fine layer at the given slot-space origin offset.
fn emit_fingerprint(s: &mut String, f: &FeatureVector, ox: i64, oy: i64) {
    let ridges: Vec<Ridge> = build_ridges(f);
    let off = |p: Pt| Pt {
        x: p.x + fixed::from_int(ox),
        y: p.y + fixed::from_int(oy),
    };

    // Bold primary ridges. Widths are in slot units and get scaled up ~5/3 by
    // the slot transform, so ~1.9 reads as a bold ~3.2px stroke: heavy enough to
    // survive the fax downscale, still letting many nested ridges sit side by
    // side without merging into a blob.
    for r in ridges.iter().filter(|r| !r.fine) {
        ridge_path(s, &r.pts, off, "1.9", false);
    }
    // Fine/incipient ridges: solid but slightly thinner, so they read as real
    // ridges filling the print rather than dotted noise.
    for r in ridges.iter().filter(|r| r.fine) {
        ridge_path(s, &r.pts, off, "1.4", true);
    }

    // Minutiae: subtle marks sitting ON the ridges (oriented along local flow),
    // small enough not to read as extra ink. Sizes are slot units (scaled 5/3).
    for m in &f.minutiae {
        let p = clamp_slot(feat_to_slot(m.x, m.y));
        let dir = local_dir(f, p);
        let pp = off(p);
        match m.kind {
            MinutiaKind::Ending => {
                // a tiny filled cap marking a ridge ending.
                write!(
                    s,
                    "<circle cx=\"{}\" cy=\"{}\" r=\"0.9\" fill=\"{INK}\"/>",
                    fixed::fmt(pp.x, 2),
                    fixed::fmt(pp.y, 2)
                )
                .unwrap();
            }
            MinutiaKind::Bifurcation => {
                // a short fine fork tine off the local ridge.
                let a = polar_from(pp, dir + fixed::TURN / 8, fixed::from_int(4));
                write!(
                    s,
                    "<path d=\"M{} {}L{} {}\" stroke=\"{INK}\" stroke-width=\"1\" stroke-linecap=\"round\"/>",
                    fixed::fmt(pp.x, 2),
                    fixed::fmt(pp.y, 2),
                    fixed::fmt(a.x, 2),
                    fixed::fmt(a.y, 2)
                )
                .unwrap();
            }
        }
    }
}

/// Emit one ridge as an SVG polyline path.
fn ridge_path(s: &mut String, pts: &[Pt], off: impl Fn(Pt) -> Pt, width: &str, fine: bool) {
    if pts.len() < 2 {
        return;
    }
    s.push_str("<path d=\"");
    for (i, &p) in pts.iter().enumerate() {
        let q = off(p);
        let cmd = if i == 0 { 'M' } else { 'L' };
        write!(s, "{cmd}{} {}", fixed::fmt(q.x, 2), fixed::fmt(q.y, 2)).unwrap();
    }
    let _ = fine;
    write!(
        s,
        "\" fill=\"none\" stroke=\"{INK}\" stroke-width=\"{width}\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
    )
    .unwrap();
}

/// Approval checkmark, bottom-right of the disc (fixed position).
fn checkmark(s: &mut String) {
    let bx = CX + 44;
    let by = CY + 44;
    write!(
        s,
        "<circle cx=\"{bx}\" cy=\"{by}\" r=\"20\" fill=\"{PAPER}\" stroke=\"{INK}\" stroke-width=\"3\"/>"
    )
    .unwrap();
    write!(
        s,
        "<path d=\"M{} {}L{} {}L{} {}\" fill=\"none\" stroke=\"{INK}\" stroke-width=\"3.6\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>",
        bx - 9,
        by,
        bx - 2,
        by + 7,
        bx + 10,
        by - 8
    )
    .unwrap();
}

/// Dot row: count = tier (fixed), horizontal position offset = hash checksum
/// slot. A true horizontal row just under the top banner; the whole row slides
/// left/right within a few discrete slots as a small visual checksum.
fn dot_row(s: &mut String, f: &FeatureVector, tier: Tier) {
    let n = tier.dots() as i64;
    let gap = 14; // px between dot centers (wide so dots stay separable at fax)
    let row_w = (n - 1) * gap;
    // checksum: shift the row by up to +/- a few px across DOT_SLOTS positions.
    let slot = f.dot_slot as i64 % DOT_SLOTS as i64;
    let shift = (slot - (DOT_SLOTS as i64 - 1) / 2) * 3;
    let y = CY - (RING_INNER - 26);
    let x0 = CX - row_w / 2 + shift;
    for i in 0..n {
        let x = x0 + i * gap;
        // bold radius so the tier-count survives the 0.5" fax floor.
        write!(
            s,
            "<circle cx=\"{x}\" cy=\"{y}\" r=\"4.5\" fill=\"{INK}\"/>"
        )
        .unwrap();
    }
}

/// Stars (AI-Assisted only). Discrete coarse slot + point count from hash.
fn stars(s: &mut String, f: &FeatureVector) {
    let r = fixed::from_int(RING_INNER - 14);
    for st in &f.stars {
        let ang = fixed::TURN / 12 * st.slot as i32 + fixed::TURN / 24;
        let c = polar(ang, r);
        star_glyph(s, c, st.points, fixed::from_int(6));
        let _ = st;
    }
}

fn star_glyph(s: &mut String, c: Pt, points: u8, radius: Fx) {
    let n = points.max(4) as i32;
    let inner = radius / 2;
    let step = fixed::TURN / (n * 2);
    s.push_str("<path d=\"");
    for k in 0..(n * 2) {
        let rr = if k % 2 == 0 { radius } else { inner };
        let ang = k * step - fixed::QUARTER;
        let p = Pt {
            x: c.x + fixed::mul(fixed::cos(ang), rr),
            y: c.y + fixed::mul(fixed::sin(ang), rr),
        };
        let cmd = if k == 0 { 'M' } else { 'L' };
        write!(s, "{cmd}{} {}", fixed::fmt(p.x, 2), fixed::fmt(p.y, 2)).unwrap();
    }
    write!(s, "Z\" fill=\"{INK}\"/>").unwrap();
}

/// Mode glyph at top-left (constant per mode; distinguishes the three modes).
fn mode_glyph(s: &mut String, mode: Mode) {
    let x = 30;
    let y = 36;
    match mode {
        Mode::HumanAuthored => {
            // single pen-nib triangle
            write!(s, "<path d=\"M{x} {y}l10 4l-4 10z\" fill=\"{INK}\"/>",).unwrap();
        }
        Mode::AiAssisted => {
            // small sparkle
            star_glyph(
                s,
                Pt {
                    x: fixed::from_int(x + 4),
                    y: fixed::from_int(y + 4),
                },
                4,
                fixed::from_int(7),
            );
        }
        Mode::HumanRevised => {
            // circular revision arrow
            write!(
                s,
                "<path d=\"M{} {} a7 7 0 1 1 -5 -2\" fill=\"none\" stroke=\"{INK}\" stroke-width=\"2.4\"/>",
                x + 8,
                y
            )
            .unwrap();
            write!(
                s,
                "<path d=\"M{} {}l4 -1l-1 4z\" fill=\"{INK}\"/>",
                x + 1,
                y - 2
            )
            .unwrap();
        }
    }
}

/// Tier ribbon banner at the bottom of the disc.
fn ribbon(s: &mut String, tier: Tier) {
    let y = CY + RING_OUTER - 16;
    let w = 130;
    let x0 = CX - w / 2;
    let x1 = CX + w / 2;
    // banner body with notched ends
    write!(
        s,
        "<path d=\"M{x0} {y}L{x1} {y}L{} {}L{x1} {}L{x0} {}L{} {}Z\" fill=\"{INK}\"/>",
        x1 - 8,
        y + 11,
        y + 22,
        y + 22,
        x0 + 8,
        y + 11
    )
    .unwrap();
    write!(
        s,
        "<text x=\"{CX}\" y=\"{}\" font-family=\"Helvetica,Arial,sans-serif\" font-size=\"13\" font-weight=\"700\" letter-spacing=\"1\" fill=\"{PAPER}\" text-anchor=\"middle\">{}</text>",
        y + 16,
        tier.label()
    )
    .unwrap();
}

/// Short-id text BELOW the badge, in monospace.
fn short_id_text(s: &mut String, short_id: &str) {
    write!(
        s,
        "<text x=\"{CX}\" y=\"{}\" font-family=\"'SF Mono',Menlo,monospace\" font-size=\"16\" font-weight=\"600\" letter-spacing=\"1\" fill=\"{INK}\" text-anchor=\"middle\">{}</text>",
        H - 16,
        xml_escape(short_id)
    )
    .unwrap();
}

// ---- helpers ------------------------------------------------------------------

/// Polar point around the disc center (CX,CY). Angle in brad, radius Q16.16.
/// SVG y is down; we negate the sin so 0 brad = east, QUARTER = north (up).
fn polar(angle: i32, r: Fx) -> Pt {
    Pt {
        x: fixed::from_int(CX) + fixed::mul(fixed::cos(angle), r),
        y: fixed::from_int(CY) - fixed::mul(fixed::sin(angle), r),
    }
}

/// Polar offset from an arbitrary point.
fn polar_from(c: Pt, angle: i32, r: Fx) -> Pt {
    Pt {
        x: c.x + fixed::mul(fixed::cos(angle), r),
        y: c.y - fixed::mul(fixed::sin(angle), r),
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[allow(dead_code)]
fn _uses(_p: PatternClass, _s: StarSpec) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism_byte_identical() {
        let a = render_badge_svg("WP-7F3C-A9B1", Mode::HumanAuthored, Tier::Verified);
        let b = render_badge_svg("WP-7F3C-A9B1", Mode::HumanAuthored, Tier::Verified);
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_determinism() {
        let a = render_fingerprint_svg("WP-1234-5678");
        let b = render_fingerprint_svg("WP-1234-5678");
        assert_eq!(a, b);
    }

    #[test]
    fn different_ids_differ_svg() {
        let a = render_badge_svg("WP-0000-0001", Mode::HumanAuthored, Tier::Verified);
        let b = render_badge_svg("WP-0000-0002", Mode::HumanAuthored, Tier::Verified);
        assert_ne!(a, b);
    }

    #[test]
    fn tier_dot_count_fixed() {
        assert_eq!(Tier::Verified.dots(), 3);
        assert_eq!(Tier::Corroborated.dots(), 2);
        assert_eq!(Tier::Declared.dots(), 1);
    }

    #[test]
    fn ai_mode_has_stars_others_not() {
        let ai = render_badge_svg("WP-AAAA-BBBB", Mode::AiAssisted, Tier::Verified);
        let ha = render_badge_svg("WP-AAAA-BBBB", Mode::HumanAuthored, Tier::Verified);
        // star glyphs use a filled path Z; AI badge has strictly more of them.
        assert!(ai.len() > ha.len());
    }

    #[test]
    fn from_slug_parses_ob3_values() {
        assert_eq!(Mode::from_slug("human-authored"), Mode::HumanAuthored);
        assert_eq!(Mode::from_slug("ai-assisted-disclosed"), Mode::AiAssisted);
        assert_eq!(Mode::from_slug("AI-Assisted (Disclosed)"), Mode::AiAssisted);
        assert_eq!(Mode::from_slug("human-revised"), Mode::HumanRevised);
        assert_eq!(Tier::from_slug("verified"), Tier::Verified);
        assert_eq!(Tier::from_slug("hardware_bound"), Tier::Verified);
        assert_eq!(Tier::from_slug("CORROBORATED"), Tier::Corroborated);
    }

    #[test]
    fn from_slug_unknown_degrades_safely() {
        // An unknown/forged mode can never gain AI stars; an unknown tier can
        // never inflate above the lowest assurance.
        assert_eq!(Mode::from_slug("bogus"), Mode::HumanAuthored);
        assert_eq!(Tier::from_slug("bogus"), Tier::Declared);
        assert_eq!(Tier::from_slug(""), Tier::Declared);
    }
}
