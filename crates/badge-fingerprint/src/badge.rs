//! Fixed badge template + channel rendering -> SVG string.
//!
//! The badge frame (coin-seal ring, WRITERSPROOF banner, checkmark, ribbon,
//! dots, short-id text) is IDENTICAL for every id; only the fingerprint print
//! varies. Tier sets a single-hue value ramp. The fingerprint is a deterministic
//! VISUAL COMMITMENT to the short-id (`f(id)`) — the badge file (baked
//! credential) and the printed short-id carry the decodable id, NOT the ridges.
//! Outer dimensions are pixel-identical across ids.

use crate::features::{derive_features, FeatureVector, MinutiaKind};
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
    /// Single-hue navy value ramp: lower tiers are lighter. Never inverts, so a
    /// forged tier can only darken (and unknown tiers degrade to Declared).
    pub fn ink(self) -> &'static str {
        match self {
            Tier::Verified => "#16243f",
            Tier::Corroborated => "#39496a",
            Tier::Declared => "#6c778d",
        }
    }

    /// Parse a tier (case-insensitive). Unknown values degrade to `Declared` so a
    /// forged value can never inflate the displayed assurance.
    pub fn from_slug(s: &str) -> Tier {
        match s.trim().to_ascii_lowercase().as_str() {
            "verified" | "hardware_bound" => Tier::Verified,
            "corroborated" | "attested_software" => Tier::Corroborated,
            _ => Tier::Declared,
        }
    }
}

/// Authorship mode (carried in the accessible title; does not alter geometry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    HumanAuthored,
    AiAssisted,
    HumanRevised,
}

impl Mode {
    /// Parse an OB3 authorship-mode slug/label. Unknown -> `HumanAuthored`.
    pub fn from_slug(s: &str) -> Mode {
        let norm = s.trim().to_ascii_lowercase().replace([' ', '_'], "-");
        match norm.as_str() {
            "ai-assisted" | "ai-assisted-disclosed" | "ai-assisted-(disclosed)" => Mode::AiAssisted,
            "human-revised" => Mode::HumanRevised,
            _ => Mode::HumanAuthored,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Mode::HumanAuthored => "Human-Authored",
            Mode::AiAssisted => "AI-Assisted",
            Mode::HumanRevised => "Human-Revised",
        }
    }
}

// ---- Canvas geometry (fixed for all badges) -----------------------------------

const W: i64 = 300;
const H: i64 = 360;
const CX: i64 = 150;
const CY: i64 = 150; // badge disc center
const R: i64 = 120; // outer scallop reference radius
const RING_INNER_EDGE: i64 = 96; // 0.80R: inner edge of the coin band

// Fingerprint print: offset-left fingertip oval (one element of the seal, NOT
// filling the interior — a full-interior print reads as a biometric id badge).
const FP_OCX: i64 = 132;
const FP_OCY: i64 = 152;
const FP_RY: i64 = 67;

const INK: &str = "#16243f"; // deep navy (also the short-id text, always dark)
const PAPER: &str = "#ffffff";

/// Render the full badge for an id. Frame identical across ids; print varies.
pub fn render_badge_svg(short_id: &str, mode: Mode, tier: Tier) -> String {
    let f = derive_features(&fp_seed(short_id));
    let ink = tier.ink();
    let mut s = String::with_capacity(20_000);

    write!(
        s,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{W}\" height=\"{H}\" viewBox=\"0 0 {W} {H}\" fill=\"none\">"
    )
    .unwrap();
    // Accessible text alternative (tier + mode + id).
    write!(
        s,
        "<title>WritersProof badge: {} — {}. {}</title>",
        mode.label(),
        tier.label(),
        xml_escape(short_id)
    )
    .unwrap();
    write!(s, "<rect width=\"{W}\" height=\"{H}\" fill=\"{PAPER}\"/>").unwrap();
    write!(
        s,
        "<defs><clipPath id=\"slot\"><path d=\"{}\"/></clipPath></defs>",
        FINGERTIP_PATH
    )
    .unwrap();

    coin_ring(&mut s, ink);
    top_banner(&mut s, ink);
    fingerprint_in_slot(&mut s, &f, ink);
    checkmark(&mut s, ink);
    ribbon(&mut s, tier, ink);
    dot_row(&mut s, tier, ink);
    short_id_text(&mut s, short_id);

    s.push_str("</svg>");
    s
}

/// Render only the fingerprint (slot-sized square) for isolated testing.
pub fn render_fingerprint_svg(short_id: &str) -> String {
    let f = derive_features(&fp_seed(short_id));
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
    emit_fingerprint(&mut s, &f, 0, 0, INK);
    s.push_str("</g></svg>");
    s
}

// ---- Frame elements -----------------------------------------------------------

/// Fixed fingertip-silhouette clip path (identical for every badge).
const FINGERTIP_PATH: &str = "M132 85 C185 85 185 185.5 164.9 212.3 C145.8 219 118.2 219 99.1 212.3 C79 185.5 79 85 132 85 Z";

/// Solid navy coin band: rounded scallops on a smooth-edged annulus. Footprint
/// fixed for all badges; tier sets the ink.
fn coin_ring(s: &mut String, ink: &str) {
    const N: i32 = 36; // scallop count
    const STEPS: i32 = 288;
    let base_r = fixed::from_ratio(R * 965, 1000);
    let amp = fixed::from_ratio(R * 40, 1000);
    write!(s, "<path fill-rule=\"evenodd\" fill=\"{ink}\" d=\"").unwrap();
    for k in 0..STEPS {
        let ang = ((k as i64 * fixed::TURN as i64) / STEPS as i64) as i32;
        let rr = base_r + fixed::mul(amp, fixed::cos(N * ang));
        let p = polar(ang, rr);
        write!(
            s,
            "{}{} {}",
            if k == 0 { "M" } else { "L" },
            fixed::fmt(p.x, 1),
            fixed::fmt(p.y, 1)
        )
        .unwrap();
    }
    let ri = RING_INNER_EDGE;
    write!(
        s,
        "Z M{} {} A{} {} 0 1 0 {} {} A{} {} 0 1 0 {} {} Z\"/>",
        CX + ri,
        CY,
        ri,
        ri,
        CX - ri,
        CY,
        ri,
        ri,
        CX + ri,
        CY
    )
    .unwrap();
    write!(
        s,
        "<circle cx=\"{CX}\" cy=\"{CY}\" r=\"{}\" fill=\"none\" stroke=\"{ink}\" stroke-width=\"1.4\"/>",
        ri - 3
    )
    .unwrap();
}

/// Curved "WRITERSPROOF" banner along the top, inside the white interior.
///
/// Each glyph is placed and rotated individually (librsvg drops `<textPath>`).
fn top_banner(s: &mut String, ink: &str) {
    const TEXT: &str = "WRITERSPROOF";
    let n = TEXT.chars().count() as i32;
    let r = fixed::from_int(74);
    let half_span = fixed::TURN * 59 / 360;
    let start = fixed::QUARTER + half_span; // left end (upper-left)
    let glyph_step = if n > 1 { (2 * half_span) / (n - 1) } else { 0 };
    for (i, ch) in TEXT.chars().enumerate() {
        let ang = start - i as i32 * glyph_step;
        let p = polar(ang, r);
        let ang_deg = (ang as i64 * 360) / fixed::TURN as i64;
        let rot = 90 - ang_deg;
        write!(
            s,
            "<text x=\"{px}\" y=\"{py}\" transform=\"rotate({rot} {px} {py})\" font-family=\"Helvetica,Arial,sans-serif\" font-size=\"12\" font-weight=\"700\" letter-spacing=\"0.5\" fill=\"{ink}\" text-anchor=\"middle\">{}</text>",
            xml_escape(&ch.to_string()),
            px = fixed::fmt(p.x, 2),
            py = fixed::fmt(p.y, 2),
        )
        .unwrap();
    }
}

/// Render the fingerprint scaled to fill the offset fingertip oval, clipped.
fn fingerprint_in_slot(s: &mut String, f: &FeatureVector, ink: &str) {
    s.push_str("<g clip-path=\"url(#slot)\">");
    let active = SLOT / 2 - FP_INSET; // active print radius in slot units (42)
                                      // Uniform scale to cover the oval's larger (vertical) radius; clip trims it.
    let scale = fixed::from_ratio(FP_RY * 100, active * 100);
    write!(
        s,
        "<g transform=\"translate({FP_OCX} {FP_OCY}) scale({}) translate({} {})\">",
        fixed::fmt(scale, 4),
        -SLOT / 2,
        -SLOT / 2,
    )
    .unwrap();
    emit_fingerprint(s, f, 0, 0, ink);
    s.push_str("</g></g>");
}

/// Emit ridges + minutiae at the given slot-space origin offset.
fn emit_fingerprint(s: &mut String, f: &FeatureVector, ox: i64, oy: i64, ink: &str) {
    let ridges: Vec<Ridge> = build_ridges(f);
    let off = |p: Pt| Pt {
        x: p.x + fixed::from_int(ox),
        y: p.y + fixed::from_int(oy),
    };
    for r in ridges.iter().filter(|r| !r.fine) {
        ridge_path(s, &r.pts, off, "1.9", ink);
    }
    for r in ridges.iter().filter(|r| r.fine) {
        ridge_path(s, &r.pts, off, "1.4", ink);
    }
    for m in &f.minutiae {
        let p = clamp_slot(feat_to_slot(m.x, m.y));
        let dir = local_dir(f, p);
        let pp = off(p);
        match m.kind {
            MinutiaKind::Ending => {
                write!(
                    s,
                    "<circle cx=\"{}\" cy=\"{}\" r=\"0.9\" fill=\"{ink}\"/>",
                    fixed::fmt(pp.x, 2),
                    fixed::fmt(pp.y, 2)
                )
                .unwrap();
            }
            MinutiaKind::Bifurcation => {
                let a = polar_from(pp, dir + fixed::TURN / 8, fixed::from_int(4));
                write!(
                    s,
                    "<path d=\"M{} {}L{} {}\" stroke=\"{ink}\" stroke-width=\"1\" stroke-linecap=\"round\"/>",
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
fn ridge_path(s: &mut String, pts: &[Pt], off: impl Fn(Pt) -> Pt, width: &str, ink: &str) {
    if pts.len() < 2 {
        return;
    }
    s.push_str("<path d=\"");
    for (i, &p) in pts.iter().enumerate() {
        let q = off(p);
        let cmd = if i == 0 { 'M' } else { 'L' };
        write!(s, "{cmd}{} {}", fixed::fmt(q.x, 2), fixed::fmt(q.y, 2)).unwrap();
    }
    write!(
        s,
        "\" fill=\"none\" stroke=\"{ink}\" stroke-width=\"{width}\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
    )
    .unwrap();
}

/// Large freestanding approval checkmark, center-right, overlapping the print's
/// lower-right with a white halo so it reads over the ridges.
fn checkmark(s: &mut String, ink: &str) {
    const D: &str = "M130.8 164.4L152.4 186L205.2 128.4";
    write!(
        s,
        "<path d=\"{D}\" fill=\"none\" stroke=\"{PAPER}\" stroke-width=\"19.2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
    )
    .unwrap();
    write!(
        s,
        "<path d=\"{D}\" fill=\"none\" stroke=\"{ink}\" stroke-width=\"12.6\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
    )
    .unwrap();
}

/// Tier ribbon at the bottom of the disc (white text, white halo, folded tails).
fn ribbon(s: &mut String, tier: Tier, ink: &str) {
    const BODY: &str = "M80 212L220 212L220 237L80 237Z";
    const LTAIL: &str = "M86 235L67.4 258L77.9 247.5L90.5 237Z";
    const RTAIL: &str = "M214 235L232.6 258L222.1 247.5L209.5 237Z";
    write!(
        s,
        "<path d=\"{LTAIL}\" fill=\"{ink}\"/><path d=\"{RTAIL}\" fill=\"{ink}\"/>"
    )
    .unwrap();
    write!(
        s,
        "<path d=\"{BODY}\" fill=\"none\" stroke=\"{PAPER}\" stroke-width=\"5\" stroke-linejoin=\"round\"/>"
    )
    .unwrap();
    write!(s, "<path d=\"{BODY}\" fill=\"{ink}\"/>").unwrap();
    write!(
        s,
        "<text x=\"{CX}\" y=\"229\" font-family=\"Helvetica,Arial,sans-serif\" font-size=\"14\" font-weight=\"800\" textLength=\"109\" lengthAdjust=\"spacingAndGlyphs\" letter-spacing=\"0.5\" fill=\"{PAPER}\" text-anchor=\"middle\">{}</text>",
        tier.label()
    )
    .unwrap();
}

/// Tier dot-row below the ribbon: count = tier (3/2/1), centered.
fn dot_row(s: &mut String, tier: Tier, ink: &str) {
    let n = tier.dots() as i64;
    let gap = 13;
    let y = 272;
    let x0 = CX - gap * (n - 1) / 2;
    for i in 0..n {
        let x = x0 + i * gap;
        write!(s, "<circle cx=\"{x}\" cy=\"{y}\" r=\"4\" fill=\"{ink}\"/>").unwrap();
    }
}

/// Short-id text below the badge, monospace, always dark for legibility.
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
/// SVG y is down; negate sin so 0 brad = east, QUARTER = north (up).
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

/// Fingerprint seed: the canonical 9-symbol payload of a conformant short-id
/// (prefix/hyphens/check stripped), or the raw string for non-conformant input.
/// Hashing the payload — not the display form — lets the prefix or check symbol
/// evolve without re-keying any issued badge art (spec §8.1).
pub(crate) fn fp_seed(short_id: &str) -> String {
    crate::short_id::validate(short_id).unwrap_or_else(|| short_id.to_string())
}

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
    fn fingerprint_hashes_payload_not_display_form() {
        // The print is f(payload): a conformant display short-id and its bare
        // payload yield the same fingerprint, so prefix/check can change without
        // re-keying art.
        let did = "did:key:z6MkExample";
        let display = crate::short_id::short_id_from_identifier(did);
        let payload = crate::short_id::payload_from_identifier(did);
        assert_ne!(display, payload);
        assert_eq!(
            render_fingerprint_svg(&display),
            render_fingerprint_svg(&payload)
        );
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
    fn tier_value_ramp_distinct() {
        // Lower tiers render a lighter ink; the three are distinct.
        assert_ne!(Tier::Verified.ink(), Tier::Corroborated.ink());
        assert_ne!(Tier::Corroborated.ink(), Tier::Declared.ink());
    }

    #[test]
    fn mode_reflected_in_title() {
        let ai = render_badge_svg("WP-AAAA-BBBB", Mode::AiAssisted, Tier::Verified);
        assert!(ai.contains("AI-Assisted"));
        let hr = render_badge_svg("WP-AAAA-BBBB", Mode::HumanRevised, Tier::Verified);
        assert!(hr.contains("Human-Revised"));
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
        assert_eq!(Mode::from_slug("bogus"), Mode::HumanAuthored);
        assert_eq!(Tier::from_slug("bogus"), Tier::Declared);
        assert_eq!(Tier::from_slug(""), Tier::Declared);
    }
}
