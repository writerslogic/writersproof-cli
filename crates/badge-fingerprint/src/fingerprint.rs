//! Fingerprint orientation field + ridge tracing, rendered into the fixed slot.
//!
//! The orientation field uses the Sherlock-Monro zero-pole model:
//!   theta(z) = base_rotation + 0.5 * ( sum arg(z - delta_k) - sum arg(z - core_k) )
//! plus 4 hash-derived warp harmonics. Ridges are streamlines traced
//! perpendicular to theta. Everything is computed in Q16.16 fixed-point and
//! clipped to the slot, so output is byte-identical per id and never spills the
//! ring (an SVG clipPath enforces the hard boundary on top of the soft inset).

use crate::features::{FeatureVector, MinutiaKind, PatternClass};
use crate::fixed::{self, Fx};

/// The fingerprint slot is a square of this many user units, slot-local
/// coordinates run 0..SLOT. Feature positions are normalized 0..ONE and scaled
/// into this. The badge places the slot via a transform + clipPath.
pub const SLOT: i64 = 100;

/// Inset margin (slot units) ridges/minutiae stay inside, so geometry never
/// touches the ring even before the hard clip. Exposed so the badge can match
/// its slot-disc scale to the print's active radius.
pub const INSET: i64 = 8;

/// Streamline integration step (slot units, Q16.16). Smaller = smoother.
/// One unit per step gives fine, smooth curvature while keeping point counts
/// (and SVG size) bounded.
fn step() -> Fx {
    fixed::ONE
}

/// Max points per ridge polyline before we stop integrating, per direction.
/// At one unit/step this comfortably spans the whole slot diameter (~84 units).
const MAX_RIDGE_PTS: usize = 110;

/// Ridge spacing (slot units): the target gap between adjacent bold ridges.
/// This is the separation distance for the evenly-spaced streamline placement;
/// ~5 units across an 84-unit print yields ~16-20 nested ridges, matching a
/// real loop/whorl that fills the oval while staying fax-survivable.
fn ridge_spacing() -> i64 {
    5
}

/// Hard cap on the number of bold ridges, keeping the print readable and the
/// SVG compact. Generous enough to fully fill the slot at the chosen spacing.
const MAX_RIDGES: usize = 64;

/// A 2D fixed-point point in slot space.
#[derive(Clone, Copy)]
pub struct Pt {
    pub x: Fx,
    pub y: Fx,
}

/// A traced ridge: a polyline plus whether it's a fine/decorative ridge.
pub struct Ridge {
    pub pts: Vec<Pt>,
    pub fine: bool,
}

fn slot_lo() -> Fx {
    fixed::from_int(INSET)
}
fn slot_hi() -> Fx {
    fixed::from_int(SLOT - INSET)
}

fn norm_to_slot(v: Fx) -> Fx {
    // v in 0..ONE -> 0..SLOT
    fixed::mul(v, fixed::from_int(SLOT))
}

/// Radius of the circular print region (slot units), inside the inset.
fn print_radius() -> Fx {
    fixed::from_int(SLOT / 2 - INSET)
}

/// Center of the slot in slot-local units.
fn center() -> Pt {
    Pt {
        x: fixed::from_int(SLOT / 2),
        y: fixed::from_int(SLOT / 2),
    }
}

/// A point is "inside" the print if it lies within the circular inset region.
/// A circular mask (not the square slot) makes the print read as a round
/// fingerprint that fills the seal disc instead of a square scribble.
fn inside(p: Pt) -> bool {
    let c = center();
    let dx = p.x - c.x;
    let dy = p.y - c.y;
    let r2 = fixed::mul(dx, dx) + fixed::mul(dy, dy);
    let rr = print_radius();
    r2 <= fixed::mul(rr, rr)
}

/// Orientation angle theta(z) in brad at slot-space point p.
fn theta_at(f: &FeatureVector, p: Pt) -> i32 {
    // Convert slot coords -> normalized 0..ONE for singularity math.
    let z = Pt {
        x: fixed::div(p.x, fixed::from_int(SLOT)),
        y: fixed::div(p.y, fixed::from_int(SLOT)),
    };
    let mut acc: i64 = 0; // accumulate brad
    for d in &f.deltas {
        acc += arg(z.x - d.x, z.y - d.y) as i64;
    }
    for c in &f.cores {
        acc -= arg(z.x - c.x, z.y - c.y) as i64;
    }
    // Warp harmonics: sum A_k * sin(omega_k * x + phase_k), mixing a y-term on
    // odd harmonics. amp is in brad units (Q16.16), weight is Q16.16 in
    // -ONE..ONE; their fixed-point product divided back to brad is the per-
    // harmonic perturbation.
    let turn = fixed::from_int(fixed::TURN as i64);
    let mut harm: i64 = 0;
    for (i, h) in f.harmonics.iter().enumerate() {
        let arg_brad = fixed::to_int(fixed::mul(fixed::mul(h.omega, z.x), turn)) as i32 + h.phase;
        let yarg_brad = fixed::to_int(fixed::mul(fixed::mul(h.omega, z.y), turn)) as i32 + h.phase;
        let s = fixed::sin(arg_brad);
        let sy = fixed::sin(yarg_brad);
        let weight = if i % 2 == 0 { s } else { (s + sy) / 2 };
        harm += fixed::to_int(fixed::mul(h.amp, weight));
    }

    // theta = base_rotation + 0.5 * (sum arg deltas - sum arg cores) + harmonics
    let theta = f.base_rotation as i64 + acc / 2 + harm;
    fixed::norm_brad(theta as i32)
}

/// arg of complex (x + iy) in brad. Returns 0 at origin.
fn arg(x: Fx, y: Fx) -> i32 {
    fixed::atan2(y, x)
}

/// Smallest signed difference a-b folded into -TURN/2..TURN/2 (brad).
fn ang_diff(a: i32, b: i32) -> i32 {
    let mut d = (a - b) % fixed::TURN;
    if d < -fixed::TURN / 2 {
        d += fixed::TURN;
    } else if d > fixed::TURN / 2 {
        d -= fixed::TURN;
    }
    d
}

/// Trace one streamline along the orientation field.
///
/// `theta` is a ridge *orientation* (a line, period 180 deg), not a heading.
/// Naively stepping along `theta` makes ridges double back wherever the field
/// angle wraps, producing a tangle. We instead carry a continuous heading and
/// at each step pick whichever of `theta` / `theta+180` is closest to it, so
/// the ridge flows smoothly. `dir_sign` chooses the initial side (forward vs
/// backward) from the seed.
///
/// `others` holds the points of already-placed ridges; the trace stops once it
/// drifts within the even-spacing distance of one of them, so a new streamline
/// never overlaps an existing ridge (Jobard-Lefer even-spacing condition).
fn trace(f: &FeatureVector, seed: Pt, dir_sign: i64, others: &SepGrid) -> Vec<Pt> {
    let mut pts = Vec::with_capacity(MAX_RIDGE_PTS);
    let mut p = seed;
    let st = step();
    // initial heading: theta at the seed, flipped 180 for the backward pass.
    let mut heading = theta_at(f, seed);
    if dir_sign < 0 {
        heading = fixed::norm_brad(heading + fixed::TURN / 2);
    }
    for i in 0..MAX_RIDGE_PTS {
        if !inside(p) {
            break;
        }
        // Even-spacing stop: don't let this ridge run into a placed one. Skip
        // the very first samples so a fresh seed (placed exactly on the spacing
        // line from its parent) isn't rejected instantly.
        if i > 1 && others.too_close(p) {
            break;
        }
        pts.push(p);
        let th = theta_at(f, p);
        // choose the orientation branch (th or th+180) nearest current heading.
        let alt = fixed::norm_brad(th + fixed::TURN / 2);
        let chosen = if ang_diff(th, heading).abs() <= ang_diff(alt, heading).abs() {
            th
        } else {
            alt
        };
        // limit per-step turn so a near-singularity can't snap the ridge.
        let turn = ang_diff(chosen, heading).clamp(-fixed::TURN / 12, fixed::TURN / 12);
        heading = fixed::norm_brad(heading + turn);
        let dx = fixed::mul(fixed::cos(heading), st);
        let dy = fixed::mul(fixed::sin(heading), st);
        let next = Pt {
            x: p.x + dx,
            y: p.y + dy,
        };
        if (next.x - p.x).abs() < 16 && (next.y - p.y).abs() < 16 {
            break;
        }
        p = next;
    }
    pts
}

/// Minimum separation (slot units) enforced between distinct ridges, so the
/// result is a set of bold, well-separated lines rather than an overlapping
/// scribble. This is the core of the evenly-spaced streamline placement.
fn min_sep_sq() -> Fx {
    let s = fixed::from_int(ridge_spacing());
    fixed::mul(s, s)
}

/// A uniform-bucket spatial index over the placed ridge points, so the
/// even-spacing test is O(1) per query instead of O(n) over every prior point.
/// Buckets are `ridge_spacing` wide; a query only inspects the 3x3 neighborhood,
/// which is guaranteed to contain anything within the separation distance.
struct SepGrid {
    cells: Vec<Vec<Pt>>,
    cols: i64,
    rows: i64,
    cell: i64,
}

impl SepGrid {
    fn new() -> Self {
        let cell = ridge_spacing().max(1);
        let cols = SLOT / cell + 2;
        let rows = SLOT / cell + 2;
        SepGrid {
            cells: vec![Vec::new(); (cols * rows) as usize],
            cols,
            rows,
            cell,
        }
    }

    fn coord(&self, p: Pt) -> (i64, i64) {
        let cx = (fixed::to_int(p.x) / self.cell).clamp(0, self.cols - 1);
        let cy = (fixed::to_int(p.y) / self.cell).clamp(0, self.rows - 1);
        (cx, cy)
    }

    fn insert(&mut self, p: Pt) {
        let (cx, cy) = self.coord(p);
        self.cells[(cy * self.cols + cx) as usize].push(p);
    }

    fn too_close(&self, p: Pt) -> bool {
        let lim = min_sep_sq();
        let (cx, cy) = self.coord(p);
        for gy in (cy - 1).max(0)..=(cy + 1).min(self.rows - 1) {
            for gx in (cx - 1).max(0)..=(cx + 1).min(self.cols - 1) {
                for q in &self.cells[(gy * self.cols + gx) as usize] {
                    let dx = p.x - q.x;
                    let dy = p.y - q.y;
                    if fixed::mul(dx, dx) + fixed::mul(dy, dy) < lim {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// Build ridges via evenly-spaced streamline placement (Jobard-Lefer style).
///
/// Seeds are drawn from a deterministic grid that tiles the whole circular
/// slot (plus the exact center, so the singular points are always covered),
/// visited in a fixed scan order. Each seed that is still uncovered is traced
/// far in BOTH directions until it leaves the slot or runs within the spacing
/// distance of an already-placed ridge. Because the seeds blanket the slot and
/// every trace is rejected only by genuine proximity to existing ink, the
/// result is a dense field of smooth, evenly-spaced, edge-to-edge ridges —
/// nested loops/whorls/arches that fill the oval — instead of a sparse cluster.
pub fn build_ridges(f: &FeatureVector) -> Vec<Ridge> {
    let mut ridges: Vec<Ridge> = Vec::new();
    let mut grid = SepGrid::new();
    let cap = MAX_RIDGES;

    // Seed lattice: center first (guarantees the core ridge), then a uniform
    // grid at half the ridge spacing so candidate seeds land between ridges as
    // well as on them. The fixed iteration order keeps output deterministic.
    let seeds = seed_lattice();

    let mut idx = 0u32;
    for seed in seeds {
        if ridges.len() >= cap {
            break;
        }
        if !inside(seed) || grid.too_close(seed) {
            continue;
        }
        let fwd = trace(f, seed, 1, &grid);
        let mut bwd = trace(f, seed, -1, &grid);
        bwd.reverse();
        let mut pts = bwd;
        if !fwd.is_empty() {
            pts.extend_from_slice(&fwd[1.min(fwd.len())..]);
        }
        if pts.len() < 6 {
            continue;
        }
        for &p in &pts {
            grid.insert(p);
        }
        let fine = (f.fine_ridge_mask >> (idx % 32)) & 1 == 1;
        ridges.push(Ridge { pts, fine });
        idx += 1;
    }

    if ridges.len() > cap {
        ridges.truncate(cap);
    }
    ridges
}

/// Deterministic seed positions blanketing the slot: the exact center followed
/// by a uniform lattice spaced at half the ridge gap, scanned row-major. Half
/// spacing oversamples so that wherever a ridge leaves a gap, a later seed lands
/// inside it and fills it; the even-spacing test then thins the surplus.
fn seed_lattice() -> Vec<Pt> {
    let mut v = vec![center()];
    let lo = INSET;
    let hi = SLOT - INSET;
    let stepu = ridge_spacing().max(1); // one seed per spacing cell, centered
    let half = stepu / 2;
    let mut y = lo + half;
    while y <= hi {
        let mut x = lo + half;
        while x <= hi {
            v.push(Pt {
                x: fixed::from_int(x),
                y: fixed::from_int(y),
            });
            x += stepu;
        }
        y += stepu;
    }
    v
}

/// Map a normalized feature position (0..ONE) to slot space.
pub fn feat_to_slot(x: Fx, y: Fx) -> Pt {
    Pt {
        x: norm_to_slot(x),
        y: norm_to_slot(y),
    }
}

/// Clamp a point into the soft inset so a minutia marker never spills.
pub fn clamp_slot(p: Pt) -> Pt {
    Pt {
        x: p.x.clamp(slot_lo(), slot_hi()),
        y: p.y.clamp(slot_lo(), slot_hi()),
    }
}

/// Direction (brad) of the orientation field at a feature position; used to
/// orient minutia markers along the local ridge flow.
pub fn local_dir(f: &FeatureVector, p: Pt) -> i32 {
    theta_at(f, p)
}

/// Convenience: is a pattern a whorl (used for swirl emphasis in rendering).
pub fn is_whorl(f: &FeatureVector) -> bool {
    f.pattern == PatternClass::Whorl
}

/// Re-exported for the renderer.
pub use crate::features::{Minutia, Singularity};

#[allow(dead_code)]
fn _kinds(_k: MinutiaKind) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::derive_features;

    #[test]
    fn ridges_inside_slot() {
        for i in 0..40u32 {
            let id = format!("WP-{:04X}-{:04X}", i, i * 7 + 1);
            let f = derive_features(&id);
            for r in build_ridges(&f) {
                for p in &r.pts {
                    assert!(
                        p.x >= slot_lo() - 16 && p.x <= slot_hi() + 16,
                        "x out of slot: {} id={id}",
                        fixed::fmt(p.x, 3)
                    );
                    assert!(
                        p.y >= slot_lo() - 16 && p.y <= slot_hi() + 16,
                        "y out of slot id={id}"
                    );
                }
            }
        }
    }

    #[test]
    fn ridges_nonempty() {
        let f = derive_features("WP-7F3C-A9B1");
        let r = build_ridges(&f);
        assert!(r.len() >= 4, "too few ridges: {}", r.len());
    }
}
