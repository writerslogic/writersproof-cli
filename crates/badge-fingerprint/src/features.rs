//! Deterministic `f(id) -> FeatureVector`.
//!
//! `h = SHA-256("fp-v1:" + short_id)` is the single entropy source. Every
//! channel is derived from `h` with integer / fixed-point math, so the same id
//! always produces the same features (and therefore the same SVG) on every
//! platform. The version tag `fp-v1` is part of the hashed preimage, so bumping
//! it cleanly re-keys every badge.

use crate::fixed::{self, Fx};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version tag mixed into the hash preimage. Bump to re-key all badges.
pub const VERSION: &str = "fp-v1";

/// Fingerprint pattern class. The distribution over ids is intentionally
/// FLATTENED (~even thirds) so badges are maximally glanceable-distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternClass {
    Loop,
    Whorl,
    Arch,
}

/// A singular point (core or delta) of the orientation field, in slot-local
/// fixed-point coordinates (Q16.16, normalized 0..ONE across the slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Singularity {
    pub x: Fx,
    pub y: Fx,
}

/// One warp harmonic: amplitude (brad), angular frequency, phase (brad).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Harmonic {
    pub amp: Fx,
    pub omega: Fx,
    pub phase: i32,
}

/// Minutia type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MinutiaKind {
    Ending,
    Bifurcation,
}

/// A minutia point: normalized slot-local position + kind + local direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Minutia {
    pub x: Fx,
    pub y: Fx,
    pub kind: MinutiaKind,
    pub dir: i32,
}

/// The full inspectable feature vector for one id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureVector {
    pub version: String,
    /// First 8 bytes of the hash, hex, for debugging / cross-referencing.
    pub hash_prefix: String,
    pub pattern: PatternClass,
    pub base_rotation: i32,
    pub cores: Vec<Singularity>,
    pub deltas: Vec<Singularity>,
    pub harmonics: Vec<Harmonic>,
    pub minutiae: Vec<Minutia>,
    /// Per-tooth bold state for the seal ring (true = tall/raised).
    pub tooth_code: Vec<bool>,
    /// Coarse angular slot (0..DOT_SLOTS) for the dot row (visual checksum).
    pub dot_slot: u8,
    /// Star descriptors (AI-Assisted mode only): (coarse slot, point-count).
    pub stars: Vec<StarSpec>,
    /// Indices of ridges chosen for the decorative fine/incipient layer.
    pub fine_ridge_mask: u32,
}

/// A decorative star (AI-Assisted only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarSpec {
    pub slot: u8,
    pub points: u8,
}

// ---- Per-channel budgets (tunable constants) ----------------------------------

/// Number of decorative minutiae markers. Main individualizing constellation.
pub const MINUTIAE: usize = 7;
/// Number of warp harmonics perturbing the orientation field.
pub const HARMONICS: usize = 4;
/// Number of teeth on the seal ring whose height is id-dependent.
pub const TOOTH_CODE_LEN: usize = 24;
/// Number of discrete coarse angular slots for the dot-row checksum.
pub const DOT_SLOTS: u8 = 8;

/// A little deterministic byte cursor over the hash, with rehashing for more
/// entropy than 32 bytes provides.
struct Bits {
    buf: Vec<u8>,
    pos: usize,
}

impl Bits {
    fn new(seed: &[u8]) -> Self {
        Bits {
            buf: seed.to_vec(),
            pos: 0,
        }
    }
    fn refill(&mut self) {
        // Extend deterministically: next block = SHA-256(buf).
        let mut h = Sha256::new();
        h.update(&self.buf);
        let out = h.finalize();
        self.buf.extend_from_slice(&out);
    }
    fn byte(&mut self) -> u8 {
        if self.pos >= self.buf.len() {
            self.refill();
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }
    fn u16(&mut self) -> u16 {
        let hi = self.byte() as u16;
        let lo = self.byte() as u16;
        (hi << 8) | lo
    }
    /// Uniform-ish integer in 0..n via rejection-free modulo (n small).
    fn below(&mut self, n: u32) -> u32 {
        debug_assert!(n > 0);
        (self.u16() as u32) % n
    }
    fn bit(&mut self) -> bool {
        self.byte() & 1 == 1
    }
    /// Fixed-point fraction in 0..ONE.
    fn frac(&mut self) -> Fx {
        (self.u16() as Fx * fixed::ONE) / 65536
    }
    /// Fixed-point fraction mapped into [lo, hi].
    fn range(&mut self, lo: Fx, hi: Fx) -> Fx {
        lo + fixed::mul(self.frac(), hi - lo)
    }
}

/// Quantize a fixed-point value to `steps` discrete levels (kills tiny
/// float-like jitter and keeps the SVG stable / compact).
fn quantize(v: Fx, lo: Fx, hi: Fx, steps: i64) -> Fx {
    let span = hi - lo;
    let q = fixed::div(v - lo, span); // 0..ONE
    let level = (fixed::to_int(fixed::mul(q, fixed::from_int(steps)))).clamp(0, steps - 1);
    lo + (span * level) / steps
}

/// Hash the id with the version tag and derive every channel.
pub fn derive_features(short_id: &str) -> FeatureVector {
    let mut hasher = Sha256::new();
    hasher.update(VERSION.as_bytes());
    hasher.update(b":");
    hasher.update(short_id.as_bytes());
    let h = hasher.finalize();
    let hash_prefix = hex8(&h);

    let mut bits = Bits::new(&h);

    // --- Pattern class: flattened distribution over 3 classes. ---
    let pattern = match bits.below(3) {
        0 => PatternClass::Loop,
        1 => PatternClass::Whorl,
        _ => PatternClass::Arch,
    };

    // Base ridge rotation, quantized to 64 brad steps for stability.
    let base_rotation = (bits.below(TURN_U) as i32 / 64) * 64;

    // --- Singular points, clamped well inside the slot (0.18..0.82). ---
    let (mut cores, mut deltas) = (Vec::new(), Vec::new());
    // Keep core and delta(s) well separated: stacked or coincident
    // singularities collapse the field into a tangle. Core sits upper-center;
    // delta(s) sit lower and off to the side.
    match pattern {
        PatternClass::Loop => {
            cores.push(Singularity {
                x: bits.range(fixed::from_ratio(42, 100), fixed::from_ratio(58, 100)),
                y: bits.range(fixed::from_ratio(30, 100), fixed::from_ratio(44, 100)),
            });
            // delta to the left or right third, low.
            let left = bits.bit();
            let dx = if left {
                bits.range(fixed::from_ratio(22, 100), fixed::from_ratio(36, 100))
            } else {
                bits.range(fixed::from_ratio(64, 100), fixed::from_ratio(78, 100))
            };
            deltas.push(Singularity {
                x: dx,
                y: bits.range(fixed::from_ratio(62, 100), fixed::from_ratio(74, 100)),
            });
        }
        PatternClass::Whorl => {
            // A whorl needs the field to wind a FULL turn around the center so
            // ridges close into concentric rings / a spiral. theta = base +
            // 0.5*(sum arg deltas - sum arg cores); two deltas stacked at the
            // center give +1 winding (theta ~ +arg about the center), a
            // tangential ring field. The random base_rotation rotates that into
            // a spiral seam for variety. A small hash separation keeps the two
            // deltas from collapsing into one tangled singularity. NO core: a
            // core here would cancel the winding back down to a loop.
            let cx = bits.range(fixed::from_ratio(46, 100), fixed::from_ratio(54, 100));
            let cy = bits.range(fixed::from_ratio(46, 100), fixed::from_ratio(54, 100));
            let sep = bits.range(fixed::from_ratio(6, 100), fixed::from_ratio(11, 100));
            deltas.push(Singularity { x: cx, y: cy - sep });
            deltas.push(Singularity { x: cx, y: cy + sep });
        }
        PatternClass::Arch => {
            // No singularities inside the slot -> gentle flow. A single distant
            // core far below the slot gives a smooth upward bow.
            cores.push(Singularity {
                x: bits.range(fixed::from_ratio(40, 100), fixed::from_ratio(60, 100)),
                y: fixed::from_ratio(-80, 100),
            });
        }
    }

    // --- 4 warp harmonics. Amplitude is small (a few degrees) so ridges keep
    // a smooth fingerprint flow; large swings turn the print into scribble. ---
    let amp_lo = fixed::from_ratio(TURN_I / 256, 1); // ~256 brad ~ 1.4 deg
    let amp_hi = fixed::from_ratio(TURN_I / 80, 1); // ~819 brad ~ 4.5 deg
    let mut harmonics = Vec::with_capacity(HARMONICS);
    for _ in 0..HARMONICS {
        let amp = quantize(bits.range(amp_lo, amp_hi), amp_lo, amp_hi, 6);
        // omega in [1, 3] cycles across the slot: low frequency = gentle waves.
        let omega = fixed::from_int(1 + bits.below(3) as i64);
        let phase = (bits.below(TURN_U) as i32 / 256) * 256;
        harmonics.push(Harmonic { amp, omega, phase });
    }

    // --- Minutiae constellation. ---
    let mut minutiae = Vec::with_capacity(MINUTIAE);
    let mlo = fixed::from_ratio(24, 100);
    let mhi = fixed::from_ratio(76, 100);
    for _ in 0..MINUTIAE {
        let kind = if bits.bit() {
            MinutiaKind::Ending
        } else {
            MinutiaKind::Bifurcation
        };
        minutiae.push(Minutia {
            x: bits.range(mlo, mhi),
            y: bits.range(mlo, mhi),
            kind,
            dir: (bits.below(TURN_U) as i32 / 1024) * 1024,
        });
    }

    // --- Seal-ring tooth-code: few BOLD states. ~1/3 teeth raised. ---
    let mut tooth_code = Vec::with_capacity(TOOTH_CODE_LEN);
    for _ in 0..TOOTH_CODE_LEN {
        // weight toward "short" so raised teeth are a sparse, readable subset.
        tooth_code.push(bits.below(3) == 0);
    }

    // --- Dot-row checksum slot. ---
    let dot_slot = bits.below(DOT_SLOTS as u32) as u8;

    // --- Stars (AI mode only; we always derive specs, renderer gates them). ---
    let star_count = 2 + bits.below(2) as usize; // 2..3
    let mut stars = Vec::with_capacity(star_count);
    for _ in 0..star_count {
        let slot = bits.below(12) as u8;
        let points = match bits.below(3) {
            0 => 4,
            1 => 5,
            _ => 6,
        };
        stars.push(StarSpec { slot, points });
    }

    // --- Fine/decorative ridge mask. ---
    let fine_ridge_mask = ((bits.u16() as u32) << 16) | bits.u16() as u32;

    FeatureVector {
        version: VERSION.to_string(),
        hash_prefix,
        pattern,
        base_rotation,
        cores,
        deltas,
        harmonics,
        minutiae,
        tooth_code,
        dot_slot,
        stars,
        fine_ridge_mask,
    }
}

const TURN_U: u32 = fixed::TURN as u32;
const TURN_I: i64 = fixed::TURN as i64;

fn hex8(h: &[u8]) -> String {
    let mut s = String::with_capacity(16);
    for b in h.iter().take(8) {
        s.push(nibble((b >> 4) & 0xf));
        s.push(nibble(b & 0xf));
    }
    s
}

fn nibble(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'a' + (n - 10)) as char
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_id() {
        let a = derive_features("WP-7F3C-A9B1");
        let b = derive_features("WP-7F3C-A9B1");
        assert_eq!(a, b);
    }

    #[test]
    fn different_ids_differ() {
        let a = derive_features("WP-7F3C-A9B1");
        let b = derive_features("WP-7F3C-A9B2");
        assert_ne!(a, b);
    }

    #[test]
    fn budgets_respected() {
        let f = derive_features("WP-0000-0001");
        assert_eq!(f.harmonics.len(), HARMONICS);
        assert_eq!(f.minutiae.len(), MINUTIAE);
        assert_eq!(f.tooth_code.len(), TOOTH_CODE_LEN);
        assert!(f.dot_slot < DOT_SLOTS);
    }

    #[test]
    fn pattern_distribution_flat() {
        let (mut l, mut w, mut a) = (0, 0, 0);
        for i in 0..600u32 {
            let id = format!("WP-{:04X}-{:04X}", i, i.wrapping_mul(2654435761));
            match derive_features(&id).pattern {
                PatternClass::Loop => l += 1,
                PatternClass::Whorl => w += 1,
                PatternClass::Arch => a += 1,
            }
        }
        // Each third should be within a generous band of 200.
        for c in [l, w, a] {
            assert!((150..=250).contains(&c), "skewed: l={l} w={w} a={a}");
        }
    }
}
