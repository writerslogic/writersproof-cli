//! Deterministic fixed-point math.
//!
//! All geometry is computed in Q16.16 fixed-point with integer-only operations
//! so that the same `short_id` yields byte-identical SVG on every platform.
//! Floating point is NEVER used for any value that reaches the rendered output;
//! we only convert a fixed-point value to a decimal *string* at the very end,
//! and that conversion is itself integer-based (`fmt`).
//!
//! The angle unit ("brad", binary radian) is a `u32`/`i32` where a full turn is
//! `TURN = 1 << 16`. Trig is done with a quarter-wave lookup table.

/// Number of fractional bits in the Q16.16 representation.
pub const FRAC: i64 = 16;
/// 1.0 in Q16.16.
pub const ONE: i64 = 1 << FRAC;

/// A full turn, in binary radians (brad). 65536 brad == 2*pi.
pub const TURN: i32 = 1 << 16;
/// Quarter turn in brad.
pub const QUARTER: i32 = TURN / 4;

/// Fixed-point value (Q16.16), stored in an i64 to avoid overflow during
/// multiplies. Public field is intentional: this is a thin newtype-free alias.
pub type Fx = i64;

/// Construct a fixed-point value from an integer.
#[inline]
pub const fn from_int(n: i64) -> Fx {
    n << FRAC
}

/// Construct a fixed-point value from a rational `num/den`.
#[inline]
pub fn from_ratio(num: i64, den: i64) -> Fx {
    debug_assert!(den != 0);
    (num << FRAC) / den
}

/// Fixed-point multiply.
#[inline]
pub fn mul(a: Fx, b: Fx) -> Fx {
    (a * b) >> FRAC
}

/// Fixed-point divide.
#[inline]
pub fn div(a: Fx, b: Fx) -> Fx {
    debug_assert!(b != 0);
    (a << FRAC) / b
}

/// Integer part (truncated toward zero).
#[inline]
pub fn to_int(a: Fx) -> i64 {
    a >> FRAC
}

/// Sine table: 257 entries covering 0..=QUARTER (inclusive), values in Q16.16
/// (range 0..=ONE). Generated once at startup with f64 (host-side only, NOT in
/// the rendering path) and rounded to the nearest integer, so the *table* is
/// identical on every platform that uses IEEE-754 round-to-nearest — which is
/// every platform Rust targets. After construction, all lookups are integer.
const SIN_TABLE_LEN: usize = (QUARTER as usize) + 1;

struct SinTable {
    data: [i32; SIN_TABLE_LEN],
}

impl SinTable {
    fn build() -> Self {
        let mut data = [0i32; SIN_TABLE_LEN];
        let mut i = 0usize;
        while i < SIN_TABLE_LEN {
            // angle in radians = (i / TURN) * 2pi
            let frac = i as f64 / TURN as f64;
            let radians = frac * core::f64::consts::TAU;
            let v = radians.sin() * ONE as f64;
            // round half away from zero, deterministically
            data[i] = (v + 0.5) as i32;
            i += 1;
        }
        SinTable { data }
    }
}

use std::sync::OnceLock;
static SIN: OnceLock<SinTable> = OnceLock::new();

#[inline]
fn sin_table() -> &'static SinTable {
    SIN.get_or_init(SinTable::build)
}

/// Normalize a brad angle to 0..TURN.
#[inline]
pub fn norm_brad(mut a: i32) -> i32 {
    a %= TURN;
    if a < 0 {
        a += TURN;
    }
    a
}

/// sin(angle) in Q16.16, angle in brad. Pure integer lookup after table build.
pub fn sin(angle: i32) -> Fx {
    let a = norm_brad(angle);
    let table = sin_table();
    // Map by quadrant using symmetry.
    if a <= QUARTER {
        table.data[a as usize] as Fx
    } else if a <= TURN / 2 {
        table.data[(TURN / 2 - a) as usize] as Fx
    } else if a <= 3 * QUARTER {
        -(table.data[(a - TURN / 2) as usize] as Fx)
    } else {
        -(table.data[(TURN - a) as usize] as Fx)
    }
}

/// cos(angle) in Q16.16.
#[inline]
pub fn cos(angle: i32) -> Fx {
    sin(angle.wrapping_add(QUARTER))
}

/// atan2 returning brad in 0..TURN. Integer Q16.16 inputs.
///
/// Uses a rational polynomial approximation of atan over [0,1] then octant
/// reduction. Accurate to well under a brad, and fully deterministic.
pub fn atan2(y: Fx, x: Fx) -> i32 {
    if x == 0 && y == 0 {
        return 0;
    }
    let ax = x.abs();
    let ay = y.abs();
    // angle in first octant: atan(min/max) in brad, 0..QUARTER/2 (8192).
    let (num, den, swap) = if ay <= ax {
        (ay, ax, false)
    } else {
        (ax, ay, true)
    };
    // r = num/den in Q16.16, 0..=ONE.
    let r = if den == 0 { 0 } else { div(num, den) };
    // atan(r) ~= r * (QUARTER_HALF_constant ...). Use the classic
    // approximation: atan(r) (radians) ~= r*(pi/4) - r*(r-1)*(0.2447 + 0.0663*r)
    // We work directly in brad. pi/4 == QUARTER/2 == 8192 brad.
    // Constants scaled to Q16.16.
    let c1 = (0.2447f64 * ONE as f64 + 0.5) as i64; // ~16035
    let c2 = (0.0663f64 * ONE as f64 + 0.5) as i64; // ~4345
    let pi4_brad: i64 = (QUARTER / 2) as i64; // 8192 brad == pi/4
                                              // base = r * pi4_brad  (r in Q16.16, result in brad*Q16.16 -> shift)
    let base = mul(r, from_int(pi4_brad)); // brad in Q16.16
    let corr_inner = c1 + mul(c2, r); // Q16.16
    let corr = mul(mul(r, r - ONE), corr_inner); // Q16.16, brad units
    let mut ang_fx = base - corr; // brad in Q16.16
    if ang_fx < 0 {
        ang_fx = 0;
    }
    let mut ang = to_int(ang_fx) as i32; // 0..~8192 brad

    if swap {
        ang = QUARTER - ang;
    }
    // Now ang is the angle in 0..QUARTER for the (ax, ay) magnitudes.
    // Resolve quadrant by signs of x, y.
    let result = match (x >= 0, y >= 0) {
        (true, true) => ang,
        (false, true) => TURN / 2 - ang,
        (false, false) => TURN / 2 + ang,
        (true, false) => TURN - ang,
    };
    norm_brad(result)
}

/// Integer square root of a Q16.16 value, returning Q16.16.
pub fn sqrt(a: Fx) -> Fx {
    if a <= 0 {
        return 0;
    }
    // sqrt(a) in Q16.16: sqrt(a * ONE) computed as integer isqrt of (a<<FRAC).
    let scaled = (a as u128) << (FRAC as u128);
    isqrt_u128(scaled) as Fx
}

fn isqrt_u128(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Format a Q16.16 value as a decimal string with `dp` fractional digits,
/// integer-only (no float). Used for SVG coordinate emission.
pub fn fmt(v: Fx, dp: u32) -> String {
    let neg = v < 0;
    let mut x = v.unsigned_abs();
    let int_part = x >> FRAC;
    let mut frac = x & ((1 << FRAC) - 1);
    // Compute `dp` decimal digits via repeated multiply-by-10.
    let mut digits = String::new();
    for _ in 0..dp {
        frac *= 10;
        let d = (frac >> FRAC) as u8;
        digits.push((b'0' + d) as char);
        frac &= (1 << FRAC) - 1;
    }
    let _ = &mut x;
    // Strip trailing zeros for compactness.
    while digits.ends_with('0') {
        digits.pop();
    }
    let sign = if neg && (int_part != 0 || !digits.is_empty()) {
        "-"
    } else {
        ""
    };
    if digits.is_empty() {
        format!("{sign}{int_part}")
    } else {
        format!("{sign}{int_part}.{digits}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sin_cos_known_values() {
        assert_eq!(sin(0), 0);
        assert_eq!(sin(QUARTER), ONE);
        assert!((sin(TURN / 2)).abs() < 4);
        assert_eq!(sin(3 * QUARTER), -ONE);
        assert!((cos(0) - ONE).abs() < 4);
        assert!(cos(QUARTER).abs() < 4);
    }

    #[test]
    fn atan2_quadrants() {
        // east
        assert!(atan2(0, ONE) < 8 || atan2(0, ONE) > TURN - 8);
        // north (90 deg == QUARTER)
        let n = atan2(ONE, 0);
        assert!((n - QUARTER).abs() < 16, "n={n}");
        // 45 deg
        let ne = atan2(ONE, ONE);
        assert!((ne - QUARTER / 2).abs() < 32, "ne={ne}");
        // west
        let w = atan2(0, -ONE);
        assert!((w - TURN / 2).abs() < 16, "w={w}");
    }

    #[test]
    fn sqrt_works() {
        assert_eq!(sqrt(from_int(4)), from_int(2));
        assert_eq!(sqrt(from_int(9)), from_int(3));
        let two = sqrt(from_int(2));
        // ~1.41421
        assert!((two - 92681).abs() < 8, "two={two}");
    }

    #[test]
    fn fmt_basic() {
        assert_eq!(fmt(from_int(5), 2), "5");
        assert_eq!(fmt(from_ratio(1, 2), 2), "0.5");
        assert_eq!(fmt(from_ratio(-3, 2), 3), "-1.5");
        assert_eq!(fmt(from_ratio(1, 4), 2), "0.25");
    }
}
