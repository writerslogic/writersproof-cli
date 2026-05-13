// SPDX-License-Identifier: Apache-2.0

//! Fixed-point integer types for RFC-compliant CBOR encoding.
//!
//! Implements fixed-point integer representations per
//! draft-condrey-rats-pop-schema-01 Section 3 (Numeric Representation).
//!
//! Fixed-point replaces IEEE 754 for security-critical values because:
//! 1. Cross-platform reproducibility — integer arithmetic is fully specified
//!    by CBOR (RFC 8949) with no implementation latitude.
//! 2. Constant-time comparison — eliminates timing side-channels.
//! 3. Deterministic encoding — single canonical CBOR form ensures
//!    identical hash inputs across implementations.
//!
//! | Type       | Scale Factor | Range       | Example              |
//! |------------|--------------|-------------|----------------------|
//! | Millibits  | x1000        | 0–1000      | 0.95 → 950           |
//! | Centibits  | x10000       | 0–10000     | 0.0005 → 5           |
//! | Decibits   | x10          | 0–640       | 3.2 bits → 32        |
//! | DeciWpm    | x10          | 0–5000      | 45.5 WPM → 455       |

use serde::{Deserialize, Serialize};
use std::ops::{Add, Sub};

macro_rules! fixed_point {
    (
        $(#[$meta:meta])*
        $name:ident($inner:ty), scale=$scale:expr, min=$min:expr, max=$max:expr
    ) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
            Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub $inner);

        impl $name {
            pub const MAX: $name = $name($max as $inner);
            pub const MIN: $name = $name($min as $inner);

            #[inline]
            pub const fn new(value: $inner) -> Self {
                $name(value)
            }

            pub fn from_float(value: f64) -> Self {
                if !value.is_finite() {
                    log::warn!(
                        concat!("non-finite float {} passed to ", stringify!($name), "::from_float, returning 0"),
                        value
                    );
                    return $name(0 as $inner);
                }
                let scaled = (value * ($scale as f64)).round()
                    .clamp($min as f64, $max as f64);
                let clamped = scaled as $inner;
                $name(clamped)
            }

            #[inline]
            pub const fn raw(&self) -> $inner {
                self.0
            }

            #[inline]
            pub fn to_float(&self) -> f64 {
                self.0 as f64 / $scale as f64
            }
        }

        impl From<f64> for $name {
            fn from(value: f64) -> Self {
                $name::from_float(value)
            }
        }

        impl From<$name> for f64 {
            fn from(value: $name) -> Self {
                value.to_float()
            }
        }
    };
}

fixed_point! {
    /// Ratio scaled x1000: [0, 1000] maps to [0.0, 1.0].
    /// Used for: confidence, coverage, activity ratios.
    Millibits(u16), scale=1000, min=0, max=1000
}

fixed_point! {
    /// Signed ratio scaled x1000: [-1000, 1000] maps to [-1.0, 1.0].
    /// Used for: Spearman rho correlation coefficients.
    RhoMillibits(i16), scale=1000, min=-1000, max=1000
}

fixed_point! {
    /// Fine ratio scaled x10000: [0, 10000] maps to [0.0, 1.0].
    /// Used for: differential privacy epsilon, p-values.
    Centibits(u16), scale=10000, min=0, max=10000
}

fixed_point! {
    /// Entropy scaled x10: [0, 640] maps to [0.0, 64.0] bits.
    /// Used for: Shannon entropy measurements.
    Decibits(u16), scale=10, min=0, max=640
}

fixed_point! {
    /// Slope scaled x10: [-100, 100] maps to [-10.0, +10.0].
    /// Used for: pink noise slope (typically around -1.0).
    SlopeDecibits(i8), scale=10, min=-100, max=100
}

fixed_point! {
    /// WPM scaled x10: [0, 5000] maps to [0.0, 500.0].
    /// Used for: effective typing rate measurements.
    DeciWpm(u16), scale=10, min=0, max=5000
}

/// Economic cost in microdollars (USD x 1,000,000).
/// Used for: forgery cost bounds, economic attack analysis.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Microdollars(pub u64);

impl Microdollars {
    /// Create from a raw microdollar value.
    #[inline]
    pub const fn new(value: u64) -> Self {
        Microdollars(value)
    }

    /// Convert from dollars to microdollars (1 USD = 1,000,000).
    pub fn from_dollars(value: f64) -> Self {
        if !value.is_finite() || value <= 0.0 {
            return Microdollars(0);
        }
        let scaled = (value * 1_000_000.0).round();
        // u64::MAX as f64 rounds up, so clamp to the largest f64 that fits in u64.
        let max_safe = 18_446_744_073_709_549_568.0_f64; // u64::MAX - 2047, exact in f64
        let clamped = scaled.clamp(0.0, max_safe);
        Microdollars(clamped as u64)
    }

    /// Return the raw microdollar value.
    #[inline]
    pub const fn raw(&self) -> u64 {
        self.0
    }

    /// Convert to dollars as `f64`.
    #[inline]
    pub fn to_dollars(&self) -> f64 {
        self.0 as f64 / 1_000_000.0
    }
}

impl Add for Millibits {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Millibits((self.0 + other.0).min(1000))
    }
}

impl Sub for Millibits {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Millibits(self.0.saturating_sub(other.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_millibits_roundtrip() {
        let values = [0.0, 0.5, 0.95, 1.0, 0.001, 0.999];
        for v in values {
            let mb = Millibits::from_float(v);
            let back: f64 = mb.into();
            assert!(
                (back - v).abs() < 0.001,
                "value {} roundtripped to {}",
                v,
                back
            );
        }
    }

    #[test]
    fn test_millibits_clamping() {
        assert_eq!(Millibits::from_float(-0.5).raw(), 0);
        assert_eq!(Millibits::from_float(1.5).raw(), 1000);
    }

    #[test]
    fn test_rho_millibits_signed() {
        let rho = RhoMillibits::from_float(-0.75);
        assert_eq!(rho.raw(), -750);
        assert!((rho.to_float() - (-0.75)).abs() < 0.001);
    }

    #[test]
    fn test_centibits_precision() {
        let epsilon = Centibits::from_float(0.0005);
        assert_eq!(epsilon.raw(), 5);
        assert!((epsilon.to_float() - 0.0005).abs() < 0.0001);
    }

    #[test]
    fn test_decibits_entropy() {
        let entropy = Decibits::from_float(3.2);
        assert_eq!(entropy.raw(), 32);
        assert!((entropy.to_float() - 3.2).abs() < 0.1);
    }

    #[test]
    fn test_slope_decibits_negative() {
        let slope = SlopeDecibits::from_float(-1.2);
        assert_eq!(slope.raw(), -12);
        assert!((slope.to_float() - (-1.2)).abs() < 0.1);
    }

    #[test]
    fn test_deci_wpm() {
        let wpm = DeciWpm::from_float(45.5);
        assert_eq!(wpm.raw(), 455);
        assert!((wpm.to_float() - 45.5).abs() < 0.1);
    }

    #[test]
    fn test_microdollars() {
        let cost = Microdollars::from_dollars(0.05);
        assert_eq!(cost.raw(), 50000);
        assert!((cost.to_dollars() - 0.05).abs() < 0.000001);
    }

    #[test]
    fn test_millibits_serde() {
        let mb = Millibits::from_float(0.75);
        let json = serde_json::to_string(&mb).unwrap();
        assert_eq!(json, "750");
        let decoded: Millibits = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, mb);
    }

    #[test]
    fn test_millibits_arithmetic() {
        let a = Millibits::new(300);
        let b = Millibits::new(400);
        assert_eq!((a + b).raw(), 700);
        assert_eq!((b - a).raw(), 100);
        assert_eq!((a - b).raw(), 0); // saturating
    }
}
