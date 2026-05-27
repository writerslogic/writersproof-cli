// SPDX-License-Identifier: Apache-2.0

//! Pure HMAC-based jitter engine (economic security model).

use crate::{Error, Jitter, JitterEngine, PhysHash};

#[derive(Debug, Clone)]
pub struct PureJitter {
    jmin: u32,
    range: u32,
}

impl PureJitter {
    /// Minimum jitter output in microseconds.
    pub fn jmin(&self) -> u32 {
        self.jmin
    }

    /// Range of jitter values above `jmin`.
    pub fn range(&self) -> u32 {
        self.range
    }
}

impl Default for PureJitter {
    fn default() -> Self {
        Self {
            jmin: crate::DEFAULT_JITTER_MIN_US,
            range: crate::DEFAULT_JITTER_RANGE_US,
        }
    }
}

impl PureJitter {
    /// Create a pure jitter engine.
    ///
    /// Returns `Error::InvalidParameter` if `range` is 0.
    pub fn new(jmin: u32, range: u32) -> Result<Self, Error> {
        if range == 0 {
            return Err(Error::InvalidParameter("range must be > 0"));
        }
        Ok(Self { jmin, range })
    }

    /// Create a pure jitter engine, returning `None` if `range` is 0.
    pub fn try_new(jmin: u32, range: u32) -> Option<Self> {
        Self::new(jmin, range).ok()
    }
}

impl JitterEngine for PureJitter {
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], _entropy: PhysHash) -> Jitter {
        crate::traits::hmac_jitter(secret, inputs, &[], self.jmin, self.range)
    }
}
