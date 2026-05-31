// SPDX-License-Identifier: Apache-2.0

//! Arena block type for PoSME.

pub const LAMBDA: usize = 32;
pub const BLOCK_SIZE: usize = LAMBDA * 2;

/// 64-byte arena block: `data` (computational value) + `causal` (hash chain).
///
/// `#[repr(C)]` enables zero-copy reinterpretation as `[u8; BLOCK_SIZE]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(C)]
pub struct Block {
    pub data: [u8; LAMBDA],
    pub causal: [u8; LAMBDA],
}

impl Block {
    pub const fn zeroed() -> Self {
        Self {
            data: [0u8; LAMBDA],
            causal: [0u8; LAMBDA],
        }
    }

    /// Zero-copy view as contiguous bytes.
    // SAFETY: repr(C) with alignment-1 fields guarantees layout matches [u8; 64].
    #[inline]
    pub fn as_bytes(&self) -> &[u8; BLOCK_SIZE] {
        unsafe { &*(self as *const Block as *const [u8; BLOCK_SIZE]) }
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; BLOCK_SIZE] {
        *self.as_bytes()
    }
}

impl Default for Block {
    fn default() -> Self {
        Self::zeroed()
    }
}
