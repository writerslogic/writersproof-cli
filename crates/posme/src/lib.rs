// SPDX-License-Identifier: Apache-2.0

//! Proof of Sequential Memory Execution (PoSME).
//!
//! Implements draft-condrey-cfrg-posme: a cryptographic primitive combining
//! mutable arena state, data-dependent pointer-chase addressing, and per-block
//! causal hash binding.
//!
//! # Features
//!
//! - **default**: Verifier-only types and verification logic. WASM-compatible.
//! - **prover**: Arena allocation, step execution, and proof generation. Native-only.

pub mod block;
pub mod error;
pub mod hash;
pub mod merkle;
pub mod params;
pub mod proof;
pub mod seed;

#[cfg(feature = "prover")]
pub mod init;
#[cfg(feature = "prover")]
pub mod prover;
#[cfg(feature = "prover")]
pub mod step;

pub mod verifier;

pub use block::Block;
pub use error::{PosmeError, Result};
pub use params::PosmeParams;
pub use proof::PosmeProof;
