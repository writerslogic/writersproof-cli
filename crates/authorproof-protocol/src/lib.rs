// SPDX-License-Identifier: Apache-2.0

//! CPoE wire format types, CBOR/COSE codec, and evidence builder/verifier.

pub mod baseline;
pub mod c2pa;
pub mod codec;
pub mod compact_ref;
pub mod crypto;
pub mod error;
pub mod evidence;
pub mod forensics;
pub mod identity;
pub mod method_detection;
pub mod rfc;
pub mod war;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use crate::error::{Error, Result};
pub use codec::{decode_evidence, encode_evidence};
pub use crypto::{hash_sha256, EvidenceSigner};
pub use evidence::{Builder, Verifier};
pub use rfc::{AttestationTier, DocumentRef, EvidencePacket, HashValue, Verdict};

pub const PROTOCOL_VERSION: u32 = 1;
