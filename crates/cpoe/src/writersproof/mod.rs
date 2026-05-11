// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! WritersProof attestation client and offline queue.
//!
//! Provides integration with the WritersProof external trust anchor service
//! for remote attestation of evidence packets. When offline, attestation
//! requests are queued to disk and submitted when connectivity is restored.

pub mod cert_resolver;
pub mod client;
pub mod client_cert;
pub mod queue;
pub mod tls_signer;
pub mod types;

pub use client::WritersProofClient;
pub use queue::OfflineQueue;
pub use types::*;
