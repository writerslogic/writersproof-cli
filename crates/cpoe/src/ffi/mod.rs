// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI bindings for macOS SwiftUI integration via UniFFI.

pub mod archive;
pub mod attestation;
pub mod beacon;
pub mod chain;
pub mod collaboration_ffi;
pub mod credentials;
pub mod ephemeral;
pub mod evidence;
pub mod evidence_checkpoint;
pub mod evidence_derivative;
pub mod evidence_export;
pub mod fingerprint;
pub mod forensics;
pub mod forensics_detail;
pub mod helpers;
pub mod report;
pub mod report_types;
pub mod sentinel;
pub mod sentinel_config;
pub mod sentinel_es;
pub mod sentinel_inject;
pub mod sentinel_witnessing;
pub mod snapshot;
pub mod system;
pub mod text_fragment;
pub mod types;
pub mod user_apps;
pub mod verify_detail;
pub mod writersproof_ffi;

#[cfg(feature = "did-webvh")]
pub mod did_webvh_ffi;

pub use archive::*;
pub use attestation::*;
pub use beacon::*;
pub use chain::*;
pub use collaboration_ffi::*;
pub use credentials::*;
pub use ephemeral::*;
pub use evidence_checkpoint::*;
pub use evidence_derivative::*;
pub use evidence_export::*;
pub use fingerprint::*;
pub use forensics::*;
pub use forensics_detail::*;
pub use report::*;
pub use report_types::*;
pub use sentinel::*;
pub use sentinel_config::*;
pub use sentinel_inject::*;
pub use sentinel_witnessing::*;
pub use snapshot::*;
pub use system::*;
pub use text_fragment::*;
pub use types::*;
pub use user_apps::*;
pub use verify_detail::*;
pub use writersproof_ffi::*;

#[cfg(feature = "did-webvh")]
pub use did_webvh_ffi::*;
