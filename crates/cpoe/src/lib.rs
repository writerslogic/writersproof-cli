// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

#![warn(missing_debug_implementations)]

//! CPoE (Continuous Proof of Personhood) Engine.
//!
//! A high-integrity behavioral biometric engine designed for generating
//! WAR/1.1 (Witnessd Authorship Record) evidence.

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!("cpoe_engine");

pub mod checkpoint;
pub mod checkpoint_mmr;
pub mod collaboration;
pub mod continuation;
pub mod evidence;
pub mod mmr;
pub mod provenance;

pub mod analysis;
pub mod baseline;
pub mod fingerprint;
pub mod forensics;
pub mod jitter;
pub mod physics;
pub mod presence;
mod rfc_conversions;

pub mod crypto;
pub mod keyhierarchy;
pub mod rats;
pub mod sealed_identity;
pub mod security;
pub mod tpm;
pub mod trust_policy;
pub mod vdf;

pub mod config;
pub mod error;
pub mod identity;
pub mod ipc;
pub mod platform;
pub mod sentinel;
pub mod serde_utils;
pub mod snapshot;
pub mod store;
pub mod timing;
pub mod utils;
pub mod verify;
pub mod wal;

pub mod anchors;
pub mod integrity;
pub mod credentials;
pub mod declaration;
pub mod report;
pub mod research;
pub mod transcription;
pub mod war;
pub mod writersproof;

#[cfg(feature = "cpoe_jitter")]
pub mod cpoe_jitter_bridge;

/// Maximum file size accepted for evidence operations (500 MB).
pub const MAX_FILE_SIZE: u64 = 500_000_000;

pub(crate) use crate::utils::{DateTimeNanosExt, MutexRecover, RwLockRecover};

pub use crate::crypto::{
    compute_event_hash, compute_event_hmac, derive_hmac_key, restrict_permissions,
};
pub use crate::error::{Error, Result};
pub use crate::identity::MnemonicHandler;
#[cfg(feature = "did-webvh")]
pub use identity::did_webvh::{CpopSigner, WebVHIdentity};

pub use crate::sentinel::{
    ChangeEvent, ChangeEventType, DaemonHandle, DaemonManager, DaemonState, DaemonStatus,
    DocumentSession, FocusEvent, FocusEventType, Sentinel, SentinelError, SessionEvent,
    SessionEventType, ShadowManager, WindowInfo,
};

pub use crate::vdf::{
    AggregateError, AggregateMetadata, AggregationMethod, MerkleSample, MerkleVdfBuilder,
    MerkleVdfProof, RoughtimeClient, SnarkScheme, SnarkVdfProof, TimeAnchor, TimeKeeper,
    VdfAggregateProof, VdfProof, VerificationMode,
};

pub use crate::fingerprint::{
    ActivityFingerprint, AuthorFingerprint, ConsentManager, ConsentStatus, FingerprintComparison,
    FingerprintManager, FingerprintStatus, ProfileId, StyleFingerprint,
};

pub use crate::collaboration::{
    CollaborationMode, CollaborationPolicy, CollaborationSection, Collaborator, CollaboratorRole,
    ContributionClaim, ContributionSummary, ContributionType, MergeEvent, MergeRecord,
    MergeStrategy, TimeInterval,
};
pub use crate::continuation::{ContinuationSection, ContinuationSummary};
pub use crate::physics::PhysicalContext;
pub use crate::provenance::{
    DerivationClaim, DerivationType, ProvenanceLink, ProvenanceMetadata, ProvenanceSection,
};
pub use crate::research::{
    AnonymizedSession, ResearchCollector, ResearchDataExport, ResearchUploader, UploadResult,
};

pub use crate::config::{FingerprintConfig, PrivacyConfig, ResearchConfig, SentinelConfig};
pub use crate::store::{SecureEvent, SecureStore};

pub use crate::trust_policy::{
    AppraisalPolicy, FactorEvidence, FactorType, PolicyMetadata, ThresholdType, TrustComputation,
    TrustFactor, TrustThreshold,
};

pub use crate::security::{
    EntropyAssessment, EntropyValidator, KeystrokeEvent, KeystrokeSample, TamperingDetector,
    TamperingFlags,
};

pub use authorproof_protocol::compact_ref::{
    CompactEvidenceRef, CompactMetadata, CompactRefError, CompactSummary,
};
pub use authorproof_protocol::rfc::{
    BiologyInvariantClaim, BiologyScoringParameters, BlockchainAnchor, CalibrationAttestation,
    JitterBinding, RoughtimeSample, TimeBindingTier, TimeEvidence, TsaResponse, ValidationStatus,
    VdfProofRfc,
};

pub use authorproof_protocol::rfc::wire_types::{
    AttestationResultWire, CheckpointWire, DocumentRef as WireDocumentRef, EvidencePacketWire,
    HashAlgorithm, HashValue as WireHashValue, ProcessProof as WireProcessProof, Verdict,
    CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET as CBOR_TAG_EVIDENCE_PACKET_WIRE,
};

#[cfg(feature = "cpoe_jitter")]
pub use crate::cpoe_jitter_bridge::{
    EntropyQuality, HybridEvidence, HybridJitterSession, HybridSample, ZoneTrackingEngine,
};

pub use authorproof_protocol;

#[cfg(target_os = "macos")]
#[macro_use]
extern crate objc;
