// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Anonymous research data collection for jitter proof-of-process analysis.
//!
//! This module enables opt-in collection of anonymized jitter timing data
//! to help build datasets for security analysis of the proof-of-process primitive.
//!
//! ## What is collected:
//! - Jitter timing samples (inter-keystroke intervals in microseconds)
//! - Hardware class (CPU architecture, core count range)
//! - OS type (macOS, Linux, Windows)
//! - Sample timestamps (rounded to hour for privacy)
//! - Session statistics (sample count, duration buckets)
//!
//! ## What is NOT collected:
//! - Document content or paths
//! - Actual keystrokes or text
//! - User identity or device identifiers
//! - Exact hardware model or serial numbers
//! - Network information

mod collector;
mod helpers;
mod types;
mod uploader;

#[cfg(test)]
mod tests;

pub use collector::ResearchCollector;
pub use types::{
    AnonymizedSample, AnonymizedSession, AnonymizedStatistics, HardwareClass, OsType,
    ResearchDataExport, UploadResult, CPOE_VERSION, DEFAULT_UPLOAD_INTERVAL_SECS,
    MIN_SESSIONS_FOR_UPLOAD, RESEARCH_UPLOAD_URL,
};
pub use uploader::ResearchUploader;
