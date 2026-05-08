// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Distribution types for typing dynamics analysis: IKI, zone profiles, pause signatures,
//! circadian patterns, and session signatures.

mod digraph_analysis;
mod distribution_helpers;
mod dwell_flight;
mod iki_analysis;
mod pause_analysis;
mod session_analysis;
mod zone_analysis;

#[cfg(test)]
mod tests;

pub use digraph_analysis::{DigraphProfile, DigraphTiming};
pub use dwell_flight::{DwellDistribution, FlightTimeDistribution};
pub use iki_analysis::IkiDistribution;
pub use pause_analysis::PauseSignature;
pub use session_analysis::{CircadianPattern, DimensionConfidence, SessionSignature};
pub use zone_analysis::ZoneProfile;
