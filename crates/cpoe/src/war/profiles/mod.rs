// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Projection profiles for packaging EAR tokens into standard formats.

pub mod c2pa;
pub mod cawg;
pub mod eu_ai_act;
pub mod jpeg_trust;
pub mod openbadge;
pub mod standards;
pub mod vc;

#[cfg(test)]
pub(crate) mod test_helpers;
