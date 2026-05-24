// SPDX-License-Identifier: Apache-2.0

pub mod classifier;
pub mod cognitive;
pub mod engine;
pub mod transcription;
pub mod word_frequency;

pub use classifier::{classify_authorship_method, ForensicSignals};
pub use engine::{ForensicAnalysis, ForensicVerdict, ForensicsEngine};
