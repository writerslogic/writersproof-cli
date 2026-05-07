// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

mod operations;
mod serialization;
mod types;

#[cfg(test)]
mod tests;

pub use types::{
    DictationBeginPayload, DictationEndPayload, DictationFragmentPayload, Entry, EntryType,
    Header, Wal, WalError, WalRecoveryReport, WalVerification,
};
