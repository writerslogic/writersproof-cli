// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::physics::SiliconPUF;
use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// 64-byte seed derived from a mnemonic and silicon PUF, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SensitiveSeed([u8; 64]);

impl fmt::Debug for SensitiveSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SensitiveSeed").field(&"[REDACTED]").finish()
    }
}

impl AsRef<[u8]> for SensitiveSeed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// BIP-39 mnemonic generation and PUF-bound seed derivation.
#[derive(Debug)]
pub struct MnemonicHandler;

impl MnemonicHandler {
    /// Generate a random 12-word BIP-39 mnemonic phrase, zeroized on drop.
    pub fn generate() -> Zeroizing<String> {
        log::debug!("MnemonicHandler::generate");
        let mut entropy = [0u8; 16];
        rand::rng().fill(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("16-byte entropy is valid BIP-39");
        entropy.zeroize();
        Zeroizing::new(mnemonic.to_string())
    }

    /// Derive a 64-byte seed by combining mnemonic entropy with silicon PUF.
    pub fn derive_silicon_seed(phrase: &str) -> Result<SensitiveSeed> {
        log::debug!("MnemonicHandler::derive_silicon_seed: phrase_len={}", phrase.len());
        let phrase_owned = Zeroizing::new(phrase.to_string());
        let mnemonic = Mnemonic::parse_in(Language::English, &*phrase_owned)
            .map_err(|_| anyhow!("Invalid mnemonic phrase"))?;

        let raw_seed = Zeroizing::new(mnemonic.to_seed(""));
        let puf = Zeroizing::new(SiliconPUF::generate_fingerprint());

        let hk = Hkdf::<Sha256>::new(Some(puf.as_ref()), raw_seed.as_ref());
        let mut out = Zeroizing::new([0u8; 64]);
        hk.expand(b"cpoe-silicon-seed-v1", out.as_mut())
            .map_err(|_| anyhow!("HKDF expand failed for silicon seed"))?;

        Ok(SensitiveSeed(*out))
    }

    /// Compute a short hex fingerprint binding the mnemonic to this machine.
    pub fn get_machine_fingerprint(phrase: &str) -> Result<String> {
        log::debug!("MnemonicHandler::get_machine_fingerprint: phrase_len={}", phrase.len());
        let seed = Self::derive_silicon_seed(phrase)?;
        let mut hasher = Sha256::new();
        hasher.update(seed.as_ref());
        Ok(crate::utils::short_hex_id(&hasher.finalize()))
    }

    /// Extract raw entropy bytes from a BIP-39 mnemonic phrase.
    pub fn phrase_to_entropy(phrase: &str) -> Result<Zeroizing<Vec<u8>>> {
        log::debug!("MnemonicHandler::phrase_to_entropy: phrase_len={}", phrase.len());
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| anyhow!("Invalid mnemonic"))?;
        Ok(Zeroizing::new(mnemonic.to_entropy()))
    }

    /// Convert raw entropy bytes into a BIP-39 mnemonic phrase, zeroized on drop.
    pub fn entropy_to_phrase(entropy: &[u8]) -> Result<Zeroizing<String>> {
        log::debug!("MnemonicHandler::entropy_to_phrase: entropy_len={}", entropy.len());
        let mnemonic = Mnemonic::from_entropy(entropy).map_err(|_| anyhow!("Invalid entropy"))?;
        Ok(Zeroizing::new(mnemonic.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_generation_and_validation() {
        let phrase = MnemonicHandler::generate();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12); // 128-bit entropy = 12 words
        let mnemonic = Mnemonic::parse_in(Language::English, &*phrase);
        assert!(mnemonic.is_ok());
    }

    #[test]
    fn test_invalid_mnemonic() {
        let invalid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid";
        let result = MnemonicHandler::derive_silicon_seed(invalid_phrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_silicon_seed_derivation_structure() {
        let phrase = MnemonicHandler::generate();
        let seed_result = MnemonicHandler::derive_silicon_seed(&phrase);
        assert!(seed_result.is_ok());
        let seed = seed_result.unwrap();
        assert_eq!(seed.as_ref().len(), 64);

        assert_ne!(seed.as_ref(), &[0u8; 64]);
    }

    #[test]
    fn test_machine_fingerprint_structure() {
        let phrase = MnemonicHandler::generate();
        let fp_result = MnemonicHandler::get_machine_fingerprint(&phrase);
        assert!(fp_result.is_ok());
        let fp = fp_result.unwrap();

        assert_eq!(fp.len(), 16); // 8 bytes hex-encoded
        assert!(hex::decode(&fp).is_ok());
    }

    #[test]
    fn test_derive_silicon_seed_determinism() {
        let phrase = MnemonicHandler::generate();
        let seed1 = MnemonicHandler::derive_silicon_seed(&phrase).unwrap();
        let seed2 = MnemonicHandler::derive_silicon_seed(&phrase).unwrap();

        assert_eq!(
            seed1.as_ref(),
            seed2.as_ref(),
            "Seed derivation must be deterministic on the same machine"
        );
    }

    #[test]
    fn test_generate_uniqueness() {
        let p1 = MnemonicHandler::generate();
        let p2 = MnemonicHandler::generate();
        assert_ne!(*p1, *p2, "Two generated mnemonics should differ");
    }

    #[test]
    fn test_generate_all_words_valid_bip39() {
        let phrase = MnemonicHandler::generate();
        // Every word must be in the BIP-39 English wordlist
        let wordlist = bip39::Language::English.word_list();
        for word in phrase.split_whitespace() {
            assert!(
                wordlist.contains(&word),
                "Word '{}' is not in BIP-39 English wordlist",
                word
            );
        }
    }

    #[test]
    fn test_phrase_to_entropy_roundtrip() {
        let phrase = MnemonicHandler::generate();
        let entropy = MnemonicHandler::phrase_to_entropy(&phrase).unwrap();
        assert_eq!(
            entropy.len(),
            16,
            "12-word mnemonic should yield 16 bytes of entropy"
        );

        let recovered = MnemonicHandler::entropy_to_phrase(&entropy).unwrap();
        assert_eq!(
            *phrase, *recovered,
            "entropy -> phrase should recover the original"
        );
    }

    #[test]
    fn test_entropy_to_phrase_roundtrip() {
        let entropy = [42u8; 16];
        let phrase = MnemonicHandler::entropy_to_phrase(&entropy).unwrap();
        let recovered_entropy = MnemonicHandler::phrase_to_entropy(&phrase).unwrap();
        assert_eq!(recovered_entropy.as_slice(), &entropy);
    }

    #[test]
    fn test_phrase_to_entropy_invalid() {
        let result = MnemonicHandler::phrase_to_entropy("not a valid mnemonic");
        assert!(result.is_err());
    }

    #[test]
    fn test_entropy_to_phrase_invalid_length() {
        // 15 bytes is not a valid BIP-39 entropy length
        let result = MnemonicHandler::entropy_to_phrase(&[0u8; 15]);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_silicon_seed_length() {
        let phrase = MnemonicHandler::generate();
        let seed = MnemonicHandler::derive_silicon_seed(&phrase).unwrap();
        assert_eq!(seed.as_ref().len(), 64, "Seed must be exactly 64 bytes");
    }

    #[test]
    fn test_derive_silicon_seed_different_phrases_differ() {
        let p1 = MnemonicHandler::generate();
        let p2 = MnemonicHandler::generate();
        let s1 = MnemonicHandler::derive_silicon_seed(&p1).unwrap();
        let s2 = MnemonicHandler::derive_silicon_seed(&p2).unwrap();
        assert_ne!(
            s1.as_ref(),
            s2.as_ref(),
            "Different mnemonics must produce different seeds"
        );
    }

    #[test]
    fn test_machine_fingerprint_hex_chars() {
        let phrase = MnemonicHandler::generate();
        let fp = MnemonicHandler::get_machine_fingerprint(&phrase).unwrap();
        assert_eq!(fp.len(), 16);
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "Fingerprint must contain only hex characters, got: {}",
            fp
        );
    }

    #[test]
    fn test_machine_fingerprint_deterministic() {
        let phrase = MnemonicHandler::generate();
        let fp1 = MnemonicHandler::get_machine_fingerprint(&phrase).unwrap();
        let fp2 = MnemonicHandler::get_machine_fingerprint(&phrase).unwrap();
        assert_eq!(
            fp1, fp2,
            "Fingerprint must be deterministic for the same phrase"
        );
    }

    #[test]
    fn test_machine_fingerprint_invalid_phrase() {
        let result = MnemonicHandler::get_machine_fingerprint("invalid phrase");
        assert!(result.is_err());
    }
}
