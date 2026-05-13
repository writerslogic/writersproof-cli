// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use serde::Serialize;

/// ORCID (Open Researcher and Contributor ID) identity binding.
#[derive(Debug, Clone, Serialize)]
pub struct OrcidIdentity {
    /// ORCID iD in format 0000-0002-1825-0097.
    pub orcid_id: String,
    /// Display name from the ORCID profile, if available.
    pub display_name: Option<String>,
    /// Whether the ORCID was verified via OAuth.
    pub verified: bool,
}

/// Validate an ORCID iD format.
///
/// ORCID iDs consist of 4 groups of 4 digits separated by hyphens, where the
/// last character is a check digit (0-9 or X) computed per ISO 7064 Mod 11,2.
pub fn validate_orcid(orcid: &str) -> bool {
    let stripped: String = orcid.chars().filter(|c| *c != '-').collect();
    if stripped.len() != 16 {
        return false;
    }

    // First 15 characters must be digits; last is digit or 'X'.
    let (body, check_char) = stripped.split_at(15);
    if !body.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let last = check_char.chars().next().unwrap_or(' ');
    if !last.is_ascii_digit() && last != 'X' {
        return false;
    }

    // ISO 7064 Mod 11,2 check digit verification.
    let mut total: u64 = 0;
    for c in body.chars() {
        let digit = c.to_digit(10).unwrap_or(0) as u64;
        total = (total + digit) * 2;
    }
    let remainder = total % 11;
    let expected = (12 - remainder) % 11;
    let check_value: u64 = if last == 'X' {
        10
    } else {
        last.to_digit(10).unwrap_or(99) as u64
    };

    expected == check_value
}

/// Generate a DID from an ORCID iD using the informal `did:orcid` method.
///
/// Returns `Some("did:orcid:<orcid>")` if the ORCID is valid, or `None` if invalid.
pub fn orcid_to_did(orcid: &str) -> Option<String> {
    if validate_orcid(orcid) {
        Some(format!("did:orcid:{}", orcid))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orcid_validation() {
        // Known valid ORCID (check digit 'X'): 0000-0002-1694-233X
        assert!(validate_orcid("0000-0002-1694-233X"));
        // Known valid ORCID (check digit '0'): 0000-0001-5109-3700
        assert!(validate_orcid("0000-0001-5109-3700"));
        // Known valid ORCID (check digit '7'): 0000-0002-1825-0097
        assert!(validate_orcid("0000-0002-1825-0097"));
        // Without hyphens.
        assert!(validate_orcid("0000000218250097"));
        // Too short.
        assert!(!validate_orcid("0000-0002-1825"));
        // Letters in body.
        assert!(!validate_orcid("AAAA-0002-1825-0097"));
        // Empty.
        assert!(!validate_orcid(""));
        // Wrong check digit.
        assert!(!validate_orcid("0000-0002-1825-0091"));

        // did:orcid generation.
        let did = orcid_to_did("0000-0002-1694-233X");
        assert_eq!(did, Some("did:orcid:0000-0002-1694-233X".to_string()));

        // Invalid ORCID returns None.
        assert_eq!(orcid_to_did("invalid"), None);
    }

    #[test]
    fn test_orcid_checksum_validation_iso7064() {
        // Verify the ISO 7064 Mod 11,2 check digit algorithm.
        // Valid: check digit 'X' means remainder maps to 10.
        assert!(validate_orcid("0000-0002-1694-233X"));
        // Valid: check digit '7'.
        assert!(validate_orcid("0000-0002-1825-0097"));
        // Valid: check digit '0'.
        assert!(validate_orcid("0000-0001-5109-3700"));

        // Off-by-one in check digit should fail.
        assert!(!validate_orcid("0000-0002-1694-2339")); // X -> 9
        assert!(!validate_orcid("0000-0002-1825-0098")); // 7 -> 8
        assert!(!validate_orcid("0000-0001-5109-3701")); // 0 -> 1

        // Lowercase 'x' is not valid (spec requires uppercase X).
        assert!(!validate_orcid("0000-0002-1694-233x"));

        // Too long.
        assert!(!validate_orcid("0000-0002-1825-00977"));

        // Non-digit in body.
        assert!(!validate_orcid("0000-000A-1825-0097"));
    }

    #[test]
    fn test_orcid_to_did_format() {
        let did = orcid_to_did("0000-0002-1825-0097").unwrap();
        assert!(did.starts_with("did:orcid:"));
        assert_eq!(did, "did:orcid:0000-0002-1825-0097");

        // The ORCID string is preserved exactly (including hyphens).
        let did_x = orcid_to_did("0000-0002-1694-233X").unwrap();
        assert!(did_x.ends_with("233X"));

        // Without hyphens also works.
        let did_no_hyphens = orcid_to_did("0000000218250097").unwrap();
        assert_eq!(did_no_hyphens, "did:orcid:0000000218250097");

        // Invalid returns None.
        assert!(orcid_to_did("not-an-orcid").is_none());
    }
}
