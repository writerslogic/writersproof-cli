// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub const PROFILE_URI: &str = cpoe::authorproof_protocol::war::ear::LEGACY_POP_EVIDENCE_PROFILE;
pub const EAT_PROFILE_URI: &str = cpoe::authorproof_protocol::war::ear::POP_EAR_PROFILE;
pub const MIN_CHECKPOINTS_PER_PACKET: usize = 3;

/// Map CLI tier name to CDDL content-tier: basic/standard=1, enhanced=2, maximum=3.
///
/// Logs a warning for unrecognized tier names and defaults to basic (1).
pub fn content_tier_from_cli(tier: &str) -> u8 {
    match tier.to_lowercase().as_str() {
        "basic" | "standard" => 1,
        "enhanced" => 2,
        "maximum" => 3,
        other => {
            eprintln!(
                "Warning: unknown content tier '{}', defaulting to 'basic'. \
                 Valid tiers: basic, standard, enhanced, maximum",
                other
            );
            1
        }
    }
}

pub fn profile_uri() -> &'static str {
    PROFILE_URI
}

/// Map TPM capabilities to attestation tier: T1 (software), T2 (TPM), T3 (hardware-backed).
pub fn attestation_tier_value(has_tpm: bool, tpm_hardware_backed: bool) -> u8 {
    if tpm_hardware_backed {
        3
    } else if has_tpm {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- content_tier_from_cli ---

    #[test]
    fn test_content_tier_from_cli_basic_returns_one() {
        assert_eq!(
            content_tier_from_cli("basic"),
            1,
            "tier 'basic' should map to content-tier 1"
        );
    }

    #[test]
    fn test_content_tier_from_cli_standard_returns_one() {
        assert_eq!(
            content_tier_from_cli("standard"),
            1,
            "tier 'standard' should map to content-tier 1 (same as basic)"
        );
    }

    #[test]
    fn test_content_tier_from_cli_enhanced_returns_two() {
        assert_eq!(
            content_tier_from_cli("enhanced"),
            2,
            "tier 'enhanced' should map to content-tier 2"
        );
    }

    #[test]
    fn test_content_tier_from_cli_maximum_returns_three() {
        assert_eq!(
            content_tier_from_cli("maximum"),
            3,
            "tier 'maximum' should map to content-tier 3"
        );
    }

    #[test]
    fn test_content_tier_from_cli_case_insensitive() {
        assert_eq!(
            content_tier_from_cli("ENHANCED"),
            2,
            "tier parsing should be case-insensitive"
        );
        assert_eq!(
            content_tier_from_cli("Maximum"),
            3,
            "tier parsing should be case-insensitive for mixed case"
        );
        assert_eq!(
            content_tier_from_cli("BASIC"),
            1,
            "tier parsing should be case-insensitive for uppercase"
        );
    }

    #[test]
    fn test_content_tier_from_cli_unknown_defaults_to_basic() {
        assert_eq!(
            content_tier_from_cli("premium"),
            1,
            "unknown tier 'premium' should default to basic (1)"
        );
        assert_eq!(
            content_tier_from_cli(""),
            1,
            "empty tier string should default to basic (1)"
        );
        assert_eq!(
            content_tier_from_cli("超级"),
            1,
            "Unicode tier string should default to basic (1)"
        );
    }

    #[test]
    fn test_content_tier_from_cli_all_valid_values_distinct() {
        let basic = content_tier_from_cli("basic");
        let enhanced = content_tier_from_cli("enhanced");
        let maximum = content_tier_from_cli("maximum");
        assert_ne!(
            basic, enhanced,
            "basic and enhanced must map to different tiers"
        );
        assert_ne!(
            enhanced, maximum,
            "enhanced and maximum must map to different tiers"
        );
        assert_ne!(
            basic, maximum,
            "basic and maximum must map to different tiers"
        );
    }

    // --- attestation_tier_value ---

    #[test]
    fn test_attestation_tier_software_only() {
        assert_eq!(
            attestation_tier_value(false, false),
            1,
            "no TPM = software-only = T1"
        );
    }

    #[test]
    fn test_attestation_tier_tpm_present() {
        assert_eq!(
            attestation_tier_value(true, false),
            2,
            "TPM present but not hardware-backed = T2"
        );
    }

    #[test]
    fn test_attestation_tier_hardware_backed() {
        assert_eq!(
            attestation_tier_value(true, true),
            3,
            "TPM hardware-backed = T3"
        );
    }

    #[test]
    fn test_attestation_tier_hardware_backed_without_tpm_flag() {
        // Edge case: hardware_backed=true but has_tpm=false
        // Implementation gives priority to hardware_backed
        assert_eq!(
            attestation_tier_value(false, true),
            3,
            "hardware_backed=true should return T3 regardless of has_tpm flag"
        );
    }

    // --- profile_uri ---

    #[test]
    fn test_profile_uri_returns_constant() {
        assert_eq!(
            profile_uri(),
            PROFILE_URI,
            "profile URI should match PROFILE_URI constant"
        );
    }

    // --- constants ---

    #[test]
    fn test_min_checkpoints_per_packet_is_three() {
        assert_eq!(
            MIN_CHECKPOINTS_PER_PACKET, 3,
            "protocol requires minimum 3 checkpoints per packet"
        );
    }

    #[test]
    fn test_profile_uri_format() {
        assert!(
            PROFILE_URI.starts_with("urn:ietf:params:"),
            "PROFILE_URI should be a valid IETF URN, got: {}",
            PROFILE_URI
        );
    }

    #[test]
    fn test_eat_profile_uri_format() {
        assert!(
            EAT_PROFILE_URI.starts_with("urn:ietf:params:rats:eat:"),
            "EAT_PROFILE_URI should be a RATS EAT URN, got: {}",
            EAT_PROFILE_URI
        );
    }

}
