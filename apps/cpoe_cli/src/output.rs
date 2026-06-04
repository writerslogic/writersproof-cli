// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#[derive(Clone, Copy)]
pub struct OutputMode {
    pub json: bool,
    pub quiet: bool,
}

impl OutputMode {
    pub fn new(json: bool, quiet: bool) -> Self {
        Self { json, quiet }
    }

    pub fn verbose(&self) -> bool {
        !self.json && !self.quiet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_mode_new_stores_flags_correctly() {
        let mode = OutputMode::new(true, false);
        assert!(mode.json, "json flag should be true when set");
        assert!(!mode.quiet, "quiet flag should be false when unset");

        let mode2 = OutputMode::new(false, true);
        assert!(!mode2.json, "json flag should be false when unset");
        assert!(mode2.quiet, "quiet flag should be true when set");
    }

    #[test]
    fn test_output_mode_verbose_when_neither_json_nor_quiet() {
        let mode = OutputMode::new(false, false);
        assert!(
            mode.verbose(),
            "verbose should be true when both json and quiet are false"
        );
    }

    #[test]
    fn test_output_mode_not_verbose_when_json() {
        let mode = OutputMode::new(true, false);
        assert!(!mode.verbose(), "verbose should be false when json is true");
    }

    #[test]
    fn test_output_mode_not_verbose_when_quiet() {
        let mode = OutputMode::new(false, true);
        assert!(
            !mode.verbose(),
            "verbose should be false when quiet is true"
        );
    }

    #[test]
    fn test_output_mode_not_verbose_when_both_json_and_quiet() {
        let mode = OutputMode::new(true, true);
        assert!(
            !mode.verbose(),
            "verbose should be false when both json and quiet are true"
        );
    }

    #[test]
    fn test_output_mode_is_copy() {
        let mode = OutputMode::new(true, false);
        let copied = mode;
        // Both should be usable (Copy trait)
        assert_eq!(
            mode.json, copied.json,
            "OutputMode should implement Copy correctly"
        );
        assert_eq!(mode.quiet, copied.quiet, "Copy should preserve all fields");
    }
}
