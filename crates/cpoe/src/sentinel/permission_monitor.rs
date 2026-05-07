// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Permission state tracking for sentinel keystroke capture.
//!
//! Sentinel requires two macOS permissions to capture keystrokes:
//! - **Accessibility** (`AXIsProcessTrusted`): needed for CGEventTap and focus detection.
//! - **Input Monitoring**: needed for global keyboard events.
//!
//! Either permission can be revoked at runtime via System Settings. When this
//! happens the sentinel must degrade gracefully and auto-resume when permissions
//! are re-granted.

/// Current OS permission state for sentinel capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PermissionState {
    /// Both Accessibility and Input Monitoring are granted; full capture active.
    #[default]
    Full,
    /// Accessibility is granted but Input Monitoring is not; focus tracking works
    /// but keystroke capture is unavailable.
    KeystrokeDegraded,
    /// All required permissions have been revoked; only file-hash monitoring is
    /// active. The sentinel stays running so sessions can be resumed without
    /// restarting the app.
    Revoked,
}

impl PermissionState {
    /// Query the OS for current permissions and map to a `PermissionState`.
    ///
    /// On non-macOS platforms this always returns `Full` because those platforms
    /// do not have the same permission model.
    pub fn current() -> Self {
        let status = crate::platform::check_permissions();
        if status.accessibility && status.input_monitoring {
            Self::Full
        } else if status.accessibility {
            Self::KeystrokeDegraded
        } else {
            Self::Revoked
        }
    }

    /// Whether keystroke capture should be active in this state.
    pub fn keystroke_capture_allowed(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Machine-readable name used in FFI and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::KeystrokeDegraded => "keystroke_degraded",
            Self::Revoked => "revoked",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_state() {
        assert_eq!(PermissionState::default(), PermissionState::Full);
    }

    #[test]
    fn test_keystroke_capture_allowed() {
        assert!(PermissionState::Full.keystroke_capture_allowed());
        assert!(!PermissionState::KeystrokeDegraded.keystroke_capture_allowed());
        assert!(!PermissionState::Revoked.keystroke_capture_allowed());
    }

    #[test]
    fn test_as_str() {
        assert_eq!(PermissionState::Full.as_str(), "full");
        assert_eq!(PermissionState::KeystrokeDegraded.as_str(), "keystroke_degraded");
        assert_eq!(PermissionState::Revoked.as_str(), "revoked");
    }

    #[test]
    fn test_equality() {
        assert_eq!(PermissionState::Full, PermissionState::Full);
        assert_ne!(PermissionState::Full, PermissionState::Revoked);
    }

    /// Verify `current()` doesn't panic — it queries the OS, so we only
    /// check it returns a valid variant, not a specific value.
    #[test]
    fn test_current_does_not_panic() {
        let state = PermissionState::current();
        // Valid variant check: the discriminant must be one of the three.
        assert!(matches!(
            state,
            PermissionState::Full | PermissionState::KeystrokeDegraded | PermissionState::Revoked
        ));
    }
}
