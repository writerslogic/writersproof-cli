// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Unified trait for platform-specific capabilities.

use super::{FocusMonitor, KeystrokeCapture, MouseCapture, PermissionStatus};
use anyhow::Result;

/// Provides access to platform-specific hardware and OS features.
///
/// This trait allows mocking platform interactions during tests and
/// decouples the engine from specific platform implementations.
pub trait PlatformProvider: Send + Sync {
    /// Return current platform permission status.
    fn check_permissions(&self) -> PermissionStatus;

    /// Prompt for required permissions.
    fn request_permissions(&self) -> PermissionStatus;

    /// Create and return a keystroke capture instance.
    fn create_keystroke_capture(&self) -> Result<Box<dyn KeystrokeCapture>>;

    /// Create and return a focus monitor instance.
    fn create_focus_monitor(&self) -> Result<Box<dyn FocusMonitor>>;

    /// Create and return a mouse capture instance.
    fn create_mouse_capture(&self) -> Result<Box<dyn MouseCapture>>;

    /// Return the platform-specific TPM or Secure Enclave provider, if available.
    fn get_tpm_provider(&self) -> Option<std::sync::Arc<dyn crate::tpm::Provider>>;
}

/// Default implementation of [`PlatformProvider`] for the current target OS.
#[derive(Debug, Default, Clone)]
pub struct DefaultPlatformProvider;

impl PlatformProvider for DefaultPlatformProvider {
    fn check_permissions(&self) -> PermissionStatus {
        super::check_permissions()
    }

    fn request_permissions(&self) -> PermissionStatus {
        super::request_permissions()
    }

    fn create_keystroke_capture(&self) -> Result<Box<dyn KeystrokeCapture>> {
        super::create_keystroke_capture()
    }

    fn create_focus_monitor(&self) -> Result<Box<dyn FocusMonitor>> {
        super::create_focus_monitor()
    }

    fn create_mouse_capture(&self) -> Result<Box<dyn MouseCapture>> {
        super::create_mouse_capture()
    }

    fn get_tpm_provider(&self) -> Option<std::sync::Arc<dyn crate::tpm::Provider>> {
        #[cfg(target_os = "macos")]
        {
            crate::tpm::secure_enclave::try_init()
                .map(|p| std::sync::Arc::new(p) as std::sync::Arc<dyn crate::tpm::Provider>)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Some(std::sync::Arc::new(crate::tpm::SoftwareProvider::new())
                as std::sync::Arc<dyn crate::tpm::Provider>)
        }
    }
}
