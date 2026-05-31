// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Unified trait for platform-specific capabilities.

use super::{KeystrokeCapture, MouseCapture, PermissionStatus};
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

    fn create_mouse_capture(&self) -> Result<Box<dyn MouseCapture>> {
        super::create_mouse_capture()
    }

    fn get_tpm_provider(&self) -> Option<std::sync::Arc<dyn crate::tpm::Provider>> {
        #[cfg(target_os = "macos")]
        {
            crate::tpm::secure_enclave::try_init()
                .map(|p| std::sync::Arc::new(p) as std::sync::Arc<dyn crate::tpm::Provider>)
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(provider) = crate::tpm::windows::try_init() {
                return Some(
                    std::sync::Arc::new(provider) as std::sync::Arc<dyn crate::tpm::Provider>
                );
            }
            crate::tpm::SoftwareProvider::try_new()
                .map(|p| std::sync::Arc::new(p) as std::sync::Arc<dyn crate::tpm::Provider>)
                .ok()
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            crate::tpm::SoftwareProvider::try_new()
                .map(|p| std::sync::Arc::new(p) as std::sync::Arc<dyn crate::tpm::Provider>)
                .ok()
        }
    }
}
