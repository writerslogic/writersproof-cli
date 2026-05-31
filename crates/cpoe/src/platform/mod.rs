// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Platform-specific keystroke capture and focus monitoring.

pub mod device;
pub mod events;
pub mod mouse;
pub mod provider;
pub mod stats;
pub mod status;
pub mod window_text;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "windows")]
pub mod windows_hid;

#[cfg(target_os = "linux")]
pub mod linux;

pub mod broadcaster;
pub mod mouse_stego;
pub mod synthetic;

pub use broadcaster::{EventBroadcaster, SubscriptionId, SyncEventBroadcaster};
pub use mouse_stego::{compute_mouse_jitter, MouseStegoEngine};

pub use device::{HidDeviceInfo, TransportType};
pub use events::{KeyEventType, KeystrokeEvent, MouseEvent};
pub use mouse::{MouseIdleStats, MouseStegoMode, MouseStegoParams};
pub use provider::{DefaultPlatformProvider, PlatformProvider};
pub use stats::{DualLayerValidation, EventVerificationResult, RejectionReasons, SyntheticStats};
pub use status::{FocusInfo, PermissionStatus};
pub use window_text::{WindowText, WindowTextCapture};

use anyhow::Result;
use std::sync::mpsc;

/// Platform-specific keystroke capture.
pub trait KeystrokeCapture: Send + Sync {
    /// Begin capturing keystrokes, returning a receiver for events.
    fn start(&mut self) -> Result<mpsc::Receiver<KeystrokeEvent>>;
    /// Stop capturing and release resources.
    fn stop(&mut self) -> Result<()>;
    /// Return accumulated synthetic vs. hardware detection statistics.
    fn synthetic_stats(&self) -> SyntheticStats;
    /// Return true if capture is currently active.
    fn is_running(&self) -> bool;
    /// Enable or disable strict mode (reject synthetic events).
    fn set_strict_mode(&mut self, strict: bool);
    /// Return whether strict mode is enabled.
    fn get_strict_mode(&self) -> bool;
    /// Return true if the underlying event tap is still alive and receiving events.
    /// Returns true by default; macOS overrides to detect tap-disabled failures.
    fn is_tap_alive(&self) -> bool {
        true
    }
}

/// HID device enumeration.
pub trait HidEnumerator {
    /// List all detected keyboard HID devices.
    fn enumerate_keyboards(&self) -> Result<Vec<HidDeviceInfo>>;
    /// Check whether a specific device is currently connected.
    fn is_device_connected(&self, vendor_id: u32, product_id: u32) -> bool;
}

/// Platform-specific mouse capture with idle jitter and steganography support.
pub trait MouseCapture: Send + Sync {
    /// Begin capturing mouse events, returning a receiver.
    fn start(&mut self) -> Result<mpsc::Receiver<MouseEvent>>;
    /// Stop capturing and release resources.
    fn stop(&mut self) -> Result<()>;
    /// Return true if capture is currently active.
    fn is_running(&self) -> bool;
    /// Return accumulated idle micro-movement statistics.
    fn idle_stats(&self) -> MouseIdleStats;
    /// Reset idle statistics to defaults.
    fn reset_idle_stats(&mut self);
    /// Configure steganographic mouse parameters.
    fn set_stego_params(&mut self, params: MouseStegoParams);
    /// Return current steganographic mouse parameters.
    fn get_stego_params(&self) -> MouseStegoParams;
    /// Enable or disable idle-only capture mode.
    fn set_idle_only_mode(&mut self, enabled: bool);
    /// Return whether only idle micro-movements are captured.
    fn is_idle_only_mode(&self) -> bool;
}

/// Create the platform-appropriate keystroke capture implementation.
#[cfg(target_os = "macos")]
pub fn create_keystroke_capture() -> Result<Box<dyn KeystrokeCapture>> {
    Ok(Box::new(macos::MacOSKeystrokeCapture::new()?))
}

/// Create the platform-appropriate keystroke capture implementation.
#[cfg(target_os = "windows")]
pub fn create_keystroke_capture() -> Result<Box<dyn KeystrokeCapture>> {
    Ok(Box::new(windows::WindowsKeystrokeCapture::new()?))
}

/// Create the platform-appropriate keystroke capture implementation.
#[cfg(target_os = "linux")]
pub fn create_keystroke_capture() -> Result<Box<dyn KeystrokeCapture>> {
    Ok(Box::new(linux::LinuxKeystrokeCapture::new()?))
}


/// Create the platform-appropriate mouse capture implementation.
#[cfg(target_os = "macos")]
pub fn create_mouse_capture() -> Result<Box<dyn MouseCapture>> {
    Ok(Box::new(macos::MacOSMouseCapture::new()?))
}

/// Create the platform-appropriate mouse capture implementation.
#[cfg(target_os = "windows")]
pub fn create_mouse_capture() -> Result<Box<dyn MouseCapture>> {
    Ok(Box::new(windows::WindowsMouseCapture::new()?))
}

/// Create the platform-appropriate mouse capture implementation.
#[cfg(target_os = "linux")]
pub fn create_mouse_capture() -> Result<Box<dyn MouseCapture>> {
    Ok(Box::new(linux::LinuxMouseCapture::new()?))
}

/// Query current platform permission status.
#[cfg(target_os = "macos")]
pub fn check_permissions() -> PermissionStatus {
    macos::get_permission_status()
}

/// Query current platform permission status.
#[cfg(target_os = "windows")]
pub fn check_permissions() -> PermissionStatus {
    windows::get_permission_status()
}

/// Query current platform permission status.
#[cfg(target_os = "linux")]
pub fn check_permissions() -> PermissionStatus {
    linux::get_permission_status()
}

/// Prompt for required permissions and return updated status.
#[cfg(target_os = "macos")]
pub fn request_permissions() -> PermissionStatus {
    macos::request_all_permissions()
}

/// Prompt for required permissions and return updated status.
#[cfg(target_os = "windows")]
pub fn request_permissions() -> PermissionStatus {
    windows::request_all_permissions()
}

/// Prompt for required permissions and return updated status.
#[cfg(target_os = "linux")]
pub fn request_permissions() -> PermissionStatus {
    linux::request_all_permissions()
}

/// Return true if all platform-required permissions are granted.
pub fn has_required_permissions() -> bool {
    check_permissions().all_granted
}

// Legacy compatibility re-exports
#[cfg(target_os = "macos")]
pub use macos::{
    check_accessibility_permissions, check_input_monitoring_permissions, enumerate_hid_keyboards,
    get_strict_mode, get_synthetic_stats,
    request_accessibility_permissions, request_input_monitoring_permissions, reset_synthetic_stats,
    set_strict_mode, validate_dual_layer, verify_event_source,
    DualLayerValidation as MacOSDualLayerValidation,
    EventVerificationResult as MacOSEventVerificationResult, FocusInfo as MacOSFocusInfo,
    HidDeviceInfo as MacOSHidDeviceInfo, HidInputCapture, KeystrokeInfo, KeystrokeMonitor,
    PermissionStatus as MacOSPermissionStatus, SyntheticEventStats,
};

#[cfg(target_os = "windows")]
pub use status::FocusInfo as WindowsFocusInfo;

#[cfg(target_os = "windows")]
pub use windows_hid::HidInputCapture;
