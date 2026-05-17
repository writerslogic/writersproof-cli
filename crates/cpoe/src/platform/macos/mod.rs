// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! macOS platform implementation using CGEventTap + IOKit HID.
//!
//! This module provides dual-layer keystroke verification:
//! 1. CGEventTap for key event interception with synthetic detection
//! 2. IOKit HID for direct hardware device access

mod ffi;
mod hid;
mod hid_capture;
mod keystroke;
mod mouse_capture;
mod permissions;
pub(crate) mod shared_tap;
mod synthetic;

#[cfg(test)]
mod tests;

pub use super::{
    DualLayerValidation, EventVerificationResult, FocusInfo, HidDeviceInfo, KeystrokeEvent,
    PermissionStatus, SyntheticStats, TransportType,
};

pub use hid::enumerate_hid_keyboards;
pub use hid_capture::HidInputCapture;
pub use keystroke::{
    KeystrokeCallback, KeystrokeInfo, KeystrokeMonitor, MacOSKeystrokeCapture, RunLoopHandle,
};
pub use mouse_capture::MacOSMouseCapture;
pub use permissions::{
    check_accessibility_permissions, check_input_monitoring_permissions, get_permission_status,
    has_required_permissions, request_accessibility_permissions, request_all_permissions,
    request_input_monitoring_permissions,
};
pub use synthetic::{
    get_strict_mode, get_synthetic_stats, reset_synthetic_stats, set_strict_mode,
    validate_dual_layer, verify_event_source, SyntheticEventStats,
};
