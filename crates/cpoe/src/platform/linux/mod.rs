// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Linux platform implementation using evdev.
//!
//! This module provides keystroke capture via evdev input devices
//! and focus tracking via X11/Wayland protocols.
//!
//! # Permissions
//!
//! Access to `/dev/input/event*` devices requires either:
//! - Root access
//! - Membership in the `input` group
//! - Appropriate udev rules

mod hid;
mod keystroke;
mod mouse;

#[cfg(test)]
mod tests;

pub use hid::LinuxHidEnumerator;
pub use keystroke::{
    enumerate_keyboards, keycode_to_char, linux_keycode_to_zone, LinuxKeystrokeCapture,
};
pub use mouse::{enumerate_mice, LinuxMouseCapture};

use super::{PermissionStatus, TransportType};
use evdev::{Device, Key};
use std::fs;
use std::path::PathBuf;

/// Metadata for a Linux evdev input device.
#[derive(Debug, Clone)]
pub struct LinuxInputDevice {
    pub path: PathBuf,
    pub name: String,
    /// Empty for virtual devices.
    pub phys: Option<String>,
    pub uniq: Option<String>,
    pub vendor_id: u16,
    pub product_id: u16,
    pub is_physical: bool,
}

impl LinuxInputDevice {
    /// Return true if heuristics suggest this is a virtual/software device.
    pub fn appears_virtual(&self) -> bool {
        is_virtual_device(
            &self.name,
            self.phys.as_deref(),
            self.vendor_id,
            self.product_id,
        )
    }
}

/// Shared virtual-device name patterns common to all input device types.
const VIRTUAL_NAME_PATTERNS: &[&str] = &["uinput", "virtual", "xtest", "py-evdev", "synthetic"];

/// Check if an input device appears virtual based on name patterns, physical
/// path presence, and vendor/product IDs.
///
/// - `extra_virtual_names`: additional name substrings that indicate a virtual device
///   (e.g., "ydotool" for keyboards, "xdotool"/"wacom" for mice).
/// - `known_physical_names`: name substrings that indicate a real device even when
///   vendor_id and product_id are both zero (e.g., "keyboard"/"kbd" for keyboards,
///   "mouse"/"touchpad" for mice).
pub(crate) fn is_virtual_input_device(
    name: &str,
    phys: Option<&str>,
    vendor_id: u16,
    product_id: u16,
    extra_virtual_names: &[&str],
    known_physical_names: &[&str],
) -> bool {
    let name_lower = name.to_lowercase();

    // Check shared + device-specific virtual name patterns
    for pattern in VIRTUAL_NAME_PATTERNS
        .iter()
        .chain(extra_virtual_names.iter())
    {
        if name_lower.contains(pattern) {
            return true;
        }
    }

    // No physical path usually means virtual
    if phys.map_or(true, |p| p.is_empty()) {
        return true;
    }

    // Zero vendor+product with no recognizable physical device name
    if vendor_id == 0
        && product_id == 0
        && !known_physical_names
            .iter()
            .any(|kw| name_lower.contains(kw))
    {
        return true;
    }

    false
}

/// Enumerate input devices matching a predicate, with a virtual-device filter.
pub(crate) fn enumerate_input_devices(
    matches: impl Fn(&Device) -> bool,
    is_virtual: impl Fn(&str, Option<&str>, u16, u16) -> bool,
) -> anyhow::Result<Vec<LinuxInputDevice>> {
    let mut result = Vec::new();

    let entries = fs::read_dir("/dev/input")?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("event"))
            .unwrap_or(false)
        {
            continue;
        }

        let device = match Device::open(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        if !matches(&device) {
            continue;
        }

        let name = device.name().unwrap_or("Unknown").to_string();
        let phys = device.physical_path().map(|s| s.to_string());
        let uniq = device.unique_name().map(|s| s.to_string());

        let input_id = device.input_id();
        let vendor_id = input_id.vendor();
        let product_id = input_id.product();

        result.push(LinuxInputDevice {
            path: path.clone(),
            name: name.clone(),
            phys: phys.clone(),
            uniq,
            vendor_id,
            product_id,
            is_physical: !is_virtual(&name, phys.as_deref(), vendor_id, product_id),
        });
    }

    Ok(result)
}

fn check_input_device_access() -> bool {
    match fs::read_dir("/dev/input") {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.to_string_lossy().contains("event") {
                    if let Ok(device) = Device::open(&path) {
                        if device
                            .supported_keys()
                            .is_some_and(|keys| keys.contains(Key::KEY_A))
                        {
                            return true;
                        }
                    }
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// Query current input device permission status.
pub fn get_permission_status() -> PermissionStatus {
    let input_devices = check_input_device_access();
    PermissionStatus {
        accessibility: true,    // N/A on Linux
        input_monitoring: true, // N/A on Linux
        input_devices,
        all_granted: input_devices,
    }
}

/// Log instructions for granting input device access, then return current status.
pub fn request_all_permissions() -> PermissionStatus {
    let status = get_permission_status();
    if !status.input_devices {
        log::warn!("Input device access not available.");
        log::info!("To grant access, either:");
        log::info!("  1. Run as root (not recommended for production)");
        log::info!("  2. Add your user to the 'input' group:");
        log::info!("     sudo usermod -aG input $USER");
        log::info!("     Then log out and back in");
        log::info!("  3. Set up a udev rule:");
        log::info!("     echo 'KERNEL==\"event*\", SUBSYSTEM==\"input\", TAG+=\"uaccess\"' | sudo tee /etc/udev/rules.d/99-writerslogic.rules");
        log::info!("     sudo udevadm control --reload-rules && sudo udevadm trigger");
    }
    status
}

/// Check whether the process can read input devices.
pub fn has_required_permissions() -> bool {
    check_input_device_access()
}

pub(crate) fn is_virtual_device(
    name: &str,
    phys: Option<&str>,
    vendor_id: u16,
    product_id: u16,
) -> bool {
    is_virtual_input_device(
        name,
        phys,
        vendor_id,
        product_id,
        &["ydotool"],
        &["keyboard", "kbd", "usb", "at translated"],
    )
}
