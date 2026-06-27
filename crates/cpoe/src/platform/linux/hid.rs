// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! HID keyboard enumerator for Linux evdev devices.

use super::keystroke::enumerate_keyboards;
use crate::platform::{HidDeviceInfo, HidEnumerator};
use anyhow::Result;

/// HID keyboard enumerator for Linux evdev devices.
#[derive(Debug, Default)]
pub struct LinuxHidEnumerator;

impl LinuxHidEnumerator {
    pub fn new() -> Self {
        Self
    }
}

impl HidEnumerator for LinuxHidEnumerator {
    fn enumerate_keyboards(&self) -> Result<Vec<HidDeviceInfo>> {
        let devices = enumerate_keyboards()?;
        Ok(devices
            .into_iter()
            .map(|d| HidDeviceInfo {
                vendor_id: d.vendor_id as u32,
                product_id: d.product_id as u32,
                product_name: d.name,
                manufacturer: String::new(), // evdev doesn't expose this
                serial_number: d.uniq,
                transport: d.phys.unwrap_or_default(),
            })
            .collect())
    }

    fn is_device_connected(&self, vendor_id: u32, product_id: u32) -> bool {
        if let Ok(devices) = enumerate_keyboards() {
            devices
                .iter()
                .any(|d| d.vendor_id as u32 == vendor_id && d.product_id as u32 == product_id)
        } else {
            false
        }
    }
}
