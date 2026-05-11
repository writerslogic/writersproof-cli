// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! IOKit HID device enumeration for keyboard fingerprinting.

use super::ffi::*;
use super::HidDeviceInfo;
use anyhow::{anyhow, Result};
use core_foundation::base::TCFType;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::kCFAllocatorDefault;
use core_foundation_sys::dictionary::{
    kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks, CFDictionaryCreateMutable,
    CFDictionarySetValue,
};
use core_foundation_sys::number::{kCFNumberIntType, CFNumberCreate, CFNumberGetTypeID};

/// Enumerate all connected HID keyboard devices.
pub fn enumerate_hid_keyboards() -> Result<Vec<HidDeviceInfo>> {
    unsafe {
        let manager = CfGuard::new(IOHIDManagerCreate(
            kCFAllocatorDefault,
            K_IO_HID_OPTIONS_TYPE_NONE,
        ))
        .ok_or_else(|| anyhow!("Failed to create HID manager"))?;

        let match_dict = CfGuard::new(
            CFDictionaryCreateMutable(
                kCFAllocatorDefault,
                0,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            ) as *mut _,
        );

        if let Some(ref dict) = match_dict {
            let usage_page_key = CFString::new(K_IO_HID_DEVICE_USAGE_PAGE_KEY);
            let usage_key = CFString::new(K_IO_HID_DEVICE_USAGE_KEY);

            let usage_page = K_HID_PAGE_GENERIC_DESKTOP;
            let usage = K_HID_USAGE_GD_KEYBOARD;

            if let Some(num) = CfGuard::new(
                CFNumberCreate(
                    kCFAllocatorDefault,
                    kCFNumberIntType,
                    &usage_page as *const i32 as *const std::ffi::c_void,
                ) as *mut _,
            ) {
                CFDictionarySetValue(
                    dict.as_ptr() as *mut _,
                    usage_page_key.as_concrete_TypeRef() as *const std::ffi::c_void,
                    num.as_ptr() as *const std::ffi::c_void,
                );
            }
            if let Some(num) = CfGuard::new(
                CFNumberCreate(
                    kCFAllocatorDefault,
                    kCFNumberIntType,
                    &usage as *const i32 as *const std::ffi::c_void,
                ) as *mut _,
            ) {
                CFDictionarySetValue(
                    dict.as_ptr() as *mut _,
                    usage_key.as_concrete_TypeRef() as *const std::ffi::c_void,
                    num.as_ptr() as *const std::ffi::c_void,
                );
            }
        }

        IOHIDManagerSetDeviceMatching(
            manager.as_ptr(),
            match_dict
                .as_ref()
                .map_or(std::ptr::null(), |d| d.as_ptr()) as CFDictionaryRef,
        );
        drop(match_dict);

        let result = IOHIDManagerOpen(manager.as_ptr(), K_IO_HID_OPTIONS_TYPE_NONE);
        if result != 0 {
            return Err(anyhow!("Failed to open HID manager: {}", result));
        }

        let devices_set = CfGuard::new(IOHIDManagerCopyDevices(manager.as_ptr()));
        let devices_set = match devices_set {
            Some(s) => s,
            None => {
                IOHIDManagerClose(manager.as_ptr(), K_IO_HID_OPTIONS_TYPE_NONE);
                return Ok(Vec::new());
            }
        };

        let count = CFSetGetCount(devices_set.as_ptr()).max(0) as usize;
        let mut devices = Vec::with_capacity(count);

        if count > 0 {
            let mut device_refs: Vec<*const std::ffi::c_void> = vec![std::ptr::null(); count];
            CFSetGetValues(devices_set.as_ptr(), device_refs.as_mut_ptr());

            for device_ref in device_refs {
                if let Some(info) = get_hid_device_info(device_ref as *mut std::ffi::c_void) {
                    devices.push(info);
                }
            }
        }

        drop(devices_set);
        IOHIDManagerClose(manager.as_ptr(), K_IO_HID_OPTIONS_TYPE_NONE);
        // manager released on drop

        Ok(devices)
    }
}

/// Get device info from an IOHIDDevice reference.
unsafe fn get_hid_device_info(device: *mut std::ffi::c_void) -> Option<HidDeviceInfo> {
    let vendor_id = get_device_int_property(device, K_IO_HID_VENDOR_ID_KEY)? as u32;
    let product_id = get_device_int_property(device, K_IO_HID_PRODUCT_ID_KEY)? as u32;

    let product_name = get_device_string_property(device, K_IO_HID_PRODUCT_KEY)
        .unwrap_or_else(|| "Unknown".to_string());
    let manufacturer = get_device_string_property(device, K_IO_HID_MANUFACTURER_KEY)
        .unwrap_or_else(|| "Unknown".to_string());
    let serial_number = get_device_string_property(device, K_IO_HID_SERIAL_NUMBER_KEY);
    let transport = get_device_string_property(device, K_IO_HID_TRANSPORT_KEY)
        .unwrap_or_else(|| "Unknown".to_string());

    Some(HidDeviceInfo {
        vendor_id,
        product_id,
        product_name,
        manufacturer,
        serial_number,
        transport,
    })
}

unsafe fn get_device_int_property(device: *mut std::ffi::c_void, key: &str) -> Option<i64> {
    let key_cf = CFString::new(key);
    let value = IOHIDDeviceGetProperty(device, key_cf.as_concrete_TypeRef());
    if value.is_null() {
        return None;
    }

    if CFGetTypeID(value) != CFNumberGetTypeID() {
        return None;
    }

    let cf_number = CFNumber::wrap_under_get_rule(value as *mut _);
    cf_number.to_i64()
}

unsafe fn get_device_string_property(device: *mut std::ffi::c_void, key: &str) -> Option<String> {
    let key_cf = CFString::new(key);
    let value = IOHIDDeviceGetProperty(device, key_cf.as_concrete_TypeRef());
    if value.is_null() {
        return None;
    }

    if CFGetTypeID(value) != CFStringGetTypeID() {
        return None;
    }

    let cf_string =
        CFString::wrap_under_get_rule(value as core_foundation_sys::string::CFStringRef);
    Some(cf_string.to_string())
}
