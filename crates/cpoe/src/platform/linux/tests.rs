// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::platform::MouseCapture;
use keystroke::{keycode_to_char, linux_keycode_to_zone};
use mouse::LinuxMouseCapture;

#[test]
fn test_linux_keycode_to_zone() {
    assert_eq!(linux_keycode_to_zone(30), 0);
    assert_eq!(linux_keycode_to_zone(31), 1);
    assert_eq!(linux_keycode_to_zone(32), 2);
    assert_eq!(linux_keycode_to_zone(33), 3);
    assert_eq!(linux_keycode_to_zone(36), 4);
    assert_eq!(linux_keycode_to_zone(37), 5);
    assert_eq!(linux_keycode_to_zone(38), 6);
    assert_eq!(linux_keycode_to_zone(28), 7);
}

#[test]
fn test_is_virtual_device() {
    assert!(is_virtual_device("uinput keyboard", None, 0, 0));
    assert!(is_virtual_device("Virtual Keyboard", Some(""), 0, 0));
    assert!(is_virtual_device(
        "xtest keyboard",
        Some("usb-0000:00:1d.0-1.4/input0"),
        0,
        0
    ));
    assert!(!is_virtual_device(
        "AT Translated Set 2 keyboard",
        Some("isa0060/serio0/input0"),
        1,
        1
    ));
}

#[test]
fn test_keycode_to_char() {
    assert_eq!(keycode_to_char(30), Some('a'));
    assert_eq!(keycode_to_char(57), Some(' '));
    assert_eq!(keycode_to_char(255), None);
}

#[test]
fn test_is_virtual_mouse() {
    use mouse::enumerate_mice;
    // Test is_virtual_input_device with mouse parameters
    assert!(is_virtual_input_device(
        "uinput mouse",
        None,
        0,
        0,
        &["xdotool", "wacom"],
        &["mouse", "touchpad", "trackpad", "trackpoint"],
    ));
    assert!(is_virtual_input_device(
        "Virtual Mouse",
        Some(""),
        0,
        0,
        &["xdotool", "wacom"],
        &["mouse", "touchpad", "trackpad", "trackpoint"],
    ));
    assert!(is_virtual_input_device(
        "xtest pointer",
        Some("usb-0000:00:1d.0"),
        0,
        0,
        &["xdotool", "wacom"],
        &["mouse", "touchpad", "trackpad", "trackpoint"],
    ));
    assert!(is_virtual_input_device(
        "xdotool virtual mouse",
        Some("/dev/input/event0"),
        0,
        0,
        &["xdotool", "wacom"],
        &["mouse", "touchpad", "trackpad", "trackpoint"],
    ));

    assert!(!is_virtual_input_device(
        "Logitech USB Mouse",
        Some("usb-0000:00:1d.0-1.4/input0"),
        0x046d,
        0xc077,
        &["xdotool", "wacom"],
        &["mouse", "touchpad", "trackpad", "trackpoint"],
    ));
    assert!(!is_virtual_input_device(
        "Dell MS116 USB Mouse",
        Some("usb-0000:00:14.0-1/input0"),
        0x413c,
        0x301a,
        &["xdotool", "wacom"],
        &["mouse", "touchpad", "trackpad", "trackpoint"],
    ));
}

#[test]
fn test_linux_mouse_capture_create() {
    let capture = LinuxMouseCapture::new();
    assert!(capture.is_ok());

    let capture = capture.unwrap();
    assert!(!capture.is_running());
    assert!(capture.is_idle_only_mode()); // Default is true
}
