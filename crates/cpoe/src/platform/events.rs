// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::platform::device::TransportType;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Whether a keystroke event is a press or release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyEventType {
    Down,
    Up,
}

/// Captured keystroke with timing, source device, and hardware verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeEvent {
    pub timestamp_ns: i64,
    pub keycode: u16,
    pub zone: u8,
    pub event_type: KeyEventType,
    pub char_value: Option<char>,
    /// Multi-character composed text from IME input (CJK, accented, emoji).
    /// Populated when an input method commits text spanning multiple characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composed_text: Option<String>,
    pub is_hardware: bool,
    pub device_id: Option<Arc<str>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_type: Option<TransportType>,
    /// Unix PID of the application that received this keystroke.
    /// Populated from `kCGEventTargetUnixProcessID` in the tap callback.
    #[serde(default)]
    pub target_pid: i32,
}

impl KeystrokeEvent {
    /// Create a hardware-sourced keystroke with minimal fields.
    pub fn new(timestamp_ns: i64, keycode: u16, zone: u8) -> Self {
        Self {
            timestamp_ns,
            keycode,
            zone,
            event_type: KeyEventType::Down,
            char_value: None,
            composed_text: None,
            is_hardware: true,
            device_id: None,
            transport_type: None,
            target_pid: 0,
        }
    }

    /// Create a keystroke with an explicit hardware verification flag.
    pub fn with_verification(timestamp_ns: i64, keycode: u16, zone: u8, is_hardware: bool) -> Self {
        Self {
            timestamp_ns,
            keycode,
            zone,
            event_type: KeyEventType::Down,
            char_value: None,
            composed_text: None,
            is_hardware,
            device_id: None,
            transport_type: None,
            target_pid: 0,
        }
    }

    /// Create a keystroke with full device identification.
    pub fn with_device(
        timestamp_ns: i64,
        keycode: u16,
        zone: u8,
        is_hardware: bool,
        device_id: Option<Arc<str>>,
        transport_type: Option<TransportType>,
    ) -> Self {
        Self {
            timestamp_ns,
            keycode,
            zone,
            event_type: KeyEventType::Down,
            char_value: None,
            composed_text: None,
            is_hardware,
            device_id,
            transport_type,
            target_pid: 0,
        }
    }
}

/// Captured mouse movement with position, delta, and idle/hardware flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseEvent {
    pub timestamp_ns: i64,
    pub x: f64,
    pub y: f64,
    pub dx: f64,
    pub dy: f64,
    pub is_idle: bool,
    pub is_hardware: bool,
    pub device_id: Option<Arc<str>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scroll_delta_v: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scroll_delta_h: Option<i64>,
}

impl MouseEvent {
    /// Create a non-idle, hardware-sourced mouse event.
    pub fn new(timestamp_ns: i64, x: f64, y: f64, dx: f64, dy: f64) -> Self {
        Self {
            timestamp_ns,
            x,
            y,
            dx,
            dy,
            is_idle: false,
            is_hardware: true,
            device_id: None,
            scroll_delta_v: None,
            scroll_delta_h: None,
        }
    }

    /// Create an idle jitter mouse event (micro-movement during typing).
    pub fn idle_jitter(timestamp_ns: i64, x: f64, y: f64, dx: f64, dy: f64) -> Self {
        Self {
            timestamp_ns,
            x,
            y,
            dx,
            dy,
            is_idle: true,
            is_hardware: true,
            device_id: None,
            scroll_delta_v: None,
            scroll_delta_h: None,
        }
    }

    /// Create a scroll wheel event with vertical and horizontal deltas.
    pub fn scroll(timestamp_ns: i64, x: f64, y: f64, delta_v: i64, delta_h: i64) -> Self {
        Self {
            timestamp_ns,
            x,
            y,
            dx: 0.0,
            dy: 0.0,
            is_idle: false,
            is_hardware: true,
            device_id: None,
            scroll_delta_v: Some(delta_v),
            scroll_delta_h: Some(delta_h),
        }
    }

    pub fn is_scroll(&self) -> bool {
        self.scroll_delta_v.is_some()
    }

    /// Compute the Euclidean magnitude of the movement delta.
    pub fn movement_magnitude(&self) -> f64 {
        (self.dx * self.dx + self.dy * self.dy).sqrt()
    }

    /// Return true if the movement magnitude is below the micro-movement threshold.
    pub fn is_micro_movement(&self) -> bool {
        self.movement_magnitude() < 3.0
    }
}
