// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Linux mouse capture via evdev device readers with idle jitter support.

use super::{
    check_input_device_access, is_virtual_input_device, request_all_permissions, LinuxInputDevice,
};
use crate::platform::{MouseCapture, MouseEvent, MouseIdleStats, MouseStegoParams};
use crate::{DateTimeNanosExt, RwLockRecover};
use anyhow::{anyhow, Result};
use evdev::{Device, EventType, InputEventKind, RelativeAxisType};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, RwLock};

/// Enumerate physical and virtual mouse devices via evdev.
pub fn enumerate_mice() -> Result<Vec<LinuxInputDevice>> {
    super::enumerate_input_devices(
        |dev| {
            dev.supported_relative_axes().is_some_and(|axes| {
                axes.contains(RelativeAxisType::REL_X) && axes.contains(RelativeAxisType::REL_Y)
            })
        },
        is_virtual_mouse,
    )
}

fn is_virtual_mouse(name: &str, phys: Option<&str>, vendor_id: u16, product_id: u16) -> bool {
    is_virtual_input_device(
        name,
        phys,
        vendor_id,
        product_id,
        &["xdotool", "wacom"],
        &["mouse", "touchpad", "trackpad", "trackpoint"],
    )
}

/// Linux mouse capture via evdev device readers with idle jitter support.
pub struct LinuxMouseCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<MouseEvent>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    idle_only_mode: Arc<AtomicBool>,
    stats: Arc<RwLock<MouseIdleStats>>,
    stego_params: Arc<RwLock<MouseStegoParams>>,
    last_position: Arc<RwLock<(f64, f64)>>,
    physical_devices: Arc<RwLock<HashMap<PathBuf, LinuxInputDevice>>>,
}

impl LinuxMouseCapture {
    /// Create a new mouse capture instance in idle-only mode.
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            threads: Vec::new(),
            idle_only_mode: Arc::new(AtomicBool::new(true)),
            stats: Arc::new(RwLock::new(MouseIdleStats::default())),
            stego_params: Arc::new(RwLock::new(MouseStegoParams::default())),
            last_position: Arc::new(RwLock::new((0.0, 0.0))),
            physical_devices: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn enumerate_physical_devices(&self) -> Result<Vec<PathBuf>> {
        let mice = enumerate_mice()?;
        let mut devices = self.physical_devices.write_recover();
        let mut physical_paths = Vec::new();

        for mouse in mice {
            if mouse.is_physical {
                physical_paths.push(mouse.path.clone());
            }
            devices.insert(mouse.path.clone(), mouse);
        }

        Ok(physical_paths)
    }

    fn device_reader_thread(
        path: PathBuf,
        tx: mpsc::Sender<MouseEvent>,
        stats: Arc<RwLock<MouseIdleStats>>,
        running: Arc<AtomicBool>,
        devices: Arc<RwLock<HashMap<PathBuf, LinuxInputDevice>>>,
        last_position: Arc<RwLock<(f64, f64)>>,
        idle_only_mode: Arc<AtomicBool>,
    ) {
        let mut device = match Device::open(&path) {
            Ok(d) => d,
            Err(e) => {
                log::error!("Failed to open mouse device {:?}: {}", path, e);
                return;
            }
        };

        let device_info = devices.read_recover().get(&path).cloned();
        let is_physical = device_info.as_ref().is_some_and(|d| d.is_physical);
        let device_id: Option<Arc<str>> = device_info
            .as_ref()
            .map(|d| Arc::from(format!("{:04x}:{:04x}", d.vendor_id, d.product_id)));

        let mut pending_dx: f64 = 0.0;
        let mut pending_dy: f64 = 0.0;

        while running.load(Ordering::SeqCst) {
            match device.fetch_events() {
                Ok(events) => {
                    for event in events {
                        if event.event_type() != EventType::RELATIVE {
                            if event.event_type() == EventType::SYNCHRONIZATION
                                && (pending_dx != 0.0 || pending_dy != 0.0)
                            {
                                let now = chrono::Utc::now().timestamp_nanos_safe();

                                let (x, y) = {
                                    let mut pos = last_position.write_recover();
                                    pos.0 += pending_dx;
                                    pos.1 += pending_dy;
                                    (pos.0, pos.1)
                                };

                                let magnitude =
                                    (pending_dx * pending_dx + pending_dy * pending_dy).sqrt();
                                let magnitude = if magnitude.is_finite() {
                                    magnitude
                                } else {
                                    0.0
                                };
                                let is_micro = magnitude < 5.0;

                                let mouse_event = MouseEvent {
                                    timestamp_ns: now,
                                    x,
                                    y,
                                    dx: pending_dx,
                                    dy: pending_dy,
                                    is_idle: is_micro,
                                    is_hardware: is_physical,
                                    device_id: device_id.clone(),
                                    scroll_delta_h: None,
                                    scroll_delta_v: None,
                                };

                                if is_micro {
                                    stats.write_recover().record(&mouse_event);
                                }

                                if (!idle_only_mode.load(Ordering::Relaxed) || is_micro)
                                    && tx.send(mouse_event).is_err()
                                {
                                    return;
                                }

                                pending_dx = 0.0;
                                pending_dy = 0.0;
                            }
                            continue;
                        }

                        if let InputEventKind::RelAxis(axis) = event.kind() {
                            match axis {
                                RelativeAxisType::REL_X => {
                                    pending_dx += event.value() as f64;
                                }
                                RelativeAxisType::REL_Y => {
                                    pending_dy += event.value() as f64;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Err(e) => {
                    if running.load(Ordering::SeqCst) {
                        log::error!("Error reading from mouse device {:?}: {}", path, e);
                    }
                    break;
                }
            }
        }
    }
}

impl MouseCapture for LinuxMouseCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<MouseEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Mouse capture already running"));
        }

        if !check_input_device_access() {
            let _ = request_all_permissions();
            return Err(anyhow!(
                "No access to input devices. See error messages above for solutions."
            ));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        self.running.store(true, Ordering::SeqCst);

        let physical_paths = self.enumerate_physical_devices()?;
        if physical_paths.is_empty() {
            log::warn!("No physical mouse devices found");
        }

        let stats = Arc::clone(&self.stats);
        let running = Arc::clone(&self.running);
        let devices = Arc::clone(&self.physical_devices);
        let last_position = Arc::clone(&self.last_position);
        let idle_only_mode = Arc::clone(&self.idle_only_mode);

        for path in physical_paths {
            let tx = tx.clone();
            let stats = Arc::clone(&stats);
            let running = Arc::clone(&running);
            let devices = Arc::clone(&devices);
            let last_position = Arc::clone(&last_position);
            let idle_only_mode = Arc::clone(&idle_only_mode);

            let thread = std::thread::spawn(move || {
                Self::device_reader_thread(
                    path,
                    tx,
                    stats,
                    running,
                    devices,
                    last_position,
                    idle_only_mode,
                );
            });

            self.threads.push(thread);
        }

        Ok(rx)
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;

        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }

        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn idle_stats(&self) -> MouseIdleStats {
        self.stats.read_recover().clone()
    }

    fn reset_idle_stats(&mut self) {
        *self.stats.write_recover() = MouseIdleStats::new();
    }

    fn set_stego_params(&mut self, params: MouseStegoParams) {
        *self.stego_params.write_recover() = params;
    }

    fn get_stego_params(&self) -> MouseStegoParams {
        self.stego_params.read_recover().clone()
    }

    fn set_idle_only_mode(&mut self, enabled: bool) {
        self.idle_only_mode.store(enabled, Ordering::Relaxed);
    }

    fn is_idle_only_mode(&self) -> bool {
        self.idle_only_mode.load(Ordering::Relaxed)
    }
}

impl Drop for LinuxMouseCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
