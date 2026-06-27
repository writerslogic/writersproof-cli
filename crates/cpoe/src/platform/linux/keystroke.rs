// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Linux keystroke capture via evdev device readers.

use super::{check_input_device_access, is_virtual_device, request_all_permissions};
use super::{LinuxInputDevice, TransportType};
use crate::platform::{KeystrokeCapture, KeystrokeEvent, SyntheticStats};
use crate::{DateTimeNanosExt, RwLockRecover};
use anyhow::{anyhow, Result};
use evdev::{Device, EventType, Key};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, RwLock};

/// Map Linux evdev keycode to keyboard zone (0-7).
/// Zones are based on standard QWERTY keyboard layout and typical finger usage.
pub fn linux_keycode_to_zone(keycode: u16) -> u8 {
    match keycode {
        // Left pinky zone (0)
        1 | 15 | 16 | 30 | 44 | 58 | 42 | 29 => 0, // ESC, TAB, Q, A, Z, CAPS, LSHIFT, LCTRL

        // Left ring zone (1)
        2 | 17 | 31 | 45 => 1, // 1, W, S, X

        // Left middle zone (2)
        3 | 18 | 32 | 46 => 2, // 2, E, D, C

        // Left index zone (3)
        4 | 5 | 19 | 20 | 33 | 34 | 47 | 48 => 3, // 3, 4, R, T, F, G, V, B

        // Right index zone (4)
        6 | 7 | 21 | 22 | 35 | 36 | 49 | 50 => 4, // 5, 6, Y, U, H, J, N, M

        // Right middle zone (5)
        8 | 23 | 37 | 51 => 5, // 7, I, K, ,

        // Right ring zone (6)
        9 | 24 | 38 | 52 => 6, // 8, O, L, .

        // Right pinky zone (7)
        10 | 11 | 12 | 13 | 25 | 26 | 27 | 39 | 40 | 41 | 43 | 53 | 54 | 28 | 14 | 57 | 100
        | 97 | 56 => 7, // 9, 0, -, =, P, [, ], ;, ', `, \, /, RSHIFT, ENTER, BKSP, SPACE, RALT, RCTRL, LALT

        _ => 0,
    }
}

/// Enumerate physical and virtual keyboard devices via evdev.
pub fn enumerate_keyboards() -> Result<Vec<LinuxInputDevice>> {
    super::enumerate_input_devices(
        |dev| {
            dev.supported_keys()
                .is_some_and(|keys| keys.contains(Key::KEY_A))
        },
        is_virtual_device,
    )
}

pub fn keycode_to_char(keycode: u16) -> Option<char> {
    match keycode {
        16 => Some('q'),
        17 => Some('w'),
        18 => Some('e'),
        19 => Some('r'),
        20 => Some('t'),
        21 => Some('y'),
        22 => Some('u'),
        23 => Some('i'),
        24 => Some('o'),
        25 => Some('p'),
        30 => Some('a'),
        31 => Some('s'),
        32 => Some('d'),
        33 => Some('f'),
        34 => Some('g'),
        35 => Some('h'),
        36 => Some('j'),
        37 => Some('k'),
        38 => Some('l'),
        44 => Some('z'),
        45 => Some('x'),
        46 => Some('c'),
        47 => Some('v'),
        48 => Some('b'),
        49 => Some('n'),
        50 => Some('m'),
        2 => Some('1'),
        3 => Some('2'),
        4 => Some('3'),
        5 => Some('4'),
        6 => Some('5'),
        7 => Some('6'),
        8 => Some('7'),
        9 => Some('8'),
        10 => Some('9'),
        11 => Some('0'),
        57 => Some(' '),
        _ => None,
    }
}

/// Linux keystroke capture via evdev device readers.
#[allow(missing_debug_implementations)]
pub struct LinuxKeystrokeCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<KeystrokeEvent>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    strict_mode: bool,
    stats: Arc<RwLock<SyntheticStats>>,
    physical_devices: Arc<RwLock<HashMap<PathBuf, LinuxInputDevice>>>,
}

impl LinuxKeystrokeCapture {
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            threads: Vec::new(),
            strict_mode: true,
            stats: Arc::new(RwLock::new(SyntheticStats::default())),
            physical_devices: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn enumerate_physical_devices(&self) -> Result<Vec<PathBuf>> {
        let keyboards = enumerate_keyboards()?;
        let mut devices = self.physical_devices.write_recover();
        let mut physical_paths = Vec::new();

        for kbd in keyboards {
            if kbd.is_physical {
                physical_paths.push(kbd.path.clone());
            }
            devices.insert(kbd.path.clone(), kbd);
        }

        Ok(physical_paths)
    }

    /// Read keystroke events from a single evdev device until `running` is cleared.
    ///
    /// **Limitation:** `device.fetch_events()` blocks until the next input event arrives.
    /// If `stop()` is called while this thread is blocked, the thread will not exit until
    /// the next input event is received on this device. There is no portable non-blocking
    /// evdev API to work around this without polling or epoll, which would add complexity.
    fn device_reader_thread(
        path: PathBuf,
        tx: mpsc::Sender<KeystrokeEvent>,
        stats: Arc<RwLock<SyntheticStats>>,
        running: Arc<AtomicBool>,
        devices: Arc<RwLock<HashMap<PathBuf, LinuxInputDevice>>>,
        strict: bool,
    ) {
        let mut device = match Device::open(&path) {
            Ok(d) => d,
            Err(e) => {
                log::error!("Failed to open device {:?}: {}", path, e);
                return;
            }
        };

        let device_info = devices.read_recover().get(&path).cloned();
        let is_physical = device_info.as_ref().is_some_and(|d| d.is_physical);
        let device_id: Option<Arc<str>> = device_info
            .as_ref()
            .map(|d| Arc::from(format!("{:04x}:{:04x}", d.vendor_id, d.product_id)));
        let transport_type = device_info
            .as_ref()
            .map(|d| TransportType::from_linux_phys(d.phys.as_deref()));

        while running.load(Ordering::SeqCst) {
            match device.fetch_events() {
                Ok(events) => {
                    for event in events {
                        if event.event_type() != EventType::KEY {
                            continue;
                        }

                        if event.value() != 1 {
                            continue;
                        }

                        let keycode = event.code();

                        {
                            let mut s = stats.write_recover();
                            s.total_events += 1;

                            if is_physical {
                                s.verified_hardware += 1;
                            } else {
                                s.rejected_synthetic += 1;
                                s.rejection_reasons.virtual_device += 1;
                            }
                        }

                        if !is_physical && strict {
                            continue;
                        }

                        let now = chrono::Utc::now().timestamp_nanos_safe();
                        let zone = linux_keycode_to_zone(keycode);

                        let char_value = keycode_to_char(keycode);

                        let keystroke = KeystrokeEvent {
                            timestamp_ns: now,
                            keycode,
                            zone,
                            event_type: crate::platform::KeyEventType::Down,
                            char_value,
                            composed_text: None,
                            is_hardware: is_physical,
                            device_id: device_id.clone(),
                            transport_type,
                            target_pid: 0,
                        };

                        if tx.send(keystroke).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    if running.load(Ordering::SeqCst) {
                        log::error!("Error reading from device {:?}: {}", path, e);
                    }
                    break;
                }
            }
        }
    }
}

impl KeystrokeCapture for LinuxKeystrokeCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<KeystrokeEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Keystroke capture already running"));
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
            return Err(anyhow!("No physical keyboard devices found"));
        }

        let stats = Arc::clone(&self.stats);
        let strict = self.strict_mode;
        let running = Arc::clone(&self.running);
        let devices = Arc::clone(&self.physical_devices);

        for path in physical_paths {
            let tx = tx.clone();
            let stats = Arc::clone(&stats);
            let running = Arc::clone(&running);
            let devices = Arc::clone(&devices);
            let path_clone = path.clone();

            let thread = std::thread::spawn(move || {
                Self::device_reader_thread(path_clone, tx, stats, running, devices, strict);
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

    fn synthetic_stats(&self) -> SyntheticStats {
        self.stats.read_recover().clone()
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    fn get_strict_mode(&self) -> bool {
        self.strict_mode
    }
}

impl Drop for LinuxKeystrokeCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
