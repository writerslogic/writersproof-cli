// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Per-transport baseline latency calibration (USB, Bluetooth, internal, etc.).

use crate::platform::TransportType;
use authorproof_protocol::rfc::jitter_binding::TransportCalibration;
use std::collections::HashMap;

#[derive(Debug)]
pub struct TransportCalibrator {
    /// Intervals in microseconds, keyed by transport type.
    samples: HashMap<TransportType, Vec<u64>>,
    min_samples: usize,
    max_samples: usize,
}

impl TransportCalibrator {
    pub fn new(min_samples: usize, max_samples: usize) -> Self {
        Self {
            samples: HashMap::new(),
            min_samples,
            max_samples,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(50, 1000)
    }

    pub fn record_sample(&mut self, transport: TransportType, interval_us: u64) {
        let samples = self.samples.entry(transport).or_default();
        samples.push(interval_us);

        if samples.len() > self.max_samples {
            let excess = samples.len() - self.max_samples;
            samples.drain(0..excess);
        }
    }

    pub fn is_calibrated(&self, transport: TransportType) -> bool {
        self.samples
            .get(&transport)
            .is_some_and(|s| s.len() >= self.min_samples)
    }

    /// Returns `None` if fewer than `min_samples` are available.
    pub fn get_calibration(&self, transport: TransportType) -> Option<TransportCalibration> {
        let samples = self.samples.get(&transport)?;
        if samples.len() < self.min_samples {
            return None;
        }

        let baseline = *samples.iter().min()?;

        let f64_samples: Vec<f64> = samples.iter().map(|&x| x as f64).collect();
        let (_mean, variance) = crate::utils::mean_and_variance(&f64_samples);
        let ts = chrono::Utc::now().timestamp_millis();
        if ts < 0 {
            log::warn!("Negative timestamp_millis ({ts}) in transport calibration; clamping to 0");
        }
        let now_ms = ts.max(0) as u64;

        Some(TransportCalibration {
            transport: transport.as_str().to_owned(),
            baseline_latency_us: baseline,
            latency_variance_us: variance.max(0.0).round() as u64,
            calibrated_at_ms: now_ms,
        })
    }

    pub fn all_calibrations(&self) -> HashMap<TransportType, TransportCalibration> {
        self.samples
            .keys()
            .filter_map(|&transport| self.get_calibration(transport).map(|cal| (transport, cal)))
            .collect()
    }

    pub fn sample_count(&self, transport: TransportType) -> usize {
        self.samples.get(&transport).map_or(0, |s| s.len())
    }

    pub fn clear(&mut self, transport: TransportType) {
        self.samples.remove(&transport);
    }

    pub fn clear_all(&mut self) {
        self.samples.clear();
    }
}

impl Default for TransportCalibrator {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calibrator_basic() {
        let mut cal = TransportCalibrator::new(5, 100);

        assert!(!cal.is_calibrated(TransportType::Usb));
        assert!(cal.get_calibration(TransportType::Usb).is_none());

        for interval in [10000, 15000, 12000, 11000, 13000] {
            cal.record_sample(TransportType::Usb, interval);
        }

        assert!(cal.is_calibrated(TransportType::Usb));
        let calib = cal.get_calibration(TransportType::Usb).unwrap();

        assert_eq!(calib.transport, "usb");
        assert_eq!(calib.baseline_latency_us, 10000);
    }

    #[test]
    fn test_calibrator_multiple_transports() {
        let mut cal = TransportCalibrator::new(3, 100);

        for interval in [10000, 11000, 12000] {
            cal.record_sample(TransportType::Usb, interval);
        }

        for interval in [20000, 22000, 21000] {
            cal.record_sample(TransportType::Bluetooth, interval);
        }

        let usb_cal = cal.get_calibration(TransportType::Usb).unwrap();
        let bt_cal = cal.get_calibration(TransportType::Bluetooth).unwrap();

        assert_eq!(usb_cal.baseline_latency_us, 10000);
        assert_eq!(bt_cal.baseline_latency_us, 20000);

        assert!(bt_cal.baseline_latency_us > usb_cal.baseline_latency_us);
    }

    #[test]
    fn test_calibrator_rolling_window() {
        let mut cal = TransportCalibrator::new(2, 5);

        for i in 0..10 {
            cal.record_sample(TransportType::Internal, i * 1000);
        }

        assert_eq!(cal.sample_count(TransportType::Internal), 5);

        let calib = cal.get_calibration(TransportType::Internal).unwrap();
        assert_eq!(calib.baseline_latency_us, 5000);
    }

    #[test]
    fn test_transport_type_parsing() {
        assert_eq!(
            TransportType::from_linux_phys(Some("usb-0000:00:14.0-4/input0")),
            TransportType::Usb
        );
        assert_eq!(
            TransportType::from_linux_phys(Some("bluetooth")),
            TransportType::Bluetooth
        );
        assert_eq!(
            TransportType::from_linux_phys(Some("isa0060/serio0/input0")),
            TransportType::Internal
        );
        assert_eq!(TransportType::from_linux_phys(None), TransportType::Virtual);
    }
}
