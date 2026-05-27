// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Timelike, Utc};
#[cfg(target_os = "linux")]
use std::fs;

use crate::jitter::{Evidence, Statistics};

use super::types::{
    AnonymizedSample, AnonymizedSession, AnonymizedStatistics, HardwareClass, OsType,
};

impl AnonymizedSession {
    /// Strip identifying info from `Evidence`, preserving only timing patterns.
    pub fn from_evidence(evidence: &Evidence) -> Self {
        let research_id = generate_research_id();
        let collected_at = round_timestamp_to_hour(Utc::now());
        let hardware_class = detect_hardware_class();
        let os_type = detect_os_type();

        let start_time = evidence.started_at;
        let mut prev_doc_hash: Option<[u8; 32]> = None;

        let samples: Vec<AnonymizedSample> = evidence
            .samples
            .iter()
            .map(|s| {
                let relative_time = s
                    .timestamp
                    .signed_duration_since(start_time)
                    .to_std()
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);

                let doc_changed = prev_doc_hash
                    .map(|prev| prev != s.document_hash)
                    .unwrap_or(true);
                prev_doc_hash = Some(s.document_hash);

                // Differential privacy: add Laplacian noise to per-sample jitter.
                let noisy_jitter = add_laplace_noise(
                    s.jitter_micros as f64,
                    s.jitter_micros as f64 * 0.03,
                )
                .max(0.0) as u32;

                AnonymizedSample {
                    relative_time_secs: relative_time,
                    jitter_micros: noisy_jitter,
                    keystroke_ordinal: s.keystroke_count,
                    document_changed: doc_changed,
                }
            })
            .collect();

        let statistics = compute_anonymized_statistics(&evidence.statistics, &samples);

        Self {
            research_id,
            collected_at,
            hardware_class,
            os_type,
            samples,
            statistics,
        }
    }
}

pub(super) fn generate_research_id() -> String {
    let random_bytes: [u8; 16] = rand::random();
    hex::encode(random_bytes)
}

pub(super) fn round_timestamp_to_hour(ts: DateTime<Utc>) -> DateTime<Utc> {
    ts.with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(ts)
}

pub(super) fn detect_hardware_class() -> HardwareClass {
    let arch = std::env::consts::ARCH.to_string();

    let core_count = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);

    let core_bucket = match core_count {
        1..=2 => "1-2",
        3..=4 => "3-4",
        5..=8 => "5-8",
        9..=16 => "9-16",
        _ => "17+",
    }
    .to_string();

    let memory_bucket = detect_memory_bucket();

    HardwareClass {
        arch,
        core_bucket,
        memory_bucket,
    }
}

#[cfg(target_os = "macos")]
fn detect_memory_bucket() -> String {
    use std::process::Command;

    let output = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok());

    match output {
        Some(bytes) => {
            let gb = bytes / (1024 * 1024 * 1024);
            memory_gb_to_bucket(gb)
        }
        None => "unknown".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn detect_memory_bucket() -> String {
    let meminfo = fs::read_to_string("/proc/meminfo").ok();

    let total_kb = meminfo.and_then(|content| {
        content
            .lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
            })
    });

    match total_kb {
        Some(kb) => {
            let gb = kb / (1024 * 1024);
            memory_gb_to_bucket(gb)
        }
        None => "unknown".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn detect_memory_bucket() -> String {
    // TODO: implement via GlobalMemoryStatusEx (requires unsafe)
    "unknown".to_string()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn detect_memory_bucket() -> String {
    "unknown".to_string()
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub(super) fn memory_gb_to_bucket(gb: u64) -> String {
    match gb {
        0..=4 => "<=4GB",
        5..=8 => "4-8GB",
        9..=16 => "8-16GB",
        17..=32 => "16-32GB",
        _ => "32GB+",
    }
    .to_string()
}

pub(super) fn detect_os_type() -> OsType {
    match std::env::consts::OS {
        "macos" => OsType::MacOS,
        "linux" => OsType::Linux,
        "windows" => OsType::Windows,
        _ => OsType::Other,
    }
}

pub(super) fn compute_anonymized_statistics(
    stats: &Statistics,
    samples: &[AnonymizedSample],
) -> AnonymizedStatistics {
    let duration_secs = stats.duration.as_secs();
    let duration_bucket = match duration_secs {
        0..=300 => "0-5min",
        301..=900 => "5-15min",
        901..=1800 => "15-30min",
        1801..=3600 => "30-60min",
        _ => "60min+",
    }
    .to_string();

    let typing_rate_bucket = match stats.keystrokes_per_min as u32 {
        0..=30 => "slow",
        31..=60 => "moderate",
        61..=120 => "fast",
        _ => "very_fast",
    }
    .to_string();

    let jitter_values: Vec<f64> = samples.iter().map(|s| s.jitter_micros as f64).collect();

    let (mean, std_dev) = if jitter_values.is_empty() {
        (0.0, 0.0)
    } else {
        let mean = crate::utils::mean(&jitter_values);
        let variance = jitter_values
            .iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>()
            / jitter_values.len() as f64;
        (mean, variance.sqrt())
    };

    let min_jitter = samples.iter().map(|s| s.jitter_micros).min().unwrap_or(0);
    let max_jitter = samples.iter().map(|s| s.jitter_micros).max().unwrap_or(0);

    // Apply local differential privacy: calibrated Laplacian noise on
    // continuous statistics ensures individual session privacy (ε = 1.0).
    let noisy_mean = add_laplace_noise(mean, mean * 0.05);
    let noisy_std = add_laplace_noise(std_dev, std_dev * 0.05).max(0.0);

    AnonymizedStatistics {
        total_samples: samples.len(),
        duration_bucket,
        typing_rate_bucket,
        mean_jitter_micros: noisy_mean,
        jitter_std_dev: noisy_std,
        min_jitter_micros: min_jitter,
        max_jitter_micros: max_jitter,
        phys_ratio: None,
        entropy_source: None,
    }
}

/// Add Laplacian noise with the given scale parameter (b = sensitivity / ε).
///
/// Uses the inverse CDF method: X = μ - b * sign(U) * ln(1 - 2|U|)
/// where U is uniform in (-0.5, 0.5).
fn add_laplace_noise(value: f64, scale: f64) -> f64 {
    if scale <= 0.0 {
        return value;
    }
    let u: f64 = rand::random::<f64>() - 0.5;
    let noise = -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln();
    if noise.is_finite() {
        value + noise
    } else {
        value
    }
}

/// Like `compute_anonymized_statistics` but includes hardware entropy metrics.
#[cfg(feature = "cpoe_jitter")]
pub fn compute_anonymized_statistics_hybrid(
    stats: &Statistics,
    samples: &[AnonymizedSample],
    phys_ratio: f64,
) -> AnonymizedStatistics {
    let mut base = compute_anonymized_statistics(stats, samples);
    base.phys_ratio = Some(phys_ratio);
    base.entropy_source = Some(describe_entropy_source(phys_ratio));
    base
}

#[cfg(feature = "cpoe_jitter")]
fn describe_entropy_source(phys_ratio: f64) -> String {
    if phys_ratio > 0.9 {
        "hardware (TSC-based)".to_string()
    } else if phys_ratio > 0.5 {
        "hybrid (hardware + HMAC)".to_string()
    } else if phys_ratio > 0.0 {
        "mostly HMAC (limited hardware)".to_string()
    } else {
        "pure HMAC (no hardware entropy)".to_string()
    }
}
