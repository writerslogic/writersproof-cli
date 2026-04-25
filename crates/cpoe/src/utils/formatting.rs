// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

/// Format a u64 with thousand separators (e.g., 1,234,567).
pub fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Format a byte count as a human-readable size (B, KB, MB).
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Format a duration in seconds as human-readable text.
pub fn format_duration_human(seconds: f64) -> String {
    if seconds.is_nan() || seconds < 0.0 {
        return "N/A".to_string();
    }
    if seconds.is_infinite() {
        return "Infeasible".to_string();
    }
    if seconds < 60.0 {
        format!("{:.0} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.0} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1} hours", seconds / 3600.0)
    } else if seconds < 86400.0 * 365.0 {
        format!("{:.1} days", seconds / 86400.0)
    } else {
        format!("{:.1} years", seconds / (86400.0 * 365.0))
    }
}

/// SHA-256 hash of a byte slice, returned as a fixed 32-byte array.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_number_zero() {
        assert_eq!(format_number(0), "0");
    }

    #[test]
    fn format_number_small() {
        assert_eq!(format_number(42), "42");
        assert_eq!(format_number(999), "999");
    }

    #[test]
    fn format_number_thousands() {
        assert_eq!(format_number(1_000), "1,000");
        assert_eq!(format_number(1_234_567), "1,234,567");
    }

    #[test]
    fn format_bytes_small() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
    }

    #[test]
    fn format_bytes_kb() {
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
    }

    #[test]
    fn format_bytes_mb() {
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration_human(30.0), "30 seconds");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration_human(120.0), "2 minutes");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration_human(7200.0), "2.0 hours");
    }

    #[test]
    fn format_duration_nan() {
        assert_eq!(format_duration_human(f64::NAN), "N/A");
    }

    #[test]
    fn format_duration_infinite() {
        assert_eq!(format_duration_human(f64::INFINITY), "Infeasible");
    }

    #[test]
    fn hash_bytes_deterministic() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_bytes_different_inputs() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"world");
        assert_ne!(h1, h2);
    }
}
