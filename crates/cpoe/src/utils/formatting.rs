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
///
/// Values exceeding the age of the universe (~4.3e17 seconds) are capped
/// as "computationally infeasible" to avoid absurd numeric displays.
pub fn format_duration_human(seconds: f64) -> String {
    if seconds.is_nan() || seconds < 0.0 {
        return "N/A".to_string();
    }
    if seconds.is_infinite() {
        return "Computationally infeasible".to_string();
    }
    // Cap at age of the universe (~13.8 billion years). Values beyond
    // this are dominated by hardware key extraction or equivalent
    // physically infeasible operations.
    const AGE_OF_UNIVERSE_SEC: f64 = 4.35e17;
    if seconds > AGE_OF_UNIVERSE_SEC {
        return "Computationally infeasible (exceeds hardware key extraction bound)".to_string();
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
        let years = seconds / (86400.0 * 365.0);
        if years > 1e9 {
            format!("{:.1e} years (effectively infeasible)", years)
        } else {
            format!("{:.1} years", years)
        }
    }
}

/// Format a duration in seconds as compact "Xh Xm Xs" text.
pub fn format_duration_compact(total_secs: i64) -> String {
    if total_secs < 0 {
        return "0s".to_string();
    }
    if total_secs >= 3600 {
        format!(
            "{}h {}m {}s",
            total_secs / 3600,
            (total_secs % 3600) / 60,
            total_secs % 60
        )
    } else if total_secs >= 60 {
        format!("{}m {}s", total_secs / 60, total_secs % 60)
    } else {
        format!("{}s", total_secs)
    }
}

/// Format a duration in seconds as verbose English ("X days, Y hours").
pub fn format_duration_verbose(total_secs: i64) -> String {
    if total_secs <= 0 {
        return "0 seconds".to_string();
    }

    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if days > 0 {
        if days == 1 {
            format!("{} day, {} hours", days, hours)
        } else {
            format!("{} days, {} hours", days, hours)
        }
    } else if hours > 0 {
        if hours == 1 {
            format!("{} hour, {} minutes", hours, minutes)
        } else {
            format!("{} hours, {} minutes", hours, minutes)
        }
    } else if minutes > 0 {
        if minutes == 1 {
            format!("{} minute, {} seconds", minutes, seconds)
        } else {
            format!("{} minutes, {} seconds", minutes, seconds)
        }
    } else if seconds == 1 {
        format!("{} second", seconds)
    } else {
        format!("{} seconds", seconds)
    }
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
        assert_eq!(format_duration_human(f64::INFINITY), "Computationally infeasible");
    }

    #[test]
    fn format_duration_infeasible_finite() {
        assert_eq!(
            format_duration_human(1e308),
            "Computationally infeasible (exceeds hardware key extraction bound)"
        );
    }

}
