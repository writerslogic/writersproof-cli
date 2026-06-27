// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::util::BLOCKED_EXTENSIONS;

pub fn is_initialized(writersproof_dir: &Path) -> bool {
    writersproof_dir.join("signing_key").exists()
}

pub fn is_calibrated(iterations_per_second: u64) -> bool {
    iterations_per_second > 0
}

pub fn ensure_vdf_calibrated_with_warning(iterations_per_second: u64) {
    if !is_calibrated(iterations_per_second) {
        eprintln!("Warning: VDF not calibrated. Run 'cpoe calibrate' for accurate time proofs.");
        eprintln!();
    }
}

pub fn ask_confirmation(prompt: &str, default: bool) -> Result<bool> {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    print!("{} {} ", prompt, suffix);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    match crate::util::parse_yes_no(&input) {
        Some(response) => Ok(response),
        None => Ok(default),
    }
}

pub fn get_recently_modified_files(dir: &Path, max_count: usize) -> Vec<PathBuf> {
    let mut files: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();

            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') {
                    continue;
                }
            }

            if !path.is_file() {
                continue;
            }

            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext_lower = ext.to_lowercase();
                if BLOCKED_EXTENSIONS.contains(&ext_lower.as_str()) {
                    continue;
                }
            }

            if let Ok(metadata) = path.metadata() {
                if let Ok(modified) = metadata.modified() {
                    files.push((path, modified));
                }
            }
        }
    }

    files.sort_by_key(|f| std::cmp::Reverse(f.1));
    files
        .into_iter()
        .take(max_count)
        .map(|(path, _)| path)
        .collect()
}

pub fn select_file_from_list(files: &[PathBuf], prompt_prefix: &str) -> Result<Option<PathBuf>> {
    if files.is_empty() {
        return Ok(None);
    }

    if files.len() == 1 {
        return Ok(Some(files[0].clone()));
    }

    println!();
    for (i, file) in files.iter().enumerate() {
        let display = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.display().to_string());
        println!("  [{}] {}", i + 1, display);
    }
    println!("  [0] Cancel");
    println!();

    let prompt = if prompt_prefix.is_empty() {
        "Enter choice".to_string()
    } else {
        format!("{} - enter choice", prompt_prefix)
    };

    print!("{}: ", prompt);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();

    if input.is_empty() || input == "0" {
        return Ok(None);
    }

    match input.parse::<usize>() {
        Ok(n) if n > 0 && n <= files.len() => Ok(Some(files[n - 1].clone())),
        _ => {
            let input_lower = input.to_lowercase();
            let matches: Vec<_> = files
                .iter()
                .filter(|f| {
                    f.file_name()
                        .map(|n| n.to_string_lossy().to_lowercase().contains(&input_lower))
                        .unwrap_or(false)
                })
                .collect();
            match matches.len() {
                0 => Err(anyhow!("Invalid selection: {}", input)),
                1 => Ok(Some(matches[0].clone())),
                _ => {
                    eprintln!("Multiple matches found:");
                    for m in &matches {
                        let name = m
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| m.display().to_string());
                        eprintln!("  {}", name);
                    }
                    eprintln!("Please enter a more specific name or use a number.");
                    Ok(None)
                }
            }
        }
    }
}

pub fn default_commit_message() -> String {
    format!("Checkpoint at {}", Utc::now().format("%Y-%m-%d %H:%M"))
}

pub fn show_quick_status(
    writersproof_dir: &Path,
    iterations_per_second: u64,
    tracked_files: &[(String, i64, i64)],
) {
    println!("=== CPoE Status ===");
    println!();

    if !is_initialized(writersproof_dir) {
        println!("Status: Not initialized. Run 'cpoe init' to get started.");
        return;
    }

    if !is_calibrated(iterations_per_second) {
        println!("Status: Not calibrated. Run 'cpoe calibrate' to set VDF speed.");
        return;
    }

    println!("Status: Ready");
    println!();

    if tracked_files.is_empty() {
        println!("No documents tracked yet.");
        println!();
        println!("Start checkpointing with: cpoe commit <file>");
    } else {
        println!("Tracked documents: {}", tracked_files.len());

        let mut recent: Vec<_> = tracked_files.iter().collect();
        recent.sort_by_key(|r| std::cmp::Reverse(r.1));

        for (path, ts, count) in recent.iter().take(5) {
            let name = Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone());
            let ts_str = DateTime::from_timestamp_nanos(*ts).format("%m/%d %H:%M");
            println!("  {} ({} checkpoints, {})", name, count, ts_str);
        }

        if tracked_files.len() > 5 {
            println!("  ... and {} more", tracked_files.len() - 5);
        }

        println!();
        println!("Shortcuts: cpoe <file>, cpoe <folder>");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_commit_message() {
        let msg = default_commit_message();
        assert!(msg.starts_with("Checkpoint at "));
    }

    #[test]
    fn test_is_initialized() {
        let temp = std::env::temp_dir().join("writersproof_test_init");
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();

        assert!(!is_initialized(&temp));

        fs::write(temp.join("signing_key"), b"test").unwrap();
        assert!(is_initialized(&temp));

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_get_recently_modified_files() {
        let dir = tempfile::tempdir().unwrap();
        let f1 = dir.path().join("a.txt");
        let f2 = dir.path().join("b.txt");

        fs::write(&f1, "a").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&f2, "b").unwrap();

        let files = get_recently_modified_files(dir.path(), 10);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].file_name().unwrap(), "b.txt");
        assert_eq!(files[1].file_name().unwrap(), "a.txt");
    }
}
