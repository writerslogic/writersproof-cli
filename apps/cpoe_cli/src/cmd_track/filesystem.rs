// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use glob::Pattern;
use std::fs;
use std::path::{Path, PathBuf};

use crate::util::BLOCKED_EXTENSIONS;

use super::types::TrackTarget;
use super::IGNORED_DIRS;

pub(super) fn classify_target(path: &Path) -> Result<TrackTarget> {
    if !path.exists() {
        return Err(anyhow!(
            "Not found: {}\n\nCreate the file first, then track it.",
            path.display()
        ));
    }

    // Reject symlinks at the entry point to prevent TOCTOU attacks where a
    // symlink replaces the target between classification and checkpointing.
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("Cannot stat path: {}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "Refusing to track symlink: {}\n\nTrack the real file instead.",
            path.display()
        ));
    }

    let abs = fs::canonicalize(path)
        .with_context(|| format!("Cannot resolve path: {}", path.display()))?;

    if abs.is_file() {
        return Ok(TrackTarget::SingleFile(abs));
    }

    if !abs.is_dir() {
        return Err(anyhow!("Not a file or directory: {}", path.display()));
    }

    let ext = abs.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "scriv" => Ok(TrackTarget::ScrivenerPackage(abs)),
        "textbundle" => Ok(TrackTarget::TextBundle(abs)),
        _ => Ok(TrackTarget::Directory(abs)),
    }
}

pub(super) fn should_track_file(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };

    if name.starts_with('.') || name.ends_with('~') || name.ends_with(".tmp") {
        return false;
    }

    for ancestor in path.ancestors().skip(1) {
        if let Some(dir_name) = ancestor.file_name().and_then(|n| n.to_str()) {
            if IGNORED_DIRS.contains(&dir_name) {
                return false;
            }
        }
    }

    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => !BLOCKED_EXTENSIONS.contains(&ext.to_lowercase().as_str()),
        None => true,
    }
}

/// Check whether `path` falls within the given track target.
///
/// SAFETY: Both `path` and the target root must be canonicalized before
/// calling this function. The lexical `starts_with` check is only reliable
/// on canonical (absolute, symlink-resolved) paths.
pub(super) fn is_within_target(path: &Path, target: &TrackTarget) -> bool {
    match target {
        TrackTarget::SingleFile(f) => path == f.as_path(),
        TrackTarget::Directory(root)
        | TrackTarget::ScrivenerPackage(root)
        | TrackTarget::TextBundle(root) => path.starts_with(root),
    }
}

/// Collect all trackable files in a target.
pub(super) fn collect_trackable_files(target: &TrackTarget) -> Vec<PathBuf> {
    match target {
        TrackTarget::SingleFile(f) => vec![f.clone()],
        TrackTarget::Directory(root) => walk_trackable_files(root),
        TrackTarget::ScrivenerPackage(root) => {
            let data_dir = root.join("Files").join("Data");
            if data_dir.exists() {
                walk_trackable_files(&data_dir)
            } else {
                walk_trackable_files(root)
            }
        }
        TrackTarget::TextBundle(root) => {
            let mut files = Vec::new();
            for name in &["text.txt", "text.md", "text.markdown"] {
                let p = root.join(name);
                if p.exists() {
                    files.push(p);
                }
            }
            if files.is_empty() {
                walk_trackable_files(root)
            } else {
                files
            }
        }
    }
}

pub(super) fn walk_trackable_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') || IGNORED_DIRS.contains(&name) {
                    continue;
                }
            }

            if path.is_dir() {
                stack.push(path);
            } else if should_track_file(&path) {
                files.push(path);
            }
        }
    }

    files.sort();
    files
}

/// Check if a path matches glob patterns (for directory/watch mode).
pub(super) fn matches_patterns(path: &Path, patterns: &[Pattern]) -> bool {
    if patterns.is_empty() {
        return should_track_file(path);
    }
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    patterns.iter().any(|p| p.matches(name))
}
